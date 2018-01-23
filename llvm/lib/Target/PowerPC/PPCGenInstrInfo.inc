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

namespace PPC {
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
    ADD4	= 24,
    ADD4TLS	= 25,
    ADD4o	= 26,
    ADD8	= 27,
    ADD8TLS	= 28,
    ADD8TLS_	= 29,
    ADD8o	= 30,
    ADDC	= 31,
    ADDC8	= 32,
    ADDC8o	= 33,
    ADDCo	= 34,
    ADDE	= 35,
    ADDE8	= 36,
    ADDE8o	= 37,
    ADDEo	= 38,
    ADDI	= 39,
    ADDI8	= 40,
    ADDIC	= 41,
    ADDIC8	= 42,
    ADDICo	= 43,
    ADDIS	= 44,
    ADDIS8	= 45,
    ADDISdtprelHA	= 46,
    ADDISdtprelHA32	= 47,
    ADDISgotTprelHA	= 48,
    ADDIStlsgdHA	= 49,
    ADDIStlsldHA	= 50,
    ADDIStocHA	= 51,
    ADDIdtprelL	= 52,
    ADDIdtprelL32	= 53,
    ADDItlsgdL	= 54,
    ADDItlsgdL32	= 55,
    ADDItlsgdLADDR	= 56,
    ADDItlsgdLADDR32	= 57,
    ADDItlsldL	= 58,
    ADDItlsldL32	= 59,
    ADDItlsldLADDR	= 60,
    ADDItlsldLADDR32	= 61,
    ADDItocL	= 62,
    ADDME	= 63,
    ADDME8	= 64,
    ADDME8o	= 65,
    ADDMEo	= 66,
    ADDZE	= 67,
    ADDZE8	= 68,
    ADDZE8o	= 69,
    ADDZEo	= 70,
    ADJCALLSTACKDOWN	= 71,
    ADJCALLSTACKUP	= 72,
    AND	= 73,
    AND8	= 74,
    AND8o	= 75,
    ANDC	= 76,
    ANDC8	= 77,
    ANDC8o	= 78,
    ANDCo	= 79,
    ANDISo	= 80,
    ANDISo8	= 81,
    ANDIo	= 82,
    ANDIo8	= 83,
    ANDIo_1_EQ_BIT	= 84,
    ANDIo_1_EQ_BIT8	= 85,
    ANDIo_1_GT_BIT	= 86,
    ANDIo_1_GT_BIT8	= 87,
    ANDo	= 88,
    ATOMIC_CMP_SWAP_I16	= 89,
    ATOMIC_CMP_SWAP_I32	= 90,
    ATOMIC_CMP_SWAP_I64	= 91,
    ATOMIC_CMP_SWAP_I8	= 92,
    ATOMIC_LOAD_ADD_I16	= 93,
    ATOMIC_LOAD_ADD_I32	= 94,
    ATOMIC_LOAD_ADD_I64	= 95,
    ATOMIC_LOAD_ADD_I8	= 96,
    ATOMIC_LOAD_AND_I16	= 97,
    ATOMIC_LOAD_AND_I32	= 98,
    ATOMIC_LOAD_AND_I64	= 99,
    ATOMIC_LOAD_AND_I8	= 100,
    ATOMIC_LOAD_NAND_I16	= 101,
    ATOMIC_LOAD_NAND_I32	= 102,
    ATOMIC_LOAD_NAND_I64	= 103,
    ATOMIC_LOAD_NAND_I8	= 104,
    ATOMIC_LOAD_OR_I16	= 105,
    ATOMIC_LOAD_OR_I32	= 106,
    ATOMIC_LOAD_OR_I64	= 107,
    ATOMIC_LOAD_OR_I8	= 108,
    ATOMIC_LOAD_SUB_I16	= 109,
    ATOMIC_LOAD_SUB_I32	= 110,
    ATOMIC_LOAD_SUB_I64	= 111,
    ATOMIC_LOAD_SUB_I8	= 112,
    ATOMIC_LOAD_XOR_I16	= 113,
    ATOMIC_LOAD_XOR_I32	= 114,
    ATOMIC_LOAD_XOR_I64	= 115,
    ATOMIC_LOAD_XOR_I8	= 116,
    ATOMIC_SWAP_I16	= 117,
    ATOMIC_SWAP_I32	= 118,
    ATOMIC_SWAP_I64	= 119,
    ATOMIC_SWAP_I8	= 120,
    ATTN	= 121,
    B	= 122,
    BA	= 123,
    BC	= 124,
    BCC	= 125,
    BCCA	= 126,
    BCCCTR	= 127,
    BCCCTR8	= 128,
    BCCCTRL	= 129,
    BCCCTRL8	= 130,
    BCCL	= 131,
    BCCLA	= 132,
    BCCLR	= 133,
    BCCLRL	= 134,
    BCCTR	= 135,
    BCCTR8	= 136,
    BCCTR8n	= 137,
    BCCTRL	= 138,
    BCCTRL8	= 139,
    BCCTRL8n	= 140,
    BCCTRLn	= 141,
    BCCTRn	= 142,
    BCL	= 143,
    BCLR	= 144,
    BCLRL	= 145,
    BCLRLn	= 146,
    BCLRn	= 147,
    BCLalways	= 148,
    BCLn	= 149,
    BCTR	= 150,
    BCTR8	= 151,
    BCTRL	= 152,
    BCTRL8	= 153,
    BCTRL8_LDinto_toc	= 154,
    BCn	= 155,
    BDNZ	= 156,
    BDNZ8	= 157,
    BDNZA	= 158,
    BDNZAm	= 159,
    BDNZAp	= 160,
    BDNZL	= 161,
    BDNZLA	= 162,
    BDNZLAm	= 163,
    BDNZLAp	= 164,
    BDNZLR	= 165,
    BDNZLR8	= 166,
    BDNZLRL	= 167,
    BDNZLRLm	= 168,
    BDNZLRLp	= 169,
    BDNZLRm	= 170,
    BDNZLRp	= 171,
    BDNZLm	= 172,
    BDNZLp	= 173,
    BDNZm	= 174,
    BDNZp	= 175,
    BDZ	= 176,
    BDZ8	= 177,
    BDZA	= 178,
    BDZAm	= 179,
    BDZAp	= 180,
    BDZL	= 181,
    BDZLA	= 182,
    BDZLAm	= 183,
    BDZLAp	= 184,
    BDZLR	= 185,
    BDZLR8	= 186,
    BDZLRL	= 187,
    BDZLRLm	= 188,
    BDZLRLp	= 189,
    BDZLRm	= 190,
    BDZLRp	= 191,
    BDZLm	= 192,
    BDZLp	= 193,
    BDZm	= 194,
    BDZp	= 195,
    BL	= 196,
    BL8	= 197,
    BL8_NOP	= 198,
    BL8_NOP_TLS	= 199,
    BL8_TLS	= 200,
    BL8_TLS_	= 201,
    BLA	= 202,
    BLA8	= 203,
    BLA8_NOP	= 204,
    BLR	= 205,
    BLR8	= 206,
    BLRL	= 207,
    BL_TLS	= 208,
    BPERMD	= 209,
    BRINC	= 210,
    CLRBHRB	= 211,
    CLRLSLDI	= 212,
    CLRLSLDIo	= 213,
    CLRLSLWI	= 214,
    CLRLSLWIo	= 215,
    CLRRDI	= 216,
    CLRRDIo	= 217,
    CLRRWI	= 218,
    CLRRWIo	= 219,
    CMPB	= 220,
    CMPB8	= 221,
    CMPD	= 222,
    CMPDI	= 223,
    CMPLD	= 224,
    CMPLDI	= 225,
    CMPLW	= 226,
    CMPLWI	= 227,
    CMPW	= 228,
    CMPWI	= 229,
    CNTLZD	= 230,
    CNTLZDo	= 231,
    CNTLZW	= 232,
    CNTLZW8	= 233,
    CNTLZW8o	= 234,
    CNTLZWo	= 235,
    CR6SET	= 236,
    CR6UNSET	= 237,
    CRAND	= 238,
    CRANDC	= 239,
    CREQV	= 240,
    CRNAND	= 241,
    CRNOR	= 242,
    CROR	= 243,
    CRORC	= 244,
    CRSET	= 245,
    CRUNSET	= 246,
    CRXOR	= 247,
    DCBA	= 248,
    DCBF	= 249,
    DCBI	= 250,
    DCBST	= 251,
    DCBT	= 252,
    DCBTCT	= 253,
    DCBTDS	= 254,
    DCBTST	= 255,
    DCBTSTCT	= 256,
    DCBTSTDS	= 257,
    DCBTSTT	= 258,
    DCBTSTx	= 259,
    DCBTT	= 260,
    DCBTx	= 261,
    DCBZ	= 262,
    DCBZL	= 263,
    DCCCI	= 264,
    DIVD	= 265,
    DIVDE	= 266,
    DIVDEU	= 267,
    DIVDEUo	= 268,
    DIVDEo	= 269,
    DIVDU	= 270,
    DIVDUo	= 271,
    DIVDo	= 272,
    DIVW	= 273,
    DIVWE	= 274,
    DIVWEU	= 275,
    DIVWEUo	= 276,
    DIVWEo	= 277,
    DIVWU	= 278,
    DIVWUo	= 279,
    DIVWo	= 280,
    DSS	= 281,
    DSSALL	= 282,
    DST	= 283,
    DST64	= 284,
    DSTST	= 285,
    DSTST64	= 286,
    DSTSTT	= 287,
    DSTSTT64	= 288,
    DSTT	= 289,
    DSTT64	= 290,
    DYNALLOC	= 291,
    DYNALLOC8	= 292,
    DYNAREAOFFSET	= 293,
    DYNAREAOFFSET8	= 294,
    EH_SjLj_LongJmp32	= 295,
    EH_SjLj_LongJmp64	= 296,
    EH_SjLj_SetJmp32	= 297,
    EH_SjLj_SetJmp64	= 298,
    EH_SjLj_Setup	= 299,
    EQV	= 300,
    EQV8	= 301,
    EQV8o	= 302,
    EQVo	= 303,
    EVABS	= 304,
    EVADDIW	= 305,
    EVADDSMIAAW	= 306,
    EVADDSSIAAW	= 307,
    EVADDUMIAAW	= 308,
    EVADDUSIAAW	= 309,
    EVADDW	= 310,
    EVAND	= 311,
    EVANDC	= 312,
    EVCMPEQ	= 313,
    EVCMPGTS	= 314,
    EVCMPGTU	= 315,
    EVCMPLTS	= 316,
    EVCMPLTU	= 317,
    EVCNTLSW	= 318,
    EVCNTLZW	= 319,
    EVDIVWS	= 320,
    EVDIVWU	= 321,
    EVEQV	= 322,
    EVEXTSB	= 323,
    EVEXTSH	= 324,
    EVLDD	= 325,
    EVLDDX	= 326,
    EVLDH	= 327,
    EVLDHX	= 328,
    EVLDW	= 329,
    EVLDWX	= 330,
    EVLHHESPLAT	= 331,
    EVLHHESPLATX	= 332,
    EVLHHOSSPLAT	= 333,
    EVLHHOSSPLATX	= 334,
    EVLHHOUSPLAT	= 335,
    EVLHHOUSPLATX	= 336,
    EVLWHE	= 337,
    EVLWHEX	= 338,
    EVLWHOS	= 339,
    EVLWHOSX	= 340,
    EVLWHOU	= 341,
    EVLWHOUX	= 342,
    EVLWHSPLAT	= 343,
    EVLWHSPLATX	= 344,
    EVLWWSPLAT	= 345,
    EVLWWSPLATX	= 346,
    EVMERGEHI	= 347,
    EVMERGEHILO	= 348,
    EVMERGELO	= 349,
    EVMERGELOHI	= 350,
    EVMHEGSMFAA	= 351,
    EVMHEGSMFAN	= 352,
    EVMHEGSMIAA	= 353,
    EVMHEGSMIAN	= 354,
    EVMHEGUMIAA	= 355,
    EVMHEGUMIAN	= 356,
    EVMHESMF	= 357,
    EVMHESMFA	= 358,
    EVMHESMFAAW	= 359,
    EVMHESMFANW	= 360,
    EVMHESMI	= 361,
    EVMHESMIA	= 362,
    EVMHESMIAAW	= 363,
    EVMHESMIANW	= 364,
    EVMHESSF	= 365,
    EVMHESSFA	= 366,
    EVMHESSFAAW	= 367,
    EVMHESSFANW	= 368,
    EVMHESSIAAW	= 369,
    EVMHESSIANW	= 370,
    EVMHEUMI	= 371,
    EVMHEUMIA	= 372,
    EVMHEUMIAAW	= 373,
    EVMHEUMIANW	= 374,
    EVMHEUSIAAW	= 375,
    EVMHEUSIANW	= 376,
    EVMHOGSMFAA	= 377,
    EVMHOGSMFAN	= 378,
    EVMHOGSMIAA	= 379,
    EVMHOGSMIAN	= 380,
    EVMHOGUMIAA	= 381,
    EVMHOGUMIAN	= 382,
    EVMHOSMF	= 383,
    EVMHOSMFA	= 384,
    EVMHOSMFAAW	= 385,
    EVMHOSMFANW	= 386,
    EVMHOSMI	= 387,
    EVMHOSMIA	= 388,
    EVMHOSMIAAW	= 389,
    EVMHOSMIANW	= 390,
    EVMHOSSF	= 391,
    EVMHOSSFA	= 392,
    EVMHOSSFAAW	= 393,
    EVMHOSSFANW	= 394,
    EVMHOSSIAAW	= 395,
    EVMHOSSIANW	= 396,
    EVMHOUMI	= 397,
    EVMHOUMIA	= 398,
    EVMHOUMIAAW	= 399,
    EVMHOUMIANW	= 400,
    EVMHOUSIAAW	= 401,
    EVMHOUSIANW	= 402,
    EVMRA	= 403,
    EVMWHSMF	= 404,
    EVMWHSMFA	= 405,
    EVMWHSMI	= 406,
    EVMWHSMIA	= 407,
    EVMWHSSF	= 408,
    EVMWHSSFA	= 409,
    EVMWHUMI	= 410,
    EVMWHUMIA	= 411,
    EVMWLSMIAAW	= 412,
    EVMWLSMIANW	= 413,
    EVMWLSSIAAW	= 414,
    EVMWLSSIANW	= 415,
    EVMWLUMI	= 416,
    EVMWLUMIA	= 417,
    EVMWLUMIAAW	= 418,
    EVMWLUMIANW	= 419,
    EVMWLUSIAAW	= 420,
    EVMWLUSIANW	= 421,
    EVMWSMF	= 422,
    EVMWSMFA	= 423,
    EVMWSMFAA	= 424,
    EVMWSMFAN	= 425,
    EVMWSMI	= 426,
    EVMWSMIA	= 427,
    EVMWSMIAA	= 428,
    EVMWSMIAN	= 429,
    EVMWSSF	= 430,
    EVMWSSFA	= 431,
    EVMWSSFAA	= 432,
    EVMWSSFAN	= 433,
    EVMWUMI	= 434,
    EVMWUMIA	= 435,
    EVMWUMIAA	= 436,
    EVMWUMIAN	= 437,
    EVNAND	= 438,
    EVNEG	= 439,
    EVNOR	= 440,
    EVOR	= 441,
    EVORC	= 442,
    EVRLW	= 443,
    EVRLWI	= 444,
    EVRNDW	= 445,
    EVSLW	= 446,
    EVSLWI	= 447,
    EVSPLATFI	= 448,
    EVSPLATI	= 449,
    EVSRWIS	= 450,
    EVSRWIU	= 451,
    EVSRWS	= 452,
    EVSRWU	= 453,
    EVSTDD	= 454,
    EVSTDDX	= 455,
    EVSTDH	= 456,
    EVSTDHX	= 457,
    EVSTDW	= 458,
    EVSTDWX	= 459,
    EVSTWHE	= 460,
    EVSTWHEX	= 461,
    EVSTWHO	= 462,
    EVSTWHOX	= 463,
    EVSTWWE	= 464,
    EVSTWWEX	= 465,
    EVSTWWO	= 466,
    EVSTWWOX	= 467,
    EVSUBFSMIAAW	= 468,
    EVSUBFSSIAAW	= 469,
    EVSUBFUMIAAW	= 470,
    EVSUBFUSIAAW	= 471,
    EVSUBFW	= 472,
    EVSUBIFW	= 473,
    EVXOR	= 474,
    EXTLDI	= 475,
    EXTLDIo	= 476,
    EXTLWI	= 477,
    EXTLWIo	= 478,
    EXTRDI	= 479,
    EXTRDIo	= 480,
    EXTRWI	= 481,
    EXTRWIo	= 482,
    EXTSB	= 483,
    EXTSB8	= 484,
    EXTSB8_32_64	= 485,
    EXTSB8o	= 486,
    EXTSBo	= 487,
    EXTSH	= 488,
    EXTSH8	= 489,
    EXTSH8_32_64	= 490,
    EXTSH8o	= 491,
    EXTSHo	= 492,
    EXTSW	= 493,
    EXTSW_32_64	= 494,
    EXTSW_32_64o	= 495,
    EXTSWo	= 496,
    EnforceIEIO	= 497,
    FABSD	= 498,
    FABSDo	= 499,
    FABSS	= 500,
    FABSSo	= 501,
    FADD	= 502,
    FADDS	= 503,
    FADDSo	= 504,
    FADDo	= 505,
    FADDrtz	= 506,
    FCFID	= 507,
    FCFIDS	= 508,
    FCFIDSo	= 509,
    FCFIDU	= 510,
    FCFIDUS	= 511,
    FCFIDUSo	= 512,
    FCFIDUo	= 513,
    FCFIDo	= 514,
    FCMPUD	= 515,
    FCMPUS	= 516,
    FCPSGND	= 517,
    FCPSGNDo	= 518,
    FCPSGNS	= 519,
    FCPSGNSo	= 520,
    FCTID	= 521,
    FCTIDUZ	= 522,
    FCTIDUZo	= 523,
    FCTIDZ	= 524,
    FCTIDZo	= 525,
    FCTIDo	= 526,
    FCTIW	= 527,
    FCTIWUZ	= 528,
    FCTIWUZo	= 529,
    FCTIWZ	= 530,
    FCTIWZo	= 531,
    FCTIWo	= 532,
    FDIV	= 533,
    FDIVS	= 534,
    FDIVSo	= 535,
    FDIVo	= 536,
    FMADD	= 537,
    FMADDS	= 538,
    FMADDSo	= 539,
    FMADDo	= 540,
    FMR	= 541,
    FMRo	= 542,
    FMSUB	= 543,
    FMSUBS	= 544,
    FMSUBSo	= 545,
    FMSUBo	= 546,
    FMUL	= 547,
    FMULS	= 548,
    FMULSo	= 549,
    FMULo	= 550,
    FNABSD	= 551,
    FNABSDo	= 552,
    FNABSS	= 553,
    FNABSSo	= 554,
    FNEGD	= 555,
    FNEGDo	= 556,
    FNEGS	= 557,
    FNEGSo	= 558,
    FNMADD	= 559,
    FNMADDS	= 560,
    FNMADDSo	= 561,
    FNMADDo	= 562,
    FNMSUB	= 563,
    FNMSUBS	= 564,
    FNMSUBSo	= 565,
    FNMSUBo	= 566,
    FRE	= 567,
    FRES	= 568,
    FRESo	= 569,
    FREo	= 570,
    FRIMD	= 571,
    FRIMDo	= 572,
    FRIMS	= 573,
    FRIMSo	= 574,
    FRIND	= 575,
    FRINDo	= 576,
    FRINS	= 577,
    FRINSo	= 578,
    FRIPD	= 579,
    FRIPDo	= 580,
    FRIPS	= 581,
    FRIPSo	= 582,
    FRIZD	= 583,
    FRIZDo	= 584,
    FRIZS	= 585,
    FRIZSo	= 586,
    FRSP	= 587,
    FRSPo	= 588,
    FRSQRTE	= 589,
    FRSQRTES	= 590,
    FRSQRTESo	= 591,
    FRSQRTEo	= 592,
    FSELD	= 593,
    FSELDo	= 594,
    FSELS	= 595,
    FSELSo	= 596,
    FSQRT	= 597,
    FSQRTS	= 598,
    FSQRTSo	= 599,
    FSQRTo	= 600,
    FSUB	= 601,
    FSUBS	= 602,
    FSUBSo	= 603,
    FSUBo	= 604,
    GETtlsADDR	= 605,
    GETtlsADDR32	= 606,
    GETtlsldADDR	= 607,
    GETtlsldADDR32	= 608,
    ICBI	= 609,
    ICBT	= 610,
    ICCCI	= 611,
    INSLWI	= 612,
    INSLWIo	= 613,
    INSRDI	= 614,
    INSRDIo	= 615,
    INSRWI	= 616,
    INSRWIo	= 617,
    ISEL	= 618,
    ISEL8	= 619,
    ISYNC	= 620,
    LA	= 621,
    LAx	= 622,
    LBARX	= 623,
    LBARXL	= 624,
    LBZ	= 625,
    LBZ8	= 626,
    LBZCIX	= 627,
    LBZU	= 628,
    LBZU8	= 629,
    LBZUX	= 630,
    LBZUX8	= 631,
    LBZX	= 632,
    LBZX8	= 633,
    LD	= 634,
    LDARX	= 635,
    LDARXL	= 636,
    LDBRX	= 637,
    LDCIX	= 638,
    LDU	= 639,
    LDUX	= 640,
    LDX	= 641,
    LDgotTprelL	= 642,
    LDgotTprelL32	= 643,
    LDtoc	= 644,
    LDtocBA	= 645,
    LDtocCPT	= 646,
    LDtocJTI	= 647,
    LDtocL	= 648,
    LFD	= 649,
    LFDU	= 650,
    LFDUX	= 651,
    LFDX	= 652,
    LFIWAX	= 653,
    LFIWZX	= 654,
    LFS	= 655,
    LFSU	= 656,
    LFSUX	= 657,
    LFSX	= 658,
    LHA	= 659,
    LHA8	= 660,
    LHARX	= 661,
    LHARXL	= 662,
    LHAU	= 663,
    LHAU8	= 664,
    LHAUX	= 665,
    LHAUX8	= 666,
    LHAX	= 667,
    LHAX8	= 668,
    LHBRX	= 669,
    LHBRX8	= 670,
    LHZ	= 671,
    LHZ8	= 672,
    LHZCIX	= 673,
    LHZU	= 674,
    LHZU8	= 675,
    LHZUX	= 676,
    LHZUX8	= 677,
    LHZX	= 678,
    LHZX8	= 679,
    LI	= 680,
    LI8	= 681,
    LIS	= 682,
    LIS8	= 683,
    LMW	= 684,
    LSWI	= 685,
    LVEBX	= 686,
    LVEHX	= 687,
    LVEWX	= 688,
    LVSL	= 689,
    LVSR	= 690,
    LVX	= 691,
    LVXL	= 692,
    LWA	= 693,
    LWARX	= 694,
    LWARXL	= 695,
    LWAUX	= 696,
    LWAX	= 697,
    LWAX_32	= 698,
    LWA_32	= 699,
    LWBRX	= 700,
    LWBRX8	= 701,
    LWZ	= 702,
    LWZ8	= 703,
    LWZCIX	= 704,
    LWZU	= 705,
    LWZU8	= 706,
    LWZUX	= 707,
    LWZUX8	= 708,
    LWZX	= 709,
    LWZX8	= 710,
    LWZtoc	= 711,
    LXSDX	= 712,
    LXSIWAX	= 713,
    LXSIWZX	= 714,
    LXSSPX	= 715,
    LXVD2X	= 716,
    LXVDSX	= 717,
    LXVW4X	= 718,
    MBAR	= 719,
    MCRF	= 720,
    MCRFS	= 721,
    MFBHRBE	= 722,
    MFCR	= 723,
    MFCR8	= 724,
    MFCTR	= 725,
    MFCTR8	= 726,
    MFDCR	= 727,
    MFFS	= 728,
    MFFSo	= 729,
    MFLR	= 730,
    MFLR8	= 731,
    MFMSR	= 732,
    MFOCRF	= 733,
    MFOCRF8	= 734,
    MFSPR	= 735,
    MFSPR8	= 736,
    MFSR	= 737,
    MFSRIN	= 738,
    MFTB	= 739,
    MFTB8	= 740,
    MFVRSAVE	= 741,
    MFVRSAVEv	= 742,
    MFVSCR	= 743,
    MFVSRD	= 744,
    MFVSRWZ	= 745,
    MSYNC	= 746,
    MTCRF	= 747,
    MTCRF8	= 748,
    MTCTR	= 749,
    MTCTR8	= 750,
    MTCTR8loop	= 751,
    MTCTRloop	= 752,
    MTDCR	= 753,
    MTFSB0	= 754,
    MTFSB1	= 755,
    MTFSF	= 756,
    MTFSFI	= 757,
    MTFSFIo	= 758,
    MTFSFb	= 759,
    MTFSFo	= 760,
    MTLR	= 761,
    MTLR8	= 762,
    MTMSR	= 763,
    MTMSRD	= 764,
    MTOCRF	= 765,
    MTOCRF8	= 766,
    MTSPR	= 767,
    MTSPR8	= 768,
    MTSR	= 769,
    MTSRIN	= 770,
    MTVRSAVE	= 771,
    MTVRSAVEv	= 772,
    MTVSCR	= 773,
    MTVSRD	= 774,
    MTVSRWA	= 775,
    MTVSRWZ	= 776,
    MULHD	= 777,
    MULHDU	= 778,
    MULHDUo	= 779,
    MULHDo	= 780,
    MULHW	= 781,
    MULHWU	= 782,
    MULHWUo	= 783,
    MULHWo	= 784,
    MULLD	= 785,
    MULLDo	= 786,
    MULLI	= 787,
    MULLI8	= 788,
    MULLW	= 789,
    MULLWo	= 790,
    MoveGOTtoLR	= 791,
    MovePCtoLR	= 792,
    MovePCtoLR8	= 793,
    NAND	= 794,
    NAND8	= 795,
    NAND8o	= 796,
    NANDo	= 797,
    NEG	= 798,
    NEG8	= 799,
    NEG8o	= 800,
    NEGo	= 801,
    NOP	= 802,
    NOP_GT_PWR6	= 803,
    NOP_GT_PWR7	= 804,
    NOR	= 805,
    NOR8	= 806,
    NOR8o	= 807,
    NORo	= 808,
    OR	= 809,
    OR8	= 810,
    OR8o	= 811,
    ORC	= 812,
    ORC8	= 813,
    ORC8o	= 814,
    ORCo	= 815,
    ORI	= 816,
    ORI8	= 817,
    ORIS	= 818,
    ORIS8	= 819,
    ORo	= 820,
    POPCNTD	= 821,
    POPCNTW	= 822,
    PPC32GOT	= 823,
    PPC32PICGOT	= 824,
    QVALIGNI	= 825,
    QVALIGNIb	= 826,
    QVALIGNIs	= 827,
    QVESPLATI	= 828,
    QVESPLATIb	= 829,
    QVESPLATIs	= 830,
    QVFABS	= 831,
    QVFABSs	= 832,
    QVFADD	= 833,
    QVFADDS	= 834,
    QVFADDSs	= 835,
    QVFCFID	= 836,
    QVFCFIDS	= 837,
    QVFCFIDU	= 838,
    QVFCFIDUS	= 839,
    QVFCFIDb	= 840,
    QVFCMPEQ	= 841,
    QVFCMPEQb	= 842,
    QVFCMPEQbs	= 843,
    QVFCMPGT	= 844,
    QVFCMPGTb	= 845,
    QVFCMPGTbs	= 846,
    QVFCMPLT	= 847,
    QVFCMPLTb	= 848,
    QVFCMPLTbs	= 849,
    QVFCPSGN	= 850,
    QVFCPSGNs	= 851,
    QVFCTID	= 852,
    QVFCTIDU	= 853,
    QVFCTIDUZ	= 854,
    QVFCTIDZ	= 855,
    QVFCTIDb	= 856,
    QVFCTIW	= 857,
    QVFCTIWU	= 858,
    QVFCTIWUZ	= 859,
    QVFCTIWZ	= 860,
    QVFLOGICAL	= 861,
    QVFLOGICALb	= 862,
    QVFLOGICALs	= 863,
    QVFMADD	= 864,
    QVFMADDS	= 865,
    QVFMADDSs	= 866,
    QVFMR	= 867,
    QVFMRb	= 868,
    QVFMRs	= 869,
    QVFMSUB	= 870,
    QVFMSUBS	= 871,
    QVFMSUBSs	= 872,
    QVFMUL	= 873,
    QVFMULS	= 874,
    QVFMULSs	= 875,
    QVFNABS	= 876,
    QVFNABSs	= 877,
    QVFNEG	= 878,
    QVFNEGs	= 879,
    QVFNMADD	= 880,
    QVFNMADDS	= 881,
    QVFNMADDSs	= 882,
    QVFNMSUB	= 883,
    QVFNMSUBS	= 884,
    QVFNMSUBSs	= 885,
    QVFPERM	= 886,
    QVFPERMs	= 887,
    QVFRE	= 888,
    QVFRES	= 889,
    QVFRESs	= 890,
    QVFRIM	= 891,
    QVFRIMs	= 892,
    QVFRIN	= 893,
    QVFRINs	= 894,
    QVFRIP	= 895,
    QVFRIPs	= 896,
    QVFRIZ	= 897,
    QVFRIZs	= 898,
    QVFRSP	= 899,
    QVFRSPs	= 900,
    QVFRSQRTE	= 901,
    QVFRSQRTES	= 902,
    QVFRSQRTESs	= 903,
    QVFSEL	= 904,
    QVFSELb	= 905,
    QVFSELbb	= 906,
    QVFSELbs	= 907,
    QVFSUB	= 908,
    QVFSUBS	= 909,
    QVFSUBSs	= 910,
    QVFTSTNAN	= 911,
    QVFTSTNANb	= 912,
    QVFTSTNANbs	= 913,
    QVFXMADD	= 914,
    QVFXMADDS	= 915,
    QVFXMUL	= 916,
    QVFXMULS	= 917,
    QVFXXCPNMADD	= 918,
    QVFXXCPNMADDS	= 919,
    QVFXXMADD	= 920,
    QVFXXMADDS	= 921,
    QVFXXNPMADD	= 922,
    QVFXXNPMADDS	= 923,
    QVGPCI	= 924,
    QVLFCDUX	= 925,
    QVLFCDUXA	= 926,
    QVLFCDX	= 927,
    QVLFCDXA	= 928,
    QVLFCSUX	= 929,
    QVLFCSUXA	= 930,
    QVLFCSX	= 931,
    QVLFCSXA	= 932,
    QVLFCSXs	= 933,
    QVLFDUX	= 934,
    QVLFDUXA	= 935,
    QVLFDX	= 936,
    QVLFDXA	= 937,
    QVLFDXb	= 938,
    QVLFIWAX	= 939,
    QVLFIWAXA	= 940,
    QVLFIWZX	= 941,
    QVLFIWZXA	= 942,
    QVLFSUX	= 943,
    QVLFSUXA	= 944,
    QVLFSX	= 945,
    QVLFSXA	= 946,
    QVLFSXb	= 947,
    QVLFSXs	= 948,
    QVLPCLDX	= 949,
    QVLPCLSX	= 950,
    QVLPCLSXint	= 951,
    QVLPCRDX	= 952,
    QVLPCRSX	= 953,
    QVSTFCDUX	= 954,
    QVSTFCDUXA	= 955,
    QVSTFCDUXI	= 956,
    QVSTFCDUXIA	= 957,
    QVSTFCDX	= 958,
    QVSTFCDXA	= 959,
    QVSTFCDXI	= 960,
    QVSTFCDXIA	= 961,
    QVSTFCSUX	= 962,
    QVSTFCSUXA	= 963,
    QVSTFCSUXI	= 964,
    QVSTFCSUXIA	= 965,
    QVSTFCSX	= 966,
    QVSTFCSXA	= 967,
    QVSTFCSXI	= 968,
    QVSTFCSXIA	= 969,
    QVSTFCSXs	= 970,
    QVSTFDUX	= 971,
    QVSTFDUXA	= 972,
    QVSTFDUXI	= 973,
    QVSTFDUXIA	= 974,
    QVSTFDX	= 975,
    QVSTFDXA	= 976,
    QVSTFDXI	= 977,
    QVSTFDXIA	= 978,
    QVSTFDXb	= 979,
    QVSTFIWX	= 980,
    QVSTFIWXA	= 981,
    QVSTFSUX	= 982,
    QVSTFSUXA	= 983,
    QVSTFSUXI	= 984,
    QVSTFSUXIA	= 985,
    QVSTFSUXs	= 986,
    QVSTFSX	= 987,
    QVSTFSXA	= 988,
    QVSTFSXI	= 989,
    QVSTFSXIA	= 990,
    QVSTFSXs	= 991,
    RESTORE_CR	= 992,
    RESTORE_CRBIT	= 993,
    RESTORE_VRSAVE	= 994,
    RFCI	= 995,
    RFDI	= 996,
    RFEBB	= 997,
    RFI	= 998,
    RFID	= 999,
    RFMCI	= 1000,
    RLDCL	= 1001,
    RLDCLo	= 1002,
    RLDCR	= 1003,
    RLDCRo	= 1004,
    RLDIC	= 1005,
    RLDICL	= 1006,
    RLDICL_32_64	= 1007,
    RLDICLo	= 1008,
    RLDICR	= 1009,
    RLDICRo	= 1010,
    RLDICo	= 1011,
    RLDIMI	= 1012,
    RLDIMIo	= 1013,
    RLWIMI	= 1014,
    RLWIMI8	= 1015,
    RLWIMI8o	= 1016,
    RLWIMIbm	= 1017,
    RLWIMIo	= 1018,
    RLWIMIobm	= 1019,
    RLWINM	= 1020,
    RLWINM8	= 1021,
    RLWINM8o	= 1022,
    RLWINMbm	= 1023,
    RLWINMo	= 1024,
    RLWINMobm	= 1025,
    RLWNM	= 1026,
    RLWNM8	= 1027,
    RLWNM8o	= 1028,
    RLWNMbm	= 1029,
    RLWNMo	= 1030,
    RLWNMobm	= 1031,
    ROTRDI	= 1032,
    ROTRDIo	= 1033,
    ROTRWI	= 1034,
    ROTRWIo	= 1035,
    ReadTB	= 1036,
    SC	= 1037,
    SELECT_CC_F4	= 1038,
    SELECT_CC_F8	= 1039,
    SELECT_CC_I4	= 1040,
    SELECT_CC_I8	= 1041,
    SELECT_CC_QBRC	= 1042,
    SELECT_CC_QFRC	= 1043,
    SELECT_CC_QSRC	= 1044,
    SELECT_CC_VRRC	= 1045,
    SELECT_CC_VSFRC	= 1046,
    SELECT_CC_VSRC	= 1047,
    SELECT_CC_VSSRC	= 1048,
    SELECT_F4	= 1049,
    SELECT_F8	= 1050,
    SELECT_I4	= 1051,
    SELECT_I8	= 1052,
    SELECT_QBRC	= 1053,
    SELECT_QFRC	= 1054,
    SELECT_QSRC	= 1055,
    SELECT_VRRC	= 1056,
    SELECT_VSFRC	= 1057,
    SELECT_VSRC	= 1058,
    SELECT_VSSRC	= 1059,
    SLBIA	= 1060,
    SLBIE	= 1061,
    SLBMFEE	= 1062,
    SLBMTE	= 1063,
    SLD	= 1064,
    SLDI	= 1065,
    SLDIo	= 1066,
    SLDo	= 1067,
    SLW	= 1068,
    SLW8	= 1069,
    SLW8o	= 1070,
    SLWI	= 1071,
    SLWIo	= 1072,
    SLWo	= 1073,
    SPILL_CR	= 1074,
    SPILL_CRBIT	= 1075,
    SPILL_VRSAVE	= 1076,
    SRAD	= 1077,
    SRADI	= 1078,
    SRADIo	= 1079,
    SRADo	= 1080,
    SRAW	= 1081,
    SRAWI	= 1082,
    SRAWIo	= 1083,
    SRAWo	= 1084,
    SRD	= 1085,
    SRDI	= 1086,
    SRDIo	= 1087,
    SRDo	= 1088,
    SRW	= 1089,
    SRW8	= 1090,
    SRW8o	= 1091,
    SRWI	= 1092,
    SRWIo	= 1093,
    SRWo	= 1094,
    STB	= 1095,
    STB8	= 1096,
    STBCIX	= 1097,
    STBCX	= 1098,
    STBU	= 1099,
    STBU8	= 1100,
    STBUX	= 1101,
    STBUX8	= 1102,
    STBX	= 1103,
    STBX8	= 1104,
    STD	= 1105,
    STDBRX	= 1106,
    STDCIX	= 1107,
    STDCX	= 1108,
    STDU	= 1109,
    STDUX	= 1110,
    STDX	= 1111,
    STFD	= 1112,
    STFDU	= 1113,
    STFDUX	= 1114,
    STFDX	= 1115,
    STFIWX	= 1116,
    STFS	= 1117,
    STFSU	= 1118,
    STFSUX	= 1119,
    STFSX	= 1120,
    STH	= 1121,
    STH8	= 1122,
    STHBRX	= 1123,
    STHCIX	= 1124,
    STHCX	= 1125,
    STHU	= 1126,
    STHU8	= 1127,
    STHUX	= 1128,
    STHUX8	= 1129,
    STHX	= 1130,
    STHX8	= 1131,
    STMW	= 1132,
    STSWI	= 1133,
    STVEBX	= 1134,
    STVEHX	= 1135,
    STVEWX	= 1136,
    STVX	= 1137,
    STVXL	= 1138,
    STW	= 1139,
    STW8	= 1140,
    STWBRX	= 1141,
    STWCIX	= 1142,
    STWCX	= 1143,
    STWU	= 1144,
    STWU8	= 1145,
    STWUX	= 1146,
    STWUX8	= 1147,
    STWX	= 1148,
    STWX8	= 1149,
    STXSDX	= 1150,
    STXSIWX	= 1151,
    STXSSPX	= 1152,
    STXVD2X	= 1153,
    STXVW4X	= 1154,
    SUBF	= 1155,
    SUBF8	= 1156,
    SUBF8o	= 1157,
    SUBFC	= 1158,
    SUBFC8	= 1159,
    SUBFC8o	= 1160,
    SUBFCo	= 1161,
    SUBFE	= 1162,
    SUBFE8	= 1163,
    SUBFE8o	= 1164,
    SUBFEo	= 1165,
    SUBFIC	= 1166,
    SUBFIC8	= 1167,
    SUBFME	= 1168,
    SUBFME8	= 1169,
    SUBFME8o	= 1170,
    SUBFMEo	= 1171,
    SUBFZE	= 1172,
    SUBFZE8	= 1173,
    SUBFZE8o	= 1174,
    SUBFZEo	= 1175,
    SUBFo	= 1176,
    SUBI	= 1177,
    SUBIC	= 1178,
    SUBICo	= 1179,
    SUBIS	= 1180,
    SYNC	= 1181,
    TABORT	= 1182,
    TABORTDC	= 1183,
    TABORTDCI	= 1184,
    TABORTWC	= 1185,
    TABORTWCI	= 1186,
    TAILB	= 1187,
    TAILB8	= 1188,
    TAILBA	= 1189,
    TAILBA8	= 1190,
    TAILBCTR	= 1191,
    TAILBCTR8	= 1192,
    TBEGIN	= 1193,
    TCHECK	= 1194,
    TCHECK_RET	= 1195,
    TCRETURNai	= 1196,
    TCRETURNai8	= 1197,
    TCRETURNdi	= 1198,
    TCRETURNdi8	= 1199,
    TCRETURNri	= 1200,
    TCRETURNri8	= 1201,
    TD	= 1202,
    TDI	= 1203,
    TEND	= 1204,
    TLBIA	= 1205,
    TLBIE	= 1206,
    TLBIEL	= 1207,
    TLBIVAX	= 1208,
    TLBLD	= 1209,
    TLBLI	= 1210,
    TLBRE	= 1211,
    TLBRE2	= 1212,
    TLBSX	= 1213,
    TLBSX2	= 1214,
    TLBSX2D	= 1215,
    TLBSYNC	= 1216,
    TLBWE	= 1217,
    TLBWE2	= 1218,
    TRAP	= 1219,
    TRECHKPT	= 1220,
    TRECLAIM	= 1221,
    TSR	= 1222,
    TW	= 1223,
    TWI	= 1224,
    UPDATE_VRSAVE	= 1225,
    UpdateGBR	= 1226,
    VADDCUQ	= 1227,
    VADDCUW	= 1228,
    VADDECUQ	= 1229,
    VADDEUQM	= 1230,
    VADDFP	= 1231,
    VADDSBS	= 1232,
    VADDSHS	= 1233,
    VADDSWS	= 1234,
    VADDUBM	= 1235,
    VADDUBS	= 1236,
    VADDUDM	= 1237,
    VADDUHM	= 1238,
    VADDUHS	= 1239,
    VADDUQM	= 1240,
    VADDUWM	= 1241,
    VADDUWS	= 1242,
    VAND	= 1243,
    VANDC	= 1244,
    VAVGSB	= 1245,
    VAVGSH	= 1246,
    VAVGSW	= 1247,
    VAVGUB	= 1248,
    VAVGUH	= 1249,
    VAVGUW	= 1250,
    VBPERMQ	= 1251,
    VCFSX	= 1252,
    VCFSX_0	= 1253,
    VCFUX	= 1254,
    VCFUX_0	= 1255,
    VCIPHER	= 1256,
    VCIPHERLAST	= 1257,
    VCLZB	= 1258,
    VCLZD	= 1259,
    VCLZH	= 1260,
    VCLZW	= 1261,
    VCMPBFP	= 1262,
    VCMPBFPo	= 1263,
    VCMPEQFP	= 1264,
    VCMPEQFPo	= 1265,
    VCMPEQUB	= 1266,
    VCMPEQUBo	= 1267,
    VCMPEQUD	= 1268,
    VCMPEQUDo	= 1269,
    VCMPEQUH	= 1270,
    VCMPEQUHo	= 1271,
    VCMPEQUW	= 1272,
    VCMPEQUWo	= 1273,
    VCMPGEFP	= 1274,
    VCMPGEFPo	= 1275,
    VCMPGTFP	= 1276,
    VCMPGTFPo	= 1277,
    VCMPGTSB	= 1278,
    VCMPGTSBo	= 1279,
    VCMPGTSD	= 1280,
    VCMPGTSDo	= 1281,
    VCMPGTSH	= 1282,
    VCMPGTSHo	= 1283,
    VCMPGTSW	= 1284,
    VCMPGTSWo	= 1285,
    VCMPGTUB	= 1286,
    VCMPGTUBo	= 1287,
    VCMPGTUD	= 1288,
    VCMPGTUDo	= 1289,
    VCMPGTUH	= 1290,
    VCMPGTUHo	= 1291,
    VCMPGTUW	= 1292,
    VCMPGTUWo	= 1293,
    VCTSXS	= 1294,
    VCTSXS_0	= 1295,
    VCTUXS	= 1296,
    VCTUXS_0	= 1297,
    VEQV	= 1298,
    VEXPTEFP	= 1299,
    VGBBD	= 1300,
    VLOGEFP	= 1301,
    VMADDFP	= 1302,
    VMAXFP	= 1303,
    VMAXSB	= 1304,
    VMAXSD	= 1305,
    VMAXSH	= 1306,
    VMAXSW	= 1307,
    VMAXUB	= 1308,
    VMAXUD	= 1309,
    VMAXUH	= 1310,
    VMAXUW	= 1311,
    VMHADDSHS	= 1312,
    VMHRADDSHS	= 1313,
    VMINFP	= 1314,
    VMINSB	= 1315,
    VMINSD	= 1316,
    VMINSH	= 1317,
    VMINSW	= 1318,
    VMINUB	= 1319,
    VMINUD	= 1320,
    VMINUH	= 1321,
    VMINUW	= 1322,
    VMLADDUHM	= 1323,
    VMRGEW	= 1324,
    VMRGHB	= 1325,
    VMRGHH	= 1326,
    VMRGHW	= 1327,
    VMRGLB	= 1328,
    VMRGLH	= 1329,
    VMRGLW	= 1330,
    VMRGOW	= 1331,
    VMSUMMBM	= 1332,
    VMSUMSHM	= 1333,
    VMSUMSHS	= 1334,
    VMSUMUBM	= 1335,
    VMSUMUHM	= 1336,
    VMSUMUHS	= 1337,
    VMULESB	= 1338,
    VMULESH	= 1339,
    VMULESW	= 1340,
    VMULEUB	= 1341,
    VMULEUH	= 1342,
    VMULEUW	= 1343,
    VMULOSB	= 1344,
    VMULOSH	= 1345,
    VMULOSW	= 1346,
    VMULOUB	= 1347,
    VMULOUH	= 1348,
    VMULOUW	= 1349,
    VMULUWM	= 1350,
    VNAND	= 1351,
    VNCIPHER	= 1352,
    VNCIPHERLAST	= 1353,
    VNMSUBFP	= 1354,
    VNOR	= 1355,
    VOR	= 1356,
    VORC	= 1357,
    VPERM	= 1358,
    VPERMXOR	= 1359,
    VPKPX	= 1360,
    VPKSDSS	= 1361,
    VPKSDUS	= 1362,
    VPKSHSS	= 1363,
    VPKSHUS	= 1364,
    VPKSWSS	= 1365,
    VPKSWUS	= 1366,
    VPKUDUM	= 1367,
    VPKUDUS	= 1368,
    VPKUHUM	= 1369,
    VPKUHUS	= 1370,
    VPKUWUM	= 1371,
    VPKUWUS	= 1372,
    VPMSUMB	= 1373,
    VPMSUMD	= 1374,
    VPMSUMH	= 1375,
    VPMSUMW	= 1376,
    VPOPCNTB	= 1377,
    VPOPCNTD	= 1378,
    VPOPCNTH	= 1379,
    VPOPCNTW	= 1380,
    VREFP	= 1381,
    VRFIM	= 1382,
    VRFIN	= 1383,
    VRFIP	= 1384,
    VRFIZ	= 1385,
    VRLB	= 1386,
    VRLD	= 1387,
    VRLH	= 1388,
    VRLW	= 1389,
    VRSQRTEFP	= 1390,
    VSBOX	= 1391,
    VSEL	= 1392,
    VSHASIGMAD	= 1393,
    VSHASIGMAW	= 1394,
    VSL	= 1395,
    VSLB	= 1396,
    VSLD	= 1397,
    VSLDOI	= 1398,
    VSLH	= 1399,
    VSLO	= 1400,
    VSLW	= 1401,
    VSPLTB	= 1402,
    VSPLTH	= 1403,
    VSPLTISB	= 1404,
    VSPLTISH	= 1405,
    VSPLTISW	= 1406,
    VSPLTW	= 1407,
    VSR	= 1408,
    VSRAB	= 1409,
    VSRAD	= 1410,
    VSRAH	= 1411,
    VSRAW	= 1412,
    VSRB	= 1413,
    VSRD	= 1414,
    VSRH	= 1415,
    VSRO	= 1416,
    VSRW	= 1417,
    VSUBCUQ	= 1418,
    VSUBCUW	= 1419,
    VSUBECUQ	= 1420,
    VSUBEUQM	= 1421,
    VSUBFP	= 1422,
    VSUBSBS	= 1423,
    VSUBSHS	= 1424,
    VSUBSWS	= 1425,
    VSUBUBM	= 1426,
    VSUBUBS	= 1427,
    VSUBUDM	= 1428,
    VSUBUHM	= 1429,
    VSUBUHS	= 1430,
    VSUBUQM	= 1431,
    VSUBUWM	= 1432,
    VSUBUWS	= 1433,
    VSUM2SWS	= 1434,
    VSUM4SBS	= 1435,
    VSUM4SHS	= 1436,
    VSUM4UBS	= 1437,
    VSUMSWS	= 1438,
    VUPKHPX	= 1439,
    VUPKHSB	= 1440,
    VUPKHSH	= 1441,
    VUPKHSW	= 1442,
    VUPKLPX	= 1443,
    VUPKLSB	= 1444,
    VUPKLSH	= 1445,
    VUPKLSW	= 1446,
    VXOR	= 1447,
    V_SET0	= 1448,
    V_SET0B	= 1449,
    V_SET0H	= 1450,
    V_SETALLONES	= 1451,
    V_SETALLONESB	= 1452,
    V_SETALLONESH	= 1453,
    WAIT	= 1454,
    WRTEE	= 1455,
    WRTEEI	= 1456,
    XOR	= 1457,
    XOR8	= 1458,
    XOR8o	= 1459,
    XORI	= 1460,
    XORI8	= 1461,
    XORIS	= 1462,
    XORIS8	= 1463,
    XORo	= 1464,
    XSABSDP	= 1465,
    XSADDDP	= 1466,
    XSADDSP	= 1467,
    XSCMPODP	= 1468,
    XSCMPUDP	= 1469,
    XSCPSGNDP	= 1470,
    XSCVDPSP	= 1471,
    XSCVDPSPN	= 1472,
    XSCVDPSXDS	= 1473,
    XSCVDPSXWS	= 1474,
    XSCVDPUXDS	= 1475,
    XSCVDPUXWS	= 1476,
    XSCVSPDP	= 1477,
    XSCVSPDPN	= 1478,
    XSCVSXDDP	= 1479,
    XSCVSXDSP	= 1480,
    XSCVUXDDP	= 1481,
    XSCVUXDSP	= 1482,
    XSDIVDP	= 1483,
    XSDIVSP	= 1484,
    XSMADDADP	= 1485,
    XSMADDASP	= 1486,
    XSMADDMDP	= 1487,
    XSMADDMSP	= 1488,
    XSMAXDP	= 1489,
    XSMINDP	= 1490,
    XSMSUBADP	= 1491,
    XSMSUBASP	= 1492,
    XSMSUBMDP	= 1493,
    XSMSUBMSP	= 1494,
    XSMULDP	= 1495,
    XSMULSP	= 1496,
    XSNABSDP	= 1497,
    XSNEGDP	= 1498,
    XSNMADDADP	= 1499,
    XSNMADDASP	= 1500,
    XSNMADDMDP	= 1501,
    XSNMADDMSP	= 1502,
    XSNMSUBADP	= 1503,
    XSNMSUBASP	= 1504,
    XSNMSUBMDP	= 1505,
    XSNMSUBMSP	= 1506,
    XSRDPI	= 1507,
    XSRDPIC	= 1508,
    XSRDPIM	= 1509,
    XSRDPIP	= 1510,
    XSRDPIZ	= 1511,
    XSREDP	= 1512,
    XSRESP	= 1513,
    XSRSQRTEDP	= 1514,
    XSRSQRTESP	= 1515,
    XSSQRTDP	= 1516,
    XSSQRTSP	= 1517,
    XSSUBDP	= 1518,
    XSSUBSP	= 1519,
    XSTDIVDP	= 1520,
    XSTSQRTDP	= 1521,
    XVABSDP	= 1522,
    XVABSSP	= 1523,
    XVADDDP	= 1524,
    XVADDSP	= 1525,
    XVCMPEQDP	= 1526,
    XVCMPEQDPo	= 1527,
    XVCMPEQSP	= 1528,
    XVCMPEQSPo	= 1529,
    XVCMPGEDP	= 1530,
    XVCMPGEDPo	= 1531,
    XVCMPGESP	= 1532,
    XVCMPGESPo	= 1533,
    XVCMPGTDP	= 1534,
    XVCMPGTDPo	= 1535,
    XVCMPGTSP	= 1536,
    XVCMPGTSPo	= 1537,
    XVCPSGNDP	= 1538,
    XVCPSGNSP	= 1539,
    XVCVDPSP	= 1540,
    XVCVDPSXDS	= 1541,
    XVCVDPSXWS	= 1542,
    XVCVDPUXDS	= 1543,
    XVCVDPUXWS	= 1544,
    XVCVSPDP	= 1545,
    XVCVSPSXDS	= 1546,
    XVCVSPSXWS	= 1547,
    XVCVSPUXDS	= 1548,
    XVCVSPUXWS	= 1549,
    XVCVSXDDP	= 1550,
    XVCVSXDSP	= 1551,
    XVCVSXWDP	= 1552,
    XVCVSXWSP	= 1553,
    XVCVUXDDP	= 1554,
    XVCVUXDSP	= 1555,
    XVCVUXWDP	= 1556,
    XVCVUXWSP	= 1557,
    XVDIVDP	= 1558,
    XVDIVSP	= 1559,
    XVMADDADP	= 1560,
    XVMADDASP	= 1561,
    XVMADDMDP	= 1562,
    XVMADDMSP	= 1563,
    XVMAXDP	= 1564,
    XVMAXSP	= 1565,
    XVMINDP	= 1566,
    XVMINSP	= 1567,
    XVMSUBADP	= 1568,
    XVMSUBASP	= 1569,
    XVMSUBMDP	= 1570,
    XVMSUBMSP	= 1571,
    XVMULDP	= 1572,
    XVMULSP	= 1573,
    XVNABSDP	= 1574,
    XVNABSSP	= 1575,
    XVNEGDP	= 1576,
    XVNEGSP	= 1577,
    XVNMADDADP	= 1578,
    XVNMADDASP	= 1579,
    XVNMADDMDP	= 1580,
    XVNMADDMSP	= 1581,
    XVNMSUBADP	= 1582,
    XVNMSUBASP	= 1583,
    XVNMSUBMDP	= 1584,
    XVNMSUBMSP	= 1585,
    XVRDPI	= 1586,
    XVRDPIC	= 1587,
    XVRDPIM	= 1588,
    XVRDPIP	= 1589,
    XVRDPIZ	= 1590,
    XVREDP	= 1591,
    XVRESP	= 1592,
    XVRSPI	= 1593,
    XVRSPIC	= 1594,
    XVRSPIM	= 1595,
    XVRSPIP	= 1596,
    XVRSPIZ	= 1597,
    XVRSQRTEDP	= 1598,
    XVRSQRTESP	= 1599,
    XVSQRTDP	= 1600,
    XVSQRTSP	= 1601,
    XVSUBDP	= 1602,
    XVSUBSP	= 1603,
    XVTDIVDP	= 1604,
    XVTDIVSP	= 1605,
    XVTSQRTDP	= 1606,
    XVTSQRTSP	= 1607,
    XXLAND	= 1608,
    XXLANDC	= 1609,
    XXLEQV	= 1610,
    XXLNAND	= 1611,
    XXLNOR	= 1612,
    XXLOR	= 1613,
    XXLORC	= 1614,
    XXLORf	= 1615,
    XXLXOR	= 1616,
    XXMRGHW	= 1617,
    XXMRGLW	= 1618,
    XXPERMDI	= 1619,
    XXSEL	= 1620,
    XXSLDWI	= 1621,
    XXSPLTW	= 1622,
    gBC	= 1623,
    gBCA	= 1624,
    gBCCTR	= 1625,
    gBCCTRL	= 1626,
    gBCL	= 1627,
    gBCLA	= 1628,
    gBCLR	= 1629,
    gBCLRL	= 1630,
    INSTRUCTION_LIST_END = 1631
  };

namespace Sched {
  enum {
    NoInstrModel	= 0,
    IIC_IntSimple	= 1,
    IIC_IntGeneral	= 2,
    IIC_BrB	= 3,
    IIC_VecFP	= 4,
    IIC_IntCompare	= 5,
    IIC_BrCR	= 6,
    IIC_LdStDCBF	= 7,
    IIC_LdStLoad	= 8,
    IIC_IntDivD	= 9,
    IIC_IntDivW	= 10,
    IIC_FPGeneral	= 11,
    IIC_FPAddSub	= 12,
    IIC_FPCompare	= 13,
    IIC_FPDivD	= 14,
    IIC_FPDivS	= 15,
    IIC_FPFused	= 16,
    IIC_FPSqrtD	= 17,
    IIC_FPSqrtS	= 18,
    IIC_LdStICBI	= 19,
    IIC_IntISEL	= 20,
    IIC_SprISYNC	= 21,
    IIC_LdStLWARX	= 22,
    IIC_LdStLoadUpd	= 23,
    IIC_LdStLoadUpdX	= 24,
    IIC_LdStLD	= 25,
    IIC_LdStLDARX	= 26,
    IIC_LdStLDU	= 27,
    IIC_LdStLDUX	= 28,
    IIC_LdStLFD	= 29,
    IIC_LdStLFDU	= 30,
    IIC_LdStLFDUX	= 31,
    IIC_LdStLHA	= 32,
    IIC_LdStLHAU	= 33,
    IIC_LdStLHAUX	= 34,
    IIC_LdStLMW	= 35,
    IIC_LdStLWA	= 36,
    IIC_BrMCR	= 37,
    IIC_SprMFCR	= 38,
    IIC_SprMFSPR	= 39,
    IIC_IntMFFS	= 40,
    IIC_SprMFMSR	= 41,
    IIC_SprMFCRF	= 42,
    IIC_SprMFSR	= 43,
    IIC_SprMFTB	= 44,
    IIC_LdStStore	= 45,
    IIC_VecGeneral	= 46,
    IIC_LdStSync	= 47,
    IIC_BrMCRX	= 48,
    IIC_SprMTSPR	= 49,
    IIC_IntMTFSB0	= 50,
    IIC_SprMTMSR	= 51,
    IIC_SprMTMSRD	= 52,
    IIC_SprMTSR	= 53,
    IIC_IntMulHW	= 54,
    IIC_IntMulHWU	= 55,
    IIC_IntMulHD	= 56,
    IIC_IntMulLI	= 57,
    IIC_VecPerm	= 58,
    IIC_LdStSTFD	= 59,
    IIC_LdStSTFDU	= 60,
    IIC_SprRFI	= 61,
    IIC_IntRFID	= 62,
    IIC_IntRotateD	= 63,
    IIC_IntRotateDI	= 64,
    IIC_IntRotate	= 65,
    IIC_SprSLBIA	= 66,
    IIC_SprSLBIE	= 67,
    IIC_SprSLBMFEE	= 68,
    IIC_SprSLBMTE	= 69,
    IIC_IntShift	= 70,
    IIC_LdStSTWCX	= 71,
    IIC_LdStStoreUpd	= 72,
    IIC_LdStSTD	= 73,
    IIC_LdStSTDCX	= 74,
    IIC_LdStSTDU	= 75,
    IIC_LdStSTDUX	= 76,
    IIC_IntTrapD	= 77,
    IIC_SprTLBIA	= 78,
    IIC_SprTLBIE	= 79,
    IIC_SprTLBIEL	= 80,
    IIC_SprTLBSYNC	= 81,
    IIC_IntTrapW	= 82,
    IIC_VecFPCompare	= 83,
    SCHED_LIST_END = 84
  };
} // end Sched namespace
} // end PPC namespace
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

static const MCPhysReg ImplicitList1[] = { PPC::CR0, 0 };
static const MCPhysReg ImplicitList2[] = { PPC::CARRY, 0 };
static const MCPhysReg ImplicitList3[] = { PPC::CARRY, PPC::CR0, 0 };
static const MCPhysReg ImplicitList4[] = { PPC::X0, PPC::X3, PPC::X4, PPC::X5, PPC::X6, PPC::X7, PPC::X8, PPC::X9, PPC::X10, PPC::X11, PPC::X12, PPC::LR8, PPC::CTR8, PPC::CR0, PPC::CR1, PPC::CR5, PPC::CR6, PPC::CR7, 0 };
static const MCPhysReg ImplicitList5[] = { PPC::R0, PPC::R3, PPC::R4, PPC::R5, PPC::R6, PPC::R7, PPC::R8, PPC::R9, PPC::R10, PPC::R11, PPC::R12, PPC::LR, PPC::CTR, PPC::CR0, PPC::CR1, PPC::CR5, PPC::CR6, PPC::CR7, 0 };
static const MCPhysReg ImplicitList6[] = { PPC::R1, 0 };
static const MCPhysReg ImplicitList7[] = { PPC::CTR, 0 };
static const MCPhysReg ImplicitList8[] = { PPC::CTR8, 0 };
static const MCPhysReg ImplicitList9[] = { PPC::CTR, PPC::RM, 0 };
static const MCPhysReg ImplicitList10[] = { PPC::LR, 0 };
static const MCPhysReg ImplicitList11[] = { PPC::CTR8, PPC::RM, 0 };
static const MCPhysReg ImplicitList12[] = { PPC::LR8, 0 };
static const MCPhysReg ImplicitList13[] = { PPC::RM, 0 };
static const MCPhysReg ImplicitList14[] = { PPC::LR, PPC::RM, 0 };
static const MCPhysReg ImplicitList15[] = { PPC::LR8, PPC::X2, 0 };
static const MCPhysReg ImplicitList16[] = { PPC::CTR, PPC::LR, PPC::RM, 0 };
static const MCPhysReg ImplicitList17[] = { PPC::CTR8, PPC::LR8, PPC::RM, 0 };
static const MCPhysReg ImplicitList18[] = { PPC::LR8, PPC::RM, 0 };
static const MCPhysReg ImplicitList19[] = { PPC::CR1EQ, 0 };
static const MCPhysReg ImplicitList20[] = { PPC::X1, 0 };
static const MCPhysReg ImplicitList21[] = { PPC::CR1, 0 };
static const MCPhysReg ImplicitList22[] = { PPC::X0, PPC::X4, PPC::X5, PPC::X6, PPC::X7, PPC::X8, PPC::X9, PPC::X10, PPC::X11, PPC::X12, PPC::LR8, PPC::CTR8, PPC::CR0, PPC::CR1, PPC::CR5, PPC::CR6, PPC::CR7, 0 };
static const MCPhysReg ImplicitList23[] = { PPC::R0, PPC::R4, PPC::R5, PPC::R6, PPC::R7, PPC::R8, PPC::R9, PPC::R10, PPC::R11, PPC::R12, PPC::LR, PPC::CTR, PPC::CR0, PPC::CR1, PPC::CR5, PPC::CR6, PPC::CR7, 0 };
static const MCPhysReg ImplicitList24[] = { PPC::CR6, 0 };
static const MCPhysReg ImplicitList25[] = { PPC::LR, PPC::CTR, 0 };

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
static const MCOperandInfo OperandInfo13[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo14[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo15[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo16[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo17[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo18[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo19[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo20[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo21[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo22[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo23[] = { { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo24[] = { { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo25[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo26[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo27[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo28[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo29[] = { { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo30[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo31[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo32[] = { { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo35[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo46[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo50[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo53[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo54[] = { { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo55[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo56[] = { { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo57[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo58[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo59[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo60[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo61[] = { { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo62[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo63[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo64[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo65[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo66[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo67[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo68[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo69[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo70[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo71[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo72[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo73[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo74[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo75[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo76[] = { { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo77[] = { { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo78[] = { { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo79[] = { { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo80[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo81[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo82[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo83[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo84[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo85[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo86[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo87[] = { { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo88[] = { { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo89[] = { { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo90[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo91[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo92[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo93[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo94[] = { { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo95[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo96[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRSAVERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo97[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo98[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo99[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo100[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo101[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo102[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo103[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo104[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo105[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo106[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo107[] = { { PPC::VRSAVERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo108[] = { { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo109[] = { { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo110[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo111[] = { { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo112[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo113[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo114[] = { { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo115[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo116[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo117[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo118[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo119[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo120[] = { { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo121[] = { { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo122[] = { { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo123[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo124[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo125[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo126[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo127[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo128[] = { { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo129[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo130[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo131[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo132[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo133[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo134[] = { { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo135[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo136[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo137[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo138[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo139[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo140[] = { { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo141[] = { { PPC::VRSAVERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo142[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo143[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo144[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo145[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo146[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo147[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo148[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo149[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo150[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo151[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo152[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo153[] = { { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo154[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo155[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo156[] = { { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo157[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo158[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo159[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo160[] = { { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo161[] = { { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo162[] = { { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo163[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo164[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo165[] = { { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QBRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo166[] = { { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo167[] = { { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::QSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo168[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo169[] = { { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo170[] = { { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo171[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo172[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo173[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo174[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo175[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo176[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo177[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo178[] = { { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo179[] = { { PPC::CRRC0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo180[] = { { PPC::CRRC0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo181[] = { { PPC::CRRC0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo182[] = { { PPC::CRRC0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo183[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo184[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo185[] = { { PPC::CTRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo186[] = { { PPC::CTRRC8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo187[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo188[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo189[] = { { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo190[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo191[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo192[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo193[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo194[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo195[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo196[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo197[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo198[] = { { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo199[] = { { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo200[] = { { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo201[] = { { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo202[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo203[] = { { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo204[] = { { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo205[] = { { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo206[] = { { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo207[] = { { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo208[] = { { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo209[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo210[] = { { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo211[] = { { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo212[] = { { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo213[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo214[] = { { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo215[] = { { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo216[] = { { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo217[] = { { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo218[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo219[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };

extern const MCInstrDesc PPCInsts[] = {
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
  { 24,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #24 = ADD4
  { 25,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #25 = ADD4TLS
  { 26,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #26 = ADD4o
  { 27,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #27 = ADD8
  { 28,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #28 = ADD8TLS
  { 29,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #29 = ADD8TLS_
  { 30,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #30 = ADD8o
  { 31,	3,	1,	4,	2,	0|(1ULL<<MCID::Commutable), 0xcULL, nullptr, ImplicitList2, OperandInfo13, -1 ,nullptr },  // Inst #31 = ADDC
  { 32,	3,	1,	4,	2,	0|(1ULL<<MCID::Commutable), 0xcULL, nullptr, ImplicitList2, OperandInfo15, -1 ,nullptr },  // Inst #32 = ADDC8
  { 33,	3,	1,	4,	2,	0|(1ULL<<MCID::Commutable), 0xcULL, nullptr, ImplicitList3, OperandInfo15, -1 ,nullptr },  // Inst #33 = ADDC8o
  { 34,	3,	1,	4,	2,	0|(1ULL<<MCID::Commutable), 0xcULL, nullptr, ImplicitList3, OperandInfo13, -1 ,nullptr },  // Inst #34 = ADDCo
  { 35,	3,	1,	4,	2,	0|(1ULL<<MCID::Commutable), 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo13, -1 ,nullptr },  // Inst #35 = ADDE
  { 36,	3,	1,	4,	2,	0|(1ULL<<MCID::Commutable), 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo15, -1 ,nullptr },  // Inst #36 = ADDE8
  { 37,	3,	1,	4,	2,	0|(1ULL<<MCID::Commutable), 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo15, -1 ,nullptr },  // Inst #37 = ADDE8o
  { 38,	3,	1,	4,	2,	0|(1ULL<<MCID::Commutable), 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo13, -1 ,nullptr },  // Inst #38 = ADDEo
  { 39,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #39 = ADDI
  { 40,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #40 = ADDI8
  { 41,	3,	1,	4,	2,	0, 0xcULL, nullptr, ImplicitList2, OperandInfo14, -1 ,nullptr },  // Inst #41 = ADDIC
  { 42,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList2, OperandInfo16, -1 ,nullptr },  // Inst #42 = ADDIC8
  { 43,	3,	1,	4,	2,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL, nullptr, ImplicitList3, OperandInfo14, -1 ,nullptr },  // Inst #43 = ADDICo
  { 44,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #44 = ADDIS
  { 45,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #45 = ADDIS8
  { 46,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #46 = ADDISdtprelHA
  { 47,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #47 = ADDISdtprelHA32
  { 48,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #48 = ADDISgotTprelHA
  { 49,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #49 = ADDIStlsgdHA
  { 50,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #50 = ADDIStlsldHA
  { 51,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #51 = ADDIStocHA
  { 52,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #52 = ADDIdtprelL
  { 53,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #53 = ADDIdtprelL32
  { 54,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #54 = ADDItlsgdL
  { 55,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #55 = ADDItlsgdL32
  { 56,	4,	1,	4,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList4, OperandInfo19, -1 ,nullptr },  // Inst #56 = ADDItlsgdLADDR
  { 57,	4,	1,	4,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList5, OperandInfo20, -1 ,nullptr },  // Inst #57 = ADDItlsgdLADDR32
  { 58,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #58 = ADDItlsldL
  { 59,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #59 = ADDItlsldL32
  { 60,	4,	1,	4,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList4, OperandInfo19, -1 ,nullptr },  // Inst #60 = ADDItlsldLADDR
  { 61,	4,	1,	4,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList5, OperandInfo20, -1 ,nullptr },  // Inst #61 = ADDItlsldLADDR32
  { 62,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #62 = ADDItocL
  { 63,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo21, -1 ,nullptr },  // Inst #63 = ADDME
  { 64,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo22, -1 ,nullptr },  // Inst #64 = ADDME8
  { 65,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo22, -1 ,nullptr },  // Inst #65 = ADDME8o
  { 66,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo21, -1 ,nullptr },  // Inst #66 = ADDMEo
  { 67,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo21, -1 ,nullptr },  // Inst #67 = ADDZE
  { 68,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo22, -1 ,nullptr },  // Inst #68 = ADDZE8
  { 69,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo22, -1 ,nullptr },  // Inst #69 = ADDZE8o
  { 70,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo21, -1 ,nullptr },  // Inst #70 = ADDZEo
  { 71,	1,	0,	4,	0,	0, 0x0ULL, ImplicitList6, ImplicitList6, OperandInfo5, -1 ,nullptr },  // Inst #71 = ADJCALLSTACKDOWN
  { 72,	2,	0,	4,	0,	0, 0x0ULL, ImplicitList6, ImplicitList6, OperandInfo7, -1 ,nullptr },  // Inst #72 = ADJCALLSTACKUP
  { 73,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #73 = AND
  { 74,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #74 = AND8
  { 75,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #75 = AND8o
  { 76,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #76 = ANDC
  { 77,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #77 = ANDC8
  { 78,	3,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #78 = ANDC8o
  { 79,	3,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #79 = ANDCo
  { 80,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #80 = ANDISo
  { 81,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #81 = ANDISo8
  { 82,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #82 = ANDIo
  { 83,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #83 = ANDIo8
  { 84,	2,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #84 = ANDIo_1_EQ_BIT
  { 85,	2,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #85 = ANDIo_1_EQ_BIT8
  { 86,	2,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #86 = ANDIo_1_GT_BIT
  { 87,	2,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #87 = ANDIo_1_GT_BIT8
  { 88,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #88 = ANDo
  { 89,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #89 = ATOMIC_CMP_SWAP_I16
  { 90,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #90 = ATOMIC_CMP_SWAP_I32
  { 91,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #91 = ATOMIC_CMP_SWAP_I64
  { 92,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #92 = ATOMIC_CMP_SWAP_I8
  { 93,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #93 = ATOMIC_LOAD_ADD_I16
  { 94,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #94 = ATOMIC_LOAD_ADD_I32
  { 95,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #95 = ATOMIC_LOAD_ADD_I64
  { 96,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #96 = ATOMIC_LOAD_ADD_I8
  { 97,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #97 = ATOMIC_LOAD_AND_I16
  { 98,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #98 = ATOMIC_LOAD_AND_I32
  { 99,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #99 = ATOMIC_LOAD_AND_I64
  { 100,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #100 = ATOMIC_LOAD_AND_I8
  { 101,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #101 = ATOMIC_LOAD_NAND_I16
  { 102,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #102 = ATOMIC_LOAD_NAND_I32
  { 103,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #103 = ATOMIC_LOAD_NAND_I64
  { 104,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #104 = ATOMIC_LOAD_NAND_I8
  { 105,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #105 = ATOMIC_LOAD_OR_I16
  { 106,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #106 = ATOMIC_LOAD_OR_I32
  { 107,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #107 = ATOMIC_LOAD_OR_I64
  { 108,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #108 = ATOMIC_LOAD_OR_I8
  { 109,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #109 = ATOMIC_LOAD_SUB_I16
  { 110,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #110 = ATOMIC_LOAD_SUB_I32
  { 111,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #111 = ATOMIC_LOAD_SUB_I64
  { 112,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #112 = ATOMIC_LOAD_SUB_I8
  { 113,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #113 = ATOMIC_LOAD_XOR_I16
  { 114,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #114 = ATOMIC_LOAD_XOR_I32
  { 115,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #115 = ATOMIC_LOAD_XOR_I64
  { 116,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #116 = ATOMIC_LOAD_XOR_I8
  { 117,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #117 = ATOMIC_SWAP_I16
  { 118,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #118 = ATOMIC_SWAP_I32
  { 119,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #119 = ATOMIC_SWAP_I64
  { 120,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #120 = ATOMIC_SWAP_I8
  { 121,	0,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #121 = ATTN
  { 122,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x38ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #122 = B
  { 123,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #123 = BA
  { 124,	2,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #124 = BC
  { 125,	3,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #125 = BCC
  { 126,	3,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #126 = BCCA
  { 127,	2,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #127 = BCCCTR
  { 128,	2,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList8, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #128 = BCCCTR8
  { 129,	2,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList10, OperandInfo31, -1 ,nullptr },  // Inst #129 = BCCCTRL
  { 130,	2,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList11, ImplicitList12, OperandInfo31, -1 ,nullptr },  // Inst #130 = BCCCTRL8
  { 131,	3,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, ImplicitList10, OperandInfo30, -1 ,nullptr },  // Inst #131 = BCCL
  { 132,	3,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, ImplicitList10, OperandInfo30, -1 ,nullptr },  // Inst #132 = BCCLA
  { 133,	2,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList14, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #133 = BCCLR
  { 134,	2,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList14, ImplicitList10, OperandInfo31, -1 ,nullptr },  // Inst #134 = BCCLRL
  { 135,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #135 = BCCTR
  { 136,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList8, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #136 = BCCTR8
  { 137,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList8, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #137 = BCCTR8n
  { 138,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList10, OperandInfo32, -1 ,nullptr },  // Inst #138 = BCCTRL
  { 139,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList11, ImplicitList12, OperandInfo32, -1 ,nullptr },  // Inst #139 = BCCTRL8
  { 140,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList11, ImplicitList12, OperandInfo32, -1 ,nullptr },  // Inst #140 = BCCTRL8n
  { 141,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList10, OperandInfo32, -1 ,nullptr },  // Inst #141 = BCCTRLn
  { 142,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #142 = BCCTRn
  { 143,	2,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, ImplicitList10, OperandInfo29, -1 ,nullptr },  // Inst #143 = BCL
  { 144,	1,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList14, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #144 = BCLR
  { 145,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList14, ImplicitList10, OperandInfo32, -1 ,nullptr },  // Inst #145 = BCLRL
  { 146,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList14, ImplicitList10, OperandInfo32, -1 ,nullptr },  // Inst #146 = BCLRLn
  { 147,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #147 = BCLRn
  { 148,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, ImplicitList10, OperandInfo5, -1 ,nullptr },  // Inst #148 = BCLalways
  { 149,	2,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, ImplicitList10, OperandInfo29, -1 ,nullptr },  // Inst #149 = BCLn
  { 150,	0,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, nullptr, nullptr, -1 ,nullptr },  // Inst #150 = BCTR
  { 151,	0,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList8, nullptr, nullptr, -1 ,nullptr },  // Inst #151 = BCTR8
  { 152,	0,	0,	4,	3,	0|(1ULL<<MCID::Call), 0x38ULL, ImplicitList9, ImplicitList10, nullptr, -1 ,nullptr },  // Inst #152 = BCTRL
  { 153,	0,	0,	4,	3,	0|(1ULL<<MCID::Call), 0x38ULL, ImplicitList11, ImplicitList12, nullptr, -1 ,nullptr },  // Inst #153 = BCTRL8
  { 154,	2,	0,	8,	3,	0|(1ULL<<MCID::Call), 0x38ULL, ImplicitList11, ImplicitList15, OperandInfo33, -1 ,nullptr },  // Inst #154 = BCTRL8_LDinto_toc
  { 155,	2,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #155 = BCn
  { 156,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #156 = BDNZ
  { 157,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList8, ImplicitList8, OperandInfo5, -1 ,nullptr },  // Inst #157 = BDNZ8
  { 158,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #158 = BDNZA
  { 159,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #159 = BDNZAm
  { 160,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #160 = BDNZAp
  { 161,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #161 = BDNZL
  { 162,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #162 = BDNZLA
  { 163,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #163 = BDNZLAm
  { 164,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #164 = BDNZLAp
  { 165,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #165 = BDNZLR
  { 166,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList17, ImplicitList8, nullptr, -1 ,nullptr },  // Inst #166 = BDNZLR8
  { 167,	0,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #167 = BDNZLRL
  { 168,	0,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #168 = BDNZLRLm
  { 169,	0,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #169 = BDNZLRLp
  { 170,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #170 = BDNZLRm
  { 171,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #171 = BDNZLRp
  { 172,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #172 = BDNZLm
  { 173,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #173 = BDNZLp
  { 174,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #174 = BDNZm
  { 175,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #175 = BDNZp
  { 176,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #176 = BDZ
  { 177,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList8, ImplicitList8, OperandInfo5, -1 ,nullptr },  // Inst #177 = BDZ8
  { 178,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #178 = BDZA
  { 179,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #179 = BDZAm
  { 180,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #180 = BDZAp
  { 181,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #181 = BDZL
  { 182,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #182 = BDZLA
  { 183,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #183 = BDZLAm
  { 184,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #184 = BDZLAp
  { 185,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #185 = BDZLR
  { 186,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList17, ImplicitList8, nullptr, -1 ,nullptr },  // Inst #186 = BDZLR8
  { 187,	0,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #187 = BDZLRL
  { 188,	0,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #188 = BDZLRLm
  { 189,	0,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #189 = BDZLRLp
  { 190,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #190 = BDZLRm
  { 191,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #191 = BDZLRp
  { 192,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #192 = BDZLm
  { 193,	1,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #193 = BDZLp
  { 194,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #194 = BDZm
  { 195,	1,	0,	4,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList7, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #195 = BDZp
  { 196,	1,	0,	4,	3,	0|(1ULL<<MCID::Call), 0x38ULL, ImplicitList13, ImplicitList10, OperandInfo5, -1 ,nullptr },  // Inst #196 = BL
  { 197,	1,	0,	4,	3,	0|(1ULL<<MCID::Call), 0x38ULL, ImplicitList13, ImplicitList12, OperandInfo5, -1 ,nullptr },  // Inst #197 = BL8
  { 198,	1,	0,	8,	3,	0|(1ULL<<MCID::Call), 0x38ULL, ImplicitList13, ImplicitList12, OperandInfo5, -1 ,nullptr },  // Inst #198 = BL8_NOP
  { 199,	2,	0,	8,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, ImplicitList12, OperandInfo7, -1 ,nullptr },  // Inst #199 = BL8_NOP_TLS
  { 200,	2,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, ImplicitList12, OperandInfo7, -1 ,nullptr },  // Inst #200 = BL8_TLS
  { 201,	2,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, ImplicitList12, OperandInfo7, -1 ,nullptr },  // Inst #201 = BL8_TLS_
  { 202,	1,	0,	4,	3,	0|(1ULL<<MCID::Call), 0x38ULL, ImplicitList13, ImplicitList10, OperandInfo5, -1 ,nullptr },  // Inst #202 = BLA
  { 203,	1,	0,	4,	3,	0|(1ULL<<MCID::Call), 0x38ULL, ImplicitList13, ImplicitList12, OperandInfo5, -1 ,nullptr },  // Inst #203 = BLA8
  { 204,	1,	0,	8,	3,	0|(1ULL<<MCID::Call), 0x38ULL, ImplicitList13, ImplicitList12, OperandInfo5, -1 ,nullptr },  // Inst #204 = BLA8_NOP
  { 205,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x38ULL, ImplicitList14, nullptr, nullptr, -1 ,nullptr },  // Inst #205 = BLR
  { 206,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x38ULL, ImplicitList18, nullptr, nullptr, -1 ,nullptr },  // Inst #206 = BLR8
  { 207,	0,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList14, ImplicitList10, nullptr, -1 ,nullptr },  // Inst #207 = BLRL
  { 208,	2,	0,	4,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, ImplicitList10, OperandInfo7, -1 ,nullptr },  // Inst #208 = BL_TLS
  { 209,	3,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #209 = BPERMD
  { 210,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #210 = BRINC
  { 211,	0,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #211 = CLRBHRB
  { 212,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #212 = CLRLSLDI
  { 213,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #213 = CLRLSLDIo
  { 214,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #214 = CLRLSLWI
  { 215,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #215 = CLRLSLWIo
  { 216,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #216 = CLRRDI
  { 217,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #217 = CLRRDIo
  { 218,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #218 = CLRRWI
  { 219,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #219 = CLRRWIo
  { 220,	3,	1,	4,	2,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #220 = CMPB
  { 221,	3,	1,	4,	2,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #221 = CMPB8
  { 222,	3,	1,	4,	5,	0|(1ULL<<MCID::Compare), 0x8ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #222 = CMPD
  { 223,	3,	1,	4,	5,	0|(1ULL<<MCID::Compare), 0x8ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #223 = CMPDI
  { 224,	3,	1,	4,	5,	0|(1ULL<<MCID::Compare), 0x8ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #224 = CMPLD
  { 225,	3,	1,	4,	5,	0|(1ULL<<MCID::Compare), 0x8ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #225 = CMPLDI
  { 226,	3,	1,	4,	5,	0|(1ULL<<MCID::Compare), 0x8ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #226 = CMPLW
  { 227,	3,	1,	4,	5,	0|(1ULL<<MCID::Compare), 0x8ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #227 = CMPLWI
  { 228,	3,	1,	4,	5,	0|(1ULL<<MCID::Compare), 0x8ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #228 = CMPW
  { 229,	3,	1,	4,	5,	0|(1ULL<<MCID::Compare), 0x8ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #229 = CMPWI
  { 230,	2,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #230 = CNTLZD
  { 231,	2,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #231 = CNTLZDo
  { 232,	2,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #232 = CNTLZW
  { 233,	2,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #233 = CNTLZW8
  { 234,	2,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #234 = CNTLZW8o
  { 235,	2,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #235 = CNTLZWo
  { 236,	0,	0,	4,	6,	0, 0x0ULL, nullptr, ImplicitList19, nullptr, -1 ,nullptr },  // Inst #236 = CR6SET
  { 237,	0,	0,	4,	6,	0, 0x0ULL, nullptr, ImplicitList19, nullptr, -1 ,nullptr },  // Inst #237 = CR6UNSET
  { 238,	3,	1,	4,	6,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #238 = CRAND
  { 239,	3,	1,	4,	6,	0, 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #239 = CRANDC
  { 240,	3,	1,	4,	6,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #240 = CREQV
  { 241,	3,	1,	4,	6,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #241 = CRNAND
  { 242,	3,	1,	4,	6,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #242 = CRNOR
  { 243,	3,	1,	4,	6,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #243 = CROR
  { 244,	3,	1,	4,	6,	0, 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #244 = CRORC
  { 245,	1,	1,	4,	6,	0, 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #245 = CRSET
  { 246,	1,	1,	4,	6,	0, 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #246 = CRUNSET
  { 247,	3,	1,	4,	6,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #247 = CRXOR
  { 248,	2,	0,	4,	7,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #248 = DCBA
  { 249,	2,	0,	4,	7,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #249 = DCBF
  { 250,	2,	0,	4,	7,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #250 = DCBI
  { 251,	2,	0,	4,	7,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #251 = DCBST
  { 252,	3,	0,	4,	7,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #252 = DCBT
  { 253,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #253 = DCBTCT
  { 254,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #254 = DCBTDS
  { 255,	3,	0,	4,	7,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x2ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #255 = DCBTST
  { 256,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #256 = DCBTSTCT
  { 257,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #257 = DCBTSTDS
  { 258,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #258 = DCBTSTT
  { 259,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #259 = DCBTSTx
  { 260,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #260 = DCBTT
  { 261,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #261 = DCBTx
  { 262,	2,	0,	4,	7,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #262 = DCBZ
  { 263,	2,	0,	4,	7,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #263 = DCBZL
  { 264,	2,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #264 = DCCCI
  { 265,	3,	1,	4,	9,	0, 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #265 = DIVD
  { 266,	3,	1,	4,	9,	0, 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #266 = DIVDE
  { 267,	3,	1,	4,	9,	0, 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #267 = DIVDEU
  { 268,	3,	1,	4,	9,	0, 0xdULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #268 = DIVDEUo
  { 269,	3,	1,	4,	9,	0, 0xdULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #269 = DIVDEo
  { 270,	3,	1,	4,	9,	0, 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #270 = DIVDU
  { 271,	3,	1,	4,	9,	0, 0xdULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #271 = DIVDUo
  { 272,	3,	1,	4,	9,	0, 0xdULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #272 = DIVDo
  { 273,	3,	1,	4,	10,	0, 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #273 = DIVW
  { 274,	3,	1,	4,	10,	0, 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #274 = DIVWE
  { 275,	3,	1,	4,	10,	0, 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #275 = DIVWEU
  { 276,	3,	1,	4,	10,	0, 0xdULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #276 = DIVWEUo
  { 277,	3,	1,	4,	10,	0, 0xdULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #277 = DIVWEo
  { 278,	3,	1,	4,	10,	0, 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #278 = DIVWU
  { 279,	3,	1,	4,	10,	0, 0xdULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #279 = DIVWUo
  { 280,	3,	1,	4,	10,	0, 0xdULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #280 = DIVWo
  { 281,	1,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, PPC::DeprecatedDST ,nullptr },  // Inst #281 = DSS
  { 282,	0,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, PPC::DeprecatedDST ,nullptr },  // Inst #282 = DSSALL
  { 283,	3,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo44, PPC::DeprecatedDST ,nullptr },  // Inst #283 = DST
  { 284,	3,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo45, PPC::DeprecatedDST ,nullptr },  // Inst #284 = DST64
  { 285,	3,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo44, PPC::DeprecatedDST ,nullptr },  // Inst #285 = DSTST
  { 286,	3,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo45, PPC::DeprecatedDST ,nullptr },  // Inst #286 = DSTST64
  { 287,	3,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo44, PPC::DeprecatedDST ,nullptr },  // Inst #287 = DSTSTT
  { 288,	3,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo45, PPC::DeprecatedDST ,nullptr },  // Inst #288 = DSTSTT64
  { 289,	3,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo44, PPC::DeprecatedDST ,nullptr },  // Inst #289 = DSTT
  { 290,	3,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo45, PPC::DeprecatedDST ,nullptr },  // Inst #290 = DSTT64
  { 291,	4,	1,	4,	0,	0, 0x0ULL, ImplicitList6, ImplicitList6, OperandInfo46, -1 ,nullptr },  // Inst #291 = DYNALLOC
  { 292,	4,	1,	4,	0,	0, 0x0ULL, ImplicitList20, ImplicitList20, OperandInfo47, -1 ,nullptr },  // Inst #292 = DYNALLOC8
  { 293,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #293 = DYNAREAOFFSET
  { 294,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #294 = DYNAREAOFFSET8
  { 295,	1,	0,	4,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo10, -1 ,nullptr },  // Inst #295 = EH_SjLj_LongJmp32
  { 296,	1,	0,	4,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo10, -1 ,nullptr },  // Inst #296 = EH_SjLj_LongJmp64
  { 297,	2,	1,	4,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList7, OperandInfo49, -1 ,nullptr },  // Inst #297 = EH_SjLj_SetJmp32
  { 298,	2,	1,	4,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList8, OperandInfo49, -1 ,nullptr },  // Inst #298 = EH_SjLj_SetJmp64
  { 299,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #299 = EH_SjLj_Setup
  { 300,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #300 = EQV
  { 301,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #301 = EQV8
  { 302,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #302 = EQV8o
  { 303,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #303 = EQVo
  { 304,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #304 = EVABS
  { 305,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #305 = EVADDIW
  { 306,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #306 = EVADDSMIAAW
  { 307,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #307 = EVADDSSIAAW
  { 308,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #308 = EVADDUMIAAW
  { 309,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #309 = EVADDUSIAAW
  { 310,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #310 = EVADDW
  { 311,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #311 = EVAND
  { 312,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #312 = EVANDC
  { 313,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #313 = EVCMPEQ
  { 314,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #314 = EVCMPGTS
  { 315,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #315 = EVCMPGTU
  { 316,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #316 = EVCMPLTS
  { 317,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #317 = EVCMPLTU
  { 318,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #318 = EVCNTLSW
  { 319,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #319 = EVCNTLZW
  { 320,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #320 = EVDIVWS
  { 321,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #321 = EVDIVWU
  { 322,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #322 = EVEQV
  { 323,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #323 = EVEXTSB
  { 324,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #324 = EVEXTSH
  { 325,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #325 = EVLDD
  { 326,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #326 = EVLDDX
  { 327,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #327 = EVLDH
  { 328,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #328 = EVLDHX
  { 329,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #329 = EVLDW
  { 330,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #330 = EVLDWX
  { 331,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #331 = EVLHHESPLAT
  { 332,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #332 = EVLHHESPLATX
  { 333,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #333 = EVLHHOSSPLAT
  { 334,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #334 = EVLHHOSSPLATX
  { 335,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #335 = EVLHHOUSPLAT
  { 336,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #336 = EVLHHOUSPLATX
  { 337,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #337 = EVLWHE
  { 338,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #338 = EVLWHEX
  { 339,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #339 = EVLWHOS
  { 340,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #340 = EVLWHOSX
  { 341,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #341 = EVLWHOU
  { 342,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #342 = EVLWHOUX
  { 343,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #343 = EVLWHSPLAT
  { 344,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #344 = EVLWHSPLATX
  { 345,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #345 = EVLWWSPLAT
  { 346,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #346 = EVLWWSPLATX
  { 347,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #347 = EVMERGEHI
  { 348,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #348 = EVMERGEHILO
  { 349,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #349 = EVMERGELO
  { 350,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #350 = EVMERGELOHI
  { 351,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #351 = EVMHEGSMFAA
  { 352,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #352 = EVMHEGSMFAN
  { 353,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #353 = EVMHEGSMIAA
  { 354,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #354 = EVMHEGSMIAN
  { 355,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #355 = EVMHEGUMIAA
  { 356,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #356 = EVMHEGUMIAN
  { 357,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #357 = EVMHESMF
  { 358,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #358 = EVMHESMFA
  { 359,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #359 = EVMHESMFAAW
  { 360,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #360 = EVMHESMFANW
  { 361,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #361 = EVMHESMI
  { 362,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #362 = EVMHESMIA
  { 363,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #363 = EVMHESMIAAW
  { 364,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #364 = EVMHESMIANW
  { 365,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #365 = EVMHESSF
  { 366,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #366 = EVMHESSFA
  { 367,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #367 = EVMHESSFAAW
  { 368,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #368 = EVMHESSFANW
  { 369,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #369 = EVMHESSIAAW
  { 370,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #370 = EVMHESSIANW
  { 371,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #371 = EVMHEUMI
  { 372,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #372 = EVMHEUMIA
  { 373,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #373 = EVMHEUMIAAW
  { 374,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #374 = EVMHEUMIANW
  { 375,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #375 = EVMHEUSIAAW
  { 376,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #376 = EVMHEUSIANW
  { 377,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #377 = EVMHOGSMFAA
  { 378,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #378 = EVMHOGSMFAN
  { 379,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #379 = EVMHOGSMIAA
  { 380,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #380 = EVMHOGSMIAN
  { 381,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #381 = EVMHOGUMIAA
  { 382,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #382 = EVMHOGUMIAN
  { 383,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #383 = EVMHOSMF
  { 384,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #384 = EVMHOSMFA
  { 385,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #385 = EVMHOSMFAAW
  { 386,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #386 = EVMHOSMFANW
  { 387,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #387 = EVMHOSMI
  { 388,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #388 = EVMHOSMIA
  { 389,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #389 = EVMHOSMIAAW
  { 390,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #390 = EVMHOSMIANW
  { 391,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #391 = EVMHOSSF
  { 392,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #392 = EVMHOSSFA
  { 393,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #393 = EVMHOSSFAAW
  { 394,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #394 = EVMHOSSFANW
  { 395,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #395 = EVMHOSSIAAW
  { 396,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #396 = EVMHOSSIANW
  { 397,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #397 = EVMHOUMI
  { 398,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #398 = EVMHOUMIA
  { 399,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #399 = EVMHOUMIAAW
  { 400,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #400 = EVMHOUMIANW
  { 401,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #401 = EVMHOUSIAAW
  { 402,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #402 = EVMHOUSIANW
  { 403,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #403 = EVMRA
  { 404,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #404 = EVMWHSMF
  { 405,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #405 = EVMWHSMFA
  { 406,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #406 = EVMWHSMI
  { 407,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #407 = EVMWHSMIA
  { 408,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #408 = EVMWHSSF
  { 409,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #409 = EVMWHSSFA
  { 410,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #410 = EVMWHUMI
  { 411,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #411 = EVMWHUMIA
  { 412,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #412 = EVMWLSMIAAW
  { 413,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #413 = EVMWLSMIANW
  { 414,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #414 = EVMWLSSIAAW
  { 415,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #415 = EVMWLSSIANW
  { 416,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #416 = EVMWLUMI
  { 417,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #417 = EVMWLUMIA
  { 418,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #418 = EVMWLUMIAAW
  { 419,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #419 = EVMWLUMIANW
  { 420,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #420 = EVMWLUSIAAW
  { 421,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #421 = EVMWLUSIANW
  { 422,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #422 = EVMWSMF
  { 423,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #423 = EVMWSMFA
  { 424,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #424 = EVMWSMFAA
  { 425,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #425 = EVMWSMFAN
  { 426,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #426 = EVMWSMI
  { 427,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #427 = EVMWSMIA
  { 428,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #428 = EVMWSMIAA
  { 429,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #429 = EVMWSMIAN
  { 430,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #430 = EVMWSSF
  { 431,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #431 = EVMWSSFA
  { 432,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #432 = EVMWSSFAA
  { 433,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #433 = EVMWSSFAN
  { 434,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #434 = EVMWUMI
  { 435,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #435 = EVMWUMIA
  { 436,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #436 = EVMWUMIAA
  { 437,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #437 = EVMWUMIAN
  { 438,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #438 = EVNAND
  { 439,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #439 = EVNEG
  { 440,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #440 = EVNOR
  { 441,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #441 = EVOR
  { 442,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #442 = EVORC
  { 443,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #443 = EVRLW
  { 444,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #444 = EVRLWI
  { 445,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #445 = EVRNDW
  { 446,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #446 = EVSLW
  { 447,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #447 = EVSLWI
  { 448,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #448 = EVSPLATFI
  { 449,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #449 = EVSPLATI
  { 450,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #450 = EVSRWIS
  { 451,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #451 = EVSRWIU
  { 452,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #452 = EVSRWS
  { 453,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #453 = EVSRWU
  { 454,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #454 = EVSTDD
  { 455,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #455 = EVSTDDX
  { 456,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #456 = EVSTDH
  { 457,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #457 = EVSTDHX
  { 458,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #458 = EVSTDW
  { 459,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #459 = EVSTDWX
  { 460,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #460 = EVSTWHE
  { 461,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #461 = EVSTWHEX
  { 462,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #462 = EVSTWHO
  { 463,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #463 = EVSTWHOX
  { 464,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #464 = EVSTWWE
  { 465,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #465 = EVSTWWEX
  { 466,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #466 = EVSTWWO
  { 467,	3,	0,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #467 = EVSTWWOX
  { 468,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #468 = EVSUBFSMIAAW
  { 469,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #469 = EVSUBFSSIAAW
  { 470,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #470 = EVSUBFUMIAAW
  { 471,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #471 = EVSUBFUSIAAW
  { 472,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #472 = EVSUBFW
  { 473,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #473 = EVSUBIFW
  { 474,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #474 = EVXOR
  { 475,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #475 = EXTLDI
  { 476,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #476 = EXTLDIo
  { 477,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #477 = EXTLWI
  { 478,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #478 = EXTLWIo
  { 479,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #479 = EXTRDI
  { 480,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #480 = EXTRDIo
  { 481,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #481 = EXTRWI
  { 482,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #482 = EXTRWIo
  { 483,	2,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #483 = EXTSB
  { 484,	2,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #484 = EXTSB8
  { 485,	2,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #485 = EXTSB8_32_64
  { 486,	2,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #486 = EXTSB8o
  { 487,	2,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #487 = EXTSBo
  { 488,	2,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #488 = EXTSH
  { 489,	2,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #489 = EXTSH8
  { 490,	2,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #490 = EXTSH8_32_64
  { 491,	2,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #491 = EXTSH8o
  { 492,	2,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #492 = EXTSHo
  { 493,	2,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #493 = EXTSW
  { 494,	2,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #494 = EXTSW_32_64
  { 495,	2,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo53, -1 ,nullptr },  // Inst #495 = EXTSW_32_64o
  { 496,	2,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #496 = EXTSWo
  { 497,	0,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #497 = EnforceIEIO
  { 498,	2,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #498 = FABSD
  { 499,	2,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #499 = FABSDo
  { 500,	2,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #500 = FABSS
  { 501,	2,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #501 = FABSSo
  { 502,	3,	1,	4,	12,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #502 = FADD
  { 503,	3,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #503 = FADDS
  { 504,	3,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo57, -1 ,nullptr },  // Inst #504 = FADDSo
  { 505,	3,	1,	4,	12,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo56, -1 ,nullptr },  // Inst #505 = FADDo
  { 506,	3,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList13, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #506 = FADDrtz
  { 507,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #507 = FCFID
  { 508,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #508 = FCFIDS
  { 509,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo58, -1 ,nullptr },  // Inst #509 = FCFIDSo
  { 510,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #510 = FCFIDU
  { 511,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #511 = FCFIDUS
  { 512,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo58, -1 ,nullptr },  // Inst #512 = FCFIDUSo
  { 513,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #513 = FCFIDUo
  { 514,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #514 = FCFIDo
  { 515,	3,	1,	4,	13,	0|(1ULL<<MCID::Compare), 0x18ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #515 = FCMPUD
  { 516,	3,	1,	4,	13,	0|(1ULL<<MCID::Compare), 0x18ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #516 = FCMPUS
  { 517,	3,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #517 = FCPSGND
  { 518,	3,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo56, -1 ,nullptr },  // Inst #518 = FCPSGNDo
  { 519,	3,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #519 = FCPSGNS
  { 520,	3,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo57, -1 ,nullptr },  // Inst #520 = FCPSGNSo
  { 521,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #521 = FCTID
  { 522,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #522 = FCTIDUZ
  { 523,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #523 = FCTIDUZo
  { 524,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #524 = FCTIDZ
  { 525,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #525 = FCTIDZo
  { 526,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #526 = FCTIDo
  { 527,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #527 = FCTIW
  { 528,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #528 = FCTIWUZ
  { 529,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #529 = FCTIWUZo
  { 530,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #530 = FCTIWZ
  { 531,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #531 = FCTIWZo
  { 532,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #532 = FCTIWo
  { 533,	3,	1,	4,	14,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #533 = FDIV
  { 534,	3,	1,	4,	15,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #534 = FDIVS
  { 535,	3,	1,	4,	15,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo57, -1 ,nullptr },  // Inst #535 = FDIVSo
  { 536,	3,	1,	4,	14,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo56, -1 ,nullptr },  // Inst #536 = FDIVo
  { 537,	4,	1,	4,	16,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #537 = FMADD
  { 538,	4,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #538 = FMADDS
  { 539,	4,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo62, -1 ,nullptr },  // Inst #539 = FMADDSo
  { 540,	4,	1,	4,	16,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo61, -1 ,nullptr },  // Inst #540 = FMADDo
  { 541,	2,	1,	4,	11,	0, 0x0ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #541 = FMR
  { 542,	2,	1,	4,	11,	0, 0x0ULL, nullptr, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #542 = FMRo
  { 543,	4,	1,	4,	16,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #543 = FMSUB
  { 544,	4,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #544 = FMSUBS
  { 545,	4,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo62, -1 ,nullptr },  // Inst #545 = FMSUBSo
  { 546,	4,	1,	4,	16,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo61, -1 ,nullptr },  // Inst #546 = FMSUBo
  { 547,	3,	1,	4,	16,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #547 = FMUL
  { 548,	3,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #548 = FMULS
  { 549,	3,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo57, -1 ,nullptr },  // Inst #549 = FMULSo
  { 550,	3,	1,	4,	16,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo56, -1 ,nullptr },  // Inst #550 = FMULo
  { 551,	2,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #551 = FNABSD
  { 552,	2,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #552 = FNABSDo
  { 553,	2,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #553 = FNABSS
  { 554,	2,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #554 = FNABSSo
  { 555,	2,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #555 = FNEGD
  { 556,	2,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #556 = FNEGDo
  { 557,	2,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #557 = FNEGS
  { 558,	2,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #558 = FNEGSo
  { 559,	4,	1,	4,	16,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #559 = FNMADD
  { 560,	4,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #560 = FNMADDS
  { 561,	4,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo62, -1 ,nullptr },  // Inst #561 = FNMADDSo
  { 562,	4,	1,	4,	16,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo61, -1 ,nullptr },  // Inst #562 = FNMADDo
  { 563,	4,	1,	4,	16,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #563 = FNMSUB
  { 564,	4,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #564 = FNMSUBS
  { 565,	4,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo62, -1 ,nullptr },  // Inst #565 = FNMSUBSo
  { 566,	4,	1,	4,	16,	0|(1ULL<<MCID::Commutable), 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo61, -1 ,nullptr },  // Inst #566 = FNMSUBo
  { 567,	2,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #567 = FRE
  { 568,	2,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #568 = FRES
  { 569,	2,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #569 = FRESo
  { 570,	2,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #570 = FREo
  { 571,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #571 = FRIMD
  { 572,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #572 = FRIMDo
  { 573,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #573 = FRIMS
  { 574,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #574 = FRIMSo
  { 575,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #575 = FRIND
  { 576,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #576 = FRINDo
  { 577,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #577 = FRINS
  { 578,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #578 = FRINSo
  { 579,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #579 = FRIPD
  { 580,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #580 = FRIPDo
  { 581,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #581 = FRIPS
  { 582,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #582 = FRIPSo
  { 583,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #583 = FRIZD
  { 584,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #584 = FRIZDo
  { 585,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #585 = FRIZS
  { 586,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #586 = FRIZSo
  { 587,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #587 = FRSP
  { 588,	2,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo58, -1 ,nullptr },  // Inst #588 = FRSPo
  { 589,	2,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #589 = FRSQRTE
  { 590,	2,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #590 = FRSQRTES
  { 591,	2,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #591 = FRSQRTESo
  { 592,	2,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #592 = FRSQRTEo
  { 593,	4,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #593 = FSELD
  { 594,	4,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo61, -1 ,nullptr },  // Inst #594 = FSELDo
  { 595,	4,	1,	4,	11,	0, 0x18ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #595 = FSELS
  { 596,	4,	1,	4,	11,	0, 0x18ULL, nullptr, ImplicitList21, OperandInfo63, -1 ,nullptr },  // Inst #596 = FSELSo
  { 597,	2,	1,	4,	17,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #597 = FSQRT
  { 598,	2,	1,	4,	18,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #598 = FSQRTS
  { 599,	2,	1,	4,	18,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo55, -1 ,nullptr },  // Inst #599 = FSQRTSo
  { 600,	2,	1,	4,	17,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo54, -1 ,nullptr },  // Inst #600 = FSQRTo
  { 601,	3,	1,	4,	12,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #601 = FSUB
  { 602,	3,	1,	4,	11,	0, 0x18ULL, ImplicitList13, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #602 = FSUBS
  { 603,	3,	1,	4,	11,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo57, -1 ,nullptr },  // Inst #603 = FSUBSo
  { 604,	3,	1,	4,	12,	0, 0x18ULL, ImplicitList13, ImplicitList21, OperandInfo56, -1 ,nullptr },  // Inst #604 = FSUBo
  { 605,	3,	1,	4,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList22, OperandInfo16, -1 ,nullptr },  // Inst #605 = GETtlsADDR
  { 606,	3,	1,	4,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList23, OperandInfo14, -1 ,nullptr },  // Inst #606 = GETtlsADDR32
  { 607,	3,	1,	4,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList22, OperandInfo16, -1 ,nullptr },  // Inst #607 = GETtlsldADDR
  { 608,	3,	1,	4,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL, nullptr, ImplicitList23, OperandInfo14, -1 ,nullptr },  // Inst #608 = GETtlsldADDR32
  { 609,	2,	0,	4,	19,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #609 = ICBI
  { 610,	3,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #610 = ICBT
  { 611,	2,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #611 = ICCCI
  { 612,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #612 = INSLWI
  { 613,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #613 = INSLWIo
  { 614,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #614 = INSRDI
  { 615,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #615 = INSRDIo
  { 616,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #616 = INSRWI
  { 617,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #617 = INSRWIo
  { 618,	4,	1,	4,	20,	0|(1ULL<<MCID::Select), 0x8ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #618 = ISEL
  { 619,	4,	1,	4,	20,	0|(1ULL<<MCID::Select), 0x8ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #619 = ISEL8
  { 620,	0,	0,	4,	21,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #620 = ISYNC
  { 621,	3,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #621 = LA
  { 622,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #622 = LAx
  { 623,	3,	1,	4,	22,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #623 = LBARX
  { 624,	3,	1,	4,	22,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #624 = LBARXL
  { 625,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #625 = LBZ
  { 626,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #626 = LBZ8
  { 627,	3,	1,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #627 = LBZCIX
  { 628,	4,	2,	4,	23,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #628 = LBZU
  { 629,	4,	2,	4,	23,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo69, -1 ,nullptr },  // Inst #629 = LBZU8
  { 630,	4,	2,	4,	24,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #630 = LBZUX
  { 631,	4,	2,	4,	24,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #631 = LBZUX8
  { 632,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #632 = LBZX
  { 633,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #633 = LBZX8
  { 634,	3,	1,	4,	25,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #634 = LD
  { 635,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #635 = LDARX
  { 636,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #636 = LDARXL
  { 637,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #637 = LDBRX
  { 638,	3,	1,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #638 = LDCIX
  { 639,	4,	2,	4,	27,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo69, -1 ,nullptr },  // Inst #639 = LDU
  { 640,	4,	2,	4,	28,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #640 = LDUX
  { 641,	3,	1,	4,	25,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #641 = LDX
  { 642,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #642 = LDgotTprelL
  { 643,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #643 = LDgotTprelL32
  { 644,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #644 = LDtoc
  { 645,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #645 = LDtocBA
  { 646,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #646 = LDtocCPT
  { 647,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #647 = LDtocJTI
  { 648,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #648 = LDtocL
  { 649,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #649 = LFD
  { 650,	4,	2,	4,	30,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #650 = LFDU
  { 651,	4,	2,	4,	31,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #651 = LFDUX
  { 652,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #652 = LFDX
  { 653,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #653 = LFIWAX
  { 654,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #654 = LFIWZX
  { 655,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #655 = LFS
  { 656,	4,	2,	4,	30,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #656 = LFSU
  { 657,	4,	2,	4,	31,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #657 = LFSUX
  { 658,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #658 = LFSX
  { 659,	3,	1,	4,	32,	0|(1ULL<<MCID::MayLoad), 0x14ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #659 = LHA
  { 660,	3,	1,	4,	32,	0|(1ULL<<MCID::MayLoad), 0x14ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #660 = LHA8
  { 661,	3,	1,	4,	22,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #661 = LHARX
  { 662,	3,	1,	4,	22,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #662 = LHARXL
  { 663,	4,	2,	4,	33,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #663 = LHAU
  { 664,	4,	2,	4,	33,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo69, -1 ,nullptr },  // Inst #664 = LHAU8
  { 665,	4,	2,	4,	34,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #665 = LHAUX
  { 666,	4,	2,	4,	34,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #666 = LHAUX8
  { 667,	3,	1,	4,	32,	0|(1ULL<<MCID::MayLoad), 0x14ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #667 = LHAX
  { 668,	3,	1,	4,	32,	0|(1ULL<<MCID::MayLoad), 0x14ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #668 = LHAX8
  { 669,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #669 = LHBRX
  { 670,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #670 = LHBRX8
  { 671,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #671 = LHZ
  { 672,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #672 = LHZ8
  { 673,	3,	1,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #673 = LHZCIX
  { 674,	4,	2,	4,	23,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #674 = LHZU
  { 675,	4,	2,	4,	23,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo69, -1 ,nullptr },  // Inst #675 = LHZU8
  { 676,	4,	2,	4,	24,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #676 = LHZUX
  { 677,	4,	2,	4,	24,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #677 = LHZUX8
  { 678,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #678 = LHZX
  { 679,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #679 = LHZX8
  { 680,	2,	1,	4,	1,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x8ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #680 = LI
  { 681,	2,	1,	4,	1,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x8ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #681 = LI8
  { 682,	2,	1,	4,	1,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x8ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #682 = LIS
  { 683,	2,	1,	4,	1,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x8ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #683 = LIS8
  { 684,	3,	1,	4,	35,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #684 = LMW
  { 685,	3,	1,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #685 = LSWI
  { 686,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #686 = LVEBX
  { 687,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #687 = LVEHX
  { 688,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #688 = LVEWX
  { 689,	3,	1,	4,	8,	0, 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #689 = LVSL
  { 690,	3,	1,	4,	8,	0, 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #690 = LVSR
  { 691,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #691 = LVX
  { 692,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #692 = LVXL
  { 693,	3,	1,	4,	36,	0|(1ULL<<MCID::MayLoad), 0x14ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #693 = LWA
  { 694,	3,	1,	4,	22,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #694 = LWARX
  { 695,	3,	1,	4,	22,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #695 = LWARXL
  { 696,	4,	2,	4,	34,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #696 = LWAUX
  { 697,	3,	1,	4,	32,	0|(1ULL<<MCID::MayLoad), 0x14ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #697 = LWAX
  { 698,	3,	1,	4,	32,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x14ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #698 = LWAX_32
  { 699,	3,	1,	4,	36,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x14ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #699 = LWA_32
  { 700,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #700 = LWBRX
  { 701,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #701 = LWBRX8
  { 702,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #702 = LWZ
  { 703,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #703 = LWZ8
  { 704,	3,	1,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #704 = LWZCIX
  { 705,	4,	2,	4,	23,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #705 = LWZU
  { 706,	4,	2,	4,	23,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo69, -1 ,nullptr },  // Inst #706 = LWZU8
  { 707,	4,	2,	4,	24,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #707 = LWZUX
  { 708,	4,	2,	4,	24,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #708 = LWZUX8
  { 709,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #709 = LWZX
  { 710,	3,	1,	4,	8,	0|(1ULL<<MCID::MayLoad), 0x10ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #710 = LWZX8
  { 711,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #711 = LWZtoc
  { 712,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #712 = LXSDX
  { 713,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #713 = LXSIWAX
  { 714,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #714 = LXSIWZX
  { 715,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo88, -1 ,nullptr },  // Inst #715 = LXSSPX
  { 716,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #716 = LXVD2X
  { 717,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #717 = LXVDSX
  { 718,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #718 = LXVW4X
  { 719,	1,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #719 = MBAR
  { 720,	2,	1,	4,	37,	0, 0x21ULL, nullptr, nullptr, OperandInfo90, -1 ,nullptr },  // Inst #720 = MCRF
  { 721,	2,	1,	4,	37,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo90, -1 ,nullptr },  // Inst #721 = MCRFS
  { 722,	3,	1,	4,	3,	0, 0x1ULL, nullptr, nullptr, OperandInfo91, -1 ,nullptr },  // Inst #722 = MFBHRBE
  { 723,	1,	1,	4,	38,	0|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x20ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #723 = MFCR
  { 724,	1,	1,	4,	38,	0|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x20ULL, nullptr, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #724 = MFCR8
  { 725,	1,	1,	4,	39,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, ImplicitList7, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #725 = MFCTR
  { 726,	1,	1,	4,	39,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, ImplicitList8, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #726 = MFCTR8
  { 727,	2,	1,	4,	39,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #727 = MFDCR
  { 728,	1,	1,	4,	40,	0, 0x1aULL, ImplicitList13, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #728 = MFFS
  { 729,	1,	1,	4,	40,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList13, ImplicitList21, OperandInfo94, -1 ,nullptr },  // Inst #729 = MFFSo
  { 730,	1,	1,	4,	39,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, ImplicitList10, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #730 = MFLR
  { 731,	1,	1,	4,	39,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, ImplicitList12, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #731 = MFLR8
  { 732,	1,	1,	4,	41,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #732 = MFMSR
  { 733,	2,	1,	4,	42,	0|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x21ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #733 = MFOCRF
  { 734,	2,	1,	4,	42,	0|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x21ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #734 = MFOCRF8
  { 735,	2,	1,	4,	39,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #735 = MFSPR
  { 736,	2,	1,	4,	39,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #736 = MFSPR8
  { 737,	2,	1,	4,	43,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #737 = MFSR
  { 738,	2,	1,	4,	43,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #738 = MFSRIN
  { 739,	2,	1,	4,	44,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #739 = MFTB
  { 740,	1,	1,	4,	44,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, nullptr, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #740 = MFTB8
  { 741,	1,	1,	4,	2,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #741 = MFVRSAVE
  { 742,	2,	1,	4,	2,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, nullptr, nullptr, OperandInfo96, -1 ,nullptr },  // Inst #742 = MFVRSAVEv
  { 743,	1,	1,	4,	45,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #743 = MFVSCR
  { 744,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo98, -1 ,nullptr },  // Inst #744 = MFVSRD
  { 745,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo99, -1 ,nullptr },  // Inst #745 = MFVSRWZ
  { 746,	0,	0,	4,	47,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #746 = MSYNC
  { 747,	2,	0,	4,	48,	0|(1ULL<<MCID::ExtraDefRegAllocReq), 0x20ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #747 = MTCRF
  { 748,	2,	0,	4,	48,	0|(1ULL<<MCID::ExtraDefRegAllocReq), 0x20ULL, nullptr, nullptr, OperandInfo101, -1 ,nullptr },  // Inst #748 = MTCRF8
  { 749,	1,	0,	4,	49,	0, 0x9ULL, nullptr, ImplicitList7, OperandInfo92, -1 ,nullptr },  // Inst #749 = MTCTR
  { 750,	1,	0,	4,	49,	0, 0x9ULL, nullptr, ImplicitList8, OperandInfo93, -1 ,nullptr },  // Inst #750 = MTCTR8
  { 751,	1,	0,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, nullptr, ImplicitList8, OperandInfo93, -1 ,nullptr },  // Inst #751 = MTCTR8loop
  { 752,	1,	0,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, nullptr, ImplicitList7, OperandInfo92, -1 ,nullptr },  // Inst #752 = MTCTRloop
  { 753,	2,	0,	4,	49,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #753 = MTDCR
  { 754,	1,	0,	4,	50,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL, ImplicitList13, ImplicitList13, OperandInfo5, -1 ,nullptr },  // Inst #754 = MTFSB0
  { 755,	1,	0,	4,	50,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL, ImplicitList13, ImplicitList13, OperandInfo5, -1 ,nullptr },  // Inst #755 = MTFSB1
  { 756,	4,	0,	4,	40,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo102, -1 ,nullptr },  // Inst #756 = MTFSF
  { 757,	3,	1,	4,	40,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #757 = MTFSFI
  { 758,	3,	1,	4,	40,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #758 = MTFSFIo
  { 759,	2,	0,	4,	50,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL, ImplicitList13, ImplicitList13, OperandInfo104, -1 ,nullptr },  // Inst #759 = MTFSFb
  { 760,	4,	0,	4,	40,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo102, -1 ,nullptr },  // Inst #760 = MTFSFo
  { 761,	1,	0,	4,	49,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, nullptr, ImplicitList10, OperandInfo92, -1 ,nullptr },  // Inst #761 = MTLR
  { 762,	1,	0,	4,	49,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL, nullptr, ImplicitList12, OperandInfo93, -1 ,nullptr },  // Inst #762 = MTLR8
  { 763,	2,	0,	4,	51,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #763 = MTMSR
  { 764,	2,	0,	4,	52,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #764 = MTMSRD
  { 765,	2,	1,	4,	48,	0|(1ULL<<MCID::ExtraDefRegAllocReq), 0x21ULL, nullptr, nullptr, OperandInfo105, -1 ,nullptr },  // Inst #765 = MTOCRF
  { 766,	2,	1,	4,	48,	0|(1ULL<<MCID::ExtraDefRegAllocReq), 0x21ULL, nullptr, nullptr, OperandInfo106, -1 ,nullptr },  // Inst #766 = MTOCRF8
  { 767,	2,	0,	4,	49,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #767 = MTSPR
  { 768,	2,	0,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo101, -1 ,nullptr },  // Inst #768 = MTSPR8
  { 769,	2,	0,	4,	53,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #769 = MTSR
  { 770,	2,	0,	4,	53,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #770 = MTSRIN
  { 771,	1,	0,	4,	2,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xaULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #771 = MTVRSAVE
  { 772,	2,	1,	4,	2,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xaULL, nullptr, nullptr, OperandInfo107, -1 ,nullptr },  // Inst #772 = MTVRSAVEv
  { 773,	1,	0,	4,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #773 = MTVSCR
  { 774,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #774 = MTVSRD
  { 775,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #775 = MTVSRWA
  { 776,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #776 = MTVSRWZ
  { 777,	3,	1,	4,	54,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #777 = MULHD
  { 778,	3,	1,	4,	55,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #778 = MULHDU
  { 779,	3,	1,	4,	55,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #779 = MULHDUo
  { 780,	3,	1,	4,	54,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #780 = MULHDo
  { 781,	3,	1,	4,	54,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #781 = MULHW
  { 782,	3,	1,	4,	55,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #782 = MULHWU
  { 783,	3,	1,	4,	55,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #783 = MULHWUo
  { 784,	3,	1,	4,	54,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #784 = MULHWo
  { 785,	3,	1,	4,	56,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #785 = MULLD
  { 786,	3,	1,	4,	56,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #786 = MULLDo
  { 787,	3,	1,	4,	57,	0, 0x8ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #787 = MULLI
  { 788,	3,	1,	4,	57,	0, 0x8ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #788 = MULLI8
  { 789,	3,	1,	4,	54,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #789 = MULLW
  { 790,	3,	1,	4,	54,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #790 = MULLWo
  { 791,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, nullptr, ImplicitList10, nullptr, -1 ,nullptr },  // Inst #791 = MoveGOTtoLR
  { 792,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, nullptr, ImplicitList10, nullptr, -1 ,nullptr },  // Inst #792 = MovePCtoLR
  { 793,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, nullptr, ImplicitList12, nullptr, -1 ,nullptr },  // Inst #793 = MovePCtoLR8
  { 794,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #794 = NAND
  { 795,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #795 = NAND8
  { 796,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #796 = NAND8o
  { 797,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #797 = NANDo
  { 798,	2,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #798 = NEG
  { 799,	2,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #799 = NEG8
  { 800,	2,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #800 = NEG8o
  { 801,	2,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #801 = NEGo
  { 802,	0,	0,	4,	1,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #802 = NOP
  { 803,	0,	0,	4,	1,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #803 = NOP_GT_PWR6
  { 804,	0,	0,	4,	1,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #804 = NOP_GT_PWR7
  { 805,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #805 = NOR
  { 806,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #806 = NOR8
  { 807,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #807 = NOR8o
  { 808,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #808 = NORo
  { 809,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #809 = OR
  { 810,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #810 = OR8
  { 811,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #811 = OR8o
  { 812,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #812 = ORC
  { 813,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #813 = ORC8
  { 814,	3,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #814 = ORC8o
  { 815,	3,	1,	4,	1,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #815 = ORCo
  { 816,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #816 = ORI
  { 817,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #817 = ORI8
  { 818,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #818 = ORIS
  { 819,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #819 = ORIS8
  { 820,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #820 = ORo
  { 821,	2,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #821 = POPCNTD
  { 822,	2,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #822 = POPCNTW
  { 823,	1,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #823 = PPC32GOT
  { 824,	2,	2,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #824 = PPC32PICGOT
  { 825,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #825 = QVALIGNI
  { 826,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #826 = QVALIGNIb
  { 827,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo112, -1 ,nullptr },  // Inst #827 = QVALIGNIs
  { 828,	3,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #828 = QVESPLATI
  { 829,	3,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #829 = QVESPLATIb
  { 830,	3,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #830 = QVESPLATIs
  { 831,	2,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #831 = QVFABS
  { 832,	2,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #832 = QVFABSs
  { 833,	3,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #833 = QVFADD
  { 834,	3,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #834 = QVFADDS
  { 835,	3,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo119, -1 ,nullptr },  // Inst #835 = QVFADDSs
  { 836,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #836 = QVFCFID
  { 837,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #837 = QVFCFIDS
  { 838,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #838 = QVFCFIDU
  { 839,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #839 = QVFCFIDUS
  { 840,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo120, -1 ,nullptr },  // Inst #840 = QVFCFIDb
  { 841,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #841 = QVFCMPEQ
  { 842,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo121, -1 ,nullptr },  // Inst #842 = QVFCMPEQb
  { 843,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #843 = QVFCMPEQbs
  { 844,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #844 = QVFCMPGT
  { 845,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo121, -1 ,nullptr },  // Inst #845 = QVFCMPGTb
  { 846,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #846 = QVFCMPGTbs
  { 847,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #847 = QVFCMPLT
  { 848,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo121, -1 ,nullptr },  // Inst #848 = QVFCMPLTb
  { 849,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #849 = QVFCMPLTbs
  { 850,	3,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #850 = QVFCPSGN
  { 851,	3,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo119, -1 ,nullptr },  // Inst #851 = QVFCPSGNs
  { 852,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #852 = QVFCTID
  { 853,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #853 = QVFCTIDU
  { 854,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #854 = QVFCTIDUZ
  { 855,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #855 = QVFCTIDZ
  { 856,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo120, -1 ,nullptr },  // Inst #856 = QVFCTIDb
  { 857,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #857 = QVFCTIW
  { 858,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #858 = QVFCTIWU
  { 859,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #859 = QVFCTIWUZ
  { 860,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #860 = QVFCTIWZ
  { 861,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #861 = QVFLOGICAL
  { 862,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #862 = QVFLOGICALb
  { 863,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #863 = QVFLOGICALs
  { 864,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #864 = QVFMADD
  { 865,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #865 = QVFMADDS
  { 866,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #866 = QVFMADDSs
  { 867,	2,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #867 = QVFMR
  { 868,	2,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo120, -1 ,nullptr },  // Inst #868 = QVFMRb
  { 869,	2,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #869 = QVFMRs
  { 870,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #870 = QVFMSUB
  { 871,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #871 = QVFMSUBS
  { 872,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #872 = QVFMSUBSs
  { 873,	3,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #873 = QVFMUL
  { 874,	3,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #874 = QVFMULS
  { 875,	3,	1,	4,	11,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo119, -1 ,nullptr },  // Inst #875 = QVFMULSs
  { 876,	2,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #876 = QVFNABS
  { 877,	2,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #877 = QVFNABSs
  { 878,	2,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #878 = QVFNEG
  { 879,	2,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #879 = QVFNEGs
  { 880,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #880 = QVFNMADD
  { 881,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #881 = QVFNMADDS
  { 882,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #882 = QVFNMADDSs
  { 883,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #883 = QVFNMSUB
  { 884,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #884 = QVFNMSUBS
  { 885,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #885 = QVFNMSUBSs
  { 886,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #886 = QVFPERM
  { 887,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #887 = QVFPERMs
  { 888,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #888 = QVFRE
  { 889,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #889 = QVFRES
  { 890,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #890 = QVFRESs
  { 891,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #891 = QVFRIM
  { 892,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #892 = QVFRIMs
  { 893,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #893 = QVFRIN
  { 894,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #894 = QVFRINs
  { 895,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #895 = QVFRIP
  { 896,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #896 = QVFRIPs
  { 897,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #897 = QVFRIZ
  { 898,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #898 = QVFRIZs
  { 899,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #899 = QVFRSP
  { 900,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #900 = QVFRSPs
  { 901,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #901 = QVFRSQRTE
  { 902,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #902 = QVFRSQRTES
  { 903,	2,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #903 = QVFRSQRTESs
  { 904,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #904 = QVFSEL
  { 905,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #905 = QVFSELb
  { 906,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo128, -1 ,nullptr },  // Inst #906 = QVFSELbb
  { 907,	4,	1,	4,	58,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #907 = QVFSELbs
  { 908,	3,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #908 = QVFSUB
  { 909,	3,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #909 = QVFSUBS
  { 910,	3,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo119, -1 ,nullptr },  // Inst #910 = QVFSUBSs
  { 911,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #911 = QVFTSTNAN
  { 912,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo121, -1 ,nullptr },  // Inst #912 = QVFTSTNANb
  { 913,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #913 = QVFTSTNANbs
  { 914,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #914 = QVFXMADD
  { 915,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #915 = QVFXMADDS
  { 916,	3,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #916 = QVFXMUL
  { 917,	3,	1,	4,	11,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #917 = QVFXMULS
  { 918,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #918 = QVFXXCPNMADD
  { 919,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #919 = QVFXXCPNMADDS
  { 920,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #920 = QVFXXMADD
  { 921,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #921 = QVFXXMADDS
  { 922,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #922 = QVFXXNPMADD
  { 923,	4,	1,	4,	16,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #923 = QVFXXNPMADDS
  { 924,	2,	1,	4,	58,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, ImplicitList13, nullptr, OperandInfo130, -1 ,nullptr },  // Inst #924 = QVGPCI
  { 925,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #925 = QVLFCDUX
  { 926,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #926 = QVLFCDUXA
  { 927,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #927 = QVLFCDX
  { 928,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #928 = QVLFCDXA
  { 929,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #929 = QVLFCSUX
  { 930,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #930 = QVLFCSUXA
  { 931,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #931 = QVLFCSX
  { 932,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #932 = QVLFCSXA
  { 933,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #933 = QVLFCSXs
  { 934,	4,	2,	4,	30,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #934 = QVLFDUX
  { 935,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #935 = QVLFDUXA
  { 936,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #936 = QVLFDX
  { 937,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #937 = QVLFDXA
  { 938,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo134, -1 ,nullptr },  // Inst #938 = QVLFDXb
  { 939,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #939 = QVLFIWAX
  { 940,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #940 = QVLFIWAXA
  { 941,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #941 = QVLFIWZX
  { 942,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #942 = QVLFIWZXA
  { 943,	4,	2,	4,	30,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo135, -1 ,nullptr },  // Inst #943 = QVLFSUX
  { 944,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #944 = QVLFSUXA
  { 945,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #945 = QVLFSX
  { 946,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #946 = QVLFSXA
  { 947,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo134, -1 ,nullptr },  // Inst #947 = QVLFSXb
  { 948,	3,	1,	4,	29,	0|(1ULL<<MCID::MayLoad), 0x0ULL, ImplicitList13, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #948 = QVLFSXs
  { 949,	3,	1,	4,	29,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #949 = QVLPCLDX
  { 950,	3,	1,	4,	29,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #950 = QVLPCLSX
  { 951,	2,	1,	4,	29,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo136, -1 ,nullptr },  // Inst #951 = QVLPCLSXint
  { 952,	3,	1,	4,	29,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #952 = QVLPCRDX
  { 953,	3,	1,	4,	29,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #953 = QVLPCRSX
  { 954,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #954 = QVSTFCDUX
  { 955,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #955 = QVSTFCDUXA
  { 956,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #956 = QVSTFCDUXI
  { 957,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #957 = QVSTFCDUXIA
  { 958,	3,	0,	4,	59,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #958 = QVSTFCDX
  { 959,	3,	0,	4,	59,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #959 = QVSTFCDXA
  { 960,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #960 = QVSTFCDXI
  { 961,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #961 = QVSTFCDXIA
  { 962,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #962 = QVSTFCSUX
  { 963,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #963 = QVSTFCSUXA
  { 964,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #964 = QVSTFCSUXI
  { 965,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #965 = QVSTFCSUXIA
  { 966,	3,	0,	4,	59,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #966 = QVSTFCSX
  { 967,	3,	0,	4,	59,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #967 = QVSTFCSXA
  { 968,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #968 = QVSTFCSXI
  { 969,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #969 = QVSTFCSXIA
  { 970,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #970 = QVSTFCSXs
  { 971,	4,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo137, -1 ,nullptr },  // Inst #971 = QVSTFDUX
  { 972,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #972 = QVSTFDUXA
  { 973,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #973 = QVSTFDUXI
  { 974,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #974 = QVSTFDUXIA
  { 975,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #975 = QVSTFDX
  { 976,	3,	0,	4,	59,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #976 = QVSTFDXA
  { 977,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #977 = QVSTFDXI
  { 978,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #978 = QVSTFDXIA
  { 979,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo134, -1 ,nullptr },  // Inst #979 = QVSTFDXb
  { 980,	3,	0,	4,	59,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #980 = QVSTFIWX
  { 981,	3,	0,	4,	59,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #981 = QVSTFIWXA
  { 982,	4,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo138, -1 ,nullptr },  // Inst #982 = QVSTFSUX
  { 983,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #983 = QVSTFSUXA
  { 984,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #984 = QVSTFSUXI
  { 985,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #985 = QVSTFSUXIA
  { 986,	4,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo137, -1 ,nullptr },  // Inst #986 = QVSTFSUXs
  { 987,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #987 = QVSTFSX
  { 988,	3,	0,	4,	59,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #988 = QVSTFSXA
  { 989,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #989 = QVSTFSXI
  { 990,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #990 = QVSTFSXIA
  { 991,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #991 = QVSTFSXs
  { 992,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo139, -1 ,nullptr },  // Inst #992 = RESTORE_CR
  { 993,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo140, -1 ,nullptr },  // Inst #993 = RESTORE_CRBIT
  { 994,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo141, -1 ,nullptr },  // Inst #994 = RESTORE_VRSAVE
  { 995,	0,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #995 = RFCI
  { 996,	0,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #996 = RFDI
  { 997,	1,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #997 = RFEBB
  { 998,	0,	0,	4,	61,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #998 = RFI
  { 999,	0,	0,	4,	62,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #999 = RFID
  { 1000,	0,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1000 = RFMCI
  { 1001,	4,	1,	4,	63,	0, 0x8ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1001 = RLDCL
  { 1002,	4,	1,	4,	63,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo142, -1 ,nullptr },  // Inst #1002 = RLDCLo
  { 1003,	4,	1,	4,	63,	0, 0x8ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1003 = RLDCR
  { 1004,	4,	1,	4,	63,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo142, -1 ,nullptr },  // Inst #1004 = RLDCRo
  { 1005,	4,	1,	4,	64,	0, 0x8ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1005 = RLDIC
  { 1006,	4,	1,	4,	64,	0, 0x8ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1006 = RLDICL
  { 1007,	4,	1,	4,	64,	0, 0x8ULL, nullptr, nullptr, OperandInfo143, -1 ,nullptr },  // Inst #1007 = RLDICL_32_64
  { 1008,	4,	1,	4,	64,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1008 = RLDICLo
  { 1009,	4,	1,	4,	64,	0, 0x8ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1009 = RLDICR
  { 1010,	4,	1,	4,	64,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1010 = RLDICRo
  { 1011,	4,	1,	4,	64,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1011 = RLDICo
  { 1012,	5,	1,	4,	64,	0, 0x8ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1012 = RLDIMI
  { 1013,	5,	1,	4,	64,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo144, -1 ,nullptr },  // Inst #1013 = RLDIMIo
  { 1014,	6,	1,	4,	65,	0|(1ULL<<MCID::Commutable), 0xcULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1014 = RLWIMI
  { 1015,	6,	1,	4,	65,	0, 0xcULL, nullptr, nullptr, OperandInfo146, -1 ,nullptr },  // Inst #1015 = RLWIMI8
  { 1016,	6,	1,	4,	65,	0, 0xcULL, nullptr, ImplicitList1, OperandInfo146, -1 ,nullptr },  // Inst #1016 = RLWIMI8o
  { 1017,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1017 = RLWIMIbm
  { 1018,	6,	1,	4,	65,	0|(1ULL<<MCID::Commutable), 0xcULL, nullptr, ImplicitList1, OperandInfo145, -1 ,nullptr },  // Inst #1018 = RLWIMIo
  { 1019,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1019 = RLWIMIobm
  { 1020,	5,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1020 = RLWINM
  { 1021,	5,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo149, -1 ,nullptr },  // Inst #1021 = RLWINM8
  { 1022,	5,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo149, -1 ,nullptr },  // Inst #1022 = RLWINM8o
  { 1023,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1023 = RLWINMbm
  { 1024,	5,	1,	4,	2,	0, 0xcULL, nullptr, ImplicitList1, OperandInfo148, -1 ,nullptr },  // Inst #1024 = RLWINMo
  { 1025,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1025 = RLWINMobm
  { 1026,	5,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo150, -1 ,nullptr },  // Inst #1026 = RLWNM
  { 1027,	5,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo151, -1 ,nullptr },  // Inst #1027 = RLWNM8
  { 1028,	5,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo151, -1 ,nullptr },  // Inst #1028 = RLWNM8o
  { 1029,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1029 = RLWNMbm
  { 1030,	5,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo150, -1 ,nullptr },  // Inst #1030 = RLWNMo
  { 1031,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1031 = RLWNMobm
  { 1032,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1032 = ROTRDI
  { 1033,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1033 = ROTRDIo
  { 1034,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1034 = ROTRWI
  { 1035,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1035 = ROTRWIo
  { 1036,	2,	2,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #1036 = ReadTB
  { 1037,	1,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #1037 = SC
  { 1038,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo152, -1 ,nullptr },  // Inst #1038 = SELECT_CC_F4
  { 1039,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo153, -1 ,nullptr },  // Inst #1039 = SELECT_CC_F8
  { 1040,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo154, -1 ,nullptr },  // Inst #1040 = SELECT_CC_I4
  { 1041,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo155, -1 ,nullptr },  // Inst #1041 = SELECT_CC_I8
  { 1042,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList13, nullptr, OperandInfo156, -1 ,nullptr },  // Inst #1042 = SELECT_CC_QBRC
  { 1043,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList13, nullptr, OperandInfo157, -1 ,nullptr },  // Inst #1043 = SELECT_CC_QFRC
  { 1044,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList13, nullptr, OperandInfo158, -1 ,nullptr },  // Inst #1044 = SELECT_CC_QSRC
  { 1045,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo159, -1 ,nullptr },  // Inst #1045 = SELECT_CC_VRRC
  { 1046,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo153, -1 ,nullptr },  // Inst #1046 = SELECT_CC_VSFRC
  { 1047,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo160, -1 ,nullptr },  // Inst #1047 = SELECT_CC_VSRC
  { 1048,	5,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL, nullptr, nullptr, OperandInfo152, -1 ,nullptr },  // Inst #1048 = SELECT_CC_VSSRC
  { 1049,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL, nullptr, nullptr, OperandInfo161, -1 ,nullptr },  // Inst #1049 = SELECT_F4
  { 1050,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL, nullptr, nullptr, OperandInfo162, -1 ,nullptr },  // Inst #1050 = SELECT_F8
  { 1051,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL, nullptr, nullptr, OperandInfo163, -1 ,nullptr },  // Inst #1051 = SELECT_I4
  { 1052,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL, nullptr, nullptr, OperandInfo164, -1 ,nullptr },  // Inst #1052 = SELECT_I8
  { 1053,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList13, nullptr, OperandInfo165, -1 ,nullptr },  // Inst #1053 = SELECT_QBRC
  { 1054,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList13, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1054 = SELECT_QFRC
  { 1055,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList13, nullptr, OperandInfo167, -1 ,nullptr },  // Inst #1055 = SELECT_QSRC
  { 1056,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1056 = SELECT_VRRC
  { 1057,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL, nullptr, nullptr, OperandInfo162, -1 ,nullptr },  // Inst #1057 = SELECT_VSFRC
  { 1058,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1058 = SELECT_VSRC
  { 1059,	4,	1,	4,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL, nullptr, nullptr, OperandInfo161, -1 ,nullptr },  // Inst #1059 = SELECT_VSSRC
  { 1060,	0,	0,	4,	66,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1060 = SLBIA
  { 1061,	1,	0,	4,	67,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #1061 = SLBIE
  { 1062,	2,	1,	4,	68,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #1062 = SLBMFEE
  { 1063,	2,	0,	4,	69,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #1063 = SLBMTE
  { 1064,	3,	1,	4,	63,	0, 0x8ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1064 = SLD
  { 1065,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1065 = SLDI
  { 1066,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1066 = SLDIo
  { 1067,	3,	1,	4,	63,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo170, -1 ,nullptr },  // Inst #1067 = SLDo
  { 1068,	3,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1068 = SLW
  { 1069,	3,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1069 = SLW8
  { 1070,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1070 = SLW8o
  { 1071,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1071 = SLWI
  { 1072,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1072 = SLWIo
  { 1073,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #1073 = SLWo
  { 1074,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo139, -1 ,nullptr },  // Inst #1074 = SPILL_CR
  { 1075,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo140, -1 ,nullptr },  // Inst #1075 = SPILL_CRBIT
  { 1076,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo141, -1 ,nullptr },  // Inst #1076 = SPILL_VRSAVE
  { 1077,	3,	1,	4,	63,	0, 0x8ULL, nullptr, ImplicitList2, OperandInfo170, -1 ,nullptr },  // Inst #1077 = SRAD
  { 1078,	3,	1,	4,	64,	0, 0x8ULL, nullptr, ImplicitList2, OperandInfo16, -1 ,nullptr },  // Inst #1078 = SRADI
  { 1079,	3,	1,	4,	64,	0, 0x8ULL, nullptr, ImplicitList3, OperandInfo16, -1 ,nullptr },  // Inst #1079 = SRADIo
  { 1080,	3,	1,	4,	63,	0, 0x8ULL, nullptr, ImplicitList3, OperandInfo170, -1 ,nullptr },  // Inst #1080 = SRADo
  { 1081,	3,	1,	4,	70,	0, 0x8ULL, nullptr, ImplicitList2, OperandInfo13, -1 ,nullptr },  // Inst #1081 = SRAW
  { 1082,	3,	1,	4,	70,	0, 0x8ULL, nullptr, ImplicitList2, OperandInfo14, -1 ,nullptr },  // Inst #1082 = SRAWI
  { 1083,	3,	1,	4,	70,	0, 0x8ULL, nullptr, ImplicitList3, OperandInfo14, -1 ,nullptr },  // Inst #1083 = SRAWIo
  { 1084,	3,	1,	4,	70,	0, 0x8ULL, nullptr, ImplicitList3, OperandInfo13, -1 ,nullptr },  // Inst #1084 = SRAWo
  { 1085,	3,	1,	4,	63,	0, 0x8ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1085 = SRD
  { 1086,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1086 = SRDI
  { 1087,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1087 = SRDIo
  { 1088,	3,	1,	4,	63,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo170, -1 ,nullptr },  // Inst #1088 = SRDo
  { 1089,	3,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1089 = SRW
  { 1090,	3,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1090 = SRW8
  { 1091,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1091 = SRW8o
  { 1092,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1092 = SRWI
  { 1093,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1093 = SRWIo
  { 1094,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #1094 = SRWo
  { 1095,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #1095 = STB
  { 1096,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #1096 = STB8
  { 1097,	3,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1097 = STBCIX
  { 1098,	3,	0,	4,	71,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo66, -1 ,nullptr },  // Inst #1098 = STBCX
  { 1099,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo171, -1 ,nullptr },  // Inst #1099 = STBU
  { 1100,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1100 = STBU8
  { 1101,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1101 = STBUX
  { 1102,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1102 = STBUX8
  { 1103,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #1103 = STBX
  { 1104,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #1104 = STBX8
  { 1105,	3,	0,	4,	73,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #1105 = STD
  { 1106,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #1106 = STDBRX
  { 1107,	3,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1107 = STDCIX
  { 1108,	3,	0,	4,	74,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo72, -1 ,nullptr },  // Inst #1108 = STDCX
  { 1109,	4,	1,	4,	75,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1109 = STDU
  { 1110,	4,	1,	4,	76,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1110 = STDUX
  { 1111,	3,	0,	4,	73,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #1111 = STDX
  { 1112,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #1112 = STFD
  { 1113,	4,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1113 = STFDU
  { 1114,	4,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1114 = STFDUX
  { 1115,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #1115 = STFDX
  { 1116,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #1116 = STFIWX
  { 1117,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #1117 = STFS
  { 1118,	4,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1118 = STFSU
  { 1119,	4,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1119 = STFSUX
  { 1120,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #1120 = STFSX
  { 1121,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #1121 = STH
  { 1122,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #1122 = STH8
  { 1123,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #1123 = STHBRX
  { 1124,	3,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1124 = STHCIX
  { 1125,	3,	0,	4,	71,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo66, -1 ,nullptr },  // Inst #1125 = STHCX
  { 1126,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo171, -1 ,nullptr },  // Inst #1126 = STHU
  { 1127,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1127 = STHU8
  { 1128,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1128 = STHUX
  { 1129,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1129 = STHUX8
  { 1130,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #1130 = STHX
  { 1131,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #1131 = STHX8
  { 1132,	3,	0,	4,	35,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #1132 = STMW
  { 1133,	3,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1133 = STSWI
  { 1134,	3,	0,	4,	45,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #1134 = STVEBX
  { 1135,	3,	0,	4,	45,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #1135 = STVEHX
  { 1136,	3,	0,	4,	45,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #1136 = STVEWX
  { 1137,	3,	0,	4,	45,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #1137 = STVX
  { 1138,	3,	0,	4,	45,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #1138 = STVXL
  { 1139,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #1139 = STW
  { 1140,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #1140 = STW8
  { 1141,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #1141 = STWBRX
  { 1142,	3,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1142 = STWCIX
  { 1143,	3,	0,	4,	71,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo66, -1 ,nullptr },  // Inst #1143 = STWCX
  { 1144,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo171, -1 ,nullptr },  // Inst #1144 = STWU
  { 1145,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x10ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1145 = STWU8
  { 1146,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1146 = STWUX
  { 1147,	4,	1,	4,	72,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1147 = STWUX8
  { 1148,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #1148 = STWX
  { 1149,	3,	0,	4,	45,	0|(1ULL<<MCID::MayStore), 0x14ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #1149 = STWX8
  { 1150,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #1150 = STXSDX
  { 1151,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #1151 = STXSIWX
  { 1152,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo88, -1 ,nullptr },  // Inst #1152 = STXSSPX
  { 1153,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #1153 = STXVD2X
  { 1154,	3,	0,	4,	59,	0|(1ULL<<MCID::MayStore), 0x0ULL, ImplicitList13, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #1154 = STXVW4X
  { 1155,	3,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1155 = SUBF
  { 1156,	3,	1,	4,	2,	0, 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1156 = SUBF8
  { 1157,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1157 = SUBF8o
  { 1158,	3,	1,	4,	2,	0, 0xcULL, nullptr, ImplicitList2, OperandInfo13, -1 ,nullptr },  // Inst #1158 = SUBFC
  { 1159,	3,	1,	4,	2,	0, 0xcULL, nullptr, ImplicitList2, OperandInfo15, -1 ,nullptr },  // Inst #1159 = SUBFC8
  { 1160,	3,	1,	4,	2,	0, 0xcULL, nullptr, ImplicitList2, OperandInfo15, -1 ,nullptr },  // Inst #1160 = SUBFC8o
  { 1161,	3,	1,	4,	2,	0, 0xcULL, nullptr, ImplicitList3, OperandInfo13, -1 ,nullptr },  // Inst #1161 = SUBFCo
  { 1162,	3,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo13, -1 ,nullptr },  // Inst #1162 = SUBFE
  { 1163,	3,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo15, -1 ,nullptr },  // Inst #1163 = SUBFE8
  { 1164,	3,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo15, -1 ,nullptr },  // Inst #1164 = SUBFE8o
  { 1165,	3,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo13, -1 ,nullptr },  // Inst #1165 = SUBFEo
  { 1166,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList2, OperandInfo14, -1 ,nullptr },  // Inst #1166 = SUBFIC
  { 1167,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList2, OperandInfo16, -1 ,nullptr },  // Inst #1167 = SUBFIC8
  { 1168,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo21, -1 ,nullptr },  // Inst #1168 = SUBFME
  { 1169,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo22, -1 ,nullptr },  // Inst #1169 = SUBFME8
  { 1170,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo22, -1 ,nullptr },  // Inst #1170 = SUBFME8o
  { 1171,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo21, -1 ,nullptr },  // Inst #1171 = SUBFMEo
  { 1172,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo21, -1 ,nullptr },  // Inst #1172 = SUBFZE
  { 1173,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList2, OperandInfo22, -1 ,nullptr },  // Inst #1173 = SUBFZE8
  { 1174,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo22, -1 ,nullptr },  // Inst #1174 = SUBFZE8o
  { 1175,	2,	1,	4,	2,	0, 0x8ULL, ImplicitList2, ImplicitList3, OperandInfo21, -1 ,nullptr },  // Inst #1175 = SUBFZEo
  { 1176,	3,	1,	4,	2,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #1176 = SUBFo
  { 1177,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1177 = SUBI
  { 1178,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1178 = SUBIC
  { 1179,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1179 = SUBICo
  { 1180,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1180 = SUBIS
  { 1181,	1,	0,	4,	47,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #1181 = SYNC
  { 1182,	2,	1,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1182 = TABORT
  { 1183,	4,	1,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1183 = TABORTDC
  { 1184,	4,	1,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1184 = TABORTDCI
  { 1185,	4,	1,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1185 = TABORTWC
  { 1186,	4,	1,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1186 = TABORTWCI
  { 1187,	1,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1187 = TAILB
  { 1188,	1,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1188 = TAILB8
  { 1189,	1,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1189 = TAILBA
  { 1190,	1,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList13, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1190 = TAILBA8
  { 1191,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, nullptr, nullptr, -1 ,nullptr },  // Inst #1191 = TAILBCTR
  { 1192,	0,	0,	4,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList11, nullptr, nullptr, -1 ,nullptr },  // Inst #1192 = TAILBCTR8
  { 1193,	2,	1,	4,	49,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1193 = TBEGIN
  { 1194,	1,	0,	4,	49,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1194 = TCHECK
  { 1195,	1,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1195 = TCHECK_RET
  { 1196,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList13, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1196 = TCRETURNai
  { 1197,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList13, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1197 = TCRETURNai8
  { 1198,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList13, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1198 = TCRETURNdi
  { 1199,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList13, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1199 = TCRETURNdi8
  { 1200,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList13, nullptr, OperandInfo185, -1 ,nullptr },  // Inst #1200 = TCRETURNri
  { 1201,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList13, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1201 = TCRETURNri8
  { 1202,	3,	0,	4,	77,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1202 = TD
  { 1203,	3,	0,	4,	77,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1203 = TDI
  { 1204,	2,	1,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1204 = TEND
  { 1205,	0,	0,	4,	78,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1205 = TLBIA
  { 1206,	2,	0,	4,	79,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #1206 = TLBIE
  { 1207,	1,	0,	4,	80,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #1207 = TLBIEL
  { 1208,	2,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #1208 = TLBIVAX
  { 1209,	1,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #1209 = TLBLD
  { 1210,	1,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #1210 = TLBLI
  { 1211,	0,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1211 = TLBRE
  { 1212,	3,	1,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1212 = TLBRE2
  { 1213,	2,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #1213 = TLBSX
  { 1214,	3,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1214 = TLBSX2
  { 1215,	3,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1215 = TLBSX2D
  { 1216,	0,	0,	4,	81,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1216 = TLBSYNC
  { 1217,	0,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1217 = TLBWE
  { 1218,	3,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1218 = TLBWE2
  { 1219,	0,	0,	4,	8,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1219 = TRAP
  { 1220,	1,	1,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1220 = TRECHKPT
  { 1221,	2,	1,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #1221 = TRECLAIM
  { 1222,	2,	1,	4,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1222 = TSR
  { 1223,	3,	0,	4,	82,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #1223 = TW
  { 1224,	3,	0,	4,	82,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #1224 = TWI
  { 1225,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #1225 = UPDATE_VRSAVE
  { 1226,	3,	2,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1226 = UpdateGBR
  { 1227,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1227 = VADDCUQ
  { 1228,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1228 = VADDCUW
  { 1229,	4,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1229 = VADDECUQ
  { 1230,	4,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1230 = VADDEUQM
  { 1231,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1231 = VADDFP
  { 1232,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1232 = VADDSBS
  { 1233,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1233 = VADDSHS
  { 1234,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1234 = VADDSWS
  { 1235,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1235 = VADDUBM
  { 1236,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1236 = VADDUBS
  { 1237,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1237 = VADDUDM
  { 1238,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1238 = VADDUHM
  { 1239,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1239 = VADDUHS
  { 1240,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1240 = VADDUQM
  { 1241,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1241 = VADDUWM
  { 1242,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1242 = VADDUWS
  { 1243,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1243 = VAND
  { 1244,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1244 = VANDC
  { 1245,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1245 = VAVGSB
  { 1246,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1246 = VAVGSH
  { 1247,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1247 = VAVGSW
  { 1248,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1248 = VAVGUB
  { 1249,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1249 = VAVGUH
  { 1250,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1250 = VAVGUW
  { 1251,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1251 = VBPERMQ
  { 1252,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1252 = VCFSX
  { 1253,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1253 = VCFSX_0
  { 1254,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1254 = VCFUX
  { 1255,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1255 = VCFUX_0
  { 1256,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1256 = VCIPHER
  { 1257,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1257 = VCIPHERLAST
  { 1258,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1258 = VCLZB
  { 1259,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1259 = VCLZD
  { 1260,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1260 = VCLZH
  { 1261,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1261 = VCLZW
  { 1262,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1262 = VCMPBFP
  { 1263,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1263 = VCMPBFPo
  { 1264,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1264 = VCMPEQFP
  { 1265,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1265 = VCMPEQFPo
  { 1266,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1266 = VCMPEQUB
  { 1267,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1267 = VCMPEQUBo
  { 1268,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1268 = VCMPEQUD
  { 1269,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1269 = VCMPEQUDo
  { 1270,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1270 = VCMPEQUH
  { 1271,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1271 = VCMPEQUHo
  { 1272,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1272 = VCMPEQUW
  { 1273,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1273 = VCMPEQUWo
  { 1274,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1274 = VCMPGEFP
  { 1275,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1275 = VCMPGEFPo
  { 1276,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1276 = VCMPGTFP
  { 1277,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1277 = VCMPGTFPo
  { 1278,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1278 = VCMPGTSB
  { 1279,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1279 = VCMPGTSBo
  { 1280,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1280 = VCMPGTSD
  { 1281,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1281 = VCMPGTSDo
  { 1282,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1282 = VCMPGTSH
  { 1283,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1283 = VCMPGTSHo
  { 1284,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1284 = VCMPGTSW
  { 1285,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1285 = VCMPGTSWo
  { 1286,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1286 = VCMPGTUB
  { 1287,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1287 = VCMPGTUBo
  { 1288,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1288 = VCMPGTUD
  { 1289,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1289 = VCMPGTUDo
  { 1290,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1290 = VCMPGTUH
  { 1291,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1291 = VCMPGTUHo
  { 1292,	3,	1,	4,	83,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1292 = VCMPGTUW
  { 1293,	3,	1,	4,	83,	0, 0x28ULL, nullptr, ImplicitList24, OperandInfo192, -1 ,nullptr },  // Inst #1293 = VCMPGTUWo
  { 1294,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1294 = VCTSXS
  { 1295,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1295 = VCTSXS_0
  { 1296,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1296 = VCTUXS
  { 1297,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1297 = VCTUXS_0
  { 1298,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1298 = VEQV
  { 1299,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1299 = VEXPTEFP
  { 1300,	2,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1300 = VGBBD
  { 1301,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1301 = VLOGEFP
  { 1302,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1302 = VMADDFP
  { 1303,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1303 = VMAXFP
  { 1304,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1304 = VMAXSB
  { 1305,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1305 = VMAXSD
  { 1306,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1306 = VMAXSH
  { 1307,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1307 = VMAXSW
  { 1308,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1308 = VMAXUB
  { 1309,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1309 = VMAXUD
  { 1310,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1310 = VMAXUH
  { 1311,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1311 = VMAXUW
  { 1312,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1312 = VMHADDSHS
  { 1313,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1313 = VMHRADDSHS
  { 1314,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1314 = VMINFP
  { 1315,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1315 = VMINSB
  { 1316,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1316 = VMINSD
  { 1317,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1317 = VMINSH
  { 1318,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1318 = VMINSW
  { 1319,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1319 = VMINUB
  { 1320,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1320 = VMINUD
  { 1321,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1321 = VMINUH
  { 1322,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1322 = VMINUW
  { 1323,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1323 = VMLADDUHM
  { 1324,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1324 = VMRGEW
  { 1325,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1325 = VMRGHB
  { 1326,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1326 = VMRGHH
  { 1327,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1327 = VMRGHW
  { 1328,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1328 = VMRGLB
  { 1329,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1329 = VMRGLH
  { 1330,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1330 = VMRGLW
  { 1331,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1331 = VMRGOW
  { 1332,	4,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1332 = VMSUMMBM
  { 1333,	4,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1333 = VMSUMSHM
  { 1334,	4,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1334 = VMSUMSHS
  { 1335,	4,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1335 = VMSUMUBM
  { 1336,	4,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1336 = VMSUMUHM
  { 1337,	4,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1337 = VMSUMUHS
  { 1338,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1338 = VMULESB
  { 1339,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1339 = VMULESH
  { 1340,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1340 = VMULESW
  { 1341,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1341 = VMULEUB
  { 1342,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1342 = VMULEUH
  { 1343,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1343 = VMULEUW
  { 1344,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1344 = VMULOSB
  { 1345,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1345 = VMULOSH
  { 1346,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1346 = VMULOSW
  { 1347,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1347 = VMULOUB
  { 1348,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1348 = VMULOUH
  { 1349,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1349 = VMULOUW
  { 1350,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1350 = VMULUWM
  { 1351,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1351 = VNAND
  { 1352,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1352 = VNCIPHER
  { 1353,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1353 = VNCIPHERLAST
  { 1354,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1354 = VNMSUBFP
  { 1355,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1355 = VNOR
  { 1356,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1356 = VOR
  { 1357,	3,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1357 = VORC
  { 1358,	4,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1358 = VPERM
  { 1359,	4,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1359 = VPERMXOR
  { 1360,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1360 = VPKPX
  { 1361,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1361 = VPKSDSS
  { 1362,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1362 = VPKSDUS
  { 1363,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1363 = VPKSHSS
  { 1364,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1364 = VPKSHUS
  { 1365,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1365 = VPKSWSS
  { 1366,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1366 = VPKSWUS
  { 1367,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1367 = VPKUDUM
  { 1368,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1368 = VPKUDUS
  { 1369,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1369 = VPKUHUM
  { 1370,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1370 = VPKUHUS
  { 1371,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1371 = VPKUWUM
  { 1372,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1372 = VPKUWUS
  { 1373,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1373 = VPMSUMB
  { 1374,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1374 = VPMSUMD
  { 1375,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1375 = VPMSUMH
  { 1376,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1376 = VPMSUMW
  { 1377,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1377 = VPOPCNTB
  { 1378,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1378 = VPOPCNTD
  { 1379,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1379 = VPOPCNTH
  { 1380,	2,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1380 = VPOPCNTW
  { 1381,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1381 = VREFP
  { 1382,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1382 = VRFIM
  { 1383,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1383 = VRFIN
  { 1384,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1384 = VRFIP
  { 1385,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1385 = VRFIZ
  { 1386,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1386 = VRLB
  { 1387,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1387 = VRLD
  { 1388,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1388 = VRLH
  { 1389,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1389 = VRLW
  { 1390,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1390 = VRSQRTEFP
  { 1391,	2,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1391 = VSBOX
  { 1392,	4,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1392 = VSEL
  { 1393,	4,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #1393 = VSHASIGMAD
  { 1394,	4,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #1394 = VSHASIGMAW
  { 1395,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1395 = VSL
  { 1396,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1396 = VSLB
  { 1397,	3,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1397 = VSLD
  { 1398,	4,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #1398 = VSLDOI
  { 1399,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1399 = VSLH
  { 1400,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1400 = VSLO
  { 1401,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1401 = VSLW
  { 1402,	3,	1,	4,	58,	0, 0x28ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1402 = VSPLTB
  { 1403,	3,	1,	4,	58,	0, 0x28ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1403 = VSPLTH
  { 1404,	2,	1,	4,	58,	0, 0x28ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #1404 = VSPLTISB
  { 1405,	2,	1,	4,	58,	0, 0x28ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #1405 = VSPLTISH
  { 1406,	2,	1,	4,	58,	0, 0x28ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #1406 = VSPLTISW
  { 1407,	3,	1,	4,	58,	0, 0x28ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1407 = VSPLTW
  { 1408,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1408 = VSR
  { 1409,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1409 = VSRAB
  { 1410,	3,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1410 = VSRAD
  { 1411,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1411 = VSRAH
  { 1412,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1412 = VSRAW
  { 1413,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1413 = VSRB
  { 1414,	3,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1414 = VSRD
  { 1415,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1415 = VSRH
  { 1416,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1416 = VSRO
  { 1417,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1417 = VSRW
  { 1418,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1418 = VSUBCUQ
  { 1419,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1419 = VSUBCUW
  { 1420,	4,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1420 = VSUBECUQ
  { 1421,	4,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1421 = VSUBEUQM
  { 1422,	3,	1,	4,	46,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1422 = VSUBFP
  { 1423,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1423 = VSUBSBS
  { 1424,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1424 = VSUBSHS
  { 1425,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1425 = VSUBSWS
  { 1426,	3,	1,	4,	46,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1426 = VSUBUBM
  { 1427,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1427 = VSUBUBS
  { 1428,	3,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1428 = VSUBUDM
  { 1429,	3,	1,	4,	46,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1429 = VSUBUHM
  { 1430,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1430 = VSUBUHS
  { 1431,	3,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1431 = VSUBUQM
  { 1432,	3,	1,	4,	46,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1432 = VSUBUWM
  { 1433,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1433 = VSUBUWS
  { 1434,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1434 = VSUM2SWS
  { 1435,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1435 = VSUM4SBS
  { 1436,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1436 = VSUM4SHS
  { 1437,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1437 = VSUM4UBS
  { 1438,	3,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1438 = VSUMSWS
  { 1439,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1439 = VUPKHPX
  { 1440,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1440 = VUPKHSB
  { 1441,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1441 = VUPKHSH
  { 1442,	2,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1442 = VUPKHSW
  { 1443,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1443 = VUPKLPX
  { 1444,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1444 = VUPKLSB
  { 1445,	2,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1445 = VUPKLSH
  { 1446,	2,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1446 = VUPKLSW
  { 1447,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x28ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1447 = VXOR
  { 1448,	1,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #1448 = V_SET0
  { 1449,	1,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #1449 = V_SET0B
  { 1450,	1,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #1450 = V_SET0H
  { 1451,	1,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #1451 = V_SETALLONES
  { 1452,	1,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #1452 = V_SETALLONESB
  { 1453,	1,	1,	4,	4,	0, 0x28ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #1453 = V_SETALLONESH
  { 1454,	1,	0,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #1454 = WAIT
  { 1455,	1,	0,	4,	51,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #1455 = WRTEE
  { 1456,	1,	0,	4,	51,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #1456 = WRTEEI
  { 1457,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1457 = XOR
  { 1458,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1458 = XOR8
  { 1459,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1459 = XOR8o
  { 1460,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1460 = XORI
  { 1461,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1461 = XORI8
  { 1462,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1462 = XORIS
  { 1463,	3,	1,	4,	1,	0, 0x8ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1463 = XORIS8
  { 1464,	3,	1,	4,	1,	0|(1ULL<<MCID::Commutable), 0x8ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #1464 = XORo
  { 1465,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1465 = XSABSDP
  { 1466,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1466 = XSADDDP
  { 1467,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1467 = XSADDSP
  { 1468,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1468 = XSCMPODP
  { 1469,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1469 = XSCMPUDP
  { 1470,	3,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1470 = XSCPSGNDP
  { 1471,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1471 = XSCVDPSP
  { 1472,	2,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo203, -1 ,nullptr },  // Inst #1472 = XSCVDPSPN
  { 1473,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1473 = XSCVDPSXDS
  { 1474,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1474 = XSCVDPSXWS
  { 1475,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1475 = XSCVDPUXDS
  { 1476,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1476 = XSCVDPUXWS
  { 1477,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1477 = XSCVSPDP
  { 1478,	2,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo204, -1 ,nullptr },  // Inst #1478 = XSCVSPDPN
  { 1479,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1479 = XSCVSXDDP
  { 1480,	2,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo205, -1 ,nullptr },  // Inst #1480 = XSCVSXDSP
  { 1481,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1481 = XSCVUXDDP
  { 1482,	2,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo205, -1 ,nullptr },  // Inst #1482 = XSCVUXDSP
  { 1483,	3,	1,	4,	14,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1483 = XSDIVDP
  { 1484,	3,	1,	4,	15,	0, 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1484 = XSDIVSP
  { 1485,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1485 = XSMADDADP
  { 1486,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1486 = XSMADDASP
  { 1487,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1487 = XSMADDMDP
  { 1488,	4,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1488 = XSMADDMSP
  { 1489,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1489 = XSMAXDP
  { 1490,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1490 = XSMINDP
  { 1491,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1491 = XSMSUBADP
  { 1492,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1492 = XSMSUBASP
  { 1493,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1493 = XSMSUBMDP
  { 1494,	4,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1494 = XSMSUBMSP
  { 1495,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1495 = XSMULDP
  { 1496,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1496 = XSMULSP
  { 1497,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1497 = XSNABSDP
  { 1498,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1498 = XSNEGDP
  { 1499,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1499 = XSNMADDADP
  { 1500,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1500 = XSNMADDASP
  { 1501,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1501 = XSNMADDMDP
  { 1502,	4,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1502 = XSNMADDMSP
  { 1503,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1503 = XSNMSUBADP
  { 1504,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1504 = XSNMSUBASP
  { 1505,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1505 = XSNMSUBMDP
  { 1506,	4,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1506 = XSNMSUBMSP
  { 1507,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1507 = XSRDPI
  { 1508,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1508 = XSRDPIC
  { 1509,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1509 = XSRDPIM
  { 1510,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1510 = XSRDPIP
  { 1511,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1511 = XSRDPIZ
  { 1512,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1512 = XSREDP
  { 1513,	2,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo208, -1 ,nullptr },  // Inst #1513 = XSRESP
  { 1514,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1514 = XSRSQRTEDP
  { 1515,	2,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo208, -1 ,nullptr },  // Inst #1515 = XSRSQRTESP
  { 1516,	2,	1,	4,	17,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1516 = XSSQRTDP
  { 1517,	2,	1,	4,	18,	0, 0x0ULL, nullptr, nullptr, OperandInfo208, -1 ,nullptr },  // Inst #1517 = XSSQRTSP
  { 1518,	3,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1518 = XSSUBDP
  { 1519,	3,	1,	4,	4,	0, 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1519 = XSSUBSP
  { 1520,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1520 = XSTDIVDP
  { 1521,	2,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo209, -1 ,nullptr },  // Inst #1521 = XSTSQRTDP
  { 1522,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1522 = XVABSDP
  { 1523,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1523 = XVABSSP
  { 1524,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1524 = XVADDDP
  { 1525,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1525 = XVADDSP
  { 1526,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1526 = XVCMPEQDP
  { 1527,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, ImplicitList24, OperandInfo211, -1 ,nullptr },  // Inst #1527 = XVCMPEQDPo
  { 1528,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1528 = XVCMPEQSP
  { 1529,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, ImplicitList24, OperandInfo211, -1 ,nullptr },  // Inst #1529 = XVCMPEQSPo
  { 1530,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1530 = XVCMPGEDP
  { 1531,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, ImplicitList24, OperandInfo211, -1 ,nullptr },  // Inst #1531 = XVCMPGEDPo
  { 1532,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1532 = XVCMPGESP
  { 1533,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, ImplicitList24, OperandInfo211, -1 ,nullptr },  // Inst #1533 = XVCMPGESPo
  { 1534,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1534 = XVCMPGTDP
  { 1535,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, ImplicitList24, OperandInfo211, -1 ,nullptr },  // Inst #1535 = XVCMPGTDPo
  { 1536,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1536 = XVCMPGTSP
  { 1537,	3,	1,	4,	83,	0, 0x0ULL, ImplicitList13, ImplicitList24, OperandInfo211, -1 ,nullptr },  // Inst #1537 = XVCMPGTSPo
  { 1538,	3,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1538 = XVCPSGNDP
  { 1539,	3,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1539 = XVCPSGNSP
  { 1540,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1540 = XVCVDPSP
  { 1541,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1541 = XVCVDPSXDS
  { 1542,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1542 = XVCVDPSXWS
  { 1543,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1543 = XVCVDPUXDS
  { 1544,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1544 = XVCVDPUXWS
  { 1545,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1545 = XVCVSPDP
  { 1546,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1546 = XVCVSPSXDS
  { 1547,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1547 = XVCVSPSXWS
  { 1548,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1548 = XVCVSPUXDS
  { 1549,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1549 = XVCVSPUXWS
  { 1550,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1550 = XVCVSXDDP
  { 1551,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1551 = XVCVSXDSP
  { 1552,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1552 = XVCVSXWDP
  { 1553,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1553 = XVCVSXWSP
  { 1554,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1554 = XVCVUXDDP
  { 1555,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1555 = XVCVUXDSP
  { 1556,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1556 = XVCVUXWDP
  { 1557,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1557 = XVCVUXWSP
  { 1558,	3,	1,	4,	14,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1558 = XVDIVDP
  { 1559,	3,	1,	4,	15,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1559 = XVDIVSP
  { 1560,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1560 = XVMADDADP
  { 1561,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1561 = XVMADDASP
  { 1562,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1562 = XVMADDMDP
  { 1563,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1563 = XVMADDMSP
  { 1564,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1564 = XVMAXDP
  { 1565,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1565 = XVMAXSP
  { 1566,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1566 = XVMINDP
  { 1567,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1567 = XVMINSP
  { 1568,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1568 = XVMSUBADP
  { 1569,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1569 = XVMSUBASP
  { 1570,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1570 = XVMSUBMDP
  { 1571,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1571 = XVMSUBMSP
  { 1572,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1572 = XVMULDP
  { 1573,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1573 = XVMULSP
  { 1574,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1574 = XVNABSDP
  { 1575,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1575 = XVNABSSP
  { 1576,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1576 = XVNEGDP
  { 1577,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1577 = XVNEGSP
  { 1578,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1578 = XVNMADDADP
  { 1579,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1579 = XVNMADDASP
  { 1580,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1580 = XVNMADDMDP
  { 1581,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1581 = XVNMADDMSP
  { 1582,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1582 = XVNMSUBADP
  { 1583,	4,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1583 = XVNMSUBASP
  { 1584,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1584 = XVNMSUBMDP
  { 1585,	4,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #1585 = XVNMSUBMSP
  { 1586,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1586 = XVRDPI
  { 1587,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1587 = XVRDPIC
  { 1588,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1588 = XVRDPIM
  { 1589,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1589 = XVRDPIP
  { 1590,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1590 = XVRDPIZ
  { 1591,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1591 = XVREDP
  { 1592,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1592 = XVRESP
  { 1593,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1593 = XVRSPI
  { 1594,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1594 = XVRSPIC
  { 1595,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1595 = XVRSPIM
  { 1596,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1596 = XVRSPIP
  { 1597,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1597 = XVRSPIZ
  { 1598,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1598 = XVRSQRTEDP
  { 1599,	2,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1599 = XVRSQRTESP
  { 1600,	2,	1,	4,	17,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1600 = XVSQRTDP
  { 1601,	2,	1,	4,	18,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #1601 = XVSQRTSP
  { 1602,	3,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1602 = XVSUBDP
  { 1603,	3,	1,	4,	4,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1603 = XVSUBSP
  { 1604,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #1604 = XVTDIVDP
  { 1605,	3,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #1605 = XVTDIVSP
  { 1606,	2,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo214, -1 ,nullptr },  // Inst #1606 = XVTSQRTDP
  { 1607,	2,	1,	4,	13,	0, 0x0ULL, ImplicitList13, nullptr, OperandInfo214, -1 ,nullptr },  // Inst #1607 = XVTSQRTSP
  { 1608,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1608 = XXLAND
  { 1609,	3,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1609 = XXLANDC
  { 1610,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1610 = XXLEQV
  { 1611,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1611 = XXLNAND
  { 1612,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1612 = XXLNOR
  { 1613,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1613 = XXLOR
  { 1614,	3,	1,	4,	46,	0, 0x0ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1614 = XXLORC
  { 1615,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1615 = XXLORf
  { 1616,	3,	1,	4,	46,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1616 = XXLXOR
  { 1617,	3,	1,	4,	58,	0, 0x0ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1617 = XXMRGHW
  { 1618,	3,	1,	4,	58,	0, 0x0ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #1618 = XXMRGLW
  { 1619,	4,	1,	4,	58,	0, 0x0ULL, nullptr, nullptr, OperandInfo215, -1 ,nullptr },  // Inst #1619 = XXPERMDI
  { 1620,	4,	1,	4,	58,	0, 0x0ULL, nullptr, nullptr, OperandInfo216, -1 ,nullptr },  // Inst #1620 = XXSEL
  { 1621,	4,	1,	4,	58,	0, 0x0ULL, nullptr, nullptr, OperandInfo215, -1 ,nullptr },  // Inst #1621 = XXSLDWI
  { 1622,	3,	1,	4,	58,	0, 0x0ULL, nullptr, nullptr, OperandInfo217, -1 ,nullptr },  // Inst #1622 = XXSPLTW
  { 1623,	3,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo218, -1 ,nullptr },  // Inst #1623 = gBC
  { 1624,	3,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList7, OperandInfo218, -1 ,nullptr },  // Inst #1624 = gBCA
  { 1625,	3,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, OperandInfo219, -1 ,nullptr },  // Inst #1625 = gBCCTR
  { 1626,	3,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList25, OperandInfo219, -1 ,nullptr },  // Inst #1626 = gBCCTRL
  { 1627,	3,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList25, OperandInfo218, -1 ,nullptr },  // Inst #1627 = gBCL
  { 1628,	3,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList9, ImplicitList25, OperandInfo218, -1 ,nullptr },  // Inst #1628 = gBCLA
  { 1629,	3,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList7, OperandInfo219, -1 ,nullptr },  // Inst #1629 = gBCLR
  { 1630,	3,	0,	4,	3,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL, ImplicitList16, ImplicitList25, OperandInfo219, -1 ,nullptr },  // Inst #1630 = gBCLRL
};

static inline void InitPPCMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(PPCInsts, NULL, NULL, 1631);
}

} // end llvm namespace 
#endif // GET_INSTRINFO_MC_DESC


#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER
namespace llvm_ks {
struct PPCGenInstrInfo : public TargetInstrInfo {
  explicit PPCGenInstrInfo(int CFSetupOpcode = -1, int CFDestroyOpcode = -1, int CatchRetOpcode = -1);
  ~PPCGenInstrInfo() override {}
};
} // end llvm namespace 
#endif // GET_INSTRINFO_HEADER


#ifdef GET_INSTRINFO_OPERAND_ENUM
#undef GET_INSTRINFO_OPERAND_ENUM
namespace llvm_ks {
namespace PPC {
namespace OpName { 
enum {
OPERAND_LAST
};
} // end namespace OpName
} // end namespace PPC
} // end namespace llvm_ks
#endif //GET_INSTRINFO_OPERAND_ENUM
#ifdef GET_INSTRINFO_NAMED_OPS
#undef GET_INSTRINFO_NAMED_OPS
namespace llvm_ks {
namespace PPC {
LLVM_READONLY
int16_t getNamedOperandIdx(uint16_t Opcode, uint16_t NamedIdx) {
  return -1;
}
} // end namespace PPC
} // end namespace llvm_ks
#endif //GET_INSTRINFO_NAMED_OPS

#ifdef GET_INSTRINFO_OPERAND_TYPES_ENUM
#undef GET_INSTRINFO_OPERAND_TYPES_ENUM
namespace llvm_ks {
namespace PPC {
namespace OpTypes { 
enum OperandType {
  abscalltarget = 0,
  abscondbrtarget = 1,
  absdirectbrtarget = 2,
  calltarget = 3,
  condbrtarget = 4,
  crbitm = 5,
  directbrtarget = 6,
  dispRI = 7,
  dispRIX = 8,
  dispSPE2 = 9,
  dispSPE4 = 10,
  dispSPE8 = 11,
  f32imm = 12,
  f64imm = 13,
  i16imm = 14,
  i1imm = 15,
  i32imm = 16,
  i64imm = 17,
  i8imm = 18,
  imm32SExt16 = 19,
  imm64SExt16 = 20,
  imm64ZExt32 = 21,
  memr = 22,
  memri = 23,
  memrix = 24,
  memrr = 25,
  pred = 26,
  ptr_rc_idx = 27,
  ptr_rc_nor0 = 28,
  s16imm = 29,
  s16imm64 = 30,
  s17imm = 31,
  s17imm64 = 32,
  s5imm = 33,
  spe2dis = 34,
  spe4dis = 35,
  spe8dis = 36,
  tlscall = 37,
  tlscall32 = 38,
  tlsgd = 39,
  tlsgd32 = 40,
  tlsreg = 41,
  tlsreg32 = 42,
  tocentry = 43,
  tocentry32 = 44,
  u10imm = 45,
  u12imm = 46,
  u16imm = 47,
  u16imm64 = 48,
  u1imm = 49,
  u2imm = 50,
  u3imm = 51,
  u4imm = 52,
  u5imm = 53,
  u6imm = 54,
  OPERAND_TYPE_LIST_END
};
} // end namespace OpTypes
} // end namespace PPC
} // end namespace llvm_ks
#endif // GET_INSTRINFO_OPERAND_TYPES_ENUM
#ifdef GET_INSTRMAP_INFO
#undef GET_INSTRMAP_INFO
namespace llvm_ks {

namespace PPC {

enum IsVSXFMAAlt {
	IsVSXFMAAlt_1
};

enum RC {
	RC_0,
	RC_1
};

// getAltVSXFMAOpcode
LLVM_READONLY
int getAltVSXFMAOpcode(uint16_t Opcode) {
static const uint16_t getAltVSXFMAOpcodeTable[][2] = {
  { PPC::XSMADDADP, PPC::XSMADDMDP },
  { PPC::XSMADDASP, PPC::XSMADDMSP },
  { PPC::XSMSUBADP, PPC::XSMSUBMDP },
  { PPC::XSMSUBASP, PPC::XSMSUBMSP },
  { PPC::XSNMADDADP, PPC::XSNMADDMDP },
  { PPC::XSNMADDASP, PPC::XSNMADDMSP },
  { PPC::XSNMSUBADP, PPC::XSNMSUBMDP },
  { PPC::XSNMSUBASP, PPC::XSNMSUBMSP },
  { PPC::XVMADDADP, PPC::XVMADDMDP },
  { PPC::XVMADDASP, PPC::XVMADDMSP },
  { PPC::XVMSUBADP, PPC::XVMSUBMDP },
  { PPC::XVMSUBASP, PPC::XVMSUBMSP },
  { PPC::XVNMADDADP, PPC::XVNMADDMDP },
  { PPC::XVNMADDASP, PPC::XVNMADDMSP },
  { PPC::XVNMSUBADP, PPC::XVNMSUBMDP },
  { PPC::XVNMSUBASP, PPC::XVNMSUBMSP },
}; // End of getAltVSXFMAOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 16;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getAltVSXFMAOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getAltVSXFMAOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getAltVSXFMAOpcodeTable[mid][1];
}

// getNonRecordFormOpcode
LLVM_READONLY
int getNonRecordFormOpcode(uint16_t Opcode) {
static const uint16_t getNonRecordFormOpcodeTable[][2] = {
  { PPC::ADD4o, PPC::ADD4 },
  { PPC::ADD8o, PPC::ADD8 },
  { PPC::ADDC8o, PPC::ADDC8 },
  { PPC::ADDCo, PPC::ADDC },
  { PPC::ADDE8o, PPC::ADDE8 },
  { PPC::ADDEo, PPC::ADDE },
  { PPC::ADDICo, PPC::ADDIC },
  { PPC::ADDME8o, PPC::ADDME8 },
  { PPC::ADDMEo, PPC::ADDME },
  { PPC::ADDZE8o, PPC::ADDZE8 },
  { PPC::ADDZEo, PPC::ADDZE },
  { PPC::AND8o, PPC::AND8 },
  { PPC::ANDC8o, PPC::ANDC8 },
  { PPC::ANDCo, PPC::ANDC },
  { PPC::ANDo, PPC::AND },
  { PPC::CNTLZDo, PPC::CNTLZD },
  { PPC::CNTLZW8o, PPC::CNTLZW8 },
  { PPC::CNTLZWo, PPC::CNTLZW },
  { PPC::DIVDUo, PPC::DIVDU },
  { PPC::DIVDo, PPC::DIVD },
  { PPC::DIVWUo, PPC::DIVWU },
  { PPC::DIVWo, PPC::DIVW },
  { PPC::EQV8o, PPC::EQV8 },
  { PPC::EQVo, PPC::EQV },
  { PPC::EXTSB8o, PPC::EXTSB8 },
  { PPC::EXTSBo, PPC::EXTSB },
  { PPC::EXTSH8o, PPC::EXTSH8 },
  { PPC::EXTSHo, PPC::EXTSH },
  { PPC::EXTSW_32_64o, PPC::EXTSW_32_64 },
  { PPC::EXTSWo, PPC::EXTSW },
  { PPC::FABSDo, PPC::FABSD },
  { PPC::FABSSo, PPC::FABSS },
  { PPC::FADDSo, PPC::FADDS },
  { PPC::FADDo, PPC::FADD },
  { PPC::FCFIDSo, PPC::FCFIDS },
  { PPC::FCFIDUSo, PPC::FCFIDUS },
  { PPC::FCFIDUo, PPC::FCFIDU },
  { PPC::FCFIDo, PPC::FCFID },
  { PPC::FCPSGNDo, PPC::FCPSGND },
  { PPC::FCPSGNSo, PPC::FCPSGNS },
  { PPC::FCTIDUZo, PPC::FCTIDUZ },
  { PPC::FCTIDZo, PPC::FCTIDZ },
  { PPC::FCTIDo, PPC::FCTID },
  { PPC::FCTIWUZo, PPC::FCTIWUZ },
  { PPC::FCTIWZo, PPC::FCTIWZ },
  { PPC::FCTIWo, PPC::FCTIW },
  { PPC::FDIVSo, PPC::FDIVS },
  { PPC::FDIVo, PPC::FDIV },
  { PPC::FMADDSo, PPC::FMADDS },
  { PPC::FMADDo, PPC::FMADD },
  { PPC::FMRo, PPC::FMR },
  { PPC::FMSUBSo, PPC::FMSUBS },
  { PPC::FMSUBo, PPC::FMSUB },
  { PPC::FMULSo, PPC::FMULS },
  { PPC::FMULo, PPC::FMUL },
  { PPC::FNABSDo, PPC::FNABSD },
  { PPC::FNABSSo, PPC::FNABSS },
  { PPC::FNEGDo, PPC::FNEGD },
  { PPC::FNEGSo, PPC::FNEGS },
  { PPC::FNMADDSo, PPC::FNMADDS },
  { PPC::FNMADDo, PPC::FNMADD },
  { PPC::FNMSUBSo, PPC::FNMSUBS },
  { PPC::FNMSUBo, PPC::FNMSUB },
  { PPC::FRESo, PPC::FRES },
  { PPC::FREo, PPC::FRE },
  { PPC::FRIMDo, PPC::FRIMD },
  { PPC::FRIMSo, PPC::FRIMS },
  { PPC::FRINDo, PPC::FRIND },
  { PPC::FRINSo, PPC::FRINS },
  { PPC::FRIPDo, PPC::FRIPD },
  { PPC::FRIPSo, PPC::FRIPS },
  { PPC::FRIZDo, PPC::FRIZD },
  { PPC::FRIZSo, PPC::FRIZS },
  { PPC::FRSPo, PPC::FRSP },
  { PPC::FRSQRTESo, PPC::FRSQRTES },
  { PPC::FRSQRTEo, PPC::FRSQRTE },
  { PPC::FSELDo, PPC::FSELD },
  { PPC::FSELSo, PPC::FSELS },
  { PPC::FSQRTSo, PPC::FSQRTS },
  { PPC::FSQRTo, PPC::FSQRT },
  { PPC::FSUBSo, PPC::FSUBS },
  { PPC::FSUBo, PPC::FSUB },
  { PPC::MULHDUo, PPC::MULHDU },
  { PPC::MULHDo, PPC::MULHD },
  { PPC::MULHWUo, PPC::MULHWU },
  { PPC::MULHWo, PPC::MULHW },
  { PPC::MULLDo, PPC::MULLD },
  { PPC::MULLWo, PPC::MULLW },
  { PPC::NAND8o, PPC::NAND8 },
  { PPC::NANDo, PPC::NAND },
  { PPC::NEG8o, PPC::NEG8 },
  { PPC::NEGo, PPC::NEG },
  { PPC::NOR8o, PPC::NOR8 },
  { PPC::NORo, PPC::NOR },
  { PPC::OR8o, PPC::OR8 },
  { PPC::ORC8o, PPC::ORC8 },
  { PPC::ORCo, PPC::ORC },
  { PPC::ORo, PPC::OR },
  { PPC::RLDCLo, PPC::RLDCL },
  { PPC::RLDCRo, PPC::RLDCR },
  { PPC::RLDICLo, PPC::RLDICL },
  { PPC::RLDICRo, PPC::RLDICR },
  { PPC::RLDICo, PPC::RLDIC },
  { PPC::RLDIMIo, PPC::RLDIMI },
  { PPC::RLWIMI8o, PPC::RLWIMI8 },
  { PPC::RLWIMIo, PPC::RLWIMI },
  { PPC::RLWINM8o, PPC::RLWINM8 },
  { PPC::RLWINMo, PPC::RLWINM },
  { PPC::RLWNM8o, PPC::RLWNM8 },
  { PPC::RLWNMo, PPC::RLWNM },
  { PPC::SLDo, PPC::SLD },
  { PPC::SLW8o, PPC::SLW8 },
  { PPC::SLWo, PPC::SLW },
  { PPC::SRADIo, PPC::SRADI },
  { PPC::SRADo, PPC::SRAD },
  { PPC::SRAWIo, PPC::SRAWI },
  { PPC::SRAWo, PPC::SRAW },
  { PPC::SRDo, PPC::SRD },
  { PPC::SRW8o, PPC::SRW8 },
  { PPC::SRWo, PPC::SRW },
  { PPC::SUBF8o, PPC::SUBF8 },
  { PPC::SUBFC8o, PPC::SUBFC8 },
  { PPC::SUBFCo, PPC::SUBFC },
  { PPC::SUBFE8o, PPC::SUBFE8 },
  { PPC::SUBFEo, PPC::SUBFE },
  { PPC::SUBFME8o, PPC::SUBFME8 },
  { PPC::SUBFMEo, PPC::SUBFME },
  { PPC::SUBFZE8o, PPC::SUBFZE8 },
  { PPC::SUBFZEo, PPC::SUBFZE },
  { PPC::SUBFo, PPC::SUBF },
  { PPC::XOR8o, PPC::XOR8 },
  { PPC::XORo, PPC::XOR },
}; // End of getNonRecordFormOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 132;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getNonRecordFormOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getNonRecordFormOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getNonRecordFormOpcodeTable[mid][1];
}

// getRecordFormOpcode
LLVM_READONLY
int getRecordFormOpcode(uint16_t Opcode) {
static const uint16_t getRecordFormOpcodeTable[][2] = {
  { PPC::ADD4, PPC::ADD4o },
  { PPC::ADD8, PPC::ADD8o },
  { PPC::ADDC, PPC::ADDCo },
  { PPC::ADDC8, PPC::ADDC8o },
  { PPC::ADDE, PPC::ADDEo },
  { PPC::ADDE8, PPC::ADDE8o },
  { PPC::ADDIC, PPC::ADDICo },
  { PPC::ADDME, PPC::ADDMEo },
  { PPC::ADDME8, PPC::ADDME8o },
  { PPC::ADDZE, PPC::ADDZEo },
  { PPC::ADDZE8, PPC::ADDZE8o },
  { PPC::AND, PPC::ANDo },
  { PPC::AND8, PPC::AND8o },
  { PPC::ANDC, PPC::ANDCo },
  { PPC::ANDC8, PPC::ANDC8o },
  { PPC::CNTLZD, PPC::CNTLZDo },
  { PPC::CNTLZW, PPC::CNTLZWo },
  { PPC::CNTLZW8, PPC::CNTLZW8o },
  { PPC::DIVD, PPC::DIVDo },
  { PPC::DIVDU, PPC::DIVDUo },
  { PPC::DIVW, PPC::DIVWo },
  { PPC::DIVWU, PPC::DIVWUo },
  { PPC::EQV, PPC::EQVo },
  { PPC::EQV8, PPC::EQV8o },
  { PPC::EXTSB, PPC::EXTSBo },
  { PPC::EXTSB8, PPC::EXTSB8o },
  { PPC::EXTSH, PPC::EXTSHo },
  { PPC::EXTSH8, PPC::EXTSH8o },
  { PPC::EXTSW, PPC::EXTSWo },
  { PPC::EXTSW_32_64, PPC::EXTSW_32_64o },
  { PPC::FABSD, PPC::FABSDo },
  { PPC::FABSS, PPC::FABSSo },
  { PPC::FADD, PPC::FADDo },
  { PPC::FADDS, PPC::FADDSo },
  { PPC::FCFID, PPC::FCFIDo },
  { PPC::FCFIDS, PPC::FCFIDSo },
  { PPC::FCFIDU, PPC::FCFIDUo },
  { PPC::FCFIDUS, PPC::FCFIDUSo },
  { PPC::FCPSGND, PPC::FCPSGNDo },
  { PPC::FCPSGNS, PPC::FCPSGNSo },
  { PPC::FCTID, PPC::FCTIDo },
  { PPC::FCTIDUZ, PPC::FCTIDUZo },
  { PPC::FCTIDZ, PPC::FCTIDZo },
  { PPC::FCTIW, PPC::FCTIWo },
  { PPC::FCTIWUZ, PPC::FCTIWUZo },
  { PPC::FCTIWZ, PPC::FCTIWZo },
  { PPC::FDIV, PPC::FDIVo },
  { PPC::FDIVS, PPC::FDIVSo },
  { PPC::FMADD, PPC::FMADDo },
  { PPC::FMADDS, PPC::FMADDSo },
  { PPC::FMR, PPC::FMRo },
  { PPC::FMSUB, PPC::FMSUBo },
  { PPC::FMSUBS, PPC::FMSUBSo },
  { PPC::FMUL, PPC::FMULo },
  { PPC::FMULS, PPC::FMULSo },
  { PPC::FNABSD, PPC::FNABSDo },
  { PPC::FNABSS, PPC::FNABSSo },
  { PPC::FNEGD, PPC::FNEGDo },
  { PPC::FNEGS, PPC::FNEGSo },
  { PPC::FNMADD, PPC::FNMADDo },
  { PPC::FNMADDS, PPC::FNMADDSo },
  { PPC::FNMSUB, PPC::FNMSUBo },
  { PPC::FNMSUBS, PPC::FNMSUBSo },
  { PPC::FRE, PPC::FREo },
  { PPC::FRES, PPC::FRESo },
  { PPC::FRIMD, PPC::FRIMDo },
  { PPC::FRIMS, PPC::FRIMSo },
  { PPC::FRIND, PPC::FRINDo },
  { PPC::FRINS, PPC::FRINSo },
  { PPC::FRIPD, PPC::FRIPDo },
  { PPC::FRIPS, PPC::FRIPSo },
  { PPC::FRIZD, PPC::FRIZDo },
  { PPC::FRIZS, PPC::FRIZSo },
  { PPC::FRSP, PPC::FRSPo },
  { PPC::FRSQRTE, PPC::FRSQRTEo },
  { PPC::FRSQRTES, PPC::FRSQRTESo },
  { PPC::FSELD, PPC::FSELDo },
  { PPC::FSELS, PPC::FSELSo },
  { PPC::FSQRT, PPC::FSQRTo },
  { PPC::FSQRTS, PPC::FSQRTSo },
  { PPC::FSUB, PPC::FSUBo },
  { PPC::FSUBS, PPC::FSUBSo },
  { PPC::MULHD, PPC::MULHDo },
  { PPC::MULHDU, PPC::MULHDUo },
  { PPC::MULHW, PPC::MULHWo },
  { PPC::MULHWU, PPC::MULHWUo },
  { PPC::MULLD, PPC::MULLDo },
  { PPC::MULLW, PPC::MULLWo },
  { PPC::NAND, PPC::NANDo },
  { PPC::NAND8, PPC::NAND8o },
  { PPC::NEG, PPC::NEGo },
  { PPC::NEG8, PPC::NEG8o },
  { PPC::NOR, PPC::NORo },
  { PPC::NOR8, PPC::NOR8o },
  { PPC::OR, PPC::ORo },
  { PPC::OR8, PPC::OR8o },
  { PPC::ORC, PPC::ORCo },
  { PPC::ORC8, PPC::ORC8o },
  { PPC::RLDCL, PPC::RLDCLo },
  { PPC::RLDCR, PPC::RLDCRo },
  { PPC::RLDIC, PPC::RLDICo },
  { PPC::RLDICL, PPC::RLDICLo },
  { PPC::RLDICR, PPC::RLDICRo },
  { PPC::RLDIMI, PPC::RLDIMIo },
  { PPC::RLWIMI, PPC::RLWIMIo },
  { PPC::RLWIMI8, PPC::RLWIMI8o },
  { PPC::RLWINM, PPC::RLWINMo },
  { PPC::RLWINM8, PPC::RLWINM8o },
  { PPC::RLWNM, PPC::RLWNMo },
  { PPC::RLWNM8, PPC::RLWNM8o },
  { PPC::SLD, PPC::SLDo },
  { PPC::SLW, PPC::SLWo },
  { PPC::SLW8, PPC::SLW8o },
  { PPC::SRAD, PPC::SRADo },
  { PPC::SRADI, PPC::SRADIo },
  { PPC::SRAW, PPC::SRAWo },
  { PPC::SRAWI, PPC::SRAWIo },
  { PPC::SRD, PPC::SRDo },
  { PPC::SRW, PPC::SRWo },
  { PPC::SRW8, PPC::SRW8o },
  { PPC::SUBF, PPC::SUBFo },
  { PPC::SUBF8, PPC::SUBF8o },
  { PPC::SUBFC, PPC::SUBFCo },
  { PPC::SUBFC8, PPC::SUBFC8o },
  { PPC::SUBFE, PPC::SUBFEo },
  { PPC::SUBFE8, PPC::SUBFE8o },
  { PPC::SUBFME, PPC::SUBFMEo },
  { PPC::SUBFME8, PPC::SUBFME8o },
  { PPC::SUBFZE, PPC::SUBFZEo },
  { PPC::SUBFZE8, PPC::SUBFZE8o },
  { PPC::XOR, PPC::XORo },
  { PPC::XOR8, PPC::XOR8o },
}; // End of getRecordFormOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 132;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getRecordFormOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getRecordFormOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getRecordFormOpcodeTable[mid][1];
}

} // End PPC namespace
} // End llvm namespace
#endif // GET_INSTRMAP_INFO

