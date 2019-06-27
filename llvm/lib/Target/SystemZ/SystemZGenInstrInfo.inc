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

namespace SystemZ {
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
    A	= 24,
    ADB	= 25,
    ADBR	= 26,
    ADJCALLSTACKDOWN	= 27,
    ADJCALLSTACKUP	= 28,
    ADJDYNALLOC	= 29,
    AEB	= 30,
    AEBR	= 31,
    AEXT128_64	= 32,
    AFI	= 33,
    AFIMux	= 34,
    AG	= 35,
    AGF	= 36,
    AGFI	= 37,
    AGFR	= 38,
    AGHI	= 39,
    AGHIK	= 40,
    AGR	= 41,
    AGRK	= 42,
    AGSI	= 43,
    AH	= 44,
    AHI	= 45,
    AHIK	= 46,
    AHIMux	= 47,
    AHIMuxK	= 48,
    AHY	= 49,
    AIH	= 50,
    AL	= 51,
    ALC	= 52,
    ALCG	= 53,
    ALCGR	= 54,
    ALCR	= 55,
    ALFI	= 56,
    ALG	= 57,
    ALGF	= 58,
    ALGFI	= 59,
    ALGFR	= 60,
    ALGHSIK	= 61,
    ALGR	= 62,
    ALGRK	= 63,
    ALHSIK	= 64,
    ALR	= 65,
    ALRK	= 66,
    ALY	= 67,
    AR	= 68,
    ARK	= 69,
    ASI	= 70,
    ATOMIC_CMP_SWAPW	= 71,
    ATOMIC_LOADW_AFI	= 72,
    ATOMIC_LOADW_AR	= 73,
    ATOMIC_LOADW_MAX	= 74,
    ATOMIC_LOADW_MIN	= 75,
    ATOMIC_LOADW_NILH	= 76,
    ATOMIC_LOADW_NILHi	= 77,
    ATOMIC_LOADW_NR	= 78,
    ATOMIC_LOADW_NRi	= 79,
    ATOMIC_LOADW_OILH	= 80,
    ATOMIC_LOADW_OR	= 81,
    ATOMIC_LOADW_SR	= 82,
    ATOMIC_LOADW_UMAX	= 83,
    ATOMIC_LOADW_UMIN	= 84,
    ATOMIC_LOADW_XILF	= 85,
    ATOMIC_LOADW_XR	= 86,
    ATOMIC_LOAD_AFI	= 87,
    ATOMIC_LOAD_AGFI	= 88,
    ATOMIC_LOAD_AGHI	= 89,
    ATOMIC_LOAD_AGR	= 90,
    ATOMIC_LOAD_AHI	= 91,
    ATOMIC_LOAD_AR	= 92,
    ATOMIC_LOAD_MAX_32	= 93,
    ATOMIC_LOAD_MAX_64	= 94,
    ATOMIC_LOAD_MIN_32	= 95,
    ATOMIC_LOAD_MIN_64	= 96,
    ATOMIC_LOAD_NGR	= 97,
    ATOMIC_LOAD_NGRi	= 98,
    ATOMIC_LOAD_NIHF64	= 99,
    ATOMIC_LOAD_NIHF64i	= 100,
    ATOMIC_LOAD_NIHH64	= 101,
    ATOMIC_LOAD_NIHH64i	= 102,
    ATOMIC_LOAD_NIHL64	= 103,
    ATOMIC_LOAD_NIHL64i	= 104,
    ATOMIC_LOAD_NILF	= 105,
    ATOMIC_LOAD_NILF64	= 106,
    ATOMIC_LOAD_NILF64i	= 107,
    ATOMIC_LOAD_NILFi	= 108,
    ATOMIC_LOAD_NILH	= 109,
    ATOMIC_LOAD_NILH64	= 110,
    ATOMIC_LOAD_NILH64i	= 111,
    ATOMIC_LOAD_NILHi	= 112,
    ATOMIC_LOAD_NILL	= 113,
    ATOMIC_LOAD_NILL64	= 114,
    ATOMIC_LOAD_NILL64i	= 115,
    ATOMIC_LOAD_NILLi	= 116,
    ATOMIC_LOAD_NR	= 117,
    ATOMIC_LOAD_NRi	= 118,
    ATOMIC_LOAD_OGR	= 119,
    ATOMIC_LOAD_OIHF64	= 120,
    ATOMIC_LOAD_OIHH64	= 121,
    ATOMIC_LOAD_OIHL64	= 122,
    ATOMIC_LOAD_OILF	= 123,
    ATOMIC_LOAD_OILF64	= 124,
    ATOMIC_LOAD_OILH	= 125,
    ATOMIC_LOAD_OILH64	= 126,
    ATOMIC_LOAD_OILL	= 127,
    ATOMIC_LOAD_OILL64	= 128,
    ATOMIC_LOAD_OR	= 129,
    ATOMIC_LOAD_SGR	= 130,
    ATOMIC_LOAD_SR	= 131,
    ATOMIC_LOAD_UMAX_32	= 132,
    ATOMIC_LOAD_UMAX_64	= 133,
    ATOMIC_LOAD_UMIN_32	= 134,
    ATOMIC_LOAD_UMIN_64	= 135,
    ATOMIC_LOAD_XGR	= 136,
    ATOMIC_LOAD_XIHF64	= 137,
    ATOMIC_LOAD_XILF	= 138,
    ATOMIC_LOAD_XILF64	= 139,
    ATOMIC_LOAD_XR	= 140,
    ATOMIC_SWAPW	= 141,
    ATOMIC_SWAP_32	= 142,
    ATOMIC_SWAP_64	= 143,
    AXBR	= 144,
    AY	= 145,
    AsmBCR	= 146,
    AsmBRC	= 147,
    AsmBRCL	= 148,
    AsmCGIJ	= 149,
    AsmCGRJ	= 150,
    AsmCIJ	= 151,
    AsmCLGIJ	= 152,
    AsmCLGRJ	= 153,
    AsmCLIJ	= 154,
    AsmCLRJ	= 155,
    AsmCRJ	= 156,
    AsmEBR	= 157,
    AsmEJ	= 158,
    AsmEJG	= 159,
    AsmELOC	= 160,
    AsmELOCG	= 161,
    AsmELOCGR	= 162,
    AsmELOCR	= 163,
    AsmESTOC	= 164,
    AsmESTOCG	= 165,
    AsmHBR	= 166,
    AsmHEBR	= 167,
    AsmHEJ	= 168,
    AsmHEJG	= 169,
    AsmHELOC	= 170,
    AsmHELOCG	= 171,
    AsmHELOCGR	= 172,
    AsmHELOCR	= 173,
    AsmHESTOC	= 174,
    AsmHESTOCG	= 175,
    AsmHJ	= 176,
    AsmHJG	= 177,
    AsmHLOC	= 178,
    AsmHLOCG	= 179,
    AsmHLOCGR	= 180,
    AsmHLOCR	= 181,
    AsmHSTOC	= 182,
    AsmHSTOCG	= 183,
    AsmJEAltCGI	= 184,
    AsmJEAltCGR	= 185,
    AsmJEAltCI	= 186,
    AsmJEAltCLGI	= 187,
    AsmJEAltCLGR	= 188,
    AsmJEAltCLI	= 189,
    AsmJEAltCLR	= 190,
    AsmJEAltCR	= 191,
    AsmJECGI	= 192,
    AsmJECGR	= 193,
    AsmJECI	= 194,
    AsmJECLGI	= 195,
    AsmJECLGR	= 196,
    AsmJECLI	= 197,
    AsmJECLR	= 198,
    AsmJECR	= 199,
    AsmJHAltCGI	= 200,
    AsmJHAltCGR	= 201,
    AsmJHAltCI	= 202,
    AsmJHAltCLGI	= 203,
    AsmJHAltCLGR	= 204,
    AsmJHAltCLI	= 205,
    AsmJHAltCLR	= 206,
    AsmJHAltCR	= 207,
    AsmJHCGI	= 208,
    AsmJHCGR	= 209,
    AsmJHCI	= 210,
    AsmJHCLGI	= 211,
    AsmJHCLGR	= 212,
    AsmJHCLI	= 213,
    AsmJHCLR	= 214,
    AsmJHCR	= 215,
    AsmJHEAltCGI	= 216,
    AsmJHEAltCGR	= 217,
    AsmJHEAltCI	= 218,
    AsmJHEAltCLGI	= 219,
    AsmJHEAltCLGR	= 220,
    AsmJHEAltCLI	= 221,
    AsmJHEAltCLR	= 222,
    AsmJHEAltCR	= 223,
    AsmJHECGI	= 224,
    AsmJHECGR	= 225,
    AsmJHECI	= 226,
    AsmJHECLGI	= 227,
    AsmJHECLGR	= 228,
    AsmJHECLI	= 229,
    AsmJHECLR	= 230,
    AsmJHECR	= 231,
    AsmJLAltCGI	= 232,
    AsmJLAltCGR	= 233,
    AsmJLAltCI	= 234,
    AsmJLAltCLGI	= 235,
    AsmJLAltCLGR	= 236,
    AsmJLAltCLI	= 237,
    AsmJLAltCLR	= 238,
    AsmJLAltCR	= 239,
    AsmJLCGI	= 240,
    AsmJLCGR	= 241,
    AsmJLCI	= 242,
    AsmJLCLGI	= 243,
    AsmJLCLGR	= 244,
    AsmJLCLI	= 245,
    AsmJLCLR	= 246,
    AsmJLCR	= 247,
    AsmJLEAltCGI	= 248,
    AsmJLEAltCGR	= 249,
    AsmJLEAltCI	= 250,
    AsmJLEAltCLGI	= 251,
    AsmJLEAltCLGR	= 252,
    AsmJLEAltCLI	= 253,
    AsmJLEAltCLR	= 254,
    AsmJLEAltCR	= 255,
    AsmJLECGI	= 256,
    AsmJLECGR	= 257,
    AsmJLECI	= 258,
    AsmJLECLGI	= 259,
    AsmJLECLGR	= 260,
    AsmJLECLI	= 261,
    AsmJLECLR	= 262,
    AsmJLECR	= 263,
    AsmJLHAltCGI	= 264,
    AsmJLHAltCGR	= 265,
    AsmJLHAltCI	= 266,
    AsmJLHAltCLGI	= 267,
    AsmJLHAltCLGR	= 268,
    AsmJLHAltCLI	= 269,
    AsmJLHAltCLR	= 270,
    AsmJLHAltCR	= 271,
    AsmJLHCGI	= 272,
    AsmJLHCGR	= 273,
    AsmJLHCI	= 274,
    AsmJLHCLGI	= 275,
    AsmJLHCLGR	= 276,
    AsmJLHCLI	= 277,
    AsmJLHCLR	= 278,
    AsmJLHCR	= 279,
    AsmLBR	= 280,
    AsmLEBR	= 281,
    AsmLEJ	= 282,
    AsmLEJG	= 283,
    AsmLELOC	= 284,
    AsmLELOCG	= 285,
    AsmLELOCGR	= 286,
    AsmLELOCR	= 287,
    AsmLESTOC	= 288,
    AsmLESTOCG	= 289,
    AsmLHBR	= 290,
    AsmLHJ	= 291,
    AsmLHJG	= 292,
    AsmLHLOC	= 293,
    AsmLHLOCG	= 294,
    AsmLHLOCGR	= 295,
    AsmLHLOCR	= 296,
    AsmLHSTOC	= 297,
    AsmLHSTOCG	= 298,
    AsmLJ	= 299,
    AsmLJG	= 300,
    AsmLLOC	= 301,
    AsmLLOCG	= 302,
    AsmLLOCGR	= 303,
    AsmLLOCR	= 304,
    AsmLOC	= 305,
    AsmLOCG	= 306,
    AsmLOCGR	= 307,
    AsmLOCR	= 308,
    AsmLSTOC	= 309,
    AsmLSTOCG	= 310,
    AsmNEBR	= 311,
    AsmNEJ	= 312,
    AsmNEJG	= 313,
    AsmNELOC	= 314,
    AsmNELOCG	= 315,
    AsmNELOCGR	= 316,
    AsmNELOCR	= 317,
    AsmNESTOC	= 318,
    AsmNESTOCG	= 319,
    AsmNHBR	= 320,
    AsmNHEBR	= 321,
    AsmNHEJ	= 322,
    AsmNHEJG	= 323,
    AsmNHELOC	= 324,
    AsmNHELOCG	= 325,
    AsmNHELOCGR	= 326,
    AsmNHELOCR	= 327,
    AsmNHESTOC	= 328,
    AsmNHESTOCG	= 329,
    AsmNHJ	= 330,
    AsmNHJG	= 331,
    AsmNHLOC	= 332,
    AsmNHLOCG	= 333,
    AsmNHLOCGR	= 334,
    AsmNHLOCR	= 335,
    AsmNHSTOC	= 336,
    AsmNHSTOCG	= 337,
    AsmNLBR	= 338,
    AsmNLEBR	= 339,
    AsmNLEJ	= 340,
    AsmNLEJG	= 341,
    AsmNLELOC	= 342,
    AsmNLELOCG	= 343,
    AsmNLELOCGR	= 344,
    AsmNLELOCR	= 345,
    AsmNLESTOC	= 346,
    AsmNLESTOCG	= 347,
    AsmNLHBR	= 348,
    AsmNLHJ	= 349,
    AsmNLHJG	= 350,
    AsmNLHLOC	= 351,
    AsmNLHLOCG	= 352,
    AsmNLHLOCGR	= 353,
    AsmNLHLOCR	= 354,
    AsmNLHSTOC	= 355,
    AsmNLHSTOCG	= 356,
    AsmNLJ	= 357,
    AsmNLJG	= 358,
    AsmNLLOC	= 359,
    AsmNLLOCG	= 360,
    AsmNLLOCGR	= 361,
    AsmNLLOCR	= 362,
    AsmNLSTOC	= 363,
    AsmNLSTOCG	= 364,
    AsmNOBR	= 365,
    AsmNOJ	= 366,
    AsmNOJG	= 367,
    AsmNOLOC	= 368,
    AsmNOLOCG	= 369,
    AsmNOLOCGR	= 370,
    AsmNOLOCR	= 371,
    AsmNOSTOC	= 372,
    AsmNOSTOCG	= 373,
    AsmOBR	= 374,
    AsmOJ	= 375,
    AsmOJG	= 376,
    AsmOLOC	= 377,
    AsmOLOCG	= 378,
    AsmOLOCGR	= 379,
    AsmOLOCR	= 380,
    AsmOSTOC	= 381,
    AsmOSTOCG	= 382,
    AsmSTOC	= 383,
    AsmSTOCG	= 384,
    BASR	= 385,
    BR	= 386,
    BRAS	= 387,
    BRASL	= 388,
    BRC	= 389,
    BRCL	= 390,
    BRCT	= 391,
    BRCTG	= 392,
    C	= 393,
    CDB	= 394,
    CDBR	= 395,
    CDFBR	= 396,
    CDGBR	= 397,
    CDLFBR	= 398,
    CDLGBR	= 399,
    CEB	= 400,
    CEBR	= 401,
    CEFBR	= 402,
    CEGBR	= 403,
    CELFBR	= 404,
    CELGBR	= 405,
    CFDBR	= 406,
    CFEBR	= 407,
    CFI	= 408,
    CFIMux	= 409,
    CFXBR	= 410,
    CG	= 411,
    CGDBR	= 412,
    CGEBR	= 413,
    CGF	= 414,
    CGFI	= 415,
    CGFR	= 416,
    CGFRL	= 417,
    CGH	= 418,
    CGHI	= 419,
    CGHRL	= 420,
    CGHSI	= 421,
    CGIJ	= 422,
    CGR	= 423,
    CGRJ	= 424,
    CGRL	= 425,
    CGXBR	= 426,
    CH	= 427,
    CHF	= 428,
    CHHSI	= 429,
    CHI	= 430,
    CHRL	= 431,
    CHSI	= 432,
    CHY	= 433,
    CIH	= 434,
    CIJ	= 435,
    CL	= 436,
    CLC	= 437,
    CLCLoop	= 438,
    CLCSequence	= 439,
    CLFDBR	= 440,
    CLFEBR	= 441,
    CLFHSI	= 442,
    CLFI	= 443,
    CLFIMux	= 444,
    CLFXBR	= 445,
    CLG	= 446,
    CLGDBR	= 447,
    CLGEBR	= 448,
    CLGF	= 449,
    CLGFI	= 450,
    CLGFR	= 451,
    CLGFRL	= 452,
    CLGHRL	= 453,
    CLGHSI	= 454,
    CLGIJ	= 455,
    CLGR	= 456,
    CLGRJ	= 457,
    CLGRL	= 458,
    CLGXBR	= 459,
    CLHF	= 460,
    CLHHSI	= 461,
    CLHRL	= 462,
    CLI	= 463,
    CLIH	= 464,
    CLIJ	= 465,
    CLIY	= 466,
    CLMux	= 467,
    CLR	= 468,
    CLRJ	= 469,
    CLRL	= 470,
    CLST	= 471,
    CLSTLoop	= 472,
    CLY	= 473,
    CMux	= 474,
    CPSDRdd	= 475,
    CPSDRds	= 476,
    CPSDRsd	= 477,
    CPSDRss	= 478,
    CR	= 479,
    CRJ	= 480,
    CRL	= 481,
    CS	= 482,
    CSG	= 483,
    CSY	= 484,
    CXBR	= 485,
    CXFBR	= 486,
    CXGBR	= 487,
    CXLFBR	= 488,
    CXLGBR	= 489,
    CY	= 490,
    CallBASR	= 491,
    CallBR	= 492,
    CallBRASL	= 493,
    CallJG	= 494,
    CondStore16	= 495,
    CondStore16Inv	= 496,
    CondStore16Mux	= 497,
    CondStore16MuxInv	= 498,
    CondStore32	= 499,
    CondStore32Inv	= 500,
    CondStore64	= 501,
    CondStore64Inv	= 502,
    CondStore8	= 503,
    CondStore8Inv	= 504,
    CondStore8Mux	= 505,
    CondStore8MuxInv	= 506,
    CondStoreF32	= 507,
    CondStoreF32Inv	= 508,
    CondStoreF64	= 509,
    CondStoreF64Inv	= 510,
    DDB	= 511,
    DDBR	= 512,
    DEB	= 513,
    DEBR	= 514,
    DL	= 515,
    DLG	= 516,
    DLGR	= 517,
    DLR	= 518,
    DSG	= 519,
    DSGF	= 520,
    DSGFR	= 521,
    DSGR	= 522,
    DXBR	= 523,
    EAR	= 524,
    ETND	= 525,
    FIDBR	= 526,
    FIDBRA	= 527,
    FIEBR	= 528,
    FIEBRA	= 529,
    FIXBR	= 530,
    FIXBRA	= 531,
    FLOGR	= 532,
    GOT	= 533,
    IC	= 534,
    IC32	= 535,
    IC32Y	= 536,
    ICY	= 537,
    IIFMux	= 538,
    IIHF	= 539,
    IIHF64	= 540,
    IIHH	= 541,
    IIHH64	= 542,
    IIHL	= 543,
    IIHL64	= 544,
    IIHMux	= 545,
    IILF	= 546,
    IILF64	= 547,
    IILH	= 548,
    IILH64	= 549,
    IILL	= 550,
    IILL64	= 551,
    IILMux	= 552,
    IPM	= 553,
    J	= 554,
    JG	= 555,
    L	= 556,
    L128	= 557,
    LA	= 558,
    LAA	= 559,
    LAAG	= 560,
    LAAL	= 561,
    LAALG	= 562,
    LAN	= 563,
    LANG	= 564,
    LAO	= 565,
    LAOG	= 566,
    LARL	= 567,
    LAX	= 568,
    LAXG	= 569,
    LAY	= 570,
    LB	= 571,
    LBH	= 572,
    LBMux	= 573,
    LBR	= 574,
    LCBB	= 575,
    LCDBR	= 576,
    LCDFR	= 577,
    LCDFR_32	= 578,
    LCEBR	= 579,
    LCGFR	= 580,
    LCGR	= 581,
    LCR	= 582,
    LCXBR	= 583,
    LD	= 584,
    LDE32	= 585,
    LDEB	= 586,
    LDEBR	= 587,
    LDGR	= 588,
    LDR	= 589,
    LDXBR	= 590,
    LDXBRA	= 591,
    LDY	= 592,
    LE	= 593,
    LEDBR	= 594,
    LEDBRA	= 595,
    LEFR	= 596,
    LER	= 597,
    LEXBR	= 598,
    LEXBRA	= 599,
    LEY	= 600,
    LFER	= 601,
    LFH	= 602,
    LG	= 603,
    LGB	= 604,
    LGBR	= 605,
    LGDR	= 606,
    LGF	= 607,
    LGFI	= 608,
    LGFR	= 609,
    LGFRL	= 610,
    LGH	= 611,
    LGHI	= 612,
    LGHR	= 613,
    LGHRL	= 614,
    LGR	= 615,
    LGRL	= 616,
    LH	= 617,
    LHH	= 618,
    LHI	= 619,
    LHIMux	= 620,
    LHMux	= 621,
    LHR	= 622,
    LHRL	= 623,
    LHY	= 624,
    LLC	= 625,
    LLCH	= 626,
    LLCMux	= 627,
    LLCR	= 628,
    LLCRMux	= 629,
    LLGC	= 630,
    LLGCR	= 631,
    LLGF	= 632,
    LLGFR	= 633,
    LLGFRL	= 634,
    LLGH	= 635,
    LLGHR	= 636,
    LLGHRL	= 637,
    LLH	= 638,
    LLHH	= 639,
    LLHMux	= 640,
    LLHR	= 641,
    LLHRL	= 642,
    LLHRMux	= 643,
    LLIHF	= 644,
    LLIHH	= 645,
    LLIHL	= 646,
    LLILF	= 647,
    LLILH	= 648,
    LLILL	= 649,
    LMG	= 650,
    LMux	= 651,
    LNDBR	= 652,
    LNDFR	= 653,
    LNDFR_32	= 654,
    LNEBR	= 655,
    LNGFR	= 656,
    LNGR	= 657,
    LNR	= 658,
    LNXBR	= 659,
    LOC	= 660,
    LOCG	= 661,
    LOCGR	= 662,
    LOCR	= 663,
    LPDBR	= 664,
    LPDFR	= 665,
    LPDFR_32	= 666,
    LPEBR	= 667,
    LPGFR	= 668,
    LPGR	= 669,
    LPR	= 670,
    LPXBR	= 671,
    LR	= 672,
    LRL	= 673,
    LRMux	= 674,
    LRV	= 675,
    LRVG	= 676,
    LRVGR	= 677,
    LRVR	= 678,
    LT	= 679,
    LTDBR	= 680,
    LTDBRCompare	= 681,
    LTDBRCompare_VecPseudo	= 682,
    LTEBR	= 683,
    LTEBRCompare	= 684,
    LTEBRCompare_VecPseudo	= 685,
    LTG	= 686,
    LTGF	= 687,
    LTGFR	= 688,
    LTGR	= 689,
    LTR	= 690,
    LTXBR	= 691,
    LTXBRCompare	= 692,
    LTXBRCompare_VecPseudo	= 693,
    LX	= 694,
    LXDB	= 695,
    LXDBR	= 696,
    LXEB	= 697,
    LXEBR	= 698,
    LXR	= 699,
    LY	= 700,
    LZDR	= 701,
    LZER	= 702,
    LZXR	= 703,
    MADB	= 704,
    MADBR	= 705,
    MAEB	= 706,
    MAEBR	= 707,
    MDB	= 708,
    MDBR	= 709,
    MDEB	= 710,
    MDEBR	= 711,
    MEEB	= 712,
    MEEBR	= 713,
    MGHI	= 714,
    MH	= 715,
    MHI	= 716,
    MHY	= 717,
    MLG	= 718,
    MLGR	= 719,
    MS	= 720,
    MSDB	= 721,
    MSDBR	= 722,
    MSEB	= 723,
    MSEBR	= 724,
    MSFI	= 725,
    MSG	= 726,
    MSGF	= 727,
    MSGFI	= 728,
    MSGFR	= 729,
    MSGR	= 730,
    MSR	= 731,
    MSY	= 732,
    MVC	= 733,
    MVCLoop	= 734,
    MVCSequence	= 735,
    MVGHI	= 736,
    MVHHI	= 737,
    MVHI	= 738,
    MVI	= 739,
    MVIY	= 740,
    MVST	= 741,
    MVSTLoop	= 742,
    MXBR	= 743,
    MXDB	= 744,
    MXDBR	= 745,
    N	= 746,
    NC	= 747,
    NCLoop	= 748,
    NCSequence	= 749,
    NG	= 750,
    NGR	= 751,
    NGRK	= 752,
    NI	= 753,
    NIFMux	= 754,
    NIHF	= 755,
    NIHF64	= 756,
    NIHH	= 757,
    NIHH64	= 758,
    NIHL	= 759,
    NIHL64	= 760,
    NIHMux	= 761,
    NILF	= 762,
    NILF64	= 763,
    NILH	= 764,
    NILH64	= 765,
    NILL	= 766,
    NILL64	= 767,
    NILMux	= 768,
    NIY	= 769,
    NR	= 770,
    NRK	= 771,
    NTSTG	= 772,
    NY	= 773,
    O	= 774,
    OC	= 775,
    OCLoop	= 776,
    OCSequence	= 777,
    OG	= 778,
    OGR	= 779,
    OGRK	= 780,
    OI	= 781,
    OIFMux	= 782,
    OIHF	= 783,
    OIHF64	= 784,
    OIHH	= 785,
    OIHH64	= 786,
    OIHL	= 787,
    OIHL64	= 788,
    OIHMux	= 789,
    OILF	= 790,
    OILF64	= 791,
    OILH	= 792,
    OILH64	= 793,
    OILL	= 794,
    OILL64	= 795,
    OILMux	= 796,
    OIY	= 797,
    OR	= 798,
    ORK	= 799,
    OY	= 800,
    PFD	= 801,
    PFDRL	= 802,
    POPCNT	= 803,
    PPA	= 804,
    RISBG	= 805,
    RISBG32	= 806,
    RISBGN	= 807,
    RISBHG	= 808,
    RISBHH	= 809,
    RISBHL	= 810,
    RISBLG	= 811,
    RISBLH	= 812,
    RISBLL	= 813,
    RISBMux	= 814,
    RLL	= 815,
    RLLG	= 816,
    RNSBG	= 817,
    ROSBG	= 818,
    RXSBG	= 819,
    Return	= 820,
    S	= 821,
    SDB	= 822,
    SDBR	= 823,
    SEB	= 824,
    SEBR	= 825,
    SG	= 826,
    SGF	= 827,
    SGFR	= 828,
    SGR	= 829,
    SGRK	= 830,
    SH	= 831,
    SHY	= 832,
    SL	= 833,
    SLB	= 834,
    SLBG	= 835,
    SLBGR	= 836,
    SLBR	= 837,
    SLFI	= 838,
    SLG	= 839,
    SLGF	= 840,
    SLGFI	= 841,
    SLGFR	= 842,
    SLGR	= 843,
    SLGRK	= 844,
    SLL	= 845,
    SLLG	= 846,
    SLLK	= 847,
    SLR	= 848,
    SLRK	= 849,
    SLY	= 850,
    SQDB	= 851,
    SQDBR	= 852,
    SQEB	= 853,
    SQEBR	= 854,
    SQXBR	= 855,
    SR	= 856,
    SRA	= 857,
    SRAG	= 858,
    SRAK	= 859,
    SRK	= 860,
    SRL	= 861,
    SRLG	= 862,
    SRLK	= 863,
    SRST	= 864,
    SRSTLoop	= 865,
    ST	= 866,
    ST128	= 867,
    STC	= 868,
    STCH	= 869,
    STCK	= 870,
    STCKE	= 871,
    STCKF	= 872,
    STCMux	= 873,
    STCY	= 874,
    STD	= 875,
    STDY	= 876,
    STE	= 877,
    STEY	= 878,
    STFH	= 879,
    STFLE	= 880,
    STG	= 881,
    STGRL	= 882,
    STH	= 883,
    STHH	= 884,
    STHMux	= 885,
    STHRL	= 886,
    STHY	= 887,
    STMG	= 888,
    STMux	= 889,
    STOC	= 890,
    STOCG	= 891,
    STRL	= 892,
    STRV	= 893,
    STRVG	= 894,
    STX	= 895,
    STY	= 896,
    SXBR	= 897,
    SY	= 898,
    Select32	= 899,
    Select32Mux	= 900,
    Select64	= 901,
    SelectF128	= 902,
    SelectF32	= 903,
    SelectF64	= 904,
    Serialize	= 905,
    TABORT	= 906,
    TBEGIN	= 907,
    TBEGINC	= 908,
    TBEGIN_nofloat	= 909,
    TEND	= 910,
    TLS_GDCALL	= 911,
    TLS_LDCALL	= 912,
    TM	= 913,
    TMHH	= 914,
    TMHH64	= 915,
    TMHL	= 916,
    TMHL64	= 917,
    TMHMux	= 918,
    TMLH	= 919,
    TMLH64	= 920,
    TMLL	= 921,
    TMLL64	= 922,
    TMLMux	= 923,
    TMY	= 924,
    VAB	= 925,
    VACCB	= 926,
    VACCCQ	= 927,
    VACCF	= 928,
    VACCG	= 929,
    VACCH	= 930,
    VACCQ	= 931,
    VACQ	= 932,
    VAF	= 933,
    VAG	= 934,
    VAH	= 935,
    VAQ	= 936,
    VAVGB	= 937,
    VAVGF	= 938,
    VAVGG	= 939,
    VAVGH	= 940,
    VAVGLB	= 941,
    VAVGLF	= 942,
    VAVGLG	= 943,
    VAVGLH	= 944,
    VCDGB	= 945,
    VCDLGB	= 946,
    VCEQB	= 947,
    VCEQBS	= 948,
    VCEQF	= 949,
    VCEQFS	= 950,
    VCEQG	= 951,
    VCEQGS	= 952,
    VCEQH	= 953,
    VCEQHS	= 954,
    VCGDB	= 955,
    VCHB	= 956,
    VCHBS	= 957,
    VCHF	= 958,
    VCHFS	= 959,
    VCHG	= 960,
    VCHGS	= 961,
    VCHH	= 962,
    VCHHS	= 963,
    VCHLB	= 964,
    VCHLBS	= 965,
    VCHLF	= 966,
    VCHLFS	= 967,
    VCHLG	= 968,
    VCHLGS	= 969,
    VCHLH	= 970,
    VCHLHS	= 971,
    VCKSM	= 972,
    VCLGDB	= 973,
    VCLZB	= 974,
    VCLZF	= 975,
    VCLZG	= 976,
    VCLZH	= 977,
    VCTZB	= 978,
    VCTZF	= 979,
    VCTZG	= 980,
    VCTZH	= 981,
    VECB	= 982,
    VECF	= 983,
    VECG	= 984,
    VECH	= 985,
    VECLB	= 986,
    VECLF	= 987,
    VECLG	= 988,
    VECLH	= 989,
    VERIMB	= 990,
    VERIMF	= 991,
    VERIMG	= 992,
    VERIMH	= 993,
    VERLLB	= 994,
    VERLLF	= 995,
    VERLLG	= 996,
    VERLLH	= 997,
    VERLLVB	= 998,
    VERLLVF	= 999,
    VERLLVG	= 1000,
    VERLLVH	= 1001,
    VESLB	= 1002,
    VESLF	= 1003,
    VESLG	= 1004,
    VESLH	= 1005,
    VESLVB	= 1006,
    VESLVF	= 1007,
    VESLVG	= 1008,
    VESLVH	= 1009,
    VESRAB	= 1010,
    VESRAF	= 1011,
    VESRAG	= 1012,
    VESRAH	= 1013,
    VESRAVB	= 1014,
    VESRAVF	= 1015,
    VESRAVG	= 1016,
    VESRAVH	= 1017,
    VESRLB	= 1018,
    VESRLF	= 1019,
    VESRLG	= 1020,
    VESRLH	= 1021,
    VESRLVB	= 1022,
    VESRLVF	= 1023,
    VESRLVG	= 1024,
    VESRLVH	= 1025,
    VFADB	= 1026,
    VFAEB	= 1027,
    VFAEBS	= 1028,
    VFAEF	= 1029,
    VFAEFS	= 1030,
    VFAEH	= 1031,
    VFAEHS	= 1032,
    VFAEZB	= 1033,
    VFAEZBS	= 1034,
    VFAEZF	= 1035,
    VFAEZFS	= 1036,
    VFAEZH	= 1037,
    VFAEZHS	= 1038,
    VFCEDB	= 1039,
    VFCEDBS	= 1040,
    VFCHDB	= 1041,
    VFCHDBS	= 1042,
    VFCHEDB	= 1043,
    VFCHEDBS	= 1044,
    VFDDB	= 1045,
    VFEEB	= 1046,
    VFEEBS	= 1047,
    VFEEF	= 1048,
    VFEEFS	= 1049,
    VFEEH	= 1050,
    VFEEHS	= 1051,
    VFEEZB	= 1052,
    VFEEZBS	= 1053,
    VFEEZF	= 1054,
    VFEEZFS	= 1055,
    VFEEZH	= 1056,
    VFEEZHS	= 1057,
    VFENEB	= 1058,
    VFENEBS	= 1059,
    VFENEF	= 1060,
    VFENEFS	= 1061,
    VFENEH	= 1062,
    VFENEHS	= 1063,
    VFENEZB	= 1064,
    VFENEZBS	= 1065,
    VFENEZF	= 1066,
    VFENEZFS	= 1067,
    VFENEZH	= 1068,
    VFENEZHS	= 1069,
    VFIDB	= 1070,
    VFLCDB	= 1071,
    VFLNDB	= 1072,
    VFLPDB	= 1073,
    VFMADB	= 1074,
    VFMDB	= 1075,
    VFMSDB	= 1076,
    VFSDB	= 1077,
    VFSQDB	= 1078,
    VFTCIDB	= 1079,
    VGBM	= 1080,
    VGEF	= 1081,
    VGEG	= 1082,
    VGFMAB	= 1083,
    VGFMAF	= 1084,
    VGFMAG	= 1085,
    VGFMAH	= 1086,
    VGFMB	= 1087,
    VGFMF	= 1088,
    VGFMG	= 1089,
    VGFMH	= 1090,
    VGMB	= 1091,
    VGMF	= 1092,
    VGMG	= 1093,
    VGMH	= 1094,
    VISTRB	= 1095,
    VISTRBS	= 1096,
    VISTRF	= 1097,
    VISTRFS	= 1098,
    VISTRH	= 1099,
    VISTRHS	= 1100,
    VL	= 1101,
    VL32	= 1102,
    VL64	= 1103,
    VLBB	= 1104,
    VLCB	= 1105,
    VLCF	= 1106,
    VLCG	= 1107,
    VLCH	= 1108,
    VLDEB	= 1109,
    VLEB	= 1110,
    VLEDB	= 1111,
    VLEF	= 1112,
    VLEG	= 1113,
    VLEH	= 1114,
    VLEIB	= 1115,
    VLEIF	= 1116,
    VLEIG	= 1117,
    VLEIH	= 1118,
    VLGVB	= 1119,
    VLGVF	= 1120,
    VLGVG	= 1121,
    VLGVH	= 1122,
    VLL	= 1123,
    VLLEZB	= 1124,
    VLLEZF	= 1125,
    VLLEZG	= 1126,
    VLLEZH	= 1127,
    VLM	= 1128,
    VLPB	= 1129,
    VLPF	= 1130,
    VLPG	= 1131,
    VLPH	= 1132,
    VLR	= 1133,
    VLR32	= 1134,
    VLR64	= 1135,
    VLREPB	= 1136,
    VLREPF	= 1137,
    VLREPG	= 1138,
    VLREPH	= 1139,
    VLVGB	= 1140,
    VLVGF	= 1141,
    VLVGG	= 1142,
    VLVGH	= 1143,
    VLVGP	= 1144,
    VLVGP32	= 1145,
    VMAEB	= 1146,
    VMAEF	= 1147,
    VMAEH	= 1148,
    VMAHB	= 1149,
    VMAHF	= 1150,
    VMAHH	= 1151,
    VMALB	= 1152,
    VMALEB	= 1153,
    VMALEF	= 1154,
    VMALEH	= 1155,
    VMALF	= 1156,
    VMALHB	= 1157,
    VMALHF	= 1158,
    VMALHH	= 1159,
    VMALHW	= 1160,
    VMALOB	= 1161,
    VMALOF	= 1162,
    VMALOH	= 1163,
    VMAOB	= 1164,
    VMAOF	= 1165,
    VMAOH	= 1166,
    VMEB	= 1167,
    VMEF	= 1168,
    VMEH	= 1169,
    VMHB	= 1170,
    VMHF	= 1171,
    VMHH	= 1172,
    VMLB	= 1173,
    VMLEB	= 1174,
    VMLEF	= 1175,
    VMLEH	= 1176,
    VMLF	= 1177,
    VMLHB	= 1178,
    VMLHF	= 1179,
    VMLHH	= 1180,
    VMLHW	= 1181,
    VMLOB	= 1182,
    VMLOF	= 1183,
    VMLOH	= 1184,
    VMNB	= 1185,
    VMNF	= 1186,
    VMNG	= 1187,
    VMNH	= 1188,
    VMNLB	= 1189,
    VMNLF	= 1190,
    VMNLG	= 1191,
    VMNLH	= 1192,
    VMOB	= 1193,
    VMOF	= 1194,
    VMOH	= 1195,
    VMRHB	= 1196,
    VMRHF	= 1197,
    VMRHG	= 1198,
    VMRHH	= 1199,
    VMRLB	= 1200,
    VMRLF	= 1201,
    VMRLG	= 1202,
    VMRLH	= 1203,
    VMXB	= 1204,
    VMXF	= 1205,
    VMXG	= 1206,
    VMXH	= 1207,
    VMXLB	= 1208,
    VMXLF	= 1209,
    VMXLG	= 1210,
    VMXLH	= 1211,
    VN	= 1212,
    VNC	= 1213,
    VNO	= 1214,
    VO	= 1215,
    VONE	= 1216,
    VPDI	= 1217,
    VPERM	= 1218,
    VPKF	= 1219,
    VPKG	= 1220,
    VPKH	= 1221,
    VPKLSF	= 1222,
    VPKLSFS	= 1223,
    VPKLSG	= 1224,
    VPKLSGS	= 1225,
    VPKLSH	= 1226,
    VPKLSHS	= 1227,
    VPKSF	= 1228,
    VPKSFS	= 1229,
    VPKSG	= 1230,
    VPKSGS	= 1231,
    VPKSH	= 1232,
    VPKSHS	= 1233,
    VPOPCT	= 1234,
    VREPB	= 1235,
    VREPF	= 1236,
    VREPG	= 1237,
    VREPH	= 1238,
    VREPIB	= 1239,
    VREPIF	= 1240,
    VREPIG	= 1241,
    VREPIH	= 1242,
    VSB	= 1243,
    VSBCBIQ	= 1244,
    VSBIQ	= 1245,
    VSCBIB	= 1246,
    VSCBIF	= 1247,
    VSCBIG	= 1248,
    VSCBIH	= 1249,
    VSCBIQ	= 1250,
    VSCEF	= 1251,
    VSCEG	= 1252,
    VSEGB	= 1253,
    VSEGF	= 1254,
    VSEGH	= 1255,
    VSEL	= 1256,
    VSF	= 1257,
    VSG	= 1258,
    VSH	= 1259,
    VSL	= 1260,
    VSLB	= 1261,
    VSLDB	= 1262,
    VSQ	= 1263,
    VSRA	= 1264,
    VSRAB	= 1265,
    VSRL	= 1266,
    VSRLB	= 1267,
    VST	= 1268,
    VST32	= 1269,
    VST64	= 1270,
    VSTEB	= 1271,
    VSTEF	= 1272,
    VSTEG	= 1273,
    VSTEH	= 1274,
    VSTL	= 1275,
    VSTM	= 1276,
    VSTRCB	= 1277,
    VSTRCBS	= 1278,
    VSTRCF	= 1279,
    VSTRCFS	= 1280,
    VSTRCH	= 1281,
    VSTRCHS	= 1282,
    VSTRCZB	= 1283,
    VSTRCZBS	= 1284,
    VSTRCZF	= 1285,
    VSTRCZFS	= 1286,
    VSTRCZH	= 1287,
    VSTRCZHS	= 1288,
    VSUMB	= 1289,
    VSUMGF	= 1290,
    VSUMGH	= 1291,
    VSUMH	= 1292,
    VSUMQF	= 1293,
    VSUMQG	= 1294,
    VTM	= 1295,
    VUPHB	= 1296,
    VUPHF	= 1297,
    VUPHH	= 1298,
    VUPLB	= 1299,
    VUPLF	= 1300,
    VUPLHB	= 1301,
    VUPLHF	= 1302,
    VUPLHH	= 1303,
    VUPLHW	= 1304,
    VUPLLB	= 1305,
    VUPLLF	= 1306,
    VUPLLH	= 1307,
    VX	= 1308,
    VZERO	= 1309,
    WCDGB	= 1310,
    WCDLGB	= 1311,
    WCGDB	= 1312,
    WCLGDB	= 1313,
    WFADB	= 1314,
    WFCDB	= 1315,
    WFCEDB	= 1316,
    WFCEDBS	= 1317,
    WFCHDB	= 1318,
    WFCHDBS	= 1319,
    WFCHEDB	= 1320,
    WFCHEDBS	= 1321,
    WFDDB	= 1322,
    WFIDB	= 1323,
    WFKDB	= 1324,
    WFLCDB	= 1325,
    WFLNDB	= 1326,
    WFLPDB	= 1327,
    WFMADB	= 1328,
    WFMDB	= 1329,
    WFMSDB	= 1330,
    WFSDB	= 1331,
    WFSQDB	= 1332,
    WFTCIDB	= 1333,
    WLDEB	= 1334,
    WLEDB	= 1335,
    X	= 1336,
    XC	= 1337,
    XCLoop	= 1338,
    XCSequence	= 1339,
    XG	= 1340,
    XGR	= 1341,
    XGRK	= 1342,
    XI	= 1343,
    XIFMux	= 1344,
    XIHF	= 1345,
    XIHF64	= 1346,
    XILF	= 1347,
    XILF64	= 1348,
    XIY	= 1349,
    XR	= 1350,
    XRK	= 1351,
    XY	= 1352,
    ZEXT128_32	= 1353,
    ZEXT128_64	= 1354,
    INSTRUCTION_LIST_END = 1355
  };

namespace Sched {
  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };
} // end Sched namespace
} // end SystemZ namespace
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

static const MCPhysReg ImplicitList1[] = { SystemZ::CC, 0 };
static const MCPhysReg ImplicitList2[] = { SystemZ::R0L, 0 };
static const MCPhysReg ImplicitList3[] = { SystemZ::R14D, SystemZ::CC, 0 };
static const MCPhysReg ImplicitList4[] = { SystemZ::R1D, 0 };

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
static const MCOperandInfo OperandInfo13[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo14[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo15[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo16[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo17[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo18[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo19[] = { { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo20[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo21[] = { { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo22[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo23[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo24[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo25[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo26[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo27[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo28[] = { { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo29[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo30[] = { { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo31[] = { { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo32[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo35[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo46[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo50[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo53[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo54[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo55[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo56[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo57[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo58[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo59[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo60[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo61[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo62[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo63[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo64[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo65[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo66[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo67[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo68[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo69[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo70[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo71[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo72[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo73[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo74[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo75[] = { { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo76[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo77[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo78[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo79[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo80[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo81[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo82[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo83[] = { { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo84[] = { { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo85[] = { { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo86[] = { { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo87[] = { { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo88[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo89[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo90[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo91[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo92[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo93[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo94[] = { { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo95[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo96[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo97[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo98[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo99[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo100[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo101[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo102[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo103[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo104[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo105[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo106[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo107[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo108[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo109[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo110[] = { { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo111[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo112[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo113[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo114[] = { { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo115[] = { { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo116[] = { { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo117[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo118[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo119[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo120[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo121[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo122[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo123[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo124[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo125[] = { { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo126[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo127[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo128[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo129[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo130[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo131[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo132[] = { { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo133[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo134[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo135[] = { { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo136[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo137[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo138[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo139[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo140[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo141[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo142[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo143[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo144[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo145[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo146[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo147[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo148[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo149[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo150[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo151[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo152[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo153[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo154[] = { { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo155[] = { { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo156[] = { { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo157[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo158[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo159[] = { { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo160[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo161[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo162[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo163[] = { { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo164[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo165[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo166[] = { { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo167[] = { { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo168[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo169[] = { { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo170[] = { { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo171[] = { { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo172[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo173[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo174[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo175[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo176[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo177[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo178[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo179[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo180[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo181[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo182[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo183[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo184[] = { { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo185[] = { { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo186[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo187[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo188[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo189[] = { { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo190[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo191[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo192[] = { { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo193[] = { { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo194[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo195[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo196[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo197[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo198[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo199[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo200[] = { { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo201[] = { { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo202[] = { { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo203[] = { { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo204[] = { { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo205[] = { { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo206[] = { { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo207[] = { { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };

extern const MCInstrDesc SystemZInsts[] = {
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
  { 24,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x23c88ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #24 = A
  { 25,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x3fd08ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #25 = ADB
  { 26,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #26 = ADBR
  { 27,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #27 = ADJCALLSTACKDOWN
  { 28,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo8, -1 ,nullptr },  // Inst #28 = ADJCALLSTACKUP
  { 29,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #29 = ADJDYNALLOC
  { 30,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x3fc88ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #30 = AEB
  { 31,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #31 = AEBR
  { 32,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #32 = AEXT128_64
  { 33,	3,	1,	6,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #33 = AFI
  { 34,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #34 = AFIMux
  { 35,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x23d0cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #35 = AG
  { 36,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x23c8cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #36 = AGF
  { 37,	3,	1,	6,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #37 = AGFI
  { 38,	3,	1,	4,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #38 = AGFR
  { 39,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #39 = AGHI
  { 40,	3,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #40 = AGHIK
  { 41,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr)|(1ULL<<MCID::Commutable), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #41 = AGR
  { 42,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #42 = AGRK
  { 43,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x23c04ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #43 = AGSI
  { 44,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x23c48ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #44 = AH
  { 45,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #45 = AHI
  { 46,	3,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #46 = AHIK
  { 47,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #47 = AHIMux
  { 48,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo30, -1 ,nullptr },  // Inst #48 = AHIMuxK
  { 49,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x23c4cULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #49 = AHY
  { 50,	3,	1,	6,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo31, -1 ,nullptr },  // Inst #50 = AIH
  { 51,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #51 = AL
  { 52,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #52 = ALC
  { 53,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL, ImplicitList1, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #53 = ALCG
  { 54,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #54 = ALCGR
  { 55,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #55 = ALCR
  { 56,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #56 = ALFI
  { 57,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #57 = ALG
  { 58,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #58 = ALGF
  { 59,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #59 = ALGFI
  { 60,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #60 = ALGFR
  { 61,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo25, -1 ,nullptr },  // Inst #61 = ALGHSIK
  { 62,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #62 = ALGR
  { 63,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #63 = ALGRK
  { 64,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo29, -1 ,nullptr },  // Inst #64 = ALHSIK
  { 65,	3,	1,	2,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #65 = ALR
  { 66,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #66 = ALRK
  { 67,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #67 = ALY
  { 68,	3,	1,	2,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr)|(1ULL<<MCID::Commutable), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #68 = AR
  { 69,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #69 = ARK
  { 70,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x23c04ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #70 = ASI
  { 71,	8,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #71 = ATOMIC_CMP_SWAPW
  { 72,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #72 = ATOMIC_LOADW_AFI
  { 73,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #73 = ATOMIC_LOADW_AR
  { 74,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #74 = ATOMIC_LOADW_MAX
  { 75,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #75 = ATOMIC_LOADW_MIN
  { 76,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #76 = ATOMIC_LOADW_NILH
  { 77,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #77 = ATOMIC_LOADW_NILHi
  { 78,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #78 = ATOMIC_LOADW_NR
  { 79,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #79 = ATOMIC_LOADW_NRi
  { 80,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #80 = ATOMIC_LOADW_OILH
  { 81,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #81 = ATOMIC_LOADW_OR
  { 82,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #82 = ATOMIC_LOADW_SR
  { 83,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #83 = ATOMIC_LOADW_UMAX
  { 84,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #84 = ATOMIC_LOADW_UMIN
  { 85,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo35, -1 ,nullptr },  // Inst #85 = ATOMIC_LOADW_XILF
  { 86,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #86 = ATOMIC_LOADW_XR
  { 87,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #87 = ATOMIC_LOAD_AFI
  { 88,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #88 = ATOMIC_LOAD_AGFI
  { 89,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #89 = ATOMIC_LOAD_AGHI
  { 90,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #90 = ATOMIC_LOAD_AGR
  { 91,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #91 = ATOMIC_LOAD_AHI
  { 92,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #92 = ATOMIC_LOAD_AR
  { 93,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #93 = ATOMIC_LOAD_MAX_32
  { 94,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #94 = ATOMIC_LOAD_MAX_64
  { 95,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #95 = ATOMIC_LOAD_MIN_32
  { 96,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #96 = ATOMIC_LOAD_MIN_64
  { 97,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #97 = ATOMIC_LOAD_NGR
  { 98,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #98 = ATOMIC_LOAD_NGRi
  { 99,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #99 = ATOMIC_LOAD_NIHF64
  { 100,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #100 = ATOMIC_LOAD_NIHF64i
  { 101,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #101 = ATOMIC_LOAD_NIHH64
  { 102,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #102 = ATOMIC_LOAD_NIHH64i
  { 103,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #103 = ATOMIC_LOAD_NIHL64
  { 104,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #104 = ATOMIC_LOAD_NIHL64i
  { 105,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #105 = ATOMIC_LOAD_NILF
  { 106,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #106 = ATOMIC_LOAD_NILF64
  { 107,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #107 = ATOMIC_LOAD_NILF64i
  { 108,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #108 = ATOMIC_LOAD_NILFi
  { 109,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #109 = ATOMIC_LOAD_NILH
  { 110,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #110 = ATOMIC_LOAD_NILH64
  { 111,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #111 = ATOMIC_LOAD_NILH64i
  { 112,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #112 = ATOMIC_LOAD_NILHi
  { 113,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #113 = ATOMIC_LOAD_NILL
  { 114,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #114 = ATOMIC_LOAD_NILL64
  { 115,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #115 = ATOMIC_LOAD_NILL64i
  { 116,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #116 = ATOMIC_LOAD_NILLi
  { 117,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #117 = ATOMIC_LOAD_NR
  { 118,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #118 = ATOMIC_LOAD_NRi
  { 119,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #119 = ATOMIC_LOAD_OGR
  { 120,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #120 = ATOMIC_LOAD_OIHF64
  { 121,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #121 = ATOMIC_LOAD_OIHH64
  { 122,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #122 = ATOMIC_LOAD_OIHL64
  { 123,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #123 = ATOMIC_LOAD_OILF
  { 124,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #124 = ATOMIC_LOAD_OILF64
  { 125,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #125 = ATOMIC_LOAD_OILH
  { 126,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #126 = ATOMIC_LOAD_OILH64
  { 127,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #127 = ATOMIC_LOAD_OILL
  { 128,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #128 = ATOMIC_LOAD_OILL64
  { 129,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #129 = ATOMIC_LOAD_OR
  { 130,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #130 = ATOMIC_LOAD_SGR
  { 131,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #131 = ATOMIC_LOAD_SR
  { 132,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #132 = ATOMIC_LOAD_UMAX_32
  { 133,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #133 = ATOMIC_LOAD_UMAX_64
  { 134,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #134 = ATOMIC_LOAD_UMIN_32
  { 135,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #135 = ATOMIC_LOAD_UMIN_64
  { 136,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #136 = ATOMIC_LOAD_XGR
  { 137,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #137 = ATOMIC_LOAD_XIHF64
  { 138,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo37, -1 ,nullptr },  // Inst #138 = ATOMIC_LOAD_XILF
  { 139,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo38, -1 ,nullptr },  // Inst #139 = ATOMIC_LOAD_XILF64
  { 140,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #140 = ATOMIC_LOAD_XR
  { 141,	7,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo36, -1 ,nullptr },  // Inst #141 = ATOMIC_SWAPW
  { 142,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo40, -1 ,nullptr },  // Inst #142 = ATOMIC_SWAP_32
  { 143,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL, nullptr, ImplicitList1, OperandInfo39, -1 ,nullptr },  // Inst #143 = ATOMIC_SWAP_64
  { 144,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo41, -1 ,nullptr },  // Inst #144 = AXBR
  { 145,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x23c8cULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #145 = AY
  { 146,	2,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #146 = AsmBCR
  { 147,	2,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #147 = AsmBRC
  { 148,	2,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #148 = AsmBRCL
  { 149,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo43, -1 ,nullptr },  // Inst #149 = AsmCGIJ
  { 150,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #150 = AsmCGRJ
  { 151,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo45, -1 ,nullptr },  // Inst #151 = AsmCIJ
  { 152,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo43, -1 ,nullptr },  // Inst #152 = AsmCLGIJ
  { 153,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #153 = AsmCLGRJ
  { 154,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo45, -1 ,nullptr },  // Inst #154 = AsmCLIJ
  { 155,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo46, -1 ,nullptr },  // Inst #155 = AsmCLRJ
  { 156,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo46, -1 ,nullptr },  // Inst #156 = AsmCRJ
  { 157,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #157 = AsmEBR
  { 158,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #158 = AsmEJ
  { 159,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #159 = AsmEJG
  { 160,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #160 = AsmELOC
  { 161,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #161 = AsmELOCG
  { 162,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #162 = AsmELOCGR
  { 163,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #163 = AsmELOCR
  { 164,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #164 = AsmESTOC
  { 165,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #165 = AsmESTOCG
  { 166,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #166 = AsmHBR
  { 167,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #167 = AsmHEBR
  { 168,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #168 = AsmHEJ
  { 169,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #169 = AsmHEJG
  { 170,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #170 = AsmHELOC
  { 171,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #171 = AsmHELOCG
  { 172,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #172 = AsmHELOCGR
  { 173,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #173 = AsmHELOCR
  { 174,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #174 = AsmHESTOC
  { 175,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #175 = AsmHESTOCG
  { 176,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #176 = AsmHJ
  { 177,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #177 = AsmHJG
  { 178,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #178 = AsmHLOC
  { 179,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #179 = AsmHLOCG
  { 180,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #180 = AsmHLOCGR
  { 181,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #181 = AsmHLOCR
  { 182,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #182 = AsmHSTOC
  { 183,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #183 = AsmHSTOCG
  { 184,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #184 = AsmJEAltCGI
  { 185,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #185 = AsmJEAltCGR
  { 186,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #186 = AsmJEAltCI
  { 187,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #187 = AsmJEAltCLGI
  { 188,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #188 = AsmJEAltCLGR
  { 189,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #189 = AsmJEAltCLI
  { 190,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #190 = AsmJEAltCLR
  { 191,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #191 = AsmJEAltCR
  { 192,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #192 = AsmJECGI
  { 193,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #193 = AsmJECGR
  { 194,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #194 = AsmJECI
  { 195,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #195 = AsmJECLGI
  { 196,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #196 = AsmJECLGR
  { 197,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #197 = AsmJECLI
  { 198,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #198 = AsmJECLR
  { 199,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #199 = AsmJECR
  { 200,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #200 = AsmJHAltCGI
  { 201,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #201 = AsmJHAltCGR
  { 202,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #202 = AsmJHAltCI
  { 203,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #203 = AsmJHAltCLGI
  { 204,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #204 = AsmJHAltCLGR
  { 205,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #205 = AsmJHAltCLI
  { 206,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #206 = AsmJHAltCLR
  { 207,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #207 = AsmJHAltCR
  { 208,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #208 = AsmJHCGI
  { 209,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #209 = AsmJHCGR
  { 210,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #210 = AsmJHCI
  { 211,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #211 = AsmJHCLGI
  { 212,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #212 = AsmJHCLGR
  { 213,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #213 = AsmJHCLI
  { 214,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #214 = AsmJHCLR
  { 215,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #215 = AsmJHCR
  { 216,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #216 = AsmJHEAltCGI
  { 217,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #217 = AsmJHEAltCGR
  { 218,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #218 = AsmJHEAltCI
  { 219,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #219 = AsmJHEAltCLGI
  { 220,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #220 = AsmJHEAltCLGR
  { 221,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #221 = AsmJHEAltCLI
  { 222,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #222 = AsmJHEAltCLR
  { 223,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #223 = AsmJHEAltCR
  { 224,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #224 = AsmJHECGI
  { 225,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #225 = AsmJHECGR
  { 226,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #226 = AsmJHECI
  { 227,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #227 = AsmJHECLGI
  { 228,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #228 = AsmJHECLGR
  { 229,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #229 = AsmJHECLI
  { 230,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #230 = AsmJHECLR
  { 231,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #231 = AsmJHECR
  { 232,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #232 = AsmJLAltCGI
  { 233,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #233 = AsmJLAltCGR
  { 234,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #234 = AsmJLAltCI
  { 235,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #235 = AsmJLAltCLGI
  { 236,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #236 = AsmJLAltCLGR
  { 237,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #237 = AsmJLAltCLI
  { 238,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #238 = AsmJLAltCLR
  { 239,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #239 = AsmJLAltCR
  { 240,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #240 = AsmJLCGI
  { 241,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #241 = AsmJLCGR
  { 242,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #242 = AsmJLCI
  { 243,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #243 = AsmJLCLGI
  { 244,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #244 = AsmJLCLGR
  { 245,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #245 = AsmJLCLI
  { 246,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #246 = AsmJLCLR
  { 247,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #247 = AsmJLCR
  { 248,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #248 = AsmJLEAltCGI
  { 249,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #249 = AsmJLEAltCGR
  { 250,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #250 = AsmJLEAltCI
  { 251,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #251 = AsmJLEAltCLGI
  { 252,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #252 = AsmJLEAltCLGR
  { 253,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #253 = AsmJLEAltCLI
  { 254,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #254 = AsmJLEAltCLR
  { 255,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #255 = AsmJLEAltCR
  { 256,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #256 = AsmJLECGI
  { 257,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #257 = AsmJLECGR
  { 258,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #258 = AsmJLECI
  { 259,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #259 = AsmJLECLGI
  { 260,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #260 = AsmJLECLGR
  { 261,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #261 = AsmJLECLI
  { 262,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #262 = AsmJLECLR
  { 263,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #263 = AsmJLECR
  { 264,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #264 = AsmJLHAltCGI
  { 265,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #265 = AsmJLHAltCGR
  { 266,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #266 = AsmJLHAltCI
  { 267,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #267 = AsmJLHAltCLGI
  { 268,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #268 = AsmJLHAltCLGR
  { 269,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #269 = AsmJLHAltCLI
  { 270,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #270 = AsmJLHAltCLR
  { 271,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #271 = AsmJLHAltCR
  { 272,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #272 = AsmJLHCGI
  { 273,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #273 = AsmJLHCGR
  { 274,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #274 = AsmJLHCI
  { 275,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #275 = AsmJLHCLGI
  { 276,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #276 = AsmJLHCLGR
  { 277,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #277 = AsmJLHCLI
  { 278,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #278 = AsmJLHCLR
  { 279,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #279 = AsmJLHCR
  { 280,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #280 = AsmLBR
  { 281,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #281 = AsmLEBR
  { 282,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #282 = AsmLEJ
  { 283,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #283 = AsmLEJG
  { 284,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #284 = AsmLELOC
  { 285,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #285 = AsmLELOCG
  { 286,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #286 = AsmLELOCGR
  { 287,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #287 = AsmLELOCR
  { 288,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #288 = AsmLESTOC
  { 289,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #289 = AsmLESTOCG
  { 290,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #290 = AsmLHBR
  { 291,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #291 = AsmLHJ
  { 292,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #292 = AsmLHJG
  { 293,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #293 = AsmLHLOC
  { 294,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #294 = AsmLHLOCG
  { 295,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #295 = AsmLHLOCGR
  { 296,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #296 = AsmLHLOCR
  { 297,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #297 = AsmLHSTOC
  { 298,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #298 = AsmLHSTOCG
  { 299,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #299 = AsmLJ
  { 300,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #300 = AsmLJG
  { 301,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #301 = AsmLLOC
  { 302,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #302 = AsmLLOCG
  { 303,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #303 = AsmLLOCGR
  { 304,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #304 = AsmLLOCR
  { 305,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, ImplicitList1, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #305 = AsmLOC
  { 306,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, ImplicitList1, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #306 = AsmLOCG
  { 307,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #307 = AsmLOCGR
  { 308,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList1, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #308 = AsmLOCR
  { 309,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #309 = AsmLSTOC
  { 310,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #310 = AsmLSTOCG
  { 311,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #311 = AsmNEBR
  { 312,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #312 = AsmNEJ
  { 313,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #313 = AsmNEJG
  { 314,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #314 = AsmNELOC
  { 315,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #315 = AsmNELOCG
  { 316,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #316 = AsmNELOCGR
  { 317,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #317 = AsmNELOCR
  { 318,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #318 = AsmNESTOC
  { 319,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #319 = AsmNESTOCG
  { 320,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #320 = AsmNHBR
  { 321,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #321 = AsmNHEBR
  { 322,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #322 = AsmNHEJ
  { 323,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #323 = AsmNHEJG
  { 324,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #324 = AsmNHELOC
  { 325,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #325 = AsmNHELOCG
  { 326,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #326 = AsmNHELOCGR
  { 327,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #327 = AsmNHELOCR
  { 328,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #328 = AsmNHESTOC
  { 329,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #329 = AsmNHESTOCG
  { 330,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #330 = AsmNHJ
  { 331,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #331 = AsmNHJG
  { 332,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #332 = AsmNHLOC
  { 333,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #333 = AsmNHLOCG
  { 334,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #334 = AsmNHLOCGR
  { 335,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #335 = AsmNHLOCR
  { 336,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #336 = AsmNHSTOC
  { 337,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #337 = AsmNHSTOCG
  { 338,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #338 = AsmNLBR
  { 339,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #339 = AsmNLEBR
  { 340,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #340 = AsmNLEJ
  { 341,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #341 = AsmNLEJG
  { 342,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #342 = AsmNLELOC
  { 343,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #343 = AsmNLELOCG
  { 344,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #344 = AsmNLELOCGR
  { 345,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #345 = AsmNLELOCR
  { 346,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #346 = AsmNLESTOC
  { 347,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #347 = AsmNLESTOCG
  { 348,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #348 = AsmNLHBR
  { 349,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #349 = AsmNLHJ
  { 350,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #350 = AsmNLHJG
  { 351,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #351 = AsmNLHLOC
  { 352,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #352 = AsmNLHLOCG
  { 353,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #353 = AsmNLHLOCGR
  { 354,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #354 = AsmNLHLOCR
  { 355,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #355 = AsmNLHSTOC
  { 356,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #356 = AsmNLHSTOCG
  { 357,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #357 = AsmNLJ
  { 358,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #358 = AsmNLJG
  { 359,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #359 = AsmNLLOC
  { 360,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #360 = AsmNLLOCG
  { 361,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #361 = AsmNLLOCGR
  { 362,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #362 = AsmNLLOCR
  { 363,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #363 = AsmNLSTOC
  { 364,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #364 = AsmNLSTOCG
  { 365,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #365 = AsmNOBR
  { 366,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #366 = AsmNOJ
  { 367,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #367 = AsmNOJG
  { 368,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #368 = AsmNOLOC
  { 369,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #369 = AsmNOLOCG
  { 370,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #370 = AsmNOLOCGR
  { 371,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #371 = AsmNOLOCR
  { 372,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #372 = AsmNOSTOC
  { 373,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #373 = AsmNOSTOCG
  { 374,	1,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #374 = AsmOBR
  { 375,	1,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #375 = AsmOJ
  { 376,	1,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #376 = AsmOJG
  { 377,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #377 = AsmOLOC
  { 378,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #378 = AsmOLOCG
  { 379,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #379 = AsmOLOCGR
  { 380,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #380 = AsmOLOCR
  { 381,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #381 = AsmOSTOC
  { 382,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #382 = AsmOSTOCG
  { 383,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x84ULL, ImplicitList1, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #383 = AsmSTOC
  { 384,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x104ULL, ImplicitList1, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #384 = AsmSTOCG
  { 385,	2,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #385 = BASR
  { 386,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #386 = BR
  { 387,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #387 = BRAS
  { 388,	3,	0,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #388 = BRASL
  { 389,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x40000ULL, ImplicitList1, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #389 = BRC
  { 390,	3,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x40000ULL, ImplicitList1, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #390 = BRCL
  { 391,	3,	1,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #391 = BRCT
  { 392,	3,	1,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #392 = BRCTG
  { 393,	4,	0,	4,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3888ULL, nullptr, ImplicitList1, OperandInfo59, -1 ,nullptr },  // Inst #393 = C
  { 394,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3d08ULL, nullptr, ImplicitList1, OperandInfo60, -1 ,nullptr },  // Inst #394 = CDB
  { 395,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x3c00ULL, nullptr, ImplicitList1, OperandInfo61, -1 ,nullptr },  // Inst #395 = CDBR
  { 396,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #396 = CDFBR
  { 397,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #397 = CDGBR
  { 398,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #398 = CDLFBR
  { 399,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #399 = CDLGBR
  { 400,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3c88ULL, nullptr, ImplicitList1, OperandInfo66, -1 ,nullptr },  // Inst #400 = CEB
  { 401,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x3c00ULL, nullptr, ImplicitList1, OperandInfo67, -1 ,nullptr },  // Inst #401 = CEBR
  { 402,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #402 = CEFBR
  { 403,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo69, -1 ,nullptr },  // Inst #403 = CEGBR
  { 404,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #404 = CELFBR
  { 405,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #405 = CELGBR
  { 406,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo72, -1 ,nullptr },  // Inst #406 = CFDBR
  { 407,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo73, -1 ,nullptr },  // Inst #407 = CFEBR
  { 408,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL, nullptr, ImplicitList1, OperandInfo74, -1 ,nullptr },  // Inst #408 = CFI
  { 409,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x3800ULL, nullptr, ImplicitList1, OperandInfo75, -1 ,nullptr },  // Inst #409 = CFIMux
  { 410,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo76, -1 ,nullptr },  // Inst #410 = CFXBR
  { 411,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x390cULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #411 = CG
  { 412,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo77, -1 ,nullptr },  // Inst #412 = CGDBR
  { 413,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo78, -1 ,nullptr },  // Inst #413 = CGEBR
  { 414,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x388cULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #414 = CGF
  { 415,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #415 = CGFI
  { 416,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL, nullptr, ImplicitList1, OperandInfo80, -1 ,nullptr },  // Inst #416 = CGFR
  { 417,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #417 = CGFRL
  { 418,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x384cULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #418 = CGH
  { 419,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #419 = CGHI
  { 420,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #420 = CGHRL
  { 421,	3,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #421 = CGHSI
  { 422,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo43, -1 ,nullptr },  // Inst #422 = CGIJ
  { 423,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL, nullptr, ImplicitList1, OperandInfo81, -1 ,nullptr },  // Inst #423 = CGR
  { 424,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #424 = CGRJ
  { 425,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #425 = CGRL
  { 426,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo82, -1 ,nullptr },  // Inst #426 = CGXBR
  { 427,	4,	0,	4,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3848ULL, nullptr, ImplicitList1, OperandInfo59, -1 ,nullptr },  // Inst #427 = CH
  { 428,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x388cULL, nullptr, ImplicitList1, OperandInfo83, -1 ,nullptr },  // Inst #428 = CHF
  { 429,	3,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #429 = CHHSI
  { 430,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL, nullptr, ImplicitList1, OperandInfo74, -1 ,nullptr },  // Inst #430 = CHI
  { 431,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL, nullptr, ImplicitList1, OperandInfo74, -1 ,nullptr },  // Inst #431 = CHRL
  { 432,	3,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #432 = CHSI
  { 433,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x384cULL, nullptr, ImplicitList1, OperandInfo59, -1 ,nullptr },  // Inst #433 = CHY
  { 434,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL, nullptr, ImplicitList1, OperandInfo84, -1 ,nullptr },  // Inst #434 = CIH
  { 435,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo45, -1 ,nullptr },  // Inst #435 = CIJ
  { 436,	4,	0,	4,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103888ULL, nullptr, ImplicitList1, OperandInfo59, -1 ,nullptr },  // Inst #436 = CL
  { 437,	5,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo85, -1 ,nullptr },  // Inst #437 = CLC
  { 438,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo86, -1 ,nullptr },  // Inst #438 = CLCLoop
  { 439,	5,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo87, -1 ,nullptr },  // Inst #439 = CLCSequence
  { 440,	4,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo88, -1 ,nullptr },  // Inst #440 = CLFDBR
  { 441,	4,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo89, -1 ,nullptr },  // Inst #441 = CLFEBR
  { 442,	3,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #442 = CLFHSI
  { 443,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL, nullptr, ImplicitList1, OperandInfo74, -1 ,nullptr },  // Inst #443 = CLFI
  { 444,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x103800ULL, nullptr, ImplicitList1, OperandInfo75, -1 ,nullptr },  // Inst #444 = CLFIMux
  { 445,	4,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo90, -1 ,nullptr },  // Inst #445 = CLFXBR
  { 446,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x10390cULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #446 = CLG
  { 447,	4,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo91, -1 ,nullptr },  // Inst #447 = CLGDBR
  { 448,	4,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo92, -1 ,nullptr },  // Inst #448 = CLGEBR
  { 449,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x10388cULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #449 = CLGF
  { 450,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #450 = CLGFI
  { 451,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL, nullptr, ImplicitList1, OperandInfo80, -1 ,nullptr },  // Inst #451 = CLGFR
  { 452,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #452 = CLGFRL
  { 453,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #453 = CLGHRL
  { 454,	3,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #454 = CLGHSI
  { 455,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo43, -1 ,nullptr },  // Inst #455 = CLGIJ
  { 456,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL, nullptr, ImplicitList1, OperandInfo81, -1 ,nullptr },  // Inst #456 = CLGR
  { 457,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo44, -1 ,nullptr },  // Inst #457 = CLGRJ
  { 458,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #458 = CLGRL
  { 459,	4,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo93, -1 ,nullptr },  // Inst #459 = CLGXBR
  { 460,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x10388cULL, nullptr, ImplicitList1, OperandInfo83, -1 ,nullptr },  // Inst #460 = CLHF
  { 461,	3,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #461 = CLHHSI
  { 462,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL, nullptr, ImplicitList1, OperandInfo74, -1 ,nullptr },  // Inst #462 = CLHRL
  { 463,	3,	0,	4,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #463 = CLI
  { 464,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL, nullptr, ImplicitList1, OperandInfo84, -1 ,nullptr },  // Inst #464 = CLIH
  { 465,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo45, -1 ,nullptr },  // Inst #465 = CLIJ
  { 466,	3,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103804ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #466 = CLIY
  { 467,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x10388cULL, nullptr, ImplicitList1, OperandInfo94, -1 ,nullptr },  // Inst #467 = CLMux
  { 468,	2,	0,	2,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL, nullptr, ImplicitList1, OperandInfo95, -1 ,nullptr },  // Inst #468 = CLR
  { 469,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo46, -1 ,nullptr },  // Inst #469 = CLRJ
  { 470,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL, nullptr, ImplicitList1, OperandInfo74, -1 ,nullptr },  // Inst #470 = CLRL
  { 471,	4,	2,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList2, ImplicitList1, OperandInfo96, -1 ,nullptr },  // Inst #471 = CLST
  { 472,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo97, -1 ,nullptr },  // Inst #472 = CLSTLoop
  { 473,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x10388cULL, nullptr, ImplicitList1, OperandInfo59, -1 ,nullptr },  // Inst #473 = CLY
  { 474,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x388cULL, nullptr, ImplicitList1, OperandInfo94, -1 ,nullptr },  // Inst #474 = CMux
  { 475,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo98, -1 ,nullptr },  // Inst #475 = CPSDRdd
  { 476,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo99, -1 ,nullptr },  // Inst #476 = CPSDRds
  { 477,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #477 = CPSDRsd
  { 478,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo101, -1 ,nullptr },  // Inst #478 = CPSDRss
  { 479,	2,	0,	2,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL, nullptr, ImplicitList1, OperandInfo95, -1 ,nullptr },  // Inst #479 = CR
  { 480,	4,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo46, -1 ,nullptr },  // Inst #480 = CRJ
  { 481,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL, nullptr, ImplicitList1, OperandInfo74, -1 ,nullptr },  // Inst #481 = CRL
  { 482,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo102, -1 ,nullptr },  // Inst #482 = CS
  { 483,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo103, -1 ,nullptr },  // Inst #483 = CSG
  { 484,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo102, -1 ,nullptr },  // Inst #484 = CSY
  { 485,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x3c00ULL, nullptr, ImplicitList1, OperandInfo104, -1 ,nullptr },  // Inst #485 = CXBR
  { 486,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo105, -1 ,nullptr },  // Inst #486 = CXFBR
  { 487,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo106, -1 ,nullptr },  // Inst #487 = CXGBR
  { 488,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo107, -1 ,nullptr },  // Inst #488 = CXLFBR
  { 489,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #489 = CXLGBR
  { 490,	4,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x388cULL, nullptr, ImplicitList1, OperandInfo59, -1 ,nullptr },  // Inst #490 = CY
  { 491,	1,	0,	2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, ImplicitList3, OperandInfo47, -1 ,nullptr },  // Inst #491 = CallBASR
  { 492,	0,	0,	2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList4, nullptr, nullptr, -1 ,nullptr },  // Inst #492 = CallBR
  { 493,	1,	0,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, ImplicitList3, OperandInfo5, -1 ,nullptr },  // Inst #493 = CallBRASL
  { 494,	1,	0,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #494 = CallJG
  { 495,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo109, -1 ,nullptr },  // Inst #495 = CondStore16
  { 496,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo109, -1 ,nullptr },  // Inst #496 = CondStore16Inv
  { 497,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo110, -1 ,nullptr },  // Inst #497 = CondStore16Mux
  { 498,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo110, -1 ,nullptr },  // Inst #498 = CondStore16MuxInv
  { 499,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo109, -1 ,nullptr },  // Inst #499 = CondStore32
  { 500,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo109, -1 ,nullptr },  // Inst #500 = CondStore32Inv
  { 501,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo111, -1 ,nullptr },  // Inst #501 = CondStore64
  { 502,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo111, -1 ,nullptr },  // Inst #502 = CondStore64Inv
  { 503,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo109, -1 ,nullptr },  // Inst #503 = CondStore8
  { 504,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo109, -1 ,nullptr },  // Inst #504 = CondStore8Inv
  { 505,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo110, -1 ,nullptr },  // Inst #505 = CondStore8Mux
  { 506,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo110, -1 ,nullptr },  // Inst #506 = CondStore8MuxInv
  { 507,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo112, -1 ,nullptr },  // Inst #507 = CondStoreF32
  { 508,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo112, -1 ,nullptr },  // Inst #508 = CondStoreF32Inv
  { 509,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo113, -1 ,nullptr },  // Inst #509 = CondStoreF64
  { 510,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo113, -1 ,nullptr },  // Inst #510 = CondStoreF64Inv
  { 511,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #511 = DDB
  { 512,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #512 = DDBR
  { 513,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #513 = DEB
  { 514,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #514 = DEBR
  { 515,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #515 = DL
  { 516,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL, nullptr, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #516 = DLG
  { 517,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #517 = DLGR
  { 518,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #518 = DLR
  { 519,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL, nullptr, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #519 = DSG
  { 520,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #520 = DSGF
  { 521,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #521 = DSGFR
  { 522,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #522 = DSGR
  { 523,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #523 = DXBR
  { 524,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #524 = EAR
  { 525,	1,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #525 = ETND
  { 526,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #526 = FIDBR
  { 527,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo119, -1 ,nullptr },  // Inst #527 = FIDBRA
  { 528,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo120, -1 ,nullptr },  // Inst #528 = FIEBR
  { 529,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo121, -1 ,nullptr },  // Inst #529 = FIEBRA
  { 530,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #530 = FIXBR
  { 531,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #531 = FIXBRA
  { 532,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo19, -1 ,nullptr },  // Inst #532 = FLOGR
  { 533,	1,	1,	6,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #533 = GOT
  { 534,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x28ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #534 = IC
  { 535,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x28ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #535 = IC32
  { 536,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2cULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #536 = IC32Y
  { 537,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2cULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #537 = ICY
  { 538,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #538 = IIFMux
  { 539,	2,	1,	6,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #539 = IIHF
  { 540,	3,	1,	6,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #540 = IIHF64
  { 541,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #541 = IIHH
  { 542,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #542 = IIHH64
  { 543,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #543 = IIHL
  { 544,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #544 = IIHL64
  { 545,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #545 = IIHMux
  { 546,	2,	1,	6,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #546 = IILF
  { 547,	3,	1,	6,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #547 = IILF64
  { 548,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #548 = IILH
  { 549,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #549 = IILH64
  { 550,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #550 = IILL
  { 551,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #551 = IILL64
  { 552,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #552 = IILMux
  { 553,	1,	1,	4,	0,	0, 0x0ULL, ImplicitList1, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #553 = IPM
  { 554,	1,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #554 = J
  { 555,	1,	0,	6,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #555 = JG
  { 556,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x89ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #556 = L
  { 557,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x1dULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #557 = L128
  { 558,	4,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x8ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #558 = LA
  { 559,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo126, -1 ,nullptr },  // Inst #559 = LAA
  { 560,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo127, -1 ,nullptr },  // Inst #560 = LAAG
  { 561,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, ImplicitList1, OperandInfo126, -1 ,nullptr },  // Inst #561 = LAAL
  { 562,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, ImplicitList1, OperandInfo127, -1 ,nullptr },  // Inst #562 = LAALG
  { 563,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo126, -1 ,nullptr },  // Inst #563 = LAN
  { 564,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo127, -1 ,nullptr },  // Inst #564 = LANG
  { 565,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo126, -1 ,nullptr },  // Inst #565 = LAO
  { 566,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo127, -1 ,nullptr },  // Inst #566 = LAOG
  { 567,	2,	1,	6,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #567 = LARL
  { 568,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo126, -1 ,nullptr },  // Inst #568 = LAX
  { 569,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo127, -1 ,nullptr },  // Inst #569 = LAXG
  { 570,	4,	1,	6,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xcULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #570 = LAY
  { 571,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2cULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #571 = LB
  { 572,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2cULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #572 = LBH
  { 573,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x2cULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #573 = LBMux
  { 574,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #574 = LBR
  { 575,	5,	1,	6,	0,	0, 0x8ULL, nullptr, ImplicitList1, OperandInfo128, -1 ,nullptr },  // Inst #575 = LCBB
  { 576,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo61, -1 ,nullptr },  // Inst #576 = LCDBR
  { 577,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #577 = LCDFR
  { 578,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #578 = LCDFR_32
  { 579,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo67, -1 ,nullptr },  // Inst #579 = LCEBR
  { 580,	2,	1,	4,	0,	0, 0x3b800ULL, nullptr, ImplicitList1, OperandInfo80, -1 ,nullptr },  // Inst #580 = LCGFR
  { 581,	2,	1,	4,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo81, -1 ,nullptr },  // Inst #581 = LCGR
  { 582,	2,	1,	2,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo95, -1 ,nullptr },  // Inst #582 = LCR
  { 583,	2,	1,	4,	0,	0, 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo104, -1 ,nullptr },  // Inst #583 = LCXBR
  { 584,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x109ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #584 = LD
  { 585,	4,	1,	6,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x89ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #585 = LDE32
  { 586,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #586 = LDEB
  { 587,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #587 = LDEBR
  { 588,	2,	1,	4,	0,	0|(1ULL<<MCID::Bitcast), 0x0ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #588 = LDGR
  { 589,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #589 = LDR
  { 590,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #590 = LDXBR
  { 591,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #591 = LDXBRA
  { 592,	4,	1,	6,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x10dULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #592 = LDY
  { 593,	4,	1,	4,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x89ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #593 = LE
  { 594,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo130, -1 ,nullptr },  // Inst #594 = LEDBR
  { 595,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #595 = LEDBRA
  { 596,	2,	1,	6,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #596 = LEFR
  { 597,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #597 = LER
  { 598,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #598 = LEXBR
  { 599,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #599 = LEXBRA
  { 600,	4,	1,	6,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x8dULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #600 = LEY
  { 601,	2,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #601 = LFER
  { 602,	4,	1,	6,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x8dULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #602 = LFH
  { 603,	4,	1,	6,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x10dULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #603 = LG
  { 604,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2cULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #604 = LGB
  { 605,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #605 = LGBR
  { 606,	2,	1,	4,	0,	0|(1ULL<<MCID::Bitcast), 0x0ULL, nullptr, nullptr, OperandInfo134, -1 ,nullptr },  // Inst #606 = LGDR
  { 607,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #607 = LGF
  { 608,	2,	1,	6,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #608 = LGFI
  { 609,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #609 = LGFR
  { 610,	2,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #610 = LGFRL
  { 611,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x4cULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #611 = LGH
  { 612,	2,	1,	4,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #612 = LGHI
  { 613,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #613 = LGHR
  { 614,	2,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #614 = LGHRL
  { 615,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #615 = LGR
  { 616,	2,	1,	6,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #616 = LGRL
  { 617,	4,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x48ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #617 = LH
  { 618,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x4cULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #618 = LHH
  { 619,	2,	1,	4,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #619 = LHI
  { 620,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #620 = LHIMux
  { 621,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x4cULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #621 = LHMux
  { 622,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #622 = LHR
  { 623,	2,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #623 = LHRL
  { 624,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x4cULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #624 = LHY
  { 625,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2cULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #625 = LLC
  { 626,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2cULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #626 = LLCH
  { 627,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x2cULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #627 = LLCMux
  { 628,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #628 = LLCR
  { 629,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo135, -1 ,nullptr },  // Inst #629 = LLCRMux
  { 630,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2cULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #630 = LLGC
  { 631,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #631 = LLGCR
  { 632,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #632 = LLGF
  { 633,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #633 = LLGFR
  { 634,	2,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #634 = LLGFRL
  { 635,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x4cULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #635 = LLGH
  { 636,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #636 = LLGHR
  { 637,	2,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #637 = LLGHRL
  { 638,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x4cULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #638 = LLH
  { 639,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x4cULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #639 = LLHH
  { 640,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x4cULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #640 = LLHMux
  { 641,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #641 = LLHR
  { 642,	2,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #642 = LLHRL
  { 643,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo135, -1 ,nullptr },  // Inst #643 = LLHRMux
  { 644,	2,	1,	6,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #644 = LLIHF
  { 645,	2,	1,	4,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #645 = LLIHH
  { 646,	2,	1,	4,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #646 = LLIHL
  { 647,	2,	1,	6,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #647 = LLILF
  { 648,	2,	1,	4,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #648 = LLILH
  { 649,	2,	1,	4,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #649 = LLILL
  { 650,	4,	2,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #650 = LMG
  { 651,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x8dULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #651 = LMux
  { 652,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo61, -1 ,nullptr },  // Inst #652 = LNDBR
  { 653,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #653 = LNDFR
  { 654,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #654 = LNDFR_32
  { 655,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo67, -1 ,nullptr },  // Inst #655 = LNEBR
  { 656,	2,	1,	4,	0,	0, 0x3b800ULL, nullptr, ImplicitList1, OperandInfo80, -1 ,nullptr },  // Inst #656 = LNGFR
  { 657,	2,	1,	4,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo81, -1 ,nullptr },  // Inst #657 = LNGR
  { 658,	2,	1,	2,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo95, -1 ,nullptr },  // Inst #658 = LNR
  { 659,	2,	1,	4,	0,	0, 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo104, -1 ,nullptr },  // Inst #659 = LNXBR
  { 660,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x80084ULL, ImplicitList1, nullptr, OperandInfo136, -1 ,nullptr },  // Inst #660 = LOC
  { 661,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x80104ULL, ImplicitList1, nullptr, OperandInfo137, -1 ,nullptr },  // Inst #661 = LOCG
  { 662,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80000ULL, ImplicitList1, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #662 = LOCGR
  { 663,	4,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80000ULL, ImplicitList1, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #663 = LOCR
  { 664,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo61, -1 ,nullptr },  // Inst #664 = LPDBR
  { 665,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #665 = LPDFR
  { 666,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #666 = LPDFR_32
  { 667,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo67, -1 ,nullptr },  // Inst #667 = LPEBR
  { 668,	2,	1,	4,	0,	0, 0x3b800ULL, nullptr, ImplicitList1, OperandInfo80, -1 ,nullptr },  // Inst #668 = LPGFR
  { 669,	2,	1,	4,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo81, -1 ,nullptr },  // Inst #669 = LPGR
  { 670,	2,	1,	2,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo95, -1 ,nullptr },  // Inst #670 = LPR
  { 671,	2,	1,	4,	0,	0, 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo104, -1 ,nullptr },  // Inst #671 = LPXBR
  { 672,	2,	1,	2,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #672 = LR
  { 673,	2,	1,	6,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #673 = LRL
  { 674,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo135, -1 ,nullptr },  // Inst #674 = LRMux
  { 675,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #675 = LRV
  { 676,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #676 = LRVG
  { 677,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #677 = LRVGR
  { 678,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #678 = LRVR
  { 679,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x3b88cULL, nullptr, ImplicitList1, OperandInfo59, -1 ,nullptr },  // Inst #679 = LT
  { 680,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo61, -1 ,nullptr },  // Inst #680 = LTDBR
  { 681,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo61, -1 ,nullptr },  // Inst #681 = LTDBRCompare
  { 682,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo61, -1 ,nullptr },  // Inst #682 = LTDBRCompare_VecPseudo
  { 683,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo67, -1 ,nullptr },  // Inst #683 = LTEBR
  { 684,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo67, -1 ,nullptr },  // Inst #684 = LTEBRCompare
  { 685,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo67, -1 ,nullptr },  // Inst #685 = LTEBRCompare_VecPseudo
  { 686,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x3b90cULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #686 = LTG
  { 687,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x3b88cULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #687 = LTGF
  { 688,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3b800ULL, nullptr, ImplicitList1, OperandInfo80, -1 ,nullptr },  // Inst #688 = LTGFR
  { 689,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3b800ULL, nullptr, ImplicitList1, OperandInfo81, -1 ,nullptr },  // Inst #689 = LTGR
  { 690,	2,	1,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3b800ULL, nullptr, ImplicitList1, OperandInfo95, -1 ,nullptr },  // Inst #690 = LTR
  { 691,	2,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo104, -1 ,nullptr },  // Inst #691 = LTXBR
  { 692,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo104, -1 ,nullptr },  // Inst #692 = LTXBRCompare
  { 693,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo104, -1 ,nullptr },  // Inst #693 = LTXBRCompare_VecPseudo
  { 694,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x1dULL, nullptr, nullptr, OperandInfo138, -1 ,nullptr },  // Inst #694 = LX
  { 695,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL, nullptr, nullptr, OperandInfo138, -1 ,nullptr },  // Inst #695 = LXDB
  { 696,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo139, -1 ,nullptr },  // Inst #696 = LXDBR
  { 697,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL, nullptr, nullptr, OperandInfo138, -1 ,nullptr },  // Inst #697 = LXEB
  { 698,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo140, -1 ,nullptr },  // Inst #698 = LXEBR
  { 699,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #699 = LXR
  { 700,	4,	1,	6,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad), 0x8dULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #700 = LY
  { 701,	1,	1,	4,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo141, -1 ,nullptr },  // Inst #701 = LZDR
  { 702,	1,	1,	4,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #702 = LZER
  { 703,	1,	1,	4,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo143, -1 ,nullptr },  // Inst #703 = LZXR
  { 704,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #704 = MADB
  { 705,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #705 = MADBR
  { 706,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL, nullptr, nullptr, OperandInfo146, -1 ,nullptr },  // Inst #706 = MAEB
  { 707,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #707 = MAEBR
  { 708,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #708 = MDB
  { 709,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #709 = MDBR
  { 710,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x88ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #710 = MDEB
  { 711,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #711 = MDEBR
  { 712,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #712 = MEEB
  { 713,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #713 = MEEBR
  { 714,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #714 = MGHI
  { 715,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x48ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #715 = MH
  { 716,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #716 = MHI
  { 717,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x4cULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #717 = MHY
  { 718,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL, nullptr, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #718 = MLG
  { 719,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #719 = MLGR
  { 720,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #720 = MS
  { 721,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #721 = MSDB
  { 722,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #722 = MSDBR
  { 723,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL, nullptr, nullptr, OperandInfo146, -1 ,nullptr },  // Inst #723 = MSEB
  { 724,	4,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #724 = MSEBR
  { 725,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #725 = MSFI
  { 726,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #726 = MSG
  { 727,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #727 = MSGF
  { 728,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #728 = MSGFI
  { 729,	3,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #729 = MSGFR
  { 730,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #730 = MSGR
  { 731,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #731 = MSR
  { 732,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #732 = MSY
  { 733,	5,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #733 = MVC
  { 734,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #734 = MVCLoop
  { 735,	5,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #735 = MVCSequence
  { 736,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #736 = MVGHI
  { 737,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #737 = MVHHI
  { 738,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #738 = MVHI
  { 739,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #739 = MVI
  { 740,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #740 = MVIY
  { 741,	4,	2,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList2, ImplicitList1, OperandInfo96, -1 ,nullptr },  // Inst #741 = MVST
  { 742,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo97, -1 ,nullptr },  // Inst #742 = MVSTLoop
  { 743,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #743 = MXBR
  { 744,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x108ULL, nullptr, nullptr, OperandInfo149, -1 ,nullptr },  // Inst #744 = MXDB
  { 745,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo150, -1 ,nullptr },  // Inst #745 = MXDBR
  { 746,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x23088ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #746 = N
  { 747,	5,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo85, -1 ,nullptr },  // Inst #747 = NC
  { 748,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo86, -1 ,nullptr },  // Inst #748 = NCLoop
  { 749,	5,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo87, -1 ,nullptr },  // Inst #749 = NCSequence
  { 750,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2310cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #750 = NG
  { 751,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr)|(1ULL<<MCID::Commutable), 0x23000ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #751 = NGR
  { 752,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x23000ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #752 = NGRK
  { 753,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #753 = NI
  { 754,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x23000ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #754 = NIFMux
  { 755,	3,	1,	6,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x23000ULL, nullptr, ImplicitList1, OperandInfo31, -1 ,nullptr },  // Inst #755 = NIHF
  { 756,	3,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #756 = NIHF64
  { 757,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo31, -1 ,nullptr },  // Inst #757 = NIHH
  { 758,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #758 = NIHH64
  { 759,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo31, -1 ,nullptr },  // Inst #759 = NIHL
  { 760,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #760 = NIHL64
  { 761,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #761 = NIHMux
  { 762,	3,	1,	6,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x23000ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #762 = NILF
  { 763,	3,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #763 = NILF64
  { 764,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #764 = NILH
  { 765,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #765 = NILH64
  { 766,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #766 = NILL
  { 767,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #767 = NILL64
  { 768,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #768 = NILMux
  { 769,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #769 = NIY
  { 770,	3,	1,	2,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr)|(1ULL<<MCID::Commutable), 0x23000ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #770 = NR
  { 771,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x23000ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #771 = NRK
  { 772,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10cULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #772 = NTSTG
  { 773,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2308cULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #773 = NY
  { 774,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x23088ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #774 = O
  { 775,	5,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo85, -1 ,nullptr },  // Inst #775 = OC
  { 776,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo86, -1 ,nullptr },  // Inst #776 = OCLoop
  { 777,	5,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo87, -1 ,nullptr },  // Inst #777 = OCSequence
  { 778,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2310cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #778 = OG
  { 779,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr)|(1ULL<<MCID::Commutable), 0x23000ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #779 = OGR
  { 780,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x23000ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #780 = OGRK
  { 781,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #781 = OI
  { 782,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x23000ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #782 = OIFMux
  { 783,	3,	1,	6,	0,	0, 0x23000ULL, nullptr, ImplicitList1, OperandInfo31, -1 ,nullptr },  // Inst #783 = OIHF
  { 784,	3,	1,	6,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #784 = OIHF64
  { 785,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo31, -1 ,nullptr },  // Inst #785 = OIHH
  { 786,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #786 = OIHH64
  { 787,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo31, -1 ,nullptr },  // Inst #787 = OIHL
  { 788,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #788 = OIHL64
  { 789,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #789 = OIHMux
  { 790,	3,	1,	6,	0,	0, 0x23000ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #790 = OILF
  { 791,	3,	1,	6,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #791 = OILF64
  { 792,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #792 = OILH
  { 793,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #793 = OILH64
  { 794,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #794 = OILL
  { 795,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #795 = OILL64
  { 796,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #796 = OILMux
  { 797,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #797 = OIY
  { 798,	3,	1,	2,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr)|(1ULL<<MCID::Commutable), 0x23000ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #798 = OR
  { 799,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x23000ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #799 = ORK
  { 800,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2308cULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #800 = OY
  { 801,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xcULL, nullptr, nullptr, OperandInfo151, -1 ,nullptr },  // Inst #801 = PFD
  { 802,	2,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #802 = PFDRL
  { 803,	2,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo81, -1 ,nullptr },  // Inst #803 = POPCNT
  { 804,	3,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #804 = PPA
  { 805,	6,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3b800ULL, nullptr, ImplicitList1, OperandInfo152, -1 ,nullptr },  // Inst #805 = RISBG
  { 806,	6,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo153, -1 ,nullptr },  // Inst #806 = RISBG32
  { 807,	6,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo152, -1 ,nullptr },  // Inst #807 = RISBGN
  { 808,	6,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo154, -1 ,nullptr },  // Inst #808 = RISBHG
  { 809,	6,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo155, -1 ,nullptr },  // Inst #809 = RISBHH
  { 810,	6,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo156, -1 ,nullptr },  // Inst #810 = RISBHL
  { 811,	6,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo157, -1 ,nullptr },  // Inst #811 = RISBLG
  { 812,	6,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo158, -1 ,nullptr },  // Inst #812 = RISBLH
  { 813,	6,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo153, -1 ,nullptr },  // Inst #813 = RISBLL
  { 814,	6,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo159, -1 ,nullptr },  // Inst #814 = RISBMux
  { 815,	4,	1,	6,	0,	0, 0x4ULL, nullptr, nullptr, OperandInfo160, -1 ,nullptr },  // Inst #815 = RLL
  { 816,	4,	1,	6,	0,	0, 0x4ULL, nullptr, nullptr, OperandInfo161, -1 ,nullptr },  // Inst #816 = RLLG
  { 817,	6,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo152, -1 ,nullptr },  // Inst #817 = RNSBG
  { 818,	6,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo152, -1 ,nullptr },  // Inst #818 = ROSBG
  { 819,	6,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo152, -1 ,nullptr },  // Inst #819 = RXSBG
  { 820,	0,	0,	2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #820 = Return
  { 821,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x23c88ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #821 = S
  { 822,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x3fd08ULL, nullptr, ImplicitList1, OperandInfo14, -1 ,nullptr },  // Inst #822 = SDB
  { 823,	3,	1,	4,	0,	0, 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #823 = SDBR
  { 824,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x3fc88ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #824 = SEB
  { 825,	3,	1,	4,	0,	0, 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo18, -1 ,nullptr },  // Inst #825 = SEBR
  { 826,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x23d0cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #826 = SG
  { 827,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x23c8cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #827 = SGF
  { 828,	3,	1,	4,	0,	0, 0x23c00ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #828 = SGFR
  { 829,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #829 = SGR
  { 830,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #830 = SGRK
  { 831,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x23c48ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #831 = SH
  { 832,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x23c4cULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #832 = SHY
  { 833,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #833 = SL
  { 834,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, ImplicitList1, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #834 = SLB
  { 835,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL, ImplicitList1, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #835 = SLBG
  { 836,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #836 = SLBGR
  { 837,	3,	1,	4,	0,	0, 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #837 = SLBR
  { 838,	3,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #838 = SLFI
  { 839,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #839 = SLG
  { 840,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #840 = SLGF
  { 841,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #841 = SLGFI
  { 842,	3,	1,	4,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo24, -1 ,nullptr },  // Inst #842 = SLGFR
  { 843,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #843 = SLGR
  { 844,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #844 = SLGRK
  { 845,	4,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, nullptr, OperandInfo162, -1 ,nullptr },  // Inst #845 = SLL
  { 846,	4,	1,	6,	0,	0, 0x4ULL, nullptr, nullptr, OperandInfo161, -1 ,nullptr },  // Inst #846 = SLLG
  { 847,	4,	1,	6,	0,	0, 0x4ULL, nullptr, nullptr, OperandInfo160, -1 ,nullptr },  // Inst #847 = SLLK
  { 848,	3,	1,	2,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #848 = SLR
  { 849,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #849 = SLRK
  { 850,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #850 = SLY
  { 851,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #851 = SQDB
  { 852,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #852 = SQDBR
  { 853,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #853 = SQEB
  { 854,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #854 = SQEBR
  { 855,	2,	1,	4,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #855 = SQXBR
  { 856,	3,	1,	2,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #856 = SR
  { 857,	4,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x3b800ULL, nullptr, ImplicitList1, OperandInfo162, -1 ,nullptr },  // Inst #857 = SRA
  { 858,	4,	1,	6,	0,	0, 0x3b804ULL, nullptr, ImplicitList1, OperandInfo161, -1 ,nullptr },  // Inst #858 = SRAG
  { 859,	4,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3b804ULL, nullptr, ImplicitList1, OperandInfo160, -1 ,nullptr },  // Inst #859 = SRAK
  { 860,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x23c00ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #860 = SRK
  { 861,	4,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL, nullptr, nullptr, OperandInfo162, -1 ,nullptr },  // Inst #861 = SRL
  { 862,	4,	1,	6,	0,	0, 0x4ULL, nullptr, nullptr, OperandInfo161, -1 ,nullptr },  // Inst #862 = SRLG
  { 863,	4,	1,	6,	0,	0, 0x4ULL, nullptr, nullptr, OperandInfo160, -1 ,nullptr },  // Inst #863 = SRLK
  { 864,	4,	2,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, ImplicitList2, ImplicitList1, OperandInfo96, -1 ,nullptr },  // Inst #864 = SRST
  { 865,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo97, -1 ,nullptr },  // Inst #865 = SRSTLoop
  { 866,	4,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x8aULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #866 = ST
  { 867,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x1eULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #867 = ST128
  { 868,	4,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x28ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #868 = STC
  { 869,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x2cULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #869 = STCH
  { 870,	2,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo163, -1 ,nullptr },  // Inst #870 = STCK
  { 871,	2,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo163, -1 ,nullptr },  // Inst #871 = STCKE
  { 872,	2,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo163, -1 ,nullptr },  // Inst #872 = STCKF
  { 873,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x2cULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #873 = STCMux
  { 874,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x2cULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #874 = STCY
  { 875,	4,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x10aULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #875 = STD
  { 876,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x10eULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #876 = STDY
  { 877,	4,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x8aULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #877 = STE
  { 878,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x8eULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #878 = STEY
  { 879,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x8eULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #879 = STFH
  { 880,	2,	0,	4,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo163, -1 ,nullptr },  // Inst #880 = STFLE
  { 881,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x10eULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #881 = STG
  { 882,	2,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #882 = STGRL
  { 883,	4,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x48ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #883 = STH
  { 884,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x4cULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #884 = STHH
  { 885,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x2cULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #885 = STHMux
  { 886,	2,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #886 = STHRL
  { 887,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x4cULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #887 = STHY
  { 888,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #888 = STMG
  { 889,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x8eULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #889 = STMux
  { 890,	5,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80084ULL, ImplicitList1, nullptr, OperandInfo164, -1 ,nullptr },  // Inst #890 = STOC
  { 891,	5,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80104ULL, ImplicitList1, nullptr, OperandInfo165, -1 ,nullptr },  // Inst #891 = STOCG
  { 892,	2,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #892 = STRL
  { 893,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x8cULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #893 = STRV
  { 894,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x10cULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #894 = STRVG
  { 895,	4,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x1eULL, nullptr, nullptr, OperandInfo138, -1 ,nullptr },  // Inst #895 = STX
  { 896,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x8eULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #896 = STY
  { 897,	3,	1,	4,	0,	0, 0x3fc00ULL, nullptr, ImplicitList1, OperandInfo41, -1 ,nullptr },  // Inst #897 = SXBR
  { 898,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x23c8cULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #898 = SY
  { 899,	5,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo166, -1 ,nullptr },  // Inst #899 = Select32
  { 900,	5,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo167, -1 ,nullptr },  // Inst #900 = Select32Mux
  { 901,	5,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo168, -1 ,nullptr },  // Inst #901 = Select64
  { 902,	5,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo169, -1 ,nullptr },  // Inst #902 = SelectF128
  { 903,	5,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo170, -1 ,nullptr },  // Inst #903 = SelectF32
  { 904,	5,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo171, -1 ,nullptr },  // Inst #904 = SelectF64
  { 905,	0,	0,	2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #905 = Serialize
  { 906,	2,	0,	4,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo163, -1 ,nullptr },  // Inst #906 = TABORT
  { 907,	3,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #907 = TBEGIN
  { 908,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #908 = TBEGINC
  { 909,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #909 = TBEGIN_nofloat
  { 910,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, nullptr, -1 ,nullptr },  // Inst #910 = TEND
  { 911,	1,	0,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, ImplicitList3, OperandInfo5, -1 ,nullptr },  // Inst #911 = TLS_GDCALL
  { 912,	1,	0,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, ImplicitList3, OperandInfo5, -1 ,nullptr },  // Inst #912 = TLS_LDCALL
  { 913,	3,	0,	4,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #913 = TM
  { 914,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x0ULL, nullptr, ImplicitList1, OperandInfo84, -1 ,nullptr },  // Inst #914 = TMHH
  { 915,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x0ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #915 = TMHH64
  { 916,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x0ULL, nullptr, ImplicitList1, OperandInfo84, -1 ,nullptr },  // Inst #916 = TMHL
  { 917,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x0ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #917 = TMHL64
  { 918,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo75, -1 ,nullptr },  // Inst #918 = TMHMux
  { 919,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x0ULL, nullptr, ImplicitList1, OperandInfo74, -1 ,nullptr },  // Inst #919 = TMLH
  { 920,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x0ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #920 = TMLH64
  { 921,	2,	0,	4,	0,	0|(1ULL<<MCID::Compare), 0x0ULL, nullptr, ImplicitList1, OperandInfo74, -1 ,nullptr },  // Inst #921 = TMLL
  { 922,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x0ULL, nullptr, ImplicitList1, OperandInfo79, -1 ,nullptr },  // Inst #922 = TMLL64
  { 923,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo75, -1 ,nullptr },  // Inst #923 = TMLMux
  { 924,	3,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x4ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #924 = TMY
  { 925,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #925 = VAB
  { 926,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #926 = VACCB
  { 927,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #927 = VACCCQ
  { 928,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #928 = VACCF
  { 929,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #929 = VACCG
  { 930,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #930 = VACCH
  { 931,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #931 = VACCQ
  { 932,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #932 = VACQ
  { 933,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #933 = VAF
  { 934,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #934 = VAG
  { 935,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #935 = VAH
  { 936,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #936 = VAQ
  { 937,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #937 = VAVGB
  { 938,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #938 = VAVGF
  { 939,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #939 = VAVGG
  { 940,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #940 = VAVGH
  { 941,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #941 = VAVGLB
  { 942,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #942 = VAVGLF
  { 943,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #943 = VAVGLG
  { 944,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #944 = VAVGLH
  { 945,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #945 = VCDGB
  { 946,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #946 = VCDLGB
  { 947,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #947 = VCEQB
  { 948,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #948 = VCEQBS
  { 949,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #949 = VCEQF
  { 950,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #950 = VCEQFS
  { 951,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #951 = VCEQG
  { 952,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #952 = VCEQGS
  { 953,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #953 = VCEQH
  { 954,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #954 = VCEQHS
  { 955,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #955 = VCGDB
  { 956,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #956 = VCHB
  { 957,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #957 = VCHBS
  { 958,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #958 = VCHF
  { 959,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #959 = VCHFS
  { 960,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #960 = VCHG
  { 961,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #961 = VCHGS
  { 962,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #962 = VCHH
  { 963,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #963 = VCHHS
  { 964,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #964 = VCHLB
  { 965,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #965 = VCHLBS
  { 966,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #966 = VCHLF
  { 967,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #967 = VCHLFS
  { 968,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #968 = VCHLG
  { 969,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #969 = VCHLGS
  { 970,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #970 = VCHLH
  { 971,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #971 = VCHLHS
  { 972,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #972 = VCKSM
  { 973,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #973 = VCLGDB
  { 974,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #974 = VCLZB
  { 975,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #975 = VCLZF
  { 976,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #976 = VCLZG
  { 977,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #977 = VCLZH
  { 978,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #978 = VCTZB
  { 979,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #979 = VCTZF
  { 980,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #980 = VCTZG
  { 981,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #981 = VCTZH
  { 982,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #982 = VECB
  { 983,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #983 = VECF
  { 984,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #984 = VECG
  { 985,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #985 = VECH
  { 986,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #986 = VECLB
  { 987,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #987 = VECLF
  { 988,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #988 = VECLG
  { 989,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #989 = VECLH
  { 990,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #990 = VERIMB
  { 991,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #991 = VERIMF
  { 992,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #992 = VERIMG
  { 993,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #993 = VERIMH
  { 994,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #994 = VERLLB
  { 995,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #995 = VERLLF
  { 996,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #996 = VERLLG
  { 997,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #997 = VERLLH
  { 998,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #998 = VERLLVB
  { 999,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #999 = VERLLVF
  { 1000,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1000 = VERLLVG
  { 1001,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1001 = VERLLVH
  { 1002,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1002 = VESLB
  { 1003,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1003 = VESLF
  { 1004,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1004 = VESLG
  { 1005,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1005 = VESLH
  { 1006,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1006 = VESLVB
  { 1007,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1007 = VESLVF
  { 1008,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1008 = VESLVG
  { 1009,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1009 = VESLVH
  { 1010,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1010 = VESRAB
  { 1011,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1011 = VESRAF
  { 1012,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1012 = VESRAG
  { 1013,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1013 = VESRAH
  { 1014,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1014 = VESRAVB
  { 1015,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1015 = VESRAVF
  { 1016,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1016 = VESRAVG
  { 1017,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1017 = VESRAVH
  { 1018,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1018 = VESRLB
  { 1019,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1019 = VESRLF
  { 1020,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1020 = VESRLG
  { 1021,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1021 = VESRLH
  { 1022,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1022 = VESRLVB
  { 1023,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1023 = VESRLVF
  { 1024,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1024 = VESRLVG
  { 1025,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1025 = VESRLVH
  { 1026,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1026 = VFADB
  { 1027,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1027 = VFAEB
  { 1028,	4,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo178, -1 ,nullptr },  // Inst #1028 = VFAEBS
  { 1029,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1029 = VFAEF
  { 1030,	4,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo178, -1 ,nullptr },  // Inst #1030 = VFAEFS
  { 1031,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1031 = VFAEH
  { 1032,	4,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo178, -1 ,nullptr },  // Inst #1032 = VFAEHS
  { 1033,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1033 = VFAEZB
  { 1034,	4,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo178, -1 ,nullptr },  // Inst #1034 = VFAEZBS
  { 1035,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1035 = VFAEZF
  { 1036,	4,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo178, -1 ,nullptr },  // Inst #1036 = VFAEZFS
  { 1037,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1037 = VFAEZH
  { 1038,	4,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo178, -1 ,nullptr },  // Inst #1038 = VFAEZHS
  { 1039,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1039 = VFCEDB
  { 1040,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1040 = VFCEDBS
  { 1041,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1041 = VFCHDB
  { 1042,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1042 = VFCHDBS
  { 1043,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1043 = VFCHEDB
  { 1044,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1044 = VFCHEDBS
  { 1045,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1045 = VFDDB
  { 1046,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1046 = VFEEB
  { 1047,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1047 = VFEEBS
  { 1048,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1048 = VFEEF
  { 1049,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1049 = VFEEFS
  { 1050,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1050 = VFEEH
  { 1051,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1051 = VFEEHS
  { 1052,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1052 = VFEEZB
  { 1053,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1053 = VFEEZBS
  { 1054,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1054 = VFEEZF
  { 1055,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1055 = VFEEZFS
  { 1056,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1056 = VFEEZH
  { 1057,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1057 = VFEEZHS
  { 1058,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1058 = VFENEB
  { 1059,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1059 = VFENEBS
  { 1060,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1060 = VFENEF
  { 1061,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1061 = VFENEFS
  { 1062,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1062 = VFENEH
  { 1063,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1063 = VFENEHS
  { 1064,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1064 = VFENEZB
  { 1065,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1065 = VFENEZBS
  { 1066,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1066 = VFENEZF
  { 1067,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1067 = VFENEZFS
  { 1068,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1068 = VFENEZH
  { 1069,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1069 = VFENEZHS
  { 1070,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1070 = VFIDB
  { 1071,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1071 = VFLCDB
  { 1072,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1072 = VFLNDB
  { 1073,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1073 = VFLPDB
  { 1074,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1074 = VFMADB
  { 1075,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1075 = VFMDB
  { 1076,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1076 = VFMSDB
  { 1077,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1077 = VFSDB
  { 1078,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1078 = VFSQDB
  { 1079,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo179, -1 ,nullptr },  // Inst #1079 = VFTCIDB
  { 1080,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1080 = VGBM
  { 1081,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1081 = VGEF
  { 1082,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1082 = VGEG
  { 1083,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1083 = VGFMAB
  { 1084,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1084 = VGFMAF
  { 1085,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1085 = VGFMAG
  { 1086,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1086 = VGFMAH
  { 1087,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1087 = VGFMB
  { 1088,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1088 = VGFMF
  { 1089,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1089 = VGFMG
  { 1090,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1090 = VGFMH
  { 1091,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1091 = VGMB
  { 1092,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1092 = VGMF
  { 1093,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1093 = VGMG
  { 1094,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1094 = VGMH
  { 1095,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1095 = VISTRB
  { 1096,	2,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #1096 = VISTRBS
  { 1097,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1097 = VISTRF
  { 1098,	2,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #1098 = VISTRFS
  { 1099,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1099 = VISTRH
  { 1100,	2,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #1100 = VISTRHS
  { 1101,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x200ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1101 = VL
  { 1102,	4,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1102 = VL32
  { 1103,	4,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo185, -1 ,nullptr },  // Inst #1103 = VL64
  { 1104,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1104 = VLBB
  { 1105,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1105 = VLCB
  { 1106,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1106 = VLCF
  { 1107,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1107 = VLCG
  { 1108,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1108 = VLCH
  { 1109,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1109 = VLDEB
  { 1110,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x20ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1110 = VLEB
  { 1111,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1111 = VLEDB
  { 1112,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1112 = VLEF
  { 1113,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x100ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1113 = VLEG
  { 1114,	6,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1114 = VLEH
  { 1115,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1115 = VLEIB
  { 1116,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1116 = VLEIF
  { 1117,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1117 = VLEIG
  { 1118,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1118 = VLEIH
  { 1119,	4,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1119 = VLGVB
  { 1120,	4,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1120 = VLGVF
  { 1121,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1121 = VLGVG
  { 1122,	4,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1122 = VLGVH
  { 1123,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #1123 = VLL
  { 1124,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x20ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1124 = VLLEZB
  { 1125,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1125 = VLLEZF
  { 1126,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x100ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1126 = VLLEZG
  { 1127,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1127 = VLLEZH
  { 1128,	4,	2,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #1128 = VLM
  { 1129,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1129 = VLPB
  { 1130,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1130 = VLPF
  { 1131,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1131 = VLPG
  { 1132,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1132 = VLPH
  { 1133,	2,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1133 = VLR
  { 1134,	2,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1134 = VLR32
  { 1135,	2,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1135 = VLR64
  { 1136,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x20ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1136 = VLREPB
  { 1137,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1137 = VLREPF
  { 1138,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x100ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1138 = VLREPG
  { 1139,	4,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1139 = VLREPH
  { 1140,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1140 = VLVGB
  { 1141,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1141 = VLVGF
  { 1142,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1142 = VLVGG
  { 1143,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1143 = VLVGH
  { 1144,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #1144 = VLVGP
  { 1145,	3,	1,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #1145 = VLVGP32
  { 1146,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1146 = VMAEB
  { 1147,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1147 = VMAEF
  { 1148,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1148 = VMAEH
  { 1149,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1149 = VMAHB
  { 1150,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1150 = VMAHF
  { 1151,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1151 = VMAHH
  { 1152,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1152 = VMALB
  { 1153,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1153 = VMALEB
  { 1154,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1154 = VMALEF
  { 1155,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1155 = VMALEH
  { 1156,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1156 = VMALF
  { 1157,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1157 = VMALHB
  { 1158,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1158 = VMALHF
  { 1159,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1159 = VMALHH
  { 1160,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1160 = VMALHW
  { 1161,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1161 = VMALOB
  { 1162,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1162 = VMALOF
  { 1163,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1163 = VMALOH
  { 1164,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1164 = VMAOB
  { 1165,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1165 = VMAOF
  { 1166,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1166 = VMAOH
  { 1167,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1167 = VMEB
  { 1168,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1168 = VMEF
  { 1169,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1169 = VMEH
  { 1170,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1170 = VMHB
  { 1171,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1171 = VMHF
  { 1172,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1172 = VMHH
  { 1173,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1173 = VMLB
  { 1174,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1174 = VMLEB
  { 1175,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1175 = VMLEF
  { 1176,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1176 = VMLEH
  { 1177,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1177 = VMLF
  { 1178,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1178 = VMLHB
  { 1179,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1179 = VMLHF
  { 1180,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1180 = VMLHH
  { 1181,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1181 = VMLHW
  { 1182,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1182 = VMLOB
  { 1183,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1183 = VMLOF
  { 1184,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1184 = VMLOH
  { 1185,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1185 = VMNB
  { 1186,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1186 = VMNF
  { 1187,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1187 = VMNG
  { 1188,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1188 = VMNH
  { 1189,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1189 = VMNLB
  { 1190,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1190 = VMNLF
  { 1191,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1191 = VMNLG
  { 1192,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1192 = VMNLH
  { 1193,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1193 = VMOB
  { 1194,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1194 = VMOF
  { 1195,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1195 = VMOH
  { 1196,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1196 = VMRHB
  { 1197,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1197 = VMRHF
  { 1198,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1198 = VMRHG
  { 1199,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1199 = VMRHH
  { 1200,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1200 = VMRLB
  { 1201,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1201 = VMRLF
  { 1202,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1202 = VMRLG
  { 1203,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1203 = VMRLH
  { 1204,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1204 = VMXB
  { 1205,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1205 = VMXF
  { 1206,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1206 = VMXG
  { 1207,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1207 = VMXH
  { 1208,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1208 = VMXLB
  { 1209,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1209 = VMXLF
  { 1210,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1210 = VMXLG
  { 1211,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1211 = VMXLH
  { 1212,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1212 = VN
  { 1213,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1213 = VNC
  { 1214,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1214 = VNO
  { 1215,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1215 = VO
  { 1216,	1,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #1216 = VONE
  { 1217,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1217 = VPDI
  { 1218,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1218 = VPERM
  { 1219,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1219 = VPKF
  { 1220,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1220 = VPKG
  { 1221,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1221 = VPKH
  { 1222,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1222 = VPKLSF
  { 1223,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1223 = VPKLSFS
  { 1224,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1224 = VPKLSG
  { 1225,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1225 = VPKLSGS
  { 1226,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1226 = VPKLSH
  { 1227,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1227 = VPKLSHS
  { 1228,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1228 = VPKSF
  { 1229,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1229 = VPKSFS
  { 1230,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1230 = VPKSG
  { 1231,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1231 = VPKSGS
  { 1232,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1232 = VPKSH
  { 1233,	3,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo172, -1 ,nullptr },  // Inst #1233 = VPKSHS
  { 1234,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1234 = VPOPCT
  { 1235,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1235 = VREPB
  { 1236,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1236 = VREPF
  { 1237,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1237 = VREPG
  { 1238,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1238 = VREPH
  { 1239,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1239 = VREPIB
  { 1240,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1240 = VREPIF
  { 1241,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1241 = VREPIG
  { 1242,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1242 = VREPIH
  { 1243,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1243 = VSB
  { 1244,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1244 = VSBCBIQ
  { 1245,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1245 = VSBIQ
  { 1246,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1246 = VSCBIB
  { 1247,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1247 = VSCBIF
  { 1248,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1248 = VSCBIG
  { 1249,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1249 = VSCBIH
  { 1250,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1250 = VSCBIQ
  { 1251,	5,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1251 = VSCEF
  { 1252,	5,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #1252 = VSCEG
  { 1253,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1253 = VSEGB
  { 1254,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1254 = VSEGF
  { 1255,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1255 = VSEGH
  { 1256,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1256 = VSEL
  { 1257,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1257 = VSF
  { 1258,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1258 = VSG
  { 1259,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1259 = VSH
  { 1260,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1260 = VSL
  { 1261,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1261 = VSLB
  { 1262,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1262 = VSLDB
  { 1263,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1263 = VSQ
  { 1264,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1264 = VSRA
  { 1265,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1265 = VSRAB
  { 1266,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1266 = VSRL
  { 1267,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1267 = VSRLB
  { 1268,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x200ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1268 = VST
  { 1269,	4,	0,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1269 = VST32
  { 1270,	4,	0,	6,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo185, -1 ,nullptr },  // Inst #1270 = VST64
  { 1271,	5,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x20ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1271 = VSTEB
  { 1272,	5,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x80ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1272 = VSTEF
  { 1273,	5,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x100ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1273 = VSTEG
  { 1274,	5,	0,	6,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1274 = VSTEH
  { 1275,	4,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #1275 = VSTL
  { 1276,	4,	0,	6,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #1276 = VSTM
  { 1277,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1277 = VSTRCB
  { 1278,	5,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo200, -1 ,nullptr },  // Inst #1278 = VSTRCBS
  { 1279,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1279 = VSTRCF
  { 1280,	5,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo200, -1 ,nullptr },  // Inst #1280 = VSTRCFS
  { 1281,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1281 = VSTRCH
  { 1282,	5,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo200, -1 ,nullptr },  // Inst #1282 = VSTRCHS
  { 1283,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1283 = VSTRCZB
  { 1284,	5,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo200, -1 ,nullptr },  // Inst #1284 = VSTRCZBS
  { 1285,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1285 = VSTRCZF
  { 1286,	5,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo200, -1 ,nullptr },  // Inst #1286 = VSTRCZFS
  { 1287,	5,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #1287 = VSTRCZH
  { 1288,	5,	1,	6,	0,	0, 0x0ULL, nullptr, ImplicitList1, OperandInfo200, -1 ,nullptr },  // Inst #1288 = VSTRCZHS
  { 1289,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1289 = VSUMB
  { 1290,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1290 = VSUMGF
  { 1291,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1291 = VSUMGH
  { 1292,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1292 = VSUMH
  { 1293,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1293 = VSUMQF
  { 1294,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1294 = VSUMQG
  { 1295,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare), 0x0ULL, nullptr, ImplicitList1, OperandInfo175, -1 ,nullptr },  // Inst #1295 = VTM
  { 1296,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1296 = VUPHB
  { 1297,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1297 = VUPHF
  { 1298,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1298 = VUPHH
  { 1299,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1299 = VUPLB
  { 1300,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1300 = VUPLF
  { 1301,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1301 = VUPLHB
  { 1302,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1302 = VUPLHF
  { 1303,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1303 = VUPLHH
  { 1304,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1304 = VUPLHW
  { 1305,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1305 = VUPLLB
  { 1306,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1306 = VUPLLF
  { 1307,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1307 = VUPLLH
  { 1308,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1308 = VX
  { 1309,	1,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #1309 = VZERO
  { 1310,	4,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1310 = WCDGB
  { 1311,	4,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1311 = WCDLGB
  { 1312,	4,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1312 = WCGDB
  { 1313,	4,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1313 = WCLGDB
  { 1314,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1314 = WFADB
  { 1315,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare), 0x0ULL, nullptr, ImplicitList1, OperandInfo193, -1 ,nullptr },  // Inst #1315 = WFCDB
  { 1316,	3,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1316 = WFCEDB
  { 1317,	3,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo202, -1 ,nullptr },  // Inst #1317 = WFCEDBS
  { 1318,	3,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1318 = WFCHDB
  { 1319,	3,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo202, -1 ,nullptr },  // Inst #1319 = WFCHDBS
  { 1320,	3,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1320 = WFCHEDB
  { 1321,	3,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo202, -1 ,nullptr },  // Inst #1321 = WFCHEDBS
  { 1322,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1322 = WFDDB
  { 1323,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #1323 = WFIDB
  { 1324,	2,	0,	6,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo193, -1 ,nullptr },  // Inst #1324 = WFKDB
  { 1325,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1325 = WFLCDB
  { 1326,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1326 = WFLNDB
  { 1327,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1327 = WFLPDB
  { 1328,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo203, -1 ,nullptr },  // Inst #1328 = WFMADB
  { 1329,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1329 = WFMDB
  { 1330,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo203, -1 ,nullptr },  // Inst #1330 = WFMSDB
  { 1331,	3,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #1331 = WFSDB
  { 1332,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1332 = WFSQDB
  { 1333,	3,	1,	6,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo204, -1 ,nullptr },  // Inst #1333 = WFTCIDB
  { 1334,	2,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo205, -1 ,nullptr },  // Inst #1334 = WLDEB
  { 1335,	4,	1,	6,	0,	0, 0x0ULL, nullptr, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #1335 = WLEDB
  { 1336,	5,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x23088ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #1336 = X
  { 1337,	5,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, ImplicitList1, OperandInfo85, -1 ,nullptr },  // Inst #1337 = XC
  { 1338,	6,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo86, -1 ,nullptr },  // Inst #1338 = XCLoop
  { 1339,	5,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, ImplicitList1, OperandInfo87, -1 ,nullptr },  // Inst #1339 = XCSequence
  { 1340,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2310cULL, nullptr, ImplicitList1, OperandInfo22, -1 ,nullptr },  // Inst #1340 = XG
  { 1341,	3,	1,	4,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr)|(1ULL<<MCID::Commutable), 0x23000ULL, nullptr, ImplicitList1, OperandInfo26, -1 ,nullptr },  // Inst #1341 = XGR
  { 1342,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x23000ULL, nullptr, ImplicitList1, OperandInfo27, -1 ,nullptr },  // Inst #1342 = XGRK
  { 1343,	3,	0,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #1343 = XI
  { 1344,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x23000ULL, nullptr, ImplicitList1, OperandInfo21, -1 ,nullptr },  // Inst #1344 = XIFMux
  { 1345,	3,	1,	6,	0,	0, 0x23000ULL, nullptr, ImplicitList1, OperandInfo31, -1 ,nullptr },  // Inst #1345 = XIHF
  { 1346,	3,	1,	6,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #1346 = XIHF64
  { 1347,	3,	1,	6,	0,	0, 0x23000ULL, nullptr, ImplicitList1, OperandInfo20, -1 ,nullptr },  // Inst #1347 = XILF
  { 1348,	3,	1,	6,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #1348 = XILF64
  { 1349,	3,	0,	6,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, ImplicitList1, OperandInfo28, -1 ,nullptr },  // Inst #1349 = XIY
  { 1350,	3,	1,	2,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr)|(1ULL<<MCID::Commutable), 0x23000ULL, nullptr, ImplicitList1, OperandInfo32, -1 ,nullptr },  // Inst #1350 = XR
  { 1351,	3,	1,	4,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x23000ULL, nullptr, ImplicitList1, OperandInfo33, -1 ,nullptr },  // Inst #1351 = XRK
  { 1352,	5,	1,	6,	0,	0|(1ULL<<MCID::MayLoad), 0x2308cULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #1352 = XY
  { 1353,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #1353 = ZEXT128_32
  { 1354,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #1354 = ZEXT128_64
};

static inline void InitSystemZMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(SystemZInsts, NULL, NULL, 1355);
}

} // end llvm namespace 
#endif // GET_INSTRINFO_MC_DESC


#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER
namespace llvm_ks {
struct SystemZGenInstrInfo : public TargetInstrInfo {
  explicit SystemZGenInstrInfo(int CFSetupOpcode = -1, int CFDestroyOpcode = -1, int CatchRetOpcode = -1);
  ~SystemZGenInstrInfo() override {}
};
} // end llvm namespace 
#endif // GET_INSTRINFO_HEADER


#ifdef GET_INSTRINFO_OPERAND_ENUM
#undef GET_INSTRINFO_OPERAND_ENUM
namespace llvm_ks {
namespace SystemZ {
namespace OpName { 
enum {
OPERAND_LAST
};
} // end namespace OpName
} // end namespace SystemZ
} // end namespace llvm_ks
#endif //GET_INSTRINFO_OPERAND_ENUM
#ifdef GET_INSTRINFO_NAMED_OPS
#undef GET_INSTRINFO_NAMED_OPS
namespace llvm_ks {
namespace SystemZ {
LLVM_READONLY
int16_t getNamedOperandIdx(uint16_t Opcode, uint16_t NamedIdx) {
  return -1;
}
} // end namespace SystemZ
} // end namespace llvm_ks
#endif //GET_INSTRINFO_NAMED_OPS

#ifdef GET_INSTRINFO_OPERAND_TYPES_ENUM
#undef GET_INSTRINFO_OPERAND_TYPES_ENUM
namespace llvm_ks {
namespace SystemZ {
namespace OpTypes { 
enum OperandType {
  access_reg = 0,
  bdaddr12only = 1,
  bdaddr12pair = 2,
  bdaddr20only = 3,
  bdaddr20pair = 4,
  bdladdr12onlylen8 = 5,
  bdvaddr12only = 6,
  bdxaddr12only = 7,
  bdxaddr12pair = 8,
  bdxaddr20only = 9,
  bdxaddr20only128 = 10,
  bdxaddr20pair = 11,
  brtarget16 = 12,
  brtarget16tls = 13,
  brtarget32 = 14,
  brtarget32tls = 15,
  cond4 = 16,
  disp12imm32 = 17,
  disp12imm64 = 18,
  disp20imm32 = 19,
  disp20imm64 = 20,
  dynalloc12only = 21,
  f32imm = 22,
  f64imm = 23,
  i16imm = 24,
  i1imm = 25,
  i32imm = 26,
  i64imm = 27,
  i8imm = 28,
  imm32lh16 = 29,
  imm32lh16c = 30,
  imm32ll16 = 31,
  imm32ll16c = 32,
  imm32sx16 = 33,
  imm32sx16trunc = 34,
  imm32sx8 = 35,
  imm32zx1 = 36,
  imm32zx12 = 37,
  imm32zx16 = 38,
  imm32zx2 = 39,
  imm32zx3 = 40,
  imm32zx4 = 41,
  imm32zx4even = 42,
  imm32zx6 = 43,
  imm32zx8 = 44,
  imm32zx8trunc = 45,
  imm64 = 46,
  imm64hf32 = 47,
  imm64hf32c = 48,
  imm64hh16 = 49,
  imm64hh16c = 50,
  imm64hl16 = 51,
  imm64hl16c = 52,
  imm64lf32 = 53,
  imm64lf32c = 54,
  imm64lh16 = 55,
  imm64lh16c = 56,
  imm64ll16 = 57,
  imm64ll16c = 58,
  imm64sx16 = 59,
  imm64sx32 = 60,
  imm64sx8 = 61,
  imm64zx16 = 62,
  imm64zx32 = 63,
  imm64zx32n = 64,
  imm64zx8 = 65,
  laaddr12pair = 66,
  laaddr20pair = 67,
  mviaddr12pair = 68,
  mviaddr20pair = 69,
  pcrel32 = 70,
  shift12only = 71,
  shift20only = 72,
  simm32 = 73,
  tlssym = 74,
  uimm32 = 75,
  OPERAND_TYPE_LIST_END
};
} // end namespace OpTypes
} // end namespace SystemZ
} // end namespace llvm_ks
#endif // GET_INSTRINFO_OPERAND_TYPES_ENUM
#ifdef GET_INSTRMAP_INFO
#undef GET_INSTRMAP_INFO
namespace llvm_ks {

namespace SystemZ {

enum DispSize {
	DispSize_12,
	DispSize_20
};

enum NumOpsValue {
	NumOpsValue_3
};

enum OpType {
	OpType_mem
};

// getDisp12Opcode
LLVM_READONLY
int getDisp12Opcode(uint16_t Opcode) {
static const uint16_t getDisp12OpcodeTable[][2] = {
  { SystemZ::AHY, SystemZ::AH },
  { SystemZ::ALY, SystemZ::AL },
  { SystemZ::AY, SystemZ::A },
  { SystemZ::CHY, SystemZ::CH },
  { SystemZ::CLIY, SystemZ::CLI },
  { SystemZ::CLY, SystemZ::CL },
  { SystemZ::CSY, SystemZ::CS },
  { SystemZ::CY, SystemZ::C },
  { SystemZ::IC32Y, SystemZ::IC32 },
  { SystemZ::ICY, SystemZ::IC },
  { SystemZ::LAY, SystemZ::LA },
  { SystemZ::LDY, SystemZ::LD },
  { SystemZ::LEY, SystemZ::LE },
  { SystemZ::LHY, SystemZ::LH },
  { SystemZ::LY, SystemZ::L },
  { SystemZ::MHY, SystemZ::MH },
  { SystemZ::MSY, SystemZ::MS },
  { SystemZ::MVIY, SystemZ::MVI },
  { SystemZ::NIY, SystemZ::NI },
  { SystemZ::NY, SystemZ::N },
  { SystemZ::OIY, SystemZ::OI },
  { SystemZ::OY, SystemZ::O },
  { SystemZ::SHY, SystemZ::SH },
  { SystemZ::SLY, SystemZ::SL },
  { SystemZ::STCY, SystemZ::STC },
  { SystemZ::STDY, SystemZ::STD },
  { SystemZ::STEY, SystemZ::STE },
  { SystemZ::STHY, SystemZ::STH },
  { SystemZ::STY, SystemZ::ST },
  { SystemZ::SY, SystemZ::S },
  { SystemZ::TMY, SystemZ::TM },
  { SystemZ::XIY, SystemZ::XI },
  { SystemZ::XY, SystemZ::X },
}; // End of getDisp12OpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 33;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getDisp12OpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getDisp12OpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getDisp12OpcodeTable[mid][1];
}

// getDisp20Opcode
LLVM_READONLY
int getDisp20Opcode(uint16_t Opcode) {
static const uint16_t getDisp20OpcodeTable[][2] = {
  { SystemZ::A, SystemZ::AY },
  { SystemZ::AH, SystemZ::AHY },
  { SystemZ::AL, SystemZ::ALY },
  { SystemZ::C, SystemZ::CY },
  { SystemZ::CH, SystemZ::CHY },
  { SystemZ::CL, SystemZ::CLY },
  { SystemZ::CLI, SystemZ::CLIY },
  { SystemZ::CS, SystemZ::CSY },
  { SystemZ::IC, SystemZ::ICY },
  { SystemZ::IC32, SystemZ::IC32Y },
  { SystemZ::L, SystemZ::LY },
  { SystemZ::LA, SystemZ::LAY },
  { SystemZ::LD, SystemZ::LDY },
  { SystemZ::LE, SystemZ::LEY },
  { SystemZ::LH, SystemZ::LHY },
  { SystemZ::MH, SystemZ::MHY },
  { SystemZ::MS, SystemZ::MSY },
  { SystemZ::MVI, SystemZ::MVIY },
  { SystemZ::N, SystemZ::NY },
  { SystemZ::NI, SystemZ::NIY },
  { SystemZ::O, SystemZ::OY },
  { SystemZ::OI, SystemZ::OIY },
  { SystemZ::S, SystemZ::SY },
  { SystemZ::SH, SystemZ::SHY },
  { SystemZ::SL, SystemZ::SLY },
  { SystemZ::ST, SystemZ::STY },
  { SystemZ::STC, SystemZ::STCY },
  { SystemZ::STD, SystemZ::STDY },
  { SystemZ::STE, SystemZ::STEY },
  { SystemZ::STH, SystemZ::STHY },
  { SystemZ::TM, SystemZ::TMY },
  { SystemZ::X, SystemZ::XY },
  { SystemZ::XI, SystemZ::XIY },
}; // End of getDisp20OpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 33;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getDisp20OpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getDisp20OpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getDisp20OpcodeTable[mid][1];
}

// getMemOpcode
LLVM_READONLY
int getMemOpcode(uint16_t Opcode) {
static const uint16_t getMemOpcodeTable[][2] = {
  { SystemZ::ADBR, SystemZ::ADB },
  { SystemZ::AEBR, SystemZ::AEB },
  { SystemZ::AGFR, SystemZ::AGF },
  { SystemZ::AGR, SystemZ::AG },
  { SystemZ::ALCGR, SystemZ::ALCG },
  { SystemZ::ALCR, SystemZ::ALC },
  { SystemZ::ALGFR, SystemZ::ALGF },
  { SystemZ::ALGR, SystemZ::ALG },
  { SystemZ::ALR, SystemZ::AL },
  { SystemZ::AR, SystemZ::A },
  { SystemZ::CDBR, SystemZ::CDB },
  { SystemZ::CEBR, SystemZ::CEB },
  { SystemZ::CGFR, SystemZ::CGF },
  { SystemZ::CGR, SystemZ::CG },
  { SystemZ::CLGFR, SystemZ::CLGF },
  { SystemZ::CLGR, SystemZ::CLG },
  { SystemZ::CLR, SystemZ::CL },
  { SystemZ::CR, SystemZ::C },
  { SystemZ::DDBR, SystemZ::DDB },
  { SystemZ::DEBR, SystemZ::DEB },
  { SystemZ::DLGR, SystemZ::DLG },
  { SystemZ::DLR, SystemZ::DL },
  { SystemZ::DSGFR, SystemZ::DSGF },
  { SystemZ::DSGR, SystemZ::DSG },
  { SystemZ::LBR, SystemZ::LB },
  { SystemZ::LDEBR, SystemZ::LDEB },
  { SystemZ::LDR, SystemZ::LD },
  { SystemZ::LER, SystemZ::LE },
  { SystemZ::LGBR, SystemZ::LGB },
  { SystemZ::LGFR, SystemZ::LGF },
  { SystemZ::LGHR, SystemZ::LGH },
  { SystemZ::LGR, SystemZ::LG },
  { SystemZ::LHR, SystemZ::LH },
  { SystemZ::LLCR, SystemZ::LLC },
  { SystemZ::LLCRMux, SystemZ::LLCMux },
  { SystemZ::LLGCR, SystemZ::LLGC },
  { SystemZ::LLGFR, SystemZ::LLGF },
  { SystemZ::LLGHR, SystemZ::LLGH },
  { SystemZ::LLHR, SystemZ::LLH },
  { SystemZ::LLHRMux, SystemZ::LLHMux },
  { SystemZ::LR, SystemZ::L },
  { SystemZ::LRMux, SystemZ::LMux },
  { SystemZ::LRVGR, SystemZ::LRVG },
  { SystemZ::LRVR, SystemZ::LRV },
  { SystemZ::LTGFR, SystemZ::LTGF },
  { SystemZ::LTGR, SystemZ::LTG },
  { SystemZ::LTR, SystemZ::LT },
  { SystemZ::LXDBR, SystemZ::LXDB },
  { SystemZ::LXEBR, SystemZ::LXEB },
  { SystemZ::MADBR, SystemZ::MADB },
  { SystemZ::MAEBR, SystemZ::MAEB },
  { SystemZ::MDBR, SystemZ::MDB },
  { SystemZ::MDEBR, SystemZ::MDEB },
  { SystemZ::MEEBR, SystemZ::MEEB },
  { SystemZ::MLGR, SystemZ::MLG },
  { SystemZ::MSDBR, SystemZ::MSDB },
  { SystemZ::MSEBR, SystemZ::MSEB },
  { SystemZ::MSGFR, SystemZ::MSGF },
  { SystemZ::MSGR, SystemZ::MSG },
  { SystemZ::MSR, SystemZ::MS },
  { SystemZ::MXDBR, SystemZ::MXDB },
  { SystemZ::NGR, SystemZ::NG },
  { SystemZ::NR, SystemZ::N },
  { SystemZ::OGR, SystemZ::OG },
  { SystemZ::OR, SystemZ::O },
  { SystemZ::SDBR, SystemZ::SDB },
  { SystemZ::SEBR, SystemZ::SEB },
  { SystemZ::SGFR, SystemZ::SGF },
  { SystemZ::SGR, SystemZ::SG },
  { SystemZ::SLBGR, SystemZ::SLBG },
  { SystemZ::SLBR, SystemZ::SLB },
  { SystemZ::SLGFR, SystemZ::SLGF },
  { SystemZ::SLGR, SystemZ::SLG },
  { SystemZ::SLR, SystemZ::SL },
  { SystemZ::SQDBR, SystemZ::SQDB },
  { SystemZ::SQEBR, SystemZ::SQEB },
  { SystemZ::SR, SystemZ::S },
  { SystemZ::XGR, SystemZ::XG },
  { SystemZ::XR, SystemZ::X },
}; // End of getMemOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 79;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getMemOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getMemOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getMemOpcodeTable[mid][1];
}

// getThreeOperandOpcode
LLVM_READONLY
int getThreeOperandOpcode(uint16_t Opcode) {
static const uint16_t getThreeOperandOpcodeTable[][2] = {
  { SystemZ::AGHI, SystemZ::AGHIK },
  { SystemZ::AGR, SystemZ::AGRK },
  { SystemZ::AHI, SystemZ::AHIK },
  { SystemZ::AHIMux, SystemZ::AHIMuxK },
  { SystemZ::ALGR, SystemZ::ALGRK },
  { SystemZ::ALR, SystemZ::ALRK },
  { SystemZ::AR, SystemZ::ARK },
  { SystemZ::NGR, SystemZ::NGRK },
  { SystemZ::NR, SystemZ::NRK },
  { SystemZ::OGR, SystemZ::OGRK },
  { SystemZ::OR, SystemZ::ORK },
  { SystemZ::SGR, SystemZ::SGRK },
  { SystemZ::SLGR, SystemZ::SLGRK },
  { SystemZ::SLL, SystemZ::SLLK },
  { SystemZ::SLR, SystemZ::SLRK },
  { SystemZ::SR, SystemZ::SRK },
  { SystemZ::SRA, SystemZ::SRAK },
  { SystemZ::SRL, SystemZ::SRLK },
  { SystemZ::XGR, SystemZ::XGRK },
  { SystemZ::XR, SystemZ::XRK },
}; // End of getThreeOperandOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 20;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getThreeOperandOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getThreeOperandOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getThreeOperandOpcodeTable[mid][1];
}

} // End SystemZ namespace
} // End llvm namespace
#endif // GET_INSTRMAP_INFO

