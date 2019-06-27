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

namespace Hexagon {
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
    A2_abs	= 24,
    A2_absp	= 25,
    A2_abssat	= 26,
    A2_add	= 27,
    A2_addh_h16_hh	= 28,
    A2_addh_h16_hl	= 29,
    A2_addh_h16_lh	= 30,
    A2_addh_h16_ll	= 31,
    A2_addh_h16_sat_hh	= 32,
    A2_addh_h16_sat_hl	= 33,
    A2_addh_h16_sat_lh	= 34,
    A2_addh_h16_sat_ll	= 35,
    A2_addh_l16_hl	= 36,
    A2_addh_l16_ll	= 37,
    A2_addh_l16_sat_hl	= 38,
    A2_addh_l16_sat_ll	= 39,
    A2_addi	= 40,
    A2_addp	= 41,
    A2_addpsat	= 42,
    A2_addsat	= 43,
    A2_addsp	= 44,
    A2_addsph	= 45,
    A2_addspl	= 46,
    A2_and	= 47,
    A2_andir	= 48,
    A2_andp	= 49,
    A2_aslh	= 50,
    A2_asrh	= 51,
    A2_combine_hh	= 52,
    A2_combine_hl	= 53,
    A2_combine_lh	= 54,
    A2_combine_ll	= 55,
    A2_combineii	= 56,
    A2_combinew	= 57,
    A2_max	= 58,
    A2_maxp	= 59,
    A2_maxu	= 60,
    A2_maxup	= 61,
    A2_min	= 62,
    A2_minp	= 63,
    A2_minu	= 64,
    A2_minup	= 65,
    A2_negp	= 66,
    A2_negsat	= 67,
    A2_nop	= 68,
    A2_not	= 69,
    A2_notp	= 70,
    A2_or	= 71,
    A2_orir	= 72,
    A2_orp	= 73,
    A2_paddf	= 74,
    A2_paddfnew	= 75,
    A2_paddif	= 76,
    A2_paddifnew	= 77,
    A2_paddit	= 78,
    A2_padditnew	= 79,
    A2_paddt	= 80,
    A2_paddtnew	= 81,
    A2_pandf	= 82,
    A2_pandfnew	= 83,
    A2_pandt	= 84,
    A2_pandtnew	= 85,
    A2_porf	= 86,
    A2_porfnew	= 87,
    A2_port	= 88,
    A2_portnew	= 89,
    A2_psubf	= 90,
    A2_psubfnew	= 91,
    A2_psubt	= 92,
    A2_psubtnew	= 93,
    A2_pxorf	= 94,
    A2_pxorfnew	= 95,
    A2_pxort	= 96,
    A2_pxortnew	= 97,
    A2_roundsat	= 98,
    A2_sat	= 99,
    A2_satb	= 100,
    A2_sath	= 101,
    A2_satub	= 102,
    A2_satuh	= 103,
    A2_sub	= 104,
    A2_subh_h16_hh	= 105,
    A2_subh_h16_hl	= 106,
    A2_subh_h16_lh	= 107,
    A2_subh_h16_ll	= 108,
    A2_subh_h16_sat_hh	= 109,
    A2_subh_h16_sat_hl	= 110,
    A2_subh_h16_sat_lh	= 111,
    A2_subh_h16_sat_ll	= 112,
    A2_subh_l16_hl	= 113,
    A2_subh_l16_ll	= 114,
    A2_subh_l16_sat_hl	= 115,
    A2_subh_l16_sat_ll	= 116,
    A2_subp	= 117,
    A2_subri	= 118,
    A2_subsat	= 119,
    A2_svaddh	= 120,
    A2_svaddhs	= 121,
    A2_svadduhs	= 122,
    A2_svavgh	= 123,
    A2_svavghs	= 124,
    A2_svnavgh	= 125,
    A2_svsubh	= 126,
    A2_svsubhs	= 127,
    A2_svsubuhs	= 128,
    A2_swiz	= 129,
    A2_sxtb	= 130,
    A2_sxth	= 131,
    A2_sxtw	= 132,
    A2_tfr	= 133,
    A2_tfrcrr	= 134,
    A2_tfrf	= 135,
    A2_tfrfnew	= 136,
    A2_tfrih	= 137,
    A2_tfril	= 138,
    A2_tfrp	= 139,
    A2_tfrpf	= 140,
    A2_tfrpfnew	= 141,
    A2_tfrpi	= 142,
    A2_tfrpt	= 143,
    A2_tfrptnew	= 144,
    A2_tfrrcr	= 145,
    A2_tfrsi	= 146,
    A2_tfrt	= 147,
    A2_tfrtnew	= 148,
    A2_vabsh	= 149,
    A2_vabshsat	= 150,
    A2_vabsw	= 151,
    A2_vabswsat	= 152,
    A2_vaddh	= 153,
    A2_vaddhs	= 154,
    A2_vaddub	= 155,
    A2_vaddubs	= 156,
    A2_vadduhs	= 157,
    A2_vaddw	= 158,
    A2_vaddws	= 159,
    A2_vavgh	= 160,
    A2_vavghcr	= 161,
    A2_vavghr	= 162,
    A2_vavgub	= 163,
    A2_vavgubr	= 164,
    A2_vavguh	= 165,
    A2_vavguhr	= 166,
    A2_vavguw	= 167,
    A2_vavguwr	= 168,
    A2_vavgw	= 169,
    A2_vavgwcr	= 170,
    A2_vavgwr	= 171,
    A2_vcmpbeq	= 172,
    A2_vcmpbgtu	= 173,
    A2_vcmpheq	= 174,
    A2_vcmphgt	= 175,
    A2_vcmphgtu	= 176,
    A2_vcmpweq	= 177,
    A2_vcmpwgt	= 178,
    A2_vcmpwgtu	= 179,
    A2_vconj	= 180,
    A2_vmaxb	= 181,
    A2_vmaxh	= 182,
    A2_vmaxub	= 183,
    A2_vmaxuh	= 184,
    A2_vmaxuw	= 185,
    A2_vmaxw	= 186,
    A2_vminb	= 187,
    A2_vminh	= 188,
    A2_vminub	= 189,
    A2_vminuh	= 190,
    A2_vminuw	= 191,
    A2_vminw	= 192,
    A2_vnavgh	= 193,
    A2_vnavghcr	= 194,
    A2_vnavghr	= 195,
    A2_vnavgw	= 196,
    A2_vnavgwcr	= 197,
    A2_vnavgwr	= 198,
    A2_vraddub	= 199,
    A2_vraddub_acc	= 200,
    A2_vrsadub	= 201,
    A2_vrsadub_acc	= 202,
    A2_vsubh	= 203,
    A2_vsubhs	= 204,
    A2_vsubub	= 205,
    A2_vsububs	= 206,
    A2_vsubuhs	= 207,
    A2_vsubw	= 208,
    A2_vsubws	= 209,
    A2_xor	= 210,
    A2_xorp	= 211,
    A2_zxtb	= 212,
    A2_zxth	= 213,
    A4_addp_c	= 214,
    A4_andn	= 215,
    A4_andnp	= 216,
    A4_bitsplit	= 217,
    A4_bitspliti	= 218,
    A4_boundscheck	= 219,
    A4_boundscheck_hi	= 220,
    A4_boundscheck_lo	= 221,
    A4_cmpbeq	= 222,
    A4_cmpbeqi	= 223,
    A4_cmpbgt	= 224,
    A4_cmpbgti	= 225,
    A4_cmpbgtu	= 226,
    A4_cmpbgtui	= 227,
    A4_cmpheq	= 228,
    A4_cmpheqi	= 229,
    A4_cmphgt	= 230,
    A4_cmphgti	= 231,
    A4_cmphgtu	= 232,
    A4_cmphgtui	= 233,
    A4_combineii	= 234,
    A4_combineir	= 235,
    A4_combineri	= 236,
    A4_cround_ri	= 237,
    A4_cround_rr	= 238,
    A4_ext	= 239,
    A4_ext_b	= 240,
    A4_ext_c	= 241,
    A4_ext_g	= 242,
    A4_modwrapu	= 243,
    A4_orn	= 244,
    A4_ornp	= 245,
    A4_paslhf	= 246,
    A4_paslhfnew	= 247,
    A4_paslht	= 248,
    A4_paslhtnew	= 249,
    A4_pasrhf	= 250,
    A4_pasrhfnew	= 251,
    A4_pasrht	= 252,
    A4_pasrhtnew	= 253,
    A4_psxtbf	= 254,
    A4_psxtbfnew	= 255,
    A4_psxtbt	= 256,
    A4_psxtbtnew	= 257,
    A4_psxthf	= 258,
    A4_psxthfnew	= 259,
    A4_psxtht	= 260,
    A4_psxthtnew	= 261,
    A4_pzxtbf	= 262,
    A4_pzxtbfnew	= 263,
    A4_pzxtbt	= 264,
    A4_pzxtbtnew	= 265,
    A4_pzxthf	= 266,
    A4_pzxthfnew	= 267,
    A4_pzxtht	= 268,
    A4_pzxthtnew	= 269,
    A4_rcmpeq	= 270,
    A4_rcmpeqi	= 271,
    A4_rcmpneq	= 272,
    A4_rcmpneqi	= 273,
    A4_round_ri	= 274,
    A4_round_ri_sat	= 275,
    A4_round_rr	= 276,
    A4_round_rr_sat	= 277,
    A4_subp_c	= 278,
    A4_tfrcpp	= 279,
    A4_tfrpcp	= 280,
    A4_tlbmatch	= 281,
    A4_vcmpbeq_any	= 282,
    A4_vcmpbeqi	= 283,
    A4_vcmpbgt	= 284,
    A4_vcmpbgti	= 285,
    A4_vcmpbgtui	= 286,
    A4_vcmpheqi	= 287,
    A4_vcmphgti	= 288,
    A4_vcmphgtui	= 289,
    A4_vcmpweqi	= 290,
    A4_vcmpwgti	= 291,
    A4_vcmpwgtui	= 292,
    A4_vrmaxh	= 293,
    A4_vrmaxuh	= 294,
    A4_vrmaxuw	= 295,
    A4_vrmaxw	= 296,
    A4_vrminh	= 297,
    A4_vrminuh	= 298,
    A4_vrminuw	= 299,
    A4_vrminw	= 300,
    A5_ACS	= 301,
    A5_vaddhubs	= 302,
    ADJCALLSTACKDOWN	= 303,
    ADJCALLSTACKUP	= 304,
    ALIGNA	= 305,
    ALLOCA	= 306,
    ARGEXTEND	= 307,
    C2_all8	= 308,
    C2_and	= 309,
    C2_andn	= 310,
    C2_any8	= 311,
    C2_bitsclr	= 312,
    C2_bitsclri	= 313,
    C2_bitsset	= 314,
    C2_ccombinewf	= 315,
    C2_ccombinewnewf	= 316,
    C2_ccombinewnewt	= 317,
    C2_ccombinewt	= 318,
    C2_cmoveif	= 319,
    C2_cmoveit	= 320,
    C2_cmovenewif	= 321,
    C2_cmovenewit	= 322,
    C2_cmpeq	= 323,
    C2_cmpeqi	= 324,
    C2_cmpeqp	= 325,
    C2_cmpgei	= 326,
    C2_cmpgeui	= 327,
    C2_cmpgt	= 328,
    C2_cmpgti	= 329,
    C2_cmpgtp	= 330,
    C2_cmpgtu	= 331,
    C2_cmpgtui	= 332,
    C2_cmpgtup	= 333,
    C2_mask	= 334,
    C2_mux	= 335,
    C2_muxii	= 336,
    C2_muxir	= 337,
    C2_muxri	= 338,
    C2_not	= 339,
    C2_or	= 340,
    C2_orn	= 341,
    C2_pxfer_map	= 342,
    C2_tfrpr	= 343,
    C2_tfrrp	= 344,
    C2_vitpack	= 345,
    C2_vmux	= 346,
    C2_xor	= 347,
    C4_addipc	= 348,
    C4_and_and	= 349,
    C4_and_andn	= 350,
    C4_and_or	= 351,
    C4_and_orn	= 352,
    C4_cmplte	= 353,
    C4_cmpltei	= 354,
    C4_cmplteu	= 355,
    C4_cmplteui	= 356,
    C4_cmpneq	= 357,
    C4_cmpneqi	= 358,
    C4_fastcorner9	= 359,
    C4_fastcorner9_not	= 360,
    C4_nbitsclr	= 361,
    C4_nbitsclri	= 362,
    C4_nbitsset	= 363,
    C4_or_and	= 364,
    C4_or_andn	= 365,
    C4_or_or	= 366,
    C4_or_orn	= 367,
    CALLRv3nr	= 368,
    CALLv3nr	= 369,
    CONST32	= 370,
    CONST32_Float_Real	= 371,
    CONST32_Int_Real	= 372,
    CONST64_Float_Real	= 373,
    CONST64_Int_Real	= 374,
    DuplexIClass0	= 375,
    DuplexIClass1	= 376,
    DuplexIClass2	= 377,
    DuplexIClass3	= 378,
    DuplexIClass4	= 379,
    DuplexIClass5	= 380,
    DuplexIClass6	= 381,
    DuplexIClass7	= 382,
    DuplexIClass8	= 383,
    DuplexIClass9	= 384,
    DuplexIClassA	= 385,
    DuplexIClassB	= 386,
    DuplexIClassC	= 387,
    DuplexIClassD	= 388,
    DuplexIClassE	= 389,
    DuplexIClassF	= 390,
    EH_RETURN_JMPR	= 391,
    ENDLOOP0	= 392,
    ENDLOOP1	= 393,
    F2_conv_d2df	= 394,
    F2_conv_d2sf	= 395,
    F2_conv_df2d	= 396,
    F2_conv_df2d_chop	= 397,
    F2_conv_df2sf	= 398,
    F2_conv_df2ud	= 399,
    F2_conv_df2ud_chop	= 400,
    F2_conv_df2uw	= 401,
    F2_conv_df2uw_chop	= 402,
    F2_conv_df2w	= 403,
    F2_conv_df2w_chop	= 404,
    F2_conv_sf2d	= 405,
    F2_conv_sf2d_chop	= 406,
    F2_conv_sf2df	= 407,
    F2_conv_sf2ud	= 408,
    F2_conv_sf2ud_chop	= 409,
    F2_conv_sf2uw	= 410,
    F2_conv_sf2uw_chop	= 411,
    F2_conv_sf2w	= 412,
    F2_conv_sf2w_chop	= 413,
    F2_conv_ud2df	= 414,
    F2_conv_ud2sf	= 415,
    F2_conv_uw2df	= 416,
    F2_conv_uw2sf	= 417,
    F2_conv_w2df	= 418,
    F2_conv_w2sf	= 419,
    F2_dfclass	= 420,
    F2_dfcmpeq	= 421,
    F2_dfcmpge	= 422,
    F2_dfcmpgt	= 423,
    F2_dfcmpuo	= 424,
    F2_dfimm_n	= 425,
    F2_dfimm_p	= 426,
    F2_sfadd	= 427,
    F2_sfclass	= 428,
    F2_sfcmpeq	= 429,
    F2_sfcmpge	= 430,
    F2_sfcmpgt	= 431,
    F2_sfcmpuo	= 432,
    F2_sffixupd	= 433,
    F2_sffixupn	= 434,
    F2_sffixupr	= 435,
    F2_sffma	= 436,
    F2_sffma_lib	= 437,
    F2_sffma_sc	= 438,
    F2_sffms	= 439,
    F2_sffms_lib	= 440,
    F2_sfimm_n	= 441,
    F2_sfimm_p	= 442,
    F2_sfinvsqrta	= 443,
    F2_sfmax	= 444,
    F2_sfmin	= 445,
    F2_sfmpy	= 446,
    F2_sfrecipa	= 447,
    F2_sfsub	= 448,
    FCONST32_nsdata	= 449,
    HEXAGON_V6_hi	= 450,
    HEXAGON_V6_hi_128B	= 451,
    HEXAGON_V6_lo	= 452,
    HEXAGON_V6_lo_128B	= 453,
    HEXAGON_V6_vassignp	= 454,
    HEXAGON_V6_vassignp_128B	= 455,
    HEXAGON_V6_vd0_pseudo	= 456,
    HEXAGON_V6_vd0_pseudo_128B	= 457,
    HI	= 458,
    HI_GOT	= 459,
    HI_GOTREL	= 460,
    HI_L	= 461,
    HI_PIC	= 462,
    Insert4	= 463,
    J2_call	= 464,
    J2_callf	= 465,
    J2_callr	= 466,
    J2_callrf	= 467,
    J2_callrt	= 468,
    J2_callt	= 469,
    J2_jump	= 470,
    J2_jump_ext	= 471,
    J2_jump_extf	= 472,
    J2_jump_extfnew	= 473,
    J2_jump_extfnewpt	= 474,
    J2_jump_extt	= 475,
    J2_jump_exttnew	= 476,
    J2_jump_exttnewpt	= 477,
    J2_jump_noext	= 478,
    J2_jump_noextf	= 479,
    J2_jump_noextfnew	= 480,
    J2_jump_noextfnewpt	= 481,
    J2_jump_noextt	= 482,
    J2_jump_noexttnew	= 483,
    J2_jump_noexttnewpt	= 484,
    J2_jumpf	= 485,
    J2_jumpfnew	= 486,
    J2_jumpfnewpt	= 487,
    J2_jumpr	= 488,
    J2_jumprf	= 489,
    J2_jumprfnew	= 490,
    J2_jumprfnewpt	= 491,
    J2_jumprgtez	= 492,
    J2_jumprgtezpt	= 493,
    J2_jumprltez	= 494,
    J2_jumprltezpt	= 495,
    J2_jumprnz	= 496,
    J2_jumprnzpt	= 497,
    J2_jumprt	= 498,
    J2_jumprtnew	= 499,
    J2_jumprtnewpt	= 500,
    J2_jumprz	= 501,
    J2_jumprzpt	= 502,
    J2_jumpt	= 503,
    J2_jumptnew	= 504,
    J2_jumptnewpt	= 505,
    J2_loop0i	= 506,
    J2_loop0iext	= 507,
    J2_loop0r	= 508,
    J2_loop0rext	= 509,
    J2_loop1i	= 510,
    J2_loop1iext	= 511,
    J2_loop1r	= 512,
    J2_loop1rext	= 513,
    J2_ploop1si	= 514,
    J2_ploop1sr	= 515,
    J2_ploop2si	= 516,
    J2_ploop2sr	= 517,
    J2_ploop3si	= 518,
    J2_ploop3sr	= 519,
    J4_cmpeq_f_jumpnv_nt	= 520,
    J4_cmpeq_f_jumpnv_t	= 521,
    J4_cmpeq_fp0_jump_nt	= 522,
    J4_cmpeq_fp0_jump_t	= 523,
    J4_cmpeq_fp1_jump_nt	= 524,
    J4_cmpeq_fp1_jump_t	= 525,
    J4_cmpeq_t_jumpnv_nt	= 526,
    J4_cmpeq_t_jumpnv_t	= 527,
    J4_cmpeq_tp0_jump_nt	= 528,
    J4_cmpeq_tp0_jump_t	= 529,
    J4_cmpeq_tp1_jump_nt	= 530,
    J4_cmpeq_tp1_jump_t	= 531,
    J4_cmpeqi_f_jumpnv_nt	= 532,
    J4_cmpeqi_f_jumpnv_t	= 533,
    J4_cmpeqi_fp0_jump_nt	= 534,
    J4_cmpeqi_fp0_jump_t	= 535,
    J4_cmpeqi_fp1_jump_nt	= 536,
    J4_cmpeqi_fp1_jump_t	= 537,
    J4_cmpeqi_t_jumpnv_nt	= 538,
    J4_cmpeqi_t_jumpnv_t	= 539,
    J4_cmpeqi_tp0_jump_nt	= 540,
    J4_cmpeqi_tp0_jump_t	= 541,
    J4_cmpeqi_tp1_jump_nt	= 542,
    J4_cmpeqi_tp1_jump_t	= 543,
    J4_cmpeqn1_f_jumpnv_nt	= 544,
    J4_cmpeqn1_f_jumpnv_t	= 545,
    J4_cmpeqn1_fp0_jump_nt	= 546,
    J4_cmpeqn1_fp0_jump_t	= 547,
    J4_cmpeqn1_fp1_jump_nt	= 548,
    J4_cmpeqn1_fp1_jump_t	= 549,
    J4_cmpeqn1_t_jumpnv_nt	= 550,
    J4_cmpeqn1_t_jumpnv_t	= 551,
    J4_cmpeqn1_tp0_jump_nt	= 552,
    J4_cmpeqn1_tp0_jump_t	= 553,
    J4_cmpeqn1_tp1_jump_nt	= 554,
    J4_cmpeqn1_tp1_jump_t	= 555,
    J4_cmpgt_f_jumpnv_nt	= 556,
    J4_cmpgt_f_jumpnv_t	= 557,
    J4_cmpgt_fp0_jump_nt	= 558,
    J4_cmpgt_fp0_jump_t	= 559,
    J4_cmpgt_fp1_jump_nt	= 560,
    J4_cmpgt_fp1_jump_t	= 561,
    J4_cmpgt_t_jumpnv_nt	= 562,
    J4_cmpgt_t_jumpnv_t	= 563,
    J4_cmpgt_tp0_jump_nt	= 564,
    J4_cmpgt_tp0_jump_t	= 565,
    J4_cmpgt_tp1_jump_nt	= 566,
    J4_cmpgt_tp1_jump_t	= 567,
    J4_cmpgti_f_jumpnv_nt	= 568,
    J4_cmpgti_f_jumpnv_t	= 569,
    J4_cmpgti_fp0_jump_nt	= 570,
    J4_cmpgti_fp0_jump_t	= 571,
    J4_cmpgti_fp1_jump_nt	= 572,
    J4_cmpgti_fp1_jump_t	= 573,
    J4_cmpgti_t_jumpnv_nt	= 574,
    J4_cmpgti_t_jumpnv_t	= 575,
    J4_cmpgti_tp0_jump_nt	= 576,
    J4_cmpgti_tp0_jump_t	= 577,
    J4_cmpgti_tp1_jump_nt	= 578,
    J4_cmpgti_tp1_jump_t	= 579,
    J4_cmpgtn1_f_jumpnv_nt	= 580,
    J4_cmpgtn1_f_jumpnv_t	= 581,
    J4_cmpgtn1_fp0_jump_nt	= 582,
    J4_cmpgtn1_fp0_jump_t	= 583,
    J4_cmpgtn1_fp1_jump_nt	= 584,
    J4_cmpgtn1_fp1_jump_t	= 585,
    J4_cmpgtn1_t_jumpnv_nt	= 586,
    J4_cmpgtn1_t_jumpnv_t	= 587,
    J4_cmpgtn1_tp0_jump_nt	= 588,
    J4_cmpgtn1_tp0_jump_t	= 589,
    J4_cmpgtn1_tp1_jump_nt	= 590,
    J4_cmpgtn1_tp1_jump_t	= 591,
    J4_cmpgtu_f_jumpnv_nt	= 592,
    J4_cmpgtu_f_jumpnv_t	= 593,
    J4_cmpgtu_fp0_jump_nt	= 594,
    J4_cmpgtu_fp0_jump_t	= 595,
    J4_cmpgtu_fp1_jump_nt	= 596,
    J4_cmpgtu_fp1_jump_t	= 597,
    J4_cmpgtu_t_jumpnv_nt	= 598,
    J4_cmpgtu_t_jumpnv_t	= 599,
    J4_cmpgtu_tp0_jump_nt	= 600,
    J4_cmpgtu_tp0_jump_t	= 601,
    J4_cmpgtu_tp1_jump_nt	= 602,
    J4_cmpgtu_tp1_jump_t	= 603,
    J4_cmpgtui_f_jumpnv_nt	= 604,
    J4_cmpgtui_f_jumpnv_t	= 605,
    J4_cmpgtui_fp0_jump_nt	= 606,
    J4_cmpgtui_fp0_jump_t	= 607,
    J4_cmpgtui_fp1_jump_nt	= 608,
    J4_cmpgtui_fp1_jump_t	= 609,
    J4_cmpgtui_t_jumpnv_nt	= 610,
    J4_cmpgtui_t_jumpnv_t	= 611,
    J4_cmpgtui_tp0_jump_nt	= 612,
    J4_cmpgtui_tp0_jump_t	= 613,
    J4_cmpgtui_tp1_jump_nt	= 614,
    J4_cmpgtui_tp1_jump_t	= 615,
    J4_cmplt_f_jumpnv_nt	= 616,
    J4_cmplt_f_jumpnv_t	= 617,
    J4_cmplt_t_jumpnv_nt	= 618,
    J4_cmplt_t_jumpnv_t	= 619,
    J4_cmpltu_f_jumpnv_nt	= 620,
    J4_cmpltu_f_jumpnv_t	= 621,
    J4_cmpltu_t_jumpnv_nt	= 622,
    J4_cmpltu_t_jumpnv_t	= 623,
    J4_hintjumpr	= 624,
    J4_jumpseti	= 625,
    J4_jumpsetr	= 626,
    J4_tstbit0_f_jumpnv_nt	= 627,
    J4_tstbit0_f_jumpnv_t	= 628,
    J4_tstbit0_fp0_jump_nt	= 629,
    J4_tstbit0_fp0_jump_t	= 630,
    J4_tstbit0_fp1_jump_nt	= 631,
    J4_tstbit0_fp1_jump_t	= 632,
    J4_tstbit0_t_jumpnv_nt	= 633,
    J4_tstbit0_t_jumpnv_t	= 634,
    J4_tstbit0_tp0_jump_nt	= 635,
    J4_tstbit0_tp0_jump_t	= 636,
    J4_tstbit0_tp1_jump_nt	= 637,
    J4_tstbit0_tp1_jump_t	= 638,
    JMPret	= 639,
    JMPretf	= 640,
    JMPretfnew	= 641,
    JMPretfnewpt	= 642,
    JMPrett	= 643,
    JMPrettnew	= 644,
    JMPrettnewpt	= 645,
    L2_deallocframe	= 646,
    L2_loadalignb_io	= 647,
    L2_loadalignb_pbr	= 648,
    L2_loadalignb_pci	= 649,
    L2_loadalignb_pcr	= 650,
    L2_loadalignb_pi	= 651,
    L2_loadalignb_pr	= 652,
    L2_loadalignh_io	= 653,
    L2_loadalignh_pbr	= 654,
    L2_loadalignh_pci	= 655,
    L2_loadalignh_pcr	= 656,
    L2_loadalignh_pi	= 657,
    L2_loadalignh_pr	= 658,
    L2_loadbsw2_io	= 659,
    L2_loadbsw2_pbr	= 660,
    L2_loadbsw2_pci	= 661,
    L2_loadbsw2_pcr	= 662,
    L2_loadbsw2_pi	= 663,
    L2_loadbsw2_pr	= 664,
    L2_loadbsw4_io	= 665,
    L2_loadbsw4_pbr	= 666,
    L2_loadbsw4_pci	= 667,
    L2_loadbsw4_pcr	= 668,
    L2_loadbsw4_pi	= 669,
    L2_loadbsw4_pr	= 670,
    L2_loadbzw2_io	= 671,
    L2_loadbzw2_pbr	= 672,
    L2_loadbzw2_pci	= 673,
    L2_loadbzw2_pcr	= 674,
    L2_loadbzw2_pi	= 675,
    L2_loadbzw2_pr	= 676,
    L2_loadbzw4_io	= 677,
    L2_loadbzw4_pbr	= 678,
    L2_loadbzw4_pci	= 679,
    L2_loadbzw4_pcr	= 680,
    L2_loadbzw4_pi	= 681,
    L2_loadbzw4_pr	= 682,
    L2_loadrb_io	= 683,
    L2_loadrb_pbr	= 684,
    L2_loadrb_pbr_pseudo	= 685,
    L2_loadrb_pci	= 686,
    L2_loadrb_pci_pseudo	= 687,
    L2_loadrb_pcr	= 688,
    L2_loadrb_pi	= 689,
    L2_loadrb_pr	= 690,
    L2_loadrbgp	= 691,
    L2_loadrd_io	= 692,
    L2_loadrd_pbr	= 693,
    L2_loadrd_pbr_pseudo	= 694,
    L2_loadrd_pci	= 695,
    L2_loadrd_pci_pseudo	= 696,
    L2_loadrd_pcr	= 697,
    L2_loadrd_pi	= 698,
    L2_loadrd_pr	= 699,
    L2_loadrdgp	= 700,
    L2_loadrh_io	= 701,
    L2_loadrh_pbr	= 702,
    L2_loadrh_pbr_pseudo	= 703,
    L2_loadrh_pci	= 704,
    L2_loadrh_pci_pseudo	= 705,
    L2_loadrh_pcr	= 706,
    L2_loadrh_pi	= 707,
    L2_loadrh_pr	= 708,
    L2_loadrhgp	= 709,
    L2_loadri_io	= 710,
    L2_loadri_pbr	= 711,
    L2_loadri_pbr_pseudo	= 712,
    L2_loadri_pci	= 713,
    L2_loadri_pci_pseudo	= 714,
    L2_loadri_pcr	= 715,
    L2_loadri_pi	= 716,
    L2_loadri_pr	= 717,
    L2_loadrigp	= 718,
    L2_loadrub_io	= 719,
    L2_loadrub_pbr	= 720,
    L2_loadrub_pbr_pseudo	= 721,
    L2_loadrub_pci	= 722,
    L2_loadrub_pci_pseudo	= 723,
    L2_loadrub_pcr	= 724,
    L2_loadrub_pi	= 725,
    L2_loadrub_pr	= 726,
    L2_loadrubgp	= 727,
    L2_loadruh_io	= 728,
    L2_loadruh_pbr	= 729,
    L2_loadruh_pbr_pseudo	= 730,
    L2_loadruh_pci	= 731,
    L2_loadruh_pci_pseudo	= 732,
    L2_loadruh_pcr	= 733,
    L2_loadruh_pi	= 734,
    L2_loadruh_pr	= 735,
    L2_loadruhgp	= 736,
    L2_loadw_locked	= 737,
    L2_ploadrbf_io	= 738,
    L2_ploadrbf_pi	= 739,
    L2_ploadrbfnew_io	= 740,
    L2_ploadrbfnew_pi	= 741,
    L2_ploadrbt_io	= 742,
    L2_ploadrbt_pi	= 743,
    L2_ploadrbtnew_io	= 744,
    L2_ploadrbtnew_pi	= 745,
    L2_ploadrdf_io	= 746,
    L2_ploadrdf_pi	= 747,
    L2_ploadrdfnew_io	= 748,
    L2_ploadrdfnew_pi	= 749,
    L2_ploadrdt_io	= 750,
    L2_ploadrdt_pi	= 751,
    L2_ploadrdtnew_io	= 752,
    L2_ploadrdtnew_pi	= 753,
    L2_ploadrhf_io	= 754,
    L2_ploadrhf_pi	= 755,
    L2_ploadrhfnew_io	= 756,
    L2_ploadrhfnew_pi	= 757,
    L2_ploadrht_io	= 758,
    L2_ploadrht_pi	= 759,
    L2_ploadrhtnew_io	= 760,
    L2_ploadrhtnew_pi	= 761,
    L2_ploadrif_io	= 762,
    L2_ploadrif_pi	= 763,
    L2_ploadrifnew_io	= 764,
    L2_ploadrifnew_pi	= 765,
    L2_ploadrit_io	= 766,
    L2_ploadrit_pi	= 767,
    L2_ploadritnew_io	= 768,
    L2_ploadritnew_pi	= 769,
    L2_ploadrubf_io	= 770,
    L2_ploadrubf_pi	= 771,
    L2_ploadrubfnew_io	= 772,
    L2_ploadrubfnew_pi	= 773,
    L2_ploadrubt_io	= 774,
    L2_ploadrubt_pi	= 775,
    L2_ploadrubtnew_io	= 776,
    L2_ploadrubtnew_pi	= 777,
    L2_ploadruhf_io	= 778,
    L2_ploadruhf_pi	= 779,
    L2_ploadruhfnew_io	= 780,
    L2_ploadruhfnew_pi	= 781,
    L2_ploadruht_io	= 782,
    L2_ploadruht_pi	= 783,
    L2_ploadruhtnew_io	= 784,
    L2_ploadruhtnew_pi	= 785,
    L4_add_memopb_io	= 786,
    L4_add_memoph_io	= 787,
    L4_add_memopw_io	= 788,
    L4_and_memopb_io	= 789,
    L4_and_memoph_io	= 790,
    L4_and_memopw_io	= 791,
    L4_iadd_memopb_io	= 792,
    L4_iadd_memoph_io	= 793,
    L4_iadd_memopw_io	= 794,
    L4_iand_memopb_io	= 795,
    L4_iand_memoph_io	= 796,
    L4_iand_memopw_io	= 797,
    L4_ior_memopb_io	= 798,
    L4_ior_memoph_io	= 799,
    L4_ior_memopw_io	= 800,
    L4_isub_memopb_io	= 801,
    L4_isub_memoph_io	= 802,
    L4_isub_memopw_io	= 803,
    L4_loadalignb_ap	= 804,
    L4_loadalignb_ur	= 805,
    L4_loadalignh_ap	= 806,
    L4_loadalignh_ur	= 807,
    L4_loadbsw2_ap	= 808,
    L4_loadbsw2_ur	= 809,
    L4_loadbsw4_ap	= 810,
    L4_loadbsw4_ur	= 811,
    L4_loadbzw2_ap	= 812,
    L4_loadbzw2_ur	= 813,
    L4_loadbzw4_ap	= 814,
    L4_loadbzw4_ur	= 815,
    L4_loadd_locked	= 816,
    L4_loadrb_abs	= 817,
    L4_loadrb_ap	= 818,
    L4_loadrb_rr	= 819,
    L4_loadrb_ur	= 820,
    L4_loadrd_abs	= 821,
    L4_loadrd_ap	= 822,
    L4_loadrd_rr	= 823,
    L4_loadrd_ur	= 824,
    L4_loadrh_abs	= 825,
    L4_loadrh_ap	= 826,
    L4_loadrh_rr	= 827,
    L4_loadrh_ur	= 828,
    L4_loadri_abs	= 829,
    L4_loadri_ap	= 830,
    L4_loadri_rr	= 831,
    L4_loadri_ur	= 832,
    L4_loadrub_abs	= 833,
    L4_loadrub_ap	= 834,
    L4_loadrub_rr	= 835,
    L4_loadrub_ur	= 836,
    L4_loadruh_abs	= 837,
    L4_loadruh_ap	= 838,
    L4_loadruh_rr	= 839,
    L4_loadruh_ur	= 840,
    L4_or_memopb_io	= 841,
    L4_or_memoph_io	= 842,
    L4_or_memopw_io	= 843,
    L4_ploadrbf_abs	= 844,
    L4_ploadrbf_rr	= 845,
    L4_ploadrbfnew_abs	= 846,
    L4_ploadrbfnew_rr	= 847,
    L4_ploadrbt_abs	= 848,
    L4_ploadrbt_rr	= 849,
    L4_ploadrbtnew_abs	= 850,
    L4_ploadrbtnew_rr	= 851,
    L4_ploadrdf_abs	= 852,
    L4_ploadrdf_rr	= 853,
    L4_ploadrdfnew_abs	= 854,
    L4_ploadrdfnew_rr	= 855,
    L4_ploadrdt_abs	= 856,
    L4_ploadrdt_rr	= 857,
    L4_ploadrdtnew_abs	= 858,
    L4_ploadrdtnew_rr	= 859,
    L4_ploadrhf_abs	= 860,
    L4_ploadrhf_rr	= 861,
    L4_ploadrhfnew_abs	= 862,
    L4_ploadrhfnew_rr	= 863,
    L4_ploadrht_abs	= 864,
    L4_ploadrht_rr	= 865,
    L4_ploadrhtnew_abs	= 866,
    L4_ploadrhtnew_rr	= 867,
    L4_ploadrif_abs	= 868,
    L4_ploadrif_rr	= 869,
    L4_ploadrifnew_abs	= 870,
    L4_ploadrifnew_rr	= 871,
    L4_ploadrit_abs	= 872,
    L4_ploadrit_rr	= 873,
    L4_ploadritnew_abs	= 874,
    L4_ploadritnew_rr	= 875,
    L4_ploadrubf_abs	= 876,
    L4_ploadrubf_rr	= 877,
    L4_ploadrubfnew_abs	= 878,
    L4_ploadrubfnew_rr	= 879,
    L4_ploadrubt_abs	= 880,
    L4_ploadrubt_rr	= 881,
    L4_ploadrubtnew_abs	= 882,
    L4_ploadrubtnew_rr	= 883,
    L4_ploadruhf_abs	= 884,
    L4_ploadruhf_rr	= 885,
    L4_ploadruhfnew_abs	= 886,
    L4_ploadruhfnew_rr	= 887,
    L4_ploadruht_abs	= 888,
    L4_ploadruht_rr	= 889,
    L4_ploadruhtnew_abs	= 890,
    L4_ploadruhtnew_rr	= 891,
    L4_return	= 892,
    L4_return_f	= 893,
    L4_return_fnew_pnt	= 894,
    L4_return_fnew_pt	= 895,
    L4_return_t	= 896,
    L4_return_tnew_pnt	= 897,
    L4_return_tnew_pt	= 898,
    L4_sub_memopb_io	= 899,
    L4_sub_memoph_io	= 900,
    L4_sub_memopw_io	= 901,
    LDriq_pred_V6	= 902,
    LDriq_pred_V6_128B	= 903,
    LDriq_pred_vec_V6	= 904,
    LDriq_pred_vec_V6_128B	= 905,
    LDriv_pseudo_V6	= 906,
    LDriv_pseudo_V6_128B	= 907,
    LDrivv_indexed	= 908,
    LDrivv_indexed_128B	= 909,
    LDrivv_pseudo_V6	= 910,
    LDrivv_pseudo_V6_128B	= 911,
    LDriw_mod	= 912,
    LDriw_pred	= 913,
    LO	= 914,
    LO_GOT	= 915,
    LO_GOTREL	= 916,
    LO_H	= 917,
    LO_PIC	= 918,
    M2_acci	= 919,
    M2_accii	= 920,
    M2_cmaci_s0	= 921,
    M2_cmacr_s0	= 922,
    M2_cmacs_s0	= 923,
    M2_cmacs_s1	= 924,
    M2_cmacsc_s0	= 925,
    M2_cmacsc_s1	= 926,
    M2_cmpyi_s0	= 927,
    M2_cmpyr_s0	= 928,
    M2_cmpyrs_s0	= 929,
    M2_cmpyrs_s1	= 930,
    M2_cmpyrsc_s0	= 931,
    M2_cmpyrsc_s1	= 932,
    M2_cmpys_s0	= 933,
    M2_cmpys_s1	= 934,
    M2_cmpysc_s0	= 935,
    M2_cmpysc_s1	= 936,
    M2_cnacs_s0	= 937,
    M2_cnacs_s1	= 938,
    M2_cnacsc_s0	= 939,
    M2_cnacsc_s1	= 940,
    M2_dpmpyss_acc_s0	= 941,
    M2_dpmpyss_nac_s0	= 942,
    M2_dpmpyss_rnd_s0	= 943,
    M2_dpmpyss_s0	= 944,
    M2_dpmpyuu_acc_s0	= 945,
    M2_dpmpyuu_nac_s0	= 946,
    M2_dpmpyuu_s0	= 947,
    M2_hmmpyh_rs1	= 948,
    M2_hmmpyh_s1	= 949,
    M2_hmmpyl_rs1	= 950,
    M2_hmmpyl_s1	= 951,
    M2_maci	= 952,
    M2_macsin	= 953,
    M2_macsip	= 954,
    M2_mmachs_rs0	= 955,
    M2_mmachs_rs1	= 956,
    M2_mmachs_s0	= 957,
    M2_mmachs_s1	= 958,
    M2_mmacls_rs0	= 959,
    M2_mmacls_rs1	= 960,
    M2_mmacls_s0	= 961,
    M2_mmacls_s1	= 962,
    M2_mmacuhs_rs0	= 963,
    M2_mmacuhs_rs1	= 964,
    M2_mmacuhs_s0	= 965,
    M2_mmacuhs_s1	= 966,
    M2_mmaculs_rs0	= 967,
    M2_mmaculs_rs1	= 968,
    M2_mmaculs_s0	= 969,
    M2_mmaculs_s1	= 970,
    M2_mmpyh_rs0	= 971,
    M2_mmpyh_rs1	= 972,
    M2_mmpyh_s0	= 973,
    M2_mmpyh_s1	= 974,
    M2_mmpyl_rs0	= 975,
    M2_mmpyl_rs1	= 976,
    M2_mmpyl_s0	= 977,
    M2_mmpyl_s1	= 978,
    M2_mmpyuh_rs0	= 979,
    M2_mmpyuh_rs1	= 980,
    M2_mmpyuh_s0	= 981,
    M2_mmpyuh_s1	= 982,
    M2_mmpyul_rs0	= 983,
    M2_mmpyul_rs1	= 984,
    M2_mmpyul_s0	= 985,
    M2_mmpyul_s1	= 986,
    M2_mpy_acc_hh_s0	= 987,
    M2_mpy_acc_hh_s1	= 988,
    M2_mpy_acc_hl_s0	= 989,
    M2_mpy_acc_hl_s1	= 990,
    M2_mpy_acc_lh_s0	= 991,
    M2_mpy_acc_lh_s1	= 992,
    M2_mpy_acc_ll_s0	= 993,
    M2_mpy_acc_ll_s1	= 994,
    M2_mpy_acc_sat_hh_s0	= 995,
    M2_mpy_acc_sat_hh_s1	= 996,
    M2_mpy_acc_sat_hl_s0	= 997,
    M2_mpy_acc_sat_hl_s1	= 998,
    M2_mpy_acc_sat_lh_s0	= 999,
    M2_mpy_acc_sat_lh_s1	= 1000,
    M2_mpy_acc_sat_ll_s0	= 1001,
    M2_mpy_acc_sat_ll_s1	= 1002,
    M2_mpy_hh_s0	= 1003,
    M2_mpy_hh_s1	= 1004,
    M2_mpy_hl_s0	= 1005,
    M2_mpy_hl_s1	= 1006,
    M2_mpy_lh_s0	= 1007,
    M2_mpy_lh_s1	= 1008,
    M2_mpy_ll_s0	= 1009,
    M2_mpy_ll_s1	= 1010,
    M2_mpy_nac_hh_s0	= 1011,
    M2_mpy_nac_hh_s1	= 1012,
    M2_mpy_nac_hl_s0	= 1013,
    M2_mpy_nac_hl_s1	= 1014,
    M2_mpy_nac_lh_s0	= 1015,
    M2_mpy_nac_lh_s1	= 1016,
    M2_mpy_nac_ll_s0	= 1017,
    M2_mpy_nac_ll_s1	= 1018,
    M2_mpy_nac_sat_hh_s0	= 1019,
    M2_mpy_nac_sat_hh_s1	= 1020,
    M2_mpy_nac_sat_hl_s0	= 1021,
    M2_mpy_nac_sat_hl_s1	= 1022,
    M2_mpy_nac_sat_lh_s0	= 1023,
    M2_mpy_nac_sat_lh_s1	= 1024,
    M2_mpy_nac_sat_ll_s0	= 1025,
    M2_mpy_nac_sat_ll_s1	= 1026,
    M2_mpy_rnd_hh_s0	= 1027,
    M2_mpy_rnd_hh_s1	= 1028,
    M2_mpy_rnd_hl_s0	= 1029,
    M2_mpy_rnd_hl_s1	= 1030,
    M2_mpy_rnd_lh_s0	= 1031,
    M2_mpy_rnd_lh_s1	= 1032,
    M2_mpy_rnd_ll_s0	= 1033,
    M2_mpy_rnd_ll_s1	= 1034,
    M2_mpy_sat_hh_s0	= 1035,
    M2_mpy_sat_hh_s1	= 1036,
    M2_mpy_sat_hl_s0	= 1037,
    M2_mpy_sat_hl_s1	= 1038,
    M2_mpy_sat_lh_s0	= 1039,
    M2_mpy_sat_lh_s1	= 1040,
    M2_mpy_sat_ll_s0	= 1041,
    M2_mpy_sat_ll_s1	= 1042,
    M2_mpy_sat_rnd_hh_s0	= 1043,
    M2_mpy_sat_rnd_hh_s1	= 1044,
    M2_mpy_sat_rnd_hl_s0	= 1045,
    M2_mpy_sat_rnd_hl_s1	= 1046,
    M2_mpy_sat_rnd_lh_s0	= 1047,
    M2_mpy_sat_rnd_lh_s1	= 1048,
    M2_mpy_sat_rnd_ll_s0	= 1049,
    M2_mpy_sat_rnd_ll_s1	= 1050,
    M2_mpy_up	= 1051,
    M2_mpy_up_s1	= 1052,
    M2_mpy_up_s1_sat	= 1053,
    M2_mpyd_acc_hh_s0	= 1054,
    M2_mpyd_acc_hh_s1	= 1055,
    M2_mpyd_acc_hl_s0	= 1056,
    M2_mpyd_acc_hl_s1	= 1057,
    M2_mpyd_acc_lh_s0	= 1058,
    M2_mpyd_acc_lh_s1	= 1059,
    M2_mpyd_acc_ll_s0	= 1060,
    M2_mpyd_acc_ll_s1	= 1061,
    M2_mpyd_hh_s0	= 1062,
    M2_mpyd_hh_s1	= 1063,
    M2_mpyd_hl_s0	= 1064,
    M2_mpyd_hl_s1	= 1065,
    M2_mpyd_lh_s0	= 1066,
    M2_mpyd_lh_s1	= 1067,
    M2_mpyd_ll_s0	= 1068,
    M2_mpyd_ll_s1	= 1069,
    M2_mpyd_nac_hh_s0	= 1070,
    M2_mpyd_nac_hh_s1	= 1071,
    M2_mpyd_nac_hl_s0	= 1072,
    M2_mpyd_nac_hl_s1	= 1073,
    M2_mpyd_nac_lh_s0	= 1074,
    M2_mpyd_nac_lh_s1	= 1075,
    M2_mpyd_nac_ll_s0	= 1076,
    M2_mpyd_nac_ll_s1	= 1077,
    M2_mpyd_rnd_hh_s0	= 1078,
    M2_mpyd_rnd_hh_s1	= 1079,
    M2_mpyd_rnd_hl_s0	= 1080,
    M2_mpyd_rnd_hl_s1	= 1081,
    M2_mpyd_rnd_lh_s0	= 1082,
    M2_mpyd_rnd_lh_s1	= 1083,
    M2_mpyd_rnd_ll_s0	= 1084,
    M2_mpyd_rnd_ll_s1	= 1085,
    M2_mpyi	= 1086,
    M2_mpysin	= 1087,
    M2_mpysip	= 1088,
    M2_mpysmi	= 1089,
    M2_mpysu_up	= 1090,
    M2_mpyu_acc_hh_s0	= 1091,
    M2_mpyu_acc_hh_s1	= 1092,
    M2_mpyu_acc_hl_s0	= 1093,
    M2_mpyu_acc_hl_s1	= 1094,
    M2_mpyu_acc_lh_s0	= 1095,
    M2_mpyu_acc_lh_s1	= 1096,
    M2_mpyu_acc_ll_s0	= 1097,
    M2_mpyu_acc_ll_s1	= 1098,
    M2_mpyu_hh_s0	= 1099,
    M2_mpyu_hh_s1	= 1100,
    M2_mpyu_hl_s0	= 1101,
    M2_mpyu_hl_s1	= 1102,
    M2_mpyu_lh_s0	= 1103,
    M2_mpyu_lh_s1	= 1104,
    M2_mpyu_ll_s0	= 1105,
    M2_mpyu_ll_s1	= 1106,
    M2_mpyu_nac_hh_s0	= 1107,
    M2_mpyu_nac_hh_s1	= 1108,
    M2_mpyu_nac_hl_s0	= 1109,
    M2_mpyu_nac_hl_s1	= 1110,
    M2_mpyu_nac_lh_s0	= 1111,
    M2_mpyu_nac_lh_s1	= 1112,
    M2_mpyu_nac_ll_s0	= 1113,
    M2_mpyu_nac_ll_s1	= 1114,
    M2_mpyu_up	= 1115,
    M2_mpyud_acc_hh_s0	= 1116,
    M2_mpyud_acc_hh_s1	= 1117,
    M2_mpyud_acc_hl_s0	= 1118,
    M2_mpyud_acc_hl_s1	= 1119,
    M2_mpyud_acc_lh_s0	= 1120,
    M2_mpyud_acc_lh_s1	= 1121,
    M2_mpyud_acc_ll_s0	= 1122,
    M2_mpyud_acc_ll_s1	= 1123,
    M2_mpyud_hh_s0	= 1124,
    M2_mpyud_hh_s1	= 1125,
    M2_mpyud_hl_s0	= 1126,
    M2_mpyud_hl_s1	= 1127,
    M2_mpyud_lh_s0	= 1128,
    M2_mpyud_lh_s1	= 1129,
    M2_mpyud_ll_s0	= 1130,
    M2_mpyud_ll_s1	= 1131,
    M2_mpyud_nac_hh_s0	= 1132,
    M2_mpyud_nac_hh_s1	= 1133,
    M2_mpyud_nac_hl_s0	= 1134,
    M2_mpyud_nac_hl_s1	= 1135,
    M2_mpyud_nac_lh_s0	= 1136,
    M2_mpyud_nac_lh_s1	= 1137,
    M2_mpyud_nac_ll_s0	= 1138,
    M2_mpyud_nac_ll_s1	= 1139,
    M2_mpyui	= 1140,
    M2_nacci	= 1141,
    M2_naccii	= 1142,
    M2_subacc	= 1143,
    M2_vabsdiffh	= 1144,
    M2_vabsdiffw	= 1145,
    M2_vcmac_s0_sat_i	= 1146,
    M2_vcmac_s0_sat_r	= 1147,
    M2_vcmpy_s0_sat_i	= 1148,
    M2_vcmpy_s0_sat_r	= 1149,
    M2_vcmpy_s1_sat_i	= 1150,
    M2_vcmpy_s1_sat_r	= 1151,
    M2_vdmacs_s0	= 1152,
    M2_vdmacs_s1	= 1153,
    M2_vdmpyrs_s0	= 1154,
    M2_vdmpyrs_s1	= 1155,
    M2_vdmpys_s0	= 1156,
    M2_vdmpys_s1	= 1157,
    M2_vmac2	= 1158,
    M2_vmac2es	= 1159,
    M2_vmac2es_s0	= 1160,
    M2_vmac2es_s1	= 1161,
    M2_vmac2s_s0	= 1162,
    M2_vmac2s_s1	= 1163,
    M2_vmac2su_s0	= 1164,
    M2_vmac2su_s1	= 1165,
    M2_vmpy2es_s0	= 1166,
    M2_vmpy2es_s1	= 1167,
    M2_vmpy2s_s0	= 1168,
    M2_vmpy2s_s0pack	= 1169,
    M2_vmpy2s_s1	= 1170,
    M2_vmpy2s_s1pack	= 1171,
    M2_vmpy2su_s0	= 1172,
    M2_vmpy2su_s1	= 1173,
    M2_vraddh	= 1174,
    M2_vradduh	= 1175,
    M2_vrcmaci_s0	= 1176,
    M2_vrcmaci_s0c	= 1177,
    M2_vrcmacr_s0	= 1178,
    M2_vrcmacr_s0c	= 1179,
    M2_vrcmpyi_s0	= 1180,
    M2_vrcmpyi_s0c	= 1181,
    M2_vrcmpyr_s0	= 1182,
    M2_vrcmpyr_s0c	= 1183,
    M2_vrcmpys_acc_s1	= 1184,
    M2_vrcmpys_acc_s1_h	= 1185,
    M2_vrcmpys_acc_s1_l	= 1186,
    M2_vrcmpys_s1	= 1187,
    M2_vrcmpys_s1_h	= 1188,
    M2_vrcmpys_s1_l	= 1189,
    M2_vrcmpys_s1rp	= 1190,
    M2_vrcmpys_s1rp_h	= 1191,
    M2_vrcmpys_s1rp_l	= 1192,
    M2_vrmac_s0	= 1193,
    M2_vrmpy_s0	= 1194,
    M2_xor_xacc	= 1195,
    M4_and_and	= 1196,
    M4_and_andn	= 1197,
    M4_and_or	= 1198,
    M4_and_xor	= 1199,
    M4_cmpyi_wh	= 1200,
    M4_cmpyi_whc	= 1201,
    M4_cmpyr_wh	= 1202,
    M4_cmpyr_whc	= 1203,
    M4_mac_up_s1_sat	= 1204,
    M4_mpyri_addi	= 1205,
    M4_mpyri_addr	= 1206,
    M4_mpyri_addr_u2	= 1207,
    M4_mpyrr_addi	= 1208,
    M4_mpyrr_addr	= 1209,
    M4_nac_up_s1_sat	= 1210,
    M4_or_and	= 1211,
    M4_or_andn	= 1212,
    M4_or_or	= 1213,
    M4_or_xor	= 1214,
    M4_pmpyw	= 1215,
    M4_pmpyw_acc	= 1216,
    M4_vpmpyh	= 1217,
    M4_vpmpyh_acc	= 1218,
    M4_vrmpyeh_acc_s0	= 1219,
    M4_vrmpyeh_acc_s1	= 1220,
    M4_vrmpyeh_s0	= 1221,
    M4_vrmpyeh_s1	= 1222,
    M4_vrmpyoh_acc_s0	= 1223,
    M4_vrmpyoh_acc_s1	= 1224,
    M4_vrmpyoh_s0	= 1225,
    M4_vrmpyoh_s1	= 1226,
    M4_xor_and	= 1227,
    M4_xor_andn	= 1228,
    M4_xor_or	= 1229,
    M4_xor_xacc	= 1230,
    M5_vdmacbsu	= 1231,
    M5_vdmpybsu	= 1232,
    M5_vmacbsu	= 1233,
    M5_vmacbuu	= 1234,
    M5_vmpybsu	= 1235,
    M5_vmpybuu	= 1236,
    M5_vrmacbsu	= 1237,
    M5_vrmacbuu	= 1238,
    M5_vrmpybsu	= 1239,
    M5_vrmpybuu	= 1240,
    MUX64_rr	= 1241,
    MUX_ir_f	= 1242,
    MUX_ri_f	= 1243,
    RESTORE_DEALLOC_BEFORE_TAILCALL_V4	= 1244,
    RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT	= 1245,
    RESTORE_DEALLOC_RET_JMP_V4	= 1246,
    RESTORE_DEALLOC_RET_JMP_V4_EXT	= 1247,
    S2_addasl_rrri	= 1248,
    S2_allocframe	= 1249,
    S2_asl_i_p	= 1250,
    S2_asl_i_p_acc	= 1251,
    S2_asl_i_p_and	= 1252,
    S2_asl_i_p_nac	= 1253,
    S2_asl_i_p_or	= 1254,
    S2_asl_i_p_xacc	= 1255,
    S2_asl_i_r	= 1256,
    S2_asl_i_r_acc	= 1257,
    S2_asl_i_r_and	= 1258,
    S2_asl_i_r_nac	= 1259,
    S2_asl_i_r_or	= 1260,
    S2_asl_i_r_sat	= 1261,
    S2_asl_i_r_xacc	= 1262,
    S2_asl_i_vh	= 1263,
    S2_asl_i_vw	= 1264,
    S2_asl_r_p	= 1265,
    S2_asl_r_p_acc	= 1266,
    S2_asl_r_p_and	= 1267,
    S2_asl_r_p_nac	= 1268,
    S2_asl_r_p_or	= 1269,
    S2_asl_r_p_xor	= 1270,
    S2_asl_r_r	= 1271,
    S2_asl_r_r_acc	= 1272,
    S2_asl_r_r_and	= 1273,
    S2_asl_r_r_nac	= 1274,
    S2_asl_r_r_or	= 1275,
    S2_asl_r_r_sat	= 1276,
    S2_asl_r_vh	= 1277,
    S2_asl_r_vw	= 1278,
    S2_asr_i_p	= 1279,
    S2_asr_i_p_acc	= 1280,
    S2_asr_i_p_and	= 1281,
    S2_asr_i_p_nac	= 1282,
    S2_asr_i_p_or	= 1283,
    S2_asr_i_p_rnd	= 1284,
    S2_asr_i_p_rnd_goodsyntax	= 1285,
    S2_asr_i_r	= 1286,
    S2_asr_i_r_acc	= 1287,
    S2_asr_i_r_and	= 1288,
    S2_asr_i_r_nac	= 1289,
    S2_asr_i_r_or	= 1290,
    S2_asr_i_r_rnd	= 1291,
    S2_asr_i_r_rnd_goodsyntax	= 1292,
    S2_asr_i_svw_trun	= 1293,
    S2_asr_i_vh	= 1294,
    S2_asr_i_vw	= 1295,
    S2_asr_r_p	= 1296,
    S2_asr_r_p_acc	= 1297,
    S2_asr_r_p_and	= 1298,
    S2_asr_r_p_nac	= 1299,
    S2_asr_r_p_or	= 1300,
    S2_asr_r_p_xor	= 1301,
    S2_asr_r_r	= 1302,
    S2_asr_r_r_acc	= 1303,
    S2_asr_r_r_and	= 1304,
    S2_asr_r_r_nac	= 1305,
    S2_asr_r_r_or	= 1306,
    S2_asr_r_r_sat	= 1307,
    S2_asr_r_svw_trun	= 1308,
    S2_asr_r_vh	= 1309,
    S2_asr_r_vw	= 1310,
    S2_brev	= 1311,
    S2_brevp	= 1312,
    S2_cabacdecbin	= 1313,
    S2_cabacencbin	= 1314,
    S2_cl0	= 1315,
    S2_cl0p	= 1316,
    S2_cl1	= 1317,
    S2_cl1p	= 1318,
    S2_clb	= 1319,
    S2_clbnorm	= 1320,
    S2_clbp	= 1321,
    S2_clrbit_i	= 1322,
    S2_clrbit_r	= 1323,
    S2_ct0	= 1324,
    S2_ct0p	= 1325,
    S2_ct1	= 1326,
    S2_ct1p	= 1327,
    S2_deinterleave	= 1328,
    S2_extractu	= 1329,
    S2_extractu_rp	= 1330,
    S2_extractup	= 1331,
    S2_extractup_rp	= 1332,
    S2_insert	= 1333,
    S2_insert_rp	= 1334,
    S2_insertp	= 1335,
    S2_insertp_rp	= 1336,
    S2_interleave	= 1337,
    S2_lfsp	= 1338,
    S2_lsl_r_p	= 1339,
    S2_lsl_r_p_acc	= 1340,
    S2_lsl_r_p_and	= 1341,
    S2_lsl_r_p_nac	= 1342,
    S2_lsl_r_p_or	= 1343,
    S2_lsl_r_p_xor	= 1344,
    S2_lsl_r_r	= 1345,
    S2_lsl_r_r_acc	= 1346,
    S2_lsl_r_r_and	= 1347,
    S2_lsl_r_r_nac	= 1348,
    S2_lsl_r_r_or	= 1349,
    S2_lsl_r_vh	= 1350,
    S2_lsl_r_vw	= 1351,
    S2_lsr_i_p	= 1352,
    S2_lsr_i_p_acc	= 1353,
    S2_lsr_i_p_and	= 1354,
    S2_lsr_i_p_nac	= 1355,
    S2_lsr_i_p_or	= 1356,
    S2_lsr_i_p_xacc	= 1357,
    S2_lsr_i_r	= 1358,
    S2_lsr_i_r_acc	= 1359,
    S2_lsr_i_r_and	= 1360,
    S2_lsr_i_r_nac	= 1361,
    S2_lsr_i_r_or	= 1362,
    S2_lsr_i_r_xacc	= 1363,
    S2_lsr_i_vh	= 1364,
    S2_lsr_i_vw	= 1365,
    S2_lsr_r_p	= 1366,
    S2_lsr_r_p_acc	= 1367,
    S2_lsr_r_p_and	= 1368,
    S2_lsr_r_p_nac	= 1369,
    S2_lsr_r_p_or	= 1370,
    S2_lsr_r_p_xor	= 1371,
    S2_lsr_r_r	= 1372,
    S2_lsr_r_r_acc	= 1373,
    S2_lsr_r_r_and	= 1374,
    S2_lsr_r_r_nac	= 1375,
    S2_lsr_r_r_or	= 1376,
    S2_lsr_r_vh	= 1377,
    S2_lsr_r_vw	= 1378,
    S2_packhl	= 1379,
    S2_parityp	= 1380,
    S2_pstorerbf_io	= 1381,
    S2_pstorerbf_pi	= 1382,
    S2_pstorerbfnew_pi	= 1383,
    S2_pstorerbnewf_io	= 1384,
    S2_pstorerbnewf_pi	= 1385,
    S2_pstorerbnewfnew_pi	= 1386,
    S2_pstorerbnewt_io	= 1387,
    S2_pstorerbnewt_pi	= 1388,
    S2_pstorerbnewtnew_pi	= 1389,
    S2_pstorerbt_io	= 1390,
    S2_pstorerbt_pi	= 1391,
    S2_pstorerbtnew_pi	= 1392,
    S2_pstorerdf_io	= 1393,
    S2_pstorerdf_pi	= 1394,
    S2_pstorerdfnew_pi	= 1395,
    S2_pstorerdt_io	= 1396,
    S2_pstorerdt_pi	= 1397,
    S2_pstorerdtnew_pi	= 1398,
    S2_pstorerff_io	= 1399,
    S2_pstorerff_pi	= 1400,
    S2_pstorerffnew_pi	= 1401,
    S2_pstorerft_io	= 1402,
    S2_pstorerft_pi	= 1403,
    S2_pstorerftnew_pi	= 1404,
    S2_pstorerhf_io	= 1405,
    S2_pstorerhf_pi	= 1406,
    S2_pstorerhfnew_pi	= 1407,
    S2_pstorerhnewf_io	= 1408,
    S2_pstorerhnewf_pi	= 1409,
    S2_pstorerhnewfnew_pi	= 1410,
    S2_pstorerhnewt_io	= 1411,
    S2_pstorerhnewt_pi	= 1412,
    S2_pstorerhnewtnew_pi	= 1413,
    S2_pstorerht_io	= 1414,
    S2_pstorerht_pi	= 1415,
    S2_pstorerhtnew_pi	= 1416,
    S2_pstorerif_io	= 1417,
    S2_pstorerif_pi	= 1418,
    S2_pstorerifnew_pi	= 1419,
    S2_pstorerinewf_io	= 1420,
    S2_pstorerinewf_pi	= 1421,
    S2_pstorerinewfnew_pi	= 1422,
    S2_pstorerinewt_io	= 1423,
    S2_pstorerinewt_pi	= 1424,
    S2_pstorerinewtnew_pi	= 1425,
    S2_pstorerit_io	= 1426,
    S2_pstorerit_pi	= 1427,
    S2_pstoreritnew_pi	= 1428,
    S2_setbit_i	= 1429,
    S2_setbit_r	= 1430,
    S2_shuffeb	= 1431,
    S2_shuffeh	= 1432,
    S2_shuffob	= 1433,
    S2_shuffoh	= 1434,
    S2_storerb_io	= 1435,
    S2_storerb_pbr	= 1436,
    S2_storerb_pbr_pseudo	= 1437,
    S2_storerb_pci	= 1438,
    S2_storerb_pci_pseudo	= 1439,
    S2_storerb_pcr	= 1440,
    S2_storerb_pi	= 1441,
    S2_storerb_pr	= 1442,
    S2_storerbabs	= 1443,
    S2_storerbgp	= 1444,
    S2_storerbnew_io	= 1445,
    S2_storerbnew_pbr	= 1446,
    S2_storerbnew_pci	= 1447,
    S2_storerbnew_pcr	= 1448,
    S2_storerbnew_pi	= 1449,
    S2_storerbnew_pr	= 1450,
    S2_storerbnewabs	= 1451,
    S2_storerbnewgp	= 1452,
    S2_storerd_io	= 1453,
    S2_storerd_pbr	= 1454,
    S2_storerd_pbr_pseudo	= 1455,
    S2_storerd_pci	= 1456,
    S2_storerd_pci_pseudo	= 1457,
    S2_storerd_pcr	= 1458,
    S2_storerd_pi	= 1459,
    S2_storerd_pr	= 1460,
    S2_storerdabs	= 1461,
    S2_storerdgp	= 1462,
    S2_storerf_io	= 1463,
    S2_storerf_pbr	= 1464,
    S2_storerf_pbr_pseudo	= 1465,
    S2_storerf_pci	= 1466,
    S2_storerf_pci_pseudo	= 1467,
    S2_storerf_pcr	= 1468,
    S2_storerf_pi	= 1469,
    S2_storerf_pr	= 1470,
    S2_storerfabs	= 1471,
    S2_storerfgp	= 1472,
    S2_storerh_io	= 1473,
    S2_storerh_pbr	= 1474,
    S2_storerh_pbr_pseudo	= 1475,
    S2_storerh_pci	= 1476,
    S2_storerh_pci_pseudo	= 1477,
    S2_storerh_pcr	= 1478,
    S2_storerh_pi	= 1479,
    S2_storerh_pr	= 1480,
    S2_storerhabs	= 1481,
    S2_storerhgp	= 1482,
    S2_storerhnew_io	= 1483,
    S2_storerhnew_pbr	= 1484,
    S2_storerhnew_pci	= 1485,
    S2_storerhnew_pcr	= 1486,
    S2_storerhnew_pi	= 1487,
    S2_storerhnew_pr	= 1488,
    S2_storerhnewabs	= 1489,
    S2_storerhnewgp	= 1490,
    S2_storeri_io	= 1491,
    S2_storeri_pbr	= 1492,
    S2_storeri_pbr_pseudo	= 1493,
    S2_storeri_pci	= 1494,
    S2_storeri_pci_pseudo	= 1495,
    S2_storeri_pcr	= 1496,
    S2_storeri_pi	= 1497,
    S2_storeri_pr	= 1498,
    S2_storeriabs	= 1499,
    S2_storerigp	= 1500,
    S2_storerinew_io	= 1501,
    S2_storerinew_pbr	= 1502,
    S2_storerinew_pci	= 1503,
    S2_storerinew_pcr	= 1504,
    S2_storerinew_pi	= 1505,
    S2_storerinew_pr	= 1506,
    S2_storerinewabs	= 1507,
    S2_storerinewgp	= 1508,
    S2_storew_locked	= 1509,
    S2_svsathb	= 1510,
    S2_svsathub	= 1511,
    S2_tableidxb	= 1512,
    S2_tableidxb_goodsyntax	= 1513,
    S2_tableidxd	= 1514,
    S2_tableidxd_goodsyntax	= 1515,
    S2_tableidxh	= 1516,
    S2_tableidxh_goodsyntax	= 1517,
    S2_tableidxw	= 1518,
    S2_tableidxw_goodsyntax	= 1519,
    S2_togglebit_i	= 1520,
    S2_togglebit_r	= 1521,
    S2_tstbit_i	= 1522,
    S2_tstbit_r	= 1523,
    S2_valignib	= 1524,
    S2_valignrb	= 1525,
    S2_vcnegh	= 1526,
    S2_vcrotate	= 1527,
    S2_vrcnegh	= 1528,
    S2_vrndpackwh	= 1529,
    S2_vrndpackwhs	= 1530,
    S2_vsathb	= 1531,
    S2_vsathb_nopack	= 1532,
    S2_vsathub	= 1533,
    S2_vsathub_nopack	= 1534,
    S2_vsatwh	= 1535,
    S2_vsatwh_nopack	= 1536,
    S2_vsatwuh	= 1537,
    S2_vsatwuh_nopack	= 1538,
    S2_vsplatrb	= 1539,
    S2_vsplatrh	= 1540,
    S2_vspliceib	= 1541,
    S2_vsplicerb	= 1542,
    S2_vsxtbh	= 1543,
    S2_vsxthw	= 1544,
    S2_vtrunehb	= 1545,
    S2_vtrunewh	= 1546,
    S2_vtrunohb	= 1547,
    S2_vtrunowh	= 1548,
    S2_vzxtbh	= 1549,
    S2_vzxthw	= 1550,
    S4_addaddi	= 1551,
    S4_addi_asl_ri	= 1552,
    S4_addi_lsr_ri	= 1553,
    S4_andi_asl_ri	= 1554,
    S4_andi_lsr_ri	= 1555,
    S4_clbaddi	= 1556,
    S4_clbpaddi	= 1557,
    S4_clbpnorm	= 1558,
    S4_extract	= 1559,
    S4_extract_rp	= 1560,
    S4_extractp	= 1561,
    S4_extractp_rp	= 1562,
    S4_lsli	= 1563,
    S4_ntstbit_i	= 1564,
    S4_ntstbit_r	= 1565,
    S4_or_andi	= 1566,
    S4_or_andix	= 1567,
    S4_or_ori	= 1568,
    S4_ori_asl_ri	= 1569,
    S4_ori_lsr_ri	= 1570,
    S4_parity	= 1571,
    S4_pstorerbf_abs	= 1572,
    S4_pstorerbf_rr	= 1573,
    S4_pstorerbfnew_abs	= 1574,
    S4_pstorerbfnew_io	= 1575,
    S4_pstorerbfnew_rr	= 1576,
    S4_pstorerbnewf_abs	= 1577,
    S4_pstorerbnewf_rr	= 1578,
    S4_pstorerbnewfnew_abs	= 1579,
    S4_pstorerbnewfnew_io	= 1580,
    S4_pstorerbnewfnew_rr	= 1581,
    S4_pstorerbnewt_abs	= 1582,
    S4_pstorerbnewt_rr	= 1583,
    S4_pstorerbnewtnew_abs	= 1584,
    S4_pstorerbnewtnew_io	= 1585,
    S4_pstorerbnewtnew_rr	= 1586,
    S4_pstorerbt_abs	= 1587,
    S4_pstorerbt_rr	= 1588,
    S4_pstorerbtnew_abs	= 1589,
    S4_pstorerbtnew_io	= 1590,
    S4_pstorerbtnew_rr	= 1591,
    S4_pstorerdf_abs	= 1592,
    S4_pstorerdf_rr	= 1593,
    S4_pstorerdfnew_abs	= 1594,
    S4_pstorerdfnew_io	= 1595,
    S4_pstorerdfnew_rr	= 1596,
    S4_pstorerdt_abs	= 1597,
    S4_pstorerdt_rr	= 1598,
    S4_pstorerdtnew_abs	= 1599,
    S4_pstorerdtnew_io	= 1600,
    S4_pstorerdtnew_rr	= 1601,
    S4_pstorerff_abs	= 1602,
    S4_pstorerff_rr	= 1603,
    S4_pstorerffnew_abs	= 1604,
    S4_pstorerffnew_io	= 1605,
    S4_pstorerffnew_rr	= 1606,
    S4_pstorerft_abs	= 1607,
    S4_pstorerft_rr	= 1608,
    S4_pstorerftnew_abs	= 1609,
    S4_pstorerftnew_io	= 1610,
    S4_pstorerftnew_rr	= 1611,
    S4_pstorerhf_abs	= 1612,
    S4_pstorerhf_rr	= 1613,
    S4_pstorerhfnew_abs	= 1614,
    S4_pstorerhfnew_io	= 1615,
    S4_pstorerhfnew_rr	= 1616,
    S4_pstorerhnewf_abs	= 1617,
    S4_pstorerhnewf_rr	= 1618,
    S4_pstorerhnewfnew_abs	= 1619,
    S4_pstorerhnewfnew_io	= 1620,
    S4_pstorerhnewfnew_rr	= 1621,
    S4_pstorerhnewt_abs	= 1622,
    S4_pstorerhnewt_rr	= 1623,
    S4_pstorerhnewtnew_abs	= 1624,
    S4_pstorerhnewtnew_io	= 1625,
    S4_pstorerhnewtnew_rr	= 1626,
    S4_pstorerht_abs	= 1627,
    S4_pstorerht_rr	= 1628,
    S4_pstorerhtnew_abs	= 1629,
    S4_pstorerhtnew_io	= 1630,
    S4_pstorerhtnew_rr	= 1631,
    S4_pstorerif_abs	= 1632,
    S4_pstorerif_rr	= 1633,
    S4_pstorerifnew_abs	= 1634,
    S4_pstorerifnew_io	= 1635,
    S4_pstorerifnew_rr	= 1636,
    S4_pstorerinewf_abs	= 1637,
    S4_pstorerinewf_rr	= 1638,
    S4_pstorerinewfnew_abs	= 1639,
    S4_pstorerinewfnew_io	= 1640,
    S4_pstorerinewfnew_rr	= 1641,
    S4_pstorerinewt_abs	= 1642,
    S4_pstorerinewt_rr	= 1643,
    S4_pstorerinewtnew_abs	= 1644,
    S4_pstorerinewtnew_io	= 1645,
    S4_pstorerinewtnew_rr	= 1646,
    S4_pstorerit_abs	= 1647,
    S4_pstorerit_rr	= 1648,
    S4_pstoreritnew_abs	= 1649,
    S4_pstoreritnew_io	= 1650,
    S4_pstoreritnew_rr	= 1651,
    S4_stored_locked	= 1652,
    S4_storeirb_io	= 1653,
    S4_storeirbf_io	= 1654,
    S4_storeirbfnew_io	= 1655,
    S4_storeirbt_io	= 1656,
    S4_storeirbtnew_io	= 1657,
    S4_storeirh_io	= 1658,
    S4_storeirhf_io	= 1659,
    S4_storeirhfnew_io	= 1660,
    S4_storeirht_io	= 1661,
    S4_storeirhtnew_io	= 1662,
    S4_storeiri_io	= 1663,
    S4_storeirif_io	= 1664,
    S4_storeirifnew_io	= 1665,
    S4_storeirit_io	= 1666,
    S4_storeiritnew_io	= 1667,
    S4_storerb_ap	= 1668,
    S4_storerb_rr	= 1669,
    S4_storerb_ur	= 1670,
    S4_storerbnew_ap	= 1671,
    S4_storerbnew_rr	= 1672,
    S4_storerbnew_ur	= 1673,
    S4_storerd_ap	= 1674,
    S4_storerd_rr	= 1675,
    S4_storerd_ur	= 1676,
    S4_storerf_ap	= 1677,
    S4_storerf_rr	= 1678,
    S4_storerf_ur	= 1679,
    S4_storerh_ap	= 1680,
    S4_storerh_rr	= 1681,
    S4_storerh_ur	= 1682,
    S4_storerhnew_ap	= 1683,
    S4_storerhnew_rr	= 1684,
    S4_storerhnew_ur	= 1685,
    S4_storeri_ap	= 1686,
    S4_storeri_rr	= 1687,
    S4_storeri_ur	= 1688,
    S4_storerinew_ap	= 1689,
    S4_storerinew_rr	= 1690,
    S4_storerinew_ur	= 1691,
    S4_subaddi	= 1692,
    S4_subi_asl_ri	= 1693,
    S4_subi_lsr_ri	= 1694,
    S4_vrcrotate	= 1695,
    S4_vrcrotate_acc	= 1696,
    S4_vxaddsubh	= 1697,
    S4_vxaddsubhr	= 1698,
    S4_vxaddsubw	= 1699,
    S4_vxsubaddh	= 1700,
    S4_vxsubaddhr	= 1701,
    S4_vxsubaddw	= 1702,
    S5_asrhub_rnd_sat	= 1703,
    S5_asrhub_rnd_sat_goodsyntax	= 1704,
    S5_asrhub_sat	= 1705,
    S5_popcountp	= 1706,
    S5_vasrhrnd	= 1707,
    S5_vasrhrnd_goodsyntax	= 1708,
    S6_rol_i_p	= 1709,
    S6_rol_i_p_acc	= 1710,
    S6_rol_i_p_and	= 1711,
    S6_rol_i_p_nac	= 1712,
    S6_rol_i_p_or	= 1713,
    S6_rol_i_p_xacc	= 1714,
    S6_rol_i_r	= 1715,
    S6_rol_i_r_acc	= 1716,
    S6_rol_i_r_and	= 1717,
    S6_rol_i_r_nac	= 1718,
    S6_rol_i_r_or	= 1719,
    S6_rol_i_r_xacc	= 1720,
    SAVE_REGISTERS_CALL_V4	= 1721,
    SAVE_REGISTERS_CALL_V4_EXT	= 1722,
    STriq_pred_V6	= 1723,
    STriq_pred_V6_128B	= 1724,
    STriq_pred_vec_V6	= 1725,
    STriq_pred_vec_V6_128B	= 1726,
    STriv_pseudo_V6	= 1727,
    STriv_pseudo_V6_128B	= 1728,
    STrivv_indexed	= 1729,
    STrivv_indexed_128B	= 1730,
    STrivv_pseudo_V6	= 1731,
    STrivv_pseudo_V6_128B	= 1732,
    STriw_mod	= 1733,
    STriw_pred	= 1734,
    TCRETURNi	= 1735,
    TCRETURNr	= 1736,
    TFRI64_V2_ext	= 1737,
    TFRI64_V4	= 1738,
    TFRI_cNotPt_f	= 1739,
    TFRI_cPt_f	= 1740,
    TFRI_f	= 1741,
    TFR_FI	= 1742,
    TFR_FIA	= 1743,
    TFR_PdFalse	= 1744,
    TFR_PdTrue	= 1745,
    V4_SA1_addi	= 1746,
    V4_SA1_addrx	= 1747,
    V4_SA1_addsp	= 1748,
    V4_SA1_and1	= 1749,
    V4_SA1_clrf	= 1750,
    V4_SA1_clrfnew	= 1751,
    V4_SA1_clrt	= 1752,
    V4_SA1_clrtnew	= 1753,
    V4_SA1_cmpeqi	= 1754,
    V4_SA1_combine0i	= 1755,
    V4_SA1_combine1i	= 1756,
    V4_SA1_combine2i	= 1757,
    V4_SA1_combine3i	= 1758,
    V4_SA1_combinerz	= 1759,
    V4_SA1_combinezr	= 1760,
    V4_SA1_dec	= 1761,
    V4_SA1_inc	= 1762,
    V4_SA1_seti	= 1763,
    V4_SA1_setin1	= 1764,
    V4_SA1_sxtb	= 1765,
    V4_SA1_sxth	= 1766,
    V4_SA1_tfr	= 1767,
    V4_SA1_zxtb	= 1768,
    V4_SA1_zxth	= 1769,
    V4_SL1_loadri_io	= 1770,
    V4_SL1_loadrub_io	= 1771,
    V4_SL2_deallocframe	= 1772,
    V4_SL2_jumpr31	= 1773,
    V4_SL2_jumpr31_f	= 1774,
    V4_SL2_jumpr31_fnew	= 1775,
    V4_SL2_jumpr31_t	= 1776,
    V4_SL2_jumpr31_tnew	= 1777,
    V4_SL2_loadrb_io	= 1778,
    V4_SL2_loadrd_sp	= 1779,
    V4_SL2_loadrh_io	= 1780,
    V4_SL2_loadri_sp	= 1781,
    V4_SL2_loadruh_io	= 1782,
    V4_SL2_return	= 1783,
    V4_SL2_return_f	= 1784,
    V4_SL2_return_fnew	= 1785,
    V4_SL2_return_t	= 1786,
    V4_SL2_return_tnew	= 1787,
    V4_SS1_storeb_io	= 1788,
    V4_SS1_storew_io	= 1789,
    V4_SS2_allocframe	= 1790,
    V4_SS2_storebi0	= 1791,
    V4_SS2_storebi1	= 1792,
    V4_SS2_stored_sp	= 1793,
    V4_SS2_storeh_io	= 1794,
    V4_SS2_storew_sp	= 1795,
    V4_SS2_storewi0	= 1796,
    V4_SS2_storewi1	= 1797,
    V6_extractw	= 1798,
    V6_extractw_128B	= 1799,
    V6_lvsplatw	= 1800,
    V6_lvsplatw_128B	= 1801,
    V6_pred_and	= 1802,
    V6_pred_and_128B	= 1803,
    V6_pred_and_n	= 1804,
    V6_pred_and_n_128B	= 1805,
    V6_pred_not	= 1806,
    V6_pred_not_128B	= 1807,
    V6_pred_or	= 1808,
    V6_pred_or_128B	= 1809,
    V6_pred_or_n	= 1810,
    V6_pred_or_n_128B	= 1811,
    V6_pred_scalar2	= 1812,
    V6_pred_scalar2_128B	= 1813,
    V6_pred_xor	= 1814,
    V6_pred_xor_128B	= 1815,
    V6_vL32Ub_ai	= 1816,
    V6_vL32Ub_ai_128B	= 1817,
    V6_vL32Ub_pi	= 1818,
    V6_vL32Ub_pi_128B	= 1819,
    V6_vL32Ub_ppu	= 1820,
    V6_vL32b_ai	= 1821,
    V6_vL32b_ai_128B	= 1822,
    V6_vL32b_cur_ai	= 1823,
    V6_vL32b_cur_ai_128B	= 1824,
    V6_vL32b_cur_pi	= 1825,
    V6_vL32b_cur_pi_128B	= 1826,
    V6_vL32b_cur_ppu	= 1827,
    V6_vL32b_nt_ai	= 1828,
    V6_vL32b_nt_ai_128B	= 1829,
    V6_vL32b_nt_cur_ai	= 1830,
    V6_vL32b_nt_cur_ai_128B	= 1831,
    V6_vL32b_nt_cur_pi	= 1832,
    V6_vL32b_nt_cur_pi_128B	= 1833,
    V6_vL32b_nt_cur_ppu	= 1834,
    V6_vL32b_nt_pi	= 1835,
    V6_vL32b_nt_pi_128B	= 1836,
    V6_vL32b_nt_ppu	= 1837,
    V6_vL32b_nt_tmp_ai	= 1838,
    V6_vL32b_nt_tmp_ai_128B	= 1839,
    V6_vL32b_nt_tmp_pi	= 1840,
    V6_vL32b_nt_tmp_pi_128B	= 1841,
    V6_vL32b_nt_tmp_ppu	= 1842,
    V6_vL32b_pi	= 1843,
    V6_vL32b_pi_128B	= 1844,
    V6_vL32b_ppu	= 1845,
    V6_vL32b_tmp_ai	= 1846,
    V6_vL32b_tmp_ai_128B	= 1847,
    V6_vL32b_tmp_pi	= 1848,
    V6_vL32b_tmp_pi_128B	= 1849,
    V6_vL32b_tmp_ppu	= 1850,
    V6_vS32Ub_ai	= 1851,
    V6_vS32Ub_ai_128B	= 1852,
    V6_vS32Ub_npred_ai	= 1853,
    V6_vS32Ub_npred_ai_128B	= 1854,
    V6_vS32Ub_npred_pi	= 1855,
    V6_vS32Ub_npred_pi_128B	= 1856,
    V6_vS32Ub_npred_ppu	= 1857,
    V6_vS32Ub_pi	= 1858,
    V6_vS32Ub_pi_128B	= 1859,
    V6_vS32Ub_ppu	= 1860,
    V6_vS32Ub_pred_ai	= 1861,
    V6_vS32Ub_pred_ai_128B	= 1862,
    V6_vS32Ub_pred_pi	= 1863,
    V6_vS32Ub_pred_pi_128B	= 1864,
    V6_vS32Ub_pred_ppu	= 1865,
    V6_vS32b_ai	= 1866,
    V6_vS32b_ai_128B	= 1867,
    V6_vS32b_new_ai	= 1868,
    V6_vS32b_new_ai_128B	= 1869,
    V6_vS32b_new_npred_ai	= 1870,
    V6_vS32b_new_npred_ai_128B	= 1871,
    V6_vS32b_new_npred_pi	= 1872,
    V6_vS32b_new_npred_pi_128B	= 1873,
    V6_vS32b_new_npred_ppu	= 1874,
    V6_vS32b_new_pi	= 1875,
    V6_vS32b_new_pi_128B	= 1876,
    V6_vS32b_new_ppu	= 1877,
    V6_vS32b_new_pred_ai	= 1878,
    V6_vS32b_new_pred_ai_128B	= 1879,
    V6_vS32b_new_pred_pi	= 1880,
    V6_vS32b_new_pred_pi_128B	= 1881,
    V6_vS32b_new_pred_ppu	= 1882,
    V6_vS32b_npred_ai	= 1883,
    V6_vS32b_npred_ai_128B	= 1884,
    V6_vS32b_npred_pi	= 1885,
    V6_vS32b_npred_pi_128B	= 1886,
    V6_vS32b_npred_ppu	= 1887,
    V6_vS32b_nqpred_ai	= 1888,
    V6_vS32b_nqpred_ai_128B	= 1889,
    V6_vS32b_nqpred_pi	= 1890,
    V6_vS32b_nqpred_pi_128B	= 1891,
    V6_vS32b_nqpred_ppu	= 1892,
    V6_vS32b_nt_ai	= 1893,
    V6_vS32b_nt_ai_128B	= 1894,
    V6_vS32b_nt_new_ai	= 1895,
    V6_vS32b_nt_new_ai_128B	= 1896,
    V6_vS32b_nt_new_npred_ai	= 1897,
    V6_vS32b_nt_new_npred_ai_128B	= 1898,
    V6_vS32b_nt_new_npred_pi	= 1899,
    V6_vS32b_nt_new_npred_pi_128B	= 1900,
    V6_vS32b_nt_new_npred_ppu	= 1901,
    V6_vS32b_nt_new_pi	= 1902,
    V6_vS32b_nt_new_pi_128B	= 1903,
    V6_vS32b_nt_new_ppu	= 1904,
    V6_vS32b_nt_new_pred_ai	= 1905,
    V6_vS32b_nt_new_pred_ai_128B	= 1906,
    V6_vS32b_nt_new_pred_pi	= 1907,
    V6_vS32b_nt_new_pred_pi_128B	= 1908,
    V6_vS32b_nt_new_pred_ppu	= 1909,
    V6_vS32b_nt_npred_ai	= 1910,
    V6_vS32b_nt_npred_ai_128B	= 1911,
    V6_vS32b_nt_npred_pi	= 1912,
    V6_vS32b_nt_npred_pi_128B	= 1913,
    V6_vS32b_nt_npred_ppu	= 1914,
    V6_vS32b_nt_nqpred_ai	= 1915,
    V6_vS32b_nt_nqpred_ai_128B	= 1916,
    V6_vS32b_nt_nqpred_pi	= 1917,
    V6_vS32b_nt_nqpred_pi_128B	= 1918,
    V6_vS32b_nt_nqpred_ppu	= 1919,
    V6_vS32b_nt_pi	= 1920,
    V6_vS32b_nt_pi_128B	= 1921,
    V6_vS32b_nt_ppu	= 1922,
    V6_vS32b_nt_pred_ai	= 1923,
    V6_vS32b_nt_pred_ai_128B	= 1924,
    V6_vS32b_nt_pred_pi	= 1925,
    V6_vS32b_nt_pred_pi_128B	= 1926,
    V6_vS32b_nt_pred_ppu	= 1927,
    V6_vS32b_nt_qpred_ai	= 1928,
    V6_vS32b_nt_qpred_ai_128B	= 1929,
    V6_vS32b_nt_qpred_pi	= 1930,
    V6_vS32b_nt_qpred_pi_128B	= 1931,
    V6_vS32b_nt_qpred_ppu	= 1932,
    V6_vS32b_pi	= 1933,
    V6_vS32b_pi_128B	= 1934,
    V6_vS32b_ppu	= 1935,
    V6_vS32b_pred_ai	= 1936,
    V6_vS32b_pred_ai_128B	= 1937,
    V6_vS32b_pred_pi	= 1938,
    V6_vS32b_pred_pi_128B	= 1939,
    V6_vS32b_pred_ppu	= 1940,
    V6_vS32b_qpred_ai	= 1941,
    V6_vS32b_qpred_ai_128B	= 1942,
    V6_vS32b_qpred_pi	= 1943,
    V6_vS32b_qpred_pi_128B	= 1944,
    V6_vS32b_qpred_ppu	= 1945,
    V6_vabsdiffh	= 1946,
    V6_vabsdiffh_128B	= 1947,
    V6_vabsdiffub	= 1948,
    V6_vabsdiffub_128B	= 1949,
    V6_vabsdiffuh	= 1950,
    V6_vabsdiffuh_128B	= 1951,
    V6_vabsdiffw	= 1952,
    V6_vabsdiffw_128B	= 1953,
    V6_vabsh	= 1954,
    V6_vabsh_128B	= 1955,
    V6_vabsh_sat	= 1956,
    V6_vabsh_sat_128B	= 1957,
    V6_vabsw	= 1958,
    V6_vabsw_128B	= 1959,
    V6_vabsw_sat	= 1960,
    V6_vabsw_sat_128B	= 1961,
    V6_vaddb	= 1962,
    V6_vaddb_128B	= 1963,
    V6_vaddb_dv	= 1964,
    V6_vaddb_dv_128B	= 1965,
    V6_vaddbnq	= 1966,
    V6_vaddbnq_128B	= 1967,
    V6_vaddbq	= 1968,
    V6_vaddbq_128B	= 1969,
    V6_vaddh	= 1970,
    V6_vaddh_128B	= 1971,
    V6_vaddh_dv	= 1972,
    V6_vaddh_dv_128B	= 1973,
    V6_vaddhnq	= 1974,
    V6_vaddhnq_128B	= 1975,
    V6_vaddhq	= 1976,
    V6_vaddhq_128B	= 1977,
    V6_vaddhsat	= 1978,
    V6_vaddhsat_128B	= 1979,
    V6_vaddhsat_dv	= 1980,
    V6_vaddhsat_dv_128B	= 1981,
    V6_vaddhw	= 1982,
    V6_vaddhw_128B	= 1983,
    V6_vaddubh	= 1984,
    V6_vaddubh_128B	= 1985,
    V6_vaddubsat	= 1986,
    V6_vaddubsat_128B	= 1987,
    V6_vaddubsat_dv	= 1988,
    V6_vaddubsat_dv_128B	= 1989,
    V6_vadduhsat	= 1990,
    V6_vadduhsat_128B	= 1991,
    V6_vadduhsat_dv	= 1992,
    V6_vadduhsat_dv_128B	= 1993,
    V6_vadduhw	= 1994,
    V6_vadduhw_128B	= 1995,
    V6_vaddw	= 1996,
    V6_vaddw_128B	= 1997,
    V6_vaddw_dv	= 1998,
    V6_vaddw_dv_128B	= 1999,
    V6_vaddwnq	= 2000,
    V6_vaddwnq_128B	= 2001,
    V6_vaddwq	= 2002,
    V6_vaddwq_128B	= 2003,
    V6_vaddwsat	= 2004,
    V6_vaddwsat_128B	= 2005,
    V6_vaddwsat_dv	= 2006,
    V6_vaddwsat_dv_128B	= 2007,
    V6_valignb	= 2008,
    V6_valignb_128B	= 2009,
    V6_valignbi	= 2010,
    V6_valignbi_128B	= 2011,
    V6_vand	= 2012,
    V6_vand_128B	= 2013,
    V6_vandqrt	= 2014,
    V6_vandqrt_128B	= 2015,
    V6_vandqrt_acc	= 2016,
    V6_vandqrt_acc_128B	= 2017,
    V6_vandvrt	= 2018,
    V6_vandvrt_128B	= 2019,
    V6_vandvrt_acc	= 2020,
    V6_vandvrt_acc_128B	= 2021,
    V6_vaslh	= 2022,
    V6_vaslh_128B	= 2023,
    V6_vaslhv	= 2024,
    V6_vaslhv_128B	= 2025,
    V6_vaslw	= 2026,
    V6_vaslw_128B	= 2027,
    V6_vaslw_acc	= 2028,
    V6_vaslw_acc_128B	= 2029,
    V6_vaslwv	= 2030,
    V6_vaslwv_128B	= 2031,
    V6_vasrh	= 2032,
    V6_vasrh_128B	= 2033,
    V6_vasrhbrndsat	= 2034,
    V6_vasrhbrndsat_128B	= 2035,
    V6_vasrhubrndsat	= 2036,
    V6_vasrhubrndsat_128B	= 2037,
    V6_vasrhubsat	= 2038,
    V6_vasrhubsat_128B	= 2039,
    V6_vasrhv	= 2040,
    V6_vasrhv_128B	= 2041,
    V6_vasrw	= 2042,
    V6_vasrw_128B	= 2043,
    V6_vasrw_acc	= 2044,
    V6_vasrw_acc_128B	= 2045,
    V6_vasrwh	= 2046,
    V6_vasrwh_128B	= 2047,
    V6_vasrwhrndsat	= 2048,
    V6_vasrwhrndsat_128B	= 2049,
    V6_vasrwhsat	= 2050,
    V6_vasrwhsat_128B	= 2051,
    V6_vasrwuhsat	= 2052,
    V6_vasrwuhsat_128B	= 2053,
    V6_vasrwv	= 2054,
    V6_vasrwv_128B	= 2055,
    V6_vassign	= 2056,
    V6_vassign_128B	= 2057,
    V6_vavgh	= 2058,
    V6_vavgh_128B	= 2059,
    V6_vavghrnd	= 2060,
    V6_vavghrnd_128B	= 2061,
    V6_vavgub	= 2062,
    V6_vavgub_128B	= 2063,
    V6_vavgubrnd	= 2064,
    V6_vavgubrnd_128B	= 2065,
    V6_vavguh	= 2066,
    V6_vavguh_128B	= 2067,
    V6_vavguhrnd	= 2068,
    V6_vavguhrnd_128B	= 2069,
    V6_vavgw	= 2070,
    V6_vavgw_128B	= 2071,
    V6_vavgwrnd	= 2072,
    V6_vavgwrnd_128B	= 2073,
    V6_vccombine	= 2074,
    V6_vccombine_128B	= 2075,
    V6_vcl0h	= 2076,
    V6_vcl0h_128B	= 2077,
    V6_vcl0w	= 2078,
    V6_vcl0w_128B	= 2079,
    V6_vcmov	= 2080,
    V6_vcmov_128B	= 2081,
    V6_vcombine	= 2082,
    V6_vcombine_128B	= 2083,
    V6_vdeal	= 2084,
    V6_vdeal_128B	= 2085,
    V6_vdealb	= 2086,
    V6_vdealb4w	= 2087,
    V6_vdealb4w_128B	= 2088,
    V6_vdealb_128B	= 2089,
    V6_vdealh	= 2090,
    V6_vdealh_128B	= 2091,
    V6_vdealvdd	= 2092,
    V6_vdealvdd_128B	= 2093,
    V6_vdelta	= 2094,
    V6_vdelta_128B	= 2095,
    V6_vdmpybus	= 2096,
    V6_vdmpybus_128B	= 2097,
    V6_vdmpybus_acc	= 2098,
    V6_vdmpybus_acc_128B	= 2099,
    V6_vdmpybus_dv	= 2100,
    V6_vdmpybus_dv_128B	= 2101,
    V6_vdmpybus_dv_acc	= 2102,
    V6_vdmpybus_dv_acc_128B	= 2103,
    V6_vdmpyhb	= 2104,
    V6_vdmpyhb_128B	= 2105,
    V6_vdmpyhb_acc	= 2106,
    V6_vdmpyhb_acc_128B	= 2107,
    V6_vdmpyhb_dv	= 2108,
    V6_vdmpyhb_dv_128B	= 2109,
    V6_vdmpyhb_dv_acc	= 2110,
    V6_vdmpyhb_dv_acc_128B	= 2111,
    V6_vdmpyhisat	= 2112,
    V6_vdmpyhisat_128B	= 2113,
    V6_vdmpyhisat_acc	= 2114,
    V6_vdmpyhisat_acc_128B	= 2115,
    V6_vdmpyhsat	= 2116,
    V6_vdmpyhsat_128B	= 2117,
    V6_vdmpyhsat_acc	= 2118,
    V6_vdmpyhsat_acc_128B	= 2119,
    V6_vdmpyhsuisat	= 2120,
    V6_vdmpyhsuisat_128B	= 2121,
    V6_vdmpyhsuisat_acc	= 2122,
    V6_vdmpyhsuisat_acc_128B	= 2123,
    V6_vdmpyhsusat	= 2124,
    V6_vdmpyhsusat_128B	= 2125,
    V6_vdmpyhsusat_acc	= 2126,
    V6_vdmpyhsusat_acc_128B	= 2127,
    V6_vdmpyhvsat	= 2128,
    V6_vdmpyhvsat_128B	= 2129,
    V6_vdmpyhvsat_acc	= 2130,
    V6_vdmpyhvsat_acc_128B	= 2131,
    V6_vdsaduh	= 2132,
    V6_vdsaduh_128B	= 2133,
    V6_vdsaduh_acc	= 2134,
    V6_vdsaduh_acc_128B	= 2135,
    V6_veqb	= 2136,
    V6_veqb_128B	= 2137,
    V6_veqb_and	= 2138,
    V6_veqb_and_128B	= 2139,
    V6_veqb_or	= 2140,
    V6_veqb_or_128B	= 2141,
    V6_veqb_xor	= 2142,
    V6_veqb_xor_128B	= 2143,
    V6_veqh	= 2144,
    V6_veqh_128B	= 2145,
    V6_veqh_and	= 2146,
    V6_veqh_and_128B	= 2147,
    V6_veqh_or	= 2148,
    V6_veqh_or_128B	= 2149,
    V6_veqh_xor	= 2150,
    V6_veqh_xor_128B	= 2151,
    V6_veqw	= 2152,
    V6_veqw_128B	= 2153,
    V6_veqw_and	= 2154,
    V6_veqw_and_128B	= 2155,
    V6_veqw_or	= 2156,
    V6_veqw_or_128B	= 2157,
    V6_veqw_xor	= 2158,
    V6_veqw_xor_128B	= 2159,
    V6_vgtb	= 2160,
    V6_vgtb_128B	= 2161,
    V6_vgtb_and	= 2162,
    V6_vgtb_and_128B	= 2163,
    V6_vgtb_or	= 2164,
    V6_vgtb_or_128B	= 2165,
    V6_vgtb_xor	= 2166,
    V6_vgtb_xor_128B	= 2167,
    V6_vgth	= 2168,
    V6_vgth_128B	= 2169,
    V6_vgth_and	= 2170,
    V6_vgth_and_128B	= 2171,
    V6_vgth_or	= 2172,
    V6_vgth_or_128B	= 2173,
    V6_vgth_xor	= 2174,
    V6_vgth_xor_128B	= 2175,
    V6_vgtub	= 2176,
    V6_vgtub_128B	= 2177,
    V6_vgtub_and	= 2178,
    V6_vgtub_and_128B	= 2179,
    V6_vgtub_or	= 2180,
    V6_vgtub_or_128B	= 2181,
    V6_vgtub_xor	= 2182,
    V6_vgtub_xor_128B	= 2183,
    V6_vgtuh	= 2184,
    V6_vgtuh_128B	= 2185,
    V6_vgtuh_and	= 2186,
    V6_vgtuh_and_128B	= 2187,
    V6_vgtuh_or	= 2188,
    V6_vgtuh_or_128B	= 2189,
    V6_vgtuh_xor	= 2190,
    V6_vgtuh_xor_128B	= 2191,
    V6_vgtuw	= 2192,
    V6_vgtuw_128B	= 2193,
    V6_vgtuw_and	= 2194,
    V6_vgtuw_and_128B	= 2195,
    V6_vgtuw_or	= 2196,
    V6_vgtuw_or_128B	= 2197,
    V6_vgtuw_xor	= 2198,
    V6_vgtuw_xor_128B	= 2199,
    V6_vgtw	= 2200,
    V6_vgtw_128B	= 2201,
    V6_vgtw_and	= 2202,
    V6_vgtw_and_128B	= 2203,
    V6_vgtw_or	= 2204,
    V6_vgtw_or_128B	= 2205,
    V6_vgtw_xor	= 2206,
    V6_vgtw_xor_128B	= 2207,
    V6_vhist	= 2208,
    V6_vhistq	= 2209,
    V6_vinsertwr	= 2210,
    V6_vinsertwr_128B	= 2211,
    V6_vlalignb	= 2212,
    V6_vlalignb_128B	= 2213,
    V6_vlalignbi	= 2214,
    V6_vlalignbi_128B	= 2215,
    V6_vlsrh	= 2216,
    V6_vlsrh_128B	= 2217,
    V6_vlsrhv	= 2218,
    V6_vlsrhv_128B	= 2219,
    V6_vlsrw	= 2220,
    V6_vlsrw_128B	= 2221,
    V6_vlsrwv	= 2222,
    V6_vlsrwv_128B	= 2223,
    V6_vlutvvb	= 2224,
    V6_vlutvvb_128B	= 2225,
    V6_vlutvvb_oracc	= 2226,
    V6_vlutvvb_oracc_128B	= 2227,
    V6_vlutvwh	= 2228,
    V6_vlutvwh_128B	= 2229,
    V6_vlutvwh_oracc	= 2230,
    V6_vlutvwh_oracc_128B	= 2231,
    V6_vmaxh	= 2232,
    V6_vmaxh_128B	= 2233,
    V6_vmaxub	= 2234,
    V6_vmaxub_128B	= 2235,
    V6_vmaxuh	= 2236,
    V6_vmaxuh_128B	= 2237,
    V6_vmaxw	= 2238,
    V6_vmaxw_128B	= 2239,
    V6_vminh	= 2240,
    V6_vminh_128B	= 2241,
    V6_vminub	= 2242,
    V6_vminub_128B	= 2243,
    V6_vminuh	= 2244,
    V6_vminuh_128B	= 2245,
    V6_vminw	= 2246,
    V6_vminw_128B	= 2247,
    V6_vmpabus	= 2248,
    V6_vmpabus_128B	= 2249,
    V6_vmpabus_acc	= 2250,
    V6_vmpabus_acc_128B	= 2251,
    V6_vmpabusv	= 2252,
    V6_vmpabusv_128B	= 2253,
    V6_vmpabuuv	= 2254,
    V6_vmpabuuv_128B	= 2255,
    V6_vmpahb	= 2256,
    V6_vmpahb_128B	= 2257,
    V6_vmpahb_acc	= 2258,
    V6_vmpahb_acc_128B	= 2259,
    V6_vmpybus	= 2260,
    V6_vmpybus_128B	= 2261,
    V6_vmpybus_acc	= 2262,
    V6_vmpybus_acc_128B	= 2263,
    V6_vmpybusv	= 2264,
    V6_vmpybusv_128B	= 2265,
    V6_vmpybusv_acc	= 2266,
    V6_vmpybusv_acc_128B	= 2267,
    V6_vmpybv	= 2268,
    V6_vmpybv_128B	= 2269,
    V6_vmpybv_acc	= 2270,
    V6_vmpybv_acc_128B	= 2271,
    V6_vmpyewuh	= 2272,
    V6_vmpyewuh_128B	= 2273,
    V6_vmpyh	= 2274,
    V6_vmpyh_128B	= 2275,
    V6_vmpyhsat_acc	= 2276,
    V6_vmpyhsat_acc_128B	= 2277,
    V6_vmpyhsrs	= 2278,
    V6_vmpyhsrs_128B	= 2279,
    V6_vmpyhss	= 2280,
    V6_vmpyhss_128B	= 2281,
    V6_vmpyhus	= 2282,
    V6_vmpyhus_128B	= 2283,
    V6_vmpyhus_acc	= 2284,
    V6_vmpyhus_acc_128B	= 2285,
    V6_vmpyhv	= 2286,
    V6_vmpyhv_128B	= 2287,
    V6_vmpyhv_acc	= 2288,
    V6_vmpyhv_acc_128B	= 2289,
    V6_vmpyhvsrs	= 2290,
    V6_vmpyhvsrs_128B	= 2291,
    V6_vmpyieoh	= 2292,
    V6_vmpyieoh_128B	= 2293,
    V6_vmpyiewh_acc	= 2294,
    V6_vmpyiewh_acc_128B	= 2295,
    V6_vmpyiewuh	= 2296,
    V6_vmpyiewuh_128B	= 2297,
    V6_vmpyiewuh_acc	= 2298,
    V6_vmpyiewuh_acc_128B	= 2299,
    V6_vmpyih	= 2300,
    V6_vmpyih_128B	= 2301,
    V6_vmpyih_acc	= 2302,
    V6_vmpyih_acc_128B	= 2303,
    V6_vmpyihb	= 2304,
    V6_vmpyihb_128B	= 2305,
    V6_vmpyihb_acc	= 2306,
    V6_vmpyihb_acc_128B	= 2307,
    V6_vmpyiowh	= 2308,
    V6_vmpyiowh_128B	= 2309,
    V6_vmpyiwb	= 2310,
    V6_vmpyiwb_128B	= 2311,
    V6_vmpyiwb_acc	= 2312,
    V6_vmpyiwb_acc_128B	= 2313,
    V6_vmpyiwh	= 2314,
    V6_vmpyiwh_128B	= 2315,
    V6_vmpyiwh_acc	= 2316,
    V6_vmpyiwh_acc_128B	= 2317,
    V6_vmpyowh	= 2318,
    V6_vmpyowh_128B	= 2319,
    V6_vmpyowh_rnd	= 2320,
    V6_vmpyowh_rnd_128B	= 2321,
    V6_vmpyowh_rnd_sacc	= 2322,
    V6_vmpyowh_rnd_sacc_128B	= 2323,
    V6_vmpyowh_sacc	= 2324,
    V6_vmpyowh_sacc_128B	= 2325,
    V6_vmpyub	= 2326,
    V6_vmpyub_128B	= 2327,
    V6_vmpyub_acc	= 2328,
    V6_vmpyub_acc_128B	= 2329,
    V6_vmpyubv	= 2330,
    V6_vmpyubv_128B	= 2331,
    V6_vmpyubv_acc	= 2332,
    V6_vmpyubv_acc_128B	= 2333,
    V6_vmpyuh	= 2334,
    V6_vmpyuh_128B	= 2335,
    V6_vmpyuh_acc	= 2336,
    V6_vmpyuh_acc_128B	= 2337,
    V6_vmpyuhv	= 2338,
    V6_vmpyuhv_128B	= 2339,
    V6_vmpyuhv_acc	= 2340,
    V6_vmpyuhv_acc_128B	= 2341,
    V6_vmux	= 2342,
    V6_vmux_128B	= 2343,
    V6_vnavgh	= 2344,
    V6_vnavgh_128B	= 2345,
    V6_vnavgub	= 2346,
    V6_vnavgub_128B	= 2347,
    V6_vnavgw	= 2348,
    V6_vnavgw_128B	= 2349,
    V6_vnccombine	= 2350,
    V6_vnccombine_128B	= 2351,
    V6_vncmov	= 2352,
    V6_vncmov_128B	= 2353,
    V6_vnormamth	= 2354,
    V6_vnormamth_128B	= 2355,
    V6_vnormamtw	= 2356,
    V6_vnormamtw_128B	= 2357,
    V6_vnot	= 2358,
    V6_vnot_128B	= 2359,
    V6_vor	= 2360,
    V6_vor_128B	= 2361,
    V6_vpackeb	= 2362,
    V6_vpackeb_128B	= 2363,
    V6_vpackeh	= 2364,
    V6_vpackeh_128B	= 2365,
    V6_vpackhb_sat	= 2366,
    V6_vpackhb_sat_128B	= 2367,
    V6_vpackhub_sat	= 2368,
    V6_vpackhub_sat_128B	= 2369,
    V6_vpackob	= 2370,
    V6_vpackob_128B	= 2371,
    V6_vpackoh	= 2372,
    V6_vpackoh_128B	= 2373,
    V6_vpackwh_sat	= 2374,
    V6_vpackwh_sat_128B	= 2375,
    V6_vpackwuh_sat	= 2376,
    V6_vpackwuh_sat_128B	= 2377,
    V6_vpopcounth	= 2378,
    V6_vpopcounth_128B	= 2379,
    V6_vrdelta	= 2380,
    V6_vrdelta_128B	= 2381,
    V6_vrmpybus	= 2382,
    V6_vrmpybus_128B	= 2383,
    V6_vrmpybus_acc	= 2384,
    V6_vrmpybus_acc_128B	= 2385,
    V6_vrmpybusi	= 2386,
    V6_vrmpybusi_128B	= 2387,
    V6_vrmpybusi_acc	= 2388,
    V6_vrmpybusi_acc_128B	= 2389,
    V6_vrmpybusv	= 2390,
    V6_vrmpybusv_128B	= 2391,
    V6_vrmpybusv_acc	= 2392,
    V6_vrmpybusv_acc_128B	= 2393,
    V6_vrmpybv	= 2394,
    V6_vrmpybv_128B	= 2395,
    V6_vrmpybv_acc	= 2396,
    V6_vrmpybv_acc_128B	= 2397,
    V6_vrmpyub	= 2398,
    V6_vrmpyub_128B	= 2399,
    V6_vrmpyub_acc	= 2400,
    V6_vrmpyub_acc_128B	= 2401,
    V6_vrmpyubi	= 2402,
    V6_vrmpyubi_128B	= 2403,
    V6_vrmpyubi_acc	= 2404,
    V6_vrmpyubi_acc_128B	= 2405,
    V6_vrmpyubv	= 2406,
    V6_vrmpyubv_128B	= 2407,
    V6_vrmpyubv_acc	= 2408,
    V6_vrmpyubv_acc_128B	= 2409,
    V6_vror	= 2410,
    V6_vror_128B	= 2411,
    V6_vroundhb	= 2412,
    V6_vroundhb_128B	= 2413,
    V6_vroundhub	= 2414,
    V6_vroundhub_128B	= 2415,
    V6_vroundwh	= 2416,
    V6_vroundwh_128B	= 2417,
    V6_vroundwuh	= 2418,
    V6_vroundwuh_128B	= 2419,
    V6_vrsadubi	= 2420,
    V6_vrsadubi_128B	= 2421,
    V6_vrsadubi_acc	= 2422,
    V6_vrsadubi_acc_128B	= 2423,
    V6_vsathub	= 2424,
    V6_vsathub_128B	= 2425,
    V6_vsatwh	= 2426,
    V6_vsatwh_128B	= 2427,
    V6_vsb	= 2428,
    V6_vsb_128B	= 2429,
    V6_vsh	= 2430,
    V6_vsh_128B	= 2431,
    V6_vshufeh	= 2432,
    V6_vshufeh_128B	= 2433,
    V6_vshuff	= 2434,
    V6_vshuff_128B	= 2435,
    V6_vshuffb	= 2436,
    V6_vshuffb_128B	= 2437,
    V6_vshuffeb	= 2438,
    V6_vshuffeb_128B	= 2439,
    V6_vshuffh	= 2440,
    V6_vshuffh_128B	= 2441,
    V6_vshuffob	= 2442,
    V6_vshuffob_128B	= 2443,
    V6_vshuffvdd	= 2444,
    V6_vshuffvdd_128B	= 2445,
    V6_vshufoeb	= 2446,
    V6_vshufoeb_128B	= 2447,
    V6_vshufoeh	= 2448,
    V6_vshufoeh_128B	= 2449,
    V6_vshufoh	= 2450,
    V6_vshufoh_128B	= 2451,
    V6_vsubb	= 2452,
    V6_vsubb_128B	= 2453,
    V6_vsubb_dv	= 2454,
    V6_vsubb_dv_128B	= 2455,
    V6_vsubbnq	= 2456,
    V6_vsubbnq_128B	= 2457,
    V6_vsubbq	= 2458,
    V6_vsubbq_128B	= 2459,
    V6_vsubh	= 2460,
    V6_vsubh_128B	= 2461,
    V6_vsubh_dv	= 2462,
    V6_vsubh_dv_128B	= 2463,
    V6_vsubhnq	= 2464,
    V6_vsubhnq_128B	= 2465,
    V6_vsubhq	= 2466,
    V6_vsubhq_128B	= 2467,
    V6_vsubhsat	= 2468,
    V6_vsubhsat_128B	= 2469,
    V6_vsubhsat_dv	= 2470,
    V6_vsubhsat_dv_128B	= 2471,
    V6_vsubhw	= 2472,
    V6_vsubhw_128B	= 2473,
    V6_vsububh	= 2474,
    V6_vsububh_128B	= 2475,
    V6_vsububsat	= 2476,
    V6_vsububsat_128B	= 2477,
    V6_vsububsat_dv	= 2478,
    V6_vsububsat_dv_128B	= 2479,
    V6_vsubuhsat	= 2480,
    V6_vsubuhsat_128B	= 2481,
    V6_vsubuhsat_dv	= 2482,
    V6_vsubuhsat_dv_128B	= 2483,
    V6_vsubuhw	= 2484,
    V6_vsubuhw_128B	= 2485,
    V6_vsubw	= 2486,
    V6_vsubw_128B	= 2487,
    V6_vsubw_dv	= 2488,
    V6_vsubw_dv_128B	= 2489,
    V6_vsubwnq	= 2490,
    V6_vsubwnq_128B	= 2491,
    V6_vsubwq	= 2492,
    V6_vsubwq_128B	= 2493,
    V6_vsubwsat	= 2494,
    V6_vsubwsat_128B	= 2495,
    V6_vsubwsat_dv	= 2496,
    V6_vsubwsat_dv_128B	= 2497,
    V6_vswap	= 2498,
    V6_vswap_128B	= 2499,
    V6_vtmpyb	= 2500,
    V6_vtmpyb_128B	= 2501,
    V6_vtmpyb_acc	= 2502,
    V6_vtmpyb_acc_128B	= 2503,
    V6_vtmpybus	= 2504,
    V6_vtmpybus_128B	= 2505,
    V6_vtmpybus_acc	= 2506,
    V6_vtmpybus_acc_128B	= 2507,
    V6_vtmpyhb	= 2508,
    V6_vtmpyhb_128B	= 2509,
    V6_vtmpyhb_acc	= 2510,
    V6_vtmpyhb_acc_128B	= 2511,
    V6_vunpackb	= 2512,
    V6_vunpackb_128B	= 2513,
    V6_vunpackh	= 2514,
    V6_vunpackh_128B	= 2515,
    V6_vunpackob	= 2516,
    V6_vunpackob_128B	= 2517,
    V6_vunpackoh	= 2518,
    V6_vunpackoh_128B	= 2519,
    V6_vunpackub	= 2520,
    V6_vunpackub_128B	= 2521,
    V6_vunpackuh	= 2522,
    V6_vunpackuh_128B	= 2523,
    V6_vxor	= 2524,
    V6_vxor_128B	= 2525,
    V6_vzb	= 2526,
    V6_vzb_128B	= 2527,
    V6_vzh	= 2528,
    V6_vzh_128B	= 2529,
    VMULW	= 2530,
    VMULW_ACC	= 2531,
    VSelectDblPseudo_V6	= 2532,
    VSelectPseudo_V6	= 2533,
    Y2_barrier	= 2534,
    Y2_dccleana	= 2535,
    Y2_dccleaninva	= 2536,
    Y2_dcfetchbo	= 2537,
    Y2_dcinva	= 2538,
    Y2_dczeroa	= 2539,
    Y2_icinva	= 2540,
    Y2_isync	= 2541,
    Y2_syncht	= 2542,
    Y4_l2fetch	= 2543,
    Y4_trace	= 2544,
    Y5_l2fetch	= 2545,
    Y5_l2gclean	= 2546,
    Y5_l2gcleaninv	= 2547,
    Y5_l2gunlock	= 2548,
    Y5_l2locka	= 2549,
    Y5_l2unlocka	= 2550,
    Y6_l2gcleaninvpa	= 2551,
    Y6_l2gcleanpa	= 2552,
    dep_A2_addsat	= 2553,
    dep_A2_subsat	= 2554,
    dep_S2_packhl	= 2555,
    INSTRUCTION_LIST_END = 2556
  };

namespace Sched {
  enum {
    NoInstrModel	= 0,
    S_2op_tc_2_SLOT23	= 1,
    S_2op_tc_1_SLOT23	= 2,
    ALU32_3op_tc_1_SLOT0123	= 3,
    ALU64_tc_1_SLOT23	= 4,
    ALU64_tc_2_SLOT23	= 5,
    ALU32_ADDI_tc_1_SLOT0123	= 6,
    ALU32_3op_tc_2_SLOT0123	= 7,
    ALU32_2op_tc_1_SLOT0123	= 8,
    CR_tc_3x_SLOT3	= 9,
    ALU64_tc_2early_SLOT23	= 10,
    M_tc_3x_SLOT23	= 11,
    S_3op_tc_1_SLOT23	= 12,
    S_3op_tc_2early_SLOT23	= 13,
    S_3op_tc_2_SLOT23	= 14,
    EXTENDER_tc_1_SLOT0123	= 15,
    S_3op_tc_3_SLOT23	= 16,
    M_tc_3stall_SLOT23	= 17,
    PSEUDO	= 18,
    CR_tc_2early_SLOT23	= 19,
    S_2op_tc_2early_SLOT23	= 20,
    ALU32_3op_tc_2early_SLOT0123	= 21,
    ALU32_2op_tc_2early_SLOT0123	= 22,
    CR_tc_2_SLOT3	= 23,
    J_tc_2early_SLOT2	= 24,
    J_tc_2early_SLOT23	= 25,
    LD_tc_ld_SLOT01	= 26,
    DUPLEX	= 27,
    J_tc_2early_SLOT0123	= 28,
    S_2op_tc_3or4x_SLOT23	= 29,
    ALU64_tc_3x_SLOT23	= 30,
    M_tc_3or4x_SLOT23	= 31,
    M_tc_3_SLOT23	= 32,
    CVI_VA	= 33,
    PSEUDOM	= 34,
    CR_tc_2early_SLOT3	= 35,
    NCJ_tc_3or4stall_SLOT0	= 36,
    COMPOUND	= 37,
    V2LDST_tc_ld_SLOT01	= 38,
    LD_tc_ld_SLOT0	= 39,
    V4LDST_tc_st_SLOT0	= 40,
    V4LDST_tc_ld_SLOT01	= 41,
    LD_tc_3or4stall_SLOT0	= 42,
    CVI_VM_LD	= 43,
    M_tc_2_SLOT23	= 44,
    S_3op_tc_3x_SLOT23	= 45,
    ST_tc_ld_SLOT0	= 46,
    V2LDST_tc_st_SLOT01	= 47,
    ST_tc_st_SLOT01	= 48,
    V2LDST_tc_st_SLOT0	= 49,
    ST_tc_st_SLOT0	= 50,
    V4LDST_tc_st_SLOT01	= 51,
    CVI_VM_ST	= 52,
    PREFIX	= 53,
    CVI_VX_LATE	= 54,
    CVI_VA_DV	= 55,
    CVI_VP_LONG	= 56,
    CVI_VM_VP_LDU	= 57,
    CVI_VM_CUR_LD	= 58,
    CVI_VM_TMP_LD	= 59,
    CVI_VM_STU	= 60,
    CVI_VM_NEW_ST	= 61,
    CVI_VX	= 62,
    CVI_VX_DV	= 63,
    CVI_VS	= 64,
    CVI_VP_VS_LONG_EARLY	= 65,
    CVI_VP	= 66,
    CVI_VP_VS_LONG	= 67,
    CVI_HIST	= 68,
    CVI_VX_DV_LONG	= 69,
    CVI_VX_LONG	= 70,
    CVI_VINLANESAT	= 71,
    CVI_VP_VS	= 72,
    ST_tc_3stall_SLOT0	= 73,
    SCHED_LIST_END = 74
  };
} // end Sched namespace
} // end Hexagon namespace
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

static const MCPhysReg ImplicitList1[] = { Hexagon::USR_OVF, 0 };
static const MCPhysReg ImplicitList2[] = { Hexagon::R31, Hexagon::R30, Hexagon::R29, 0 };
static const MCPhysReg ImplicitList3[] = { Hexagon::R29, Hexagon::R30, 0 };
static const MCPhysReg ImplicitList4[] = { Hexagon::R29, 0 };
static const MCPhysReg ImplicitList5[] = { Hexagon::R29, Hexagon::R30, Hexagon::R31, 0 };
static const MCPhysReg ImplicitList6[] = { Hexagon::R30, 0 };
static const MCPhysReg ImplicitList7[] = { Hexagon::PC, 0 };
static const MCPhysReg ImplicitList8[] = { Hexagon::D0, Hexagon::D1, Hexagon::D2, Hexagon::D3, Hexagon::D4, Hexagon::D5, Hexagon::D6, Hexagon::D7, Hexagon::R28, Hexagon::R31, Hexagon::P0, Hexagon::P1, Hexagon::P2, Hexagon::P3, Hexagon::M0, Hexagon::M1, Hexagon::LC0, Hexagon::LC1, Hexagon::SA0, Hexagon::SA1, Hexagon::USR, Hexagon::USR_OVF, 0 };
static const MCPhysReg ImplicitList9[] = { Hexagon::R28, 0 };
static const MCPhysReg ImplicitList10[] = { Hexagon::SA0, Hexagon::LC0, 0 };
static const MCPhysReg ImplicitList11[] = { Hexagon::PC, Hexagon::LC0, 0 };
static const MCPhysReg ImplicitList12[] = { Hexagon::SA1, Hexagon::LC1, 0 };
static const MCPhysReg ImplicitList13[] = { Hexagon::PC, Hexagon::LC1, 0 };
static const MCPhysReg ImplicitList14[] = { Hexagon::USR, 0 };
static const MCPhysReg ImplicitList15[] = { Hexagon::SA0, Hexagon::LC0, Hexagon::USR, 0 };
static const MCPhysReg ImplicitList16[] = { Hexagon::LC0, Hexagon::SA0, Hexagon::P3, Hexagon::USR, 0 };
static const MCPhysReg ImplicitList17[] = { Hexagon::P0, 0 };
static const MCPhysReg ImplicitList18[] = { Hexagon::PC, Hexagon::P0, 0 };
static const MCPhysReg ImplicitList19[] = { Hexagon::P1, 0 };
static const MCPhysReg ImplicitList20[] = { Hexagon::PC, Hexagon::P1, 0 };
static const MCPhysReg ImplicitList21[] = { Hexagon::CS, 0 };
static const MCPhysReg ImplicitList22[] = { Hexagon::GP, 0 };
static const MCPhysReg ImplicitList23[] = { Hexagon::R29, Hexagon::R30, Hexagon::R31, Hexagon::PC, 0 };
static const MCPhysReg ImplicitList24[] = { Hexagon::R29, Hexagon::R31, Hexagon::R30, 0 };
static const MCPhysReg ImplicitList25[] = { Hexagon::R29, Hexagon::R31, 0 };
static const MCPhysReg ImplicitList26[] = { Hexagon::R31, Hexagon::R29, Hexagon::R30, 0 };
static const MCPhysReg ImplicitList27[] = { Hexagon::R31, 0 };
static const MCPhysReg ImplicitList28[] = { Hexagon::P0, Hexagon::R31, 0 };
static const MCPhysReg ImplicitList29[] = { Hexagon::PC, Hexagon::R31, Hexagon::R29, Hexagon::R30, 0 };
static const MCPhysReg ImplicitList30[] = { Hexagon::R30, Hexagon::P0, 0 };
static const MCPhysReg ImplicitList31[] = { Hexagon::R30, Hexagon::R31, Hexagon::R29, 0 };

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
static const MCOperandInfo OperandInfo13[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo14[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo15[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo16[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo17[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo18[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo19[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo20[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo21[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo22[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo23[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo24[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo25[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo26[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::CtrRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo27[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo28[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo29[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo30[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo31[] = { { Hexagon::CtrRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo32[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo35[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, };
static const MCOperandInfo OperandInfo36[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::CtrRegs64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { Hexagon::CtrRegs64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo46[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo50[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo53[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo54[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo55[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo56[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo57[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo58[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo59[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo60[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo61[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo62[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo63[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo64[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo65[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo66[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo67[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo68[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo69[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo70[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo71[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo72[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo73[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo74[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo75[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo76[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo77[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo78[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo79[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo80[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo81[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo82[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo83[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo84[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo85[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo86[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo87[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo88[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo89[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo90[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo91[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo92[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo93[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo94[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo95[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo96[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo97[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo98[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo99[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo100[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo101[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo102[] = { { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo103[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo104[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo105[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo106[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo107[] = { { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo108[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo109[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo110[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo111[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo112[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo113[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo114[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo115[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo116[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo117[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo118[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo119[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo120[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo121[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo122[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo123[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo124[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo125[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo126[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo127[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo128[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo129[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo130[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo131[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo132[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo133[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo134[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo135[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo136[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo137[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo138[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo139[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo140[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo141[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo142[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo143[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo144[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo145[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo146[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo147[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo148[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo149[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo150[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo151[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo152[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo153[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo154[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo155[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo156[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo157[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo158[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo159[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo160[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo161[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo162[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo163[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo164[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo165[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo166[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo167[] = { { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo168[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo169[] = { { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo170[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo171[] = { { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo172[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo173[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo174[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo175[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo176[] = { { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo177[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo178[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo179[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo180[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo181[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo182[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo183[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo184[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo185[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo186[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo187[] = { { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::ModRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo188[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo189[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo190[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo191[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo192[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo193[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo194[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo195[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo196[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo197[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo198[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsLow8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo199[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsLow8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo200[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo201[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo202[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo203[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo204[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo205[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo206[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo207[] = { { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo208[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo209[] = { { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo210[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo211[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo212[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo213[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo214[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo215[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo216[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo217[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo218[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo219[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((1 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo220[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsLow8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo221[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsLow8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo222[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo223[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo224[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo225[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo226[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo227[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo228[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo229[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo230[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo231[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo232[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo233[] = { { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo234[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo235[] = { { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo236[] = { { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo237[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo238[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo239[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsLow8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo240[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsLow8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo241[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsLow8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo242[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsLow8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo243[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo244[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo245[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo246[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo247[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo248[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo249[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo250[] = { { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo251[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo252[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo253[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo254[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo255[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo256[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo257[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo258[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecPredRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo259[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo260[] = { { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { Hexagon::VectorRegs128BRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo261[] = { { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VecDblRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo262[] = { { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::PredRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Hexagon::VectorRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo263[] = { { Hexagon::DoubleRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };

extern const MCInstrDesc HexagonInsts[] = {
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
  { 24,	2,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #24 = A2_abs
  { 25,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #25 = A2_absp
  { 26,	2,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #26 = A2_abssat
  { 27,	3,	1,	4,	3,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #27 = A2_add
  { 28,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #28 = A2_addh_h16_hh
  { 29,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #29 = A2_addh_h16_hl
  { 30,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #30 = A2_addh_h16_lh
  { 31,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #31 = A2_addh_h16_ll
  { 32,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #32 = A2_addh_h16_sat_hh
  { 33,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #33 = A2_addh_h16_sat_hl
  { 34,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #34 = A2_addh_h16_sat_lh
  { 35,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #35 = A2_addh_h16_sat_ll
  { 36,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #36 = A2_addh_l16_hl
  { 37,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #37 = A2_addh_l16_ll
  { 38,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #38 = A2_addh_l16_sat_hl
  { 39,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #39 = A2_addh_l16_sat_ll
  { 40,	3,	1,	4,	6,	0|(1ULL<<MCID::Predicable), 0xfc85202001ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #40 = A2_addi
  { 41,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #41 = A2_addp
  { 42,	3,	1,	4,	5,	0|(1ULL<<MCID::Commutable), 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #42 = A2_addpsat
  { 43,	3,	1,	4,	7,	0|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #43 = A2_addsat
  { 44,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #44 = A2_addsp
  { 45,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #45 = A2_addsph
  { 46,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #46 = A2_addspl
  { 47,	3,	1,	4,	3,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #47 = A2_and
  { 48,	3,	1,	4,	8,	0, 0xfc55202001ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #48 = A2_andir
  { 49,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #49 = A2_andp
  { 50,	2,	1,	4,	8,	0|(1ULL<<MCID::Predicable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #50 = A2_aslh
  { 51,	2,	1,	4,	8,	0|(1ULL<<MCID::Predicable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #51 = A2_asrh
  { 52,	3,	1,	4,	3,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #52 = A2_combine_hh
  { 53,	3,	1,	4,	3,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #53 = A2_combine_hl
  { 54,	3,	1,	4,	3,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #54 = A2_combine_lh
  { 55,	3,	1,	4,	3,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #55 = A2_combine_ll
  { 56,	3,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc44a00001ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #56 = A2_combineii
  { 57,	3,	1,	4,	3,	0|(1ULL<<MCID::Predicable), 0xfc00000001ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #57 = A2_combinew
  { 58,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #58 = A2_max
  { 59,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #59 = A2_maxp
  { 60,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #60 = A2_maxu
  { 61,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #61 = A2_maxup
  { 62,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #62 = A2_min
  { 63,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #63 = A2_minp
  { 64,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #64 = A2_minu
  { 65,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #65 = A2_minup
  { 66,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #66 = A2_negp
  { 67,	2,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #67 = A2_negsat
  { 68,	0,	0,	4,	8,	0, 0xfc00000001ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #68 = A2_nop
  { 69,	2,	1,	4,	8,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000001ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #69 = A2_not
  { 70,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #70 = A2_notp
  { 71,	3,	1,	4,	3,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #71 = A2_or
  { 72,	3,	1,	4,	8,	0, 0xfc55202001ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #72 = A2_orir
  { 73,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #73 = A2_orp
  { 74,	4,	1,	4,	3,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #74 = A2_paddf
  { 75,	4,	1,	4,	3,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #75 = A2_paddfnew
  { 76,	4,	1,	4,	8,	0, 0xfc45a02301ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #76 = A2_paddif
  { 77,	4,	1,	4,	8,	0, 0xfc45a02701ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #77 = A2_paddifnew
  { 78,	4,	1,	4,	8,	0, 0xfc45a02101ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #78 = A2_paddit
  { 79,	4,	1,	4,	8,	0, 0xfc45a02501ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #79 = A2_padditnew
  { 80,	4,	1,	4,	3,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #80 = A2_paddt
  { 81,	4,	1,	4,	3,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #81 = A2_paddtnew
  { 82,	4,	1,	4,	3,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #82 = A2_pandf
  { 83,	4,	1,	4,	3,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #83 = A2_pandfnew
  { 84,	4,	1,	4,	3,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #84 = A2_pandt
  { 85,	4,	1,	4,	3,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #85 = A2_pandtnew
  { 86,	4,	1,	4,	3,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #86 = A2_porf
  { 87,	4,	1,	4,	3,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #87 = A2_porfnew
  { 88,	4,	1,	4,	3,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #88 = A2_port
  { 89,	4,	1,	4,	3,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #89 = A2_portnew
  { 90,	4,	1,	4,	3,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #90 = A2_psubf
  { 91,	4,	1,	4,	3,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #91 = A2_psubfnew
  { 92,	4,	1,	4,	3,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #92 = A2_psubt
  { 93,	4,	1,	4,	3,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #93 = A2_psubtnew
  { 94,	4,	1,	4,	3,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #94 = A2_pxorf
  { 95,	4,	1,	4,	3,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #95 = A2_pxorfnew
  { 96,	4,	1,	4,	3,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #96 = A2_pxort
  { 97,	4,	1,	4,	3,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #97 = A2_pxortnew
  { 98,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #98 = A2_roundsat
  { 99,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #99 = A2_sat
  { 100,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #100 = A2_satb
  { 101,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #101 = A2_sath
  { 102,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #102 = A2_satub
  { 103,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #103 = A2_satuh
  { 104,	3,	1,	4,	3,	0|(1ULL<<MCID::Predicable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #104 = A2_sub
  { 105,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #105 = A2_subh_h16_hh
  { 106,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #106 = A2_subh_h16_hl
  { 107,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #107 = A2_subh_h16_lh
  { 108,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #108 = A2_subh_h16_ll
  { 109,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #109 = A2_subh_h16_sat_hh
  { 110,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #110 = A2_subh_h16_sat_hl
  { 111,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #111 = A2_subh_h16_sat_lh
  { 112,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #112 = A2_subh_h16_sat_ll
  { 113,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #113 = A2_subh_l16_hl
  { 114,	3,	1,	4,	4,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #114 = A2_subh_l16_ll
  { 115,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #115 = A2_subh_l16_sat_hl
  { 116,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #116 = A2_subh_l16_sat_ll
  { 117,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #117 = A2_subp
  { 118,	3,	1,	4,	8,	0, 0xfc54a02001ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #118 = A2_subri
  { 119,	3,	1,	4,	7,	0, 0xfc00002001ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #119 = A2_subsat
  { 120,	3,	1,	4,	3,	0|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #120 = A2_svaddh
  { 121,	3,	1,	4,	7,	0|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #121 = A2_svaddhs
  { 122,	3,	1,	4,	7,	0|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #122 = A2_svadduhs
  { 123,	3,	1,	4,	3,	0|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #123 = A2_svavgh
  { 124,	3,	1,	4,	7,	0|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #124 = A2_svavghs
  { 125,	3,	1,	4,	3,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #125 = A2_svnavgh
  { 126,	3,	1,	4,	3,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #126 = A2_svsubh
  { 127,	3,	1,	4,	7,	0, 0xfc00002001ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #127 = A2_svsubhs
  { 128,	3,	1,	4,	7,	0, 0xfc00002001ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #128 = A2_svsubuhs
  { 129,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #129 = A2_swiz
  { 130,	2,	1,	4,	8,	0|(1ULL<<MCID::Predicable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #130 = A2_sxtb
  { 131,	2,	1,	4,	8,	0|(1ULL<<MCID::Predicable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #131 = A2_sxth
  { 132,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #132 = A2_sxtw
  { 133,	2,	1,	4,	8,	0|(1ULL<<MCID::Predicable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #133 = A2_tfr
  { 134,	2,	1,	4,	9,	0, 0xfc00002002ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #134 = A2_tfrcrr
  { 135,	3,	1,	4,	8,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #135 = A2_tfrf
  { 136,	3,	1,	4,	8,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #136 = A2_tfrfnew
  { 137,	3,	1,	4,	8,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #137 = A2_tfrih
  { 138,	3,	1,	4,	8,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #138 = A2_tfril
  { 139,	2,	1,	4,	8,	0|(1ULL<<MCID::Predicable), 0xfc00000001ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #139 = A2_tfrp
  { 140,	3,	1,	4,	8,	0, 0xfc00000301ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #140 = A2_tfrpf
  { 141,	3,	1,	4,	8,	0, 0xfc00000701ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #141 = A2_tfrpfnew
  { 142,	2,	1,	4,	4,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc00000008ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #142 = A2_tfrpi
  { 143,	3,	1,	4,	8,	0, 0xfc00000101ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #143 = A2_tfrpt
  { 144,	3,	1,	4,	8,	0, 0xfc00000501ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #144 = A2_tfrptnew
  { 145,	2,	1,	4,	9,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #145 = A2_tfrrcr
  { 146,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc84a02001ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #146 = A2_tfrsi
  { 147,	3,	1,	4,	8,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #147 = A2_tfrt
  { 148,	3,	1,	4,	8,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #148 = A2_tfrtnew
  { 149,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #149 = A2_vabsh
  { 150,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #150 = A2_vabshsat
  { 151,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #151 = A2_vabsw
  { 152,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #152 = A2_vabswsat
  { 153,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #153 = A2_vaddh
  { 154,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #154 = A2_vaddhs
  { 155,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #155 = A2_vaddub
  { 156,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #156 = A2_vaddubs
  { 157,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #157 = A2_vadduhs
  { 158,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #158 = A2_vaddw
  { 159,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #159 = A2_vaddws
  { 160,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #160 = A2_vavgh
  { 161,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #161 = A2_vavghcr
  { 162,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #162 = A2_vavghr
  { 163,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #163 = A2_vavgub
  { 164,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #164 = A2_vavgubr
  { 165,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #165 = A2_vavguh
  { 166,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #166 = A2_vavguhr
  { 167,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #167 = A2_vavguw
  { 168,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #168 = A2_vavguwr
  { 169,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #169 = A2_vavgw
  { 170,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #170 = A2_vavgwcr
  { 171,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #171 = A2_vavgwr
  { 172,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #172 = A2_vcmpbeq
  { 173,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #173 = A2_vcmpbgtu
  { 174,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #174 = A2_vcmpheq
  { 175,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #175 = A2_vcmphgt
  { 176,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #176 = A2_vcmphgtu
  { 177,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #177 = A2_vcmpweq
  { 178,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #178 = A2_vcmpwgt
  { 179,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #179 = A2_vcmpwgtu
  { 180,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #180 = A2_vconj
  { 181,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #181 = A2_vmaxb
  { 182,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #182 = A2_vmaxh
  { 183,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #183 = A2_vmaxub
  { 184,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #184 = A2_vmaxuh
  { 185,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #185 = A2_vmaxuw
  { 186,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #186 = A2_vmaxw
  { 187,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #187 = A2_vminb
  { 188,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #188 = A2_vminh
  { 189,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #189 = A2_vminub
  { 190,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #190 = A2_vminuh
  { 191,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #191 = A2_vminuw
  { 192,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #192 = A2_vminw
  { 193,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #193 = A2_vnavgh
  { 194,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #194 = A2_vnavghcr
  { 195,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #195 = A2_vnavghr
  { 196,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #196 = A2_vnavgw
  { 197,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #197 = A2_vnavgwcr
  { 198,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #198 = A2_vnavgwr
  { 199,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #199 = A2_vraddub
  { 200,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #200 = A2_vraddub_acc
  { 201,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #201 = A2_vrsadub
  { 202,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #202 = A2_vrsadub_acc
  { 203,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #203 = A2_vsubh
  { 204,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #204 = A2_vsubhs
  { 205,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #205 = A2_vsubub
  { 206,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #206 = A2_vsububs
  { 207,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #207 = A2_vsubuhs
  { 208,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #208 = A2_vsubw
  { 209,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #209 = A2_vsubws
  { 210,	3,	1,	4,	3,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #210 = A2_xor
  { 211,	3,	1,	4,	4,	0|(1ULL<<MCID::Commutable), 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #211 = A2_xorp
  { 212,	2,	1,	4,	8,	0|(1ULL<<MCID::Predicable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #212 = A2_zxtb
  { 213,	2,	1,	4,	8,	0|(1ULL<<MCID::Predicable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #213 = A2_zxth
  { 214,	5,	2,	4,	12,	0, 0xfc00000808ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #214 = A4_addp_c
  { 215,	3,	1,	4,	3,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #215 = A4_andn
  { 216,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #216 = A4_andnp
  { 217,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #217 = A4_bitsplit
  { 218,	3,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #218 = A4_bitspliti
  { 219,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #219 = A4_boundscheck
  { 220,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #220 = A4_boundscheck_hi
  { 221,	3,	1,	4,	5,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #221 = A4_boundscheck_lo
  { 222,	3,	1,	4,	13,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable), 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #222 = A4_cmpbeq
  { 223,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable), 0xfc40000008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #223 = A4_cmpbeqi
  { 224,	3,	1,	4,	13,	0|(1ULL<<MCID::Compare), 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #224 = A4_cmpbgt
  { 225,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0xfc44000008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #225 = A4_cmpbgti
  { 226,	3,	1,	4,	13,	0|(1ULL<<MCID::Compare), 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #226 = A4_cmpbgtu
  { 227,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0xfc39200008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #227 = A4_cmpbgtui
  { 228,	3,	1,	4,	13,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable), 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #228 = A4_cmpheq
  { 229,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable), 0xfc45200008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #229 = A4_cmpheqi
  { 230,	3,	1,	4,	13,	0|(1ULL<<MCID::Compare), 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #230 = A4_cmphgt
  { 231,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0xfc45200008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #231 = A4_cmphgti
  { 232,	3,	1,	4,	13,	0|(1ULL<<MCID::Compare), 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #232 = A4_cmphgtu
  { 233,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0xfc39200008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #233 = A4_cmphgtui
  { 234,	3,	1,	4,	8,	0, 0xfc31200001ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #234 = A4_combineii
  { 235,	3,	1,	4,	8,	0, 0xfc44a00001ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #235 = A4_combineir
  { 236,	3,	1,	4,	8,	0, 0xfc45200001ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #236 = A4_combineri
  { 237,	3,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #237 = A4_cround_ri
  { 238,	3,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #238 = A4_cround_rr
  { 239,	1,	0,	4,	15,	0, 0xfc0000001eULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #239 = A4_ext
  { 240,	1,	0,	4,	15,	0|(1ULL<<MCID::Branch), 0xfc0000001eULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #240 = A4_ext_b
  { 241,	1,	0,	4,	15,	0|(1ULL<<MCID::Call), 0xfc0000001eULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #241 = A4_ext_c
  { 242,	1,	0,	4,	15,	0, 0xfc0000001eULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #242 = A4_ext_g
  { 243,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #243 = A4_modwrapu
  { 244,	3,	1,	4,	3,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #244 = A4_orn
  { 245,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #245 = A4_ornp
  { 246,	3,	1,	4,	8,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #246 = A4_paslhf
  { 247,	3,	1,	4,	8,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #247 = A4_paslhfnew
  { 248,	3,	1,	4,	8,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #248 = A4_paslht
  { 249,	3,	1,	4,	8,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #249 = A4_paslhtnew
  { 250,	3,	1,	4,	8,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #250 = A4_pasrhf
  { 251,	3,	1,	4,	8,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #251 = A4_pasrhfnew
  { 252,	3,	1,	4,	8,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #252 = A4_pasrht
  { 253,	3,	1,	4,	8,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #253 = A4_pasrhtnew
  { 254,	3,	1,	4,	8,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #254 = A4_psxtbf
  { 255,	3,	1,	4,	8,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #255 = A4_psxtbfnew
  { 256,	3,	1,	4,	8,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #256 = A4_psxtbt
  { 257,	3,	1,	4,	8,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #257 = A4_psxtbtnew
  { 258,	3,	1,	4,	8,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #258 = A4_psxthf
  { 259,	3,	1,	4,	8,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #259 = A4_psxthfnew
  { 260,	3,	1,	4,	8,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #260 = A4_psxtht
  { 261,	3,	1,	4,	8,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #261 = A4_psxthtnew
  { 262,	3,	1,	4,	8,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #262 = A4_pzxtbf
  { 263,	3,	1,	4,	8,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #263 = A4_pzxtbfnew
  { 264,	3,	1,	4,	8,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #264 = A4_pzxtbt
  { 265,	3,	1,	4,	8,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #265 = A4_pzxtbtnew
  { 266,	3,	1,	4,	8,	0, 0xfc00002301ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #266 = A4_pzxthf
  { 267,	3,	1,	4,	8,	0, 0xfc00002701ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #267 = A4_pzxthfnew
  { 268,	3,	1,	4,	8,	0, 0xfc00002101ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #268 = A4_pzxtht
  { 269,	3,	1,	4,	8,	0, 0xfc00002501ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #269 = A4_pzxthtnew
  { 270,	3,	1,	4,	3,	0|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #270 = A4_rcmpeq
  { 271,	3,	1,	4,	8,	0, 0xfc45202001ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #271 = A4_rcmpeqi
  { 272,	3,	1,	4,	3,	0|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #272 = A4_rcmpneq
  { 273,	3,	1,	4,	8,	0, 0xfc45202001ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #273 = A4_rcmpneqi
  { 274,	3,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #274 = A4_round_ri
  { 275,	3,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #275 = A4_round_ri_sat
  { 276,	3,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #276 = A4_round_rr
  { 277,	3,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #277 = A4_round_rr_sat
  { 278,	5,	2,	4,	12,	0, 0xfc00000808ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #278 = A4_subp_c
  { 279,	2,	1,	4,	9,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #279 = A4_tfrcpp
  { 280,	2,	1,	4,	9,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #280 = A4_tfrpcp
  { 281,	3,	1,	4,	10,	0, 0xfc00000808ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #281 = A4_tlbmatch
  { 282,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #282 = A4_vcmpbeq_any
  { 283,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #283 = A4_vcmpbeqi
  { 284,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #284 = A4_vcmpbgt
  { 285,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #285 = A4_vcmpbgti
  { 286,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #286 = A4_vcmpbgtui
  { 287,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #287 = A4_vcmpheqi
  { 288,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #288 = A4_vcmphgti
  { 289,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #289 = A4_vcmphgtui
  { 290,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #290 = A4_vcmpweqi
  { 291,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #291 = A4_vcmpwgti
  { 292,	3,	1,	4,	10,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #292 = A4_vcmpwgtui
  { 293,	4,	1,	4,	16,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #293 = A4_vrmaxh
  { 294,	4,	1,	4,	16,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #294 = A4_vrmaxuh
  { 295,	4,	1,	4,	16,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #295 = A4_vrmaxuw
  { 296,	4,	1,	4,	16,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #296 = A4_vrmaxw
  { 297,	4,	1,	4,	16,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #297 = A4_vrminh
  { 298,	4,	1,	4,	16,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #298 = A4_vrminuh
  { 299,	4,	1,	4,	16,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #299 = A4_vrminuw
  { 300,	4,	1,	4,	16,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #300 = A4_vrminw
  { 301,	5,	2,	4,	17,	0, 0xf000000808ULL, nullptr, ImplicitList1, OperandInfo46, -1 ,nullptr },  // Inst #301 = A5_ACS
  { 302,	3,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #302 = A5_vaddhubs
  { 303,	1,	0,	4,	18,	0|(1ULL<<MCID::Pseudo), 0xfc00000000ULL, ImplicitList2, ImplicitList3, OperandInfo2, -1 ,nullptr },  // Inst #303 = ADJCALLSTACKDOWN
  { 304,	2,	0,	4,	18,	0|(1ULL<<MCID::Pseudo), 0xfc00000000ULL, ImplicitList4, ImplicitList5, OperandInfo8, -1 ,nullptr },  // Inst #304 = ADJCALLSTACKUP
  { 305,	2,	1,	4,	8,	0|(1ULL<<MCID::Pseudo), 0xfc00000001ULL, ImplicitList6, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #305 = ALIGNA
  { 306,	3,	1,	4,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000001ULL, nullptr, ImplicitList4, OperandInfo16, -1 ,nullptr },  // Inst #306 = ALLOCA
  { 307,	2,	1,	4,	8,	0, 0xfc00000001ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #307 = ARGEXTEND
  { 308,	2,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #308 = C2_all8
  { 309,	3,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #309 = C2_and
  { 310,	3,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #310 = C2_andn
  { 311,	2,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #311 = C2_any8
  { 312,	3,	1,	4,	13,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #312 = C2_bitsclr
  { 313,	3,	1,	4,	20,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #313 = C2_bitsclri
  { 314,	3,	1,	4,	13,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #314 = C2_bitsset
  { 315,	4,	1,	4,	3,	0, 0xfc00000301ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #315 = C2_ccombinewf
  { 316,	4,	1,	4,	3,	0, 0xfc00000701ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #316 = C2_ccombinewnewf
  { 317,	4,	1,	4,	3,	0, 0xfc00000501ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #317 = C2_ccombinewnewt
  { 318,	4,	1,	4,	3,	0, 0xfc00000101ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #318 = C2_ccombinewt
  { 319,	3,	1,	4,	8,	0|(1ULL<<MCID::MoveImm), 0xfc65202301ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #319 = C2_cmoveif
  { 320,	3,	1,	4,	8,	0|(1ULL<<MCID::MoveImm), 0xfc65202101ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #320 = C2_cmoveit
  { 321,	3,	1,	4,	8,	0|(1ULL<<MCID::MoveImm), 0xfc65202701ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #321 = C2_cmovenewif
  { 322,	3,	1,	4,	8,	0|(1ULL<<MCID::MoveImm), 0xfc65202501ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #322 = C2_cmovenewit
  { 323,	3,	1,	4,	21,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #323 = C2_cmpeq
  { 324,	3,	1,	4,	22,	0|(1ULL<<MCID::Compare), 0xfc55200001ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #324 = C2_cmpeqi
  { 325,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable), 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #325 = C2_cmpeqp
  { 326,	3,	1,	4,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000001ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #326 = C2_cmpgei
  { 327,	3,	1,	4,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000001ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #327 = C2_cmpgeui
  { 328,	3,	1,	4,	21,	0|(1ULL<<MCID::Compare), 0xfc00002001ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #328 = C2_cmpgt
  { 329,	3,	1,	4,	22,	0|(1ULL<<MCID::Compare), 0xfc55200001ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #329 = C2_cmpgti
  { 330,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #330 = C2_cmpgtp
  { 331,	3,	1,	4,	21,	0|(1ULL<<MCID::Compare), 0xfc00002001ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #331 = C2_cmpgtu
  { 332,	3,	1,	4,	22,	0|(1ULL<<MCID::Compare), 0xfc49200001ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #332 = C2_cmpgtui
  { 333,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0xfc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #333 = C2_cmpgtup
  { 334,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #334 = C2_mask
  { 335,	4,	1,	4,	3,	0, 0xfc00002001ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #335 = C2_mux
  { 336,	4,	1,	4,	8,	0, 0xfc45202001ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #336 = C2_muxii
  { 337,	4,	1,	4,	8,	0, 0xfc45a02001ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #337 = C2_muxir
  { 338,	4,	1,	4,	8,	0, 0xfc45202001ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #338 = C2_muxri
  { 339,	2,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #339 = C2_not
  { 340,	3,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #340 = C2_or
  { 341,	3,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #341 = C2_orn
  { 342,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #342 = C2_pxfer_map
  { 343,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #343 = C2_tfrpr
  { 344,	2,	1,	4,	20,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #344 = C2_tfrrp
  { 345,	3,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #345 = C2_vitpack
  { 346,	4,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #346 = C2_vmux
  { 347,	3,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #347 = C2_xor
  { 348,	2,	1,	4,	23,	0, 0xfc30a02002ULL, ImplicitList7, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #348 = C4_addipc
  { 349,	4,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #349 = C4_and_and
  { 350,	4,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #350 = C4_and_andn
  { 351,	4,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #351 = C4_and_or
  { 352,	4,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #352 = C4_and_orn
  { 353,	3,	1,	4,	3,	0|(1ULL<<MCID::Compare), 0xfc00002001ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #353 = C4_cmplte
  { 354,	3,	1,	4,	22,	0|(1ULL<<MCID::Compare), 0xfc55200001ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #354 = C4_cmpltei
  { 355,	3,	1,	4,	3,	0|(1ULL<<MCID::Compare), 0xfc00002001ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #355 = C4_cmplteu
  { 356,	3,	1,	4,	22,	0|(1ULL<<MCID::Compare), 0xfc49200001ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #356 = C4_cmplteui
  { 357,	3,	1,	4,	3,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #357 = C4_cmpneq
  { 358,	3,	1,	4,	22,	0|(1ULL<<MCID::Compare), 0xfc55200001ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #358 = C4_cmpneqi
  { 359,	3,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #359 = C4_fastcorner9
  { 360,	3,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #360 = C4_fastcorner9_not
  { 361,	3,	1,	4,	13,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #361 = C4_nbitsclr
  { 362,	3,	1,	4,	20,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #362 = C4_nbitsclri
  { 363,	3,	1,	4,	13,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #363 = C4_nbitsset
  { 364,	4,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #364 = C4_or_and
  { 365,	4,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #365 = C4_or_andn
  { 366,	4,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #366 = C4_or_or
  { 367,	4,	1,	4,	19,	0, 0xfc00000002ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #367 = C4_or_orn
  { 368,	1,	0,	4,	24,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000203ULL, nullptr, ImplicitList8, OperandInfo60, -1 ,nullptr },  // Inst #368 = CALLRv3nr
  { 369,	1,	0,	4,	25,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0xfec4200004ULL, nullptr, ImplicitList8, OperandInfo5, -1 ,nullptr },  // Inst #369 = CALLv3nr
  { 370,	2,	1,	4,	26,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #370 = CONST32
  { 371,	2,	1,	4,	26,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0xfc00000005ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #371 = CONST32_Float_Real
  { 372,	2,	1,	4,	26,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0xfc00000005ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #372 = CONST32_Int_Real
  { 373,	2,	1,	4,	26,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0xfc00000005ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #373 = CONST64_Float_Real
  { 374,	2,	1,	4,	26,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0xfc00000005ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #374 = CONST64_Int_Real
  { 375,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #375 = DuplexIClass0
  { 376,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #376 = DuplexIClass1
  { 377,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #377 = DuplexIClass2
  { 378,	0,	0,	4,	27,	0, 0x1000bULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #378 = DuplexIClass3
  { 379,	0,	0,	4,	27,	0, 0x1000bULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #379 = DuplexIClass4
  { 380,	0,	0,	4,	27,	0, 0x1000bULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #380 = DuplexIClass5
  { 381,	0,	0,	4,	27,	0, 0x1000bULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #381 = DuplexIClass6
  { 382,	0,	0,	4,	27,	0, 0x1000bULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #382 = DuplexIClass7
  { 383,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #383 = DuplexIClass8
  { 384,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #384 = DuplexIClass9
  { 385,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #385 = DuplexIClassA
  { 386,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #386 = DuplexIClassB
  { 387,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #387 = DuplexIClassC
  { 388,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #388 = DuplexIClassD
  { 389,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #389 = DuplexIClassE
  { 390,	0,	0,	4,	27,	0, 0xbULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #390 = DuplexIClassF
  { 391,	1,	0,	4,	24,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0xfc00000003ULL, ImplicitList9, ImplicitList7, OperandInfo60, -1 ,nullptr },  // Inst #391 = EH_RETURN_JMPR
  { 392,	1,	0,	4,	28,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfc0000001fULL, ImplicitList10, ImplicitList11, OperandInfo5, -1 ,nullptr },  // Inst #392 = ENDLOOP0
  { 393,	1,	0,	4,	28,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfc0000001fULL, ImplicitList12, ImplicitList13, OperandInfo5, -1 ,nullptr },  // Inst #393 = ENDLOOP1
  { 394,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #394 = F2_conv_d2df
  { 395,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #395 = F2_conv_d2sf
  { 396,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #396 = F2_conv_df2d
  { 397,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #397 = F2_conv_df2d_chop
  { 398,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #398 = F2_conv_df2sf
  { 399,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #399 = F2_conv_df2ud
  { 400,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #400 = F2_conv_df2ud_chop
  { 401,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #401 = F2_conv_df2uw
  { 402,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #402 = F2_conv_df2uw_chop
  { 403,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #403 = F2_conv_df2w
  { 404,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #404 = F2_conv_df2w_chop
  { 405,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #405 = F2_conv_sf2d
  { 406,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #406 = F2_conv_sf2d_chop
  { 407,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #407 = F2_conv_sf2df
  { 408,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #408 = F2_conv_sf2ud
  { 409,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #409 = F2_conv_sf2ud_chop
  { 410,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #410 = F2_conv_sf2uw
  { 411,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #411 = F2_conv_sf2uw_chop
  { 412,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #412 = F2_conv_sf2w
  { 413,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #413 = F2_conv_sf2w_chop
  { 414,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #414 = F2_conv_ud2df
  { 415,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #415 = F2_conv_ud2sf
  { 416,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #416 = F2_conv_uw2df
  { 417,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #417 = F2_conv_uw2sf
  { 418,	2,	1,	4,	29,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #418 = F2_conv_w2df
  { 419,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #419 = F2_conv_w2sf
  { 420,	3,	1,	4,	10,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #420 = F2_dfclass
  { 421,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0x100fc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #421 = F2_dfcmpeq
  { 422,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0x100fc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #422 = F2_dfcmpge
  { 423,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0x100fc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #423 = F2_dfcmpgt
  { 424,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0x100fc00000008ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #424 = F2_dfcmpuo
  { 425,	2,	1,	4,	30,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #425 = F2_dfimm_n
  { 426,	2,	1,	4,	30,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #426 = F2_dfimm_p
  { 427,	3,	1,	4,	31,	0|(1ULL<<MCID::Commutable), 0x100fc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #427 = F2_sfadd
  { 428,	3,	1,	4,	20,	0, 0x100fc00000008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #428 = F2_sfclass
  { 429,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0x100fc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #429 = F2_sfcmpeq
  { 430,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0x100fc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #430 = F2_sfcmpge
  { 431,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0x100fc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #431 = F2_sfcmpgt
  { 432,	3,	1,	4,	10,	0|(1ULL<<MCID::Compare), 0x100fc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #432 = F2_sfcmpuo
  { 433,	3,	1,	4,	31,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #433 = F2_sffixupd
  { 434,	3,	1,	4,	31,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #434 = F2_sffixupn
  { 435,	2,	1,	4,	29,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #435 = F2_sffixupr
  { 436,	4,	1,	4,	32,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #436 = F2_sffma
  { 437,	4,	1,	4,	32,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #437 = F2_sffma_lib
  { 438,	5,	1,	4,	32,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #438 = F2_sffma_sc
  { 439,	4,	1,	4,	32,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #439 = F2_sffms
  { 440,	4,	1,	4,	32,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #440 = F2_sffms_lib
  { 441,	2,	1,	4,	30,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #441 = F2_sfimm_n
  { 442,	2,	1,	4,	30,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #442 = F2_sfimm_p
  { 443,	3,	2,	4,	2,	0, 0x100f800002808ULL, ImplicitList14, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #443 = F2_sfinvsqrta
  { 444,	3,	1,	4,	11,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #444 = F2_sfmax
  { 445,	3,	1,	4,	11,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #445 = F2_sfmin
  { 446,	3,	1,	4,	31,	0|(1ULL<<MCID::Commutable), 0x100fc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #446 = F2_sfmpy
  { 447,	4,	2,	4,	11,	0, 0x100fc00002808ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #447 = F2_sfrecipa
  { 448,	3,	1,	4,	31,	0, 0x100fc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #448 = F2_sfsub
  { 449,	2,	1,	4,	26,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0xfc00000005ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #449 = FCONST32_nsdata
  { 450,	2,	1,	4,	33,	0|(1ULL<<MCID::Pseudo), 0xe00000000dULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #450 = HEXAGON_V6_hi
  { 451,	2,	1,	4,	33,	0|(1ULL<<MCID::Pseudo), 0xe00000000dULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #451 = HEXAGON_V6_hi_128B
  { 452,	2,	1,	4,	33,	0|(1ULL<<MCID::Pseudo), 0xe00000000dULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #452 = HEXAGON_V6_lo
  { 453,	2,	1,	4,	33,	0|(1ULL<<MCID::Pseudo), 0xe00000000dULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #453 = HEXAGON_V6_lo_128B
  { 454,	2,	1,	4,	33,	0|(1ULL<<MCID::Pseudo), 0xe00000000dULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #454 = HEXAGON_V6_vassignp
  { 455,	2,	1,	4,	33,	0|(1ULL<<MCID::Pseudo), 0xe00000000dULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #455 = HEXAGON_V6_vassignp_128B
  { 456,	1,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #456 = HEXAGON_V6_vd0_pseudo
  { 457,	1,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo69, -1 ,nullptr },  // Inst #457 = HEXAGON_V6_vd0_pseudo_128B
  { 458,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #458 = HI
  { 459,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable), 0xfc00000001ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #459 = HI_GOT
  { 460,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable), 0xfc00000001ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #460 = HI_GOTREL
  { 461,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #461 = HI_L
  { 462,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000001ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #462 = HI_PIC
  { 463,	5,	1,	4,	34,	0|(1ULL<<MCID::Pseudo), 0xfc00000000ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #463 = Insert4
  { 464,	1,	0,	4,	25,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0xfec4200004ULL, nullptr, ImplicitList8, OperandInfo5, -1 ,nullptr },  // Inst #464 = J2_call
  { 465,	2,	0,	4,	25,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0xfe8ca00304ULL, nullptr, ImplicitList8, OperandInfo71, -1 ,nullptr },  // Inst #465 = J2_callf
  { 466,	1,	0,	4,	24,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000203ULL, nullptr, ImplicitList8, OperandInfo60, -1 ,nullptr },  // Inst #466 = J2_callr
  { 467,	2,	0,	4,	24,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000303ULL, nullptr, ImplicitList8, OperandInfo56, -1 ,nullptr },  // Inst #467 = J2_callrf
  { 468,	2,	0,	4,	24,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000103ULL, nullptr, ImplicitList8, OperandInfo56, -1 ,nullptr },  // Inst #468 = J2_callrt
  { 469,	2,	0,	4,	25,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0xfe8ca00104ULL, nullptr, ImplicitList8, OperandInfo71, -1 ,nullptr },  // Inst #469 = J2_callt
  { 470,	1,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0xfec4200004ULL, nullptr, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #470 = J2_jump
  { 471,	1,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0xfec4200004ULL, nullptr, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #471 = J2_jump_ext
  { 472,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00304ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #472 = J2_jump_extf
  { 473,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00704ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #473 = J2_jump_extfnew
  { 474,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe8ca00704ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #474 = J2_jump_extfnewpt
  { 475,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00104ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #475 = J2_jump_extt
  { 476,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00504ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #476 = J2_jump_exttnew
  { 477,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe8ca00504ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #477 = J2_jump_exttnewpt
  { 478,	1,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0xfec4200004ULL, nullptr, ImplicitList7, OperandInfo5, -1 ,nullptr },  // Inst #478 = J2_jump_noext
  { 479,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00304ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #479 = J2_jump_noextf
  { 480,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00704ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #480 = J2_jump_noextfnew
  { 481,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe8ca00704ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #481 = J2_jump_noextfnewpt
  { 482,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00104ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #482 = J2_jump_noextt
  { 483,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00504ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #483 = J2_jump_noexttnew
  { 484,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe8ca00504ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #484 = J2_jump_noexttnewpt
  { 485,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00304ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #485 = J2_jumpf
  { 486,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00704ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #486 = J2_jumpfnew
  { 487,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe8ca00704ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #487 = J2_jumpfnewpt
  { 488,	1,	0,	4,	24,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0xfc00000003ULL, nullptr, ImplicitList7, OperandInfo60, -1 ,nullptr },  // Inst #488 = J2_jumpr
  { 489,	2,	0,	4,	24,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0xfc00000303ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #489 = J2_jumprf
  { 490,	2,	0,	4,	24,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0xfc00000703ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #490 = J2_jumprfnew
  { 491,	2,	0,	4,	24,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x80fc00000703ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #491 = J2_jumprfnewpt
  { 492,	2,	0,	4,	35,	0|(1ULL<<MCID::Branch), 0xfc00000102ULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #492 = J2_jumprgtez
  { 493,	2,	0,	4,	35,	0|(1ULL<<MCID::Branch), 0xfc00000102ULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #493 = J2_jumprgtezpt
  { 494,	2,	0,	4,	35,	0|(1ULL<<MCID::Branch), 0xfc00000102ULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #494 = J2_jumprltez
  { 495,	2,	0,	4,	35,	0|(1ULL<<MCID::Branch), 0xfc00000102ULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #495 = J2_jumprltezpt
  { 496,	2,	0,	4,	35,	0|(1ULL<<MCID::Branch), 0xfc00000102ULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #496 = J2_jumprnz
  { 497,	2,	0,	4,	35,	0|(1ULL<<MCID::Branch), 0xfc00000102ULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #497 = J2_jumprnzpt
  { 498,	2,	0,	4,	24,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0xfc00000103ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #498 = J2_jumprt
  { 499,	2,	0,	4,	24,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0xfc00000503ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #499 = J2_jumprtnew
  { 500,	2,	0,	4,	24,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x80fc00000503ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #500 = J2_jumprtnewpt
  { 501,	2,	0,	4,	35,	0|(1ULL<<MCID::Branch), 0xfc00000102ULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #501 = J2_jumprz
  { 502,	2,	0,	4,	35,	0|(1ULL<<MCID::Branch), 0xfc00000102ULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #502 = J2_jumprzpt
  { 503,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00104ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #503 = J2_jumpt
  { 504,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe8ca00504ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #504 = J2_jumptnew
  { 505,	2,	0,	4,	25,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe8ca00504ULL, nullptr, ImplicitList7, OperandInfo71, -1 ,nullptr },  // Inst #505 = J2_jumptnewpt
  { 506,	2,	0,	4,	9,	0, 0xfe4c200002ULL, nullptr, ImplicitList15, OperandInfo72, -1 ,nullptr },  // Inst #506 = J2_loop0i
  { 507,	2,	0,	4,	9,	0, 0xfe4c600002ULL, nullptr, ImplicitList15, OperandInfo72, -1 ,nullptr },  // Inst #507 = J2_loop0iext
  { 508,	2,	0,	4,	9,	0, 0xfe4c200002ULL, nullptr, ImplicitList15, OperandInfo73, -1 ,nullptr },  // Inst #508 = J2_loop0r
  { 509,	2,	0,	4,	9,	0, 0xfe4c600002ULL, nullptr, ImplicitList15, OperandInfo73, -1 ,nullptr },  // Inst #509 = J2_loop0rext
  { 510,	2,	0,	4,	9,	0, 0xfe4c200002ULL, nullptr, ImplicitList12, OperandInfo72, -1 ,nullptr },  // Inst #510 = J2_loop1i
  { 511,	2,	0,	4,	9,	0, 0xfe4c600002ULL, nullptr, ImplicitList12, OperandInfo72, -1 ,nullptr },  // Inst #511 = J2_loop1iext
  { 512,	2,	0,	4,	9,	0, 0xfe4c200002ULL, nullptr, ImplicitList12, OperandInfo73, -1 ,nullptr },  // Inst #512 = J2_loop1r
  { 513,	2,	0,	4,	9,	0, 0xfe4c600002ULL, nullptr, ImplicitList12, OperandInfo73, -1 ,nullptr },  // Inst #513 = J2_loop1rext
  { 514,	2,	0,	4,	35,	0, 0xfe4c200802ULL, nullptr, ImplicitList16, OperandInfo72, -1 ,nullptr },  // Inst #514 = J2_ploop1si
  { 515,	2,	0,	4,	35,	0, 0xfe4c200802ULL, nullptr, ImplicitList16, OperandInfo73, -1 ,nullptr },  // Inst #515 = J2_ploop1sr
  { 516,	2,	0,	4,	35,	0, 0xfe4c200802ULL, nullptr, ImplicitList16, OperandInfo72, -1 ,nullptr },  // Inst #516 = J2_ploop2si
  { 517,	2,	0,	4,	35,	0, 0xfe4c200802ULL, nullptr, ImplicitList16, OperandInfo73, -1 ,nullptr },  // Inst #517 = J2_ploop2sr
  { 518,	2,	0,	4,	35,	0, 0xfe4c200802ULL, nullptr, ImplicitList16, OperandInfo72, -1 ,nullptr },  // Inst #518 = J2_ploop3si
  { 519,	2,	0,	4,	35,	0, 0xfe4c200802ULL, nullptr, ImplicitList16, OperandInfo73, -1 ,nullptr },  // Inst #519 = J2_ploop3sr
  { 520,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20130aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #520 = J4_cmpeq_f_jumpnv_nt
  { 521,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20130aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #521 = J4_cmpeq_f_jumpnv_t
  { 522,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #522 = J4_cmpeq_fp0_jump_nt
  { 523,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #523 = J4_cmpeq_fp0_jump_t
  { 524,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #524 = J4_cmpeq_fp1_jump_nt
  { 525,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #525 = J4_cmpeq_fp1_jump_t
  { 526,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20110aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #526 = J4_cmpeq_t_jumpnv_nt
  { 527,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20110aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #527 = J4_cmpeq_t_jumpnv_t
  { 528,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #528 = J4_cmpeq_tp0_jump_nt
  { 529,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #529 = J4_cmpeq_tp0_jump_t
  { 530,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #530 = J4_cmpeq_tp1_jump_nt
  { 531,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #531 = J4_cmpeq_tp1_jump_t
  { 532,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20130aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #532 = J4_cmpeqi_f_jumpnv_nt
  { 533,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20130aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #533 = J4_cmpeqi_f_jumpnv_t
  { 534,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #534 = J4_cmpeqi_fp0_jump_nt
  { 535,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #535 = J4_cmpeqi_fp0_jump_t
  { 536,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #536 = J4_cmpeqi_fp1_jump_nt
  { 537,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #537 = J4_cmpeqi_fp1_jump_t
  { 538,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20110aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #538 = J4_cmpeqi_t_jumpnv_nt
  { 539,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20110aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #539 = J4_cmpeqi_t_jumpnv_t
  { 540,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #540 = J4_cmpeqi_tp0_jump_nt
  { 541,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #541 = J4_cmpeqi_tp0_jump_t
  { 542,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #542 = J4_cmpeqi_tp1_jump_nt
  { 543,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #543 = J4_cmpeqi_tp1_jump_t
  { 544,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0130aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #544 = J4_cmpeqn1_f_jumpnv_nt
  { 545,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0130aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #545 = J4_cmpeqn1_f_jumpnv_t
  { 546,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0070cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #546 = J4_cmpeqn1_fp0_jump_nt
  { 547,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0070cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #547 = J4_cmpeqn1_fp0_jump_t
  { 548,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0070cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #548 = J4_cmpeqn1_fp1_jump_nt
  { 549,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0070cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #549 = J4_cmpeqn1_fp1_jump_t
  { 550,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0110aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #550 = J4_cmpeqn1_t_jumpnv_nt
  { 551,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0110aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #551 = J4_cmpeqn1_t_jumpnv_t
  { 552,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0050cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #552 = J4_cmpeqn1_tp0_jump_nt
  { 553,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0050cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #553 = J4_cmpeqn1_tp0_jump_t
  { 554,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0050cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #554 = J4_cmpeqn1_tp1_jump_nt
  { 555,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0050cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #555 = J4_cmpeqn1_tp1_jump_t
  { 556,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20130aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #556 = J4_cmpgt_f_jumpnv_nt
  { 557,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20130aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #557 = J4_cmpgt_f_jumpnv_t
  { 558,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #558 = J4_cmpgt_fp0_jump_nt
  { 559,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #559 = J4_cmpgt_fp0_jump_t
  { 560,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #560 = J4_cmpgt_fp1_jump_nt
  { 561,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #561 = J4_cmpgt_fp1_jump_t
  { 562,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20110aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #562 = J4_cmpgt_t_jumpnv_nt
  { 563,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20110aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #563 = J4_cmpgt_t_jumpnv_t
  { 564,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #564 = J4_cmpgt_tp0_jump_nt
  { 565,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #565 = J4_cmpgt_tp0_jump_t
  { 566,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #566 = J4_cmpgt_tp1_jump_nt
  { 567,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #567 = J4_cmpgt_tp1_jump_t
  { 568,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20130aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #568 = J4_cmpgti_f_jumpnv_nt
  { 569,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20130aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #569 = J4_cmpgti_f_jumpnv_t
  { 570,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #570 = J4_cmpgti_fp0_jump_nt
  { 571,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #571 = J4_cmpgti_fp0_jump_t
  { 572,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #572 = J4_cmpgti_fp1_jump_nt
  { 573,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #573 = J4_cmpgti_fp1_jump_t
  { 574,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20110aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #574 = J4_cmpgti_t_jumpnv_nt
  { 575,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20110aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #575 = J4_cmpgti_t_jumpnv_t
  { 576,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #576 = J4_cmpgti_tp0_jump_nt
  { 577,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #577 = J4_cmpgti_tp0_jump_t
  { 578,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #578 = J4_cmpgti_tp1_jump_nt
  { 579,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #579 = J4_cmpgti_tp1_jump_t
  { 580,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0130aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #580 = J4_cmpgtn1_f_jumpnv_nt
  { 581,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0130aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #581 = J4_cmpgtn1_f_jumpnv_t
  { 582,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0070cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #582 = J4_cmpgtn1_fp0_jump_nt
  { 583,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0070cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #583 = J4_cmpgtn1_fp0_jump_t
  { 584,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0070cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #584 = J4_cmpgtn1_fp1_jump_nt
  { 585,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0070cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #585 = J4_cmpgtn1_fp1_jump_t
  { 586,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0110aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #586 = J4_cmpgtn1_t_jumpnv_nt
  { 587,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0110aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #587 = J4_cmpgtn1_t_jumpnv_t
  { 588,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0050cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #588 = J4_cmpgtn1_tp0_jump_nt
  { 589,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0050cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #589 = J4_cmpgtn1_tp0_jump_t
  { 590,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0050cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #590 = J4_cmpgtn1_tp1_jump_nt
  { 591,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0050cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #591 = J4_cmpgtn1_tp1_jump_t
  { 592,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20130aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #592 = J4_cmpgtu_f_jumpnv_nt
  { 593,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20130aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #593 = J4_cmpgtu_f_jumpnv_t
  { 594,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #594 = J4_cmpgtu_fp0_jump_nt
  { 595,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #595 = J4_cmpgtu_fp0_jump_t
  { 596,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #596 = J4_cmpgtu_fp1_jump_nt
  { 597,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #597 = J4_cmpgtu_fp1_jump_t
  { 598,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20110aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #598 = J4_cmpgtu_t_jumpnv_nt
  { 599,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20110aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #599 = J4_cmpgtu_t_jumpnv_t
  { 600,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #600 = J4_cmpgtu_tp0_jump_nt
  { 601,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo74, -1 ,nullptr },  // Inst #601 = J4_cmpgtu_tp0_jump_t
  { 602,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #602 = J4_cmpgtu_tp1_jump_nt
  { 603,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo74, -1 ,nullptr },  // Inst #603 = J4_cmpgtu_tp1_jump_t
  { 604,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20130aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #604 = J4_cmpgtui_f_jumpnv_nt
  { 605,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20130aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #605 = J4_cmpgtui_f_jumpnv_t
  { 606,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #606 = J4_cmpgtui_fp0_jump_nt
  { 607,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #607 = J4_cmpgtui_fp0_jump_t
  { 608,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #608 = J4_cmpgtui_fp1_jump_nt
  { 609,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20070cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #609 = J4_cmpgtui_fp1_jump_t
  { 610,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20110aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #610 = J4_cmpgtui_t_jumpnv_nt
  { 611,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20110aULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #611 = J4_cmpgtui_t_jumpnv_t
  { 612,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #612 = J4_cmpgtui_tp0_jump_nt
  { 613,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList17, ImplicitList18, OperandInfo75, -1 ,nullptr },  // Inst #613 = J4_cmpgtui_tp0_jump_t
  { 614,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #614 = J4_cmpgtui_tp1_jump_nt
  { 615,	3,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20050cULL, ImplicitList19, ImplicitList20, OperandInfo75, -1 ,nullptr },  // Inst #615 = J4_cmpgtui_tp1_jump_t
  { 616,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20530aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #616 = J4_cmplt_f_jumpnv_nt
  { 617,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20530aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #617 = J4_cmplt_f_jumpnv_t
  { 618,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20510aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #618 = J4_cmplt_t_jumpnv_nt
  { 619,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20510aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #619 = J4_cmplt_t_jumpnv_t
  { 620,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20530aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #620 = J4_cmpltu_f_jumpnv_nt
  { 621,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20530aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #621 = J4_cmpltu_f_jumpnv_t
  { 622,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5d20510aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #622 = J4_cmpltu_t_jumpnv_nt
  { 623,	3,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5d20510aULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #623 = J4_cmpltu_t_jumpnv_t
  { 624,	1,	0,	4,	24,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch), 0xfc00000003ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #624 = J4_hintjumpr
  { 625,	3,	1,	4,	37,	0|(1ULL<<MCID::Branch), 0xfe5d20200cULL, nullptr, ImplicitList7, OperandInfo75, -1 ,nullptr },  // Inst #625 = J4_jumpseti
  { 626,	3,	1,	4,	37,	0|(1ULL<<MCID::Branch), 0xfe5d20200cULL, nullptr, ImplicitList7, OperandInfo74, -1 ,nullptr },  // Inst #626 = J4_jumpsetr
  { 627,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0130aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #627 = J4_tstbit0_f_jumpnv_nt
  { 628,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0130aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #628 = J4_tstbit0_f_jumpnv_t
  { 629,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0070cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #629 = J4_tstbit0_fp0_jump_nt
  { 630,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0070cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #630 = J4_tstbit0_fp0_jump_t
  { 631,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0070cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #631 = J4_tstbit0_fp1_jump_nt
  { 632,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0070cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #632 = J4_tstbit0_fp1_jump_t
  { 633,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0110aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #633 = J4_tstbit0_t_jumpnv_nt
  { 634,	2,	0,	4,	36,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0110aULL, nullptr, ImplicitList7, OperandInfo61, -1 ,nullptr },  // Inst #634 = J4_tstbit0_t_jumpnv_t
  { 635,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0050cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #635 = J4_tstbit0_tp0_jump_nt
  { 636,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0050cULL, ImplicitList17, ImplicitList18, OperandInfo61, -1 ,nullptr },  // Inst #636 = J4_tstbit0_tp0_jump_t
  { 637,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfe5ca0050cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #637 = J4_tstbit0_tp1_jump_nt
  { 638,	2,	0,	4,	37,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x80fe5ca0050cULL, ImplicitList19, ImplicitList20, OperandInfo61, -1 ,nullptr },  // Inst #638 = J4_tstbit0_tp1_jump_t
  { 639,	1,	0,	4,	24,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0xfc00000003ULL, nullptr, ImplicitList7, OperandInfo60, -1 ,nullptr },  // Inst #639 = JMPret
  { 640,	2,	0,	4,	24,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0xfc00000303ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #640 = JMPretf
  { 641,	2,	0,	4,	24,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0xfc00000703ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #641 = JMPretfnew
  { 642,	2,	0,	4,	24,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x80fc00000703ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #642 = JMPretfnewpt
  { 643,	2,	0,	4,	24,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0xfc00000103ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #643 = JMPrett
  { 644,	2,	0,	4,	24,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0xfc00000503ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #644 = JMPrettnew
  { 645,	2,	0,	4,	24,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x80fc00000503ULL, nullptr, ImplicitList7, OperandInfo56, -1 ,nullptr },  // Inst #645 = JMPrettnewpt
  { 646,	0,	0,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, ImplicitList6, ImplicitList5, nullptr, -1 ,nullptr },  // Inst #646 = L2_deallocframe
  { 647,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xbfc5da00005ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #647 = L2_loadalignb_io
  { 648,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x8fc00000005ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #648 = L2_loadalignb_pbr
  { 649,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x8fc00000005ULL, ImplicitList21, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #649 = L2_loadalignb_pci
  { 650,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x8fc00000005ULL, ImplicitList21, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #650 = L2_loadalignb_pcr
  { 651,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00000005ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #651 = L2_loadalignb_pi
  { 652,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00000005ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #652 = L2_loadalignb_pr
  { 653,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x13fd65a00005ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #653 = L2_loadalignh_io
  { 654,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00000005ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #654 = L2_loadalignh_pbr
  { 655,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fd00000005ULL, ImplicitList21, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #655 = L2_loadalignh_pci
  { 656,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00000005ULL, ImplicitList21, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #656 = L2_loadalignh_pcr
  { 657,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00000005ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #657 = L2_loadalignh_pi
  { 658,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fc00000005ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #658 = L2_loadalignh_pr
  { 659,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fd65202005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #659 = L2_loadbsw2_io
  { 660,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #660 = L2_loadbsw2_pbr
  { 661,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, ImplicitList21, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #661 = L2_loadbsw2_pci
  { 662,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, ImplicitList21, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #662 = L2_loadbsw2_pcr
  { 663,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00002005ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #663 = L2_loadbsw2_pi
  { 664,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #664 = L2_loadbsw2_pr
  { 665,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fe6d200005ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #665 = L2_loadbsw4_io
  { 666,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x18fc00000005ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #666 = L2_loadbsw4_pbr
  { 667,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x18fc00000005ULL, ImplicitList21, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #667 = L2_loadbsw4_pci
  { 668,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x18fc00000005ULL, ImplicitList21, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #668 = L2_loadbsw4_pcr
  { 669,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1efe00000005ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #669 = L2_loadbsw4_pi
  { 670,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1efc00000005ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #670 = L2_loadbsw4_pr
  { 671,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fd65202005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #671 = L2_loadbzw2_io
  { 672,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #672 = L2_loadbzw2_pbr
  { 673,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, ImplicitList21, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #673 = L2_loadbzw2_pci
  { 674,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, ImplicitList21, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #674 = L2_loadbzw2_pcr
  { 675,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00002005ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #675 = L2_loadbzw2_pi
  { 676,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #676 = L2_loadbzw2_pr
  { 677,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fe6d200005ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #677 = L2_loadbzw4_io
  { 678,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x18fc00000005ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #678 = L2_loadbzw4_pbr
  { 679,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x18fc00000005ULL, ImplicitList21, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #679 = L2_loadbzw4_pci
  { 680,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x18fc00000005ULL, ImplicitList21, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #680 = L2_loadbzw4_pcr
  { 681,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1efe00000005ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #681 = L2_loadbzw4_pi
  { 682,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1efc00000005ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #682 = L2_loadbzw4_pr
  { 683,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0xbfc5d202005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #683 = L2_loadrb_io
  { 684,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x8fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #684 = L2_loadrb_pbr
  { 685,	5,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #685 = L2_loadrb_pbr_pseudo
  { 686,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x8fc00002005ULL, ImplicitList21, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #686 = L2_loadrb_pci
  { 687,	6,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #687 = L2_loadrb_pci_pseudo
  { 688,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x8fc00002005ULL, ImplicitList21, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #688 = L2_loadrb_pcr
  { 689,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0xefc00002005ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #689 = L2_loadrb_pi
  { 690,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #690 = L2_loadrb_pr
  { 691,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x8fc00002005ULL, ImplicitList22, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #691 = L2_loadrbgp
  { 692,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x23ff75200005ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #692 = L2_loadrd_io
  { 693,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x20fc00000005ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #693 = L2_loadrd_pbr
  { 694,	5,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #694 = L2_loadrd_pbr_pseudo
  { 695,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x20fc00000005ULL, ImplicitList21, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #695 = L2_loadrd_pci
  { 696,	6,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo88, -1 ,nullptr },  // Inst #696 = L2_loadrd_pci_pseudo
  { 697,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x20fc00000005ULL, ImplicitList21, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #697 = L2_loadrd_pcr
  { 698,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x26ff00000005ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #698 = L2_loadrd_pi
  { 699,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x26fc00000005ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #699 = L2_loadrd_pr
  { 700,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x20fc00000005ULL, ImplicitList22, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #700 = L2_loadrdgp
  { 701,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x13fd65202005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #701 = L2_loadrh_io
  { 702,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #702 = L2_loadrh_pbr
  { 703,	5,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #703 = L2_loadrh_pbr_pseudo
  { 704,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, ImplicitList21, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #704 = L2_loadrh_pci
  { 705,	6,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #705 = L2_loadrh_pci_pseudo
  { 706,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, ImplicitList21, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #706 = L2_loadrh_pcr
  { 707,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x16fd00002005ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #707 = L2_loadrh_pi
  { 708,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #708 = L2_loadrh_pr
  { 709,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x10fc00002005ULL, ImplicitList22, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #709 = L2_loadrhgp
  { 710,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x1bfe6d202005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #710 = L2_loadri_io
  { 711,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x18fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #711 = L2_loadri_pbr
  { 712,	5,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #712 = L2_loadri_pbr_pseudo
  { 713,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x18fc00002005ULL, ImplicitList21, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #713 = L2_loadri_pci
  { 714,	6,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #714 = L2_loadri_pci_pseudo
  { 715,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x18fc00002005ULL, ImplicitList21, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #715 = L2_loadri_pcr
  { 716,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x1efe00002005ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #716 = L2_loadri_pi
  { 717,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1efc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #717 = L2_loadri_pr
  { 718,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x18fc00002005ULL, ImplicitList22, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #718 = L2_loadrigp
  { 719,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0xbfc5d202005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #719 = L2_loadrub_io
  { 720,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x8fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #720 = L2_loadrub_pbr
  { 721,	5,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #721 = L2_loadrub_pbr_pseudo
  { 722,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x8fc00002005ULL, ImplicitList21, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #722 = L2_loadrub_pci
  { 723,	6,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #723 = L2_loadrub_pci_pseudo
  { 724,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x8fc00002005ULL, ImplicitList21, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #724 = L2_loadrub_pcr
  { 725,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0xefc00002005ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #725 = L2_loadrub_pi
  { 726,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #726 = L2_loadrub_pr
  { 727,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x8fc00002005ULL, ImplicitList22, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #727 = L2_loadrubgp
  { 728,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x13fd65202005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #728 = L2_loadruh_io
  { 729,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #729 = L2_loadruh_pbr
  { 730,	5,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #730 = L2_loadruh_pbr_pseudo
  { 731,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, ImplicitList21, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #731 = L2_loadruh_pci
  { 732,	6,	2,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc00000005ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #732 = L2_loadruh_pci_pseudo
  { 733,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x10fc00002005ULL, ImplicitList21, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #733 = L2_loadruh_pcr
  { 734,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x16fd00002005ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #734 = L2_loadruh_pi
  { 735,	4,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fc00002005ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #735 = L2_loadruh_pr
  { 736,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x10fc00002005ULL, ImplicitList22, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #736 = L2_loadruhgp
  { 737,	2,	1,	4,	39,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x18fc00002045ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #737 = L2_loadw_locked
  { 738,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0xbfc31a02305ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #738 = L2_ploadrbf_io
  { 739,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00002305ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #739 = L2_ploadrbf_pi
  { 740,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0xbfc31a02705ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #740 = L2_ploadrbfnew_io
  { 741,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00002705ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #741 = L2_ploadrbfnew_pi
  { 742,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0xbfc31a02105ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #742 = L2_ploadrbt_io
  { 743,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00002105ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #743 = L2_ploadrbt_pi
  { 744,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0xbfc31a02505ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #744 = L2_ploadrbtnew_io
  { 745,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00002505ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #745 = L2_ploadrbtnew_pi
  { 746,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x23ff49a00305ULL, nullptr, nullptr, OperandInfo90, -1 ,nullptr },  // Inst #746 = L2_ploadrdf_io
  { 747,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x26ff00000305ULL, nullptr, nullptr, OperandInfo91, -1 ,nullptr },  // Inst #747 = L2_ploadrdf_pi
  { 748,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x23ff49a00705ULL, nullptr, nullptr, OperandInfo90, -1 ,nullptr },  // Inst #748 = L2_ploadrdfnew_io
  { 749,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x26ff00000705ULL, nullptr, nullptr, OperandInfo91, -1 ,nullptr },  // Inst #749 = L2_ploadrdfnew_pi
  { 750,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x23ff49a00105ULL, nullptr, nullptr, OperandInfo90, -1 ,nullptr },  // Inst #750 = L2_ploadrdt_io
  { 751,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x26ff00000105ULL, nullptr, nullptr, OperandInfo91, -1 ,nullptr },  // Inst #751 = L2_ploadrdt_pi
  { 752,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x23ff49a00505ULL, nullptr, nullptr, OperandInfo90, -1 ,nullptr },  // Inst #752 = L2_ploadrdtnew_io
  { 753,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x26ff00000505ULL, nullptr, nullptr, OperandInfo91, -1 ,nullptr },  // Inst #753 = L2_ploadrdtnew_pi
  { 754,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x13fd39a02305ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #754 = L2_ploadrhf_io
  { 755,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00002305ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #755 = L2_ploadrhf_pi
  { 756,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x13fd39a02705ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #756 = L2_ploadrhfnew_io
  { 757,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00002705ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #757 = L2_ploadrhfnew_pi
  { 758,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x13fd39a02105ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #758 = L2_ploadrht_io
  { 759,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00002105ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #759 = L2_ploadrht_pi
  { 760,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x13fd39a02505ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #760 = L2_ploadrhtnew_io
  { 761,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00002505ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #761 = L2_ploadrhtnew_pi
  { 762,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x1bfe41a02305ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #762 = L2_ploadrif_io
  { 763,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1efe00002305ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #763 = L2_ploadrif_pi
  { 764,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x1bfe41a02705ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #764 = L2_ploadrifnew_io
  { 765,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1efe00002705ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #765 = L2_ploadrifnew_pi
  { 766,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x1bfe41a02105ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #766 = L2_ploadrit_io
  { 767,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1efe00002105ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #767 = L2_ploadrit_pi
  { 768,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x1bfe41a02505ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #768 = L2_ploadritnew_io
  { 769,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1efe00002505ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #769 = L2_ploadritnew_pi
  { 770,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0xbfc31a02305ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #770 = L2_ploadrubf_io
  { 771,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00002305ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #771 = L2_ploadrubf_pi
  { 772,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0xbfc31a02705ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #772 = L2_ploadrubfnew_io
  { 773,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00002705ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #773 = L2_ploadrubfnew_pi
  { 774,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0xbfc31a02105ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #774 = L2_ploadrubt_io
  { 775,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00002105ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #775 = L2_ploadrubt_pi
  { 776,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0xbfc31a02505ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #776 = L2_ploadrubtnew_io
  { 777,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xefc00002505ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #777 = L2_ploadrubtnew_pi
  { 778,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x13fd39a02305ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #778 = L2_ploadruhf_io
  { 779,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00002305ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #779 = L2_ploadruhf_pi
  { 780,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x13fd39a02705ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #780 = L2_ploadruhfnew_io
  { 781,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00002705ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #781 = L2_ploadruhfnew_pi
  { 782,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x13fd39a02105ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #782 = L2_ploadruht_io
  { 783,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00002105ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #783 = L2_ploadruht_pi
  { 784,	4,	1,	4,	38,	0|(1ULL<<MCID::MayLoad), 0x13fd39a02505ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #784 = L2_ploadruhtnew_io
  { 785,	5,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x16fd00002505ULL, nullptr, nullptr, OperandInfo89, -1 ,nullptr },  // Inst #785 = L2_ploadruhtnew_pi
  { 786,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x8fc30a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #786 = L4_add_memopb_io
  { 787,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10fd38a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #787 = L4_add_memoph_io
  { 788,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x18fe40a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #788 = L4_add_memopw_io
  { 789,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x8fc30a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #789 = L4_and_memopb_io
  { 790,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10fd38a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #790 = L4_and_memoph_io
  { 791,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x18fe40a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #791 = L4_and_memopw_io
  { 792,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x8fc30a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #792 = L4_iadd_memopb_io
  { 793,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10fd38a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #793 = L4_iadd_memoph_io
  { 794,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x18fe40a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #794 = L4_iadd_memopw_io
  { 795,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x8fc30a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #795 = L4_iand_memopb_io
  { 796,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10fd38a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #796 = L4_iand_memoph_io
  { 797,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x18fe40a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #797 = L4_iand_memopw_io
  { 798,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x8fc30a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #798 = L4_ior_memopb_io
  { 799,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10fd38a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #799 = L4_ior_memoph_io
  { 800,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x18fe40a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #800 = L4_ior_memopw_io
  { 801,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x8fc30a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #801 = L4_isub_memopb_io
  { 802,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10fd38a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #802 = L4_isub_memoph_io
  { 803,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x18fe40a00009ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #803 = L4_isub_memopw_io
  { 804,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xafc31400005ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #804 = L4_loadalignb_ap
  { 805,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0xcfc31c00005ULL, nullptr, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #805 = L4_loadalignb_ur
  { 806,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x12fc31400005ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #806 = L4_loadalignh_ap
  { 807,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x14fc31c00005ULL, nullptr, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #807 = L4_loadalignh_ur
  { 808,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x12fc31402005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #808 = L4_loadbsw2_ap
  { 809,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x14fc31c02005ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #809 = L4_loadbsw2_ur
  { 810,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1afc31400005ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #810 = L4_loadbsw4_ap
  { 811,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x1cfc31c00005ULL, nullptr, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #811 = L4_loadbsw4_ur
  { 812,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x12fc31402005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #812 = L4_loadbzw2_ap
  { 813,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x14fc31c02005ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #813 = L4_loadbzw2_ur
  { 814,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1afc31400005ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #814 = L4_loadbzw4_ap
  { 815,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x1cfc31c00005ULL, nullptr, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #815 = L4_loadbzw4_ur
  { 816,	2,	1,	4,	39,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x20fc00000045ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #816 = L4_loadd_locked
  { 817,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x9fc80c02005ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #817 = L4_loadrb_abs
  { 818,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xafc31402005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #818 = L4_loadrb_ap
  { 819,	4,	1,	4,	41,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0xdfc00002005ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #819 = L4_loadrb_rr
  { 820,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xcfc31c02005ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #820 = L4_loadrb_ur
  { 821,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x21ff98c00005ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #821 = L4_loadrd_abs
  { 822,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x22fc31400005ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #822 = L4_loadrd_ap
  { 823,	4,	1,	4,	41,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x25fc00000005ULL, nullptr, nullptr, OperandInfo96, -1 ,nullptr },  // Inst #823 = L4_loadrd_rr
  { 824,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x24fc31c00005ULL, nullptr, nullptr, OperandInfo93, -1 ,nullptr },  // Inst #824 = L4_loadrd_ur
  { 825,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x11fd88c02005ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #825 = L4_loadrh_abs
  { 826,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x12fc31402005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #826 = L4_loadrh_ap
  { 827,	4,	1,	4,	41,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x15fc00002005ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #827 = L4_loadrh_rr
  { 828,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x14fc31c02005ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #828 = L4_loadrh_ur
  { 829,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x19fe90c02005ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #829 = L4_loadri_abs
  { 830,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1afc31402005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #830 = L4_loadri_ap
  { 831,	4,	1,	4,	41,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x1dfc00002005ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #831 = L4_loadri_rr
  { 832,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x1cfc31c02005ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #832 = L4_loadri_ur
  { 833,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x9fc80c02005ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #833 = L4_loadrub_abs
  { 834,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xafc31402005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #834 = L4_loadrub_ap
  { 835,	4,	1,	4,	41,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0xdfc00002005ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #835 = L4_loadrub_rr
  { 836,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0xcfc31c02005ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #836 = L4_loadrub_ur
  { 837,	2,	1,	4,	38,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x11fd88c02005ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #837 = L4_loadruh_abs
  { 838,	3,	2,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x12fc31402005ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #838 = L4_loadruh_ap
  { 839,	4,	1,	4,	41,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable), 0x15fc00002005ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #839 = L4_loadruh_rr
  { 840,	4,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x14fc31c02005ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #840 = L4_loadruh_ur
  { 841,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x8fc30a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #841 = L4_or_memopb_io
  { 842,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10fd38a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #842 = L4_or_memoph_io
  { 843,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x18fe40a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #843 = L4_or_memopw_io
  { 844,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x9fc31402305ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #844 = L4_ploadrbf_abs
  { 845,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0xdfc00002305ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #845 = L4_ploadrbf_rr
  { 846,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x9fc31402705ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #846 = L4_ploadrbfnew_abs
  { 847,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0xdfc00002705ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #847 = L4_ploadrbfnew_rr
  { 848,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x9fc31402105ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #848 = L4_ploadrbt_abs
  { 849,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0xdfc00002105ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #849 = L4_ploadrbt_rr
  { 850,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x9fc31402505ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #850 = L4_ploadrbtnew_abs
  { 851,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0xdfc00002505ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #851 = L4_ploadrbtnew_rr
  { 852,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x21fc31400305ULL, nullptr, nullptr, OperandInfo98, -1 ,nullptr },  // Inst #852 = L4_ploadrdf_abs
  { 853,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x25fc00000305ULL, nullptr, nullptr, OperandInfo99, -1 ,nullptr },  // Inst #853 = L4_ploadrdf_rr
  { 854,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x21fc31400705ULL, nullptr, nullptr, OperandInfo98, -1 ,nullptr },  // Inst #854 = L4_ploadrdfnew_abs
  { 855,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x25fc00000705ULL, nullptr, nullptr, OperandInfo99, -1 ,nullptr },  // Inst #855 = L4_ploadrdfnew_rr
  { 856,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x21fc31400105ULL, nullptr, nullptr, OperandInfo98, -1 ,nullptr },  // Inst #856 = L4_ploadrdt_abs
  { 857,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x25fc00000105ULL, nullptr, nullptr, OperandInfo99, -1 ,nullptr },  // Inst #857 = L4_ploadrdt_rr
  { 858,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x21fc31400505ULL, nullptr, nullptr, OperandInfo98, -1 ,nullptr },  // Inst #858 = L4_ploadrdtnew_abs
  { 859,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x25fc00000505ULL, nullptr, nullptr, OperandInfo99, -1 ,nullptr },  // Inst #859 = L4_ploadrdtnew_rr
  { 860,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x11fc31402305ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #860 = L4_ploadrhf_abs
  { 861,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x15fc00002305ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #861 = L4_ploadrhf_rr
  { 862,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x11fc31402705ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #862 = L4_ploadrhfnew_abs
  { 863,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x15fc00002705ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #863 = L4_ploadrhfnew_rr
  { 864,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x11fc31402105ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #864 = L4_ploadrht_abs
  { 865,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x15fc00002105ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #865 = L4_ploadrht_rr
  { 866,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x11fc31402505ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #866 = L4_ploadrhtnew_abs
  { 867,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x15fc00002505ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #867 = L4_ploadrhtnew_rr
  { 868,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x19fc31402305ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #868 = L4_ploadrif_abs
  { 869,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x1dfc00002305ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #869 = L4_ploadrif_rr
  { 870,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x19fc31402705ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #870 = L4_ploadrifnew_abs
  { 871,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x1dfc00002705ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #871 = L4_ploadrifnew_rr
  { 872,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x19fc31402105ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #872 = L4_ploadrit_abs
  { 873,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x1dfc00002105ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #873 = L4_ploadrit_rr
  { 874,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x19fc31402505ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #874 = L4_ploadritnew_abs
  { 875,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x1dfc00002505ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #875 = L4_ploadritnew_rr
  { 876,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x9fc31402305ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #876 = L4_ploadrubf_abs
  { 877,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0xdfc00002305ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #877 = L4_ploadrubf_rr
  { 878,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x9fc31402705ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #878 = L4_ploadrubfnew_abs
  { 879,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0xdfc00002705ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #879 = L4_ploadrubfnew_rr
  { 880,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x9fc31402105ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #880 = L4_ploadrubt_abs
  { 881,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0xdfc00002105ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #881 = L4_ploadrubt_rr
  { 882,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x9fc31402505ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #882 = L4_ploadrubtnew_abs
  { 883,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0xdfc00002505ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #883 = L4_ploadrubtnew_rr
  { 884,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x11fc31402305ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #884 = L4_ploadruhf_abs
  { 885,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x15fc00002305ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #885 = L4_ploadruhf_rr
  { 886,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x11fc31402705ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #886 = L4_ploadruhfnew_abs
  { 887,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x15fc00002705ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #887 = L4_ploadruhfnew_rr
  { 888,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x11fc31402105ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #888 = L4_ploadruht_abs
  { 889,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x15fc00002105ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #889 = L4_ploadruht_rr
  { 890,	3,	1,	4,	26,	0|(1ULL<<MCID::MayLoad), 0x11fc31402505ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #890 = L4_ploadruhtnew_abs
  { 891,	5,	1,	4,	41,	0|(1ULL<<MCID::MayLoad), 0x15fc00002505ULL, nullptr, nullptr, OperandInfo97, -1 ,nullptr },  // Inst #891 = L4_ploadruhtnew_rr
  { 892,	0,	0,	4,	42,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0xfc00000005ULL, ImplicitList6, ImplicitList23, nullptr, -1 ,nullptr },  // Inst #892 = L4_return
  { 893,	1,	0,	4,	42,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0x80fc00000305ULL, ImplicitList6, ImplicitList23, OperandInfo100, -1 ,nullptr },  // Inst #893 = L4_return_f
  { 894,	1,	0,	4,	42,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xfc00000705ULL, ImplicitList6, ImplicitList23, OperandInfo100, -1 ,nullptr },  // Inst #894 = L4_return_fnew_pnt
  { 895,	1,	0,	4,	42,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0x80fc00000705ULL, ImplicitList6, ImplicitList23, OperandInfo100, -1 ,nullptr },  // Inst #895 = L4_return_fnew_pt
  { 896,	1,	0,	4,	42,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0x80fc00000105ULL, ImplicitList6, ImplicitList23, OperandInfo100, -1 ,nullptr },  // Inst #896 = L4_return_t
  { 897,	1,	0,	4,	42,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xfc00000505ULL, ImplicitList6, ImplicitList23, OperandInfo100, -1 ,nullptr },  // Inst #897 = L4_return_tnew_pnt
  { 898,	1,	0,	4,	42,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0x80fc00000505ULL, ImplicitList6, ImplicitList23, OperandInfo100, -1 ,nullptr },  // Inst #898 = L4_return_tnew_pt
  { 899,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x8fc30a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #899 = L4_sub_memopb_io
  { 900,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x10fd38a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #900 = L4_sub_memoph_io
  { 901,	3,	0,	4,	40,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x18fe40a00009ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #901 = L4_sub_memopw_io
  { 902,	3,	1,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfe6d200005ULL, nullptr, nullptr, OperandInfo101, -1 ,nullptr },  // Inst #902 = LDriq_pred_V6
  { 903,	3,	1,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfe6d200005ULL, nullptr, nullptr, OperandInfo102, -1 ,nullptr },  // Inst #903 = LDriq_pred_V6_128B
  { 904,	3,	1,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfe6d200005ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #904 = LDriq_pred_vec_V6
  { 905,	3,	1,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfe6d200005ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #905 = LDriq_pred_vec_V6_128B
  { 906,	3,	1,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfe6d200005ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #906 = LDriv_pseudo_V6
  { 907,	3,	1,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfe6d200005ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #907 = LDriv_pseudo_V6_128B
  { 908,	3,	1,	4,	43,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xe000000015ULL, nullptr, nullptr, OperandInfo105, -1 ,nullptr },  // Inst #908 = LDrivv_indexed
  { 909,	3,	1,	4,	43,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xe000000015ULL, nullptr, nullptr, OperandInfo106, -1 ,nullptr },  // Inst #909 = LDrivv_indexed_128B
  { 910,	3,	1,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfe6d200005ULL, nullptr, nullptr, OperandInfo105, -1 ,nullptr },  // Inst #910 = LDrivv_pseudo_V6
  { 911,	3,	1,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfe6d200005ULL, nullptr, nullptr, OperandInfo106, -1 ,nullptr },  // Inst #911 = LDrivv_pseudo_V6_128B
  { 912,	3,	1,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc6d200005ULL, nullptr, nullptr, OperandInfo107, -1 ,nullptr },  // Inst #912 = LDriw_mod
  { 913,	3,	1,	4,	26,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0xfc6d200005ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #913 = LDriw_pred
  { 914,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #914 = LO
  { 915,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable), 0xfc00000001ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #915 = LO_GOT
  { 916,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable), 0xfc00000001ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #916 = LO_GOTREL
  { 917,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable), 0xfc00002001ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #917 = LO_H
  { 918,	2,	1,	4,	8,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000001ULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #918 = LO_PIC
  { 919,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #919 = M2_acci
  { 920,	4,	1,	4,	44,	0, 0xfc45a02008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #920 = M2_accii
  { 921,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #921 = M2_cmaci_s0
  { 922,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #922 = M2_cmacr_s0
  { 923,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #923 = M2_cmacs_s0
  { 924,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #924 = M2_cmacs_s1
  { 925,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #925 = M2_cmacsc_s0
  { 926,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #926 = M2_cmacsc_s1
  { 927,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #927 = M2_cmpyi_s0
  { 928,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #928 = M2_cmpyr_s0
  { 929,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #929 = M2_cmpyrs_s0
  { 930,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #930 = M2_cmpyrs_s1
  { 931,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #931 = M2_cmpyrsc_s0
  { 932,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #932 = M2_cmpyrsc_s1
  { 933,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #933 = M2_cmpys_s0
  { 934,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #934 = M2_cmpys_s1
  { 935,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #935 = M2_cmpysc_s0
  { 936,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #936 = M2_cmpysc_s1
  { 937,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #937 = M2_cnacs_s0
  { 938,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #938 = M2_cnacs_s1
  { 939,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #939 = M2_cnacsc_s0
  { 940,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #940 = M2_cnacsc_s1
  { 941,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #941 = M2_dpmpyss_acc_s0
  { 942,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #942 = M2_dpmpyss_nac_s0
  { 943,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #943 = M2_dpmpyss_rnd_s0
  { 944,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #944 = M2_dpmpyss_s0
  { 945,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #945 = M2_dpmpyuu_acc_s0
  { 946,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #946 = M2_dpmpyuu_nac_s0
  { 947,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #947 = M2_dpmpyuu_s0
  { 948,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #948 = M2_hmmpyh_rs1
  { 949,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #949 = M2_hmmpyh_s1
  { 950,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #950 = M2_hmmpyl_rs1
  { 951,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #951 = M2_hmmpyl_s1
  { 952,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #952 = M2_maci
  { 953,	4,	1,	4,	11,	0, 0xfc41a02008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #953 = M2_macsin
  { 954,	4,	1,	4,	11,	0, 0xfc41a02008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #954 = M2_macsip
  { 955,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #955 = M2_mmachs_rs0
  { 956,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #956 = M2_mmachs_rs1
  { 957,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #957 = M2_mmachs_s0
  { 958,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #958 = M2_mmachs_s1
  { 959,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #959 = M2_mmacls_rs0
  { 960,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #960 = M2_mmacls_rs1
  { 961,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #961 = M2_mmacls_s0
  { 962,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #962 = M2_mmacls_s1
  { 963,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #963 = M2_mmacuhs_rs0
  { 964,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #964 = M2_mmacuhs_rs1
  { 965,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #965 = M2_mmacuhs_s0
  { 966,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #966 = M2_mmacuhs_s1
  { 967,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #967 = M2_mmaculs_rs0
  { 968,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #968 = M2_mmaculs_rs1
  { 969,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #969 = M2_mmaculs_s0
  { 970,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #970 = M2_mmaculs_s1
  { 971,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #971 = M2_mmpyh_rs0
  { 972,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #972 = M2_mmpyh_rs1
  { 973,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #973 = M2_mmpyh_s0
  { 974,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #974 = M2_mmpyh_s1
  { 975,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #975 = M2_mmpyl_rs0
  { 976,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #976 = M2_mmpyl_rs1
  { 977,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #977 = M2_mmpyl_s0
  { 978,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #978 = M2_mmpyl_s1
  { 979,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #979 = M2_mmpyuh_rs0
  { 980,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #980 = M2_mmpyuh_rs1
  { 981,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #981 = M2_mmpyuh_s0
  { 982,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #982 = M2_mmpyuh_s1
  { 983,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #983 = M2_mmpyul_rs0
  { 984,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #984 = M2_mmpyul_rs1
  { 985,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #985 = M2_mmpyul_s0
  { 986,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #986 = M2_mmpyul_s1
  { 987,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #987 = M2_mpy_acc_hh_s0
  { 988,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #988 = M2_mpy_acc_hh_s1
  { 989,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #989 = M2_mpy_acc_hl_s0
  { 990,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #990 = M2_mpy_acc_hl_s1
  { 991,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #991 = M2_mpy_acc_lh_s0
  { 992,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #992 = M2_mpy_acc_lh_s1
  { 993,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #993 = M2_mpy_acc_ll_s0
  { 994,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #994 = M2_mpy_acc_ll_s1
  { 995,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #995 = M2_mpy_acc_sat_hh_s0
  { 996,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #996 = M2_mpy_acc_sat_hh_s1
  { 997,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #997 = M2_mpy_acc_sat_hl_s0
  { 998,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #998 = M2_mpy_acc_sat_hl_s1
  { 999,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #999 = M2_mpy_acc_sat_lh_s0
  { 1000,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1000 = M2_mpy_acc_sat_lh_s1
  { 1001,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1001 = M2_mpy_acc_sat_ll_s0
  { 1002,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1002 = M2_mpy_acc_sat_ll_s1
  { 1003,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1003 = M2_mpy_hh_s0
  { 1004,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1004 = M2_mpy_hh_s1
  { 1005,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1005 = M2_mpy_hl_s0
  { 1006,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1006 = M2_mpy_hl_s1
  { 1007,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1007 = M2_mpy_lh_s0
  { 1008,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1008 = M2_mpy_lh_s1
  { 1009,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1009 = M2_mpy_ll_s0
  { 1010,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1010 = M2_mpy_ll_s1
  { 1011,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1011 = M2_mpy_nac_hh_s0
  { 1012,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1012 = M2_mpy_nac_hh_s1
  { 1013,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1013 = M2_mpy_nac_hl_s0
  { 1014,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1014 = M2_mpy_nac_hl_s1
  { 1015,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1015 = M2_mpy_nac_lh_s0
  { 1016,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1016 = M2_mpy_nac_lh_s1
  { 1017,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1017 = M2_mpy_nac_ll_s0
  { 1018,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1018 = M2_mpy_nac_ll_s1
  { 1019,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1019 = M2_mpy_nac_sat_hh_s0
  { 1020,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1020 = M2_mpy_nac_sat_hh_s1
  { 1021,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1021 = M2_mpy_nac_sat_hl_s0
  { 1022,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1022 = M2_mpy_nac_sat_hl_s1
  { 1023,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1023 = M2_mpy_nac_sat_lh_s0
  { 1024,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1024 = M2_mpy_nac_sat_lh_s1
  { 1025,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1025 = M2_mpy_nac_sat_ll_s0
  { 1026,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1026 = M2_mpy_nac_sat_ll_s1
  { 1027,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1027 = M2_mpy_rnd_hh_s0
  { 1028,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1028 = M2_mpy_rnd_hh_s1
  { 1029,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1029 = M2_mpy_rnd_hl_s0
  { 1030,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1030 = M2_mpy_rnd_hl_s1
  { 1031,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1031 = M2_mpy_rnd_lh_s0
  { 1032,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1032 = M2_mpy_rnd_lh_s1
  { 1033,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1033 = M2_mpy_rnd_ll_s0
  { 1034,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1034 = M2_mpy_rnd_ll_s1
  { 1035,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1035 = M2_mpy_sat_hh_s0
  { 1036,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1036 = M2_mpy_sat_hh_s1
  { 1037,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1037 = M2_mpy_sat_hl_s0
  { 1038,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1038 = M2_mpy_sat_hl_s1
  { 1039,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1039 = M2_mpy_sat_lh_s0
  { 1040,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1040 = M2_mpy_sat_lh_s1
  { 1041,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1041 = M2_mpy_sat_ll_s0
  { 1042,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1042 = M2_mpy_sat_ll_s1
  { 1043,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1043 = M2_mpy_sat_rnd_hh_s0
  { 1044,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1044 = M2_mpy_sat_rnd_hh_s1
  { 1045,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1045 = M2_mpy_sat_rnd_hl_s0
  { 1046,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1046 = M2_mpy_sat_rnd_hl_s1
  { 1047,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1047 = M2_mpy_sat_rnd_lh_s0
  { 1048,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1048 = M2_mpy_sat_rnd_lh_s1
  { 1049,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1049 = M2_mpy_sat_rnd_ll_s0
  { 1050,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1050 = M2_mpy_sat_rnd_ll_s1
  { 1051,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1051 = M2_mpy_up
  { 1052,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1052 = M2_mpy_up_s1
  { 1053,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1053 = M2_mpy_up_s1_sat
  { 1054,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1054 = M2_mpyd_acc_hh_s0
  { 1055,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1055 = M2_mpyd_acc_hh_s1
  { 1056,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1056 = M2_mpyd_acc_hl_s0
  { 1057,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1057 = M2_mpyd_acc_hl_s1
  { 1058,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1058 = M2_mpyd_acc_lh_s0
  { 1059,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1059 = M2_mpyd_acc_lh_s1
  { 1060,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1060 = M2_mpyd_acc_ll_s0
  { 1061,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1061 = M2_mpyd_acc_ll_s1
  { 1062,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1062 = M2_mpyd_hh_s0
  { 1063,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1063 = M2_mpyd_hh_s1
  { 1064,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1064 = M2_mpyd_hl_s0
  { 1065,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1065 = M2_mpyd_hl_s1
  { 1066,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1066 = M2_mpyd_lh_s0
  { 1067,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1067 = M2_mpyd_lh_s1
  { 1068,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1068 = M2_mpyd_ll_s0
  { 1069,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1069 = M2_mpyd_ll_s1
  { 1070,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1070 = M2_mpyd_nac_hh_s0
  { 1071,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1071 = M2_mpyd_nac_hh_s1
  { 1072,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1072 = M2_mpyd_nac_hl_s0
  { 1073,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1073 = M2_mpyd_nac_hl_s1
  { 1074,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1074 = M2_mpyd_nac_lh_s0
  { 1075,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1075 = M2_mpyd_nac_lh_s1
  { 1076,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1076 = M2_mpyd_nac_ll_s0
  { 1077,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1077 = M2_mpyd_nac_ll_s1
  { 1078,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1078 = M2_mpyd_rnd_hh_s0
  { 1079,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1079 = M2_mpyd_rnd_hh_s1
  { 1080,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1080 = M2_mpyd_rnd_hl_s0
  { 1081,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1081 = M2_mpyd_rnd_hl_s1
  { 1082,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1082 = M2_mpyd_rnd_lh_s0
  { 1083,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1083 = M2_mpyd_rnd_lh_s1
  { 1084,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1084 = M2_mpyd_rnd_ll_s0
  { 1085,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1085 = M2_mpyd_rnd_ll_s1
  { 1086,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1086 = M2_mpyi
  { 1087,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1087 = M2_mpysin
  { 1088,	3,	1,	4,	11,	0, 0xfc41202008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1088 = M2_mpysip
  { 1089,	3,	1,	4,	11,	0, 0xfc4d202008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1089 = M2_mpysmi
  { 1090,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1090 = M2_mpysu_up
  { 1091,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1091 = M2_mpyu_acc_hh_s0
  { 1092,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1092 = M2_mpyu_acc_hh_s1
  { 1093,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1093 = M2_mpyu_acc_hl_s0
  { 1094,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1094 = M2_mpyu_acc_hl_s1
  { 1095,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1095 = M2_mpyu_acc_lh_s0
  { 1096,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1096 = M2_mpyu_acc_lh_s1
  { 1097,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1097 = M2_mpyu_acc_ll_s0
  { 1098,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1098 = M2_mpyu_acc_ll_s1
  { 1099,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1099 = M2_mpyu_hh_s0
  { 1100,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1100 = M2_mpyu_hh_s1
  { 1101,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1101 = M2_mpyu_hl_s0
  { 1102,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1102 = M2_mpyu_hl_s1
  { 1103,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1103 = M2_mpyu_lh_s0
  { 1104,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1104 = M2_mpyu_lh_s1
  { 1105,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1105 = M2_mpyu_ll_s0
  { 1106,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1106 = M2_mpyu_ll_s1
  { 1107,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1107 = M2_mpyu_nac_hh_s0
  { 1108,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1108 = M2_mpyu_nac_hh_s1
  { 1109,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1109 = M2_mpyu_nac_hl_s0
  { 1110,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1110 = M2_mpyu_nac_hl_s1
  { 1111,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1111 = M2_mpyu_nac_lh_s0
  { 1112,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1112 = M2_mpyu_nac_lh_s1
  { 1113,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1113 = M2_mpyu_nac_ll_s0
  { 1114,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1114 = M2_mpyu_nac_ll_s1
  { 1115,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1115 = M2_mpyu_up
  { 1116,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1116 = M2_mpyud_acc_hh_s0
  { 1117,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1117 = M2_mpyud_acc_hh_s1
  { 1118,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1118 = M2_mpyud_acc_hl_s0
  { 1119,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1119 = M2_mpyud_acc_hl_s1
  { 1120,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1120 = M2_mpyud_acc_lh_s0
  { 1121,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1121 = M2_mpyud_acc_lh_s1
  { 1122,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1122 = M2_mpyud_acc_ll_s0
  { 1123,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1123 = M2_mpyud_acc_ll_s1
  { 1124,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1124 = M2_mpyud_hh_s0
  { 1125,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1125 = M2_mpyud_hh_s1
  { 1126,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1126 = M2_mpyud_hl_s0
  { 1127,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1127 = M2_mpyud_hl_s1
  { 1128,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1128 = M2_mpyud_lh_s0
  { 1129,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1129 = M2_mpyud_lh_s1
  { 1130,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1130 = M2_mpyud_ll_s0
  { 1131,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1131 = M2_mpyud_ll_s1
  { 1132,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1132 = M2_mpyud_nac_hh_s0
  { 1133,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1133 = M2_mpyud_nac_hh_s1
  { 1134,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1134 = M2_mpyud_nac_hl_s0
  { 1135,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1135 = M2_mpyud_nac_hl_s1
  { 1136,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1136 = M2_mpyud_nac_lh_s0
  { 1137,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1137 = M2_mpyud_nac_lh_s1
  { 1138,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1138 = M2_mpyud_nac_ll_s0
  { 1139,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1139 = M2_mpyud_nac_ll_s1
  { 1140,	3,	1,	4,	11,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1140 = M2_mpyui
  { 1141,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1141 = M2_nacci
  { 1142,	4,	1,	4,	44,	0, 0xfc45a02008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1142 = M2_naccii
  { 1143,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1143 = M2_subacc
  { 1144,	3,	1,	4,	44,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1144 = M2_vabsdiffh
  { 1145,	3,	1,	4,	44,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1145 = M2_vabsdiffw
  { 1146,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1146 = M2_vcmac_s0_sat_i
  { 1147,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1147 = M2_vcmac_s0_sat_r
  { 1148,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1148 = M2_vcmpy_s0_sat_i
  { 1149,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1149 = M2_vcmpy_s0_sat_r
  { 1150,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1150 = M2_vcmpy_s1_sat_i
  { 1151,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1151 = M2_vcmpy_s1_sat_r
  { 1152,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1152 = M2_vdmacs_s0
  { 1153,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1153 = M2_vdmacs_s1
  { 1154,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #1154 = M2_vdmpyrs_s0
  { 1155,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #1155 = M2_vdmpyrs_s1
  { 1156,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1156 = M2_vdmpys_s0
  { 1157,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1157 = M2_vdmpys_s1
  { 1158,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1158 = M2_vmac2
  { 1159,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1159 = M2_vmac2es
  { 1160,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1160 = M2_vmac2es_s0
  { 1161,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1161 = M2_vmac2es_s1
  { 1162,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1162 = M2_vmac2s_s0
  { 1163,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1163 = M2_vmac2s_s1
  { 1164,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1164 = M2_vmac2su_s0
  { 1165,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1165 = M2_vmac2su_s1
  { 1166,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1166 = M2_vmpy2es_s0
  { 1167,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1167 = M2_vmpy2es_s1
  { 1168,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1168 = M2_vmpy2s_s0
  { 1169,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1169 = M2_vmpy2s_s0pack
  { 1170,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1170 = M2_vmpy2s_s1
  { 1171,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1171 = M2_vmpy2s_s1pack
  { 1172,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1172 = M2_vmpy2su_s0
  { 1173,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1173 = M2_vmpy2su_s1
  { 1174,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #1174 = M2_vraddh
  { 1175,	3,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #1175 = M2_vradduh
  { 1176,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1176 = M2_vrcmaci_s0
  { 1177,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1177 = M2_vrcmaci_s0c
  { 1178,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1178 = M2_vrcmacr_s0
  { 1179,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1179 = M2_vrcmacr_s0c
  { 1180,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1180 = M2_vrcmpyi_s0
  { 1181,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1181 = M2_vrcmpyi_s0c
  { 1182,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1182 = M2_vrcmpyr_s0
  { 1183,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1183 = M2_vrcmpyr_s0c
  { 1184,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1184 = M2_vrcmpys_acc_s1
  { 1185,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1185 = M2_vrcmpys_acc_s1_h
  { 1186,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1186 = M2_vrcmpys_acc_s1_l
  { 1187,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1187 = M2_vrcmpys_s1
  { 1188,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1188 = M2_vrcmpys_s1_h
  { 1189,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1189 = M2_vrcmpys_s1_l
  { 1190,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #1190 = M2_vrcmpys_s1rp
  { 1191,	3,	1,	4,	11,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00002008ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #1191 = M2_vrcmpys_s1rp_h
  { 1192,	3,	1,	4,	11,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00002008ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #1192 = M2_vrcmpys_s1rp_l
  { 1193,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1193 = M2_vrmac_s0
  { 1194,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1194 = M2_vrmpy_s0
  { 1195,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1195 = M2_xor_xacc
  { 1196,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1196 = M4_and_and
  { 1197,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1197 = M4_and_andn
  { 1198,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1198 = M4_and_or
  { 1199,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1199 = M4_and_xor
  { 1200,	3,	1,	4,	45,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo111, -1 ,nullptr },  // Inst #1200 = M4_cmpyi_wh
  { 1201,	3,	1,	4,	45,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo111, -1 ,nullptr },  // Inst #1201 = M4_cmpyi_whc
  { 1202,	3,	1,	4,	45,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo111, -1 ,nullptr },  // Inst #1202 = M4_cmpyr_wh
  { 1203,	3,	1,	4,	45,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo111, -1 ,nullptr },  // Inst #1203 = M4_cmpyr_whc
  { 1204,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo62, -1 ,nullptr },  // Inst #1204 = M4_mac_up_s1_sat
  { 1205,	4,	1,	4,	30,	0, 0xfc30a02008ULL, nullptr, nullptr, OperandInfo112, -1 ,nullptr },  // Inst #1205 = M4_mpyri_addi
  { 1206,	4,	1,	4,	30,	0, 0xfc31a02008ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #1206 = M4_mpyri_addr
  { 1207,	4,	1,	4,	30,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #1207 = M4_mpyri_addr_u2
  { 1208,	4,	1,	4,	30,	0, 0xfc30a02008ULL, nullptr, nullptr, OperandInfo114, -1 ,nullptr },  // Inst #1208 = M4_mpyrr_addi
  { 1209,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo115, -1 ,nullptr },  // Inst #1209 = M4_mpyrr_addr
  { 1210,	4,	1,	4,	11,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo62, -1 ,nullptr },  // Inst #1210 = M4_nac_up_s1_sat
  { 1211,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1211 = M4_or_and
  { 1212,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1212 = M4_or_andn
  { 1213,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1213 = M4_or_or
  { 1214,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1214 = M4_or_xor
  { 1215,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1215 = M4_pmpyw
  { 1216,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1216 = M4_pmpyw_acc
  { 1217,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1217 = M4_vpmpyh
  { 1218,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1218 = M4_vpmpyh_acc
  { 1219,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1219 = M4_vrmpyeh_acc_s0
  { 1220,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1220 = M4_vrmpyeh_acc_s1
  { 1221,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1221 = M4_vrmpyeh_s0
  { 1222,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1222 = M4_vrmpyeh_s1
  { 1223,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1223 = M4_vrmpyoh_acc_s0
  { 1224,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1224 = M4_vrmpyoh_acc_s1
  { 1225,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1225 = M4_vrmpyoh_s0
  { 1226,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1226 = M4_vrmpyoh_s1
  { 1227,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1227 = M4_xor_and
  { 1228,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1228 = M4_xor_andn
  { 1229,	4,	1,	4,	44,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1229 = M4_xor_or
  { 1230,	4,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1230 = M4_xor_xacc
  { 1231,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo34, -1 ,nullptr },  // Inst #1231 = M5_vdmacbsu
  { 1232,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1232 = M5_vdmpybsu
  { 1233,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1233 = M5_vmacbsu
  { 1234,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo109, -1 ,nullptr },  // Inst #1234 = M5_vmacbuu
  { 1235,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1235 = M5_vmpybsu
  { 1236,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1236 = M5_vmpybuu
  { 1237,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1237 = M5_vrmacbsu
  { 1238,	4,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1238 = M5_vrmacbuu
  { 1239,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1239 = M5_vrmpybsu
  { 1240,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1240 = M5_vrmpybuu
  { 1241,	4,	1,	4,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000008ULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #1241 = MUX64_rr
  { 1242,	4,	1,	4,	8,	0|(1ULL<<MCID::Pseudo), 0xfc45c00001ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #1242 = MUX_ir_f
  { 1243,	4,	1,	4,	8,	0|(1ULL<<MCID::Pseudo), 0xfc45400001ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #1243 = MUX_ri_f
  { 1244,	1,	0,	4,	25,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0xfec4200004ULL, nullptr, ImplicitList23, OperandInfo5, -1 ,nullptr },  // Inst #1244 = RESTORE_DEALLOC_BEFORE_TAILCALL_V4
  { 1245,	1,	0,	4,	25,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0xfec4600004ULL, nullptr, ImplicitList23, OperandInfo5, -1 ,nullptr },  // Inst #1245 = RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT
  { 1246,	1,	0,	4,	25,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0xfec4200004ULL, nullptr, ImplicitList23, OperandInfo5, -1 ,nullptr },  // Inst #1246 = RESTORE_DEALLOC_RET_JMP_V4
  { 1247,	1,	0,	4,	25,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0xfec4600004ULL, nullptr, ImplicitList23, OperandInfo5, -1 ,nullptr },  // Inst #1247 = RESTORE_DEALLOC_RET_JMP_V4_EXT
  { 1248,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #1248 = S2_addasl_rrri
  { 1249,	1,	0,	4,	46,	0|(1ULL<<MCID::MayStore), 0x20fc00000006ULL, ImplicitList24, ImplicitList3, OperandInfo2, -1 ,nullptr },  // Inst #1249 = S2_allocframe
  { 1250,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1250 = S2_asl_i_p
  { 1251,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1251 = S2_asl_i_p_acc
  { 1252,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1252 = S2_asl_i_p_and
  { 1253,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1253 = S2_asl_i_p_nac
  { 1254,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1254 = S2_asl_i_p_or
  { 1255,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1255 = S2_asl_i_p_xacc
  { 1256,	3,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1256 = S2_asl_i_r
  { 1257,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1257 = S2_asl_i_r_acc
  { 1258,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1258 = S2_asl_i_r_and
  { 1259,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1259 = S2_asl_i_r_nac
  { 1260,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1260 = S2_asl_i_r_or
  { 1261,	3,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo16, -1 ,nullptr },  // Inst #1261 = S2_asl_i_r_sat
  { 1262,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1262 = S2_asl_i_r_xacc
  { 1263,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1263 = S2_asl_i_vh
  { 1264,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1264 = S2_asl_i_vw
  { 1265,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1265 = S2_asl_r_p
  { 1266,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1266 = S2_asl_r_p_acc
  { 1267,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1267 = S2_asl_r_p_and
  { 1268,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1268 = S2_asl_r_p_nac
  { 1269,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1269 = S2_asl_r_p_or
  { 1270,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1270 = S2_asl_r_p_xor
  { 1271,	3,	1,	4,	12,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1271 = S2_asl_r_r
  { 1272,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1272 = S2_asl_r_r_acc
  { 1273,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1273 = S2_asl_r_r_and
  { 1274,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1274 = S2_asl_r_r_nac
  { 1275,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1275 = S2_asl_r_r_or
  { 1276,	3,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1276 = S2_asl_r_r_sat
  { 1277,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1277 = S2_asl_r_vh
  { 1278,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1278 = S2_asl_r_vw
  { 1279,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1279 = S2_asr_i_p
  { 1280,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1280 = S2_asr_i_p_acc
  { 1281,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1281 = S2_asr_i_p_and
  { 1282,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1282 = S2_asr_i_p_nac
  { 1283,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1283 = S2_asr_i_p_or
  { 1284,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1284 = S2_asr_i_p_rnd
  { 1285,	3,	1,	4,	11,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1285 = S2_asr_i_p_rnd_goodsyntax
  { 1286,	3,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1286 = S2_asr_i_r
  { 1287,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1287 = S2_asr_i_r_acc
  { 1288,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1288 = S2_asr_i_r_and
  { 1289,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1289 = S2_asr_i_r_nac
  { 1290,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1290 = S2_asr_i_r_or
  { 1291,	3,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1291 = S2_asr_i_r_rnd
  { 1292,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1292 = S2_asr_i_r_rnd_goodsyntax
  { 1293,	3,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #1293 = S2_asr_i_svw_trun
  { 1294,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1294 = S2_asr_i_vh
  { 1295,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1295 = S2_asr_i_vw
  { 1296,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1296 = S2_asr_r_p
  { 1297,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1297 = S2_asr_r_p_acc
  { 1298,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1298 = S2_asr_r_p_and
  { 1299,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1299 = S2_asr_r_p_nac
  { 1300,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1300 = S2_asr_r_p_or
  { 1301,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1301 = S2_asr_r_p_xor
  { 1302,	3,	1,	4,	12,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1302 = S2_asr_r_r
  { 1303,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1303 = S2_asr_r_r_acc
  { 1304,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1304 = S2_asr_r_r_and
  { 1305,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1305 = S2_asr_r_r_nac
  { 1306,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1306 = S2_asr_r_r_or
  { 1307,	3,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo15, -1 ,nullptr },  // Inst #1307 = S2_asr_r_r_sat
  { 1308,	3,	1,	4,	12,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo111, -1 ,nullptr },  // Inst #1308 = S2_asr_r_svw_trun
  { 1309,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1309 = S2_asr_r_vh
  { 1310,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1310 = S2_asr_r_vw
  { 1311,	2,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1311 = S2_brev
  { 1312,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1312 = S2_brevp
  { 1313,	3,	1,	4,	12,	0, 0xfc00000808ULL, nullptr, ImplicitList17, OperandInfo17, -1 ,nullptr },  // Inst #1313 = S2_cabacdecbin
  { 1314,	4,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo119, -1 ,nullptr },  // Inst #1314 = S2_cabacencbin
  { 1315,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1315 = S2_cl0
  { 1316,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1316 = S2_cl0p
  { 1317,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1317 = S2_cl1
  { 1318,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1318 = S2_cl1p
  { 1319,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1319 = S2_clb
  { 1320,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1320 = S2_clbnorm
  { 1321,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1321 = S2_clbp
  { 1322,	3,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1322 = S2_clrbit_i
  { 1323,	3,	1,	4,	12,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1323 = S2_clrbit_r
  { 1324,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1324 = S2_ct0
  { 1325,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1325 = S2_ct0p
  { 1326,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1326 = S2_ct1
  { 1327,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1327 = S2_ct1p
  { 1328,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1328 = S2_deinterleave
  { 1329,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #1329 = S2_extractu
  { 1330,	3,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo120, -1 ,nullptr },  // Inst #1330 = S2_extractu_rp
  { 1331,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo121, -1 ,nullptr },  // Inst #1331 = S2_extractup
  { 1332,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1332 = S2_extractup_rp
  { 1333,	5,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #1333 = S2_insert
  { 1334,	4,	1,	4,	12,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo123, -1 ,nullptr },  // Inst #1334 = S2_insert_rp
  { 1335,	5,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo124, -1 ,nullptr },  // Inst #1335 = S2_insertp
  { 1336,	4,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #1336 = S2_insertp_rp
  { 1337,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1337 = S2_interleave
  { 1338,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1338 = S2_lfsp
  { 1339,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1339 = S2_lsl_r_p
  { 1340,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1340 = S2_lsl_r_p_acc
  { 1341,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1341 = S2_lsl_r_p_and
  { 1342,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1342 = S2_lsl_r_p_nac
  { 1343,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1343 = S2_lsl_r_p_or
  { 1344,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1344 = S2_lsl_r_p_xor
  { 1345,	3,	1,	4,	12,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1345 = S2_lsl_r_r
  { 1346,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1346 = S2_lsl_r_r_acc
  { 1347,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1347 = S2_lsl_r_r_and
  { 1348,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1348 = S2_lsl_r_r_nac
  { 1349,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1349 = S2_lsl_r_r_or
  { 1350,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1350 = S2_lsl_r_vh
  { 1351,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1351 = S2_lsl_r_vw
  { 1352,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1352 = S2_lsr_i_p
  { 1353,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1353 = S2_lsr_i_p_acc
  { 1354,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1354 = S2_lsr_i_p_and
  { 1355,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1355 = S2_lsr_i_p_nac
  { 1356,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1356 = S2_lsr_i_p_or
  { 1357,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1357 = S2_lsr_i_p_xacc
  { 1358,	3,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1358 = S2_lsr_i_r
  { 1359,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1359 = S2_lsr_i_r_acc
  { 1360,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1360 = S2_lsr_i_r_and
  { 1361,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1361 = S2_lsr_i_r_nac
  { 1362,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1362 = S2_lsr_i_r_or
  { 1363,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1363 = S2_lsr_i_r_xacc
  { 1364,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1364 = S2_lsr_i_vh
  { 1365,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1365 = S2_lsr_i_vw
  { 1366,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1366 = S2_lsr_r_p
  { 1367,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1367 = S2_lsr_r_p_acc
  { 1368,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1368 = S2_lsr_r_p_and
  { 1369,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1369 = S2_lsr_r_p_nac
  { 1370,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1370 = S2_lsr_r_p_or
  { 1371,	4,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1371 = S2_lsr_r_p_xor
  { 1372,	3,	1,	4,	12,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1372 = S2_lsr_r_r
  { 1373,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1373 = S2_lsr_r_r_acc
  { 1374,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1374 = S2_lsr_r_r_and
  { 1375,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1375 = S2_lsr_r_r_nac
  { 1376,	4,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1376 = S2_lsr_r_r_or
  { 1377,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1377 = S2_lsr_r_vh
  { 1378,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo110, -1 ,nullptr },  // Inst #1378 = S2_lsr_r_vw
  { 1379,	3,	1,	4,	3,	0, 0xfc00000001ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #1379 = S2_packhl
  { 1380,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #1380 = S2_parityp
  { 1381,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0xbfc31220306ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1381 = S2_pstorerbf_io
  { 1382,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0xefc00020306ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1382 = S2_pstorerbf_pi
  { 1383,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0xefc00020706ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1383 = S2_pstorerbfnew_pi
  { 1384,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0xbfc3124d30aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1384 = S2_pstorerbnewf_io
  { 1385,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0xefc0005130aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1385 = S2_pstorerbnewf_pi
  { 1386,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0xefc0005170aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1386 = S2_pstorerbnewfnew_pi
  { 1387,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0xbfc3124d10aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1387 = S2_pstorerbnewt_io
  { 1388,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0xefc0005110aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1388 = S2_pstorerbnewt_pi
  { 1389,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0xefc0005150aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1389 = S2_pstorerbnewtnew_pi
  { 1390,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0xbfc31220106ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1390 = S2_pstorerbt_io
  { 1391,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0xefc00020106ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1391 = S2_pstorerbt_pi
  { 1392,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0xefc00020506ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1392 = S2_pstorerbtnew_pi
  { 1393,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x23ff49200306ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1393 = S2_pstorerdf_io
  { 1394,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x26fc00000306ULL, nullptr, nullptr, OperandInfo128, -1 ,nullptr },  // Inst #1394 = S2_pstorerdf_pi
  { 1395,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x26fc00000706ULL, nullptr, nullptr, OperandInfo128, -1 ,nullptr },  // Inst #1395 = S2_pstorerdfnew_pi
  { 1396,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x23ff49200106ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1396 = S2_pstorerdt_io
  { 1397,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x26fc00000106ULL, nullptr, nullptr, OperandInfo128, -1 ,nullptr },  // Inst #1397 = S2_pstorerdt_pi
  { 1398,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x26fc00000506ULL, nullptr, nullptr, OperandInfo128, -1 ,nullptr },  // Inst #1398 = S2_pstorerdtnew_pi
  { 1399,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x13fd39200306ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1399 = S2_pstorerff_io
  { 1400,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x16fc00000306ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1400 = S2_pstorerff_pi
  { 1401,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x16fc00000706ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1401 = S2_pstorerffnew_pi
  { 1402,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x13fd39200106ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1402 = S2_pstorerft_io
  { 1403,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x16fc00000106ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1403 = S2_pstorerft_pi
  { 1404,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x16fc00000506ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1404 = S2_pstorerftnew_pi
  { 1405,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x13fd39220306ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1405 = S2_pstorerhf_io
  { 1406,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x16fc00020306ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1406 = S2_pstorerhf_pi
  { 1407,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x16fc00020706ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1407 = S2_pstorerhfnew_pi
  { 1408,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0x13fd3924d30aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1408 = S2_pstorerhnewf_io
  { 1409,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0x16fc0005130aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1409 = S2_pstorerhnewf_pi
  { 1410,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0x16fc0005170aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1410 = S2_pstorerhnewfnew_pi
  { 1411,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0x13fd3924d10aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1411 = S2_pstorerhnewt_io
  { 1412,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0x16fc0005110aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1412 = S2_pstorerhnewt_pi
  { 1413,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0x16fc0005150aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1413 = S2_pstorerhnewtnew_pi
  { 1414,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x13fd39220106ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1414 = S2_pstorerht_io
  { 1415,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x16fc00020106ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1415 = S2_pstorerht_pi
  { 1416,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x16fc00020506ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1416 = S2_pstorerhtnew_pi
  { 1417,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x1bfe41220306ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1417 = S2_pstorerif_io
  { 1418,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x1efc00020306ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1418 = S2_pstorerif_pi
  { 1419,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x1efc00020706ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1419 = S2_pstorerifnew_pi
  { 1420,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0x1bfe4124d30aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1420 = S2_pstorerinewf_io
  { 1421,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0x1efc0005130aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1421 = S2_pstorerinewf_pi
  { 1422,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0x1efc0005170aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1422 = S2_pstorerinewfnew_pi
  { 1423,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0x1bfe4124d10aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1423 = S2_pstorerinewt_io
  { 1424,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0x1efc0005110aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1424 = S2_pstorerinewt_pi
  { 1425,	5,	1,	4,	50,	0|(1ULL<<MCID::MayStore), 0x1efc0005150aULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1425 = S2_pstorerinewtnew_pi
  { 1426,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x1bfe41220106ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1426 = S2_pstorerit_io
  { 1427,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x1efc00020106ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1427 = S2_pstorerit_pi
  { 1428,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x1efc00020506ULL, nullptr, nullptr, OperandInfo126, -1 ,nullptr },  // Inst #1428 = S2_pstoreritnew_pi
  { 1429,	3,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1429 = S2_setbit_i
  { 1430,	3,	1,	4,	12,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1430 = S2_setbit_r
  { 1431,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1431 = S2_shuffeb
  { 1432,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1432 = S2_shuffeh
  { 1433,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1433 = S2_shuffob
  { 1434,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1434 = S2_shuffoh
  { 1435,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0xbfc5ca20006ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1435 = S2_storerb_io
  { 1436,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x8fc00020006ULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1436 = S2_storerb_pbr
  { 1437,	4,	1,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xfc00000006ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1437 = S2_storerb_pbr_pseudo
  { 1438,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc00020006ULL, ImplicitList21, nullptr, OperandInfo130, -1 ,nullptr },  // Inst #1438 = S2_storerb_pci
  { 1439,	5,	1,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xfc00000006ULL, nullptr, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #1439 = S2_storerb_pci_pseudo
  { 1440,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc00020006ULL, ImplicitList21, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1440 = S2_storerb_pcr
  { 1441,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0xefc00020006ULL, nullptr, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #1441 = S2_storerb_pi
  { 1442,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc00020006ULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1442 = S2_storerb_pr
  { 1443,	2,	0,	4,	47,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x9fc80420006ULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1443 = S2_storerbabs
  { 1444,	2,	0,	4,	47,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x8fc00020006ULL, ImplicitList22, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1444 = S2_storerbgp
  { 1445,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0xbfc5ca4900aULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1445 = S2_storerbnew_io
  { 1446,	4,	1,	4,	36,	0|(1ULL<<MCID::MayStore), 0x8fc0004d00aULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1446 = S2_storerbnew_pbr
  { 1447,	5,	1,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc0005100aULL, ImplicitList21, nullptr, OperandInfo130, -1 ,nullptr },  // Inst #1447 = S2_storerbnew_pci
  { 1448,	4,	1,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc0004d00aULL, ImplicitList21, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1448 = S2_storerbnew_pcr
  { 1449,	4,	1,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0xefc0004d00aULL, nullptr, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #1449 = S2_storerbnew_pi
  { 1450,	4,	1,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc0004d00aULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1450 = S2_storerbnew_pr
  { 1451,	2,	0,	4,	49,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x9fc8044500aULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1451 = S2_storerbnewabs
  { 1452,	2,	0,	4,	49,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x8fc0004500aULL, ImplicitList22, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1452 = S2_storerbnewgp
  { 1453,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x23ff74a00006ULL, nullptr, nullptr, OperandInfo134, -1 ,nullptr },  // Inst #1453 = S2_storerd_io
  { 1454,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x20fc00000006ULL, nullptr, nullptr, OperandInfo135, -1 ,nullptr },  // Inst #1454 = S2_storerd_pbr
  { 1455,	4,	1,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xfc00000006ULL, nullptr, nullptr, OperandInfo136, -1 ,nullptr },  // Inst #1455 = S2_storerd_pbr_pseudo
  { 1456,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc00000006ULL, ImplicitList21, nullptr, OperandInfo137, -1 ,nullptr },  // Inst #1456 = S2_storerd_pci
  { 1457,	5,	1,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xfc00000006ULL, nullptr, nullptr, OperandInfo138, -1 ,nullptr },  // Inst #1457 = S2_storerd_pci_pseudo
  { 1458,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc00000006ULL, ImplicitList21, nullptr, OperandInfo135, -1 ,nullptr },  // Inst #1458 = S2_storerd_pcr
  { 1459,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x26fc00000006ULL, nullptr, nullptr, OperandInfo139, -1 ,nullptr },  // Inst #1459 = S2_storerd_pi
  { 1460,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc00000006ULL, nullptr, nullptr, OperandInfo135, -1 ,nullptr },  // Inst #1460 = S2_storerd_pr
  { 1461,	2,	0,	4,	47,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x21ff98400006ULL, nullptr, nullptr, OperandInfo140, -1 ,nullptr },  // Inst #1461 = S2_storerdabs
  { 1462,	2,	0,	4,	47,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x20fc00000006ULL, ImplicitList22, nullptr, OperandInfo140, -1 ,nullptr },  // Inst #1462 = S2_storerdgp
  { 1463,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x13fd64a00006ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1463 = S2_storerf_io
  { 1464,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x10fc00000006ULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1464 = S2_storerf_pbr
  { 1465,	4,	1,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xfc00000006ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1465 = S2_storerf_pbr_pseudo
  { 1466,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc00000006ULL, ImplicitList21, nullptr, OperandInfo130, -1 ,nullptr },  // Inst #1466 = S2_storerf_pci
  { 1467,	5,	1,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xfc00000006ULL, nullptr, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #1467 = S2_storerf_pci_pseudo
  { 1468,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc00000006ULL, ImplicitList21, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1468 = S2_storerf_pcr
  { 1469,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x16fc00000006ULL, nullptr, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #1469 = S2_storerf_pi
  { 1470,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc00000006ULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1470 = S2_storerf_pr
  { 1471,	2,	0,	4,	47,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x11fd88400006ULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1471 = S2_storerfabs
  { 1472,	2,	0,	4,	47,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x10fc00000006ULL, ImplicitList22, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1472 = S2_storerfgp
  { 1473,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x13fd64a20006ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1473 = S2_storerh_io
  { 1474,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x10fc00020006ULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1474 = S2_storerh_pbr
  { 1475,	4,	1,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xfc00000006ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1475 = S2_storerh_pbr_pseudo
  { 1476,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc00020006ULL, ImplicitList21, nullptr, OperandInfo130, -1 ,nullptr },  // Inst #1476 = S2_storerh_pci
  { 1477,	5,	1,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xfc00000006ULL, nullptr, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #1477 = S2_storerh_pci_pseudo
  { 1478,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc00020006ULL, ImplicitList21, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1478 = S2_storerh_pcr
  { 1479,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x16fc00020006ULL, nullptr, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #1479 = S2_storerh_pi
  { 1480,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc00020006ULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1480 = S2_storerh_pr
  { 1481,	2,	0,	4,	47,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x11fd88420006ULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1481 = S2_storerhabs
  { 1482,	2,	0,	4,	47,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x10fc00020006ULL, ImplicitList22, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1482 = S2_storerhgp
  { 1483,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x13fd64a4900aULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1483 = S2_storerhnew_io
  { 1484,	4,	1,	4,	36,	0|(1ULL<<MCID::MayStore), 0x10fc0004d00aULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1484 = S2_storerhnew_pbr
  { 1485,	5,	1,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc0005100aULL, ImplicitList21, nullptr, OperandInfo130, -1 ,nullptr },  // Inst #1485 = S2_storerhnew_pci
  { 1486,	4,	1,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc0004d00aULL, ImplicitList21, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1486 = S2_storerhnew_pcr
  { 1487,	4,	1,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x16fc0004d00aULL, nullptr, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #1487 = S2_storerhnew_pi
  { 1488,	4,	1,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc0004d00aULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1488 = S2_storerhnew_pr
  { 1489,	2,	0,	4,	49,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x11fd8844500aULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1489 = S2_storerhnewabs
  { 1490,	2,	0,	4,	49,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x10fc0004500aULL, ImplicitList22, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1490 = S2_storerhnewgp
  { 1491,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x1bfe6ca20006ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1491 = S2_storeri_io
  { 1492,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore), 0x18fc00020006ULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1492 = S2_storeri_pbr
  { 1493,	4,	1,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xfc00000006ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #1493 = S2_storeri_pbr_pseudo
  { 1494,	5,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc00020006ULL, ImplicitList21, nullptr, OperandInfo130, -1 ,nullptr },  // Inst #1494 = S2_storeri_pci
  { 1495,	5,	1,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xfc00000006ULL, nullptr, nullptr, OperandInfo131, -1 ,nullptr },  // Inst #1495 = S2_storeri_pci_pseudo
  { 1496,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc00020006ULL, ImplicitList21, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1496 = S2_storeri_pcr
  { 1497,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x1efc00020006ULL, nullptr, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #1497 = S2_storeri_pi
  { 1498,	4,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc00020006ULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1498 = S2_storeri_pr
  { 1499,	2,	0,	4,	47,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x19fe90420006ULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1499 = S2_storeriabs
  { 1500,	2,	0,	4,	47,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x18fc00020006ULL, ImplicitList22, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1500 = S2_storerigp
  { 1501,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x1bfe6ca4900aULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1501 = S2_storerinew_io
  { 1502,	4,	1,	4,	36,	0|(1ULL<<MCID::MayStore), 0x18fc0004d00aULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1502 = S2_storerinew_pbr
  { 1503,	5,	1,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc0005100aULL, ImplicitList21, nullptr, OperandInfo130, -1 ,nullptr },  // Inst #1503 = S2_storerinew_pci
  { 1504,	4,	1,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc0004d00aULL, ImplicitList21, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1504 = S2_storerinew_pcr
  { 1505,	4,	1,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x1efc0004d00aULL, nullptr, nullptr, OperandInfo132, -1 ,nullptr },  // Inst #1505 = S2_storerinew_pi
  { 1506,	4,	1,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc0004d00aULL, nullptr, nullptr, OperandInfo129, -1 ,nullptr },  // Inst #1506 = S2_storerinew_pr
  { 1507,	2,	0,	4,	49,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x19fe9044500aULL, nullptr, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1507 = S2_storerinewabs
  { 1508,	2,	0,	4,	49,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x18fc0004500aULL, ImplicitList22, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1508 = S2_storerinewgp
  { 1509,	3,	1,	4,	46,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc00000846ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #1509 = S2_storew_locked
  { 1510,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #1510 = S2_svsathb
  { 1511,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo13, -1 ,nullptr },  // Inst #1511 = S2_svsathub
  { 1512,	5,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #1512 = S2_tableidxb
  { 1513,	5,	1,	4,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000008ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #1513 = S2_tableidxb_goodsyntax
  { 1514,	5,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #1514 = S2_tableidxd
  { 1515,	5,	1,	4,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000008ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #1515 = S2_tableidxd_goodsyntax
  { 1516,	5,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #1516 = S2_tableidxh
  { 1517,	5,	1,	4,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000008ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #1517 = S2_tableidxh_goodsyntax
  { 1518,	5,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #1518 = S2_tableidxw
  { 1519,	5,	1,	4,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000008ULL, nullptr, nullptr, OperandInfo122, -1 ,nullptr },  // Inst #1519 = S2_tableidxw_goodsyntax
  { 1520,	3,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1520 = S2_togglebit_i
  { 1521,	3,	1,	4,	12,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1521 = S2_togglebit_r
  { 1522,	3,	1,	4,	20,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #1522 = S2_tstbit_i
  { 1523,	3,	1,	4,	13,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #1523 = S2_tstbit_r
  { 1524,	4,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo141, -1 ,nullptr },  // Inst #1524 = S2_valignib
  { 1525,	4,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo119, -1 ,nullptr },  // Inst #1525 = S2_valignrb
  { 1526,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo110, -1 ,nullptr },  // Inst #1526 = S2_vcnegh
  { 1527,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo110, -1 ,nullptr },  // Inst #1527 = S2_vcrotate
  { 1528,	4,	1,	4,	45,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #1528 = S2_vrcnegh
  { 1529,	2,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1529 = S2_vrndpackwh
  { 1530,	2,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #1530 = S2_vrndpackwhs
  { 1531,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #1531 = S2_vsathb
  { 1532,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1532 = S2_vsathb_nopack
  { 1533,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #1533 = S2_vsathub
  { 1534,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1534 = S2_vsathub_nopack
  { 1535,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #1535 = S2_vsatwh
  { 1536,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1536 = S2_vsatwh_nopack
  { 1537,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo23, -1 ,nullptr },  // Inst #1537 = S2_vsatwuh
  { 1538,	2,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #1538 = S2_vsatwuh_nopack
  { 1539,	2,	1,	4,	2,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc00002008ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1539 = S2_vsplatrb
  { 1540,	2,	1,	4,	2,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1540 = S2_vsplatrh
  { 1541,	4,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo141, -1 ,nullptr },  // Inst #1541 = S2_vspliceib
  { 1542,	4,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo119, -1 ,nullptr },  // Inst #1542 = S2_vsplicerb
  { 1543,	2,	1,	4,	2,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1543 = S2_vsxtbh
  { 1544,	2,	1,	4,	2,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1544 = S2_vsxthw
  { 1545,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1545 = S2_vtrunehb
  { 1546,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1546 = S2_vtrunewh
  { 1547,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1547 = S2_vtrunohb
  { 1548,	3,	1,	4,	12,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1548 = S2_vtrunowh
  { 1549,	2,	1,	4,	2,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1549 = S2_vzxtbh
  { 1550,	2,	1,	4,	2,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc00000008ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1550 = S2_vzxthw
  { 1551,	4,	1,	4,	5,	0, 0xfc35a02008ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #1551 = S4_addaddi
  { 1552,	4,	1,	4,	5,	0, 0xfc40a02008ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1552 = S4_addi_asl_ri
  { 1553,	4,	1,	4,	5,	0, 0xfc40a02008ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1553 = S4_addi_lsr_ri
  { 1554,	4,	1,	4,	5,	0, 0xfc40a02008ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1554 = S4_andi_asl_ri
  { 1555,	4,	1,	4,	5,	0, 0xfc40a02008ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1555 = S4_andi_lsr_ri
  { 1556,	3,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1556 = S4_clbaddi
  { 1557,	3,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #1557 = S4_clbpaddi
  { 1558,	2,	1,	4,	2,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1558 = S4_clbpnorm
  { 1559,	4,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo94, -1 ,nullptr },  // Inst #1559 = S4_extract
  { 1560,	3,	1,	4,	14,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo120, -1 ,nullptr },  // Inst #1560 = S4_extract_rp
  { 1561,	4,	1,	4,	1,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo121, -1 ,nullptr },  // Inst #1561 = S4_extractp
  { 1562,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #1562 = S4_extractp_rp
  { 1563,	3,	1,	4,	12,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1563 = S4_lsli
  { 1564,	3,	1,	4,	20,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #1564 = S4_ntstbit_i
  { 1565,	3,	1,	4,	13,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #1565 = S4_ntstbit_r
  { 1566,	4,	1,	4,	5,	0, 0xfc55a02008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1566 = S4_or_andi
  { 1567,	4,	1,	4,	5,	0, 0xfc55a02008ULL, nullptr, nullptr, OperandInfo143, -1 ,nullptr },  // Inst #1567 = S4_or_andix
  { 1568,	4,	1,	4,	5,	0, 0xfc55a02008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1568 = S4_or_ori
  { 1569,	4,	1,	4,	4,	0, 0xfc40a02008ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1569 = S4_ori_asl_ri
  { 1570,	4,	1,	4,	4,	0, 0xfc40a02008ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1570 = S4_ori_lsr_ri
  { 1571,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1571 = S4_parity
  { 1572,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x9fc30c20306ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1572 = S4_pstorerbf_abs
  { 1573,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0xdfc00020306ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1573 = S4_pstorerbf_rr
  { 1574,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x9fc30c20706ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1574 = S4_pstorerbfnew_abs
  { 1575,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0xbfc31220706ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1575 = S4_pstorerbfnew_io
  { 1576,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0xdfc00020706ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1576 = S4_pstorerbfnew_rr
  { 1577,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x9fc30c4930aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1577 = S4_pstorerbnewf_abs
  { 1578,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0xdfc0005130aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1578 = S4_pstorerbnewf_rr
  { 1579,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x9fc30c4970aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1579 = S4_pstorerbnewfnew_abs
  { 1580,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0xbfc3124d70aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1580 = S4_pstorerbnewfnew_io
  { 1581,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0xdfc0005170aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1581 = S4_pstorerbnewfnew_rr
  { 1582,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x9fc30c4910aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1582 = S4_pstorerbnewt_abs
  { 1583,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0xdfc0005110aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1583 = S4_pstorerbnewt_rr
  { 1584,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x9fc30c4950aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1584 = S4_pstorerbnewtnew_abs
  { 1585,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0xbfc3124d50aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1585 = S4_pstorerbnewtnew_io
  { 1586,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0xdfc0005150aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1586 = S4_pstorerbnewtnew_rr
  { 1587,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x9fc30c20106ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1587 = S4_pstorerbt_abs
  { 1588,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0xdfc00020106ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1588 = S4_pstorerbt_rr
  { 1589,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x9fc30c20506ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1589 = S4_pstorerbtnew_abs
  { 1590,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0xbfc31220506ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1590 = S4_pstorerbtnew_io
  { 1591,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0xdfc00020506ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1591 = S4_pstorerbtnew_rr
  { 1592,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x21fc30c00306ULL, nullptr, nullptr, OperandInfo146, -1 ,nullptr },  // Inst #1592 = S4_pstorerdf_abs
  { 1593,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x25fc00000306ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1593 = S4_pstorerdf_rr
  { 1594,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x21fc30c00706ULL, nullptr, nullptr, OperandInfo146, -1 ,nullptr },  // Inst #1594 = S4_pstorerdfnew_abs
  { 1595,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x23ff49200706ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1595 = S4_pstorerdfnew_io
  { 1596,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x25fc00000706ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1596 = S4_pstorerdfnew_rr
  { 1597,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x21fc30c00106ULL, nullptr, nullptr, OperandInfo146, -1 ,nullptr },  // Inst #1597 = S4_pstorerdt_abs
  { 1598,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x25fc00000106ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1598 = S4_pstorerdt_rr
  { 1599,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x21fc30c00506ULL, nullptr, nullptr, OperandInfo146, -1 ,nullptr },  // Inst #1599 = S4_pstorerdtnew_abs
  { 1600,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x23ff49200506ULL, nullptr, nullptr, OperandInfo127, -1 ,nullptr },  // Inst #1600 = S4_pstorerdtnew_io
  { 1601,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x25fc00000506ULL, nullptr, nullptr, OperandInfo147, -1 ,nullptr },  // Inst #1601 = S4_pstorerdtnew_rr
  { 1602,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x11fc30c00306ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1602 = S4_pstorerff_abs
  { 1603,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x15fc00000306ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1603 = S4_pstorerff_rr
  { 1604,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x11fc30c00706ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1604 = S4_pstorerffnew_abs
  { 1605,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x13fd39200706ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1605 = S4_pstorerffnew_io
  { 1606,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x15fc00000706ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1606 = S4_pstorerffnew_rr
  { 1607,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x11fc30c00106ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1607 = S4_pstorerft_abs
  { 1608,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x15fc00000106ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1608 = S4_pstorerft_rr
  { 1609,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x11fc30c00506ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1609 = S4_pstorerftnew_abs
  { 1610,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x13fd39200506ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1610 = S4_pstorerftnew_io
  { 1611,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x15fc00000506ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1611 = S4_pstorerftnew_rr
  { 1612,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x11fc30c20306ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1612 = S4_pstorerhf_abs
  { 1613,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x15fc00020306ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1613 = S4_pstorerhf_rr
  { 1614,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x11fc30c20706ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1614 = S4_pstorerhfnew_abs
  { 1615,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x13fd39220706ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1615 = S4_pstorerhfnew_io
  { 1616,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x15fc00020706ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1616 = S4_pstorerhfnew_rr
  { 1617,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x11fc30c4930aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1617 = S4_pstorerhnewf_abs
  { 1618,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0x15fc0005130aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1618 = S4_pstorerhnewf_rr
  { 1619,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x11fc30c4970aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1619 = S4_pstorerhnewfnew_abs
  { 1620,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0x13fd3924d70aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1620 = S4_pstorerhnewfnew_io
  { 1621,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0x15fc0005170aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1621 = S4_pstorerhnewfnew_rr
  { 1622,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x11fc30c4910aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1622 = S4_pstorerhnewt_abs
  { 1623,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0x15fc0005110aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1623 = S4_pstorerhnewt_rr
  { 1624,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x11fc30c4950aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1624 = S4_pstorerhnewtnew_abs
  { 1625,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0x13fd3924d50aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1625 = S4_pstorerhnewtnew_io
  { 1626,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0x15fc0005150aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1626 = S4_pstorerhnewtnew_rr
  { 1627,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x11fc30c20106ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1627 = S4_pstorerht_abs
  { 1628,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x15fc00020106ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1628 = S4_pstorerht_rr
  { 1629,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x11fc30c20506ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1629 = S4_pstorerhtnew_abs
  { 1630,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x13fd39220506ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1630 = S4_pstorerhtnew_io
  { 1631,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x15fc00020506ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1631 = S4_pstorerhtnew_rr
  { 1632,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x19fc30c20306ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1632 = S4_pstorerif_abs
  { 1633,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x1dfc00020306ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1633 = S4_pstorerif_rr
  { 1634,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x19fc30c20706ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1634 = S4_pstorerifnew_abs
  { 1635,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x1bfe41220706ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1635 = S4_pstorerifnew_io
  { 1636,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x1dfc00020706ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1636 = S4_pstorerifnew_rr
  { 1637,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x19fc30c4930aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1637 = S4_pstorerinewf_abs
  { 1638,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0x1dfc0005130aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1638 = S4_pstorerinewf_rr
  { 1639,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x19fc30c4970aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1639 = S4_pstorerinewfnew_abs
  { 1640,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0x1bfe4124d70aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1640 = S4_pstorerinewfnew_io
  { 1641,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0x1dfc0005170aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1641 = S4_pstorerinewfnew_rr
  { 1642,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x19fc30c4910aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1642 = S4_pstorerinewt_abs
  { 1643,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0x1dfc0005110aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1643 = S4_pstorerinewt_rr
  { 1644,	3,	0,	4,	50,	0|(1ULL<<MCID::MayStore), 0x19fc30c4950aULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1644 = S4_pstorerinewtnew_abs
  { 1645,	4,	0,	4,	49,	0|(1ULL<<MCID::MayStore), 0x1bfe4124d50aULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1645 = S4_pstorerinewtnew_io
  { 1646,	5,	0,	4,	40,	0|(1ULL<<MCID::MayStore), 0x1dfc0005150aULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1646 = S4_pstorerinewtnew_rr
  { 1647,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x19fc30c20106ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1647 = S4_pstorerit_abs
  { 1648,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x1dfc00020106ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1648 = S4_pstorerit_rr
  { 1649,	3,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x19fc30c20506ULL, nullptr, nullptr, OperandInfo144, -1 ,nullptr },  // Inst #1649 = S4_pstoreritnew_abs
  { 1650,	4,	0,	4,	47,	0|(1ULL<<MCID::MayStore), 0x1bfe41220506ULL, nullptr, nullptr, OperandInfo125, -1 ,nullptr },  // Inst #1650 = S4_pstoreritnew_io
  { 1651,	5,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x1dfc00020506ULL, nullptr, nullptr, OperandInfo145, -1 ,nullptr },  // Inst #1651 = S4_pstoreritnew_rr
  { 1652,	3,	1,	4,	46,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc00000846ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #1652 = S4_stored_locked
  { 1653,	3,	0,	4,	51,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0xbfc45200006ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #1653 = S4_storeirb_io
  { 1654,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0xbfc35a00306ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1654 = S4_storeirbf_io
  { 1655,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0xbfc35a00706ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1655 = S4_storeirbfnew_io
  { 1656,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0xbfc35a00106ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1656 = S4_storeirbt_io
  { 1657,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0xbfc35a00506ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1657 = S4_storeirbtnew_io
  { 1658,	3,	0,	4,	51,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x13fc45200006ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #1658 = S4_storeirh_io
  { 1659,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x13fc35a00306ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1659 = S4_storeirhf_io
  { 1660,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x13fc35a00706ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1660 = S4_storeirhfnew_io
  { 1661,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x13fc35a00106ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1661 = S4_storeirht_io
  { 1662,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x13fc35a00506ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1662 = S4_storeirhtnew_io
  { 1663,	3,	0,	4,	51,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x1bfc45200006ULL, nullptr, nullptr, OperandInfo92, -1 ,nullptr },  // Inst #1663 = S4_storeiri_io
  { 1664,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x1bfc35a00306ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1664 = S4_storeirif_io
  { 1665,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x1bfc35a00706ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1665 = S4_storeirifnew_io
  { 1666,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x1bfc35a00106ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1666 = S4_storeirit_io
  { 1667,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore), 0x1bfc35a00506ULL, nullptr, nullptr, OperandInfo148, -1 ,nullptr },  // Inst #1667 = S4_storeiritnew_io
  { 1668,	3,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xafc30c20006ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1668 = S4_storerb_ap
  { 1669,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0xdfc00020006ULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #1669 = S4_storerb_rr
  { 1670,	4,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0xcfc31420006ULL, nullptr, nullptr, OperandInfo149, -1 ,nullptr },  // Inst #1670 = S4_storerb_ur
  { 1671,	3,	1,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xafc30c4900aULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1671 = S4_storerbnew_ap
  { 1672,	4,	0,	4,	40,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0xdfc0004d00aULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #1672 = S4_storerbnew_rr
  { 1673,	4,	0,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x4fc3144d00aULL, nullptr, nullptr, OperandInfo149, -1 ,nullptr },  // Inst #1673 = S4_storerbnew_ur
  { 1674,	3,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x22fc30c00006ULL, nullptr, nullptr, OperandInfo134, -1 ,nullptr },  // Inst #1674 = S4_storerd_ap
  { 1675,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x25fc00000006ULL, nullptr, nullptr, OperandInfo150, -1 ,nullptr },  // Inst #1675 = S4_storerd_rr
  { 1676,	4,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x24fc31400006ULL, nullptr, nullptr, OperandInfo151, -1 ,nullptr },  // Inst #1676 = S4_storerd_ur
  { 1677,	3,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x12fc30c00006ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1677 = S4_storerf_ap
  { 1678,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x15fc00000006ULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #1678 = S4_storerf_rr
  { 1679,	4,	0,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x14fc31400006ULL, nullptr, nullptr, OperandInfo149, -1 ,nullptr },  // Inst #1679 = S4_storerf_ur
  { 1680,	3,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x12fc30c20006ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1680 = S4_storerh_ap
  { 1681,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x15fc00020006ULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #1681 = S4_storerh_rr
  { 1682,	4,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x14fc31420006ULL, nullptr, nullptr, OperandInfo149, -1 ,nullptr },  // Inst #1682 = S4_storerh_ur
  { 1683,	3,	1,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x12fc30c4900aULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1683 = S4_storerhnew_ap
  { 1684,	4,	0,	4,	40,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x15fc0004d00aULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #1684 = S4_storerhnew_rr
  { 1685,	4,	0,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x4fc3144d00aULL, nullptr, nullptr, OperandInfo149, -1 ,nullptr },  // Inst #1685 = S4_storerhnew_ur
  { 1686,	3,	1,	4,	48,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x1afc30c20006ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1686 = S4_storeri_ap
  { 1687,	4,	0,	4,	51,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x1dfc00020006ULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #1687 = S4_storeri_rr
  { 1688,	4,	0,	4,	48,	0|(1ULL<<MCID::MayStore), 0x1cfc31420006ULL, nullptr, nullptr, OperandInfo149, -1 ,nullptr },  // Inst #1688 = S4_storeri_ur
  { 1689,	3,	1,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x1afc30c4900aULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1689 = S4_storerinew_ap
  { 1690,	4,	0,	4,	40,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x1dfc0004d00aULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #1690 = S4_storerinew_rr
  { 1691,	4,	0,	4,	36,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x4fc3144d00aULL, nullptr, nullptr, OperandInfo149, -1 ,nullptr },  // Inst #1691 = S4_storerinew_ur
  { 1692,	4,	1,	4,	5,	0, 0xfc35202008ULL, nullptr, nullptr, OperandInfo113, -1 ,nullptr },  // Inst #1692 = S4_subaddi
  { 1693,	4,	1,	4,	4,	0, 0xfc40a02008ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1693 = S4_subi_asl_ri
  { 1694,	4,	1,	4,	4,	0, 0xfc40a02008ULL, nullptr, nullptr, OperandInfo142, -1 ,nullptr },  // Inst #1694 = S4_subi_lsr_ri
  { 1695,	4,	1,	4,	45,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo152, -1 ,nullptr },  // Inst #1695 = S4_vrcrotate
  { 1696,	5,	1,	4,	45,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo153, -1 ,nullptr },  // Inst #1696 = S4_vrcrotate_acc
  { 1697,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1697 = S4_vxaddsubh
  { 1698,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1698 = S4_vxaddsubhr
  { 1699,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1699 = S4_vxaddsubw
  { 1700,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1700 = S4_vxsubaddh
  { 1701,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1701 = S4_vxsubaddhr
  { 1702,	3,	1,	4,	14,	0, 0xfc00000008ULL, nullptr, ImplicitList1, OperandInfo17, -1 ,nullptr },  // Inst #1702 = S4_vxsubaddw
  { 1703,	3,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo118, -1 ,nullptr },  // Inst #1703 = S5_asrhub_rnd_sat
  { 1704,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo118, -1 ,nullptr },  // Inst #1704 = S5_asrhub_rnd_sat_goodsyntax
  { 1705,	3,	1,	4,	1,	0, 0xfc00002008ULL, nullptr, ImplicitList1, OperandInfo118, -1 ,nullptr },  // Inst #1705 = S5_asrhub_sat
  { 1706,	2,	1,	4,	1,	0, 0xf800002008ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #1706 = S5_popcountp
  { 1707,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1707 = S5_vasrhrnd
  { 1708,	3,	1,	4,	2,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1708 = S5_vasrhrnd_goodsyntax
  { 1709,	3,	1,	4,	2,	0, 0xe000000008ULL, nullptr, nullptr, OperandInfo116, -1 ,nullptr },  // Inst #1709 = S6_rol_i_p
  { 1710,	4,	1,	4,	2,	0, 0xe000000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1710 = S6_rol_i_p_acc
  { 1711,	4,	1,	4,	2,	0, 0xe000000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1711 = S6_rol_i_p_and
  { 1712,	4,	1,	4,	2,	0, 0xe000000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1712 = S6_rol_i_p_nac
  { 1713,	4,	1,	4,	2,	0, 0xe000000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1713 = S6_rol_i_p_or
  { 1714,	4,	1,	4,	2,	0, 0xe000000008ULL, nullptr, nullptr, OperandInfo117, -1 ,nullptr },  // Inst #1714 = S6_rol_i_p_xacc
  { 1715,	3,	1,	4,	2,	0, 0xe000002008ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1715 = S6_rol_i_r
  { 1716,	4,	1,	4,	2,	0, 0xe000002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1716 = S6_rol_i_r_acc
  { 1717,	4,	1,	4,	2,	0, 0xe000002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1717 = S6_rol_i_r_and
  { 1718,	4,	1,	4,	2,	0, 0xe000002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1718 = S6_rol_i_r_nac
  { 1719,	4,	1,	4,	2,	0, 0xe000002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1719 = S6_rol_i_r_or
  { 1720,	4,	1,	4,	2,	0, 0xe000002008ULL, nullptr, nullptr, OperandInfo108, -1 ,nullptr },  // Inst #1720 = S6_rol_i_r_xacc
  { 1721,	1,	0,	4,	25,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0xfec4200004ULL, ImplicitList25, ImplicitList8, OperandInfo5, -1 ,nullptr },  // Inst #1721 = SAVE_REGISTERS_CALL_V4
  { 1722,	1,	0,	4,	25,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0xfec4600004ULL, ImplicitList25, ImplicitList8, OperandInfo5, -1 ,nullptr },  // Inst #1722 = SAVE_REGISTERS_CALL_V4_EXT
  { 1723,	3,	0,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xfc6ca00006ULL, nullptr, nullptr, OperandInfo154, -1 ,nullptr },  // Inst #1723 = STriq_pred_V6
  { 1724,	3,	0,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xfc6ca00006ULL, nullptr, nullptr, OperandInfo155, -1 ,nullptr },  // Inst #1724 = STriq_pred_V6_128B
  { 1725,	3,	0,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xfc6ca00006ULL, nullptr, nullptr, OperandInfo156, -1 ,nullptr },  // Inst #1725 = STriq_pred_vec_V6
  { 1726,	3,	0,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xfc6ca00006ULL, nullptr, nullptr, OperandInfo157, -1 ,nullptr },  // Inst #1726 = STriq_pred_vec_V6_128B
  { 1727,	3,	0,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xfc6ca00006ULL, nullptr, nullptr, OperandInfo156, -1 ,nullptr },  // Inst #1727 = STriv_pseudo_V6
  { 1728,	3,	0,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xfc6ca00006ULL, nullptr, nullptr, OperandInfo157, -1 ,nullptr },  // Inst #1728 = STriv_pseudo_V6_128B
  { 1729,	3,	0,	4,	52,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xe000000019ULL, nullptr, nullptr, OperandInfo158, -1 ,nullptr },  // Inst #1729 = STrivv_indexed
  { 1730,	3,	0,	4,	52,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xe000000019ULL, nullptr, nullptr, OperandInfo159, -1 ,nullptr },  // Inst #1730 = STrivv_indexed_128B
  { 1731,	3,	0,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xfc6ca00006ULL, nullptr, nullptr, OperandInfo158, -1 ,nullptr },  // Inst #1731 = STrivv_pseudo_V6
  { 1732,	3,	0,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xfc6ca00006ULL, nullptr, nullptr, OperandInfo159, -1 ,nullptr },  // Inst #1732 = STrivv_pseudo_V6_128B
  { 1733,	3,	0,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xfc6ca00006ULL, nullptr, nullptr, OperandInfo160, -1 ,nullptr },  // Inst #1733 = STriw_mod
  { 1734,	3,	0,	4,	48,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0xfc6ca00006ULL, nullptr, nullptr, OperandInfo161, -1 ,nullptr },  // Inst #1734 = STriw_pred
  { 1735,	1,	0,	4,	25,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0xfc00000004ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #1735 = TCRETURNi
  { 1736,	1,	0,	4,	24,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0xfc00000003ULL, nullptr, ImplicitList7, OperandInfo60, -1 ,nullptr },  // Inst #1736 = TCRETURNr
  { 1737,	3,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xfc30a00008ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #1737 = TFRI64_V2_ext
  { 1738,	2,	1,	4,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xfc30a00008ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1738 = TFRI64_V4
  { 1739,	3,	1,	4,	8,	0|(1ULL<<MCID::Pseudo), 0xf801400301ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #1739 = TFRI_cNotPt_f
  { 1740,	3,	1,	4,	8,	0|(1ULL<<MCID::Pseudo), 0xf801400101ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #1740 = TFRI_cPt_f
  { 1741,	2,	1,	4,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Rematerializable), 0xf800c00001ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1741 = TFRI_f
  { 1742,	3,	1,	4,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc00000001ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1742 = TFR_FI
  { 1743,	4,	1,	4,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xfc00000001ULL, nullptr, nullptr, OperandInfo95, -1 ,nullptr },  // Inst #1743 = TFR_FIA
  { 1744,	1,	1,	4,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Rematerializable), 0xfc00000008ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #1744 = TFR_PdFalse
  { 1745,	1,	1,	4,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Rematerializable), 0xfc00000008ULL, nullptr, nullptr, OperandInfo100, -1 ,nullptr },  // Inst #1745 = TFR_PdTrue
  { 1746,	3,	1,	4,	53,	0, 0xfc3d20200bULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1746 = V4_SA1_addi
  { 1747,	3,	1,	4,	53,	0, 0xfc0000200bULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #1747 = V4_SA1_addrx
  { 1748,	2,	1,	4,	53,	0, 0xfc0000200bULL, ImplicitList4, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1748 = V4_SA1_addsp
  { 1749,	2,	1,	4,	53,	0, 0xfc0000200bULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1749 = V4_SA1_and1
  { 1750,	1,	1,	4,	53,	0, 0xfc0000230bULL, ImplicitList17, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #1750 = V4_SA1_clrf
  { 1751,	1,	1,	4,	53,	0, 0xfc0000270bULL, ImplicitList17, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #1751 = V4_SA1_clrfnew
  { 1752,	1,	1,	4,	53,	0, 0xfc0000210bULL, ImplicitList17, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #1752 = V4_SA1_clrt
  { 1753,	1,	1,	4,	53,	0, 0xfc0000250bULL, ImplicitList17, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #1753 = V4_SA1_clrtnew
  { 1754,	2,	0,	4,	53,	0, 0xfc0000000bULL, nullptr, ImplicitList17, OperandInfo32, -1 ,nullptr },  // Inst #1754 = V4_SA1_cmpeqi
  { 1755,	2,	1,	4,	53,	0, 0xfc0000000bULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1755 = V4_SA1_combine0i
  { 1756,	2,	1,	4,	53,	0, 0xfc0000000bULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1756 = V4_SA1_combine1i
  { 1757,	2,	1,	4,	53,	0, 0xfc0000000bULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1757 = V4_SA1_combine2i
  { 1758,	2,	1,	4,	53,	0, 0xfc0000000bULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1758 = V4_SA1_combine3i
  { 1759,	2,	1,	4,	53,	0, 0xfc0000000bULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1759 = V4_SA1_combinerz
  { 1760,	2,	1,	4,	53,	0, 0xfc0000000bULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #1760 = V4_SA1_combinezr
  { 1761,	2,	1,	4,	53,	0, 0xfc0000200bULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1761 = V4_SA1_dec
  { 1762,	2,	1,	4,	53,	0, 0xfc0000200bULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1762 = V4_SA1_inc
  { 1763,	2,	1,	4,	53,	0, 0xfc30a0200bULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1763 = V4_SA1_seti
  { 1764,	1,	1,	4,	53,	0, 0xfc0000200bULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #1764 = V4_SA1_setin1
  { 1765,	2,	1,	4,	53,	0, 0xfc0000200bULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1765 = V4_SA1_sxtb
  { 1766,	2,	1,	4,	53,	0, 0xfc0000200bULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1766 = V4_SA1_sxth
  { 1767,	2,	1,	4,	53,	0, 0xfc0000200bULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1767 = V4_SA1_tfr
  { 1768,	2,	1,	4,	53,	0, 0xfc0000200bULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1768 = V4_SA1_zxtb
  { 1769,	2,	1,	4,	53,	0, 0xfc0000200bULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #1769 = V4_SA1_zxth
  { 1770,	3,	1,	4,	53,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc0000200bULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1770 = V4_SL1_loadri_io
  { 1771,	3,	1,	4,	53,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc0000200bULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1771 = V4_SL1_loadrub_io
  { 1772,	0,	0,	4,	53,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc0000000bULL, ImplicitList6, ImplicitList26, nullptr, -1 ,nullptr },  // Inst #1772 = V4_SL2_deallocframe
  { 1773,	0,	0,	4,	53,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch), 0xfc0000000bULL, ImplicitList27, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #1773 = V4_SL2_jumpr31
  { 1774,	0,	0,	4,	53,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch), 0xfc0000030bULL, ImplicitList28, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #1774 = V4_SL2_jumpr31_f
  { 1775,	0,	0,	4,	53,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch), 0xfc0000070bULL, ImplicitList28, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #1775 = V4_SL2_jumpr31_fnew
  { 1776,	0,	0,	4,	53,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch), 0xfc0000010bULL, ImplicitList28, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #1776 = V4_SL2_jumpr31_t
  { 1777,	0,	0,	4,	53,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch), 0xfc0000050bULL, ImplicitList28, ImplicitList7, nullptr, -1 ,nullptr },  // Inst #1777 = V4_SL2_jumpr31_tnew
  { 1778,	3,	1,	4,	53,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc0000200bULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1778 = V4_SL2_loadrb_io
  { 1779,	2,	1,	4,	53,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc0000000bULL, ImplicitList4, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #1779 = V4_SL2_loadrd_sp
  { 1780,	3,	1,	4,	53,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc0000200bULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1780 = V4_SL2_loadrh_io
  { 1781,	2,	1,	4,	53,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc0000200bULL, ImplicitList4, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1781 = V4_SL2_loadri_sp
  { 1782,	3,	1,	4,	53,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc0000200bULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #1782 = V4_SL2_loadruh_io
  { 1783,	0,	0,	4,	53,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc0000000bULL, ImplicitList6, ImplicitList29, nullptr, -1 ,nullptr },  // Inst #1783 = V4_SL2_return
  { 1784,	0,	0,	4,	53,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc0000030bULL, ImplicitList30, ImplicitList29, nullptr, -1 ,nullptr },  // Inst #1784 = V4_SL2_return_f
  { 1785,	0,	0,	4,	53,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc0000070bULL, ImplicitList30, ImplicitList29, nullptr, -1 ,nullptr },  // Inst #1785 = V4_SL2_return_fnew
  { 1786,	0,	0,	4,	53,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc0000010bULL, ImplicitList30, ImplicitList29, nullptr, -1 ,nullptr },  // Inst #1786 = V4_SL2_return_t
  { 1787,	0,	0,	4,	53,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc0000050bULL, ImplicitList30, ImplicitList29, nullptr, -1 ,nullptr },  // Inst #1787 = V4_SL2_return_tnew
  { 1788,	3,	0,	4,	53,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc0000000bULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1788 = V4_SS1_storeb_io
  { 1789,	3,	0,	4,	53,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc0000000bULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1789 = V4_SS1_storew_io
  { 1790,	1,	0,	4,	53,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc0000000bULL, ImplicitList31, ImplicitList3, OperandInfo2, -1 ,nullptr },  // Inst #1790 = V4_SS2_allocframe
  { 1791,	2,	0,	4,	53,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc0000000bULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1791 = V4_SS2_storebi0
  { 1792,	2,	0,	4,	53,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8fc0000000bULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1792 = V4_SS2_storebi1
  { 1793,	2,	0,	4,	53,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20fc0000000bULL, ImplicitList4, nullptr, OperandInfo140, -1 ,nullptr },  // Inst #1793 = V4_SS2_stored_sp
  { 1794,	3,	0,	4,	53,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10fc0000000bULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #1794 = V4_SS2_storeh_io
  { 1795,	2,	0,	4,	53,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc0000000bULL, ImplicitList4, nullptr, OperandInfo133, -1 ,nullptr },  // Inst #1795 = V4_SS2_storew_sp
  { 1796,	2,	0,	4,	53,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc0000000bULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1796 = V4_SS2_storewi0
  { 1797,	2,	0,	4,	53,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x18fc0000000bULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #1797 = V4_SS2_storewi1
  { 1798,	3,	1,	4,	39,	0|(1ULL<<MCID::MayLoad), 0xfc00000025ULL, nullptr, nullptr, OperandInfo162, -1 ,nullptr },  // Inst #1798 = V6_extractw
  { 1799,	3,	1,	4,	39,	0|(1ULL<<MCID::MayLoad), 0xfc00000025ULL, nullptr, nullptr, OperandInfo163, -1 ,nullptr },  // Inst #1799 = V6_extractw_128B
  { 1800,	2,	1,	4,	54,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo164, -1 ,nullptr },  // Inst #1800 = V6_lvsplatw
  { 1801,	2,	1,	4,	54,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo165, -1 ,nullptr },  // Inst #1801 = V6_lvsplatw_128B
  { 1802,	3,	1,	4,	55,	0, 0xe00000000eULL, nullptr, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1802 = V6_pred_and
  { 1803,	3,	1,	4,	55,	0, 0xe00000000eULL, nullptr, nullptr, OperandInfo167, -1 ,nullptr },  // Inst #1803 = V6_pred_and_128B
  { 1804,	3,	1,	4,	55,	0, 0xe00000000eULL, nullptr, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1804 = V6_pred_and_n
  { 1805,	3,	1,	4,	55,	0, 0xe00000000eULL, nullptr, nullptr, OperandInfo167, -1 ,nullptr },  // Inst #1805 = V6_pred_and_n_128B
  { 1806,	2,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo168, -1 ,nullptr },  // Inst #1806 = V6_pred_not
  { 1807,	2,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo169, -1 ,nullptr },  // Inst #1807 = V6_pred_not_128B
  { 1808,	3,	1,	4,	55,	0, 0xe00000000eULL, nullptr, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1808 = V6_pred_or
  { 1809,	3,	1,	4,	55,	0, 0xe00000000eULL, nullptr, nullptr, OperandInfo167, -1 ,nullptr },  // Inst #1809 = V6_pred_or_128B
  { 1810,	3,	1,	4,	55,	0, 0xe00000000eULL, nullptr, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1810 = V6_pred_or_n
  { 1811,	3,	1,	4,	55,	0, 0xe00000000eULL, nullptr, nullptr, OperandInfo167, -1 ,nullptr },  // Inst #1811 = V6_pred_or_n_128B
  { 1812,	2,	1,	4,	56,	0, 0xe000000011ULL, nullptr, nullptr, OperandInfo170, -1 ,nullptr },  // Inst #1812 = V6_pred_scalar2
  { 1813,	2,	1,	4,	56,	0, 0xe000000011ULL, nullptr, nullptr, OperandInfo171, -1 ,nullptr },  // Inst #1813 = V6_pred_scalar2_128B
  { 1814,	3,	1,	4,	55,	0, 0xe00000000eULL, nullptr, nullptr, OperandInfo166, -1 ,nullptr },  // Inst #1814 = V6_pred_xor
  { 1815,	3,	1,	4,	55,	0, 0xe00000000eULL, nullptr, nullptr, OperandInfo167, -1 ,nullptr },  // Inst #1815 = V6_pred_xor_128B
  { 1816,	3,	1,	4,	57,	0|(1ULL<<MCID::MayLoad), 0x3be000002018ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #1816 = V6_vL32Ub_ai
  { 1817,	3,	1,	4,	57,	0|(1ULL<<MCID::MayLoad), 0x43e000002018ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #1817 = V6_vL32Ub_ai_128B
  { 1818,	4,	2,	4,	57,	0|(1ULL<<MCID::MayLoad), 0x3ee000002018ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1818 = V6_vL32Ub_pi
  { 1819,	4,	2,	4,	57,	0|(1ULL<<MCID::MayLoad), 0x46e000002018ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1819 = V6_vL32Ub_pi_128B
  { 1820,	4,	2,	4,	57,	0|(1ULL<<MCID::MayLoad), 0xe000002018ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1820 = V6_vL32Ub_ppu
  { 1821,	3,	1,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x3be000082015ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #1821 = V6_vL32b_ai
  { 1822,	3,	1,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x43e000082015ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #1822 = V6_vL32b_ai_128B
  { 1823,	3,	1,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x3be000102015ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #1823 = V6_vL32b_cur_ai
  { 1824,	3,	1,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x43e000102015ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #1824 = V6_vL32b_cur_ai_128B
  { 1825,	4,	2,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x3ee000102015ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1825 = V6_vL32b_cur_pi
  { 1826,	4,	2,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x46e000102015ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1826 = V6_vL32b_cur_pi_128B
  { 1827,	4,	2,	4,	58,	0|(1ULL<<MCID::MayLoad), 0xe000102017ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1827 = V6_vL32b_cur_ppu
  { 1828,	3,	1,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x3be000082015ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #1828 = V6_vL32b_nt_ai
  { 1829,	3,	1,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x43e000082015ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #1829 = V6_vL32b_nt_ai_128B
  { 1830,	3,	1,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x3be000102015ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #1830 = V6_vL32b_nt_cur_ai
  { 1831,	3,	1,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x43e000102015ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #1831 = V6_vL32b_nt_cur_ai_128B
  { 1832,	4,	2,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x3ee000102015ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1832 = V6_vL32b_nt_cur_pi
  { 1833,	4,	2,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x46e000102015ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1833 = V6_vL32b_nt_cur_pi_128B
  { 1834,	4,	2,	4,	58,	0|(1ULL<<MCID::MayLoad), 0xe000102017ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1834 = V6_vL32b_nt_cur_ppu
  { 1835,	4,	2,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x3ee000082015ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1835 = V6_vL32b_nt_pi
  { 1836,	4,	2,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x46e000082015ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1836 = V6_vL32b_nt_pi_128B
  { 1837,	4,	2,	4,	43,	0|(1ULL<<MCID::MayLoad), 0xe000082015ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1837 = V6_vL32b_nt_ppu
  { 1838,	3,	1,	4,	59,	0|(1ULL<<MCID::MayLoad), 0x3be000002016ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #1838 = V6_vL32b_nt_tmp_ai
  { 1839,	3,	1,	4,	59,	0|(1ULL<<MCID::MayLoad), 0x43e000002016ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #1839 = V6_vL32b_nt_tmp_ai_128B
  { 1840,	4,	2,	4,	59,	0|(1ULL<<MCID::MayLoad), 0x3ee000002016ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1840 = V6_vL32b_nt_tmp_pi
  { 1841,	4,	2,	4,	59,	0|(1ULL<<MCID::MayLoad), 0x46e000002016ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1841 = V6_vL32b_nt_tmp_pi_128B
  { 1842,	4,	2,	4,	59,	0|(1ULL<<MCID::MayLoad), 0xe000002016ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1842 = V6_vL32b_nt_tmp_ppu
  { 1843,	4,	2,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x3ee000082015ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1843 = V6_vL32b_pi
  { 1844,	4,	2,	4,	43,	0|(1ULL<<MCID::MayLoad), 0x46e000082015ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1844 = V6_vL32b_pi_128B
  { 1845,	4,	2,	4,	43,	0|(1ULL<<MCID::MayLoad), 0xe000082015ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1845 = V6_vL32b_ppu
  { 1846,	3,	1,	4,	59,	0|(1ULL<<MCID::MayLoad), 0x3be000002016ULL, nullptr, nullptr, OperandInfo103, -1 ,nullptr },  // Inst #1846 = V6_vL32b_tmp_ai
  { 1847,	3,	1,	4,	59,	0|(1ULL<<MCID::MayLoad), 0x43e000002016ULL, nullptr, nullptr, OperandInfo104, -1 ,nullptr },  // Inst #1847 = V6_vL32b_tmp_ai_128B
  { 1848,	4,	2,	4,	59,	0|(1ULL<<MCID::MayLoad), 0x3ee000002016ULL, nullptr, nullptr, OperandInfo172, -1 ,nullptr },  // Inst #1848 = V6_vL32b_tmp_pi
  { 1849,	4,	2,	4,	59,	0|(1ULL<<MCID::MayLoad), 0x46e000002016ULL, nullptr, nullptr, OperandInfo173, -1 ,nullptr },  // Inst #1849 = V6_vL32b_tmp_pi_128B
  { 1850,	4,	2,	4,	59,	0|(1ULL<<MCID::MayLoad), 0xe000002016ULL, nullptr, nullptr, OperandInfo174, -1 ,nullptr },  // Inst #1850 = V6_vL32b_tmp_ppu
  { 1851,	3,	0,	4,	60,	0|(1ULL<<MCID::MayStore), 0x3be00000001bULL, nullptr, nullptr, OperandInfo156, -1 ,nullptr },  // Inst #1851 = V6_vS32Ub_ai
  { 1852,	3,	0,	4,	60,	0|(1ULL<<MCID::MayStore), 0x43e00000001bULL, nullptr, nullptr, OperandInfo157, -1 ,nullptr },  // Inst #1852 = V6_vS32Ub_ai_128B
  { 1853,	4,	0,	4,	60,	0|(1ULL<<MCID::MayStore), 0x3be00000031bULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1853 = V6_vS32Ub_npred_ai
  { 1854,	4,	0,	4,	60,	0|(1ULL<<MCID::MayStore), 0x43e00000031bULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1854 = V6_vS32Ub_npred_ai_128B
  { 1855,	5,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x3ee00000031bULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1855 = V6_vS32Ub_npred_pi
  { 1856,	5,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x46e00000031bULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1856 = V6_vS32Ub_npred_pi_128B
  { 1857,	5,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0xe00000031bULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1857 = V6_vS32Ub_npred_ppu
  { 1858,	4,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x3ee00000001bULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1858 = V6_vS32Ub_pi
  { 1859,	4,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x46e00000001bULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1859 = V6_vS32Ub_pi_128B
  { 1860,	4,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0xe00000001bULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1860 = V6_vS32Ub_ppu
  { 1861,	4,	0,	4,	60,	0|(1ULL<<MCID::MayStore), 0x3be00000011bULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1861 = V6_vS32Ub_pred_ai
  { 1862,	4,	0,	4,	60,	0|(1ULL<<MCID::MayStore), 0x43e00000011bULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1862 = V6_vS32Ub_pred_ai_128B
  { 1863,	5,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x3ee00000011bULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1863 = V6_vS32Ub_pred_pi
  { 1864,	5,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0x46e00000011bULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1864 = V6_vS32Ub_pred_pi_128B
  { 1865,	5,	1,	4,	60,	0|(1ULL<<MCID::MayStore), 0xe00000011bULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1865 = V6_vS32Ub_pred_ppu
  { 1866,	3,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3be000020019ULL, nullptr, nullptr, OperandInfo156, -1 ,nullptr },  // Inst #1866 = V6_vS32b_ai
  { 1867,	3,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x43e000020019ULL, nullptr, nullptr, OperandInfo157, -1 ,nullptr },  // Inst #1867 = V6_vS32b_ai_128B
  { 1868,	3,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3be00004901aULL, nullptr, nullptr, OperandInfo156, -1 ,nullptr },  // Inst #1868 = V6_vS32b_new_ai
  { 1869,	3,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x43e00004901aULL, nullptr, nullptr, OperandInfo157, -1 ,nullptr },  // Inst #1869 = V6_vS32b_new_ai_128B
  { 1870,	4,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3be00004d31aULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1870 = V6_vS32b_new_npred_ai
  { 1871,	4,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x43e00004d31aULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1871 = V6_vS32b_new_npred_ai_128B
  { 1872,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3ee00005131aULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1872 = V6_vS32b_new_npred_pi
  { 1873,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x46e00005131aULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1873 = V6_vS32b_new_npred_pi_128B
  { 1874,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0xe00005131aULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1874 = V6_vS32b_new_npred_ppu
  { 1875,	4,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3ee00004d01aULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1875 = V6_vS32b_new_pi
  { 1876,	4,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x46e00004d01aULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1876 = V6_vS32b_new_pi_128B
  { 1877,	4,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0xe00004d01aULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1877 = V6_vS32b_new_ppu
  { 1878,	4,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3be00004d11aULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1878 = V6_vS32b_new_pred_ai
  { 1879,	4,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x43e00004d11aULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1879 = V6_vS32b_new_pred_ai_128B
  { 1880,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3ee00005111aULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1880 = V6_vS32b_new_pred_pi
  { 1881,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x46e00005111aULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1881 = V6_vS32b_new_pred_pi_128B
  { 1882,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0xe00005111aULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1882 = V6_vS32b_new_pred_ppu
  { 1883,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3be000020319ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1883 = V6_vS32b_npred_ai
  { 1884,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x43e000020319ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1884 = V6_vS32b_npred_ai_128B
  { 1885,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3ee000020319ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1885 = V6_vS32b_npred_pi
  { 1886,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x46e000020319ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1886 = V6_vS32b_npred_pi_128B
  { 1887,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0xe000020319ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1887 = V6_vS32b_npred_ppu
  { 1888,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3be000000219ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1888 = V6_vS32b_nqpred_ai
  { 1889,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x43e000000219ULL, nullptr, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1889 = V6_vS32b_nqpred_ai_128B
  { 1890,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3ee000000019ULL, nullptr, nullptr, OperandInfo185, -1 ,nullptr },  // Inst #1890 = V6_vS32b_nqpred_pi
  { 1891,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x46e000000019ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1891 = V6_vS32b_nqpred_pi_128B
  { 1892,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0xe000000019ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1892 = V6_vS32b_nqpred_ppu
  { 1893,	3,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3be000020019ULL, nullptr, nullptr, OperandInfo156, -1 ,nullptr },  // Inst #1893 = V6_vS32b_nt_ai
  { 1894,	3,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x43e000020019ULL, nullptr, nullptr, OperandInfo157, -1 ,nullptr },  // Inst #1894 = V6_vS32b_nt_ai_128B
  { 1895,	3,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3be00004901aULL, nullptr, nullptr, OperandInfo156, -1 ,nullptr },  // Inst #1895 = V6_vS32b_nt_new_ai
  { 1896,	3,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x43e00004901aULL, nullptr, nullptr, OperandInfo157, -1 ,nullptr },  // Inst #1896 = V6_vS32b_nt_new_ai_128B
  { 1897,	4,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3be00004d31aULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1897 = V6_vS32b_nt_new_npred_ai
  { 1898,	4,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x43e00004d31aULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1898 = V6_vS32b_nt_new_npred_ai_128B
  { 1899,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3ee00005131aULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1899 = V6_vS32b_nt_new_npred_pi
  { 1900,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x46e00005131aULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1900 = V6_vS32b_nt_new_npred_pi_128B
  { 1901,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0xe00005131aULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1901 = V6_vS32b_nt_new_npred_ppu
  { 1902,	4,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3ee00004d01aULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1902 = V6_vS32b_nt_new_pi
  { 1903,	4,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x46e00004d01aULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1903 = V6_vS32b_nt_new_pi_128B
  { 1904,	4,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0xe00004d01aULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1904 = V6_vS32b_nt_new_ppu
  { 1905,	4,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3be00004d11aULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1905 = V6_vS32b_nt_new_pred_ai
  { 1906,	4,	0,	4,	61,	0|(1ULL<<MCID::MayStore), 0x43e00004d11aULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1906 = V6_vS32b_nt_new_pred_ai_128B
  { 1907,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x3ee00005111aULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1907 = V6_vS32b_nt_new_pred_pi
  { 1908,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0x46e00005111aULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1908 = V6_vS32b_nt_new_pred_pi_128B
  { 1909,	5,	1,	4,	61,	0|(1ULL<<MCID::MayStore), 0xe00005111aULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1909 = V6_vS32b_nt_new_pred_ppu
  { 1910,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3be000020319ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1910 = V6_vS32b_nt_npred_ai
  { 1911,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x43e000020319ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1911 = V6_vS32b_nt_npred_ai_128B
  { 1912,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3ee000020319ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1912 = V6_vS32b_nt_npred_pi
  { 1913,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x46e000020319ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1913 = V6_vS32b_nt_npred_pi_128B
  { 1914,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0xe000020319ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1914 = V6_vS32b_nt_npred_ppu
  { 1915,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3be000000219ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1915 = V6_vS32b_nt_nqpred_ai
  { 1916,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x43e000000219ULL, nullptr, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1916 = V6_vS32b_nt_nqpred_ai_128B
  { 1917,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3ee000000019ULL, nullptr, nullptr, OperandInfo185, -1 ,nullptr },  // Inst #1917 = V6_vS32b_nt_nqpred_pi
  { 1918,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x46e000000019ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1918 = V6_vS32b_nt_nqpred_pi_128B
  { 1919,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0xe000000019ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1919 = V6_vS32b_nt_nqpred_ppu
  { 1920,	4,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3ee000020019ULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1920 = V6_vS32b_nt_pi
  { 1921,	4,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x46e000020019ULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1921 = V6_vS32b_nt_pi_128B
  { 1922,	4,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0xe000020019ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1922 = V6_vS32b_nt_ppu
  { 1923,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3be000020119ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1923 = V6_vS32b_nt_pred_ai
  { 1924,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x43e000020119ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1924 = V6_vS32b_nt_pred_ai_128B
  { 1925,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3ee000020119ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1925 = V6_vS32b_nt_pred_pi
  { 1926,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x46e000020119ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1926 = V6_vS32b_nt_pred_pi_128B
  { 1927,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0xe000020119ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1927 = V6_vS32b_nt_pred_ppu
  { 1928,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3be000000019ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1928 = V6_vS32b_nt_qpred_ai
  { 1929,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x43e000000019ULL, nullptr, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1929 = V6_vS32b_nt_qpred_ai_128B
  { 1930,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3ee000000019ULL, nullptr, nullptr, OperandInfo185, -1 ,nullptr },  // Inst #1930 = V6_vS32b_nt_qpred_pi
  { 1931,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x46e000000019ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1931 = V6_vS32b_nt_qpred_pi_128B
  { 1932,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0xe000000019ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1932 = V6_vS32b_nt_qpred_ppu
  { 1933,	4,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3ee000020019ULL, nullptr, nullptr, OperandInfo180, -1 ,nullptr },  // Inst #1933 = V6_vS32b_pi
  { 1934,	4,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x46e000020019ULL, nullptr, nullptr, OperandInfo181, -1 ,nullptr },  // Inst #1934 = V6_vS32b_pi_128B
  { 1935,	4,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0xe000020019ULL, nullptr, nullptr, OperandInfo182, -1 ,nullptr },  // Inst #1935 = V6_vS32b_ppu
  { 1936,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3be000020119ULL, nullptr, nullptr, OperandInfo175, -1 ,nullptr },  // Inst #1936 = V6_vS32b_pred_ai
  { 1937,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x43e000020119ULL, nullptr, nullptr, OperandInfo176, -1 ,nullptr },  // Inst #1937 = V6_vS32b_pred_ai_128B
  { 1938,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3ee000020119ULL, nullptr, nullptr, OperandInfo177, -1 ,nullptr },  // Inst #1938 = V6_vS32b_pred_pi
  { 1939,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x46e000020119ULL, nullptr, nullptr, OperandInfo178, -1 ,nullptr },  // Inst #1939 = V6_vS32b_pred_pi_128B
  { 1940,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0xe000020119ULL, nullptr, nullptr, OperandInfo179, -1 ,nullptr },  // Inst #1940 = V6_vS32b_pred_ppu
  { 1941,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3be000000019ULL, nullptr, nullptr, OperandInfo183, -1 ,nullptr },  // Inst #1941 = V6_vS32b_qpred_ai
  { 1942,	4,	0,	4,	52,	0|(1ULL<<MCID::MayStore), 0x43e000000019ULL, nullptr, nullptr, OperandInfo184, -1 ,nullptr },  // Inst #1942 = V6_vS32b_qpred_ai_128B
  { 1943,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x3ee000000019ULL, nullptr, nullptr, OperandInfo185, -1 ,nullptr },  // Inst #1943 = V6_vS32b_qpred_pi
  { 1944,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0x46e000000019ULL, nullptr, nullptr, OperandInfo186, -1 ,nullptr },  // Inst #1944 = V6_vS32b_qpred_pi_128B
  { 1945,	5,	1,	4,	52,	0|(1ULL<<MCID::MayStore), 0xe000000019ULL, nullptr, nullptr, OperandInfo187, -1 ,nullptr },  // Inst #1945 = V6_vS32b_qpred_ppu
  { 1946,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1946 = V6_vabsdiffh
  { 1947,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1947 = V6_vabsdiffh_128B
  { 1948,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1948 = V6_vabsdiffub
  { 1949,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1949 = V6_vabsdiffub_128B
  { 1950,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1950 = V6_vabsdiffuh
  { 1951,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1951 = V6_vabsdiffuh_128B
  { 1952,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1952 = V6_vabsdiffw
  { 1953,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1953 = V6_vabsdiffw_128B
  { 1954,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #1954 = V6_vabsh
  { 1955,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #1955 = V6_vabsh_128B
  { 1956,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #1956 = V6_vabsh_sat
  { 1957,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #1957 = V6_vabsh_sat_128B
  { 1958,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #1958 = V6_vabsw
  { 1959,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #1959 = V6_vabsw_128B
  { 1960,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #1960 = V6_vabsw_sat
  { 1961,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #1961 = V6_vabsw_sat_128B
  { 1962,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1962 = V6_vaddb
  { 1963,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1963 = V6_vaddb_128B
  { 1964,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1964 = V6_vaddb_dv
  { 1965,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1965 = V6_vaddb_dv_128B
  { 1966,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1966 = V6_vaddbnq
  { 1967,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1967 = V6_vaddbnq_128B
  { 1968,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1968 = V6_vaddbq
  { 1969,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1969 = V6_vaddbq_128B
  { 1970,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1970 = V6_vaddh
  { 1971,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1971 = V6_vaddh_128B
  { 1972,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1972 = V6_vaddh_dv
  { 1973,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1973 = V6_vaddh_dv_128B
  { 1974,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1974 = V6_vaddhnq
  { 1975,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1975 = V6_vaddhnq_128B
  { 1976,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #1976 = V6_vaddhq
  { 1977,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #1977 = V6_vaddhq_128B
  { 1978,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1978 = V6_vaddhsat
  { 1979,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1979 = V6_vaddhsat_128B
  { 1980,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1980 = V6_vaddhsat_dv
  { 1981,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1981 = V6_vaddhsat_dv_128B
  { 1982,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #1982 = V6_vaddhw
  { 1983,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #1983 = V6_vaddhw_128B
  { 1984,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #1984 = V6_vaddubh
  { 1985,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #1985 = V6_vaddubh_128B
  { 1986,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1986 = V6_vaddubsat
  { 1987,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1987 = V6_vaddubsat_128B
  { 1988,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1988 = V6_vaddubsat_dv
  { 1989,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1989 = V6_vaddubsat_dv_128B
  { 1990,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1990 = V6_vadduhsat
  { 1991,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1991 = V6_vadduhsat_128B
  { 1992,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1992 = V6_vadduhsat_dv
  { 1993,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1993 = V6_vadduhsat_dv_128B
  { 1994,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #1994 = V6_vadduhw
  { 1995,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #1995 = V6_vadduhw_128B
  { 1996,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #1996 = V6_vaddw
  { 1997,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #1997 = V6_vaddw_128B
  { 1998,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #1998 = V6_vaddw_dv
  { 1999,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #1999 = V6_vaddw_dv_128B
  { 2000,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #2000 = V6_vaddwnq
  { 2001,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #2001 = V6_vaddwnq_128B
  { 2002,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #2002 = V6_vaddwq
  { 2003,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #2003 = V6_vaddwq_128B
  { 2004,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2004 = V6_vaddwsat
  { 2005,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2005 = V6_vaddwsat_128B
  { 2006,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #2006 = V6_vaddwsat_dv
  { 2007,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #2007 = V6_vaddwsat_dv_128B
  { 2008,	4,	1,	4,	56,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2008 = V6_valignb
  { 2009,	4,	1,	4,	56,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2009 = V6_valignb_128B
  { 2010,	4,	1,	4,	56,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #2010 = V6_valignbi
  { 2011,	4,	1,	4,	56,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #2011 = V6_valignbi_128B
  { 2012,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2012 = V6_vand
  { 2013,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2013 = V6_vand_128B
  { 2014,	3,	1,	4,	54,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo202, -1 ,nullptr },  // Inst #2014 = V6_vandqrt
  { 2015,	3,	1,	4,	54,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo203, -1 ,nullptr },  // Inst #2015 = V6_vandqrt_128B
  { 2016,	4,	1,	4,	54,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo204, -1 ,nullptr },  // Inst #2016 = V6_vandqrt_acc
  { 2017,	4,	1,	4,	54,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo205, -1 ,nullptr },  // Inst #2017 = V6_vandqrt_acc_128B
  { 2018,	3,	1,	4,	54,	0, 0xe00000000fULL, nullptr, nullptr, OperandInfo206, -1 ,nullptr },  // Inst #2018 = V6_vandvrt
  { 2019,	3,	1,	4,	54,	0, 0xe00000000fULL, nullptr, nullptr, OperandInfo207, -1 ,nullptr },  // Inst #2019 = V6_vandvrt_128B
  { 2020,	4,	1,	4,	54,	0, 0x4000e00000000fULL, nullptr, nullptr, OperandInfo208, -1 ,nullptr },  // Inst #2020 = V6_vandvrt_acc
  { 2021,	4,	1,	4,	54,	0, 0x4000e00000000fULL, nullptr, nullptr, OperandInfo209, -1 ,nullptr },  // Inst #2021 = V6_vandvrt_acc_128B
  { 2022,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2022 = V6_vaslh
  { 2023,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2023 = V6_vaslh_128B
  { 2024,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2024 = V6_vaslhv
  { 2025,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2025 = V6_vaslhv_128B
  { 2026,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2026 = V6_vaslw
  { 2027,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2027 = V6_vaslw_128B
  { 2028,	4,	1,	4,	64,	0, 0x4000e000002013ULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2028 = V6_vaslw_acc
  { 2029,	4,	1,	4,	64,	0, 0x4000e000002013ULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2029 = V6_vaslw_acc_128B
  { 2030,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2030 = V6_vaslwv
  { 2031,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2031 = V6_vaslwv_128B
  { 2032,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2032 = V6_vasrh
  { 2033,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2033 = V6_vasrh_128B
  { 2034,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2034 = V6_vasrhbrndsat
  { 2035,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2035 = V6_vasrhbrndsat_128B
  { 2036,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2036 = V6_vasrhubrndsat
  { 2037,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2037 = V6_vasrhubrndsat_128B
  { 2038,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2038 = V6_vasrhubsat
  { 2039,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2039 = V6_vasrhubsat_128B
  { 2040,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2040 = V6_vasrhv
  { 2041,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2041 = V6_vasrhv_128B
  { 2042,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2042 = V6_vasrw
  { 2043,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2043 = V6_vasrw_128B
  { 2044,	4,	1,	4,	64,	0, 0x4000e000002013ULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2044 = V6_vasrw_acc
  { 2045,	4,	1,	4,	64,	0, 0x4000e000002013ULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2045 = V6_vasrw_acc_128B
  { 2046,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2046 = V6_vasrwh
  { 2047,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2047 = V6_vasrwh_128B
  { 2048,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2048 = V6_vasrwhrndsat
  { 2049,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2049 = V6_vasrwhrndsat_128B
  { 2050,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2050 = V6_vasrwhsat
  { 2051,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2051 = V6_vasrwhsat_128B
  { 2052,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2052 = V6_vasrwuhsat
  { 2053,	4,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2053 = V6_vasrwuhsat_128B
  { 2054,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2054 = V6_vasrwv
  { 2055,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2055 = V6_vasrwv_128B
  { 2056,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2056 = V6_vassign
  { 2057,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2057 = V6_vassign_128B
  { 2058,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2058 = V6_vavgh
  { 2059,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2059 = V6_vavgh_128B
  { 2060,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2060 = V6_vavghrnd
  { 2061,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2061 = V6_vavghrnd_128B
  { 2062,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2062 = V6_vavgub
  { 2063,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2063 = V6_vavgub_128B
  { 2064,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2064 = V6_vavgubrnd
  { 2065,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2065 = V6_vavgubrnd_128B
  { 2066,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2066 = V6_vavguh
  { 2067,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2067 = V6_vavguh_128B
  { 2068,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2068 = V6_vavguhrnd
  { 2069,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2069 = V6_vavguhrnd_128B
  { 2070,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2070 = V6_vavgw
  { 2071,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2071 = V6_vavgw_128B
  { 2072,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2072 = V6_vavgwrnd
  { 2073,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2073 = V6_vavgwrnd_128B
  { 2074,	4,	1,	4,	55,	0, 0xe00000210eULL, nullptr, nullptr, OperandInfo214, -1 ,nullptr },  // Inst #2074 = V6_vccombine
  { 2075,	4,	1,	4,	55,	0, 0xe00000210eULL, nullptr, nullptr, OperandInfo215, -1 ,nullptr },  // Inst #2075 = V6_vccombine_128B
  { 2076,	2,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2076 = V6_vcl0h
  { 2077,	2,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2077 = V6_vcl0h_128B
  { 2078,	2,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2078 = V6_vcl0w
  { 2079,	2,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2079 = V6_vcl0w_128B
  { 2080,	3,	1,	4,	33,	0, 0xe00000210dULL, nullptr, nullptr, OperandInfo216, -1 ,nullptr },  // Inst #2080 = V6_vcmov
  { 2081,	3,	1,	4,	33,	0, 0xe00000210dULL, nullptr, nullptr, OperandInfo217, -1 ,nullptr },  // Inst #2081 = V6_vcmov_128B
  { 2082,	3,	1,	4,	55,	0|(1ULL<<MCID::RegSequence), 0xe00000200eULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2082 = V6_vcombine
  { 2083,	3,	1,	4,	55,	0|(1ULL<<MCID::RegSequence), 0xe00000200eULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2083 = V6_vcombine_128B
  { 2084,	5,	2,	4,	65,	0, 0xc00e000002012ULL, nullptr, nullptr, OperandInfo218, -1 ,nullptr },  // Inst #2084 = V6_vdeal
  { 2085,	5,	2,	4,	65,	0, 0xc00e000002012ULL, nullptr, nullptr, OperandInfo219, -1 ,nullptr },  // Inst #2085 = V6_vdeal_128B
  { 2086,	2,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2086 = V6_vdealb
  { 2087,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2087 = V6_vdealb4w
  { 2088,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2088 = V6_vdealb4w_128B
  { 2089,	2,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2089 = V6_vdealb_128B
  { 2090,	2,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2090 = V6_vdealh
  { 2091,	2,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2091 = V6_vdealh_128B
  { 2092,	4,	1,	4,	67,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo220, -1 ,nullptr },  // Inst #2092 = V6_vdealvdd
  { 2093,	4,	1,	4,	67,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo221, -1 ,nullptr },  // Inst #2093 = V6_vdealvdd_128B
  { 2094,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2094 = V6_vdelta
  { 2095,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2095 = V6_vdelta_128B
  { 2096,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2096 = V6_vdmpybus
  { 2097,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2097 = V6_vdmpybus_128B
  { 2098,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2098 = V6_vdmpybus_acc
  { 2099,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2099 = V6_vdmpybus_acc_128B
  { 2100,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #2100 = V6_vdmpybus_dv
  { 2101,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo223, -1 ,nullptr },  // Inst #2101 = V6_vdmpybus_dv_128B
  { 2102,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo224, -1 ,nullptr },  // Inst #2102 = V6_vdmpybus_dv_acc
  { 2103,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo225, -1 ,nullptr },  // Inst #2103 = V6_vdmpybus_dv_acc_128B
  { 2104,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2104 = V6_vdmpyhb
  { 2105,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2105 = V6_vdmpyhb_128B
  { 2106,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2106 = V6_vdmpyhb_acc
  { 2107,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2107 = V6_vdmpyhb_acc_128B
  { 2108,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #2108 = V6_vdmpyhb_dv
  { 2109,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo223, -1 ,nullptr },  // Inst #2109 = V6_vdmpyhb_dv_128B
  { 2110,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo224, -1 ,nullptr },  // Inst #2110 = V6_vdmpyhb_dv_acc
  { 2111,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo225, -1 ,nullptr },  // Inst #2111 = V6_vdmpyhb_dv_acc_128B
  { 2112,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo226, -1 ,nullptr },  // Inst #2112 = V6_vdmpyhisat
  { 2113,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo227, -1 ,nullptr },  // Inst #2113 = V6_vdmpyhisat_128B
  { 2114,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo228, -1 ,nullptr },  // Inst #2114 = V6_vdmpyhisat_acc
  { 2115,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo229, -1 ,nullptr },  // Inst #2115 = V6_vdmpyhisat_acc_128B
  { 2116,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2116 = V6_vdmpyhsat
  { 2117,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2117 = V6_vdmpyhsat_128B
  { 2118,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2118 = V6_vdmpyhsat_acc
  { 2119,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2119 = V6_vdmpyhsat_acc_128B
  { 2120,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo226, -1 ,nullptr },  // Inst #2120 = V6_vdmpyhsuisat
  { 2121,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo227, -1 ,nullptr },  // Inst #2121 = V6_vdmpyhsuisat_128B
  { 2122,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo228, -1 ,nullptr },  // Inst #2122 = V6_vdmpyhsuisat_acc
  { 2123,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo229, -1 ,nullptr },  // Inst #2123 = V6_vdmpyhsuisat_acc_128B
  { 2124,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2124 = V6_vdmpyhsusat
  { 2125,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2125 = V6_vdmpyhsusat_128B
  { 2126,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2126 = V6_vdmpyhsusat_acc
  { 2127,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2127 = V6_vdmpyhsusat_acc_128B
  { 2128,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2128 = V6_vdmpyhvsat
  { 2129,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2129 = V6_vdmpyhvsat_128B
  { 2130,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #2130 = V6_vdmpyhvsat_acc
  { 2131,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #2131 = V6_vdmpyhvsat_acc_128B
  { 2132,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #2132 = V6_vdsaduh
  { 2133,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo223, -1 ,nullptr },  // Inst #2133 = V6_vdsaduh_128B
  { 2134,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo224, -1 ,nullptr },  // Inst #2134 = V6_vdsaduh_acc
  { 2135,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo225, -1 ,nullptr },  // Inst #2135 = V6_vdsaduh_acc_128B
  { 2136,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo232, -1 ,nullptr },  // Inst #2136 = V6_veqb
  { 2137,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #2137 = V6_veqb_128B
  { 2138,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2138 = V6_veqb_and
  { 2139,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2139 = V6_veqb_and_128B
  { 2140,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2140 = V6_veqb_or
  { 2141,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2141 = V6_veqb_or_128B
  { 2142,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2142 = V6_veqb_xor
  { 2143,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2143 = V6_veqb_xor_128B
  { 2144,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo232, -1 ,nullptr },  // Inst #2144 = V6_veqh
  { 2145,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #2145 = V6_veqh_128B
  { 2146,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2146 = V6_veqh_and
  { 2147,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2147 = V6_veqh_and_128B
  { 2148,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2148 = V6_veqh_or
  { 2149,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2149 = V6_veqh_or_128B
  { 2150,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2150 = V6_veqh_xor
  { 2151,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2151 = V6_veqh_xor_128B
  { 2152,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo232, -1 ,nullptr },  // Inst #2152 = V6_veqw
  { 2153,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #2153 = V6_veqw_128B
  { 2154,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2154 = V6_veqw_and
  { 2155,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2155 = V6_veqw_and_128B
  { 2156,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2156 = V6_veqw_or
  { 2157,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2157 = V6_veqw_or_128B
  { 2158,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2158 = V6_veqw_xor
  { 2159,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2159 = V6_veqw_xor_128B
  { 2160,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo232, -1 ,nullptr },  // Inst #2160 = V6_vgtb
  { 2161,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #2161 = V6_vgtb_128B
  { 2162,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2162 = V6_vgtb_and
  { 2163,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2163 = V6_vgtb_and_128B
  { 2164,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2164 = V6_vgtb_or
  { 2165,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2165 = V6_vgtb_or_128B
  { 2166,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2166 = V6_vgtb_xor
  { 2167,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2167 = V6_vgtb_xor_128B
  { 2168,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo232, -1 ,nullptr },  // Inst #2168 = V6_vgth
  { 2169,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #2169 = V6_vgth_128B
  { 2170,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2170 = V6_vgth_and
  { 2171,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2171 = V6_vgth_and_128B
  { 2172,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2172 = V6_vgth_or
  { 2173,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2173 = V6_vgth_or_128B
  { 2174,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2174 = V6_vgth_xor
  { 2175,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2175 = V6_vgth_xor_128B
  { 2176,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo232, -1 ,nullptr },  // Inst #2176 = V6_vgtub
  { 2177,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #2177 = V6_vgtub_128B
  { 2178,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2178 = V6_vgtub_and
  { 2179,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2179 = V6_vgtub_and_128B
  { 2180,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2180 = V6_vgtub_or
  { 2181,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2181 = V6_vgtub_or_128B
  { 2182,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2182 = V6_vgtub_xor
  { 2183,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2183 = V6_vgtub_xor_128B
  { 2184,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo232, -1 ,nullptr },  // Inst #2184 = V6_vgtuh
  { 2185,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #2185 = V6_vgtuh_128B
  { 2186,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2186 = V6_vgtuh_and
  { 2187,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2187 = V6_vgtuh_and_128B
  { 2188,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2188 = V6_vgtuh_or
  { 2189,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2189 = V6_vgtuh_or_128B
  { 2190,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2190 = V6_vgtuh_xor
  { 2191,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2191 = V6_vgtuh_xor_128B
  { 2192,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo232, -1 ,nullptr },  // Inst #2192 = V6_vgtuw
  { 2193,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #2193 = V6_vgtuw_128B
  { 2194,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2194 = V6_vgtuw_and
  { 2195,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2195 = V6_vgtuw_and_128B
  { 2196,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2196 = V6_vgtuw_or
  { 2197,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2197 = V6_vgtuw_or_128B
  { 2198,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2198 = V6_vgtuw_xor
  { 2199,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2199 = V6_vgtuw_xor_128B
  { 2200,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo232, -1 ,nullptr },  // Inst #2200 = V6_vgtw
  { 2201,	3,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo233, -1 ,nullptr },  // Inst #2201 = V6_vgtw_128B
  { 2202,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2202 = V6_vgtw_and
  { 2203,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2203 = V6_vgtw_and_128B
  { 2204,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2204 = V6_vgtw_or
  { 2205,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2205 = V6_vgtw_or_128B
  { 2206,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo234, -1 ,nullptr },  // Inst #2206 = V6_vgtw_xor
  { 2207,	4,	1,	4,	33,	0, 0xe00000000dULL, nullptr, nullptr, OperandInfo235, -1 ,nullptr },  // Inst #2207 = V6_vgtw_xor_128B
  { 2208,	0,	0,	4,	68,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xe00000001cULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2208 = V6_vhist
  { 2209,	1,	0,	4,	68,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xe00000001cULL, nullptr, nullptr, OperandInfo236, -1 ,nullptr },  // Inst #2209 = V6_vhistq
  { 2210,	3,	1,	4,	54,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo237, -1 ,nullptr },  // Inst #2210 = V6_vinsertwr
  { 2211,	3,	1,	4,	54,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo238, -1 ,nullptr },  // Inst #2211 = V6_vinsertwr_128B
  { 2212,	4,	1,	4,	56,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2212 = V6_vlalignb
  { 2213,	4,	1,	4,	56,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2213 = V6_vlalignb_128B
  { 2214,	4,	1,	4,	56,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo200, -1 ,nullptr },  // Inst #2214 = V6_vlalignbi
  { 2215,	4,	1,	4,	56,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo201, -1 ,nullptr },  // Inst #2215 = V6_vlalignbi_128B
  { 2216,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2216 = V6_vlsrh
  { 2217,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2217 = V6_vlsrh_128B
  { 2218,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2218 = V6_vlsrhv
  { 2219,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2219 = V6_vlsrhv_128B
  { 2220,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2220 = V6_vlsrw
  { 2221,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2221 = V6_vlsrw_128B
  { 2222,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2222 = V6_vlsrwv
  { 2223,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2223 = V6_vlsrwv_128B
  { 2224,	4,	1,	4,	56,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo198, -1 ,nullptr },  // Inst #2224 = V6_vlutvvb
  { 2225,	4,	1,	4,	56,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo199, -1 ,nullptr },  // Inst #2225 = V6_vlutvvb_128B
  { 2226,	5,	1,	4,	67,	0, 0x4000e000002012ULL, nullptr, nullptr, OperandInfo239, -1 ,nullptr },  // Inst #2226 = V6_vlutvvb_oracc
  { 2227,	5,	1,	4,	67,	0, 0x4000e000002012ULL, nullptr, nullptr, OperandInfo240, -1 ,nullptr },  // Inst #2227 = V6_vlutvvb_oracc_128B
  { 2228,	4,	1,	4,	67,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo220, -1 ,nullptr },  // Inst #2228 = V6_vlutvwh
  { 2229,	4,	1,	4,	67,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo221, -1 ,nullptr },  // Inst #2229 = V6_vlutvwh_128B
  { 2230,	5,	1,	4,	67,	0, 0x4000e000002012ULL, nullptr, nullptr, OperandInfo241, -1 ,nullptr },  // Inst #2230 = V6_vlutvwh_oracc
  { 2231,	5,	1,	4,	67,	0, 0x4000e000002012ULL, nullptr, nullptr, OperandInfo242, -1 ,nullptr },  // Inst #2231 = V6_vlutvwh_oracc_128B
  { 2232,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2232 = V6_vmaxh
  { 2233,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2233 = V6_vmaxh_128B
  { 2234,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2234 = V6_vmaxub
  { 2235,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2235 = V6_vmaxub_128B
  { 2236,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2236 = V6_vmaxuh
  { 2237,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2237 = V6_vmaxuh_128B
  { 2238,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2238 = V6_vmaxw
  { 2239,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2239 = V6_vmaxw_128B
  { 2240,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2240 = V6_vminh
  { 2241,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2241 = V6_vminh_128B
  { 2242,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2242 = V6_vminub
  { 2243,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2243 = V6_vminub_128B
  { 2244,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2244 = V6_vminuh
  { 2245,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2245 = V6_vminuh_128B
  { 2246,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2246 = V6_vminw
  { 2247,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2247 = V6_vminw_128B
  { 2248,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #2248 = V6_vmpabus
  { 2249,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo223, -1 ,nullptr },  // Inst #2249 = V6_vmpabus_128B
  { 2250,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo224, -1 ,nullptr },  // Inst #2250 = V6_vmpabus_acc
  { 2251,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo225, -1 ,nullptr },  // Inst #2251 = V6_vmpabus_acc_128B
  { 2252,	3,	1,	4,	69,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #2252 = V6_vmpabusv
  { 2253,	3,	1,	4,	69,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #2253 = V6_vmpabusv_128B
  { 2254,	3,	1,	4,	69,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #2254 = V6_vmpabuuv
  { 2255,	3,	1,	4,	69,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #2255 = V6_vmpabuuv_128B
  { 2256,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #2256 = V6_vmpahb
  { 2257,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo223, -1 ,nullptr },  // Inst #2257 = V6_vmpahb_128B
  { 2258,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo224, -1 ,nullptr },  // Inst #2258 = V6_vmpahb_acc
  { 2259,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo225, -1 ,nullptr },  // Inst #2259 = V6_vmpahb_acc_128B
  { 2260,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo243, -1 ,nullptr },  // Inst #2260 = V6_vmpybus
  { 2261,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo244, -1 ,nullptr },  // Inst #2261 = V6_vmpybus_128B
  { 2262,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo245, -1 ,nullptr },  // Inst #2262 = V6_vmpybus_acc
  { 2263,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo246, -1 ,nullptr },  // Inst #2263 = V6_vmpybus_acc_128B
  { 2264,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2264 = V6_vmpybusv
  { 2265,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2265 = V6_vmpybusv_128B
  { 2266,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo247, -1 ,nullptr },  // Inst #2266 = V6_vmpybusv_acc
  { 2267,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo248, -1 ,nullptr },  // Inst #2267 = V6_vmpybusv_acc_128B
  { 2268,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2268 = V6_vmpybv
  { 2269,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2269 = V6_vmpybv_128B
  { 2270,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo247, -1 ,nullptr },  // Inst #2270 = V6_vmpybv_acc
  { 2271,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo248, -1 ,nullptr },  // Inst #2271 = V6_vmpybv_acc_128B
  { 2272,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2272 = V6_vmpyewuh
  { 2273,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2273 = V6_vmpyewuh_128B
  { 2274,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo243, -1 ,nullptr },  // Inst #2274 = V6_vmpyh
  { 2275,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo244, -1 ,nullptr },  // Inst #2275 = V6_vmpyh_128B
  { 2276,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo245, -1 ,nullptr },  // Inst #2276 = V6_vmpyhsat_acc
  { 2277,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo246, -1 ,nullptr },  // Inst #2277 = V6_vmpyhsat_acc_128B
  { 2278,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2278 = V6_vmpyhsrs
  { 2279,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2279 = V6_vmpyhsrs_128B
  { 2280,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2280 = V6_vmpyhss
  { 2281,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2281 = V6_vmpyhss_128B
  { 2282,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2282 = V6_vmpyhus
  { 2283,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2283 = V6_vmpyhus_128B
  { 2284,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo247, -1 ,nullptr },  // Inst #2284 = V6_vmpyhus_acc
  { 2285,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo248, -1 ,nullptr },  // Inst #2285 = V6_vmpyhus_acc_128B
  { 2286,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2286 = V6_vmpyhv
  { 2287,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2287 = V6_vmpyhv_128B
  { 2288,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo247, -1 ,nullptr },  // Inst #2288 = V6_vmpyhv_acc
  { 2289,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo248, -1 ,nullptr },  // Inst #2289 = V6_vmpyhv_acc_128B
  { 2290,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2290 = V6_vmpyhvsrs
  { 2291,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2291 = V6_vmpyhvsrs_128B
  { 2292,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2292 = V6_vmpyieoh
  { 2293,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2293 = V6_vmpyieoh_128B
  { 2294,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #2294 = V6_vmpyiewh_acc
  { 2295,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #2295 = V6_vmpyiewh_acc_128B
  { 2296,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2296 = V6_vmpyiewuh
  { 2297,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2297 = V6_vmpyiewuh_128B
  { 2298,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #2298 = V6_vmpyiewuh_acc
  { 2299,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #2299 = V6_vmpyiewuh_acc_128B
  { 2300,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2300 = V6_vmpyih
  { 2301,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2301 = V6_vmpyih_128B
  { 2302,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #2302 = V6_vmpyih_acc
  { 2303,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #2303 = V6_vmpyih_acc_128B
  { 2304,	3,	1,	4,	70,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2304 = V6_vmpyihb
  { 2305,	3,	1,	4,	70,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2305 = V6_vmpyihb_128B
  { 2306,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2306 = V6_vmpyihb_acc
  { 2307,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2307 = V6_vmpyihb_acc_128B
  { 2308,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2308 = V6_vmpyiowh
  { 2309,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2309 = V6_vmpyiowh_128B
  { 2310,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2310 = V6_vmpyiwb
  { 2311,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2311 = V6_vmpyiwb_128B
  { 2312,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2312 = V6_vmpyiwb_acc
  { 2313,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2313 = V6_vmpyiwb_acc_128B
  { 2314,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2314 = V6_vmpyiwh
  { 2315,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2315 = V6_vmpyiwh_128B
  { 2316,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2316 = V6_vmpyiwh_acc
  { 2317,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2317 = V6_vmpyiwh_acc_128B
  { 2318,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2318 = V6_vmpyowh
  { 2319,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2319 = V6_vmpyowh_128B
  { 2320,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2320 = V6_vmpyowh_rnd
  { 2321,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2321 = V6_vmpyowh_rnd_128B
  { 2322,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #2322 = V6_vmpyowh_rnd_sacc
  { 2323,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #2323 = V6_vmpyowh_rnd_sacc_128B
  { 2324,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #2324 = V6_vmpyowh_sacc
  { 2325,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #2325 = V6_vmpyowh_sacc_128B
  { 2326,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo243, -1 ,nullptr },  // Inst #2326 = V6_vmpyub
  { 2327,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo244, -1 ,nullptr },  // Inst #2327 = V6_vmpyub_128B
  { 2328,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo245, -1 ,nullptr },  // Inst #2328 = V6_vmpyub_acc
  { 2329,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo246, -1 ,nullptr },  // Inst #2329 = V6_vmpyub_acc_128B
  { 2330,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2330 = V6_vmpyubv
  { 2331,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2331 = V6_vmpyubv_128B
  { 2332,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo247, -1 ,nullptr },  // Inst #2332 = V6_vmpyubv_acc
  { 2333,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo248, -1 ,nullptr },  // Inst #2333 = V6_vmpyubv_acc_128B
  { 2334,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo243, -1 ,nullptr },  // Inst #2334 = V6_vmpyuh
  { 2335,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo244, -1 ,nullptr },  // Inst #2335 = V6_vmpyuh_128B
  { 2336,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo245, -1 ,nullptr },  // Inst #2336 = V6_vmpyuh_acc
  { 2337,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo246, -1 ,nullptr },  // Inst #2337 = V6_vmpyuh_acc_128B
  { 2338,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2338 = V6_vmpyuhv
  { 2339,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2339 = V6_vmpyuhv_128B
  { 2340,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo247, -1 ,nullptr },  // Inst #2340 = V6_vmpyuhv_acc
  { 2341,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo248, -1 ,nullptr },  // Inst #2341 = V6_vmpyuhv_acc_128B
  { 2342,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo249, -1 ,nullptr },  // Inst #2342 = V6_vmux
  { 2343,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo250, -1 ,nullptr },  // Inst #2343 = V6_vmux_128B
  { 2344,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2344 = V6_vnavgh
  { 2345,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2345 = V6_vnavgh_128B
  { 2346,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2346 = V6_vnavgub
  { 2347,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2347 = V6_vnavgub_128B
  { 2348,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2348 = V6_vnavgw
  { 2349,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2349 = V6_vnavgw_128B
  { 2350,	4,	1,	4,	55,	0, 0xe00000230eULL, nullptr, nullptr, OperandInfo214, -1 ,nullptr },  // Inst #2350 = V6_vnccombine
  { 2351,	4,	1,	4,	55,	0, 0xe00000230eULL, nullptr, nullptr, OperandInfo215, -1 ,nullptr },  // Inst #2351 = V6_vnccombine_128B
  { 2352,	3,	1,	4,	33,	0, 0xe00000230dULL, nullptr, nullptr, OperandInfo216, -1 ,nullptr },  // Inst #2352 = V6_vncmov
  { 2353,	3,	1,	4,	33,	0, 0xe00000230dULL, nullptr, nullptr, OperandInfo217, -1 ,nullptr },  // Inst #2353 = V6_vncmov_128B
  { 2354,	2,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2354 = V6_vnormamth
  { 2355,	2,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2355 = V6_vnormamth_128B
  { 2356,	2,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2356 = V6_vnormamtw
  { 2357,	2,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2357 = V6_vnormamtw_128B
  { 2358,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2358 = V6_vnot
  { 2359,	2,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2359 = V6_vnot_128B
  { 2360,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2360 = V6_vor
  { 2361,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2361 = V6_vor_128B
  { 2362,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2362 = V6_vpackeb
  { 2363,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2363 = V6_vpackeb_128B
  { 2364,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2364 = V6_vpackeh
  { 2365,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2365 = V6_vpackeh_128B
  { 2366,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2366 = V6_vpackhb_sat
  { 2367,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2367 = V6_vpackhb_sat_128B
  { 2368,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2368 = V6_vpackhub_sat
  { 2369,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2369 = V6_vpackhub_sat_128B
  { 2370,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2370 = V6_vpackob
  { 2371,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2371 = V6_vpackob_128B
  { 2372,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2372 = V6_vpackoh
  { 2373,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2373 = V6_vpackoh_128B
  { 2374,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2374 = V6_vpackwh_sat
  { 2375,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2375 = V6_vpackwh_sat_128B
  { 2376,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2376 = V6_vpackwuh_sat
  { 2377,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2377 = V6_vpackwuh_sat_128B
  { 2378,	2,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2378 = V6_vpopcounth
  { 2379,	2,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2379 = V6_vpopcounth_128B
  { 2380,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2380 = V6_vrdelta
  { 2381,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2381 = V6_vrdelta_128B
  { 2382,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2382 = V6_vrmpybus
  { 2383,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2383 = V6_vrmpybus_128B
  { 2384,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2384 = V6_vrmpybus_acc
  { 2385,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2385 = V6_vrmpybus_acc_128B
  { 2386,	4,	1,	4,	69,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo251, -1 ,nullptr },  // Inst #2386 = V6_vrmpybusi
  { 2387,	4,	1,	4,	69,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo252, -1 ,nullptr },  // Inst #2387 = V6_vrmpybusi_128B
  { 2388,	5,	1,	4,	69,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo253, -1 ,nullptr },  // Inst #2388 = V6_vrmpybusi_acc
  { 2389,	5,	1,	4,	69,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo254, -1 ,nullptr },  // Inst #2389 = V6_vrmpybusi_acc_128B
  { 2390,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2390 = V6_vrmpybusv
  { 2391,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2391 = V6_vrmpybusv_128B
  { 2392,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #2392 = V6_vrmpybusv_acc
  { 2393,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #2393 = V6_vrmpybusv_acc_128B
  { 2394,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2394 = V6_vrmpybv
  { 2395,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2395 = V6_vrmpybv_128B
  { 2396,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #2396 = V6_vrmpybv_acc
  { 2397,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #2397 = V6_vrmpybv_acc_128B
  { 2398,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2398 = V6_vrmpyub
  { 2399,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2399 = V6_vrmpyub_128B
  { 2400,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo212, -1 ,nullptr },  // Inst #2400 = V6_vrmpyub_acc
  { 2401,	4,	1,	4,	62,	0, 0x4000e00000200fULL, nullptr, nullptr, OperandInfo213, -1 ,nullptr },  // Inst #2401 = V6_vrmpyub_acc_128B
  { 2402,	4,	1,	4,	69,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo251, -1 ,nullptr },  // Inst #2402 = V6_vrmpyubi
  { 2403,	4,	1,	4,	69,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo252, -1 ,nullptr },  // Inst #2403 = V6_vrmpyubi_128B
  { 2404,	5,	1,	4,	69,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo253, -1 ,nullptr },  // Inst #2404 = V6_vrmpyubi_acc
  { 2405,	5,	1,	4,	69,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo254, -1 ,nullptr },  // Inst #2405 = V6_vrmpyubi_acc_128B
  { 2406,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2406 = V6_vrmpyubv
  { 2407,	3,	1,	4,	62,	0, 0xe00000200fULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2407 = V6_vrmpyubv_128B
  { 2408,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo230, -1 ,nullptr },  // Inst #2408 = V6_vrmpyubv_acc
  { 2409,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo231, -1 ,nullptr },  // Inst #2409 = V6_vrmpyubv_acc_128B
  { 2410,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo210, -1 ,nullptr },  // Inst #2410 = V6_vror
  { 2411,	3,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo211, -1 ,nullptr },  // Inst #2411 = V6_vror_128B
  { 2412,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2412 = V6_vroundhb
  { 2413,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2413 = V6_vroundhb_128B
  { 2414,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2414 = V6_vroundhub
  { 2415,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2415 = V6_vroundhub_128B
  { 2416,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2416 = V6_vroundwh
  { 2417,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2417 = V6_vroundwh_128B
  { 2418,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2418 = V6_vroundwuh
  { 2419,	3,	1,	4,	64,	0, 0xe000002013ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2419 = V6_vroundwuh_128B
  { 2420,	4,	1,	4,	69,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo251, -1 ,nullptr },  // Inst #2420 = V6_vrsadubi
  { 2421,	4,	1,	4,	69,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo252, -1 ,nullptr },  // Inst #2421 = V6_vrsadubi_128B
  { 2422,	5,	1,	4,	69,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo253, -1 ,nullptr },  // Inst #2422 = V6_vrsadubi_acc
  { 2423,	5,	1,	4,	69,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo254, -1 ,nullptr },  // Inst #2423 = V6_vrsadubi_acc_128B
  { 2424,	3,	1,	4,	71,	0, 0xe000002014ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2424 = V6_vsathub
  { 2425,	3,	1,	4,	71,	0, 0xe000002014ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2425 = V6_vsathub_128B
  { 2426,	3,	1,	4,	71,	0, 0xe000002014ULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2426 = V6_vsatwh
  { 2427,	3,	1,	4,	71,	0, 0xe000002014ULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2427 = V6_vsatwh_128B
  { 2428,	2,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo255, -1 ,nullptr },  // Inst #2428 = V6_vsb
  { 2429,	2,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #2429 = V6_vsb_128B
  { 2430,	2,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo255, -1 ,nullptr },  // Inst #2430 = V6_vsh
  { 2431,	2,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #2431 = V6_vsh_128B
  { 2432,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2432 = V6_vshufeh
  { 2433,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2433 = V6_vshufeh_128B
  { 2434,	5,	2,	4,	65,	0, 0xc00e000002012ULL, nullptr, nullptr, OperandInfo218, -1 ,nullptr },  // Inst #2434 = V6_vshuff
  { 2435,	5,	2,	4,	65,	0, 0xc00e000002012ULL, nullptr, nullptr, OperandInfo219, -1 ,nullptr },  // Inst #2435 = V6_vshuff_128B
  { 2436,	2,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2436 = V6_vshuffb
  { 2437,	2,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2437 = V6_vshuffb_128B
  { 2438,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2438 = V6_vshuffeb
  { 2439,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2439 = V6_vshuffeb_128B
  { 2440,	2,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo190, -1 ,nullptr },  // Inst #2440 = V6_vshuffh
  { 2441,	2,	1,	4,	66,	0, 0xe000002011ULL, nullptr, nullptr, OperandInfo191, -1 ,nullptr },  // Inst #2441 = V6_vshuffh_128B
  { 2442,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2442 = V6_vshuffob
  { 2443,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2443 = V6_vshuffob_128B
  { 2444,	4,	1,	4,	67,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo220, -1 ,nullptr },  // Inst #2444 = V6_vshuffvdd
  { 2445,	4,	1,	4,	67,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo221, -1 ,nullptr },  // Inst #2445 = V6_vshuffvdd_128B
  { 2446,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2446 = V6_vshufoeb
  { 2447,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2447 = V6_vshufoeb_128B
  { 2448,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2448 = V6_vshufoeh
  { 2449,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2449 = V6_vshufoeh_128B
  { 2450,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2450 = V6_vshufoh
  { 2451,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2451 = V6_vshufoh_128B
  { 2452,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2452 = V6_vsubb
  { 2453,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2453 = V6_vsubb_128B
  { 2454,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #2454 = V6_vsubb_dv
  { 2455,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #2455 = V6_vsubb_dv_128B
  { 2456,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #2456 = V6_vsubbnq
  { 2457,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #2457 = V6_vsubbnq_128B
  { 2458,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #2458 = V6_vsubbq
  { 2459,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #2459 = V6_vsubbq_128B
  { 2460,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2460 = V6_vsubh
  { 2461,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2461 = V6_vsubh_128B
  { 2462,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #2462 = V6_vsubh_dv
  { 2463,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #2463 = V6_vsubh_dv_128B
  { 2464,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #2464 = V6_vsubhnq
  { 2465,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #2465 = V6_vsubhnq_128B
  { 2466,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #2466 = V6_vsubhq
  { 2467,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #2467 = V6_vsubhq_128B
  { 2468,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2468 = V6_vsubhsat
  { 2469,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2469 = V6_vsubhsat_128B
  { 2470,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #2470 = V6_vsubhsat_dv
  { 2471,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #2471 = V6_vsubhsat_dv_128B
  { 2472,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2472 = V6_vsubhw
  { 2473,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2473 = V6_vsubhw_128B
  { 2474,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2474 = V6_vsububh
  { 2475,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2475 = V6_vsububh_128B
  { 2476,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2476 = V6_vsububsat
  { 2477,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2477 = V6_vsububsat_128B
  { 2478,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #2478 = V6_vsububsat_dv
  { 2479,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #2479 = V6_vsububsat_dv_128B
  { 2480,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2480 = V6_vsubuhsat
  { 2481,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2481 = V6_vsubuhsat_128B
  { 2482,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #2482 = V6_vsubuhsat_dv
  { 2483,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #2483 = V6_vsubuhsat_dv_128B
  { 2484,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo196, -1 ,nullptr },  // Inst #2484 = V6_vsubuhw
  { 2485,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo197, -1 ,nullptr },  // Inst #2485 = V6_vsubuhw_128B
  { 2486,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2486 = V6_vsubw
  { 2487,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2487 = V6_vsubw_128B
  { 2488,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #2488 = V6_vsubw_dv
  { 2489,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #2489 = V6_vsubw_dv_128B
  { 2490,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #2490 = V6_vsubwnq
  { 2491,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #2491 = V6_vsubwnq_128B
  { 2492,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo194, -1 ,nullptr },  // Inst #2492 = V6_vsubwq
  { 2493,	4,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo195, -1 ,nullptr },  // Inst #2493 = V6_vsubwq_128B
  { 2494,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2494 = V6_vsubwsat
  { 2495,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2495 = V6_vsubwsat_128B
  { 2496,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo192, -1 ,nullptr },  // Inst #2496 = V6_vsubwsat_dv
  { 2497,	3,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo193, -1 ,nullptr },  // Inst #2497 = V6_vsubwsat_dv_128B
  { 2498,	4,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo257, -1 ,nullptr },  // Inst #2498 = V6_vswap
  { 2499,	4,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo258, -1 ,nullptr },  // Inst #2499 = V6_vswap_128B
  { 2500,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #2500 = V6_vtmpyb
  { 2501,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo223, -1 ,nullptr },  // Inst #2501 = V6_vtmpyb_128B
  { 2502,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo224, -1 ,nullptr },  // Inst #2502 = V6_vtmpyb_acc
  { 2503,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo225, -1 ,nullptr },  // Inst #2503 = V6_vtmpyb_acc_128B
  { 2504,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #2504 = V6_vtmpybus
  { 2505,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo223, -1 ,nullptr },  // Inst #2505 = V6_vtmpybus_128B
  { 2506,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo224, -1 ,nullptr },  // Inst #2506 = V6_vtmpybus_acc
  { 2507,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo225, -1 ,nullptr },  // Inst #2507 = V6_vtmpybus_acc_128B
  { 2508,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo222, -1 ,nullptr },  // Inst #2508 = V6_vtmpyhb
  { 2509,	3,	1,	4,	63,	0, 0xe000002010ULL, nullptr, nullptr, OperandInfo223, -1 ,nullptr },  // Inst #2509 = V6_vtmpyhb_128B
  { 2510,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo224, -1 ,nullptr },  // Inst #2510 = V6_vtmpyhb_acc
  { 2511,	4,	1,	4,	63,	0, 0x4000e000002010ULL, nullptr, nullptr, OperandInfo225, -1 ,nullptr },  // Inst #2511 = V6_vtmpyhb_acc_128B
  { 2512,	2,	1,	4,	72,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo255, -1 ,nullptr },  // Inst #2512 = V6_vunpackb
  { 2513,	2,	1,	4,	72,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #2513 = V6_vunpackb_128B
  { 2514,	2,	1,	4,	72,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo255, -1 ,nullptr },  // Inst #2514 = V6_vunpackh
  { 2515,	2,	1,	4,	72,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #2515 = V6_vunpackh_128B
  { 2516,	3,	1,	4,	67,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo259, -1 ,nullptr },  // Inst #2516 = V6_vunpackob
  { 2517,	3,	1,	4,	67,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo260, -1 ,nullptr },  // Inst #2517 = V6_vunpackob_128B
  { 2518,	3,	1,	4,	67,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo259, -1 ,nullptr },  // Inst #2518 = V6_vunpackoh
  { 2519,	3,	1,	4,	67,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo260, -1 ,nullptr },  // Inst #2519 = V6_vunpackoh_128B
  { 2520,	2,	1,	4,	72,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo255, -1 ,nullptr },  // Inst #2520 = V6_vunpackub
  { 2521,	2,	1,	4,	72,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #2521 = V6_vunpackub_128B
  { 2522,	2,	1,	4,	72,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo255, -1 ,nullptr },  // Inst #2522 = V6_vunpackuh
  { 2523,	2,	1,	4,	72,	0, 0xe000002012ULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #2523 = V6_vunpackuh_128B
  { 2524,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo188, -1 ,nullptr },  // Inst #2524 = V6_vxor
  { 2525,	3,	1,	4,	33,	0, 0xe00000200dULL, nullptr, nullptr, OperandInfo189, -1 ,nullptr },  // Inst #2525 = V6_vxor_128B
  { 2526,	2,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo255, -1 ,nullptr },  // Inst #2526 = V6_vzb
  { 2527,	2,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #2527 = V6_vzb_128B
  { 2528,	2,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo255, -1 ,nullptr },  // Inst #2528 = V6_vzh
  { 2529,	2,	1,	4,	55,	0, 0xe00000200eULL, nullptr, nullptr, OperandInfo256, -1 ,nullptr },  // Inst #2529 = V6_vzh_128B
  { 2530,	3,	1,	4,	34,	0|(1ULL<<MCID::Pseudo), 0xfc00000000ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #2530 = VMULW
  { 2531,	4,	1,	4,	34,	0|(1ULL<<MCID::Pseudo), 0xfc00000000ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #2531 = VMULW_ACC
  { 2532,	4,	1,	4,	55,	0|(1ULL<<MCID::Pseudo), 0xfc0000000eULL, nullptr, nullptr, OperandInfo261, -1 ,nullptr },  // Inst #2532 = VSelectDblPseudo_V6
  { 2533,	4,	1,	4,	55,	0|(1ULL<<MCID::Pseudo), 0xfc0000000eULL, nullptr, nullptr, OperandInfo262, -1 ,nullptr },  // Inst #2533 = VSelectPseudo_V6
  { 2534,	0,	0,	4,	50,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000047ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2534 = Y2_barrier
  { 2535,	1,	0,	4,	46,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000086ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #2535 = Y2_dccleana
  { 2536,	1,	0,	4,	46,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000086ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #2536 = Y2_dccleaninva
  { 2537,	2,	0,	4,	39,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000005ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #2537 = Y2_dcfetchbo
  { 2538,	1,	0,	4,	46,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000086ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #2538 = Y2_dcinva
  { 2539,	1,	0,	4,	46,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000086ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #2539 = Y2_dczeroa
  { 2540,	1,	0,	4,	24,	0, 0xfc00000023ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #2540 = Y2_icinva
  { 2541,	0,	0,	4,	24,	0, 0xfc00000023ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2541 = Y2_isync
  { 2542,	0,	0,	4,	46,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000026ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2542 = Y2_syncht
  { 2543,	2,	0,	4,	73,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000047ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #2543 = Y4_l2fetch
  { 2544,	1,	0,	4,	35,	0, 0xfc00000042ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #2544 = Y4_trace
  { 2545,	2,	0,	4,	73,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xfc00000047ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #2545 = Y5_l2fetch
  { 2546,	0,	0,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xf000000026ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2546 = Y5_l2gclean
  { 2547,	0,	0,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xf000000026ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2547 = Y5_l2gcleaninv
  { 2548,	0,	0,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xf000000026ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #2548 = Y5_l2gunlock
  { 2549,	2,	1,	4,	73,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xf000000846ULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #2549 = Y5_l2locka
  { 2550,	1,	0,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xf000000046ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #2550 = Y5_l2unlocka
  { 2551,	1,	0,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xe000000026ULL, nullptr, nullptr, OperandInfo263, -1 ,nullptr },  // Inst #2551 = Y6_l2gcleaninvpa
  { 2552,	1,	0,	4,	50,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xe000000026ULL, nullptr, nullptr, OperandInfo263, -1 ,nullptr },  // Inst #2552 = Y6_l2gcleanpa
  { 2553,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #2553 = dep_A2_addsat
  { 2554,	3,	1,	4,	5,	0, 0xfc00002008ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #2554 = dep_A2_subsat
  { 2555,	3,	1,	4,	4,	0, 0xfc00000008ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #2555 = dep_S2_packhl
};

static inline void InitHexagonMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(HexagonInsts, NULL, NULL, 2556);
}

} // end llvm namespace 
#endif // GET_INSTRINFO_MC_DESC


#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER
namespace llvm_ks {
struct HexagonGenInstrInfo : public TargetInstrInfo {
  explicit HexagonGenInstrInfo(int CFSetupOpcode = -1, int CFDestroyOpcode = -1, int CatchRetOpcode = -1);
  ~HexagonGenInstrInfo() override {}
};
} // end llvm namespace 
#endif // GET_INSTRINFO_HEADER


#ifdef GET_INSTRINFO_OPERAND_ENUM
#undef GET_INSTRINFO_OPERAND_ENUM
namespace llvm_ks {
namespace Hexagon {
namespace OpName { 
enum {
OPERAND_LAST
};
} // end namespace OpName
} // end namespace Hexagon
} // end namespace llvm_ks
#endif //GET_INSTRINFO_OPERAND_ENUM
#ifdef GET_INSTRINFO_NAMED_OPS
#undef GET_INSTRINFO_NAMED_OPS
namespace llvm_ks {
namespace Hexagon {
LLVM_READONLY
int16_t getNamedOperandIdx(uint16_t Opcode, uint16_t NamedIdx) {
  return -1;
}
} // end namespace Hexagon
} // end namespace llvm_ks
#endif //GET_INSTRINFO_NAMED_OPS

#ifdef GET_INSTRINFO_OPERAND_TYPES_ENUM
#undef GET_INSTRINFO_OPERAND_TYPES_ENUM
namespace llvm_ks {
namespace Hexagon {
namespace OpTypes { 
enum OperandType {
  bblabel = 0,
  brtarget = 1,
  brtargetExt = 2,
  calltarget = 3,
  f32Ext = 4,
  f32imm = 5,
  f64imm = 6,
  globaladdress = 7,
  globaladdressExt = 8,
  i16imm = 9,
  i1imm = 10,
  i32imm = 11,
  i64imm = 12,
  i8imm = 13,
  jumptablebase = 14,
  n8Imm = 15,
  s10Ext = 16,
  s11_0Ext = 17,
  s11_1Ext = 18,
  s11_2Ext = 19,
  s11_3Ext = 20,
  s12Ext = 21,
  s16Ext = 22,
  s32Imm = 23,
  s3_6Imm = 24,
  s3_7Imm = 25,
  s4Imm = 26,
  s4_0Imm = 27,
  s4_1Imm = 28,
  s4_2Imm = 29,
  s4_3Imm = 30,
  s4_6Imm = 31,
  s4_7Imm = 32,
  s6Ext = 33,
  s6Imm = 34,
  s6_3Imm = 35,
  s7Ext = 36,
  s8Ext = 37,
  s8Imm = 38,
  s8Imm64 = 39,
  s9Ext = 40,
  u10Ext = 41,
  u10Imm = 42,
  u11_3Imm = 43,
  u16Imm = 44,
  u16_0Imm = 45,
  u16_1Imm = 46,
  u16_2Imm = 47,
  u16_3Imm = 48,
  u1Imm = 49,
  u26_6Imm = 50,
  u2Imm = 51,
  u32Imm = 52,
  u32MustExt = 53,
  u3Imm = 54,
  u3_0Imm = 55,
  u3_1Imm = 56,
  u3_2Imm = 57,
  u3_3Imm = 58,
  u4Imm = 59,
  u4_0Imm = 60,
  u4_1Imm = 61,
  u4_2Imm = 62,
  u4_3Imm = 63,
  u5Imm = 64,
  u5_0Imm = 65,
  u5_1Imm = 66,
  u5_2Imm = 67,
  u5_3Imm = 68,
  u64Imm = 69,
  u6Ext = 70,
  u6Imm = 71,
  u6_0Ext = 72,
  u6_0Imm = 73,
  u6_1Ext = 74,
  u6_1Imm = 75,
  u6_2Ext = 76,
  u6_2Imm = 77,
  u6_3Ext = 78,
  u6_3Imm = 79,
  u7Ext = 80,
  u7Imm = 81,
  u8Ext = 82,
  u8Imm = 83,
  u9Ext = 84,
  u9Imm = 85,
  OPERAND_TYPE_LIST_END
};
} // end namespace OpTypes
} // end namespace Hexagon
} // end namespace llvm_ks
#endif // GET_INSTRINFO_OPERAND_TYPES_ENUM
#ifdef GET_INSTRMAP_INFO
#undef GET_INSTRMAP_INFO
namespace llvm_ks {

namespace Hexagon {

enum InputType {
	InputType_reg
};

enum InstrType {
	InstrType_Pseudo,
	InstrType_Real
};

enum NValueST {
	NValueST_true,
	NValueST_false
};

enum PNewValue {
	PNewValue_new,
	PNewValue_
};

enum PredSense {
	PredSense_false,
	PredSense_true
};

enum addrMode {
	addrMode_BaseImmOffset,
	addrMode_BaseRegOffset
};

enum isBrTaken {
	isBrTaken_false,
	isBrTaken_true
};

// getBaseWithImmOffset
LLVM_READONLY
int getBaseWithImmOffset(uint16_t Opcode) {
static const uint16_t getBaseWithImmOffsetTable[][2] = {
  { Hexagon::L4_loadrb_abs, Hexagon::L2_loadrb_io },
  { Hexagon::L4_loadrd_abs, Hexagon::L2_loadrd_io },
  { Hexagon::L4_loadrh_abs, Hexagon::L2_loadrh_io },
  { Hexagon::L4_loadri_abs, Hexagon::L2_loadri_io },
  { Hexagon::L4_loadrub_abs, Hexagon::L2_loadrub_io },
  { Hexagon::L4_loadruh_abs, Hexagon::L2_loadruh_io },
  { Hexagon::L4_ploadrbf_abs, Hexagon::L2_ploadrbf_io },
  { Hexagon::L4_ploadrbfnew_abs, Hexagon::L2_ploadrbfnew_io },
  { Hexagon::L4_ploadrbt_abs, Hexagon::L2_ploadrbt_io },
  { Hexagon::L4_ploadrbtnew_abs, Hexagon::L2_ploadrbtnew_io },
  { Hexagon::L4_ploadrdf_abs, Hexagon::L2_ploadrdf_io },
  { Hexagon::L4_ploadrdfnew_abs, Hexagon::L2_ploadrdfnew_io },
  { Hexagon::L4_ploadrdt_abs, Hexagon::L2_ploadrdt_io },
  { Hexagon::L4_ploadrdtnew_abs, Hexagon::L2_ploadrdtnew_io },
  { Hexagon::L4_ploadrhf_abs, Hexagon::L2_ploadrhf_io },
  { Hexagon::L4_ploadrhfnew_abs, Hexagon::L2_ploadrhfnew_io },
  { Hexagon::L4_ploadrht_abs, Hexagon::L2_ploadrht_io },
  { Hexagon::L4_ploadrhtnew_abs, Hexagon::L2_ploadrhtnew_io },
  { Hexagon::L4_ploadrif_abs, Hexagon::L2_ploadrif_io },
  { Hexagon::L4_ploadrifnew_abs, Hexagon::L2_ploadrifnew_io },
  { Hexagon::L4_ploadrit_abs, Hexagon::L2_ploadrit_io },
  { Hexagon::L4_ploadritnew_abs, Hexagon::L2_ploadritnew_io },
  { Hexagon::L4_ploadrubf_abs, Hexagon::L2_ploadrubf_io },
  { Hexagon::L4_ploadrubfnew_abs, Hexagon::L2_ploadrubfnew_io },
  { Hexagon::L4_ploadrubt_abs, Hexagon::L2_ploadrubt_io },
  { Hexagon::L4_ploadrubtnew_abs, Hexagon::L2_ploadrubtnew_io },
  { Hexagon::L4_ploadruhf_abs, Hexagon::L2_ploadruhf_io },
  { Hexagon::L4_ploadruhfnew_abs, Hexagon::L2_ploadruhfnew_io },
  { Hexagon::L4_ploadruht_abs, Hexagon::L2_ploadruht_io },
  { Hexagon::L4_ploadruhtnew_abs, Hexagon::L2_ploadruhtnew_io },
  { Hexagon::S2_storerbabs, Hexagon::S2_storerb_io },
  { Hexagon::S2_storerbnewabs, Hexagon::S2_storerbnew_io },
  { Hexagon::S2_storerdabs, Hexagon::S2_storerd_io },
  { Hexagon::S2_storerfabs, Hexagon::S2_storerf_io },
  { Hexagon::S2_storerhabs, Hexagon::S2_storerh_io },
  { Hexagon::S2_storerhnewabs, Hexagon::S2_storerhnew_io },
  { Hexagon::S2_storeriabs, Hexagon::S2_storeri_io },
  { Hexagon::S2_storerinewabs, Hexagon::S2_storerinew_io },
  { Hexagon::S4_pstorerbf_abs, Hexagon::S2_pstorerbf_io },
  { Hexagon::S4_pstorerbfnew_abs, Hexagon::S4_pstorerbfnew_io },
  { Hexagon::S4_pstorerbnewf_abs, Hexagon::S2_pstorerbnewf_io },
  { Hexagon::S4_pstorerbnewfnew_abs, Hexagon::S4_pstorerbnewfnew_io },
  { Hexagon::S4_pstorerbnewt_abs, Hexagon::S2_pstorerbnewt_io },
  { Hexagon::S4_pstorerbnewtnew_abs, Hexagon::S4_pstorerbnewtnew_io },
  { Hexagon::S4_pstorerbt_abs, Hexagon::S2_pstorerbt_io },
  { Hexagon::S4_pstorerbtnew_abs, Hexagon::S4_pstorerbtnew_io },
  { Hexagon::S4_pstorerdf_abs, Hexagon::S2_pstorerdf_io },
  { Hexagon::S4_pstorerdfnew_abs, Hexagon::S4_pstorerdfnew_io },
  { Hexagon::S4_pstorerdt_abs, Hexagon::S2_pstorerdt_io },
  { Hexagon::S4_pstorerdtnew_abs, Hexagon::S4_pstorerdtnew_io },
  { Hexagon::S4_pstorerff_abs, Hexagon::S2_pstorerff_io },
  { Hexagon::S4_pstorerffnew_abs, Hexagon::S4_pstorerffnew_io },
  { Hexagon::S4_pstorerft_abs, Hexagon::S2_pstorerft_io },
  { Hexagon::S4_pstorerftnew_abs, Hexagon::S4_pstorerftnew_io },
  { Hexagon::S4_pstorerhf_abs, Hexagon::S2_pstorerhf_io },
  { Hexagon::S4_pstorerhfnew_abs, Hexagon::S4_pstorerhfnew_io },
  { Hexagon::S4_pstorerhnewf_abs, Hexagon::S2_pstorerhnewf_io },
  { Hexagon::S4_pstorerhnewfnew_abs, Hexagon::S4_pstorerhnewfnew_io },
  { Hexagon::S4_pstorerhnewt_abs, Hexagon::S2_pstorerhnewt_io },
  { Hexagon::S4_pstorerhnewtnew_abs, Hexagon::S4_pstorerhnewtnew_io },
  { Hexagon::S4_pstorerht_abs, Hexagon::S2_pstorerht_io },
  { Hexagon::S4_pstorerhtnew_abs, Hexagon::S4_pstorerhtnew_io },
  { Hexagon::S4_pstorerif_abs, Hexagon::S2_pstorerif_io },
  { Hexagon::S4_pstorerifnew_abs, Hexagon::S4_pstorerifnew_io },
  { Hexagon::S4_pstorerinewf_abs, Hexagon::S2_pstorerinewf_io },
  { Hexagon::S4_pstorerinewfnew_abs, Hexagon::S4_pstorerinewfnew_io },
  { Hexagon::S4_pstorerinewt_abs, Hexagon::S2_pstorerinewt_io },
  { Hexagon::S4_pstorerinewtnew_abs, Hexagon::S4_pstorerinewtnew_io },
  { Hexagon::S4_pstorerit_abs, Hexagon::S2_pstorerit_io },
  { Hexagon::S4_pstoreritnew_abs, Hexagon::S4_pstoreritnew_io },
}; // End of getBaseWithImmOffsetTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 70;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getBaseWithImmOffsetTable[mid][0]) {
      break;
    }
    if (Opcode < getBaseWithImmOffsetTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getBaseWithImmOffsetTable[mid][1];
}

// getBaseWithRegOffset
LLVM_READONLY
int getBaseWithRegOffset(uint16_t Opcode) {
static const uint16_t getBaseWithRegOffsetTable[][2] = {
  { Hexagon::L2_loadrb_io, Hexagon::L4_loadrb_rr },
  { Hexagon::L2_loadrd_io, Hexagon::L4_loadrd_rr },
  { Hexagon::L2_loadrh_io, Hexagon::L4_loadrh_rr },
  { Hexagon::L2_loadri_io, Hexagon::L4_loadri_rr },
  { Hexagon::L2_loadrub_io, Hexagon::L4_loadrub_rr },
  { Hexagon::L2_loadruh_io, Hexagon::L4_loadruh_rr },
  { Hexagon::L2_ploadrbf_io, Hexagon::L4_ploadrbf_rr },
  { Hexagon::L2_ploadrbfnew_io, Hexagon::L4_ploadrbfnew_rr },
  { Hexagon::L2_ploadrbt_io, Hexagon::L4_ploadrbt_rr },
  { Hexagon::L2_ploadrbtnew_io, Hexagon::L4_ploadrbtnew_rr },
  { Hexagon::L2_ploadrdf_io, Hexagon::L4_ploadrdf_rr },
  { Hexagon::L2_ploadrdfnew_io, Hexagon::L4_ploadrdfnew_rr },
  { Hexagon::L2_ploadrdt_io, Hexagon::L4_ploadrdt_rr },
  { Hexagon::L2_ploadrdtnew_io, Hexagon::L4_ploadrdtnew_rr },
  { Hexagon::L2_ploadrhf_io, Hexagon::L4_ploadrhf_rr },
  { Hexagon::L2_ploadrhfnew_io, Hexagon::L4_ploadrhfnew_rr },
  { Hexagon::L2_ploadrht_io, Hexagon::L4_ploadrht_rr },
  { Hexagon::L2_ploadrhtnew_io, Hexagon::L4_ploadrhtnew_rr },
  { Hexagon::L2_ploadrif_io, Hexagon::L4_ploadrif_rr },
  { Hexagon::L2_ploadrifnew_io, Hexagon::L4_ploadrifnew_rr },
  { Hexagon::L2_ploadrit_io, Hexagon::L4_ploadrit_rr },
  { Hexagon::L2_ploadritnew_io, Hexagon::L4_ploadritnew_rr },
  { Hexagon::L2_ploadrubf_io, Hexagon::L4_ploadrubf_rr },
  { Hexagon::L2_ploadrubfnew_io, Hexagon::L4_ploadrubfnew_rr },
  { Hexagon::L2_ploadrubt_io, Hexagon::L4_ploadrubt_rr },
  { Hexagon::L2_ploadrubtnew_io, Hexagon::L4_ploadrubtnew_rr },
  { Hexagon::L2_ploadruhf_io, Hexagon::L4_ploadruhf_rr },
  { Hexagon::L2_ploadruhfnew_io, Hexagon::L4_ploadruhfnew_rr },
  { Hexagon::L2_ploadruht_io, Hexagon::L4_ploadruht_rr },
  { Hexagon::L2_ploadruhtnew_io, Hexagon::L4_ploadruhtnew_rr },
  { Hexagon::S2_pstorerbf_io, Hexagon::S4_pstorerbf_rr },
  { Hexagon::S2_pstorerbnewf_io, Hexagon::S4_pstorerbnewf_rr },
  { Hexagon::S2_pstorerbnewt_io, Hexagon::S4_pstorerbnewt_rr },
  { Hexagon::S2_pstorerbt_io, Hexagon::S4_pstorerbt_rr },
  { Hexagon::S2_pstorerdf_io, Hexagon::S4_pstorerdf_rr },
  { Hexagon::S2_pstorerdt_io, Hexagon::S4_pstorerdt_rr },
  { Hexagon::S2_pstorerff_io, Hexagon::S4_pstorerff_rr },
  { Hexagon::S2_pstorerft_io, Hexagon::S4_pstorerft_rr },
  { Hexagon::S2_pstorerhf_io, Hexagon::S4_pstorerhf_rr },
  { Hexagon::S2_pstorerhnewf_io, Hexagon::S4_pstorerhnewf_rr },
  { Hexagon::S2_pstorerhnewt_io, Hexagon::S4_pstorerhnewt_rr },
  { Hexagon::S2_pstorerht_io, Hexagon::S4_pstorerht_rr },
  { Hexagon::S2_pstorerif_io, Hexagon::S4_pstorerif_rr },
  { Hexagon::S2_pstorerinewf_io, Hexagon::S4_pstorerinewf_rr },
  { Hexagon::S2_pstorerinewt_io, Hexagon::S4_pstorerinewt_rr },
  { Hexagon::S2_pstorerit_io, Hexagon::S4_pstorerit_rr },
  { Hexagon::S2_storerb_io, Hexagon::S4_storerb_rr },
  { Hexagon::S2_storerbnew_io, Hexagon::S4_storerbnew_rr },
  { Hexagon::S2_storerd_io, Hexagon::S4_storerd_rr },
  { Hexagon::S2_storerf_io, Hexagon::S4_storerf_rr },
  { Hexagon::S2_storerh_io, Hexagon::S4_storerh_rr },
  { Hexagon::S2_storerhnew_io, Hexagon::S4_storerhnew_rr },
  { Hexagon::S2_storeri_io, Hexagon::S4_storeri_rr },
  { Hexagon::S2_storerinew_io, Hexagon::S4_storerinew_rr },
  { Hexagon::S4_pstorerbfnew_io, Hexagon::S4_pstorerbfnew_rr },
  { Hexagon::S4_pstorerbnewfnew_io, Hexagon::S4_pstorerbnewfnew_rr },
  { Hexagon::S4_pstorerbnewtnew_io, Hexagon::S4_pstorerbnewtnew_rr },
  { Hexagon::S4_pstorerbtnew_io, Hexagon::S4_pstorerbtnew_rr },
  { Hexagon::S4_pstorerdfnew_io, Hexagon::S4_pstorerdfnew_rr },
  { Hexagon::S4_pstorerdtnew_io, Hexagon::S4_pstorerdtnew_rr },
  { Hexagon::S4_pstorerffnew_io, Hexagon::S4_pstorerffnew_rr },
  { Hexagon::S4_pstorerftnew_io, Hexagon::S4_pstorerftnew_rr },
  { Hexagon::S4_pstorerhfnew_io, Hexagon::S4_pstorerhfnew_rr },
  { Hexagon::S4_pstorerhnewfnew_io, Hexagon::S4_pstorerhnewfnew_rr },
  { Hexagon::S4_pstorerhnewtnew_io, Hexagon::S4_pstorerhnewtnew_rr },
  { Hexagon::S4_pstorerhtnew_io, Hexagon::S4_pstorerhtnew_rr },
  { Hexagon::S4_pstorerifnew_io, Hexagon::S4_pstorerifnew_rr },
  { Hexagon::S4_pstorerinewfnew_io, Hexagon::S4_pstorerinewfnew_rr },
  { Hexagon::S4_pstorerinewtnew_io, Hexagon::S4_pstorerinewtnew_rr },
  { Hexagon::S4_pstoreritnew_io, Hexagon::S4_pstoreritnew_rr },
}; // End of getBaseWithRegOffsetTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 70;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getBaseWithRegOffsetTable[mid][0]) {
      break;
    }
    if (Opcode < getBaseWithRegOffsetTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getBaseWithRegOffsetTable[mid][1];
}

// getFalsePredOpcode
LLVM_READONLY
int getFalsePredOpcode(uint16_t Opcode) {
static const uint16_t getFalsePredOpcodeTable[][2] = {
  { Hexagon::A2_paddit, Hexagon::A2_paddif },
  { Hexagon::A2_padditnew, Hexagon::A2_paddifnew },
  { Hexagon::A2_paddt, Hexagon::A2_paddf },
  { Hexagon::A2_paddtnew, Hexagon::A2_paddfnew },
  { Hexagon::A2_pandt, Hexagon::A2_pandf },
  { Hexagon::A2_pandtnew, Hexagon::A2_pandfnew },
  { Hexagon::A2_port, Hexagon::A2_porf },
  { Hexagon::A2_portnew, Hexagon::A2_porfnew },
  { Hexagon::A2_psubt, Hexagon::A2_psubf },
  { Hexagon::A2_psubtnew, Hexagon::A2_psubfnew },
  { Hexagon::A2_pxort, Hexagon::A2_pxorf },
  { Hexagon::A2_pxortnew, Hexagon::A2_pxorfnew },
  { Hexagon::A2_tfrpt, Hexagon::A2_tfrpf },
  { Hexagon::A2_tfrptnew, Hexagon::A2_tfrpfnew },
  { Hexagon::A2_tfrt, Hexagon::A2_tfrf },
  { Hexagon::A2_tfrtnew, Hexagon::A2_tfrfnew },
  { Hexagon::A4_paslht, Hexagon::A4_paslhf },
  { Hexagon::A4_paslhtnew, Hexagon::A4_paslhfnew },
  { Hexagon::A4_pasrht, Hexagon::A4_pasrhf },
  { Hexagon::A4_pasrhtnew, Hexagon::A4_pasrhfnew },
  { Hexagon::A4_psxtbt, Hexagon::A4_psxtbf },
  { Hexagon::A4_psxtbtnew, Hexagon::A4_psxtbfnew },
  { Hexagon::A4_psxtht, Hexagon::A4_psxthf },
  { Hexagon::A4_psxthtnew, Hexagon::A4_psxthfnew },
  { Hexagon::A4_pzxtbt, Hexagon::A4_pzxtbf },
  { Hexagon::A4_pzxtbtnew, Hexagon::A4_pzxtbfnew },
  { Hexagon::A4_pzxtht, Hexagon::A4_pzxthf },
  { Hexagon::A4_pzxthtnew, Hexagon::A4_pzxthfnew },
  { Hexagon::C2_ccombinewnewt, Hexagon::C2_ccombinewnewf },
  { Hexagon::C2_ccombinewt, Hexagon::C2_ccombinewf },
  { Hexagon::C2_cmoveit, Hexagon::C2_cmoveif },
  { Hexagon::C2_cmovenewit, Hexagon::C2_cmovenewif },
  { Hexagon::J2_callt, Hexagon::J2_callf },
  { Hexagon::J2_jumprt, Hexagon::J2_jumprf },
  { Hexagon::J2_jumprtnew, Hexagon::J2_jumprfnew },
  { Hexagon::J2_jumprtnewpt, Hexagon::J2_jumprfnewpt },
  { Hexagon::J2_jumpt, Hexagon::J2_jumpf },
  { Hexagon::J2_jumptnew, Hexagon::J2_jumpfnew },
  { Hexagon::J2_jumptnewpt, Hexagon::J2_jumpfnewpt },
  { Hexagon::J4_cmpeq_t_jumpnv_nt, Hexagon::J4_cmpeq_f_jumpnv_nt },
  { Hexagon::J4_cmpeq_t_jumpnv_t, Hexagon::J4_cmpeq_f_jumpnv_t },
  { Hexagon::J4_cmpeqi_t_jumpnv_nt, Hexagon::J4_cmpeqi_f_jumpnv_nt },
  { Hexagon::J4_cmpeqi_t_jumpnv_t, Hexagon::J4_cmpeqi_f_jumpnv_t },
  { Hexagon::J4_cmpeqn1_t_jumpnv_nt, Hexagon::J4_cmpeqn1_f_jumpnv_nt },
  { Hexagon::J4_cmpeqn1_t_jumpnv_t, Hexagon::J4_cmpeqn1_f_jumpnv_t },
  { Hexagon::J4_cmpgt_t_jumpnv_nt, Hexagon::J4_cmpgt_f_jumpnv_nt },
  { Hexagon::J4_cmpgt_t_jumpnv_t, Hexagon::J4_cmpgt_f_jumpnv_t },
  { Hexagon::J4_cmpgti_t_jumpnv_nt, Hexagon::J4_cmpgti_f_jumpnv_nt },
  { Hexagon::J4_cmpgti_t_jumpnv_t, Hexagon::J4_cmpgti_f_jumpnv_t },
  { Hexagon::J4_cmpgtn1_t_jumpnv_nt, Hexagon::J4_cmpgtn1_f_jumpnv_nt },
  { Hexagon::J4_cmpgtn1_t_jumpnv_t, Hexagon::J4_cmpgtn1_f_jumpnv_t },
  { Hexagon::J4_cmpgtu_t_jumpnv_nt, Hexagon::J4_cmpgtu_f_jumpnv_nt },
  { Hexagon::J4_cmpgtu_t_jumpnv_t, Hexagon::J4_cmpgtu_f_jumpnv_t },
  { Hexagon::J4_cmpgtui_t_jumpnv_nt, Hexagon::J4_cmpgtui_f_jumpnv_nt },
  { Hexagon::J4_cmpgtui_t_jumpnv_t, Hexagon::J4_cmpgtui_f_jumpnv_t },
  { Hexagon::J4_cmplt_t_jumpnv_nt, Hexagon::J4_cmplt_f_jumpnv_nt },
  { Hexagon::J4_cmplt_t_jumpnv_t, Hexagon::J4_cmplt_f_jumpnv_t },
  { Hexagon::J4_cmpltu_t_jumpnv_nt, Hexagon::J4_cmpltu_f_jumpnv_nt },
  { Hexagon::J4_cmpltu_t_jumpnv_t, Hexagon::J4_cmpltu_f_jumpnv_t },
  { Hexagon::J4_tstbit0_t_jumpnv_nt, Hexagon::J4_tstbit0_f_jumpnv_nt },
  { Hexagon::J4_tstbit0_t_jumpnv_t, Hexagon::J4_tstbit0_f_jumpnv_t },
  { Hexagon::JMPrett, Hexagon::JMPretf },
  { Hexagon::JMPrettnew, Hexagon::JMPretfnew },
  { Hexagon::JMPrettnewpt, Hexagon::JMPretfnewpt },
  { Hexagon::L2_ploadrbt_io, Hexagon::L2_ploadrbf_io },
  { Hexagon::L2_ploadrbt_pi, Hexagon::L2_ploadrbf_pi },
  { Hexagon::L2_ploadrbtnew_io, Hexagon::L2_ploadrbfnew_io },
  { Hexagon::L2_ploadrbtnew_pi, Hexagon::L2_ploadrbfnew_pi },
  { Hexagon::L2_ploadrdt_io, Hexagon::L2_ploadrdf_io },
  { Hexagon::L2_ploadrdt_pi, Hexagon::L2_ploadrdf_pi },
  { Hexagon::L2_ploadrdtnew_io, Hexagon::L2_ploadrdfnew_io },
  { Hexagon::L2_ploadrdtnew_pi, Hexagon::L2_ploadrdfnew_pi },
  { Hexagon::L2_ploadrht_io, Hexagon::L2_ploadrhf_io },
  { Hexagon::L2_ploadrht_pi, Hexagon::L2_ploadrhf_pi },
  { Hexagon::L2_ploadrhtnew_io, Hexagon::L2_ploadrhfnew_io },
  { Hexagon::L2_ploadrhtnew_pi, Hexagon::L2_ploadrhfnew_pi },
  { Hexagon::L2_ploadrit_io, Hexagon::L2_ploadrif_io },
  { Hexagon::L2_ploadrit_pi, Hexagon::L2_ploadrif_pi },
  { Hexagon::L2_ploadritnew_io, Hexagon::L2_ploadrifnew_io },
  { Hexagon::L2_ploadritnew_pi, Hexagon::L2_ploadrifnew_pi },
  { Hexagon::L2_ploadrubt_io, Hexagon::L2_ploadrubf_io },
  { Hexagon::L2_ploadrubt_pi, Hexagon::L2_ploadrubf_pi },
  { Hexagon::L2_ploadrubtnew_io, Hexagon::L2_ploadrubfnew_io },
  { Hexagon::L2_ploadrubtnew_pi, Hexagon::L2_ploadrubfnew_pi },
  { Hexagon::L2_ploadruht_io, Hexagon::L2_ploadruhf_io },
  { Hexagon::L2_ploadruht_pi, Hexagon::L2_ploadruhf_pi },
  { Hexagon::L2_ploadruhtnew_io, Hexagon::L2_ploadruhfnew_io },
  { Hexagon::L2_ploadruhtnew_pi, Hexagon::L2_ploadruhfnew_pi },
  { Hexagon::L4_ploadrbt_abs, Hexagon::L4_ploadrbf_abs },
  { Hexagon::L4_ploadrbt_rr, Hexagon::L4_ploadrbf_rr },
  { Hexagon::L4_ploadrbtnew_abs, Hexagon::L4_ploadrbfnew_abs },
  { Hexagon::L4_ploadrbtnew_rr, Hexagon::L4_ploadrbfnew_rr },
  { Hexagon::L4_ploadrdt_abs, Hexagon::L4_ploadrdf_abs },
  { Hexagon::L4_ploadrdt_rr, Hexagon::L4_ploadrdf_rr },
  { Hexagon::L4_ploadrdtnew_abs, Hexagon::L4_ploadrdfnew_abs },
  { Hexagon::L4_ploadrdtnew_rr, Hexagon::L4_ploadrdfnew_rr },
  { Hexagon::L4_ploadrht_abs, Hexagon::L4_ploadrhf_abs },
  { Hexagon::L4_ploadrht_rr, Hexagon::L4_ploadrhf_rr },
  { Hexagon::L4_ploadrhtnew_abs, Hexagon::L4_ploadrhfnew_abs },
  { Hexagon::L4_ploadrhtnew_rr, Hexagon::L4_ploadrhfnew_rr },
  { Hexagon::L4_ploadrit_abs, Hexagon::L4_ploadrif_abs },
  { Hexagon::L4_ploadrit_rr, Hexagon::L4_ploadrif_rr },
  { Hexagon::L4_ploadritnew_abs, Hexagon::L4_ploadrifnew_abs },
  { Hexagon::L4_ploadritnew_rr, Hexagon::L4_ploadrifnew_rr },
  { Hexagon::L4_ploadrubt_abs, Hexagon::L4_ploadrubf_abs },
  { Hexagon::L4_ploadrubt_rr, Hexagon::L4_ploadrubf_rr },
  { Hexagon::L4_ploadrubtnew_abs, Hexagon::L4_ploadrubfnew_abs },
  { Hexagon::L4_ploadrubtnew_rr, Hexagon::L4_ploadrubfnew_rr },
  { Hexagon::L4_ploadruht_abs, Hexagon::L4_ploadruhf_abs },
  { Hexagon::L4_ploadruht_rr, Hexagon::L4_ploadruhf_rr },
  { Hexagon::L4_ploadruhtnew_abs, Hexagon::L4_ploadruhfnew_abs },
  { Hexagon::L4_ploadruhtnew_rr, Hexagon::L4_ploadruhfnew_rr },
  { Hexagon::L4_return_t, Hexagon::L4_return_f },
  { Hexagon::L4_return_tnew_pnt, Hexagon::L4_return_fnew_pnt },
  { Hexagon::L4_return_tnew_pt, Hexagon::L4_return_fnew_pt },
  { Hexagon::S2_pstorerbnewt_io, Hexagon::S2_pstorerbnewf_io },
  { Hexagon::S2_pstorerbnewt_pi, Hexagon::S2_pstorerbnewf_pi },
  { Hexagon::S2_pstorerbnewtnew_pi, Hexagon::S2_pstorerbnewfnew_pi },
  { Hexagon::S2_pstorerbt_io, Hexagon::S2_pstorerbf_io },
  { Hexagon::S2_pstorerbt_pi, Hexagon::S2_pstorerbf_pi },
  { Hexagon::S2_pstorerbtnew_pi, Hexagon::S2_pstorerbfnew_pi },
  { Hexagon::S2_pstorerdt_io, Hexagon::S2_pstorerdf_io },
  { Hexagon::S2_pstorerdt_pi, Hexagon::S2_pstorerdf_pi },
  { Hexagon::S2_pstorerdtnew_pi, Hexagon::S2_pstorerdfnew_pi },
  { Hexagon::S2_pstorerft_io, Hexagon::S2_pstorerff_io },
  { Hexagon::S2_pstorerft_pi, Hexagon::S2_pstorerff_pi },
  { Hexagon::S2_pstorerftnew_pi, Hexagon::S2_pstorerffnew_pi },
  { Hexagon::S2_pstorerhnewt_io, Hexagon::S2_pstorerhnewf_io },
  { Hexagon::S2_pstorerhnewt_pi, Hexagon::S2_pstorerhnewf_pi },
  { Hexagon::S2_pstorerhnewtnew_pi, Hexagon::S2_pstorerhnewfnew_pi },
  { Hexagon::S2_pstorerht_io, Hexagon::S2_pstorerhf_io },
  { Hexagon::S2_pstorerht_pi, Hexagon::S2_pstorerhf_pi },
  { Hexagon::S2_pstorerhtnew_pi, Hexagon::S2_pstorerhfnew_pi },
  { Hexagon::S2_pstorerinewt_io, Hexagon::S2_pstorerinewf_io },
  { Hexagon::S2_pstorerinewt_pi, Hexagon::S2_pstorerinewf_pi },
  { Hexagon::S2_pstorerinewtnew_pi, Hexagon::S2_pstorerinewfnew_pi },
  { Hexagon::S2_pstorerit_io, Hexagon::S2_pstorerif_io },
  { Hexagon::S2_pstorerit_pi, Hexagon::S2_pstorerif_pi },
  { Hexagon::S2_pstoreritnew_pi, Hexagon::S2_pstorerifnew_pi },
  { Hexagon::S4_pstorerbnewt_abs, Hexagon::S4_pstorerbnewf_abs },
  { Hexagon::S4_pstorerbnewt_rr, Hexagon::S4_pstorerbnewf_rr },
  { Hexagon::S4_pstorerbnewtnew_abs, Hexagon::S4_pstorerbnewfnew_abs },
  { Hexagon::S4_pstorerbnewtnew_io, Hexagon::S4_pstorerbnewfnew_io },
  { Hexagon::S4_pstorerbnewtnew_rr, Hexagon::S4_pstorerbnewfnew_rr },
  { Hexagon::S4_pstorerbt_abs, Hexagon::S4_pstorerbf_abs },
  { Hexagon::S4_pstorerbt_rr, Hexagon::S4_pstorerbf_rr },
  { Hexagon::S4_pstorerbtnew_abs, Hexagon::S4_pstorerbfnew_abs },
  { Hexagon::S4_pstorerbtnew_io, Hexagon::S4_pstorerbfnew_io },
  { Hexagon::S4_pstorerbtnew_rr, Hexagon::S4_pstorerbfnew_rr },
  { Hexagon::S4_pstorerdt_abs, Hexagon::S4_pstorerdf_abs },
  { Hexagon::S4_pstorerdt_rr, Hexagon::S4_pstorerdf_rr },
  { Hexagon::S4_pstorerdtnew_abs, Hexagon::S4_pstorerdfnew_abs },
  { Hexagon::S4_pstorerdtnew_io, Hexagon::S4_pstorerdfnew_io },
  { Hexagon::S4_pstorerdtnew_rr, Hexagon::S4_pstorerdfnew_rr },
  { Hexagon::S4_pstorerft_abs, Hexagon::S4_pstorerff_abs },
  { Hexagon::S4_pstorerft_rr, Hexagon::S4_pstorerff_rr },
  { Hexagon::S4_pstorerftnew_abs, Hexagon::S4_pstorerffnew_abs },
  { Hexagon::S4_pstorerftnew_io, Hexagon::S4_pstorerffnew_io },
  { Hexagon::S4_pstorerftnew_rr, Hexagon::S4_pstorerffnew_rr },
  { Hexagon::S4_pstorerhnewt_abs, Hexagon::S4_pstorerhnewf_abs },
  { Hexagon::S4_pstorerhnewt_rr, Hexagon::S4_pstorerhnewf_rr },
  { Hexagon::S4_pstorerhnewtnew_abs, Hexagon::S4_pstorerhnewfnew_abs },
  { Hexagon::S4_pstorerhnewtnew_io, Hexagon::S4_pstorerhnewfnew_io },
  { Hexagon::S4_pstorerhnewtnew_rr, Hexagon::S4_pstorerhnewfnew_rr },
  { Hexagon::S4_pstorerht_abs, Hexagon::S4_pstorerhf_abs },
  { Hexagon::S4_pstorerht_rr, Hexagon::S4_pstorerhf_rr },
  { Hexagon::S4_pstorerhtnew_abs, Hexagon::S4_pstorerhfnew_abs },
  { Hexagon::S4_pstorerhtnew_io, Hexagon::S4_pstorerhfnew_io },
  { Hexagon::S4_pstorerhtnew_rr, Hexagon::S4_pstorerhfnew_rr },
  { Hexagon::S4_pstorerinewt_abs, Hexagon::S4_pstorerinewf_abs },
  { Hexagon::S4_pstorerinewt_rr, Hexagon::S4_pstorerinewf_rr },
  { Hexagon::S4_pstorerinewtnew_abs, Hexagon::S4_pstorerinewfnew_abs },
  { Hexagon::S4_pstorerinewtnew_io, Hexagon::S4_pstorerinewfnew_io },
  { Hexagon::S4_pstorerinewtnew_rr, Hexagon::S4_pstorerinewfnew_rr },
  { Hexagon::S4_pstorerit_abs, Hexagon::S4_pstorerif_abs },
  { Hexagon::S4_pstorerit_rr, Hexagon::S4_pstorerif_rr },
  { Hexagon::S4_pstoreritnew_abs, Hexagon::S4_pstorerifnew_abs },
  { Hexagon::S4_pstoreritnew_io, Hexagon::S4_pstorerifnew_io },
  { Hexagon::S4_pstoreritnew_rr, Hexagon::S4_pstorerifnew_rr },
  { Hexagon::S4_storeirbt_io, Hexagon::S4_storeirbf_io },
  { Hexagon::S4_storeirbtnew_io, Hexagon::S4_storeirbfnew_io },
  { Hexagon::S4_storeirht_io, Hexagon::S4_storeirhf_io },
  { Hexagon::S4_storeirhtnew_io, Hexagon::S4_storeirhfnew_io },
  { Hexagon::S4_storeirit_io, Hexagon::S4_storeirif_io },
  { Hexagon::S4_storeiritnew_io, Hexagon::S4_storeirifnew_io },
  { Hexagon::V6_vS32Ub_pred_ai, Hexagon::V6_vS32Ub_npred_ai },
  { Hexagon::V6_vS32Ub_pred_ai_128B, Hexagon::V6_vS32Ub_npred_ai_128B },
  { Hexagon::V6_vS32Ub_pred_pi, Hexagon::V6_vS32Ub_npred_pi },
  { Hexagon::V6_vS32Ub_pred_pi_128B, Hexagon::V6_vS32Ub_npred_pi_128B },
  { Hexagon::V6_vS32Ub_pred_ppu, Hexagon::V6_vS32Ub_npred_ppu },
  { Hexagon::V6_vS32b_new_pred_ai, Hexagon::V6_vS32b_new_npred_ai },
  { Hexagon::V6_vS32b_new_pred_ai_128B, Hexagon::V6_vS32b_new_npred_ai_128B },
  { Hexagon::V6_vS32b_new_pred_pi, Hexagon::V6_vS32b_new_npred_pi },
  { Hexagon::V6_vS32b_new_pred_pi_128B, Hexagon::V6_vS32b_new_npred_pi_128B },
  { Hexagon::V6_vS32b_new_pred_ppu, Hexagon::V6_vS32b_new_npred_ppu },
  { Hexagon::V6_vS32b_nt_new_pred_ai, Hexagon::V6_vS32b_nt_new_npred_ai },
  { Hexagon::V6_vS32b_nt_new_pred_ai_128B, Hexagon::V6_vS32b_nt_new_npred_ai_128B },
  { Hexagon::V6_vS32b_nt_new_pred_pi, Hexagon::V6_vS32b_nt_new_npred_pi },
  { Hexagon::V6_vS32b_nt_new_pred_pi_128B, Hexagon::V6_vS32b_nt_new_npred_pi_128B },
  { Hexagon::V6_vS32b_nt_new_pred_ppu, Hexagon::V6_vS32b_nt_new_npred_ppu },
  { Hexagon::V6_vS32b_nt_pred_ai, Hexagon::V6_vS32b_nt_npred_ai },
  { Hexagon::V6_vS32b_nt_pred_ai_128B, Hexagon::V6_vS32b_nt_npred_ai_128B },
  { Hexagon::V6_vS32b_nt_pred_pi, Hexagon::V6_vS32b_nt_npred_pi },
  { Hexagon::V6_vS32b_nt_pred_pi_128B, Hexagon::V6_vS32b_nt_npred_pi_128B },
  { Hexagon::V6_vS32b_nt_pred_ppu, Hexagon::V6_vS32b_nt_npred_ppu },
  { Hexagon::V6_vS32b_pred_ai, Hexagon::V6_vS32b_npred_ai },
  { Hexagon::V6_vS32b_pred_ai_128B, Hexagon::V6_vS32b_npred_ai_128B },
  { Hexagon::V6_vS32b_pred_pi, Hexagon::V6_vS32b_npred_pi },
  { Hexagon::V6_vS32b_pred_pi_128B, Hexagon::V6_vS32b_npred_pi_128B },
  { Hexagon::V6_vS32b_pred_ppu, Hexagon::V6_vS32b_npred_ppu },
}; // End of getFalsePredOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 210;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getFalsePredOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getFalsePredOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getFalsePredOpcodeTable[mid][1];
}

// getNewValueOpcode
LLVM_READONLY
int getNewValueOpcode(uint16_t Opcode) {
static const uint16_t getNewValueOpcodeTable[][2] = {
  { Hexagon::S2_pstorerbf_io, Hexagon::S2_pstorerbnewf_io },
  { Hexagon::S2_pstorerbf_pi, Hexagon::S2_pstorerbnewf_pi },
  { Hexagon::S2_pstorerbfnew_pi, Hexagon::S2_pstorerbnewfnew_pi },
  { Hexagon::S2_pstorerbt_io, Hexagon::S2_pstorerbnewt_io },
  { Hexagon::S2_pstorerbt_pi, Hexagon::S2_pstorerbnewt_pi },
  { Hexagon::S2_pstorerbtnew_pi, Hexagon::S2_pstorerbnewtnew_pi },
  { Hexagon::S2_pstorerhf_io, Hexagon::S2_pstorerhnewf_io },
  { Hexagon::S2_pstorerhf_pi, Hexagon::S2_pstorerhnewf_pi },
  { Hexagon::S2_pstorerhfnew_pi, Hexagon::S2_pstorerhnewfnew_pi },
  { Hexagon::S2_pstorerht_io, Hexagon::S2_pstorerhnewt_io },
  { Hexagon::S2_pstorerht_pi, Hexagon::S2_pstorerhnewt_pi },
  { Hexagon::S2_pstorerhtnew_pi, Hexagon::S2_pstorerhnewtnew_pi },
  { Hexagon::S2_pstorerif_io, Hexagon::S2_pstorerinewf_io },
  { Hexagon::S2_pstorerif_pi, Hexagon::S2_pstorerinewf_pi },
  { Hexagon::S2_pstorerifnew_pi, Hexagon::S2_pstorerinewfnew_pi },
  { Hexagon::S2_pstorerit_io, Hexagon::S2_pstorerinewt_io },
  { Hexagon::S2_pstorerit_pi, Hexagon::S2_pstorerinewt_pi },
  { Hexagon::S2_pstoreritnew_pi, Hexagon::S2_pstorerinewtnew_pi },
  { Hexagon::S2_storerb_io, Hexagon::S2_storerbnew_io },
  { Hexagon::S2_storerb_pbr, Hexagon::S2_storerbnew_pbr },
  { Hexagon::S2_storerb_pi, Hexagon::S2_storerbnew_pi },
  { Hexagon::S2_storerbabs, Hexagon::S2_storerbnewabs },
  { Hexagon::S2_storerbgp, Hexagon::S2_storerbnewgp },
  { Hexagon::S2_storerh_io, Hexagon::S2_storerhnew_io },
  { Hexagon::S2_storerh_pbr, Hexagon::S2_storerhnew_pbr },
  { Hexagon::S2_storerh_pi, Hexagon::S2_storerhnew_pi },
  { Hexagon::S2_storerhabs, Hexagon::S2_storerhnewabs },
  { Hexagon::S2_storerhgp, Hexagon::S2_storerhnewgp },
  { Hexagon::S2_storeri_io, Hexagon::S2_storerinew_io },
  { Hexagon::S2_storeri_pbr, Hexagon::S2_storerinew_pbr },
  { Hexagon::S2_storeri_pi, Hexagon::S2_storerinew_pi },
  { Hexagon::S2_storeriabs, Hexagon::S2_storerinewabs },
  { Hexagon::S2_storerigp, Hexagon::S2_storerinewgp },
  { Hexagon::S4_pstorerbf_abs, Hexagon::S4_pstorerbnewf_abs },
  { Hexagon::S4_pstorerbf_rr, Hexagon::S4_pstorerbnewf_rr },
  { Hexagon::S4_pstorerbfnew_abs, Hexagon::S4_pstorerbnewfnew_abs },
  { Hexagon::S4_pstorerbfnew_io, Hexagon::S4_pstorerbnewfnew_io },
  { Hexagon::S4_pstorerbfnew_rr, Hexagon::S4_pstorerbnewfnew_rr },
  { Hexagon::S4_pstorerbt_abs, Hexagon::S4_pstorerbnewt_abs },
  { Hexagon::S4_pstorerbt_rr, Hexagon::S4_pstorerbnewt_rr },
  { Hexagon::S4_pstorerbtnew_abs, Hexagon::S4_pstorerbnewtnew_abs },
  { Hexagon::S4_pstorerbtnew_io, Hexagon::S4_pstorerbnewtnew_io },
  { Hexagon::S4_pstorerbtnew_rr, Hexagon::S4_pstorerbnewtnew_rr },
  { Hexagon::S4_pstorerhf_abs, Hexagon::S4_pstorerhnewf_abs },
  { Hexagon::S4_pstorerhf_rr, Hexagon::S4_pstorerhnewf_rr },
  { Hexagon::S4_pstorerhfnew_abs, Hexagon::S4_pstorerhnewfnew_abs },
  { Hexagon::S4_pstorerhfnew_io, Hexagon::S4_pstorerhnewfnew_io },
  { Hexagon::S4_pstorerhfnew_rr, Hexagon::S4_pstorerhnewfnew_rr },
  { Hexagon::S4_pstorerht_abs, Hexagon::S4_pstorerhnewt_abs },
  { Hexagon::S4_pstorerht_rr, Hexagon::S4_pstorerhnewt_rr },
  { Hexagon::S4_pstorerhtnew_abs, Hexagon::S4_pstorerhnewtnew_abs },
  { Hexagon::S4_pstorerhtnew_io, Hexagon::S4_pstorerhnewtnew_io },
  { Hexagon::S4_pstorerhtnew_rr, Hexagon::S4_pstorerhnewtnew_rr },
  { Hexagon::S4_pstorerif_abs, Hexagon::S4_pstorerinewf_abs },
  { Hexagon::S4_pstorerif_rr, Hexagon::S4_pstorerinewf_rr },
  { Hexagon::S4_pstorerifnew_abs, Hexagon::S4_pstorerinewfnew_abs },
  { Hexagon::S4_pstorerifnew_io, Hexagon::S4_pstorerinewfnew_io },
  { Hexagon::S4_pstorerifnew_rr, Hexagon::S4_pstorerinewfnew_rr },
  { Hexagon::S4_pstorerit_abs, Hexagon::S4_pstorerinewt_abs },
  { Hexagon::S4_pstorerit_rr, Hexagon::S4_pstorerinewt_rr },
  { Hexagon::S4_pstoreritnew_abs, Hexagon::S4_pstorerinewtnew_abs },
  { Hexagon::S4_pstoreritnew_io, Hexagon::S4_pstorerinewtnew_io },
  { Hexagon::S4_pstoreritnew_rr, Hexagon::S4_pstorerinewtnew_rr },
  { Hexagon::S4_storerb_ap, Hexagon::S4_storerbnew_ap },
  { Hexagon::S4_storerb_rr, Hexagon::S4_storerbnew_rr },
  { Hexagon::S4_storerb_ur, Hexagon::S4_storerbnew_ur },
  { Hexagon::S4_storerh_ap, Hexagon::S4_storerhnew_ap },
  { Hexagon::S4_storerh_rr, Hexagon::S4_storerhnew_rr },
  { Hexagon::S4_storerh_ur, Hexagon::S4_storerhnew_ur },
  { Hexagon::S4_storeri_ap, Hexagon::S4_storerinew_ap },
  { Hexagon::S4_storeri_rr, Hexagon::S4_storerinew_rr },
  { Hexagon::S4_storeri_ur, Hexagon::S4_storerinew_ur },
  { Hexagon::V6_vS32b_ai, Hexagon::V6_vS32b_new_ai },
  { Hexagon::V6_vS32b_ai_128B, Hexagon::V6_vS32b_new_ai_128B },
  { Hexagon::V6_vS32b_npred_ai, Hexagon::V6_vS32b_new_npred_ai },
  { Hexagon::V6_vS32b_npred_ai_128B, Hexagon::V6_vS32b_new_npred_ai_128B },
  { Hexagon::V6_vS32b_npred_pi, Hexagon::V6_vS32b_new_npred_pi },
  { Hexagon::V6_vS32b_npred_pi_128B, Hexagon::V6_vS32b_new_npred_pi_128B },
  { Hexagon::V6_vS32b_npred_ppu, Hexagon::V6_vS32b_new_npred_ppu },
  { Hexagon::V6_vS32b_nt_ai, Hexagon::V6_vS32b_nt_new_ai },
  { Hexagon::V6_vS32b_nt_ai_128B, Hexagon::V6_vS32b_nt_new_ai_128B },
  { Hexagon::V6_vS32b_nt_npred_ai, Hexagon::V6_vS32b_nt_new_npred_ai },
  { Hexagon::V6_vS32b_nt_npred_ai_128B, Hexagon::V6_vS32b_nt_new_npred_ai_128B },
  { Hexagon::V6_vS32b_nt_npred_pi, Hexagon::V6_vS32b_nt_new_npred_pi },
  { Hexagon::V6_vS32b_nt_npred_pi_128B, Hexagon::V6_vS32b_nt_new_npred_pi_128B },
  { Hexagon::V6_vS32b_nt_npred_ppu, Hexagon::V6_vS32b_nt_new_npred_ppu },
  { Hexagon::V6_vS32b_nt_ppu, Hexagon::V6_vS32b_nt_new_ppu },
  { Hexagon::V6_vS32b_nt_pred_ai, Hexagon::V6_vS32b_nt_new_pred_ai },
  { Hexagon::V6_vS32b_nt_pred_ai_128B, Hexagon::V6_vS32b_nt_new_pred_ai_128B },
  { Hexagon::V6_vS32b_nt_pred_pi, Hexagon::V6_vS32b_nt_new_pred_pi },
  { Hexagon::V6_vS32b_nt_pred_pi_128B, Hexagon::V6_vS32b_nt_new_pred_pi_128B },
  { Hexagon::V6_vS32b_nt_pred_ppu, Hexagon::V6_vS32b_nt_new_pred_ppu },
  { Hexagon::V6_vS32b_ppu, Hexagon::V6_vS32b_new_ppu },
  { Hexagon::V6_vS32b_pred_ai, Hexagon::V6_vS32b_new_pred_ai },
  { Hexagon::V6_vS32b_pred_ai_128B, Hexagon::V6_vS32b_new_pred_ai_128B },
  { Hexagon::V6_vS32b_pred_pi, Hexagon::V6_vS32b_new_pred_pi },
  { Hexagon::V6_vS32b_pred_pi_128B, Hexagon::V6_vS32b_new_pred_pi_128B },
  { Hexagon::V6_vS32b_pred_ppu, Hexagon::V6_vS32b_new_pred_ppu },
}; // End of getNewValueOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 98;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getNewValueOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getNewValueOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getNewValueOpcodeTable[mid][1];
}

// getNonNVStore
LLVM_READONLY
int getNonNVStore(uint16_t Opcode) {
static const uint16_t getNonNVStoreTable[][2] = {
  { Hexagon::S2_pstorerbnewf_io, Hexagon::S2_pstorerbf_io },
  { Hexagon::S2_pstorerbnewf_pi, Hexagon::S2_pstorerbf_pi },
  { Hexagon::S2_pstorerbnewfnew_pi, Hexagon::S2_pstorerbfnew_pi },
  { Hexagon::S2_pstorerbnewt_io, Hexagon::S2_pstorerbt_io },
  { Hexagon::S2_pstorerbnewt_pi, Hexagon::S2_pstorerbt_pi },
  { Hexagon::S2_pstorerbnewtnew_pi, Hexagon::S2_pstorerbtnew_pi },
  { Hexagon::S2_pstorerhnewf_io, Hexagon::S2_pstorerhf_io },
  { Hexagon::S2_pstorerhnewf_pi, Hexagon::S2_pstorerhf_pi },
  { Hexagon::S2_pstorerhnewfnew_pi, Hexagon::S2_pstorerhfnew_pi },
  { Hexagon::S2_pstorerhnewt_io, Hexagon::S2_pstorerht_io },
  { Hexagon::S2_pstorerhnewt_pi, Hexagon::S2_pstorerht_pi },
  { Hexagon::S2_pstorerhnewtnew_pi, Hexagon::S2_pstorerhtnew_pi },
  { Hexagon::S2_pstorerinewf_io, Hexagon::S2_pstorerif_io },
  { Hexagon::S2_pstorerinewf_pi, Hexagon::S2_pstorerif_pi },
  { Hexagon::S2_pstorerinewfnew_pi, Hexagon::S2_pstorerifnew_pi },
  { Hexagon::S2_pstorerinewt_io, Hexagon::S2_pstorerit_io },
  { Hexagon::S2_pstorerinewt_pi, Hexagon::S2_pstorerit_pi },
  { Hexagon::S2_pstorerinewtnew_pi, Hexagon::S2_pstoreritnew_pi },
  { Hexagon::S2_storerbnew_io, Hexagon::S2_storerb_io },
  { Hexagon::S2_storerbnew_pbr, Hexagon::S2_storerb_pbr },
  { Hexagon::S2_storerbnew_pi, Hexagon::S2_storerb_pi },
  { Hexagon::S2_storerbnewabs, Hexagon::S2_storerbabs },
  { Hexagon::S2_storerbnewgp, Hexagon::S2_storerbgp },
  { Hexagon::S2_storerhnew_io, Hexagon::S2_storerh_io },
  { Hexagon::S2_storerhnew_pbr, Hexagon::S2_storerh_pbr },
  { Hexagon::S2_storerhnew_pi, Hexagon::S2_storerh_pi },
  { Hexagon::S2_storerhnewabs, Hexagon::S2_storerhabs },
  { Hexagon::S2_storerhnewgp, Hexagon::S2_storerhgp },
  { Hexagon::S2_storerinew_io, Hexagon::S2_storeri_io },
  { Hexagon::S2_storerinew_pbr, Hexagon::S2_storeri_pbr },
  { Hexagon::S2_storerinew_pi, Hexagon::S2_storeri_pi },
  { Hexagon::S2_storerinewabs, Hexagon::S2_storeriabs },
  { Hexagon::S2_storerinewgp, Hexagon::S2_storerigp },
  { Hexagon::S4_pstorerbnewf_abs, Hexagon::S4_pstorerbf_abs },
  { Hexagon::S4_pstorerbnewf_rr, Hexagon::S4_pstorerbf_rr },
  { Hexagon::S4_pstorerbnewfnew_abs, Hexagon::S4_pstorerbfnew_abs },
  { Hexagon::S4_pstorerbnewfnew_io, Hexagon::S4_pstorerbfnew_io },
  { Hexagon::S4_pstorerbnewfnew_rr, Hexagon::S4_pstorerbfnew_rr },
  { Hexagon::S4_pstorerbnewt_abs, Hexagon::S4_pstorerbt_abs },
  { Hexagon::S4_pstorerbnewt_rr, Hexagon::S4_pstorerbt_rr },
  { Hexagon::S4_pstorerbnewtnew_abs, Hexagon::S4_pstorerbtnew_abs },
  { Hexagon::S4_pstorerbnewtnew_io, Hexagon::S4_pstorerbtnew_io },
  { Hexagon::S4_pstorerbnewtnew_rr, Hexagon::S4_pstorerbtnew_rr },
  { Hexagon::S4_pstorerhnewf_abs, Hexagon::S4_pstorerhf_abs },
  { Hexagon::S4_pstorerhnewf_rr, Hexagon::S4_pstorerhf_rr },
  { Hexagon::S4_pstorerhnewfnew_abs, Hexagon::S4_pstorerhfnew_abs },
  { Hexagon::S4_pstorerhnewfnew_io, Hexagon::S4_pstorerhfnew_io },
  { Hexagon::S4_pstorerhnewfnew_rr, Hexagon::S4_pstorerhfnew_rr },
  { Hexagon::S4_pstorerhnewt_abs, Hexagon::S4_pstorerht_abs },
  { Hexagon::S4_pstorerhnewt_rr, Hexagon::S4_pstorerht_rr },
  { Hexagon::S4_pstorerhnewtnew_abs, Hexagon::S4_pstorerhtnew_abs },
  { Hexagon::S4_pstorerhnewtnew_io, Hexagon::S4_pstorerhtnew_io },
  { Hexagon::S4_pstorerhnewtnew_rr, Hexagon::S4_pstorerhtnew_rr },
  { Hexagon::S4_pstorerinewf_abs, Hexagon::S4_pstorerif_abs },
  { Hexagon::S4_pstorerinewf_rr, Hexagon::S4_pstorerif_rr },
  { Hexagon::S4_pstorerinewfnew_abs, Hexagon::S4_pstorerifnew_abs },
  { Hexagon::S4_pstorerinewfnew_io, Hexagon::S4_pstorerifnew_io },
  { Hexagon::S4_pstorerinewfnew_rr, Hexagon::S4_pstorerifnew_rr },
  { Hexagon::S4_pstorerinewt_abs, Hexagon::S4_pstorerit_abs },
  { Hexagon::S4_pstorerinewt_rr, Hexagon::S4_pstorerit_rr },
  { Hexagon::S4_pstorerinewtnew_abs, Hexagon::S4_pstoreritnew_abs },
  { Hexagon::S4_pstorerinewtnew_io, Hexagon::S4_pstoreritnew_io },
  { Hexagon::S4_pstorerinewtnew_rr, Hexagon::S4_pstoreritnew_rr },
  { Hexagon::S4_storerbnew_ap, Hexagon::S4_storerb_ap },
  { Hexagon::S4_storerbnew_rr, Hexagon::S4_storerb_rr },
  { Hexagon::S4_storerbnew_ur, Hexagon::S4_storerb_ur },
  { Hexagon::S4_storerhnew_ap, Hexagon::S4_storerh_ap },
  { Hexagon::S4_storerhnew_rr, Hexagon::S4_storerh_rr },
  { Hexagon::S4_storerhnew_ur, Hexagon::S4_storerh_ur },
  { Hexagon::S4_storerinew_ap, Hexagon::S4_storeri_ap },
  { Hexagon::S4_storerinew_rr, Hexagon::S4_storeri_rr },
  { Hexagon::S4_storerinew_ur, Hexagon::S4_storeri_ur },
  { Hexagon::V6_vS32b_new_ai, Hexagon::V6_vS32b_ai },
  { Hexagon::V6_vS32b_new_ai_128B, Hexagon::V6_vS32b_ai_128B },
  { Hexagon::V6_vS32b_new_npred_ai, Hexagon::V6_vS32b_npred_ai },
  { Hexagon::V6_vS32b_new_npred_ai_128B, Hexagon::V6_vS32b_npred_ai_128B },
  { Hexagon::V6_vS32b_new_npred_pi, Hexagon::V6_vS32b_npred_pi },
  { Hexagon::V6_vS32b_new_npred_pi_128B, Hexagon::V6_vS32b_npred_pi_128B },
  { Hexagon::V6_vS32b_new_npred_ppu, Hexagon::V6_vS32b_npred_ppu },
  { Hexagon::V6_vS32b_new_ppu, Hexagon::V6_vS32b_ppu },
  { Hexagon::V6_vS32b_new_pred_ai, Hexagon::V6_vS32b_pred_ai },
  { Hexagon::V6_vS32b_new_pred_ai_128B, Hexagon::V6_vS32b_pred_ai_128B },
  { Hexagon::V6_vS32b_new_pred_pi, Hexagon::V6_vS32b_pred_pi },
  { Hexagon::V6_vS32b_new_pred_pi_128B, Hexagon::V6_vS32b_pred_pi_128B },
  { Hexagon::V6_vS32b_new_pred_ppu, Hexagon::V6_vS32b_pred_ppu },
  { Hexagon::V6_vS32b_nt_new_ai, Hexagon::V6_vS32b_nt_ai },
  { Hexagon::V6_vS32b_nt_new_ai_128B, Hexagon::V6_vS32b_nt_ai_128B },
  { Hexagon::V6_vS32b_nt_new_npred_ai, Hexagon::V6_vS32b_nt_npred_ai },
  { Hexagon::V6_vS32b_nt_new_npred_ai_128B, Hexagon::V6_vS32b_nt_npred_ai_128B },
  { Hexagon::V6_vS32b_nt_new_npred_pi, Hexagon::V6_vS32b_nt_npred_pi },
  { Hexagon::V6_vS32b_nt_new_npred_pi_128B, Hexagon::V6_vS32b_nt_npred_pi_128B },
  { Hexagon::V6_vS32b_nt_new_npred_ppu, Hexagon::V6_vS32b_nt_npred_ppu },
  { Hexagon::V6_vS32b_nt_new_ppu, Hexagon::V6_vS32b_nt_ppu },
  { Hexagon::V6_vS32b_nt_new_pred_ai, Hexagon::V6_vS32b_nt_pred_ai },
  { Hexagon::V6_vS32b_nt_new_pred_ai_128B, Hexagon::V6_vS32b_nt_pred_ai_128B },
  { Hexagon::V6_vS32b_nt_new_pred_pi, Hexagon::V6_vS32b_nt_pred_pi },
  { Hexagon::V6_vS32b_nt_new_pred_pi_128B, Hexagon::V6_vS32b_nt_pred_pi_128B },
  { Hexagon::V6_vS32b_nt_new_pred_ppu, Hexagon::V6_vS32b_nt_pred_ppu },
}; // End of getNonNVStoreTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 98;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getNonNVStoreTable[mid][0]) {
      break;
    }
    if (Opcode < getNonNVStoreTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getNonNVStoreTable[mid][1];
}

// getPredNewOpcode
LLVM_READONLY
int getPredNewOpcode(uint16_t Opcode) {
static const uint16_t getPredNewOpcodeTable[][2] = {
  { Hexagon::A2_paddf, Hexagon::A2_paddfnew },
  { Hexagon::A2_paddif, Hexagon::A2_paddifnew },
  { Hexagon::A2_paddit, Hexagon::A2_padditnew },
  { Hexagon::A2_paddt, Hexagon::A2_paddtnew },
  { Hexagon::A2_pandf, Hexagon::A2_pandfnew },
  { Hexagon::A2_pandt, Hexagon::A2_pandtnew },
  { Hexagon::A2_porf, Hexagon::A2_porfnew },
  { Hexagon::A2_port, Hexagon::A2_portnew },
  { Hexagon::A2_psubf, Hexagon::A2_psubfnew },
  { Hexagon::A2_psubt, Hexagon::A2_psubtnew },
  { Hexagon::A2_pxorf, Hexagon::A2_pxorfnew },
  { Hexagon::A2_pxort, Hexagon::A2_pxortnew },
  { Hexagon::A2_tfrf, Hexagon::A2_tfrfnew },
  { Hexagon::A2_tfrpf, Hexagon::A2_tfrpfnew },
  { Hexagon::A2_tfrpt, Hexagon::A2_tfrptnew },
  { Hexagon::A2_tfrt, Hexagon::A2_tfrtnew },
  { Hexagon::A4_paslhf, Hexagon::A4_paslhfnew },
  { Hexagon::A4_paslht, Hexagon::A4_paslhtnew },
  { Hexagon::A4_pasrhf, Hexagon::A4_pasrhfnew },
  { Hexagon::A4_pasrht, Hexagon::A4_pasrhtnew },
  { Hexagon::A4_psxtbf, Hexagon::A4_psxtbfnew },
  { Hexagon::A4_psxtbt, Hexagon::A4_psxtbtnew },
  { Hexagon::A4_psxthf, Hexagon::A4_psxthfnew },
  { Hexagon::A4_psxtht, Hexagon::A4_psxthtnew },
  { Hexagon::A4_pzxtbf, Hexagon::A4_pzxtbfnew },
  { Hexagon::A4_pzxtbt, Hexagon::A4_pzxtbtnew },
  { Hexagon::A4_pzxthf, Hexagon::A4_pzxthfnew },
  { Hexagon::A4_pzxtht, Hexagon::A4_pzxthtnew },
  { Hexagon::C2_ccombinewf, Hexagon::C2_ccombinewnewf },
  { Hexagon::C2_ccombinewt, Hexagon::C2_ccombinewnewt },
  { Hexagon::C2_cmoveif, Hexagon::C2_cmovenewif },
  { Hexagon::C2_cmoveit, Hexagon::C2_cmovenewit },
  { Hexagon::J2_jumpf, Hexagon::J2_jumpfnew },
  { Hexagon::J2_jumprf, Hexagon::J2_jumprfnew },
  { Hexagon::J2_jumprt, Hexagon::J2_jumprtnew },
  { Hexagon::J2_jumpt, Hexagon::J2_jumptnew },
  { Hexagon::JMPretf, Hexagon::JMPretfnew },
  { Hexagon::JMPrett, Hexagon::JMPrettnew },
  { Hexagon::L2_ploadrbf_io, Hexagon::L2_ploadrbfnew_io },
  { Hexagon::L2_ploadrbf_pi, Hexagon::L2_ploadrbfnew_pi },
  { Hexagon::L2_ploadrbt_io, Hexagon::L2_ploadrbtnew_io },
  { Hexagon::L2_ploadrbt_pi, Hexagon::L2_ploadrbtnew_pi },
  { Hexagon::L2_ploadrdf_io, Hexagon::L2_ploadrdfnew_io },
  { Hexagon::L2_ploadrdf_pi, Hexagon::L2_ploadrdfnew_pi },
  { Hexagon::L2_ploadrdt_io, Hexagon::L2_ploadrdtnew_io },
  { Hexagon::L2_ploadrdt_pi, Hexagon::L2_ploadrdtnew_pi },
  { Hexagon::L2_ploadrhf_io, Hexagon::L2_ploadrhfnew_io },
  { Hexagon::L2_ploadrhf_pi, Hexagon::L2_ploadrhfnew_pi },
  { Hexagon::L2_ploadrht_io, Hexagon::L2_ploadrhtnew_io },
  { Hexagon::L2_ploadrht_pi, Hexagon::L2_ploadrhtnew_pi },
  { Hexagon::L2_ploadrif_io, Hexagon::L2_ploadrifnew_io },
  { Hexagon::L2_ploadrif_pi, Hexagon::L2_ploadrifnew_pi },
  { Hexagon::L2_ploadrit_io, Hexagon::L2_ploadritnew_io },
  { Hexagon::L2_ploadrit_pi, Hexagon::L2_ploadritnew_pi },
  { Hexagon::L2_ploadrubf_io, Hexagon::L2_ploadrubfnew_io },
  { Hexagon::L2_ploadrubf_pi, Hexagon::L2_ploadrubfnew_pi },
  { Hexagon::L2_ploadrubt_io, Hexagon::L2_ploadrubtnew_io },
  { Hexagon::L2_ploadrubt_pi, Hexagon::L2_ploadrubtnew_pi },
  { Hexagon::L2_ploadruhf_io, Hexagon::L2_ploadruhfnew_io },
  { Hexagon::L2_ploadruhf_pi, Hexagon::L2_ploadruhfnew_pi },
  { Hexagon::L2_ploadruht_io, Hexagon::L2_ploadruhtnew_io },
  { Hexagon::L2_ploadruht_pi, Hexagon::L2_ploadruhtnew_pi },
  { Hexagon::L4_ploadrbf_abs, Hexagon::L4_ploadrbfnew_abs },
  { Hexagon::L4_ploadrbf_rr, Hexagon::L4_ploadrbfnew_rr },
  { Hexagon::L4_ploadrbt_abs, Hexagon::L4_ploadrbtnew_abs },
  { Hexagon::L4_ploadrbt_rr, Hexagon::L4_ploadrbtnew_rr },
  { Hexagon::L4_ploadrdf_abs, Hexagon::L4_ploadrdfnew_abs },
  { Hexagon::L4_ploadrdf_rr, Hexagon::L4_ploadrdfnew_rr },
  { Hexagon::L4_ploadrdt_abs, Hexagon::L4_ploadrdtnew_abs },
  { Hexagon::L4_ploadrdt_rr, Hexagon::L4_ploadrdtnew_rr },
  { Hexagon::L4_ploadrhf_abs, Hexagon::L4_ploadrhfnew_abs },
  { Hexagon::L4_ploadrhf_rr, Hexagon::L4_ploadrhfnew_rr },
  { Hexagon::L4_ploadrht_abs, Hexagon::L4_ploadrhtnew_abs },
  { Hexagon::L4_ploadrht_rr, Hexagon::L4_ploadrhtnew_rr },
  { Hexagon::L4_ploadrif_abs, Hexagon::L4_ploadrifnew_abs },
  { Hexagon::L4_ploadrif_rr, Hexagon::L4_ploadrifnew_rr },
  { Hexagon::L4_ploadrit_abs, Hexagon::L4_ploadritnew_abs },
  { Hexagon::L4_ploadrit_rr, Hexagon::L4_ploadritnew_rr },
  { Hexagon::L4_ploadrubf_abs, Hexagon::L4_ploadrubfnew_abs },
  { Hexagon::L4_ploadrubf_rr, Hexagon::L4_ploadrubfnew_rr },
  { Hexagon::L4_ploadrubt_abs, Hexagon::L4_ploadrubtnew_abs },
  { Hexagon::L4_ploadrubt_rr, Hexagon::L4_ploadrubtnew_rr },
  { Hexagon::L4_ploadruhf_abs, Hexagon::L4_ploadruhfnew_abs },
  { Hexagon::L4_ploadruhf_rr, Hexagon::L4_ploadruhfnew_rr },
  { Hexagon::L4_ploadruht_abs, Hexagon::L4_ploadruhtnew_abs },
  { Hexagon::L4_ploadruht_rr, Hexagon::L4_ploadruhtnew_rr },
  { Hexagon::L4_return_f, Hexagon::L4_return_fnew_pt },
  { Hexagon::L4_return_t, Hexagon::L4_return_tnew_pt },
  { Hexagon::S2_pstorerbf_io, Hexagon::S4_pstorerbfnew_io },
  { Hexagon::S2_pstorerbf_pi, Hexagon::S2_pstorerbfnew_pi },
  { Hexagon::S2_pstorerbnewf_io, Hexagon::S4_pstorerbnewfnew_io },
  { Hexagon::S2_pstorerbnewf_pi, Hexagon::S2_pstorerbnewfnew_pi },
  { Hexagon::S2_pstorerbnewt_io, Hexagon::S4_pstorerbnewtnew_io },
  { Hexagon::S2_pstorerbnewt_pi, Hexagon::S2_pstorerbnewtnew_pi },
  { Hexagon::S2_pstorerbt_io, Hexagon::S4_pstorerbtnew_io },
  { Hexagon::S2_pstorerbt_pi, Hexagon::S2_pstorerbtnew_pi },
  { Hexagon::S2_pstorerdf_io, Hexagon::S4_pstorerdfnew_io },
  { Hexagon::S2_pstorerdf_pi, Hexagon::S2_pstorerdfnew_pi },
  { Hexagon::S2_pstorerdt_io, Hexagon::S4_pstorerdtnew_io },
  { Hexagon::S2_pstorerdt_pi, Hexagon::S2_pstorerdtnew_pi },
  { Hexagon::S2_pstorerff_io, Hexagon::S4_pstorerffnew_io },
  { Hexagon::S2_pstorerff_pi, Hexagon::S2_pstorerffnew_pi },
  { Hexagon::S2_pstorerft_io, Hexagon::S4_pstorerftnew_io },
  { Hexagon::S2_pstorerft_pi, Hexagon::S2_pstorerftnew_pi },
  { Hexagon::S2_pstorerhf_io, Hexagon::S4_pstorerhfnew_io },
  { Hexagon::S2_pstorerhf_pi, Hexagon::S2_pstorerhfnew_pi },
  { Hexagon::S2_pstorerhnewf_io, Hexagon::S4_pstorerhnewfnew_io },
  { Hexagon::S2_pstorerhnewf_pi, Hexagon::S2_pstorerhnewfnew_pi },
  { Hexagon::S2_pstorerhnewt_io, Hexagon::S4_pstorerhnewtnew_io },
  { Hexagon::S2_pstorerhnewt_pi, Hexagon::S2_pstorerhnewtnew_pi },
  { Hexagon::S2_pstorerht_io, Hexagon::S4_pstorerhtnew_io },
  { Hexagon::S2_pstorerht_pi, Hexagon::S2_pstorerhtnew_pi },
  { Hexagon::S2_pstorerif_io, Hexagon::S4_pstorerifnew_io },
  { Hexagon::S2_pstorerif_pi, Hexagon::S2_pstorerifnew_pi },
  { Hexagon::S2_pstorerinewf_io, Hexagon::S4_pstorerinewfnew_io },
  { Hexagon::S2_pstorerinewf_pi, Hexagon::S2_pstorerinewfnew_pi },
  { Hexagon::S2_pstorerinewt_io, Hexagon::S4_pstorerinewtnew_io },
  { Hexagon::S2_pstorerinewt_pi, Hexagon::S2_pstorerinewtnew_pi },
  { Hexagon::S2_pstorerit_io, Hexagon::S4_pstoreritnew_io },
  { Hexagon::S2_pstorerit_pi, Hexagon::S2_pstoreritnew_pi },
  { Hexagon::S4_pstorerbf_abs, Hexagon::S4_pstorerbfnew_abs },
  { Hexagon::S4_pstorerbf_rr, Hexagon::S4_pstorerbfnew_rr },
  { Hexagon::S4_pstorerbnewf_abs, Hexagon::S4_pstorerbnewfnew_abs },
  { Hexagon::S4_pstorerbnewf_rr, Hexagon::S4_pstorerbnewfnew_rr },
  { Hexagon::S4_pstorerbnewt_abs, Hexagon::S4_pstorerbnewtnew_abs },
  { Hexagon::S4_pstorerbnewt_rr, Hexagon::S4_pstorerbnewtnew_rr },
  { Hexagon::S4_pstorerbt_abs, Hexagon::S4_pstorerbtnew_abs },
  { Hexagon::S4_pstorerbt_rr, Hexagon::S4_pstorerbtnew_rr },
  { Hexagon::S4_pstorerdf_abs, Hexagon::S4_pstorerdfnew_abs },
  { Hexagon::S4_pstorerdf_rr, Hexagon::S4_pstorerdfnew_rr },
  { Hexagon::S4_pstorerdt_abs, Hexagon::S4_pstorerdtnew_abs },
  { Hexagon::S4_pstorerdt_rr, Hexagon::S4_pstorerdtnew_rr },
  { Hexagon::S4_pstorerff_abs, Hexagon::S4_pstorerffnew_abs },
  { Hexagon::S4_pstorerff_rr, Hexagon::S4_pstorerffnew_rr },
  { Hexagon::S4_pstorerft_abs, Hexagon::S4_pstorerftnew_abs },
  { Hexagon::S4_pstorerft_rr, Hexagon::S4_pstorerftnew_rr },
  { Hexagon::S4_pstorerhf_abs, Hexagon::S4_pstorerhfnew_abs },
  { Hexagon::S4_pstorerhf_rr, Hexagon::S4_pstorerhfnew_rr },
  { Hexagon::S4_pstorerhnewf_abs, Hexagon::S4_pstorerhnewfnew_abs },
  { Hexagon::S4_pstorerhnewf_rr, Hexagon::S4_pstorerhnewfnew_rr },
  { Hexagon::S4_pstorerhnewt_abs, Hexagon::S4_pstorerhnewtnew_abs },
  { Hexagon::S4_pstorerhnewt_rr, Hexagon::S4_pstorerhnewtnew_rr },
  { Hexagon::S4_pstorerht_abs, Hexagon::S4_pstorerhtnew_abs },
  { Hexagon::S4_pstorerht_rr, Hexagon::S4_pstorerhtnew_rr },
  { Hexagon::S4_pstorerif_abs, Hexagon::S4_pstorerifnew_abs },
  { Hexagon::S4_pstorerif_rr, Hexagon::S4_pstorerifnew_rr },
  { Hexagon::S4_pstorerinewf_abs, Hexagon::S4_pstorerinewfnew_abs },
  { Hexagon::S4_pstorerinewf_rr, Hexagon::S4_pstorerinewfnew_rr },
  { Hexagon::S4_pstorerinewt_abs, Hexagon::S4_pstorerinewtnew_abs },
  { Hexagon::S4_pstorerinewt_rr, Hexagon::S4_pstorerinewtnew_rr },
  { Hexagon::S4_pstorerit_abs, Hexagon::S4_pstoreritnew_abs },
  { Hexagon::S4_pstorerit_rr, Hexagon::S4_pstoreritnew_rr },
  { Hexagon::S4_storeirbf_io, Hexagon::S4_storeirbfnew_io },
  { Hexagon::S4_storeirbt_io, Hexagon::S4_storeirbtnew_io },
  { Hexagon::S4_storeirhf_io, Hexagon::S4_storeirhfnew_io },
  { Hexagon::S4_storeirht_io, Hexagon::S4_storeirhtnew_io },
  { Hexagon::S4_storeirif_io, Hexagon::S4_storeirifnew_io },
  { Hexagon::S4_storeirit_io, Hexagon::S4_storeiritnew_io },
}; // End of getPredNewOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 158;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getPredNewOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getPredNewOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getPredNewOpcodeTable[mid][1];
}

// getPredOldOpcode
LLVM_READONLY
int getPredOldOpcode(uint16_t Opcode) {
static const uint16_t getPredOldOpcodeTable[][2] = {
  { Hexagon::A2_paddfnew, Hexagon::A2_paddf },
  { Hexagon::A2_paddifnew, Hexagon::A2_paddif },
  { Hexagon::A2_padditnew, Hexagon::A2_paddit },
  { Hexagon::A2_paddtnew, Hexagon::A2_paddt },
  { Hexagon::A2_pandfnew, Hexagon::A2_pandf },
  { Hexagon::A2_pandtnew, Hexagon::A2_pandt },
  { Hexagon::A2_porfnew, Hexagon::A2_porf },
  { Hexagon::A2_portnew, Hexagon::A2_port },
  { Hexagon::A2_psubfnew, Hexagon::A2_psubf },
  { Hexagon::A2_psubtnew, Hexagon::A2_psubt },
  { Hexagon::A2_pxorfnew, Hexagon::A2_pxorf },
  { Hexagon::A2_pxortnew, Hexagon::A2_pxort },
  { Hexagon::A2_tfrfnew, Hexagon::A2_tfrf },
  { Hexagon::A2_tfrpfnew, Hexagon::A2_tfrpf },
  { Hexagon::A2_tfrptnew, Hexagon::A2_tfrpt },
  { Hexagon::A2_tfrtnew, Hexagon::A2_tfrt },
  { Hexagon::A4_paslhfnew, Hexagon::A4_paslhf },
  { Hexagon::A4_paslhtnew, Hexagon::A4_paslht },
  { Hexagon::A4_pasrhfnew, Hexagon::A4_pasrhf },
  { Hexagon::A4_pasrhtnew, Hexagon::A4_pasrht },
  { Hexagon::A4_psxtbfnew, Hexagon::A4_psxtbf },
  { Hexagon::A4_psxtbtnew, Hexagon::A4_psxtbt },
  { Hexagon::A4_psxthfnew, Hexagon::A4_psxthf },
  { Hexagon::A4_psxthtnew, Hexagon::A4_psxtht },
  { Hexagon::A4_pzxtbfnew, Hexagon::A4_pzxtbf },
  { Hexagon::A4_pzxtbtnew, Hexagon::A4_pzxtbt },
  { Hexagon::A4_pzxthfnew, Hexagon::A4_pzxthf },
  { Hexagon::A4_pzxthtnew, Hexagon::A4_pzxtht },
  { Hexagon::C2_ccombinewnewf, Hexagon::C2_ccombinewf },
  { Hexagon::C2_ccombinewnewt, Hexagon::C2_ccombinewt },
  { Hexagon::C2_cmovenewif, Hexagon::C2_cmoveif },
  { Hexagon::C2_cmovenewit, Hexagon::C2_cmoveit },
  { Hexagon::J2_jumpfnew, Hexagon::J2_jumpf },
  { Hexagon::J2_jumpfnewpt, Hexagon::J2_jumpf },
  { Hexagon::J2_jumprfnew, Hexagon::J2_jumprf },
  { Hexagon::J2_jumprfnewpt, Hexagon::J2_jumprf },
  { Hexagon::J2_jumprtnew, Hexagon::J2_jumprt },
  { Hexagon::J2_jumprtnewpt, Hexagon::J2_jumprt },
  { Hexagon::J2_jumptnew, Hexagon::J2_jumpt },
  { Hexagon::J2_jumptnewpt, Hexagon::J2_jumpt },
  { Hexagon::JMPretfnew, Hexagon::JMPretf },
  { Hexagon::JMPretfnewpt, Hexagon::JMPretf },
  { Hexagon::JMPrettnew, Hexagon::JMPrett },
  { Hexagon::JMPrettnewpt, Hexagon::JMPrett },
  { Hexagon::L2_ploadrbfnew_io, Hexagon::L2_ploadrbf_io },
  { Hexagon::L2_ploadrbfnew_pi, Hexagon::L2_ploadrbf_pi },
  { Hexagon::L2_ploadrbtnew_io, Hexagon::L2_ploadrbt_io },
  { Hexagon::L2_ploadrbtnew_pi, Hexagon::L2_ploadrbt_pi },
  { Hexagon::L2_ploadrdfnew_io, Hexagon::L2_ploadrdf_io },
  { Hexagon::L2_ploadrdfnew_pi, Hexagon::L2_ploadrdf_pi },
  { Hexagon::L2_ploadrdtnew_io, Hexagon::L2_ploadrdt_io },
  { Hexagon::L2_ploadrdtnew_pi, Hexagon::L2_ploadrdt_pi },
  { Hexagon::L2_ploadrhfnew_io, Hexagon::L2_ploadrhf_io },
  { Hexagon::L2_ploadrhfnew_pi, Hexagon::L2_ploadrhf_pi },
  { Hexagon::L2_ploadrhtnew_io, Hexagon::L2_ploadrht_io },
  { Hexagon::L2_ploadrhtnew_pi, Hexagon::L2_ploadrht_pi },
  { Hexagon::L2_ploadrifnew_io, Hexagon::L2_ploadrif_io },
  { Hexagon::L2_ploadrifnew_pi, Hexagon::L2_ploadrif_pi },
  { Hexagon::L2_ploadritnew_io, Hexagon::L2_ploadrit_io },
  { Hexagon::L2_ploadritnew_pi, Hexagon::L2_ploadrit_pi },
  { Hexagon::L2_ploadrubfnew_io, Hexagon::L2_ploadrubf_io },
  { Hexagon::L2_ploadrubfnew_pi, Hexagon::L2_ploadrubf_pi },
  { Hexagon::L2_ploadrubtnew_io, Hexagon::L2_ploadrubt_io },
  { Hexagon::L2_ploadrubtnew_pi, Hexagon::L2_ploadrubt_pi },
  { Hexagon::L2_ploadruhfnew_io, Hexagon::L2_ploadruhf_io },
  { Hexagon::L2_ploadruhfnew_pi, Hexagon::L2_ploadruhf_pi },
  { Hexagon::L2_ploadruhtnew_io, Hexagon::L2_ploadruht_io },
  { Hexagon::L2_ploadruhtnew_pi, Hexagon::L2_ploadruht_pi },
  { Hexagon::L4_ploadrbfnew_abs, Hexagon::L4_ploadrbf_abs },
  { Hexagon::L4_ploadrbfnew_rr, Hexagon::L4_ploadrbf_rr },
  { Hexagon::L4_ploadrbtnew_abs, Hexagon::L4_ploadrbt_abs },
  { Hexagon::L4_ploadrbtnew_rr, Hexagon::L4_ploadrbt_rr },
  { Hexagon::L4_ploadrdfnew_abs, Hexagon::L4_ploadrdf_abs },
  { Hexagon::L4_ploadrdfnew_rr, Hexagon::L4_ploadrdf_rr },
  { Hexagon::L4_ploadrdtnew_abs, Hexagon::L4_ploadrdt_abs },
  { Hexagon::L4_ploadrdtnew_rr, Hexagon::L4_ploadrdt_rr },
  { Hexagon::L4_ploadrhfnew_abs, Hexagon::L4_ploadrhf_abs },
  { Hexagon::L4_ploadrhfnew_rr, Hexagon::L4_ploadrhf_rr },
  { Hexagon::L4_ploadrhtnew_abs, Hexagon::L4_ploadrht_abs },
  { Hexagon::L4_ploadrhtnew_rr, Hexagon::L4_ploadrht_rr },
  { Hexagon::L4_ploadrifnew_abs, Hexagon::L4_ploadrif_abs },
  { Hexagon::L4_ploadrifnew_rr, Hexagon::L4_ploadrif_rr },
  { Hexagon::L4_ploadritnew_abs, Hexagon::L4_ploadrit_abs },
  { Hexagon::L4_ploadritnew_rr, Hexagon::L4_ploadrit_rr },
  { Hexagon::L4_ploadrubfnew_abs, Hexagon::L4_ploadrubf_abs },
  { Hexagon::L4_ploadrubfnew_rr, Hexagon::L4_ploadrubf_rr },
  { Hexagon::L4_ploadrubtnew_abs, Hexagon::L4_ploadrubt_abs },
  { Hexagon::L4_ploadrubtnew_rr, Hexagon::L4_ploadrubt_rr },
  { Hexagon::L4_ploadruhfnew_abs, Hexagon::L4_ploadruhf_abs },
  { Hexagon::L4_ploadruhfnew_rr, Hexagon::L4_ploadruhf_rr },
  { Hexagon::L4_ploadruhtnew_abs, Hexagon::L4_ploadruht_abs },
  { Hexagon::L4_ploadruhtnew_rr, Hexagon::L4_ploadruht_rr },
  { Hexagon::L4_return_fnew_pnt, Hexagon::L4_return_f },
  { Hexagon::L4_return_fnew_pt, Hexagon::L4_return_f },
  { Hexagon::L4_return_tnew_pnt, Hexagon::L4_return_t },
  { Hexagon::L4_return_tnew_pt, Hexagon::L4_return_t },
  { Hexagon::S2_pstorerbfnew_pi, Hexagon::S2_pstorerbf_pi },
  { Hexagon::S2_pstorerbnewfnew_pi, Hexagon::S2_pstorerbnewf_pi },
  { Hexagon::S2_pstorerbnewtnew_pi, Hexagon::S2_pstorerbnewt_pi },
  { Hexagon::S2_pstorerbtnew_pi, Hexagon::S2_pstorerbt_pi },
  { Hexagon::S2_pstorerdfnew_pi, Hexagon::S2_pstorerdf_pi },
  { Hexagon::S2_pstorerdtnew_pi, Hexagon::S2_pstorerdt_pi },
  { Hexagon::S2_pstorerffnew_pi, Hexagon::S2_pstorerff_pi },
  { Hexagon::S2_pstorerftnew_pi, Hexagon::S2_pstorerft_pi },
  { Hexagon::S2_pstorerhfnew_pi, Hexagon::S2_pstorerhf_pi },
  { Hexagon::S2_pstorerhnewfnew_pi, Hexagon::S2_pstorerhnewf_pi },
  { Hexagon::S2_pstorerhnewtnew_pi, Hexagon::S2_pstorerhnewt_pi },
  { Hexagon::S2_pstorerhtnew_pi, Hexagon::S2_pstorerht_pi },
  { Hexagon::S2_pstorerifnew_pi, Hexagon::S2_pstorerif_pi },
  { Hexagon::S2_pstorerinewfnew_pi, Hexagon::S2_pstorerinewf_pi },
  { Hexagon::S2_pstorerinewtnew_pi, Hexagon::S2_pstorerinewt_pi },
  { Hexagon::S2_pstoreritnew_pi, Hexagon::S2_pstorerit_pi },
  { Hexagon::S4_pstorerbfnew_abs, Hexagon::S4_pstorerbf_abs },
  { Hexagon::S4_pstorerbfnew_io, Hexagon::S2_pstorerbf_io },
  { Hexagon::S4_pstorerbfnew_rr, Hexagon::S4_pstorerbf_rr },
  { Hexagon::S4_pstorerbnewfnew_abs, Hexagon::S4_pstorerbnewf_abs },
  { Hexagon::S4_pstorerbnewfnew_io, Hexagon::S2_pstorerbnewf_io },
  { Hexagon::S4_pstorerbnewfnew_rr, Hexagon::S4_pstorerbnewf_rr },
  { Hexagon::S4_pstorerbnewtnew_abs, Hexagon::S4_pstorerbnewt_abs },
  { Hexagon::S4_pstorerbnewtnew_io, Hexagon::S2_pstorerbnewt_io },
  { Hexagon::S4_pstorerbnewtnew_rr, Hexagon::S4_pstorerbnewt_rr },
  { Hexagon::S4_pstorerbtnew_abs, Hexagon::S4_pstorerbt_abs },
  { Hexagon::S4_pstorerbtnew_io, Hexagon::S2_pstorerbt_io },
  { Hexagon::S4_pstorerbtnew_rr, Hexagon::S4_pstorerbt_rr },
  { Hexagon::S4_pstorerdfnew_abs, Hexagon::S4_pstorerdf_abs },
  { Hexagon::S4_pstorerdfnew_io, Hexagon::S2_pstorerdf_io },
  { Hexagon::S4_pstorerdfnew_rr, Hexagon::S4_pstorerdf_rr },
  { Hexagon::S4_pstorerdtnew_abs, Hexagon::S4_pstorerdt_abs },
  { Hexagon::S4_pstorerdtnew_io, Hexagon::S2_pstorerdt_io },
  { Hexagon::S4_pstorerdtnew_rr, Hexagon::S4_pstorerdt_rr },
  { Hexagon::S4_pstorerffnew_abs, Hexagon::S4_pstorerff_abs },
  { Hexagon::S4_pstorerffnew_io, Hexagon::S2_pstorerff_io },
  { Hexagon::S4_pstorerffnew_rr, Hexagon::S4_pstorerff_rr },
  { Hexagon::S4_pstorerftnew_abs, Hexagon::S4_pstorerft_abs },
  { Hexagon::S4_pstorerftnew_io, Hexagon::S2_pstorerft_io },
  { Hexagon::S4_pstorerftnew_rr, Hexagon::S4_pstorerft_rr },
  { Hexagon::S4_pstorerhfnew_abs, Hexagon::S4_pstorerhf_abs },
  { Hexagon::S4_pstorerhfnew_io, Hexagon::S2_pstorerhf_io },
  { Hexagon::S4_pstorerhfnew_rr, Hexagon::S4_pstorerhf_rr },
  { Hexagon::S4_pstorerhnewfnew_abs, Hexagon::S4_pstorerhnewf_abs },
  { Hexagon::S4_pstorerhnewfnew_io, Hexagon::S2_pstorerhnewf_io },
  { Hexagon::S4_pstorerhnewfnew_rr, Hexagon::S4_pstorerhnewf_rr },
  { Hexagon::S4_pstorerhnewtnew_abs, Hexagon::S4_pstorerhnewt_abs },
  { Hexagon::S4_pstorerhnewtnew_io, Hexagon::S2_pstorerhnewt_io },
  { Hexagon::S4_pstorerhnewtnew_rr, Hexagon::S4_pstorerhnewt_rr },
  { Hexagon::S4_pstorerhtnew_abs, Hexagon::S4_pstorerht_abs },
  { Hexagon::S4_pstorerhtnew_io, Hexagon::S2_pstorerht_io },
  { Hexagon::S4_pstorerhtnew_rr, Hexagon::S4_pstorerht_rr },
  { Hexagon::S4_pstorerifnew_abs, Hexagon::S4_pstorerif_abs },
  { Hexagon::S4_pstorerifnew_io, Hexagon::S2_pstorerif_io },
  { Hexagon::S4_pstorerifnew_rr, Hexagon::S4_pstorerif_rr },
  { Hexagon::S4_pstorerinewfnew_abs, Hexagon::S4_pstorerinewf_abs },
  { Hexagon::S4_pstorerinewfnew_io, Hexagon::S2_pstorerinewf_io },
  { Hexagon::S4_pstorerinewfnew_rr, Hexagon::S4_pstorerinewf_rr },
  { Hexagon::S4_pstorerinewtnew_abs, Hexagon::S4_pstorerinewt_abs },
  { Hexagon::S4_pstorerinewtnew_io, Hexagon::S2_pstorerinewt_io },
  { Hexagon::S4_pstorerinewtnew_rr, Hexagon::S4_pstorerinewt_rr },
  { Hexagon::S4_pstoreritnew_abs, Hexagon::S4_pstorerit_abs },
  { Hexagon::S4_pstoreritnew_io, Hexagon::S2_pstorerit_io },
  { Hexagon::S4_pstoreritnew_rr, Hexagon::S4_pstorerit_rr },
  { Hexagon::S4_storeirbfnew_io, Hexagon::S4_storeirbf_io },
  { Hexagon::S4_storeirbtnew_io, Hexagon::S4_storeirbt_io },
  { Hexagon::S4_storeirhfnew_io, Hexagon::S4_storeirhf_io },
  { Hexagon::S4_storeirhtnew_io, Hexagon::S4_storeirht_io },
  { Hexagon::S4_storeirifnew_io, Hexagon::S4_storeirif_io },
  { Hexagon::S4_storeiritnew_io, Hexagon::S4_storeirit_io },
}; // End of getPredOldOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 166;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getPredOldOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getPredOldOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getPredOldOpcodeTable[mid][1];
}

// getPredOpcode
LLVM_READONLY
int getPredOpcode(uint16_t Opcode, enum PredSense inPredSense) {
static const uint16_t getPredOpcodeTable[][3] = {
  { Hexagon::A2_add, Hexagon::A2_paddt, Hexagon::A2_paddf },
  { Hexagon::A2_addi, Hexagon::A2_paddit, Hexagon::A2_paddif },
  { Hexagon::A2_and, Hexagon::A2_pandt, Hexagon::A2_pandf },
  { Hexagon::A2_aslh, Hexagon::A4_paslht, Hexagon::A4_paslhf },
  { Hexagon::A2_asrh, Hexagon::A4_pasrht, Hexagon::A4_pasrhf },
  { Hexagon::A2_combinew, Hexagon::C2_ccombinewt, Hexagon::C2_ccombinewf },
  { Hexagon::A2_or, Hexagon::A2_port, Hexagon::A2_porf },
  { Hexagon::A2_sub, Hexagon::A2_psubt, Hexagon::A2_psubf },
  { Hexagon::A2_sxtb, Hexagon::A4_psxtbt, Hexagon::A4_psxtbf },
  { Hexagon::A2_sxth, Hexagon::A4_psxtht, Hexagon::A4_psxthf },
  { Hexagon::A2_tfr, Hexagon::A2_tfrt, Hexagon::A2_tfrf },
  { Hexagon::A2_tfrp, Hexagon::A2_tfrpt, Hexagon::A2_tfrpf },
  { Hexagon::A2_tfrsi, Hexagon::C2_cmoveit, Hexagon::C2_cmoveif },
  { Hexagon::A2_xor, Hexagon::A2_pxort, Hexagon::A2_pxorf },
  { Hexagon::A2_zxtb, Hexagon::A4_pzxtbt, Hexagon::A4_pzxtbf },
  { Hexagon::A2_zxth, Hexagon::A4_pzxtht, Hexagon::A4_pzxthf },
  { Hexagon::CALLv3nr, Hexagon::J2_callt, Hexagon::J2_callf },
  { Hexagon::J2_call, Hexagon::J2_callt, Hexagon::J2_callf },
  { Hexagon::J2_jump, Hexagon::J2_jumpt, Hexagon::J2_jumpf },
  { Hexagon::J2_jumpr, Hexagon::J2_jumprt, Hexagon::J2_jumprf },
  { Hexagon::JMPret, Hexagon::JMPrett, Hexagon::JMPretf },
  { Hexagon::L2_loadrb_io, Hexagon::L2_ploadrbt_io, Hexagon::L2_ploadrbf_io },
  { Hexagon::L2_loadrb_pi, Hexagon::L2_ploadrbt_pi, Hexagon::L2_ploadrbf_pi },
  { Hexagon::L2_loadrbgp, Hexagon::L4_ploadrbt_abs, Hexagon::L4_ploadrbf_abs },
  { Hexagon::L2_loadrd_io, Hexagon::L2_ploadrdt_io, Hexagon::L2_ploadrdf_io },
  { Hexagon::L2_loadrd_pi, Hexagon::L2_ploadrdt_pi, Hexagon::L2_ploadrdf_pi },
  { Hexagon::L2_loadrdgp, Hexagon::L4_ploadrdt_abs, Hexagon::L4_ploadrdf_abs },
  { Hexagon::L2_loadrh_io, Hexagon::L2_ploadrht_io, Hexagon::L2_ploadrhf_io },
  { Hexagon::L2_loadrh_pi, Hexagon::L2_ploadrht_pi, Hexagon::L2_ploadrhf_pi },
  { Hexagon::L2_loadrhgp, Hexagon::L4_ploadrht_abs, Hexagon::L4_ploadrhf_abs },
  { Hexagon::L2_loadri_io, Hexagon::L2_ploadrit_io, Hexagon::L2_ploadrif_io },
  { Hexagon::L2_loadri_pi, Hexagon::L2_ploadrit_pi, Hexagon::L2_ploadrif_pi },
  { Hexagon::L2_loadrigp, Hexagon::L4_ploadrit_abs, Hexagon::L4_ploadrif_abs },
  { Hexagon::L2_loadrub_io, Hexagon::L2_ploadrubt_io, Hexagon::L2_ploadrubf_io },
  { Hexagon::L2_loadrub_pi, Hexagon::L2_ploadrubt_pi, Hexagon::L2_ploadrubf_pi },
  { Hexagon::L2_loadrubgp, Hexagon::L4_ploadrubt_abs, Hexagon::L4_ploadrubf_abs },
  { Hexagon::L2_loadruh_io, Hexagon::L2_ploadruht_io, Hexagon::L2_ploadruhf_io },
  { Hexagon::L2_loadruh_pi, Hexagon::L2_ploadruht_pi, Hexagon::L2_ploadruhf_pi },
  { Hexagon::L2_loadruhgp, Hexagon::L4_ploadruht_abs, Hexagon::L4_ploadruhf_abs },
  { Hexagon::L4_loadrb_abs, Hexagon::L4_ploadrbt_abs, Hexagon::L4_ploadrbf_abs },
  { Hexagon::L4_loadrb_rr, Hexagon::L4_ploadrbt_rr, Hexagon::L4_ploadrbf_rr },
  { Hexagon::L4_loadrd_abs, Hexagon::L4_ploadrdt_abs, Hexagon::L4_ploadrdf_abs },
  { Hexagon::L4_loadrd_rr, Hexagon::L4_ploadrdt_rr, Hexagon::L4_ploadrdf_rr },
  { Hexagon::L4_loadrh_abs, Hexagon::L4_ploadrht_abs, Hexagon::L4_ploadrhf_abs },
  { Hexagon::L4_loadrh_rr, Hexagon::L4_ploadrht_rr, Hexagon::L4_ploadrhf_rr },
  { Hexagon::L4_loadri_abs, Hexagon::L4_ploadrit_abs, Hexagon::L4_ploadrif_abs },
  { Hexagon::L4_loadri_rr, Hexagon::L4_ploadrit_rr, Hexagon::L4_ploadrif_rr },
  { Hexagon::L4_loadrub_abs, Hexagon::L4_ploadrubt_abs, Hexagon::L4_ploadrubf_abs },
  { Hexagon::L4_loadrub_rr, Hexagon::L4_ploadrubt_rr, Hexagon::L4_ploadrubf_rr },
  { Hexagon::L4_loadruh_abs, Hexagon::L4_ploadruht_abs, Hexagon::L4_ploadruhf_abs },
  { Hexagon::L4_loadruh_rr, Hexagon::L4_ploadruht_rr, Hexagon::L4_ploadruhf_rr },
  { Hexagon::L4_return, Hexagon::L4_return_t, Hexagon::L4_return_f },
  { Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4, Hexagon::J2_callt, Hexagon::J2_callf },
  { Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT, Hexagon::J2_callt, Hexagon::J2_callf },
  { Hexagon::S2_storerb_io, Hexagon::S2_pstorerbt_io, Hexagon::S2_pstorerbf_io },
  { Hexagon::S2_storerb_pi, Hexagon::S2_pstorerbt_pi, Hexagon::S2_pstorerbf_pi },
  { Hexagon::S2_storerbabs, Hexagon::S4_pstorerbt_abs, Hexagon::S4_pstorerbf_abs },
  { Hexagon::S2_storerbgp, Hexagon::S4_pstorerbt_abs, Hexagon::S4_pstorerbf_abs },
  { Hexagon::S2_storerbnew_io, Hexagon::S2_pstorerbnewt_io, Hexagon::S2_pstorerbnewf_io },
  { Hexagon::S2_storerbnew_pi, Hexagon::S2_pstorerbnewt_pi, Hexagon::S2_pstorerbnewf_pi },
  { Hexagon::S2_storerbnewabs, Hexagon::S4_pstorerbnewt_abs, Hexagon::S4_pstorerbnewf_abs },
  { Hexagon::S2_storerbnewgp, Hexagon::S4_pstorerbnewt_abs, Hexagon::S4_pstorerbnewf_abs },
  { Hexagon::S2_storerd_io, Hexagon::S2_pstorerdt_io, Hexagon::S2_pstorerdf_io },
  { Hexagon::S2_storerd_pi, Hexagon::S2_pstorerdt_pi, Hexagon::S2_pstorerdf_pi },
  { Hexagon::S2_storerdabs, Hexagon::S4_pstorerdt_abs, Hexagon::S4_pstorerdf_abs },
  { Hexagon::S2_storerdgp, Hexagon::S4_pstorerdt_abs, Hexagon::S4_pstorerdf_abs },
  { Hexagon::S2_storerf_io, Hexagon::S2_pstorerft_io, Hexagon::S2_pstorerff_io },
  { Hexagon::S2_storerf_pi, Hexagon::S2_pstorerft_pi, Hexagon::S2_pstorerff_pi },
  { Hexagon::S2_storerfabs, Hexagon::S4_pstorerft_abs, Hexagon::S4_pstorerff_abs },
  { Hexagon::S2_storerfgp, Hexagon::S4_pstorerft_abs, Hexagon::S4_pstorerff_abs },
  { Hexagon::S2_storerh_io, Hexagon::S2_pstorerht_io, Hexagon::S2_pstorerhf_io },
  { Hexagon::S2_storerh_pi, Hexagon::S2_pstorerht_pi, Hexagon::S2_pstorerhf_pi },
  { Hexagon::S2_storerhabs, Hexagon::S4_pstorerht_abs, Hexagon::S4_pstorerhf_abs },
  { Hexagon::S2_storerhgp, Hexagon::S4_pstorerht_abs, Hexagon::S4_pstorerhf_abs },
  { Hexagon::S2_storerhnew_io, Hexagon::S2_pstorerhnewt_io, Hexagon::S2_pstorerhnewf_io },
  { Hexagon::S2_storerhnew_pi, Hexagon::S2_pstorerhnewt_pi, Hexagon::S2_pstorerhnewf_pi },
  { Hexagon::S2_storerhnewabs, Hexagon::S4_pstorerhnewt_abs, Hexagon::S4_pstorerhnewf_abs },
  { Hexagon::S2_storerhnewgp, Hexagon::S4_pstorerhnewt_abs, Hexagon::S4_pstorerhnewf_abs },
  { Hexagon::S2_storeri_io, Hexagon::S2_pstorerit_io, Hexagon::S2_pstorerif_io },
  { Hexagon::S2_storeri_pi, Hexagon::S2_pstorerit_pi, Hexagon::S2_pstorerif_pi },
  { Hexagon::S2_storeriabs, Hexagon::S4_pstorerit_abs, Hexagon::S4_pstorerif_abs },
  { Hexagon::S2_storerigp, Hexagon::S4_pstorerit_abs, Hexagon::S4_pstorerif_abs },
  { Hexagon::S2_storerinew_io, Hexagon::S2_pstorerinewt_io, Hexagon::S2_pstorerinewf_io },
  { Hexagon::S2_storerinew_pi, Hexagon::S2_pstorerinewt_pi, Hexagon::S2_pstorerinewf_pi },
  { Hexagon::S2_storerinewabs, Hexagon::S4_pstorerinewt_abs, Hexagon::S4_pstorerinewf_abs },
  { Hexagon::S2_storerinewgp, Hexagon::S4_pstorerinewt_abs, Hexagon::S4_pstorerinewf_abs },
  { Hexagon::S4_storeirb_io, Hexagon::S4_storeirbt_io, Hexagon::S4_storeirbf_io },
  { Hexagon::S4_storeirh_io, Hexagon::S4_storeirht_io, Hexagon::S4_storeirhf_io },
  { Hexagon::S4_storeiri_io, Hexagon::S4_storeirit_io, Hexagon::S4_storeirif_io },
  { Hexagon::S4_storerb_rr, Hexagon::S4_pstorerbt_rr, Hexagon::S4_pstorerbf_rr },
  { Hexagon::S4_storerbnew_rr, Hexagon::S4_pstorerbnewt_rr, Hexagon::S4_pstorerbnewf_rr },
  { Hexagon::S4_storerd_rr, Hexagon::S4_pstorerdt_rr, Hexagon::S4_pstorerdf_rr },
  { Hexagon::S4_storerf_rr, Hexagon::S4_pstorerft_rr, Hexagon::S4_pstorerff_rr },
  { Hexagon::S4_storerh_rr, Hexagon::S4_pstorerht_rr, Hexagon::S4_pstorerhf_rr },
  { Hexagon::S4_storerhnew_rr, Hexagon::S4_pstorerhnewt_rr, Hexagon::S4_pstorerhnewf_rr },
  { Hexagon::S4_storeri_rr, Hexagon::S4_pstorerit_rr, Hexagon::S4_pstorerif_rr },
  { Hexagon::S4_storerinew_rr, Hexagon::S4_pstorerinewt_rr, Hexagon::S4_pstorerinewf_rr },
  { Hexagon::SAVE_REGISTERS_CALL_V4, Hexagon::J2_callt, Hexagon::J2_callf },
  { Hexagon::SAVE_REGISTERS_CALL_V4_EXT, Hexagon::J2_callt, Hexagon::J2_callf },
  { Hexagon::V6_vS32Ub_ppu, Hexagon::V6_vS32Ub_pred_ppu, Hexagon::V6_vS32Ub_npred_ppu },
  { Hexagon::V6_vS32b_ai, Hexagon::V6_vS32b_pred_ai, Hexagon::V6_vS32b_npred_ai },
  { Hexagon::V6_vS32b_ai_128B, Hexagon::V6_vS32b_pred_ai_128B, Hexagon::V6_vS32b_npred_ai_128B },
  { Hexagon::V6_vS32b_new_ai, Hexagon::V6_vS32b_new_pred_ai, Hexagon::V6_vS32b_new_npred_ai },
  { Hexagon::V6_vS32b_new_ai_128B, Hexagon::V6_vS32b_new_pred_ai_128B, Hexagon::V6_vS32b_new_npred_ai_128B },
  { Hexagon::V6_vS32b_new_pi, Hexagon::V6_vS32b_new_pred_pi, Hexagon::V6_vS32b_new_npred_pi },
  { Hexagon::V6_vS32b_new_pi_128B, Hexagon::V6_vS32b_new_pred_pi_128B, Hexagon::V6_vS32b_new_npred_pi_128B },
  { Hexagon::V6_vS32b_new_ppu, Hexagon::V6_vS32b_new_pred_ppu, Hexagon::V6_vS32b_new_npred_ppu },
  { Hexagon::V6_vS32b_nt_ai, Hexagon::V6_vS32b_nt_pred_ai, Hexagon::V6_vS32b_nt_npred_ai },
  { Hexagon::V6_vS32b_nt_ai_128B, Hexagon::V6_vS32b_nt_pred_ai_128B, Hexagon::V6_vS32b_nt_npred_ai_128B },
  { Hexagon::V6_vS32b_nt_new_ai, Hexagon::V6_vS32b_nt_new_pred_ai, Hexagon::V6_vS32b_nt_new_npred_ai },
  { Hexagon::V6_vS32b_nt_new_ai_128B, Hexagon::V6_vS32b_nt_new_pred_ai_128B, Hexagon::V6_vS32b_nt_new_npred_ai_128B },
  { Hexagon::V6_vS32b_nt_new_pi, Hexagon::V6_vS32b_nt_new_pred_pi, Hexagon::V6_vS32b_nt_new_npred_pi },
  { Hexagon::V6_vS32b_nt_new_pi_128B, Hexagon::V6_vS32b_nt_new_pred_pi_128B, Hexagon::V6_vS32b_nt_new_npred_pi_128B },
  { Hexagon::V6_vS32b_nt_new_ppu, Hexagon::V6_vS32b_nt_new_pred_ppu, Hexagon::V6_vS32b_nt_new_npred_ppu },
  { Hexagon::V6_vS32b_nt_ppu, Hexagon::V6_vS32b_nt_pred_ppu, Hexagon::V6_vS32b_nt_npred_ppu },
  { Hexagon::V6_vS32b_ppu, Hexagon::V6_vS32b_pred_ppu, Hexagon::V6_vS32b_npred_ppu },
}; // End of getPredOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 116;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getPredOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getPredOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  if (inPredSense == PredSense_true)
    return getPredOpcodeTable[mid][1];
  if (inPredSense == PredSense_false)
    return getPredOpcodeTable[mid][2];
  return -1;}

// getRealHWInstr
LLVM_READONLY
int getRealHWInstr(uint16_t Opcode, enum InstrType inInstrType) {
static const uint16_t getRealHWInstrTable[][3] = {
  { Hexagon::INSTRUCTION_LIST_END, Hexagon::INSTRUCTION_LIST_END }}; // End of getRealHWInstrTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 0;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getRealHWInstrTable[mid][0]) {
      break;
    }
    if (Opcode < getRealHWInstrTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  if (inInstrType == InstrType_Pseudo)
    return getRealHWInstrTable[mid][1];
  if (inInstrType == InstrType_Real)
    return getRealHWInstrTable[mid][2];
  return -1;}

// getRegForm
LLVM_READONLY
int getRegForm(uint16_t Opcode) {
static const uint16_t getRegFormTable[][2] = {
  { Hexagon::A2_addi, Hexagon::A2_add },
  { Hexagon::A2_andir, Hexagon::A2_and },
  { Hexagon::A2_orir, Hexagon::A2_or },
  { Hexagon::A2_subri, Hexagon::A2_sub },
  { Hexagon::A2_tfrsi, Hexagon::A2_tfr },
  { Hexagon::A4_cmpbeqi, Hexagon::A4_cmpbeq },
  { Hexagon::A4_cmpbgti, Hexagon::A4_cmpbgt },
  { Hexagon::A4_cmpbgtui, Hexagon::A4_cmpbgtu },
  { Hexagon::A4_cmpheqi, Hexagon::A4_cmpheq },
  { Hexagon::A4_cmphgti, Hexagon::A4_cmphgt },
  { Hexagon::A4_cmphgtui, Hexagon::A4_cmphgtu },
  { Hexagon::A4_rcmpeqi, Hexagon::A4_rcmpeq },
  { Hexagon::A4_rcmpneqi, Hexagon::A4_rcmpneq },
  { Hexagon::C2_cmoveif, Hexagon::A2_tfrf },
  { Hexagon::C2_cmoveit, Hexagon::A2_tfrt },
  { Hexagon::C2_cmovenewif, Hexagon::A2_tfrfnew },
  { Hexagon::C2_cmovenewit, Hexagon::A2_tfrtnew },
  { Hexagon::C2_cmpeqi, Hexagon::C2_cmpeq },
  { Hexagon::C2_cmpgti, Hexagon::C2_cmpgt },
  { Hexagon::C2_cmpgtui, Hexagon::C2_cmpgtu },
  { Hexagon::C4_cmpltei, Hexagon::C2_cmpgt },
  { Hexagon::C4_cmplteui, Hexagon::C2_cmpgtu },
  { Hexagon::C4_cmpneqi, Hexagon::C2_cmpeq },
  { Hexagon::M2_accii, Hexagon::M2_acci },
  { Hexagon::M2_macsip, Hexagon::M2_maci },
  { Hexagon::M2_mpysmi, Hexagon::M2_mpyi },
  { Hexagon::M2_naccii, Hexagon::M2_nacci },
  { Hexagon::M4_mpyri_addr, Hexagon::M4_mpyrr_addr },
  { Hexagon::M4_mpyrr_addi, Hexagon::M4_mpyrr_addr },
}; // End of getRegFormTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 29;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getRegFormTable[mid][0]) {
      break;
    }
    if (Opcode < getRegFormTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getRegFormTable[mid][1];
}

// getRegShlForm
LLVM_READONLY
int getRegShlForm(uint16_t Opcode) {
static const uint16_t getRegShlFormTable[][2] = {
  { Hexagon::L4_loadrb_ur, Hexagon::L4_loadrb_rr },
  { Hexagon::L4_loadrd_ur, Hexagon::L4_loadrd_rr },
  { Hexagon::L4_loadrh_ur, Hexagon::L4_loadrh_rr },
  { Hexagon::L4_loadri_ur, Hexagon::L4_loadri_rr },
  { Hexagon::L4_loadrub_ur, Hexagon::L4_loadrub_rr },
  { Hexagon::L4_loadruh_ur, Hexagon::L4_loadruh_rr },
  { Hexagon::S4_storerb_ur, Hexagon::S4_storerb_rr },
  { Hexagon::S4_storerd_ur, Hexagon::S4_storerd_rr },
  { Hexagon::S4_storerf_ur, Hexagon::S4_storerf_rr },
  { Hexagon::S4_storerh_ur, Hexagon::S4_storerh_rr },
  { Hexagon::S4_storeri_ur, Hexagon::S4_storeri_rr },
}; // End of getRegShlFormTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 11;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getRegShlFormTable[mid][0]) {
      break;
    }
    if (Opcode < getRegShlFormTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getRegShlFormTable[mid][1];
}

// getTruePredOpcode
LLVM_READONLY
int getTruePredOpcode(uint16_t Opcode) {
static const uint16_t getTruePredOpcodeTable[][2] = {
  { Hexagon::A2_paddf, Hexagon::A2_paddt },
  { Hexagon::A2_paddfnew, Hexagon::A2_paddtnew },
  { Hexagon::A2_paddif, Hexagon::A2_paddit },
  { Hexagon::A2_paddifnew, Hexagon::A2_padditnew },
  { Hexagon::A2_pandf, Hexagon::A2_pandt },
  { Hexagon::A2_pandfnew, Hexagon::A2_pandtnew },
  { Hexagon::A2_porf, Hexagon::A2_port },
  { Hexagon::A2_porfnew, Hexagon::A2_portnew },
  { Hexagon::A2_psubf, Hexagon::A2_psubt },
  { Hexagon::A2_psubfnew, Hexagon::A2_psubtnew },
  { Hexagon::A2_pxorf, Hexagon::A2_pxort },
  { Hexagon::A2_pxorfnew, Hexagon::A2_pxortnew },
  { Hexagon::A2_tfrf, Hexagon::A2_tfrt },
  { Hexagon::A2_tfrfnew, Hexagon::A2_tfrtnew },
  { Hexagon::A2_tfrpf, Hexagon::A2_tfrpt },
  { Hexagon::A2_tfrpfnew, Hexagon::A2_tfrptnew },
  { Hexagon::A4_paslhf, Hexagon::A4_paslht },
  { Hexagon::A4_paslhfnew, Hexagon::A4_paslhtnew },
  { Hexagon::A4_pasrhf, Hexagon::A4_pasrht },
  { Hexagon::A4_pasrhfnew, Hexagon::A4_pasrhtnew },
  { Hexagon::A4_psxtbf, Hexagon::A4_psxtbt },
  { Hexagon::A4_psxtbfnew, Hexagon::A4_psxtbtnew },
  { Hexagon::A4_psxthf, Hexagon::A4_psxtht },
  { Hexagon::A4_psxthfnew, Hexagon::A4_psxthtnew },
  { Hexagon::A4_pzxtbf, Hexagon::A4_pzxtbt },
  { Hexagon::A4_pzxtbfnew, Hexagon::A4_pzxtbtnew },
  { Hexagon::A4_pzxthf, Hexagon::A4_pzxtht },
  { Hexagon::A4_pzxthfnew, Hexagon::A4_pzxthtnew },
  { Hexagon::C2_ccombinewf, Hexagon::C2_ccombinewt },
  { Hexagon::C2_ccombinewnewf, Hexagon::C2_ccombinewnewt },
  { Hexagon::C2_cmoveif, Hexagon::C2_cmoveit },
  { Hexagon::C2_cmovenewif, Hexagon::C2_cmovenewit },
  { Hexagon::J2_callf, Hexagon::J2_callt },
  { Hexagon::J2_jumpf, Hexagon::J2_jumpt },
  { Hexagon::J2_jumpfnew, Hexagon::J2_jumptnew },
  { Hexagon::J2_jumpfnewpt, Hexagon::J2_jumptnewpt },
  { Hexagon::J2_jumprf, Hexagon::J2_jumprt },
  { Hexagon::J2_jumprfnew, Hexagon::J2_jumprtnew },
  { Hexagon::J2_jumprfnewpt, Hexagon::J2_jumprtnewpt },
  { Hexagon::J4_cmpeq_f_jumpnv_nt, Hexagon::J4_cmpeq_t_jumpnv_nt },
  { Hexagon::J4_cmpeq_f_jumpnv_t, Hexagon::J4_cmpeq_t_jumpnv_t },
  { Hexagon::J4_cmpeqi_f_jumpnv_nt, Hexagon::J4_cmpeqi_t_jumpnv_nt },
  { Hexagon::J4_cmpeqi_f_jumpnv_t, Hexagon::J4_cmpeqi_t_jumpnv_t },
  { Hexagon::J4_cmpeqn1_f_jumpnv_nt, Hexagon::J4_cmpeqn1_t_jumpnv_nt },
  { Hexagon::J4_cmpeqn1_f_jumpnv_t, Hexagon::J4_cmpeqn1_t_jumpnv_t },
  { Hexagon::J4_cmpgt_f_jumpnv_nt, Hexagon::J4_cmpgt_t_jumpnv_nt },
  { Hexagon::J4_cmpgt_f_jumpnv_t, Hexagon::J4_cmpgt_t_jumpnv_t },
  { Hexagon::J4_cmpgti_f_jumpnv_nt, Hexagon::J4_cmpgti_t_jumpnv_nt },
  { Hexagon::J4_cmpgti_f_jumpnv_t, Hexagon::J4_cmpgti_t_jumpnv_t },
  { Hexagon::J4_cmpgtn1_f_jumpnv_nt, Hexagon::J4_cmpgtn1_t_jumpnv_nt },
  { Hexagon::J4_cmpgtn1_f_jumpnv_t, Hexagon::J4_cmpgtn1_t_jumpnv_t },
  { Hexagon::J4_cmpgtu_f_jumpnv_nt, Hexagon::J4_cmpgtu_t_jumpnv_nt },
  { Hexagon::J4_cmpgtu_f_jumpnv_t, Hexagon::J4_cmpgtu_t_jumpnv_t },
  { Hexagon::J4_cmpgtui_f_jumpnv_nt, Hexagon::J4_cmpgtui_t_jumpnv_nt },
  { Hexagon::J4_cmpgtui_f_jumpnv_t, Hexagon::J4_cmpgtui_t_jumpnv_t },
  { Hexagon::J4_cmplt_f_jumpnv_nt, Hexagon::J4_cmplt_t_jumpnv_nt },
  { Hexagon::J4_cmplt_f_jumpnv_t, Hexagon::J4_cmplt_t_jumpnv_t },
  { Hexagon::J4_cmpltu_f_jumpnv_nt, Hexagon::J4_cmpltu_t_jumpnv_nt },
  { Hexagon::J4_cmpltu_f_jumpnv_t, Hexagon::J4_cmpltu_t_jumpnv_t },
  { Hexagon::J4_tstbit0_f_jumpnv_nt, Hexagon::J4_tstbit0_t_jumpnv_nt },
  { Hexagon::J4_tstbit0_f_jumpnv_t, Hexagon::J4_tstbit0_t_jumpnv_t },
  { Hexagon::JMPretf, Hexagon::JMPrett },
  { Hexagon::JMPretfnew, Hexagon::JMPrettnew },
  { Hexagon::JMPretfnewpt, Hexagon::JMPrettnewpt },
  { Hexagon::L2_ploadrbf_io, Hexagon::L2_ploadrbt_io },
  { Hexagon::L2_ploadrbf_pi, Hexagon::L2_ploadrbt_pi },
  { Hexagon::L2_ploadrbfnew_io, Hexagon::L2_ploadrbtnew_io },
  { Hexagon::L2_ploadrbfnew_pi, Hexagon::L2_ploadrbtnew_pi },
  { Hexagon::L2_ploadrdf_io, Hexagon::L2_ploadrdt_io },
  { Hexagon::L2_ploadrdf_pi, Hexagon::L2_ploadrdt_pi },
  { Hexagon::L2_ploadrdfnew_io, Hexagon::L2_ploadrdtnew_io },
  { Hexagon::L2_ploadrdfnew_pi, Hexagon::L2_ploadrdtnew_pi },
  { Hexagon::L2_ploadrhf_io, Hexagon::L2_ploadrht_io },
  { Hexagon::L2_ploadrhf_pi, Hexagon::L2_ploadrht_pi },
  { Hexagon::L2_ploadrhfnew_io, Hexagon::L2_ploadrhtnew_io },
  { Hexagon::L2_ploadrhfnew_pi, Hexagon::L2_ploadrhtnew_pi },
  { Hexagon::L2_ploadrif_io, Hexagon::L2_ploadrit_io },
  { Hexagon::L2_ploadrif_pi, Hexagon::L2_ploadrit_pi },
  { Hexagon::L2_ploadrifnew_io, Hexagon::L2_ploadritnew_io },
  { Hexagon::L2_ploadrifnew_pi, Hexagon::L2_ploadritnew_pi },
  { Hexagon::L2_ploadrubf_io, Hexagon::L2_ploadrubt_io },
  { Hexagon::L2_ploadrubf_pi, Hexagon::L2_ploadrubt_pi },
  { Hexagon::L2_ploadrubfnew_io, Hexagon::L2_ploadrubtnew_io },
  { Hexagon::L2_ploadrubfnew_pi, Hexagon::L2_ploadrubtnew_pi },
  { Hexagon::L2_ploadruhf_io, Hexagon::L2_ploadruht_io },
  { Hexagon::L2_ploadruhf_pi, Hexagon::L2_ploadruht_pi },
  { Hexagon::L2_ploadruhfnew_io, Hexagon::L2_ploadruhtnew_io },
  { Hexagon::L2_ploadruhfnew_pi, Hexagon::L2_ploadruhtnew_pi },
  { Hexagon::L4_ploadrbf_abs, Hexagon::L4_ploadrbt_abs },
  { Hexagon::L4_ploadrbf_rr, Hexagon::L4_ploadrbt_rr },
  { Hexagon::L4_ploadrbfnew_abs, Hexagon::L4_ploadrbtnew_abs },
  { Hexagon::L4_ploadrbfnew_rr, Hexagon::L4_ploadrbtnew_rr },
  { Hexagon::L4_ploadrdf_abs, Hexagon::L4_ploadrdt_abs },
  { Hexagon::L4_ploadrdf_rr, Hexagon::L4_ploadrdt_rr },
  { Hexagon::L4_ploadrdfnew_abs, Hexagon::L4_ploadrdtnew_abs },
  { Hexagon::L4_ploadrdfnew_rr, Hexagon::L4_ploadrdtnew_rr },
  { Hexagon::L4_ploadrhf_abs, Hexagon::L4_ploadrht_abs },
  { Hexagon::L4_ploadrhf_rr, Hexagon::L4_ploadrht_rr },
  { Hexagon::L4_ploadrhfnew_abs, Hexagon::L4_ploadrhtnew_abs },
  { Hexagon::L4_ploadrhfnew_rr, Hexagon::L4_ploadrhtnew_rr },
  { Hexagon::L4_ploadrif_abs, Hexagon::L4_ploadrit_abs },
  { Hexagon::L4_ploadrif_rr, Hexagon::L4_ploadrit_rr },
  { Hexagon::L4_ploadrifnew_abs, Hexagon::L4_ploadritnew_abs },
  { Hexagon::L4_ploadrifnew_rr, Hexagon::L4_ploadritnew_rr },
  { Hexagon::L4_ploadrubf_abs, Hexagon::L4_ploadrubt_abs },
  { Hexagon::L4_ploadrubf_rr, Hexagon::L4_ploadrubt_rr },
  { Hexagon::L4_ploadrubfnew_abs, Hexagon::L4_ploadrubtnew_abs },
  { Hexagon::L4_ploadrubfnew_rr, Hexagon::L4_ploadrubtnew_rr },
  { Hexagon::L4_ploadruhf_abs, Hexagon::L4_ploadruht_abs },
  { Hexagon::L4_ploadruhf_rr, Hexagon::L4_ploadruht_rr },
  { Hexagon::L4_ploadruhfnew_abs, Hexagon::L4_ploadruhtnew_abs },
  { Hexagon::L4_ploadruhfnew_rr, Hexagon::L4_ploadruhtnew_rr },
  { Hexagon::L4_return_f, Hexagon::L4_return_t },
  { Hexagon::L4_return_fnew_pnt, Hexagon::L4_return_tnew_pnt },
  { Hexagon::L4_return_fnew_pt, Hexagon::L4_return_tnew_pt },
  { Hexagon::S2_pstorerbf_io, Hexagon::S2_pstorerbt_io },
  { Hexagon::S2_pstorerbf_pi, Hexagon::S2_pstorerbt_pi },
  { Hexagon::S2_pstorerbfnew_pi, Hexagon::S2_pstorerbtnew_pi },
  { Hexagon::S2_pstorerbnewf_io, Hexagon::S2_pstorerbnewt_io },
  { Hexagon::S2_pstorerbnewf_pi, Hexagon::S2_pstorerbnewt_pi },
  { Hexagon::S2_pstorerbnewfnew_pi, Hexagon::S2_pstorerbnewtnew_pi },
  { Hexagon::S2_pstorerdf_io, Hexagon::S2_pstorerdt_io },
  { Hexagon::S2_pstorerdf_pi, Hexagon::S2_pstorerdt_pi },
  { Hexagon::S2_pstorerdfnew_pi, Hexagon::S2_pstorerdtnew_pi },
  { Hexagon::S2_pstorerff_io, Hexagon::S2_pstorerft_io },
  { Hexagon::S2_pstorerff_pi, Hexagon::S2_pstorerft_pi },
  { Hexagon::S2_pstorerffnew_pi, Hexagon::S2_pstorerftnew_pi },
  { Hexagon::S2_pstorerhf_io, Hexagon::S2_pstorerht_io },
  { Hexagon::S2_pstorerhf_pi, Hexagon::S2_pstorerht_pi },
  { Hexagon::S2_pstorerhfnew_pi, Hexagon::S2_pstorerhtnew_pi },
  { Hexagon::S2_pstorerhnewf_io, Hexagon::S2_pstorerhnewt_io },
  { Hexagon::S2_pstorerhnewf_pi, Hexagon::S2_pstorerhnewt_pi },
  { Hexagon::S2_pstorerhnewfnew_pi, Hexagon::S2_pstorerhnewtnew_pi },
  { Hexagon::S2_pstorerif_io, Hexagon::S2_pstorerit_io },
  { Hexagon::S2_pstorerif_pi, Hexagon::S2_pstorerit_pi },
  { Hexagon::S2_pstorerifnew_pi, Hexagon::S2_pstoreritnew_pi },
  { Hexagon::S2_pstorerinewf_io, Hexagon::S2_pstorerinewt_io },
  { Hexagon::S2_pstorerinewf_pi, Hexagon::S2_pstorerinewt_pi },
  { Hexagon::S2_pstorerinewfnew_pi, Hexagon::S2_pstorerinewtnew_pi },
  { Hexagon::S4_pstorerbf_abs, Hexagon::S4_pstorerbt_abs },
  { Hexagon::S4_pstorerbf_rr, Hexagon::S4_pstorerbt_rr },
  { Hexagon::S4_pstorerbfnew_abs, Hexagon::S4_pstorerbtnew_abs },
  { Hexagon::S4_pstorerbfnew_io, Hexagon::S4_pstorerbtnew_io },
  { Hexagon::S4_pstorerbfnew_rr, Hexagon::S4_pstorerbtnew_rr },
  { Hexagon::S4_pstorerbnewf_abs, Hexagon::S4_pstorerbnewt_abs },
  { Hexagon::S4_pstorerbnewf_rr, Hexagon::S4_pstorerbnewt_rr },
  { Hexagon::S4_pstorerbnewfnew_abs, Hexagon::S4_pstorerbnewtnew_abs },
  { Hexagon::S4_pstorerbnewfnew_io, Hexagon::S4_pstorerbnewtnew_io },
  { Hexagon::S4_pstorerbnewfnew_rr, Hexagon::S4_pstorerbnewtnew_rr },
  { Hexagon::S4_pstorerdf_abs, Hexagon::S4_pstorerdt_abs },
  { Hexagon::S4_pstorerdf_rr, Hexagon::S4_pstorerdt_rr },
  { Hexagon::S4_pstorerdfnew_abs, Hexagon::S4_pstorerdtnew_abs },
  { Hexagon::S4_pstorerdfnew_io, Hexagon::S4_pstorerdtnew_io },
  { Hexagon::S4_pstorerdfnew_rr, Hexagon::S4_pstorerdtnew_rr },
  { Hexagon::S4_pstorerff_abs, Hexagon::S4_pstorerft_abs },
  { Hexagon::S4_pstorerff_rr, Hexagon::S4_pstorerft_rr },
  { Hexagon::S4_pstorerffnew_abs, Hexagon::S4_pstorerftnew_abs },
  { Hexagon::S4_pstorerffnew_io, Hexagon::S4_pstorerftnew_io },
  { Hexagon::S4_pstorerffnew_rr, Hexagon::S4_pstorerftnew_rr },
  { Hexagon::S4_pstorerhf_abs, Hexagon::S4_pstorerht_abs },
  { Hexagon::S4_pstorerhf_rr, Hexagon::S4_pstorerht_rr },
  { Hexagon::S4_pstorerhfnew_abs, Hexagon::S4_pstorerhtnew_abs },
  { Hexagon::S4_pstorerhfnew_io, Hexagon::S4_pstorerhtnew_io },
  { Hexagon::S4_pstorerhfnew_rr, Hexagon::S4_pstorerhtnew_rr },
  { Hexagon::S4_pstorerhnewf_abs, Hexagon::S4_pstorerhnewt_abs },
  { Hexagon::S4_pstorerhnewf_rr, Hexagon::S4_pstorerhnewt_rr },
  { Hexagon::S4_pstorerhnewfnew_abs, Hexagon::S4_pstorerhnewtnew_abs },
  { Hexagon::S4_pstorerhnewfnew_io, Hexagon::S4_pstorerhnewtnew_io },
  { Hexagon::S4_pstorerhnewfnew_rr, Hexagon::S4_pstorerhnewtnew_rr },
  { Hexagon::S4_pstorerif_abs, Hexagon::S4_pstorerit_abs },
  { Hexagon::S4_pstorerif_rr, Hexagon::S4_pstorerit_rr },
  { Hexagon::S4_pstorerifnew_abs, Hexagon::S4_pstoreritnew_abs },
  { Hexagon::S4_pstorerifnew_io, Hexagon::S4_pstoreritnew_io },
  { Hexagon::S4_pstorerifnew_rr, Hexagon::S4_pstoreritnew_rr },
  { Hexagon::S4_pstorerinewf_abs, Hexagon::S4_pstorerinewt_abs },
  { Hexagon::S4_pstorerinewf_rr, Hexagon::S4_pstorerinewt_rr },
  { Hexagon::S4_pstorerinewfnew_abs, Hexagon::S4_pstorerinewtnew_abs },
  { Hexagon::S4_pstorerinewfnew_io, Hexagon::S4_pstorerinewtnew_io },
  { Hexagon::S4_pstorerinewfnew_rr, Hexagon::S4_pstorerinewtnew_rr },
  { Hexagon::S4_storeirbf_io, Hexagon::S4_storeirbt_io },
  { Hexagon::S4_storeirbfnew_io, Hexagon::S4_storeirbtnew_io },
  { Hexagon::S4_storeirhf_io, Hexagon::S4_storeirht_io },
  { Hexagon::S4_storeirhfnew_io, Hexagon::S4_storeirhtnew_io },
  { Hexagon::S4_storeirif_io, Hexagon::S4_storeirit_io },
  { Hexagon::S4_storeirifnew_io, Hexagon::S4_storeiritnew_io },
  { Hexagon::V6_vS32Ub_npred_ai, Hexagon::V6_vS32Ub_pred_ai },
  { Hexagon::V6_vS32Ub_npred_ai_128B, Hexagon::V6_vS32Ub_pred_ai_128B },
  { Hexagon::V6_vS32Ub_npred_pi, Hexagon::V6_vS32Ub_pred_pi },
  { Hexagon::V6_vS32Ub_npred_pi_128B, Hexagon::V6_vS32Ub_pred_pi_128B },
  { Hexagon::V6_vS32Ub_npred_ppu, Hexagon::V6_vS32Ub_pred_ppu },
  { Hexagon::V6_vS32b_new_npred_ai, Hexagon::V6_vS32b_new_pred_ai },
  { Hexagon::V6_vS32b_new_npred_ai_128B, Hexagon::V6_vS32b_new_pred_ai_128B },
  { Hexagon::V6_vS32b_new_npred_pi, Hexagon::V6_vS32b_new_pred_pi },
  { Hexagon::V6_vS32b_new_npred_pi_128B, Hexagon::V6_vS32b_new_pred_pi_128B },
  { Hexagon::V6_vS32b_new_npred_ppu, Hexagon::V6_vS32b_new_pred_ppu },
  { Hexagon::V6_vS32b_npred_ai, Hexagon::V6_vS32b_pred_ai },
  { Hexagon::V6_vS32b_npred_ai_128B, Hexagon::V6_vS32b_pred_ai_128B },
  { Hexagon::V6_vS32b_npred_pi, Hexagon::V6_vS32b_pred_pi },
  { Hexagon::V6_vS32b_npred_pi_128B, Hexagon::V6_vS32b_pred_pi_128B },
  { Hexagon::V6_vS32b_npred_ppu, Hexagon::V6_vS32b_pred_ppu },
  { Hexagon::V6_vS32b_nt_new_npred_ai, Hexagon::V6_vS32b_nt_new_pred_ai },
  { Hexagon::V6_vS32b_nt_new_npred_ai_128B, Hexagon::V6_vS32b_nt_new_pred_ai_128B },
  { Hexagon::V6_vS32b_nt_new_npred_pi, Hexagon::V6_vS32b_nt_new_pred_pi },
  { Hexagon::V6_vS32b_nt_new_npred_pi_128B, Hexagon::V6_vS32b_nt_new_pred_pi_128B },
  { Hexagon::V6_vS32b_nt_new_npred_ppu, Hexagon::V6_vS32b_nt_new_pred_ppu },
  { Hexagon::V6_vS32b_nt_npred_ai, Hexagon::V6_vS32b_nt_pred_ai },
  { Hexagon::V6_vS32b_nt_npred_ai_128B, Hexagon::V6_vS32b_nt_pred_ai_128B },
  { Hexagon::V6_vS32b_nt_npred_pi, Hexagon::V6_vS32b_nt_pred_pi },
  { Hexagon::V6_vS32b_nt_npred_pi_128B, Hexagon::V6_vS32b_nt_pred_pi_128B },
  { Hexagon::V6_vS32b_nt_npred_ppu, Hexagon::V6_vS32b_nt_pred_ppu },
}; // End of getTruePredOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 210;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == getTruePredOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getTruePredOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getTruePredOpcodeTable[mid][1];
}

// notTakenBranchPrediction
LLVM_READONLY
int notTakenBranchPrediction(uint16_t Opcode) {
static const uint16_t notTakenBranchPredictionTable[][2] = {
  { Hexagon::J2_jumpfnewpt, Hexagon::J2_jumpfnew },
  { Hexagon::J2_jumprfnewpt, Hexagon::J2_jumprfnew },
  { Hexagon::J2_jumprtnewpt, Hexagon::J2_jumprtnew },
  { Hexagon::J2_jumptnewpt, Hexagon::J2_jumptnew },
  { Hexagon::J4_cmpeq_f_jumpnv_t, Hexagon::J4_cmpeq_f_jumpnv_nt },
  { Hexagon::J4_cmpeq_t_jumpnv_t, Hexagon::J4_cmpeq_t_jumpnv_nt },
  { Hexagon::J4_cmpeqi_f_jumpnv_t, Hexagon::J4_cmpeqi_f_jumpnv_nt },
  { Hexagon::J4_cmpeqi_t_jumpnv_t, Hexagon::J4_cmpeqi_t_jumpnv_nt },
  { Hexagon::J4_cmpeqn1_f_jumpnv_t, Hexagon::J4_cmpeqn1_f_jumpnv_nt },
  { Hexagon::J4_cmpeqn1_t_jumpnv_t, Hexagon::J4_cmpeqn1_t_jumpnv_nt },
  { Hexagon::J4_cmpgt_f_jumpnv_t, Hexagon::J4_cmpgt_f_jumpnv_nt },
  { Hexagon::J4_cmpgt_t_jumpnv_t, Hexagon::J4_cmpgt_t_jumpnv_nt },
  { Hexagon::J4_cmpgti_f_jumpnv_t, Hexagon::J4_cmpgti_f_jumpnv_nt },
  { Hexagon::J4_cmpgti_t_jumpnv_t, Hexagon::J4_cmpgti_t_jumpnv_nt },
  { Hexagon::J4_cmpgtn1_f_jumpnv_t, Hexagon::J4_cmpgtn1_f_jumpnv_nt },
  { Hexagon::J4_cmpgtn1_t_jumpnv_t, Hexagon::J4_cmpgtn1_t_jumpnv_nt },
  { Hexagon::J4_cmpgtu_f_jumpnv_t, Hexagon::J4_cmpgtu_f_jumpnv_nt },
  { Hexagon::J4_cmpgtu_t_jumpnv_t, Hexagon::J4_cmpgtu_t_jumpnv_nt },
  { Hexagon::J4_cmpgtui_f_jumpnv_t, Hexagon::J4_cmpgtui_f_jumpnv_nt },
  { Hexagon::J4_cmpgtui_t_jumpnv_t, Hexagon::J4_cmpgtui_t_jumpnv_nt },
  { Hexagon::J4_cmplt_f_jumpnv_t, Hexagon::J4_cmplt_f_jumpnv_nt },
  { Hexagon::J4_cmplt_t_jumpnv_t, Hexagon::J4_cmplt_t_jumpnv_nt },
  { Hexagon::J4_cmpltu_f_jumpnv_t, Hexagon::J4_cmpltu_f_jumpnv_nt },
  { Hexagon::J4_cmpltu_t_jumpnv_t, Hexagon::J4_cmpltu_t_jumpnv_nt },
  { Hexagon::J4_tstbit0_f_jumpnv_t, Hexagon::J4_tstbit0_f_jumpnv_nt },
  { Hexagon::J4_tstbit0_t_jumpnv_t, Hexagon::J4_tstbit0_t_jumpnv_nt },
  { Hexagon::JMPretfnewpt, Hexagon::JMPretfnew },
  { Hexagon::JMPrettnewpt, Hexagon::JMPrettnew },
  { Hexagon::L4_return_fnew_pt, Hexagon::L4_return_fnew_pnt },
  { Hexagon::L4_return_tnew_pt, Hexagon::L4_return_tnew_pnt },
}; // End of notTakenBranchPredictionTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 30;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == notTakenBranchPredictionTable[mid][0]) {
      break;
    }
    if (Opcode < notTakenBranchPredictionTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return notTakenBranchPredictionTable[mid][1];
}

// takenBranchPrediction
LLVM_READONLY
int takenBranchPrediction(uint16_t Opcode) {
static const uint16_t takenBranchPredictionTable[][2] = {
  { Hexagon::J2_jumpfnew, Hexagon::J2_jumpfnewpt },
  { Hexagon::J2_jumprfnew, Hexagon::J2_jumprfnewpt },
  { Hexagon::J2_jumprtnew, Hexagon::J2_jumprtnewpt },
  { Hexagon::J2_jumptnew, Hexagon::J2_jumptnewpt },
  { Hexagon::J4_cmpeq_f_jumpnv_nt, Hexagon::J4_cmpeq_f_jumpnv_t },
  { Hexagon::J4_cmpeq_t_jumpnv_nt, Hexagon::J4_cmpeq_t_jumpnv_t },
  { Hexagon::J4_cmpeqi_f_jumpnv_nt, Hexagon::J4_cmpeqi_f_jumpnv_t },
  { Hexagon::J4_cmpeqi_t_jumpnv_nt, Hexagon::J4_cmpeqi_t_jumpnv_t },
  { Hexagon::J4_cmpeqn1_f_jumpnv_nt, Hexagon::J4_cmpeqn1_f_jumpnv_t },
  { Hexagon::J4_cmpeqn1_t_jumpnv_nt, Hexagon::J4_cmpeqn1_t_jumpnv_t },
  { Hexagon::J4_cmpgt_f_jumpnv_nt, Hexagon::J4_cmpgt_f_jumpnv_t },
  { Hexagon::J4_cmpgt_t_jumpnv_nt, Hexagon::J4_cmpgt_t_jumpnv_t },
  { Hexagon::J4_cmpgti_f_jumpnv_nt, Hexagon::J4_cmpgti_f_jumpnv_t },
  { Hexagon::J4_cmpgti_t_jumpnv_nt, Hexagon::J4_cmpgti_t_jumpnv_t },
  { Hexagon::J4_cmpgtn1_f_jumpnv_nt, Hexagon::J4_cmpgtn1_f_jumpnv_t },
  { Hexagon::J4_cmpgtn1_t_jumpnv_nt, Hexagon::J4_cmpgtn1_t_jumpnv_t },
  { Hexagon::J4_cmpgtu_f_jumpnv_nt, Hexagon::J4_cmpgtu_f_jumpnv_t },
  { Hexagon::J4_cmpgtu_t_jumpnv_nt, Hexagon::J4_cmpgtu_t_jumpnv_t },
  { Hexagon::J4_cmpgtui_f_jumpnv_nt, Hexagon::J4_cmpgtui_f_jumpnv_t },
  { Hexagon::J4_cmpgtui_t_jumpnv_nt, Hexagon::J4_cmpgtui_t_jumpnv_t },
  { Hexagon::J4_cmplt_f_jumpnv_nt, Hexagon::J4_cmplt_f_jumpnv_t },
  { Hexagon::J4_cmplt_t_jumpnv_nt, Hexagon::J4_cmplt_t_jumpnv_t },
  { Hexagon::J4_cmpltu_f_jumpnv_nt, Hexagon::J4_cmpltu_f_jumpnv_t },
  { Hexagon::J4_cmpltu_t_jumpnv_nt, Hexagon::J4_cmpltu_t_jumpnv_t },
  { Hexagon::J4_tstbit0_f_jumpnv_nt, Hexagon::J4_tstbit0_f_jumpnv_t },
  { Hexagon::J4_tstbit0_t_jumpnv_nt, Hexagon::J4_tstbit0_t_jumpnv_t },
  { Hexagon::JMPretfnew, Hexagon::JMPretfnewpt },
  { Hexagon::JMPrettnew, Hexagon::JMPrettnewpt },
  { Hexagon::L4_return_fnew_pnt, Hexagon::L4_return_fnew_pt },
  { Hexagon::L4_return_tnew_pnt, Hexagon::L4_return_tnew_pt },
}; // End of takenBranchPredictionTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 30;
  while (start < end) {
    mid = start + (end - start)/2;
    if (Opcode == takenBranchPredictionTable[mid][0]) {
      break;
    }
    if (Opcode < takenBranchPredictionTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return takenBranchPredictionTable[mid][1];
}

} // End Hexagon namespace
} // End llvm namespace
#endif // GET_INSTRMAP_INFO

