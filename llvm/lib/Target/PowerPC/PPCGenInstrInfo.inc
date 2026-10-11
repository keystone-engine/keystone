/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::PPC {

  enum {
    PHI                                       = 0, // Target.td:1327
    INLINEASM                                 = 1, // Target.td:1333
    INLINEASM_BR                              = 2, // Target.td:1339
    CFI_INSTRUCTION                           = 3, // Target.td:1348
    EH_LABEL                                  = 4, // Target.td:1357
    GC_LABEL                                  = 5, // Target.td:1366
    ANNOTATION_LABEL                          = 6, // Target.td:1375
    KILL                                      = 7, // Target.td:1383
    EXTRACT_SUBREG                            = 8, // Target.td:1390
    INSERT_SUBREG                             = 9, // Target.td:1396
    IMPLICIT_DEF                              = 10, // Target.td:1403
    INIT_UNDEF                                = 11, // Target.td:1412
    SUBREG_TO_REG                             = 12, // Target.td:1419
    COPY_TO_REGCLASS                          = 13, // Target.td:1425
    DBG_VALUE                                 = 14, // Target.td:1432
    DBG_VALUE_LIST                            = 15, // Target.td:1439
    DBG_INSTR_REF                             = 16, // Target.td:1446
    DBG_PHI                                   = 17, // Target.td:1453
    DBG_LABEL                                 = 18, // Target.td:1460
    REG_SEQUENCE                              = 19, // Target.td:1467
    COPY                                      = 20, // Target.td:1474
    COPY_LANEMASK                             = 21, // Target.td:1482
    BUNDLE                                    = 22, // Target.td:1489
    LIFETIME_START                            = 23, // Target.td:1495
    LIFETIME_END                              = 24, // Target.td:1502
    PSEUDO_PROBE                              = 25, // Target.td:1509
    ARITH_FENCE                               = 26, // Target.td:1516
    STACKMAP                                  = 27, // Target.td:1525
    FENTRY_CALL                               = 28, // Target.td:1660
    PATCHPOINT                                = 29, // Target.td:1533
    LOAD_STACK_GUARD                          = 30, // Target.td:1551
    PREALLOCATED_SETUP                        = 31, // Target.td:1559
    PREALLOCATED_ARG                          = 32, // Target.td:1565
    STATEPOINT                                = 33, // Target.td:1542
    LOCAL_ESCAPE                              = 34, // Target.td:1571
    FAULTING_OP                               = 35, // Target.td:1580
    PATCHABLE_OP                              = 36, // Target.td:1600
    PATCHABLE_FUNCTION_ENTER                  = 37, // Target.td:1608
    PATCHABLE_RET                             = 38, // Target.td:1615
    PATCHABLE_FUNCTION_EXIT                   = 39, // Target.td:1624
    PATCHABLE_TAIL_CALL                       = 40, // Target.td:1632
    PATCHABLE_EVENT_CALL                      = 41, // Target.td:1640
    PATCHABLE_TYPED_EVENT_CALL                = 42, // Target.td:1650
    ICALL_BRANCH_FUNNEL                       = 43, // Target.td:1670
    FAKE_USE                                  = 44, // Target.td:1590
    MEMBARRIER                                = 45, // Target.td:1676
    JUMP_TABLE_DEBUG_INFO                     = 46, // Target.td:1684
    RELOC_NONE                                = 47, // Target.td:1692
    CONVERGENCECTRL_ENTRY                     = 48, // Target.td:1704
    CONVERGENCECTRL_ANCHOR                    = 49, // Target.td:1700
    CONVERGENCECTRL_LOOP                      = 50, // Target.td:1708
    CONVERGENCECTRL_GLUE                      = 51, // Target.td:1712
    G_ASSERT_SEXT                             = 52, // GenericOpcodes.td:1929
    G_ASSERT_ZEXT                             = 53, // GenericOpcodes.td:1921
    G_ASSERT_ALIGN                            = 54, // GenericOpcodes.td:1936
    G_ADD                                     = 55, // GenericOpcodes.td:308
    G_SUB                                     = 56, // GenericOpcodes.td:316
    G_MUL                                     = 57, // GenericOpcodes.td:324
    G_SDIV                                    = 58, // GenericOpcodes.td:332
    G_UDIV                                    = 59, // GenericOpcodes.td:340
    G_SREM                                    = 60, // GenericOpcodes.td:348
    G_UREM                                    = 61, // GenericOpcodes.td:356
    G_SDIVREM                                 = 62, // GenericOpcodes.td:364
    G_UDIVREM                                 = 63, // GenericOpcodes.td:372
    G_AND                                     = 64, // GenericOpcodes.td:380
    G_OR                                      = 65, // GenericOpcodes.td:388
    G_XOR                                     = 66, // GenericOpcodes.td:396
    G_ABDS                                    = 67, // GenericOpcodes.td:425
    G_ABDU                                    = 68, // GenericOpcodes.td:433
    G_UAVGFLOOR                               = 69, // GenericOpcodes.td:441
    G_UAVGCEIL                                = 70, // GenericOpcodes.td:448
    G_SAVGFLOOR                               = 71, // GenericOpcodes.td:455
    G_SAVGCEIL                                = 72, // GenericOpcodes.td:462
    G_IMPLICIT_DEF                            = 73, // GenericOpcodes.td:111
    G_PHI                                     = 74, // GenericOpcodes.td:118
    G_FRAME_INDEX                             = 75, // GenericOpcodes.td:125
    G_GLOBAL_VALUE                            = 76, // GenericOpcodes.td:131
    G_PTRAUTH_GLOBAL_VALUE                    = 77, // GenericOpcodes.td:137
    G_CONSTANT_POOL                           = 78, // GenericOpcodes.td:143
    G_EXTRACT                                 = 79, // GenericOpcodes.td:1516
    G_UNMERGE_VALUES                          = 80, // GenericOpcodes.td:1529
    G_INSERT                                  = 81, // GenericOpcodes.td:1538
    G_MERGE_VALUES                            = 82, // GenericOpcodes.td:1548
    G_BUILD_VECTOR                            = 83, // GenericOpcodes.td:1568
    G_BUILD_VECTOR_TRUNC                      = 84, // GenericOpcodes.td:1578
    G_CONCAT_VECTORS                          = 85, // GenericOpcodes.td:1585
    G_PTRTOINT                                = 86, // GenericOpcodes.td:155
    G_INTTOPTR                                = 87, // GenericOpcodes.td:149
    G_BITCAST                                 = 88, // GenericOpcodes.td:161
    G_FREEZE                                  = 89, // GenericOpcodes.td:284
    G_CONSTANT_FOLD_BARRIER                   = 90, // GenericOpcodes.td:1943
    G_INTRINSIC_FPTRUNC_ROUND                 = 91, // GenericOpcodes.td:1280
    G_INTRINSIC_TRUNC                         = 92, // GenericOpcodes.td:1286
    G_INTRINSIC_ROUND                         = 93, // GenericOpcodes.td:1292
    G_INTRINSIC_LRINT                         = 94, // GenericOpcodes.td:1298
    G_INTRINSIC_LLRINT                        = 95, // GenericOpcodes.td:1304
    G_INTRINSIC_ROUNDEVEN                     = 96, // GenericOpcodes.td:1310
    G_READCYCLECOUNTER                        = 97, // GenericOpcodes.td:1316
    G_READSTEADYCOUNTER                       = 98, // GenericOpcodes.td:1322
    G_LOAD                                    = 99, // GenericOpcodes.td:1349
    G_SEXTLOAD                                = 100, // GenericOpcodes.td:1358
    G_ZEXTLOAD                                = 101, // GenericOpcodes.td:1366
    G_FPEXTLOAD                               = 102, // GenericOpcodes.td:1375
    G_INDEXED_LOAD                            = 103, // GenericOpcodes.td:1385
    G_INDEXED_SEXTLOAD                        = 104, // GenericOpcodes.td:1394
    G_INDEXED_ZEXTLOAD                        = 105, // GenericOpcodes.td:1402
    G_STORE                                   = 106, // GenericOpcodes.td:1410
    G_FPTRUNCSTORE                            = 107, // GenericOpcodes.td:1420
    G_INDEXED_STORE                           = 108, // GenericOpcodes.td:1428
    G_ATOMIC_CMPXCHG_WITH_SUCCESS             = 109, // GenericOpcodes.td:1439
    G_ATOMIC_CMPXCHG                          = 110, // GenericOpcodes.td:1450
    G_ATOMICRMW_XCHG                          = 111, // GenericOpcodes.td:1470
    G_ATOMICRMW_ADD                           = 112, // GenericOpcodes.td:1471
    G_ATOMICRMW_SUB                           = 113, // GenericOpcodes.td:1472
    G_ATOMICRMW_AND                           = 114, // GenericOpcodes.td:1473
    G_ATOMICRMW_NAND                          = 115, // GenericOpcodes.td:1474
    G_ATOMICRMW_OR                            = 116, // GenericOpcodes.td:1475
    G_ATOMICRMW_XOR                           = 117, // GenericOpcodes.td:1476
    G_ATOMICRMW_MAX                           = 118, // GenericOpcodes.td:1477
    G_ATOMICRMW_MIN                           = 119, // GenericOpcodes.td:1478
    G_ATOMICRMW_UMAX                          = 120, // GenericOpcodes.td:1479
    G_ATOMICRMW_UMIN                          = 121, // GenericOpcodes.td:1480
    G_ATOMICRMW_FADD                          = 122, // GenericOpcodes.td:1481
    G_ATOMICRMW_FSUB                          = 123, // GenericOpcodes.td:1482
    G_ATOMICRMW_FMAX                          = 124, // GenericOpcodes.td:1483
    G_ATOMICRMW_FMIN                          = 125, // GenericOpcodes.td:1484
    G_ATOMICRMW_FMAXIMUM                      = 126, // GenericOpcodes.td:1485
    G_ATOMICRMW_FMINIMUM                      = 127, // GenericOpcodes.td:1486
    G_ATOMICRMW_FMAXIMUMNUM                   = 128, // GenericOpcodes.td:1487
    G_ATOMICRMW_FMINIMUMNUM                   = 129, // GenericOpcodes.td:1488
    G_ATOMICRMW_UINC_WRAP                     = 130, // GenericOpcodes.td:1489
    G_ATOMICRMW_UDEC_WRAP                     = 131, // GenericOpcodes.td:1490
    G_ATOMICRMW_USUB_COND                     = 132, // GenericOpcodes.td:1491
    G_ATOMICRMW_USUB_SAT                      = 133, // GenericOpcodes.td:1492
    G_FENCE                                   = 134, // GenericOpcodes.td:1494
    G_PREFETCH                                = 135, // GenericOpcodes.td:1501
    G_BRCOND                                  = 136, // GenericOpcodes.td:1641
    G_BRINDIRECT                              = 137, // GenericOpcodes.td:1650
    G_INVOKE_REGION_START                     = 138, // GenericOpcodes.td:1673
    G_INTRINSIC                               = 139, // GenericOpcodes.td:1593
    G_INTRINSIC_W_SIDE_EFFECTS                = 140, // GenericOpcodes.td:1600
    G_INTRINSIC_CONVERGENT                    = 141, // GenericOpcodes.td:1609
    G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS     = 142, // GenericOpcodes.td:1617
    G_ANYEXT                                  = 143, // GenericOpcodes.td:44
    G_TRUNC                                   = 144, // GenericOpcodes.td:83
    G_TRUNC_SSAT_S                            = 145, // GenericOpcodes.td:91
    G_TRUNC_SSAT_U                            = 146, // GenericOpcodes.td:98
    G_TRUNC_USAT_U                            = 147, // GenericOpcodes.td:105
    G_CONSTANT                                = 148, // GenericOpcodes.td:169
    G_FCONSTANT                               = 149, // GenericOpcodes.td:177
    G_VASTART                                 = 150, // GenericOpcodes.td:184
    G_VAARG                                   = 151, // GenericOpcodes.td:191
    G_SEXT                                    = 152, // GenericOpcodes.td:52
    G_SEXT_INREG                              = 153, // GenericOpcodes.td:66
    G_ZEXT                                    = 154, // GenericOpcodes.td:74
    G_SHL                                     = 155, // GenericOpcodes.td:404
    G_LSHR                                    = 156, // GenericOpcodes.td:411
    G_ASHR                                    = 157, // GenericOpcodes.td:418
    G_FSHL                                    = 158, // GenericOpcodes.td:470
    G_FSHR                                    = 159, // GenericOpcodes.td:478
    G_ROTR                                    = 160, // GenericOpcodes.td:485
    G_ROTL                                    = 161, // GenericOpcodes.td:492
    G_ICMP                                    = 162, // GenericOpcodes.td:499
    G_FCMP                                    = 163, // GenericOpcodes.td:506
    G_SCMP                                    = 164, // GenericOpcodes.td:513
    G_UCMP                                    = 165, // GenericOpcodes.td:520
    G_SELECT                                  = 166, // GenericOpcodes.td:527
    G_UADDO                                   = 167, // GenericOpcodes.td:601
    G_UADDE                                   = 168, // GenericOpcodes.td:609
    G_USUBO                                   = 169, // GenericOpcodes.td:631
    G_USUBE                                   = 170, // GenericOpcodes.td:637
    G_SADDO                                   = 171, // GenericOpcodes.td:616
    G_SADDE                                   = 172, // GenericOpcodes.td:624
    G_SSUBO                                   = 173, // GenericOpcodes.td:644
    G_SSUBE                                   = 174, // GenericOpcodes.td:651
    G_UMULO                                   = 175, // GenericOpcodes.td:658
    G_SMULO                                   = 176, // GenericOpcodes.td:666
    G_UMULH                                   = 177, // GenericOpcodes.td:675
    G_SMULH                                   = 178, // GenericOpcodes.td:684
    G_UADDSAT                                 = 179, // GenericOpcodes.td:696
    G_SADDSAT                                 = 180, // GenericOpcodes.td:704
    G_USUBSAT                                 = 181, // GenericOpcodes.td:712
    G_SSUBSAT                                 = 182, // GenericOpcodes.td:720
    G_USHLSAT                                 = 183, // GenericOpcodes.td:728
    G_SSHLSAT                                 = 184, // GenericOpcodes.td:736
    G_SMULFIX                                 = 185, // GenericOpcodes.td:748
    G_UMULFIX                                 = 186, // GenericOpcodes.td:755
    G_SMULFIXSAT                              = 187, // GenericOpcodes.td:765
    G_UMULFIXSAT                              = 188, // GenericOpcodes.td:772
    G_SDIVFIX                                 = 189, // GenericOpcodes.td:783
    G_UDIVFIX                                 = 190, // GenericOpcodes.td:790
    G_SDIVFIXSAT                              = 191, // GenericOpcodes.td:800
    G_UDIVFIXSAT                              = 192, // GenericOpcodes.td:807
    G_FADD                                    = 193, // GenericOpcodes.td:980
    G_FSUB                                    = 194, // GenericOpcodes.td:988
    G_FMUL                                    = 195, // GenericOpcodes.td:996
    G_FMA                                     = 196, // GenericOpcodes.td:1005
    G_FMAD                                    = 197, // GenericOpcodes.td:1014
    G_FDIV                                    = 198, // GenericOpcodes.td:1022
    G_FREM                                    = 199, // GenericOpcodes.td:1029
    G_FMODF                                   = 200, // GenericOpcodes.td:1036
    G_FPOW                                    = 201, // GenericOpcodes.td:1043
    G_FPOWI                                   = 202, // GenericOpcodes.td:1050
    G_FEXP                                    = 203, // GenericOpcodes.td:1057
    G_FEXP2                                   = 204, // GenericOpcodes.td:1064
    G_FEXP10                                  = 205, // GenericOpcodes.td:1071
    G_FLOG                                    = 206, // GenericOpcodes.td:1078
    G_FLOG2                                   = 207, // GenericOpcodes.td:1085
    G_FLOG10                                  = 208, // GenericOpcodes.td:1092
    G_FLDEXP                                  = 209, // GenericOpcodes.td:1099
    G_FFREXP                                  = 210, // GenericOpcodes.td:1106
    G_FNEG                                    = 211, // GenericOpcodes.td:818
    G_FPEXT                                   = 212, // GenericOpcodes.td:824
    G_FPTRUNC                                 = 213, // GenericOpcodes.td:830
    G_FPTOSI                                  = 214, // GenericOpcodes.td:836
    G_FPTOUI                                  = 215, // GenericOpcodes.td:842
    G_SITOFP                                  = 216, // GenericOpcodes.td:848
    G_UITOFP                                  = 217, // GenericOpcodes.td:854
    G_FPTOSI_SAT                              = 218, // GenericOpcodes.td:860
    G_FPTOUI_SAT                              = 219, // GenericOpcodes.td:866
    G_FABS                                    = 220, // GenericOpcodes.td:872
    G_FCOPYSIGN                               = 221, // GenericOpcodes.td:878
    G_IS_FPCLASS                              = 222, // GenericOpcodes.td:891
    G_FCANONICALIZE                           = 223, // GenericOpcodes.td:884
    G_FMINNUM                                 = 224, // GenericOpcodes.td:904
    G_FMAXNUM                                 = 225, // GenericOpcodes.td:911
    G_FMINNUM_IEEE                            = 226, // GenericOpcodes.td:929
    G_FMAXNUM_IEEE                            = 227, // GenericOpcodes.td:936
    G_FMINIMUM                                = 228, // GenericOpcodes.td:946
    G_FMAXIMUM                                = 229, // GenericOpcodes.td:953
    G_FMINIMUMNUM                             = 230, // GenericOpcodes.td:961
    G_FMAXIMUMNUM                             = 231, // GenericOpcodes.td:968
    G_GET_FPENV                               = 232, // GenericOpcodes.td:1236
    G_SET_FPENV                               = 233, // GenericOpcodes.td:1243
    G_RESET_FPENV                             = 234, // GenericOpcodes.td:1250
    G_GET_FPMODE                              = 235, // GenericOpcodes.td:1257
    G_SET_FPMODE                              = 236, // GenericOpcodes.td:1264
    G_RESET_FPMODE                            = 237, // GenericOpcodes.td:1271
    G_GET_ROUNDING                            = 238, // GenericOpcodes.td:1328
    G_SET_ROUNDING                            = 239, // GenericOpcodes.td:1334
    G_PTR_ADD                                 = 240, // GenericOpcodes.td:534
    G_PTRMASK                                 = 241, // GenericOpcodes.td:542
    G_SMIN                                    = 242, // GenericOpcodes.td:549
    G_SMAX                                    = 243, // GenericOpcodes.td:557
    G_UMIN                                    = 244, // GenericOpcodes.td:565
    G_UMAX                                    = 245, // GenericOpcodes.td:573
    G_ABS                                     = 246, // GenericOpcodes.td:581
    G_LROUND                                  = 247, // GenericOpcodes.td:291
    G_LLROUND                                 = 248, // GenericOpcodes.td:297
    G_BR                                      = 249, // GenericOpcodes.td:1631
    G_BRJT                                    = 250, // GenericOpcodes.td:1661
    G_VSCALE                                  = 251, // GenericOpcodes.td:1559
    G_INSERT_SUBVECTOR                        = 252, // GenericOpcodes.td:1705
    G_EXTRACT_SUBVECTOR                       = 253, // GenericOpcodes.td:1713
    G_INSERT_VECTOR_ELT                       = 254, // GenericOpcodes.td:1721
    G_EXTRACT_VECTOR_ELT                      = 255, // GenericOpcodes.td:1729
    G_SHUFFLE_VECTOR                          = 256, // GenericOpcodes.td:1740
    G_SPLAT_VECTOR                            = 257, // GenericOpcodes.td:1748
    G_STEP_VECTOR                             = 258, // GenericOpcodes.td:1756
    G_VECTOR_COMPRESS                         = 259, // GenericOpcodes.td:1763
    G_CTTZ                                    = 260, // GenericOpcodes.td:211
    G_CTTZ_ZERO_POISON                        = 261, // GenericOpcodes.td:217
    G_CTLZ                                    = 262, // GenericOpcodes.td:199
    G_CTLZ_ZERO_POISON                        = 263, // GenericOpcodes.td:205
    G_CTLS                                    = 264, // GenericOpcodes.td:223
    G_CTPOP                                   = 265, // GenericOpcodes.td:229
    G_BSWAP                                   = 266, // GenericOpcodes.td:235
    G_BITREVERSE                              = 267, // GenericOpcodes.td:242
    G_CLMUL                                   = 268, // GenericOpcodes.td:588
    G_FCEIL                                   = 269, // GenericOpcodes.td:1113
    G_FCOS                                    = 270, // GenericOpcodes.td:1120
    G_FSIN                                    = 271, // GenericOpcodes.td:1127
    G_FSINCOS                                 = 272, // GenericOpcodes.td:1134
    G_FTAN                                    = 273, // GenericOpcodes.td:1141
    G_FACOS                                   = 274, // GenericOpcodes.td:1148
    G_FASIN                                   = 275, // GenericOpcodes.td:1155
    G_FATAN                                   = 276, // GenericOpcodes.td:1162
    G_FATAN2                                  = 277, // GenericOpcodes.td:1169
    G_FCOSH                                   = 278, // GenericOpcodes.td:1176
    G_FSINH                                   = 279, // GenericOpcodes.td:1183
    G_FTANH                                   = 280, // GenericOpcodes.td:1190
    G_FSQRT                                   = 281, // GenericOpcodes.td:1200
    G_FFLOOR                                  = 282, // GenericOpcodes.td:1207
    G_FRINT                                   = 283, // GenericOpcodes.td:1214
    G_FNEARBYINT                              = 284, // GenericOpcodes.td:1221
    G_ADDRSPACE_CAST                          = 285, // GenericOpcodes.td:248
    G_BLOCK_ADDR                              = 286, // GenericOpcodes.td:254
    G_JUMP_TABLE                              = 287, // GenericOpcodes.td:260
    G_DYN_STACKALLOC                          = 288, // GenericOpcodes.td:266
    G_STACKSAVE                               = 289, // GenericOpcodes.td:272
    G_STACKRESTORE                            = 290, // GenericOpcodes.td:278
    G_STRICT_FADD                             = 291, // GenericOpcodes.td:1813
    G_STRICT_FSUB                             = 292, // GenericOpcodes.td:1814
    G_STRICT_FMUL                             = 293, // GenericOpcodes.td:1815
    G_STRICT_FDIV                             = 294, // GenericOpcodes.td:1816
    G_STRICT_FREM                             = 295, // GenericOpcodes.td:1817
    G_STRICT_FMA                              = 296, // GenericOpcodes.td:1818
    G_STRICT_FSQRT                            = 297, // GenericOpcodes.td:1819
    G_STRICT_FLDEXP                           = 298, // GenericOpcodes.td:1820
    G_STRICT_FCMP                             = 299, // GenericOpcodes.td:1821
    G_STRICT_FCMPS                            = 300, // GenericOpcodes.td:1822
    G_READ_REGISTER                           = 301, // GenericOpcodes.td:1680
    G_WRITE_REGISTER                          = 302, // GenericOpcodes.td:1690
    G_MEMCPY                                  = 303, // GenericOpcodes.td:1828
    G_MEMCPY_INLINE                           = 304, // GenericOpcodes.td:1836
    G_MEMMOVE                                 = 305, // GenericOpcodes.td:1844
    G_MEMSET                                  = 306, // GenericOpcodes.td:1852
    G_BZERO                                   = 307, // GenericOpcodes.td:1859
    G_MEMSET_INLINE                           = 308, // GenericOpcodes.td:1866
    G_TRAP                                    = 309, // GenericOpcodes.td:1876
    G_DEBUGTRAP                               = 310, // GenericOpcodes.td:1883
    G_UBSANTRAP                               = 311, // GenericOpcodes.td:1889
    G_VECREDUCE_SEQ_FADD                      = 312, // GenericOpcodes.td:1779
    G_VECREDUCE_SEQ_FMUL                      = 313, // GenericOpcodes.td:1785
    G_VECREDUCE_FADD                          = 314, // GenericOpcodes.td:1791
    G_VECREDUCE_FMUL                          = 315, // GenericOpcodes.td:1792
    G_VECREDUCE_FMAX                          = 316, // GenericOpcodes.td:1794
    G_VECREDUCE_FMIN                          = 317, // GenericOpcodes.td:1795
    G_VECREDUCE_FMAXIMUM                      = 318, // GenericOpcodes.td:1796
    G_VECREDUCE_FMINIMUM                      = 319, // GenericOpcodes.td:1797
    G_VECREDUCE_ADD                           = 320, // GenericOpcodes.td:1799
    G_VECREDUCE_MUL                           = 321, // GenericOpcodes.td:1800
    G_VECREDUCE_AND                           = 322, // GenericOpcodes.td:1801
    G_VECREDUCE_OR                            = 323, // GenericOpcodes.td:1802
    G_VECREDUCE_XOR                           = 324, // GenericOpcodes.td:1803
    G_VECREDUCE_SMAX                          = 325, // GenericOpcodes.td:1804
    G_VECREDUCE_SMIN                          = 326, // GenericOpcodes.td:1805
    G_VECREDUCE_UMAX                          = 327, // GenericOpcodes.td:1806
    G_VECREDUCE_UMIN                          = 328, // GenericOpcodes.td:1807
    G_SBFX                                    = 329, // GenericOpcodes.td:1901
    G_UBFX                                    = 330, // GenericOpcodes.td:1909
    ATOMIC_CMP_SWAP_I128                      = 331, // PPCInstr64Bit.td:394
    ATOMIC_LOAD_ADD_I128                      = 332, // PPCInstr64Bit.td:387
    ATOMIC_LOAD_AND_I128                      = 333, // PPCInstr64Bit.td:389
    ATOMIC_LOAD_NAND_I128                     = 334, // PPCInstr64Bit.td:392
    ATOMIC_LOAD_OR_I128                       = 335, // PPCInstr64Bit.td:391
    ATOMIC_LOAD_SUB_I128                      = 336, // PPCInstr64Bit.td:388
    ATOMIC_LOAD_XOR_I128                      = 337, // PPCInstr64Bit.td:390
    ATOMIC_SWAP_I128                          = 338, // PPCInstr64Bit.td:386
    BUILD_QUADWORD                            = 339, // PPCInstr64Bit.td:1699
    BUILD_UACC                                = 340, // PPCInstrMMA.td:508
    CFENCE                                    = 341, // PPCInstrInfo.td:5591
    CFENCE8                                   = 342, // PPCInstr64Bit.td:1513
    CLRLSLDI                                  = 343, // PPCInstrInfo.td:5123
    CLRLSLDI_rec                              = 344, // PPCInstrInfo.td:5125
    CLRLSLWI                                  = 345, // PPCInstrInfo.td:5070
    CLRLSLWI_rec                              = 346, // PPCInstrInfo.td:5072
    CLRRDI                                    = 347, // PPCInstrInfo.td:5119
    CLRRDI_rec                                = 348, // PPCInstrInfo.td:5121
    CLRRWI                                    = 349, // PPCInstrInfo.td:5066
    CLRRWI_rec                                = 350, // PPCInstrInfo.td:5068
    DCBFL                                     = 351, // PPCInstrInfo.td:4822
    DCBFLP                                    = 352, // PPCInstrInfo.td:4823
    DCBFPS                                    = 353, // PPCInstrInfo.td:4832
    DCBFx                                     = 354, // PPCInstrInfo.td:4821
    DCBSTPS                                   = 355, // PPCInstrInfo.td:4833
    DCBTCT                                    = 356, // PPCInstrInfo.td:4813
    DCBTDS                                    = 357, // PPCInstrInfo.td:4814
    DCBTSTCT                                  = 358, // PPCInstrInfo.td:4817
    DCBTSTDS                                  = 359, // PPCInstrInfo.td:4818
    DCBTSTT                                   = 360, // PPCInstrInfo.td:4819
    DCBTSTx                                   = 361, // PPCInstrInfo.td:4811
    DCBTT                                     = 362, // PPCInstrInfo.td:4815
    DCBTx                                     = 363, // PPCInstrInfo.td:4810
    DFLOADf32                                 = 364, // PPCInstrVSX.td:1794
    DFLOADf64                                 = 365, // PPCInstrVSX.td:1796
    DFSTOREf32                                = 366, // PPCInstrVSX.td:1798
    DFSTOREf64                                = 367, // PPCInstrVSX.td:1800
    EXTLDI                                    = 368, // PPCInstrInfo.td:5095
    EXTLDI_rec                                = 369, // PPCInstrInfo.td:5097
    EXTLWI                                    = 370, // PPCInstrInfo.td:5036
    EXTLWI_rec                                = 371, // PPCInstrInfo.td:5039
    EXTRDI                                    = 372, // PPCInstrInfo.td:5099
    EXTRDI_rec                                = 373, // PPCInstrInfo.td:5101
    EXTRWI                                    = 374, // PPCInstrInfo.td:5042
    EXTRWI_rec                                = 375, // PPCInstrInfo.td:5044
    INSLWI                                    = 376, // PPCInstrInfo.td:5046
    INSLWI_rec                                = 377, // PPCInstrInfo.td:5048
    INSRDI                                    = 378, // PPCInstrInfo.td:5103
    INSRDI_rec                                = 379, // PPCInstrInfo.td:5105
    INSRWI                                    = 380, // PPCInstrInfo.td:5050
    INSRWI_rec                                = 381, // PPCInstrInfo.td:5052
    KILL_PAIR                                 = 382, // PPCInstrMMA.td:506
    LAx                                       = 383, // PPCInstrInfo.td:5025
    LDAT_CSNE_PSEUDO                          = 384, // PPCInstr64Bit.td:358
    LIWAX                                     = 385, // PPCInstrVSX.td:1174
    LIWZX                                     = 386, // PPCInstrVSX.td:1177
    LWAT_CSNE_PSEUDO                          = 387, // PPCInstrInfo.td:2151
    PPCLdFixedAddr                            = 388, // PPCInstrInfo.td:5153
    PSUBI                                     = 389, // PPCInstrP10.td:2981
    RLWIMIbm                                  = 390, // PPCInstrInfo.td:5145
    RLWIMIbm_rec                              = 391, // PPCInstrInfo.td:5147
    RLWINMbm                                  = 392, // PPCInstrInfo.td:5141
    RLWINMbm_rec                              = 393, // PPCInstrInfo.td:5143
    RLWNMbm                                   = 394, // PPCInstrInfo.td:5149
    RLWNMbm_rec                               = 395, // PPCInstrInfo.td:5151
    ROTRDI                                    = 396, // PPCInstrInfo.td:5107
    ROTRDI_rec                                = 397, // PPCInstrInfo.td:5109
    ROTRWI                                    = 398, // PPCInstrInfo.td:5054
    ROTRWI_rec                                = 399, // PPCInstrInfo.td:5056
    SLDI                                      = 400, // PPCInstrInfo.td:5111
    SLDI_rec                                  = 401, // PPCInstrInfo.td:5113
    SLWI                                      = 402, // PPCInstrInfo.td:5058
    SLWI_rec                                  = 403, // PPCInstrInfo.td:5060
    SPILLTOVSR_LD                             = 404, // PPCInstrVSX.td:1811
    SPILLTOVSR_LDX                            = 405, // PPCInstrVSX.td:1809
    SPILLTOVSR_ST                             = 406, // PPCInstrVSX.td:1806
    SPILLTOVSR_STX                            = 407, // PPCInstrVSX.td:1804
    SRDI                                      = 408, // PPCInstrInfo.td:5115
    SRDI_rec                                  = 409, // PPCInstrInfo.td:5117
    SRWI                                      = 410, // PPCInstrInfo.td:5062
    SRWI_rec                                  = 411, // PPCInstrInfo.td:5064
    STIWX                                     = 412, // PPCInstrVSX.td:1194
    SUBI                                      = 413, // PPCInstrInfo.td:5027
    SUBIC                                     = 414, // PPCInstrInfo.td:5031
    SUBIC_rec                                 = 415, // PPCInstrInfo.td:5033
    SUBIS                                     = 416, // PPCInstrInfo.td:5029
    SUBPCIS                                   = 417, // PPCInstrInfo.td:5127
    XFLOADf32                                 = 418, // PPCInstrVSX.td:1171
    XFLOADf64                                 = 419, // PPCInstrVSX.td:351
    XFSTOREf32                                = 420, // PPCInstrVSX.td:1191
    XFSTOREf64                                = 421, // PPCInstrVSX.td:381
    ADD4                                      = 422, // PPCInstrInfo.td:1120
    ADD4O                                     = 423, // PPCInstrInfo.td:1130
    ADD4O_rec                                 = 424, // PPCInstrInfo.td:1134
    ADD4TLS                                   = 425, // PPCInstrInfo.td:3150
    ADD4_rec                                  = 426, // PPCInstrInfo.td:1124
    ADD8                                      = 427, // PPCInstrInfo.td:1120
    ADD8O                                     = 428, // PPCInstrInfo.td:1130
    ADD8O_rec                                 = 429, // PPCInstrInfo.td:1134
    ADD8TLS                                   = 430, // PPCInstr64Bit.td:697
    ADD8TLS_                                  = 431, // PPCInstr64Bit.td:829
    ADD8_rec                                  = 432, // PPCInstrInfo.td:1124
    ADDC                                      = 433, // PPCInstrInfo.td:1172
    ADDC8                                     = 434, // PPCInstrInfo.td:1172
    ADDC8O                                    = 435, // PPCInstrInfo.td:1182
    ADDC8O_rec                                = 436, // PPCInstrInfo.td:1186
    ADDC8_rec                                 = 437, // PPCInstrInfo.td:1176
    ADDCO                                     = 438, // PPCInstrInfo.td:1182
    ADDCO_rec                                 = 439, // PPCInstrInfo.td:1186
    ADDC_rec                                  = 440, // PPCInstrInfo.td:1176
    ADDE                                      = 441, // PPCInstrInfo.td:1172
    ADDE8                                     = 442, // PPCInstrInfo.td:1172
    ADDE8O                                    = 443, // PPCInstrInfo.td:1182
    ADDE8O_rec                                = 444, // PPCInstrInfo.td:1186
    ADDE8_rec                                 = 445, // PPCInstrInfo.td:1176
    ADDEO                                     = 446, // PPCInstrInfo.td:1182
    ADDEO_rec                                 = 447, // PPCInstrInfo.td:1186
    ADDEX                                     = 448, // PPCInstrInfo.td:3138
    ADDEX8                                    = 449, // PPCInstr64Bit.td:1837
    ADDE_rec                                  = 450, // PPCInstrInfo.td:1176
    ADDG6S                                    = 451, // PPCInstrInfo.td:2197
    ADDG6S8                                   = 452, // PPCInstr64Bit.td:1035
    ADDI                                      = 453, // PPCInstrInfo.td:2529
    ADDI8                                     = 454, // PPCInstr64Bit.td:775
    ADDIC                                     = 455, // PPCInstrInfo.td:2534
    ADDIC8                                    = 456, // PPCInstr64Bit.td:772
    ADDIC_rec                                 = 457, // PPCInstrInfo.td:2539
    ADDIS                                     = 458, // PPCInstrInfo.td:2543
    ADDIS8                                    = 459, // PPCInstr64Bit.td:778
    ADDISdtprelHA                             = 460, // PPCInstr64Bit.td:1622
    ADDISdtprelHA32                           = 461, // PPCInstrInfo.td:3598
    ADDISgotTprelHA                           = 462, // PPCInstr64Bit.td:1500
    ADDIStlsgdHA                              = 463, // PPCInstr64Bit.td:1517
    ADDIStlsldHA                              = 464, // PPCInstr64Bit.td:1589
    ADDIStocHA                                = 465, // PPCInstrInfo.td:3613
    ADDIStocHA8                               = 466, // PPCInstr64Bit.td:1484
    ADDIdtprelL                               = 467, // PPCInstr64Bit.td:1628
    ADDIdtprelL32                             = 468, // PPCInstrInfo.td:3594
    ADDItlsgdL                                = 469, // PPCInstr64Bit.td:1522
    ADDItlsgdL32                              = 470, // PPCInstrInfo.td:3506
    ADDItlsgdLADDR                            = 471, // PPCInstr64Bit.td:1581
    ADDItlsgdLADDR32                          = 472, // PPCInstrInfo.td:3554
    ADDItlsldL                                = 473, // PPCInstr64Bit.td:1594
    ADDItlsldL32                              = 474, // PPCInstrInfo.td:3561
    ADDItlsldLADDR                            = 475, // PPCInstr64Bit.td:1614
    ADDItlsldLADDR32                          = 476, // PPCInstrInfo.td:3587
    ADDItoc                                   = 477, // PPCInstrInfo.td:3616
    ADDItoc8                                  = 478, // PPCInstr64Bit.td:1491
    ADDItocL                                  = 479, // PPCInstrInfo.td:3618
    ADDItocL8                                 = 480, // PPCInstr64Bit.td:1486
    ADDME                                     = 481, // PPCInstrInfo.td:1221
    ADDME8                                    = 482, // PPCInstrInfo.td:1221
    ADDME8O                                   = 483, // PPCInstrInfo.td:1231
    ADDME8O_rec                               = 484, // PPCInstrInfo.td:1235
    ADDME8_rec                                = 485, // PPCInstrInfo.td:1225
    ADDMEO                                    = 486, // PPCInstrInfo.td:1231
    ADDMEO_rec                                = 487, // PPCInstrInfo.td:1235
    ADDME_rec                                 = 488, // PPCInstrInfo.td:1225
    ADDPCIS                                   = 489, // PPCInstr64Bit.td:1070
    ADDZE                                     = 490, // PPCInstrInfo.td:1221
    ADDZE8                                    = 491, // PPCInstrInfo.td:1221
    ADDZE8O                                   = 492, // PPCInstrInfo.td:1231
    ADDZE8O_rec                               = 493, // PPCInstrInfo.td:1235
    ADDZE8_rec                                = 494, // PPCInstrInfo.td:1225
    ADDZEO                                    = 495, // PPCInstrInfo.td:1231
    ADDZEO_rec                                = 496, // PPCInstrInfo.td:1235
    ADDZE_rec                                 = 497, // PPCInstrInfo.td:1225
    ADJCALLSTACKDOWN                          = 498, // PPCInstrInfo.td:1489
    ADJCALLSTACKUP                            = 499, // PPCInstrInfo.td:1492
    AND                                       = 500, // PPCInstrInfo.td:1046
    AND8                                      = 501, // PPCInstrInfo.td:1046
    AND8_rec                                  = 502, // PPCInstrInfo.td:1050
    ANDC                                      = 503, // PPCInstrInfo.td:1046
    ANDC8                                     = 504, // PPCInstrInfo.td:1046
    ANDC8_rec                                 = 505, // PPCInstrInfo.td:1050
    ANDC_rec                                  = 506, // PPCInstrInfo.td:1050
    ANDI8_rec                                 = 507, // PPCInstr64Bit.td:667
    ANDIS8_rec                                = 508, // PPCInstr64Bit.td:671
    ANDIS_rec                                 = 509, // PPCInstrInfo.td:2579
    ANDI_rec                                  = 510, // PPCInstrInfo.td:2575
    ANDI_rec_1_EQ_BIT                         = 511, // PPCInstrInfo.td:4470
    ANDI_rec_1_EQ_BIT8                        = 512, // PPCInstrInfo.td:4477
    ANDI_rec_1_GT_BIT                         = 513, // PPCInstrInfo.td:4473
    ANDI_rec_1_GT_BIT8                        = 514, // PPCInstrInfo.td:4480
    AND_rec                                   = 515, // PPCInstrInfo.td:1050
    ATOMIC_CMP_SWAP_I16                       = 516, // PPCInstrInfo.td:2090
    ATOMIC_CMP_SWAP_I32                       = 517, // PPCInstrInfo.td:2090
    ATOMIC_CMP_SWAP_I64                       = 518, // PPCInstr64Bit.td:310
    ATOMIC_CMP_SWAP_I8                        = 519, // PPCInstrInfo.td:2090
    ATOMIC_LOAD_ADD                           = 520, // PPCInstrInfo.td:2065
    ATOMIC_LOAD_ADD_I64                       = 521, // PPCInstr64Bit.td:302
    ATOMIC_LOAD_ADD_NOWP                      = 522, // PPCInstrInfo.td:2068
    ATOMIC_LOAD_AND                           = 523, // PPCInstrInfo.td:2065
    ATOMIC_LOAD_AND_I64                       = 524, // PPCInstr64Bit.td:302
    ATOMIC_LOAD_AND_NOWP                      = 525, // PPCInstrInfo.td:2068
    ATOMIC_LOAD_MAX                           = 526, // PPCInstrInfo.td:2065
    ATOMIC_LOAD_MAX_I64                       = 527, // PPCInstr64Bit.td:302
    ATOMIC_LOAD_MAX_NOWP                      = 528, // PPCInstrInfo.td:2068
    ATOMIC_LOAD_MIN                           = 529, // PPCInstrInfo.td:2065
    ATOMIC_LOAD_MIN_I64                       = 530, // PPCInstr64Bit.td:302
    ATOMIC_LOAD_MIN_NOWP                      = 531, // PPCInstrInfo.td:2068
    ATOMIC_LOAD_NAND                          = 532, // PPCInstrInfo.td:2065
    ATOMIC_LOAD_NAND_I64                      = 533, // PPCInstr64Bit.td:302
    ATOMIC_LOAD_NAND_NOWP                     = 534, // PPCInstrInfo.td:2068
    ATOMIC_LOAD_OR                            = 535, // PPCInstrInfo.td:2065
    ATOMIC_LOAD_OR_I64                        = 536, // PPCInstr64Bit.td:302
    ATOMIC_LOAD_OR_NOWP                       = 537, // PPCInstrInfo.td:2068
    ATOMIC_LOAD_SUB                           = 538, // PPCInstrInfo.td:2065
    ATOMIC_LOAD_SUB_I64                       = 539, // PPCInstr64Bit.td:302
    ATOMIC_LOAD_SUB_NOWP                      = 540, // PPCInstrInfo.td:2068
    ATOMIC_LOAD_UMAX                          = 541, // PPCInstrInfo.td:2065
    ATOMIC_LOAD_UMAX_I64                      = 542, // PPCInstr64Bit.td:302
    ATOMIC_LOAD_UMAX_NOWP                     = 543, // PPCInstrInfo.td:2068
    ATOMIC_LOAD_UMIN                          = 544, // PPCInstrInfo.td:2065
    ATOMIC_LOAD_UMIN_I64                      = 545, // PPCInstr64Bit.td:302
    ATOMIC_LOAD_UMIN_NOWP                     = 546, // PPCInstrInfo.td:2068
    ATOMIC_LOAD_XOR                           = 547, // PPCInstrInfo.td:2065
    ATOMIC_LOAD_XOR_I64                       = 548, // PPCInstr64Bit.td:302
    ATOMIC_LOAD_XOR_NOWP                      = 549, // PPCInstrInfo.td:2068
    ATOMIC_SWAP                               = 550, // PPCInstrInfo.td:2065
    ATOMIC_SWAP_I64                           = 551, // PPCInstr64Bit.td:302
    ATOMIC_SWAP_NOWP                          = 552, // PPCInstrInfo.td:2068
    ATTN                                      = 553, // PPCInstrInfo.td:4707
    B                                         = 554, // PPCInstrInfo.td:1641
    BA                                        = 555, // PPCInstrInfo.td:1644
    BC                                        = 556, // PPCInstrInfo.td:1671
    BCC                                       = 557, // PPCInstrInfo.td:1655
    BCCA                                      = 558, // PPCInstrInfo.td:1661
    BCCCTR                                    = 559, // PPCInstrInfo.td:1603
    BCCCTR8                                   = 560, // PPCInstr64Bit.td:61
    BCCCTRL                                   = 561, // PPCInstrInfo.td:1772
    BCCCTRL8                                  = 562, // PPCInstr64Bit.td:142
    BCCL                                      = 563, // PPCInstrInfo.td:1749
    BCCLA                                     = 564, // PPCInstrInfo.td:1751
    BCCLR                                     = 565, // PPCInstrInfo.td:1665
    BCCLRL                                    = 566, // PPCInstrInfo.td:1787
    BCCTR                                     = 567, // PPCInstrInfo.td:1607
    BCCTR8                                    = 568, // PPCInstr64Bit.td:66
    BCCTR8n                                   = 569, // PPCInstr64Bit.td:69
    BCCTRL                                    = 570, // PPCInstrInfo.td:1776
    BCCTRL8                                   = 571, // PPCInstr64Bit.td:147
    BCCTRL8n                                  = 572, // PPCInstr64Bit.td:150
    BCCTRLn                                   = 573, // PPCInstrInfo.td:1778
    BCCTRn                                    = 574, // PPCInstrInfo.td:1609
    BCDADD_rec                                = 575, // PPCInstrAltivec.td:1412
    BCDCFN_rec                                = 576, // PPCInstrAltivec.td:1652
    BCDCFSQ_rec                               = 577, // PPCInstrAltivec.td:1660
    BCDCFZ_rec                                = 578, // PPCInstrAltivec.td:1654
    BCDCPSGN_rec                              = 579, // PPCInstrAltivec.td:1665
    BCDCTN_rec                                = 580, // PPCInstrAltivec.td:1656
    BCDCTSQ_rec                               = 581, // PPCInstrAltivec.td:1661
    BCDCTZ_rec                                = 582, // PPCInstrAltivec.td:1658
    BCDSETSGN_rec                             = 583, // PPCInstrAltivec.td:1668
    BCDSR_rec                                 = 584, // PPCInstrAltivec.td:1674
    BCDSUB_rec                                = 585, // PPCInstrAltivec.td:1413
    BCDS_rec                                  = 586, // PPCInstrAltivec.td:1672
    BCDTRUNC_rec                              = 587, // PPCInstrAltivec.td:1677
    BCDUS_rec                                 = 588, // PPCInstrAltivec.td:1673
    BCDUTRUNC_rec                             = 589, // PPCInstrAltivec.td:1678
    BCL                                       = 590, // PPCInstrInfo.td:1754
    BCLR                                      = 591, // PPCInstrInfo.td:1679
    BCLRL                                     = 592, // PPCInstrInfo.td:1791
    BCLRLn                                    = 593, // PPCInstrInfo.td:1793
    BCLRn                                     = 594, // PPCInstrInfo.td:1681
    BCLalways                                 = 595, // PPCInstrInfo.td:1733
    BCLn                                      = 596, // PPCInstrInfo.td:1757
    BCTR                                      = 597, // PPCInstrInfo.td:1599
    BCTR8                                     = 598, // PPCInstr64Bit.td:58
    BCTRL                                     = 599, // PPCInstrInfo.td:1767
    BCTRL8                                    = 600, // PPCInstr64Bit.td:137
    BCTRL8_LDinto_toc                         = 601, // PPCInstr64Bit.td:192
    BCTRL8_LDinto_toc_RM                      = 602, // PPCInstr64Bit.td:202
    BCTRL8_RM                                 = 603, // PPCInstr64Bit.td:184
    BCTRL_LWZinto_toc                         = 604, // PPCInstrInfo.td:1878
    BCTRL_LWZinto_toc_RM                      = 605, // PPCInstrInfo.td:1906
    BCTRL_RM                                  = 606, // PPCInstrInfo.td:1853
    BCn                                       = 607, // PPCInstrInfo.td:1675
    BDNZ                                      = 608, // PPCInstrInfo.td:1704
    BDNZ8                                     = 609, // PPCInstr64Bit.td:83
    BDNZA                                     = 610, // PPCInstrInfo.td:1708
    BDNZAm                                    = 611, // PPCInstrInfo.td:1724
    BDNZAp                                    = 612, // PPCInstrInfo.td:1716
    BDNZL                                     = 613, // PPCInstrInfo.td:1800
    BDNZLA                                    = 614, // PPCInstrInfo.td:1804
    BDNZLAm                                   = 615, // PPCInstrInfo.td:1820
    BDNZLAp                                   = 616, // PPCInstrInfo.td:1812
    BDNZLR                                    = 617, // PPCInstrInfo.td:1689
    BDNZLR8                                   = 618, // PPCInstr64Bit.td:90
    BDNZLRL                                   = 619, // PPCInstrInfo.td:1826
    BDNZLRLm                                  = 620, // PPCInstrInfo.td:1834
    BDNZLRLp                                  = 621, // PPCInstrInfo.td:1830
    BDNZLRm                                   = 622, // PPCInstrInfo.td:1697
    BDNZLRp                                   = 623, // PPCInstrInfo.td:1693
    BDNZLm                                    = 624, // PPCInstrInfo.td:1816
    BDNZLp                                    = 625, // PPCInstrInfo.td:1808
    BDNZm                                     = 626, // PPCInstrInfo.td:1720
    BDNZp                                     = 627, // PPCInstrInfo.td:1712
    BDZ                                       = 628, // PPCInstrInfo.td:1702
    BDZ8                                      = 629, // PPCInstr64Bit.td:81
    BDZA                                      = 630, // PPCInstrInfo.td:1706
    BDZAm                                     = 631, // PPCInstrInfo.td:1722
    BDZAp                                     = 632, // PPCInstrInfo.td:1714
    BDZL                                      = 633, // PPCInstrInfo.td:1798
    BDZLA                                     = 634, // PPCInstrInfo.td:1802
    BDZLAm                                    = 635, // PPCInstrInfo.td:1818
    BDZLAp                                    = 636, // PPCInstrInfo.td:1810
    BDZLR                                     = 637, // PPCInstrInfo.td:1687
    BDZLR8                                    = 638, // PPCInstr64Bit.td:88
    BDZLRL                                    = 639, // PPCInstrInfo.td:1824
    BDZLRLm                                   = 640, // PPCInstrInfo.td:1832
    BDZLRLp                                   = 641, // PPCInstrInfo.td:1828
    BDZLRm                                    = 642, // PPCInstrInfo.td:1695
    BDZLRp                                    = 643, // PPCInstrInfo.td:1691
    BDZLm                                     = 644, // PPCInstrInfo.td:1814
    BDZLp                                     = 645, // PPCInstrInfo.td:1806
    BDZm                                      = 646, // PPCInstrInfo.td:1718
    BDZp                                      = 647, // PPCInstrInfo.td:1710
    BL                                        = 648, // PPCInstrInfo.td:1741
    BL8                                       = 649, // PPCInstr64Bit.td:100
    BL8_LDinto_toc                            = 650, // PPCInstr64Bit.td:213
    BL8_LDinto_toc_RM                         = 651, // PPCInstr64Bit.td:222
    BL8_NOP                                   = 652, // PPCInstr64Bit.td:110
    BL8_NOP_RM                                = 653, // PPCInstr64Bit.td:165
    BL8_NOP_TLS                               = 654, // PPCInstr64Bit.td:114
    BL8_NOTOC                                 = 655, // PPCInstr64Bit.td:127
    BL8_NOTOC_RM                              = 656, // PPCInstr64Bit.td:178
    BL8_NOTOC_TLS                             = 657, // PPCInstr64Bit.td:130
    BL8_RM                                    = 658, // PPCInstr64Bit.td:160
    BL8_TLS                                   = 659, // PPCInstr64Bit.td:103
    BL8_TLS_                                  = 660, // PPCInstr64Bit.td:237
    BLA                                       = 661, // PPCInstrInfo.td:1743
    BLA8                                      = 662, // PPCInstr64Bit.td:106
    BLA8_NOP                                  = 663, // PPCInstr64Bit.td:118
    BLA8_NOP_RM                               = 664, // PPCInstr64Bit.td:169
    BLA8_RM                                   = 665, // PPCInstr64Bit.td:163
    BLA_RM                                    = 666, // PPCInstrInfo.td:1844
    BLR                                       = 667, // PPCInstrInfo.td:1595
    BLR8                                      = 668, // PPCInstr64Bit.td:54
    BLRL                                      = 669, // PPCInstrInfo.td:1783
    BL_LWZinto_toc                            = 670, // PPCInstrInfo.td:1888
    BL_LWZinto_toc_RM                         = 671, // PPCInstrInfo.td:1896
    BL_NOP                                    = 672, // PPCInstrInfo.td:1760
    BL_NOP_RM                                 = 673, // PPCInstrInfo.td:1847
    BL_RM                                     = 674, // PPCInstrInfo.td:1842
    BL_TLS                                    = 675, // PPCInstrInfo.td:1747
    BPERMD                                    = 676, // PPCInstr64Bit.td:1007
    BRD                                       = 677, // PPCInstrP10.td:1848
    BRH                                       = 678, // PPCInstrP10.td:1837
    BRH8                                      = 679, // PPCInstrP10.td:1843
    BRINC                                     = 680, // PPCInstrSPE.td:132
    BRW                                       = 681, // PPCInstrP10.td:1839
    BRW8                                      = 682, // PPCInstrP10.td:1845
    CBCDTD                                    = 683, // PPCInstrInfo.td:2194
    CBCDTD8                                   = 684, // PPCInstr64Bit.td:1032
    CDTBCD                                    = 685, // PPCInstrInfo.td:2191
    CDTBCD8                                   = 686, // PPCInstr64Bit.td:1029
    CFUGED                                    = 687, // PPCInstrP10.td:1735
    CLRBHRB                                   = 688, // PPCInstrInfo.td:1975
    CMPB                                      = 689, // PPCInstrInfo.td:2690
    CMPB8                                     = 690, // PPCInstr64Bit.td:1013
    CMPD                                      = 691, // PPCInstr64Bit.td:891
    CMPDI                                     = 692, // PPCInstr64Bit.td:895
    CMPEQB                                    = 693, // PPCInstr64Bit.td:905
    CMPLD                                     = 694, // PPCInstr64Bit.td:893
    CMPLDI                                    = 695, // PPCInstr64Bit.td:897
    CMPLW                                     = 696, // PPCInstrInfo.td:2697
    CMPLWI                                    = 697, // PPCInstrInfo.td:2610
    CMPRB                                     = 698, // PPCInstrInfo.td:2612
    CMPRB8                                    = 699, // PPCInstr64Bit.td:901
    CMPW                                      = 700, // PPCInstrInfo.td:2695
    CMPWI                                     = 701, // PPCInstrInfo.td:2608
    CNTLZD                                    = 702, // PPCInstrInfo.td:1090
    CNTLZDM                                   = 703, // PPCInstrP10.td:1752
    CNTLZD_rec                                = 704, // PPCInstrInfo.td:1094
    CNTLZW                                    = 705, // PPCInstrInfo.td:1090
    CNTLZW8                                   = 706, // PPCInstrInfo.td:1090
    CNTLZW8_rec                               = 707, // PPCInstrInfo.td:1094
    CNTLZW_rec                                = 708, // PPCInstrInfo.td:1094
    CNTTZD                                    = 709, // PPCInstrInfo.td:1090
    CNTTZDM                                   = 710, // PPCInstrP10.td:1756
    CNTTZD_rec                                = 711, // PPCInstrInfo.td:1094
    CNTTZW                                    = 712, // PPCInstrInfo.td:1090
    CNTTZW8                                   = 713, // PPCInstrInfo.td:1090
    CNTTZW8_rec                               = 714, // PPCInstrInfo.td:1094
    CNTTZW_rec                                = 715, // PPCInstrInfo.td:1094
    CP_ABORT                                  = 716, // PPCInstrInfo.td:5386
    CP_COPY                                   = 717, // PPCInstrInfo.td:5380
    CP_COPY8                                  = 718, // PPCInstr64Bit.td:2003
    CP_PASTE8_rec                             = 719, // PPCInstr64Bit.td:2004
    CP_PASTE_rec                              = 720, // PPCInstrInfo.td:5383
    CR6SET                                    = 721, // PPCInstrInfo.td:2913
    CR6UNSET                                  = 722, // PPCInstrInfo.td:2917
    CRAND                                     = 723, // PPCInstrInfo.td:2856
    CRANDC                                    = 724, // PPCInstrInfo.td:2891
    CREQV                                     = 725, // PPCInstrInfo.td:2880
    CRNAND                                    = 726, // PPCInstrInfo.td:2861
    CRNOR                                     = 727, // PPCInstrInfo.td:2876
    CRNOT                                     = 728, // PPCInstrInfo.td:2887
    CROR                                      = 729, // PPCInstrInfo.td:2866
    CRORC                                     = 730, // PPCInstrInfo.td:2896
    CRSET                                     = 731, // PPCInstrInfo.td:2903
    CRUNSET                                   = 732, // PPCInstrInfo.td:2907
    CRXOR                                     = 733, // PPCInstrInfo.td:2871
    CTRL_DEP                                  = 734, // PPCInstrInfo.td:1659
    DADD                                      = 735, // PPCInstrInfo.td:1344
    DADDQ                                     = 736, // PPCInstrInfo.td:1344
    DADDQ_rec                                 = 737, // PPCInstrInfo.td:1348
    DADD_rec                                  = 738, // PPCInstrInfo.td:1348
    DARN                                      = 739, // PPCInstr64Bit.td:1095
    DCBA                                      = 740, // PPCInstrInfo.td:1988
    DCBF                                      = 741, // PPCInstrInfo.td:2004
    DCBFEP                                    = 742, // PPCInstrInfo.td:4769
    DCBI                                      = 743, // PPCInstrInfo.td:1991
    DCBST                                     = 744, // PPCInstrInfo.td:1994
    DCBSTEP                                   = 745, // PPCInstrInfo.td:4772
    DCBT                                      = 746, // PPCInstrInfo.td:2009
    DCBTEP                                    = 747, // PPCInstrInfo.td:4775
    DCBTST                                    = 748, // PPCInstrInfo.td:2012
    DCBTSTEP                                  = 749, // PPCInstrInfo.td:4779
    DCBZ                                      = 750, // PPCInstrInfo.td:1997
    DCBZEP                                    = 751, // PPCInstrInfo.td:4783
    DCBZL                                     = 752, // PPCInstrInfo.td:2000
    DCBZLEP                                   = 753, // PPCInstrInfo.td:4786
    DCCCI                                     = 754, // PPCInstrInfo.td:4550
    DCFFIX                                    = 755, // PPCInstrInfo.td:1330
    DCFFIXQ                                   = 756, // PPCInstrInfo.td:1330
    DCFFIXQQ                                  = 757, // PPCInstrDFP.td:110
    DCFFIXQ_rec                               = 758, // PPCInstrInfo.td:1334
    DCFFIX_rec                                = 759, // PPCInstrInfo.td:1334
    DCMPO                                     = 760, // PPCInstrDFP.td:53
    DCMPOQ                                    = 761, // PPCInstrDFP.td:56
    DCMPU                                     = 762, // PPCInstrDFP.td:47
    DCMPUQ                                    = 763, // PPCInstrDFP.td:50
    DCTDP                                     = 764, // PPCInstrInfo.td:1330
    DCTDP_rec                                 = 765, // PPCInstrInfo.td:1334
    DCTFIX                                    = 766, // PPCInstrInfo.td:1330
    DCTFIXQ                                   = 767, // PPCInstrInfo.td:1330
    DCTFIXQQ                                  = 768, // PPCInstrDFP.td:113
    DCTFIXQ_rec                               = 769, // PPCInstrInfo.td:1334
    DCTFIX_rec                                = 770, // PPCInstrInfo.td:1334
    DCTQPQ                                    = 771, // PPCInstrInfo.td:1330
    DCTQPQ_rec                                = 772, // PPCInstrInfo.td:1334
    DDEDPD                                    = 773, // PPCInstrInfo.td:1357
    DDEDPDQ                                   = 774, // PPCInstrInfo.td:1357
    DDEDPDQ_rec                               = 775, // PPCInstrInfo.td:1361
    DDEDPD_rec                                = 776, // PPCInstrInfo.td:1361
    DDIV                                      = 777, // PPCInstrInfo.td:1344
    DDIVQ                                     = 778, // PPCInstrInfo.td:1344
    DDIVQ_rec                                 = 779, // PPCInstrInfo.td:1348
    DDIV_rec                                  = 780, // PPCInstrInfo.td:1348
    DENBCD                                    = 781, // PPCInstrInfo.td:1370
    DENBCDQ                                   = 782, // PPCInstrInfo.td:1370
    DENBCDQ_rec                               = 783, // PPCInstrInfo.td:1374
    DENBCD_rec                                = 784, // PPCInstrInfo.td:1374
    DIEX                                      = 785, // PPCInstrInfo.td:1032
    DIEXQ                                     = 786, // PPCInstrInfo.td:1032
    DIEXQ_rec                                 = 787, // PPCInstrInfo.td:1036
    DIEX_rec                                  = 788, // PPCInstrInfo.td:1036
    DIVD                                      = 789, // PPCInstrInfo.td:1146
    DIVDE                                     = 790, // PPCInstrInfo.td:1146
    DIVDEO                                    = 791, // PPCInstrInfo.td:1157
    DIVDEO_rec                                = 792, // PPCInstrInfo.td:1161
    DIVDEU                                    = 793, // PPCInstrInfo.td:1146
    DIVDEUO                                   = 794, // PPCInstrInfo.td:1157
    DIVDEUO_rec                               = 795, // PPCInstrInfo.td:1161
    DIVDEU_rec                                = 796, // PPCInstrInfo.td:1150
    DIVDE_rec                                 = 797, // PPCInstrInfo.td:1150
    DIVDO                                     = 798, // PPCInstrInfo.td:1157
    DIVDO_rec                                 = 799, // PPCInstrInfo.td:1161
    DIVDU                                     = 800, // PPCInstrInfo.td:1146
    DIVDUO                                    = 801, // PPCInstrInfo.td:1157
    DIVDUO_rec                                = 802, // PPCInstrInfo.td:1161
    DIVDU_rec                                 = 803, // PPCInstrInfo.td:1150
    DIVD_rec                                  = 804, // PPCInstrInfo.td:1150
    DIVW                                      = 805, // PPCInstrInfo.td:1146
    DIVWE                                     = 806, // PPCInstrInfo.td:1146
    DIVWEO                                    = 807, // PPCInstrInfo.td:1157
    DIVWEO_rec                                = 808, // PPCInstrInfo.td:1161
    DIVWEU                                    = 809, // PPCInstrInfo.td:1146
    DIVWEUO                                   = 810, // PPCInstrInfo.td:1157
    DIVWEUO_rec                               = 811, // PPCInstrInfo.td:1161
    DIVWEU_rec                                = 812, // PPCInstrInfo.td:1150
    DIVWE_rec                                 = 813, // PPCInstrInfo.td:1150
    DIVWO                                     = 814, // PPCInstrInfo.td:1157
    DIVWO_rec                                 = 815, // PPCInstrInfo.td:1161
    DIVWU                                     = 816, // PPCInstrInfo.td:1146
    DIVWUO                                    = 817, // PPCInstrInfo.td:1157
    DIVWUO_rec                                = 818, // PPCInstrInfo.td:1161
    DIVWU_rec                                 = 819, // PPCInstrInfo.td:1150
    DIVW_rec                                  = 820, // PPCInstrInfo.td:1150
    DMMR                                      = 821, // PPCInstrFutureMMA.td:477
    DMSETDMRZ                                 = 822, // PPCInstrFutureMMA.td:487
    DMSHA2HASH                                = 823, // PPCInstrFutureMMA.td:510
    DMSHA3HASH                                = 824, // PPCInstrFutureMMA.td:517
    DMUL                                      = 825, // PPCInstrInfo.td:1344
    DMULQ                                     = 826, // PPCInstrInfo.td:1344
    DMULQ_rec                                 = 827, // PPCInstrInfo.td:1348
    DMUL_rec                                  = 828, // PPCInstrInfo.td:1348
    DMXOR                                     = 829, // PPCInstrFutureMMA.td:481
    DMXVBF16GERX2                             = 830, // PPCInstrFutureMMA.td:221
    DMXVBF16GERX2NN                           = 831, // PPCInstrFutureMMA.td:291
    DMXVBF16GERX2NP                           = 832, // PPCInstrFutureMMA.td:286
    DMXVBF16GERX2PN                           = 833, // PPCInstrFutureMMA.td:281
    DMXVBF16GERX2PP                           = 834, // PPCInstrFutureMMA.td:225
    DMXVF16GERX2                              = 835, // PPCInstrFutureMMA.td:184
    DMXVF16GERX2NN                            = 836, // PPCInstrFutureMMA.td:339
    DMXVF16GERX2NP                            = 837, // PPCInstrFutureMMA.td:334
    DMXVF16GERX2PN                            = 838, // PPCInstrFutureMMA.td:329
    DMXVF16GERX2PP                            = 839, // PPCInstrFutureMMA.td:188
    DMXVI8GERX4                               = 840, // PPCInstrFutureMMA.td:184
    DMXVI8GERX4PP                             = 841, // PPCInstrFutureMMA.td:188
    DMXVI8GERX4SPP                            = 842, // PPCInstrFutureMMA.td:532
    DMXXEXTFDMR256                            = 843, // PPCInstrFutureMMA.td:468
    DMXXEXTFDMR512                            = 844, // PPCInstrFutureMMA.td:436
    DMXXEXTFDMR512_HI                         = 845, // PPCInstrFutureMMA.td:443
    DMXXINSTDMR256                            = 846, // PPCInstrFutureMMA.td:472
    DMXXINSTDMR512                            = 847, // PPCInstrFutureMMA.td:450
    DMXXINSTDMR512_HI                         = 848, // PPCInstrFutureMMA.td:459
    DMXXSETACCZ                               = 849, // PPCInstrMMA.td:553
    DMXXSHAPAD                                = 850, // PPCInstrFutureMMA.td:524
    DQUA                                      = 851, // PPCInstrInfo.td:1441
    DQUAI                                     = 852, // PPCInstrInfo.td:1426
    DQUAIQ                                    = 853, // PPCInstrInfo.td:1426
    DQUAIQ_rec                                = 854, // PPCInstrInfo.td:1431
    DQUAI_rec                                 = 855, // PPCInstrInfo.td:1431
    DQUAQ                                     = 856, // PPCInstrInfo.td:1441
    DQUAQ_rec                                 = 857, // PPCInstrInfo.td:1445
    DQUA_rec                                  = 858, // PPCInstrInfo.td:1445
    DRDPQ                                     = 859, // PPCInstrInfo.td:1330
    DRDPQ_rec                                 = 860, // PPCInstrInfo.td:1334
    DRINTN                                    = 861, // PPCInstrInfo.td:1455
    DRINTNQ                                   = 862, // PPCInstrInfo.td:1455
    DRINTNQ_rec                               = 863, // PPCInstrInfo.td:1459
    DRINTN_rec                                = 864, // PPCInstrInfo.td:1459
    DRINTX                                    = 865, // PPCInstrInfo.td:1455
    DRINTXQ                                   = 866, // PPCInstrInfo.td:1455
    DRINTXQ_rec                               = 867, // PPCInstrInfo.td:1459
    DRINTX_rec                                = 868, // PPCInstrInfo.td:1459
    DRRND                                     = 869, // PPCInstrInfo.td:1441
    DRRNDQ                                    = 870, // PPCInstrInfo.td:1441
    DRRNDQ_rec                                = 871, // PPCInstrInfo.td:1445
    DRRND_rec                                 = 872, // PPCInstrInfo.td:1445
    DRSP                                      = 873, // PPCInstrInfo.td:1330
    DRSP_rec                                  = 874, // PPCInstrInfo.td:1334
    DSCLI                                     = 875, // PPCInstrInfo.td:1468
    DSCLIQ                                    = 876, // PPCInstrInfo.td:1468
    DSCLIQ_rec                                = 877, // PPCInstrInfo.td:1472
    DSCLI_rec                                 = 878, // PPCInstrInfo.td:1472
    DSCRI                                     = 879, // PPCInstrInfo.td:1468
    DSCRIQ                                    = 880, // PPCInstrInfo.td:1468
    DSCRIQ_rec                                = 881, // PPCInstrInfo.td:1472
    DSCRI_rec                                 = 882, // PPCInstrInfo.td:1472
    DSS                                       = 883, // PPCInstrAltivec.td:354
    DSSALL                                    = 884, // PPCInstrAltivec.td:361
    DST                                       = 885, // PPCInstrAltivec.td:369
    DST64                                     = 886, // PPCInstrAltivec.td:391
    DSTST                                     = 887, // PPCInstrAltivec.td:379
    DSTST64                                   = 888, // PPCInstrAltivec.td:401
    DSTSTT                                    = 889, // PPCInstrAltivec.td:384
    DSTSTT64                                  = 890, // PPCInstrAltivec.td:407
    DSTT                                      = 891, // PPCInstrAltivec.td:374
    DSTT64                                    = 892, // PPCInstrAltivec.td:396
    DSUB                                      = 893, // PPCInstrInfo.td:1344
    DSUBQ                                     = 894, // PPCInstrInfo.td:1344
    DSUBQ_rec                                 = 895, // PPCInstrInfo.td:1348
    DSUB_rec                                  = 896, // PPCInstrInfo.td:1348
    DTSTDC                                    = 897, // PPCInstrDFP.td:157
    DTSTDCQ                                   = 898, // PPCInstrDFP.td:161
    DTSTDG                                    = 899, // PPCInstrDFP.td:165
    DTSTDGQ                                   = 900, // PPCInstrDFP.td:169
    DTSTEX                                    = 901, // PPCInstrDFP.td:173
    DTSTEXQ                                   = 902, // PPCInstrDFP.td:176
    DTSTSF                                    = 903, // PPCInstrDFP.td:179
    DTSTSFI                                   = 904, // PPCInstrDFP.td:185
    DTSTSFIQ                                  = 905, // PPCInstrDFP.td:189
    DTSTSFQ                                   = 906, // PPCInstrDFP.td:182
    DXEX                                      = 907, // PPCInstrInfo.td:1330
    DXEXQ                                     = 908, // PPCInstrInfo.td:1330
    DXEXQ_rec                                 = 909, // PPCInstrInfo.td:1334
    DXEX_rec                                  = 910, // PPCInstrInfo.td:1334
    DYNALLOC                                  = 911, // PPCInstrInfo.td:1499
    DYNALLOC8                                 = 912, // PPCInstr64Bit.td:577
    DYNAREAOFFSET                             = 913, // PPCInstrInfo.td:1502
    DYNAREAOFFSET8                            = 914, // PPCInstr64Bit.td:580
    DecreaseCTR8loop                          = 915, // PPCInstr64Bit.td:564
    DecreaseCTRloop                           = 916, // PPCInstrInfo.td:2965
    EFDABS                                    = 917, // PPCInstrSPE.td:136
    EFDADD                                    = 918, // PPCInstrSPE.td:140
    EFDCFS                                    = 919, // PPCInstrSPE.td:144
    EFDCFSF                                   = 920, // PPCInstrSPE.td:148
    EFDCFSI                                   = 921, // PPCInstrSPE.td:151
    EFDCFSID                                  = 922, // PPCInstrSPE.td:155
    EFDCFUF                                   = 923, // PPCInstrSPE.td:159
    EFDCFUI                                   = 924, // PPCInstrSPE.td:162
    EFDCFUID                                  = 925, // PPCInstrSPE.td:166
    EFDCMPEQ                                  = 926, // PPCInstrSPE.td:171
    EFDCMPGT                                  = 927, // PPCInstrSPE.td:173
    EFDCMPLT                                  = 928, // PPCInstrSPE.td:175
    EFDCTSF                                   = 929, // PPCInstrSPE.td:179
    EFDCTSI                                   = 930, // PPCInstrSPE.td:182
    EFDCTSIDZ                                 = 931, // PPCInstrSPE.td:186
    EFDCTSIZ                                  = 932, // PPCInstrSPE.td:190
    EFDCTUF                                   = 933, // PPCInstrSPE.td:194
    EFDCTUI                                   = 934, // PPCInstrSPE.td:197
    EFDCTUIDZ                                 = 935, // PPCInstrSPE.td:201
    EFDCTUIZ                                  = 936, // PPCInstrSPE.td:205
    EFDDIV                                    = 937, // PPCInstrSPE.td:209
    EFDMUL                                    = 938, // PPCInstrSPE.td:213
    EFDNABS                                   = 939, // PPCInstrSPE.td:217
    EFDNEG                                    = 940, // PPCInstrSPE.td:221
    EFDSUB                                    = 941, // PPCInstrSPE.td:225
    EFDTSTEQ                                  = 942, // PPCInstrSPE.td:230
    EFDTSTGT                                  = 943, // PPCInstrSPE.td:232
    EFDTSTLT                                  = 944, // PPCInstrSPE.td:234
    EFSABS                                    = 945, // PPCInstrSPE.td:239
    EFSADD                                    = 946, // PPCInstrSPE.td:243
    EFSCFD                                    = 947, // PPCInstrSPE.td:247
    EFSCFSF                                   = 948, // PPCInstrSPE.td:251
    EFSCFSI                                   = 949, // PPCInstrSPE.td:254
    EFSCFUF                                   = 950, // PPCInstrSPE.td:258
    EFSCFUI                                   = 951, // PPCInstrSPE.td:261
    EFSCMPEQ                                  = 952, // PPCInstrSPE.td:266
    EFSCMPGT                                  = 953, // PPCInstrSPE.td:268
    EFSCMPLT                                  = 954, // PPCInstrSPE.td:270
    EFSCTSF                                   = 955, // PPCInstrSPE.td:274
    EFSCTSI                                   = 956, // PPCInstrSPE.td:277
    EFSCTSIZ                                  = 957, // PPCInstrSPE.td:281
    EFSCTUF                                   = 958, // PPCInstrSPE.td:285
    EFSCTUI                                   = 959, // PPCInstrSPE.td:288
    EFSCTUIZ                                  = 960, // PPCInstrSPE.td:292
    EFSDIV                                    = 961, // PPCInstrSPE.td:296
    EFSMUL                                    = 962, // PPCInstrSPE.td:300
    EFSNABS                                   = 963, // PPCInstrSPE.td:304
    EFSNEG                                    = 964, // PPCInstrSPE.td:308
    EFSSUB                                    = 965, // PPCInstrSPE.td:312
    EFSTSTEQ                                  = 966, // PPCInstrSPE.td:317
    EFSTSTGT                                  = 967, // PPCInstrSPE.td:319
    EFSTSTLT                                  = 968, // PPCInstrSPE.td:321
    EH_SjLj_LongJmp32                         = 969, // PPCInstrInfo.td:1946
    EH_SjLj_LongJmp64                         = 970, // PPCInstr64Bit.td:529
    EH_SjLj_SetJmp32                          = 971, // PPCInstrInfo.td:1938
    EH_SjLj_SetJmp64                          = 972, // PPCInstr64Bit.td:521
    EH_SjLj_Setup                             = 973, // PPCInstrInfo.td:1956
    EQV                                       = 974, // PPCInstrInfo.td:1046
    EQV8                                      = 975, // PPCInstrInfo.td:1046
    EQV8_rec                                  = 976, // PPCInstrInfo.td:1050
    EQV_rec                                   = 977, // PPCInstrInfo.td:1050
    EVABS                                     = 978, // PPCInstrSPE.td:327
    EVADDIW                                   = 979, // PPCInstrSPE.td:331
    EVADDSMIAAW                               = 980, // PPCInstrSPE.td:333
    EVADDSSIAAW                               = 981, // PPCInstrSPE.td:335
    EVADDUMIAAW                               = 982, // PPCInstrSPE.td:339
    EVADDUSIAAW                               = 983, // PPCInstrSPE.td:337
    EVADDW                                    = 984, // PPCInstrSPE.td:341
    EVAND                                     = 985, // PPCInstrSPE.td:345
    EVANDC                                    = 986, // PPCInstrSPE.td:348
    EVCMPEQ                                   = 987, // PPCInstrSPE.td:353
    EVCMPGTS                                  = 988, // PPCInstrSPE.td:355
    EVCMPGTU                                  = 989, // PPCInstrSPE.td:357
    EVCMPLTS                                  = 990, // PPCInstrSPE.td:359
    EVCMPLTU                                  = 991, // PPCInstrSPE.td:361
    EVCNTLSW                                  = 992, // PPCInstrSPE.td:365
    EVCNTLZW                                  = 993, // PPCInstrSPE.td:367
    EVDIVWS                                   = 994, // PPCInstrSPE.td:371
    EVDIVWU                                   = 995, // PPCInstrSPE.td:374
    EVEQV                                     = 996, // PPCInstrSPE.td:378
    EVEXTSB                                   = 997, // PPCInstrSPE.td:382
    EVEXTSH                                   = 998, // PPCInstrSPE.td:385
    EVFSABS                                   = 999, // PPCInstrSPE.td:389
    EVFSADD                                   = 1000, // PPCInstrSPE.td:392
    EVFSCFSF                                  = 1001, // PPCInstrSPE.td:395
    EVFSCFSI                                  = 1002, // PPCInstrSPE.td:397
    EVFSCFUF                                  = 1003, // PPCInstrSPE.td:400
    EVFSCFUI                                  = 1004, // PPCInstrSPE.td:402
    EVFSCMPEQ                                 = 1005, // PPCInstrSPE.td:406
    EVFSCMPGT                                 = 1006, // PPCInstrSPE.td:408
    EVFSCMPLT                                 = 1007, // PPCInstrSPE.td:410
    EVFSCTSF                                  = 1008, // PPCInstrSPE.td:414
    EVFSCTSI                                  = 1009, // PPCInstrSPE.td:416
    EVFSCTSIZ                                 = 1010, // PPCInstrSPE.td:419
    EVFSCTUF                                  = 1011, // PPCInstrSPE.td:422
    EVFSCTUI                                  = 1012, // PPCInstrSPE.td:424
    EVFSCTUIZ                                 = 1013, // PPCInstrSPE.td:427
    EVFSDIV                                   = 1014, // PPCInstrSPE.td:430
    EVFSMUL                                   = 1015, // PPCInstrSPE.td:433
    EVFSNABS                                  = 1016, // PPCInstrSPE.td:436
    EVFSNEG                                   = 1017, // PPCInstrSPE.td:439
    EVFSSUB                                   = 1018, // PPCInstrSPE.td:442
    EVFSTSTEQ                                 = 1019, // PPCInstrSPE.td:447
    EVFSTSTGT                                 = 1020, // PPCInstrSPE.td:449
    EVFSTSTLT                                 = 1021, // PPCInstrSPE.td:451
    EVLDD                                     = 1022, // PPCInstrSPE.td:455
    EVLDDX                                    = 1023, // PPCInstrSPE.td:458
    EVLDH                                     = 1024, // PPCInstrSPE.td:461
    EVLDHX                                    = 1025, // PPCInstrSPE.td:463
    EVLDW                                     = 1026, // PPCInstrSPE.td:465
    EVLDWX                                    = 1027, // PPCInstrSPE.td:468
    EVLHHESPLAT                               = 1028, // PPCInstrSPE.td:471
    EVLHHESPLATX                              = 1029, // PPCInstrSPE.td:473
    EVLHHOSSPLAT                              = 1030, // PPCInstrSPE.td:479
    EVLHHOSSPLATX                             = 1031, // PPCInstrSPE.td:481
    EVLHHOUSPLAT                              = 1032, // PPCInstrSPE.td:475
    EVLHHOUSPLATX                             = 1033, // PPCInstrSPE.td:477
    EVLWHE                                    = 1034, // PPCInstrSPE.td:483
    EVLWHEX                                   = 1035, // PPCInstrSPE.td:485
    EVLWHOS                                   = 1036, // PPCInstrSPE.td:487
    EVLWHOSX                                  = 1037, // PPCInstrSPE.td:489
    EVLWHOU                                   = 1038, // PPCInstrSPE.td:491
    EVLWHOUX                                  = 1039, // PPCInstrSPE.td:493
    EVLWHSPLAT                                = 1040, // PPCInstrSPE.td:495
    EVLWHSPLATX                               = 1041, // PPCInstrSPE.td:497
    EVLWWSPLAT                                = 1042, // PPCInstrSPE.td:499
    EVLWWSPLATX                               = 1043, // PPCInstrSPE.td:501
    EVMERGEHI                                 = 1044, // PPCInstrSPE.td:504
    EVMERGEHILO                               = 1045, // PPCInstrSPE.td:508
    EVMERGELO                                 = 1046, // PPCInstrSPE.td:506
    EVMERGELOHI                               = 1047, // PPCInstrSPE.td:510
    EVMHEGSMFAA                               = 1048, // PPCInstrSPE.td:513
    EVMHEGSMFAN                               = 1049, // PPCInstrSPE.td:515
    EVMHEGSMIAA                               = 1050, // PPCInstrSPE.td:517
    EVMHEGSMIAN                               = 1051, // PPCInstrSPE.td:519
    EVMHEGUMIAA                               = 1052, // PPCInstrSPE.td:521
    EVMHEGUMIAN                               = 1053, // PPCInstrSPE.td:523
    EVMHESMF                                  = 1054, // PPCInstrSPE.td:526
    EVMHESMFA                                 = 1055, // PPCInstrSPE.td:528
    EVMHESMFAAW                               = 1056, // PPCInstrSPE.td:530
    EVMHESMFANW                               = 1057, // PPCInstrSPE.td:532
    EVMHESMI                                  = 1058, // PPCInstrSPE.td:534
    EVMHESMIA                                 = 1059, // PPCInstrSPE.td:536
    EVMHESMIAAW                               = 1060, // PPCInstrSPE.td:538
    EVMHESMIANW                               = 1061, // PPCInstrSPE.td:540
    EVMHESSF                                  = 1062, // PPCInstrSPE.td:542
    EVMHESSFA                                 = 1063, // PPCInstrSPE.td:544
    EVMHESSFAAW                               = 1064, // PPCInstrSPE.td:546
    EVMHESSFANW                               = 1065, // PPCInstrSPE.td:548
    EVMHESSIAAW                               = 1066, // PPCInstrSPE.td:550
    EVMHESSIANW                               = 1067, // PPCInstrSPE.td:552
    EVMHEUMI                                  = 1068, // PPCInstrSPE.td:554
    EVMHEUMIA                                 = 1069, // PPCInstrSPE.td:556
    EVMHEUMIAAW                               = 1070, // PPCInstrSPE.td:558
    EVMHEUMIANW                               = 1071, // PPCInstrSPE.td:560
    EVMHEUSIAAW                               = 1072, // PPCInstrSPE.td:562
    EVMHEUSIANW                               = 1073, // PPCInstrSPE.td:564
    EVMHOGSMFAA                               = 1074, // PPCInstrSPE.td:566
    EVMHOGSMFAN                               = 1075, // PPCInstrSPE.td:568
    EVMHOGSMIAA                               = 1076, // PPCInstrSPE.td:570
    EVMHOGSMIAN                               = 1077, // PPCInstrSPE.td:572
    EVMHOGUMIAA                               = 1078, // PPCInstrSPE.td:574
    EVMHOGUMIAN                               = 1079, // PPCInstrSPE.td:576
    EVMHOSMF                                  = 1080, // PPCInstrSPE.td:578
    EVMHOSMFA                                 = 1081, // PPCInstrSPE.td:580
    EVMHOSMFAAW                               = 1082, // PPCInstrSPE.td:582
    EVMHOSMFANW                               = 1083, // PPCInstrSPE.td:584
    EVMHOSMI                                  = 1084, // PPCInstrSPE.td:586
    EVMHOSMIA                                 = 1085, // PPCInstrSPE.td:588
    EVMHOSMIAAW                               = 1086, // PPCInstrSPE.td:590
    EVMHOSMIANW                               = 1087, // PPCInstrSPE.td:592
    EVMHOSSF                                  = 1088, // PPCInstrSPE.td:594
    EVMHOSSFA                                 = 1089, // PPCInstrSPE.td:596
    EVMHOSSFAAW                               = 1090, // PPCInstrSPE.td:598
    EVMHOSSFANW                               = 1091, // PPCInstrSPE.td:600
    EVMHOSSIAAW                               = 1092, // PPCInstrSPE.td:602
    EVMHOSSIANW                               = 1093, // PPCInstrSPE.td:604
    EVMHOUMI                                  = 1094, // PPCInstrSPE.td:606
    EVMHOUMIA                                 = 1095, // PPCInstrSPE.td:608
    EVMHOUMIAAW                               = 1096, // PPCInstrSPE.td:610
    EVMHOUMIANW                               = 1097, // PPCInstrSPE.td:612
    EVMHOUSIAAW                               = 1098, // PPCInstrSPE.td:614
    EVMHOUSIANW                               = 1099, // PPCInstrSPE.td:616
    EVMRA                                     = 1100, // PPCInstrSPE.td:619
    EVMWHSMF                                  = 1101, // PPCInstrSPE.td:622
    EVMWHSMFA                                 = 1102, // PPCInstrSPE.td:624
    EVMWHSMI                                  = 1103, // PPCInstrSPE.td:626
    EVMWHSMIA                                 = 1104, // PPCInstrSPE.td:628
    EVMWHSSF                                  = 1105, // PPCInstrSPE.td:630
    EVMWHSSFA                                 = 1106, // PPCInstrSPE.td:632
    EVMWHUMI                                  = 1107, // PPCInstrSPE.td:634
    EVMWHUMIA                                 = 1108, // PPCInstrSPE.td:636
    EVMWLSMIAAW                               = 1109, // PPCInstrSPE.td:638
    EVMWLSMIANW                               = 1110, // PPCInstrSPE.td:640
    EVMWLSSIAAW                               = 1111, // PPCInstrSPE.td:642
    EVMWLSSIANW                               = 1112, // PPCInstrSPE.td:644
    EVMWLUMI                                  = 1113, // PPCInstrSPE.td:646
    EVMWLUMIA                                 = 1114, // PPCInstrSPE.td:649
    EVMWLUMIAAW                               = 1115, // PPCInstrSPE.td:651
    EVMWLUMIANW                               = 1116, // PPCInstrSPE.td:653
    EVMWLUSIAAW                               = 1117, // PPCInstrSPE.td:655
    EVMWLUSIANW                               = 1118, // PPCInstrSPE.td:657
    EVMWSMF                                   = 1119, // PPCInstrSPE.td:659
    EVMWSMFA                                  = 1120, // PPCInstrSPE.td:661
    EVMWSMFAA                                 = 1121, // PPCInstrSPE.td:663
    EVMWSMFAN                                 = 1122, // PPCInstrSPE.td:665
    EVMWSMI                                   = 1123, // PPCInstrSPE.td:667
    EVMWSMIA                                  = 1124, // PPCInstrSPE.td:669
    EVMWSMIAA                                 = 1125, // PPCInstrSPE.td:671
    EVMWSMIAN                                 = 1126, // PPCInstrSPE.td:673
    EVMWSSF                                   = 1127, // PPCInstrSPE.td:675
    EVMWSSFA                                  = 1128, // PPCInstrSPE.td:677
    EVMWSSFAA                                 = 1129, // PPCInstrSPE.td:679
    EVMWSSFAN                                 = 1130, // PPCInstrSPE.td:681
    EVMWUMI                                   = 1131, // PPCInstrSPE.td:683
    EVMWUMIA                                  = 1132, // PPCInstrSPE.td:685
    EVMWUMIAA                                 = 1133, // PPCInstrSPE.td:687
    EVMWUMIAN                                 = 1134, // PPCInstrSPE.td:689
    EVNAND                                    = 1135, // PPCInstrSPE.td:693
    EVNEG                                     = 1136, // PPCInstrSPE.td:697
    EVNOR                                     = 1137, // PPCInstrSPE.td:701
    EVOR                                      = 1138, // PPCInstrSPE.td:704
    EVORC                                     = 1139, // PPCInstrSPE.td:707
    EVRLW                                     = 1140, // PPCInstrSPE.td:713
    EVRLWI                                    = 1141, // PPCInstrSPE.td:711
    EVRNDW                                    = 1142, // PPCInstrSPE.td:717
    EVSEL                                     = 1143, // PPCInstrSPE.td:720
    EVSLW                                     = 1144, // PPCInstrSPE.td:726
    EVSLWI                                    = 1145, // PPCInstrSPE.td:724
    EVSPLATFI                                 = 1146, // PPCInstrSPE.td:730
    EVSPLATI                                  = 1147, // PPCInstrSPE.td:732
    EVSRWIS                                   = 1148, // PPCInstrSPE.td:735
    EVSRWIU                                   = 1149, // PPCInstrSPE.td:737
    EVSRWS                                    = 1150, // PPCInstrSPE.td:739
    EVSRWU                                    = 1151, // PPCInstrSPE.td:742
    EVSTDD                                    = 1152, // PPCInstrSPE.td:746
    EVSTDDX                                   = 1153, // PPCInstrSPE.td:749
    EVSTDH                                    = 1154, // PPCInstrSPE.td:752
    EVSTDHX                                   = 1155, // PPCInstrSPE.td:754
    EVSTDW                                    = 1156, // PPCInstrSPE.td:756
    EVSTDWX                                   = 1157, // PPCInstrSPE.td:759
    EVSTWHE                                   = 1158, // PPCInstrSPE.td:762
    EVSTWHEX                                  = 1159, // PPCInstrSPE.td:764
    EVSTWHO                                   = 1160, // PPCInstrSPE.td:766
    EVSTWHOX                                  = 1161, // PPCInstrSPE.td:768
    EVSTWWE                                   = 1162, // PPCInstrSPE.td:770
    EVSTWWEX                                  = 1163, // PPCInstrSPE.td:772
    EVSTWWO                                   = 1164, // PPCInstrSPE.td:774
    EVSTWWOX                                  = 1165, // PPCInstrSPE.td:776
    EVSUBFSMIAAW                              = 1166, // PPCInstrSPE.td:781
    EVSUBFSSIAAW                              = 1167, // PPCInstrSPE.td:779
    EVSUBFUMIAAW                              = 1168, // PPCInstrSPE.td:783
    EVSUBFUSIAAW                              = 1169, // PPCInstrSPE.td:785
    EVSUBFW                                   = 1170, // PPCInstrSPE.td:787
    EVSUBIFW                                  = 1171, // PPCInstrSPE.td:790
    EVXOR                                     = 1172, // PPCInstrSPE.td:792
    EXTSB                                     = 1173, // PPCInstrInfo.td:1090
    EXTSB8                                    = 1174, // PPCInstrInfo.td:1090
    EXTSB8_32_64                              = 1175, // PPCInstr64Bit.td:952
    EXTSB8_rec                                = 1176, // PPCInstrInfo.td:1094
    EXTSB_rec                                 = 1177, // PPCInstrInfo.td:1094
    EXTSH                                     = 1178, // PPCInstrInfo.td:1090
    EXTSH8                                    = 1179, // PPCInstrInfo.td:1090
    EXTSH8_32_64                              = 1180, // PPCInstr64Bit.td:955
    EXTSH8_rec                                = 1181, // PPCInstrInfo.td:1094
    EXTSH_rec                                 = 1182, // PPCInstrInfo.td:1094
    EXTSW                                     = 1183, // PPCInstrInfo.td:1090
    EXTSWSLI                                  = 1184, // PPCInstrInfo.td:1302
    EXTSWSLI_32_64                            = 1185, // PPCInstrInfo.td:1316
    EXTSWSLI_32_64_rec                        = 1186, // PPCInstrInfo.td:1320
    EXTSWSLI_rec                              = 1187, // PPCInstrInfo.td:1306
    EXTSW_32                                  = 1188, // PPCInstr64Bit.td:970
    EXTSW_32_64                               = 1189, // PPCInstrInfo.td:1090
    EXTSW_32_64_rec                           = 1190, // PPCInstrInfo.td:1094
    EXTSW_rec                                 = 1191, // PPCInstrInfo.td:1094
    EnforceIEIO                               = 1192, // PPCInstrInfo.td:2505
    FABSD                                     = 1193, // PPCInstrInfo.td:1330
    FABSD_rec                                 = 1194, // PPCInstrInfo.td:1334
    FABSS                                     = 1195, // PPCInstrInfo.td:1330
    FABSS_rec                                 = 1196, // PPCInstrInfo.td:1334
    FADD                                      = 1197, // PPCInstrInfo.td:1398
    FADDS                                     = 1198, // PPCInstrInfo.td:1398
    FADDS_rec                                 = 1199, // PPCInstrInfo.td:1402
    FADD_rec                                  = 1200, // PPCInstrInfo.td:1402
    FADDrtz                                   = 1201, // PPCInstrInfo.td:3062
    FCFID                                     = 1202, // PPCInstrInfo.td:1330
    FCFIDS                                    = 1203, // PPCInstrInfo.td:1330
    FCFIDS_rec                                = 1204, // PPCInstrInfo.td:1334
    FCFIDU                                    = 1205, // PPCInstrInfo.td:1330
    FCFIDUS                                   = 1206, // PPCInstrInfo.td:1330
    FCFIDUS_rec                               = 1207, // PPCInstrInfo.td:1334
    FCFIDU_rec                                = 1208, // PPCInstrInfo.td:1334
    FCFID_rec                                 = 1209, // PPCInstrInfo.td:1334
    FCMPOD                                    = 1210, // PPCInstrInfo.td:2710
    FCMPOS                                    = 1211, // PPCInstrInfo.td:2705
    FCMPUD                                    = 1212, // PPCInstrInfo.td:2708
    FCMPUS                                    = 1213, // PPCInstrInfo.td:2703
    FCPSGND                                   = 1214, // PPCInstrInfo.td:1344
    FCPSGND_rec                               = 1215, // PPCInstrInfo.td:1348
    FCPSGNS                                   = 1216, // PPCInstrInfo.td:1344
    FCPSGNS_rec                               = 1217, // PPCInstrInfo.td:1348
    FCTID                                     = 1218, // PPCInstrInfo.td:1330
    FCTIDU                                    = 1219, // PPCInstrInfo.td:1330
    FCTIDUZ                                   = 1220, // PPCInstrInfo.td:1330
    FCTIDUZ_rec                               = 1221, // PPCInstrInfo.td:1334
    FCTIDU_rec                                = 1222, // PPCInstrInfo.td:1334
    FCTIDZ                                    = 1223, // PPCInstrInfo.td:1330
    FCTIDZ_rec                                = 1224, // PPCInstrInfo.td:1334
    FCTID_rec                                 = 1225, // PPCInstrInfo.td:1334
    FCTIW                                     = 1226, // PPCInstrInfo.td:1330
    FCTIWU                                    = 1227, // PPCInstrInfo.td:1330
    FCTIWUZ                                   = 1228, // PPCInstrInfo.td:1330
    FCTIWUZ_rec                               = 1229, // PPCInstrInfo.td:1334
    FCTIWU_rec                                = 1230, // PPCInstrInfo.td:1334
    FCTIWZ                                    = 1231, // PPCInstrInfo.td:1330
    FCTIWZ_rec                                = 1232, // PPCInstrInfo.td:1334
    FCTIW_rec                                 = 1233, // PPCInstrInfo.td:1334
    FDIV                                      = 1234, // PPCInstrInfo.td:1398
    FDIVS                                     = 1235, // PPCInstrInfo.td:1398
    FDIVS_rec                                 = 1236, // PPCInstrInfo.td:1402
    FDIV_rec                                  = 1237, // PPCInstrInfo.td:1402
    FENCE                                     = 1238, // PPCInstrInfo.td:1628
    FMADD                                     = 1239, // PPCInstrInfo.td:1384
    FMADDS                                    = 1240, // PPCInstrInfo.td:1384
    FMADDS_rec                                = 1241, // PPCInstrInfo.td:1388
    FMADD_rec                                 = 1242, // PPCInstrInfo.td:1388
    FMR                                       = 1243, // PPCInstrInfo.td:1330
    FMR_rec                                   = 1244, // PPCInstrInfo.td:1334
    FMSUB                                     = 1245, // PPCInstrInfo.td:1384
    FMSUBS                                    = 1246, // PPCInstrInfo.td:1384
    FMSUBS_rec                                = 1247, // PPCInstrInfo.td:1388
    FMSUB_rec                                 = 1248, // PPCInstrInfo.td:1388
    FMUL                                      = 1249, // PPCInstrInfo.td:1412
    FMULS                                     = 1250, // PPCInstrInfo.td:1412
    FMULS_rec                                 = 1251, // PPCInstrInfo.td:1416
    FMUL_rec                                  = 1252, // PPCInstrInfo.td:1416
    FNABSD                                    = 1253, // PPCInstrInfo.td:1330
    FNABSD_rec                                = 1254, // PPCInstrInfo.td:1334
    FNABSS                                    = 1255, // PPCInstrInfo.td:1330
    FNABSS_rec                                = 1256, // PPCInstrInfo.td:1334
    FNEGD                                     = 1257, // PPCInstrInfo.td:1330
    FNEGD_rec                                 = 1258, // PPCInstrInfo.td:1334
    FNEGS                                     = 1259, // PPCInstrInfo.td:1330
    FNEGS_rec                                 = 1260, // PPCInstrInfo.td:1334
    FNMADD                                    = 1261, // PPCInstrInfo.td:1384
    FNMADDS                                   = 1262, // PPCInstrInfo.td:1384
    FNMADDS_rec                               = 1263, // PPCInstrInfo.td:1388
    FNMADD_rec                                = 1264, // PPCInstrInfo.td:1388
    FNMSUB                                    = 1265, // PPCInstrInfo.td:1384
    FNMSUBS                                   = 1266, // PPCInstrInfo.td:1384
    FNMSUBS_rec                               = 1267, // PPCInstrInfo.td:1388
    FNMSUB_rec                                = 1268, // PPCInstrInfo.td:1388
    FRE                                       = 1269, // PPCInstrInfo.td:1330
    FRES                                      = 1270, // PPCInstrInfo.td:1330
    FRES_rec                                  = 1271, // PPCInstrInfo.td:1334
    FRE_rec                                   = 1272, // PPCInstrInfo.td:1334
    FRIMD                                     = 1273, // PPCInstrInfo.td:1330
    FRIMD_rec                                 = 1274, // PPCInstrInfo.td:1334
    FRIMS                                     = 1275, // PPCInstrInfo.td:1330
    FRIMS_rec                                 = 1276, // PPCInstrInfo.td:1334
    FRIND                                     = 1277, // PPCInstrInfo.td:1330
    FRIND_rec                                 = 1278, // PPCInstrInfo.td:1334
    FRINS                                     = 1279, // PPCInstrInfo.td:1330
    FRINS_rec                                 = 1280, // PPCInstrInfo.td:1334
    FRIPD                                     = 1281, // PPCInstrInfo.td:1330
    FRIPD_rec                                 = 1282, // PPCInstrInfo.td:1334
    FRIPS                                     = 1283, // PPCInstrInfo.td:1330
    FRIPS_rec                                 = 1284, // PPCInstrInfo.td:1334
    FRIZD                                     = 1285, // PPCInstrInfo.td:1330
    FRIZD_rec                                 = 1286, // PPCInstrInfo.td:1334
    FRIZS                                     = 1287, // PPCInstrInfo.td:1330
    FRIZS_rec                                 = 1288, // PPCInstrInfo.td:1334
    FRSP                                      = 1289, // PPCInstrInfo.td:1330
    FRSP_rec                                  = 1290, // PPCInstrInfo.td:1334
    FRSQRTE                                   = 1291, // PPCInstrInfo.td:1330
    FRSQRTES                                  = 1292, // PPCInstrInfo.td:1330
    FRSQRTES_rec                              = 1293, // PPCInstrInfo.td:1334
    FRSQRTE_rec                               = 1294, // PPCInstrInfo.td:1334
    FSELD                                     = 1295, // PPCInstrInfo.td:1384
    FSELD_rec                                 = 1296, // PPCInstrInfo.td:1388
    FSELS                                     = 1297, // PPCInstrInfo.td:1384
    FSELS_rec                                 = 1298, // PPCInstrInfo.td:1388
    FSQRT                                     = 1299, // PPCInstrInfo.td:1330
    FSQRTS                                    = 1300, // PPCInstrInfo.td:1330
    FSQRTS_rec                                = 1301, // PPCInstrInfo.td:1334
    FSQRT_rec                                 = 1302, // PPCInstrInfo.td:1334
    FSUB                                      = 1303, // PPCInstrInfo.td:1398
    FSUBS                                     = 1304, // PPCInstrInfo.td:1398
    FSUBS_rec                                 = 1305, // PPCInstrInfo.td:1402
    FSUB_rec                                  = 1306, // PPCInstrInfo.td:1402
    FTDIV                                     = 1307, // PPCInstrInfo.td:2715
    FTSQRT                                    = 1308, // PPCInstrInfo.td:2717
    GETtlsADDR                                = 1309, // PPCInstr64Bit.td:1545
    GETtlsADDR32                              = 1310, // PPCInstrInfo.td:3514
    GETtlsADDR32AIX                           = 1311, // PPCInstrInfo.td:3523
    GETtlsADDR64AIX                           = 1312, // PPCInstr64Bit.td:1562
    GETtlsADDRPCREL                           = 1313, // PPCInstr64Bit.td:1547
    GETtlsMOD32AIX                            = 1314, // PPCInstrInfo.td:3527
    GETtlsMOD64AIX                            = 1315, // PPCInstr64Bit.td:1568
    GETtlsTpointer32AIX                       = 1316, // PPCInstrInfo.td:3538
    GETtlsldADDR                              = 1317, // PPCInstr64Bit.td:1552
    GETtlsldADDR32                            = 1318, // PPCInstrInfo.td:3578
    GETtlsldADDRPCREL                         = 1319, // PPCInstr64Bit.td:1554
    HASHCHK                                   = 1320, // PPCInstrInfo.td:5582
    HASHCHK8                                  = 1321, // PPCInstr64Bit.td:1828
    HASHCHKP                                  = 1322, // PPCInstrInfo.td:5585
    HASHCHKP8                                 = 1323, // PPCInstr64Bit.td:1831
    HASHST                                    = 1324, // PPCInstrInfo.td:5569
    HASHST8                                   = 1325, // PPCInstr64Bit.td:1814
    HASHSTP                                   = 1326, // PPCInstrInfo.td:5572
    HASHSTP8                                  = 1327, // PPCInstr64Bit.td:1817
    HRFID                                     = 1328, // PPCInstrInfo.td:4704
    ICBI                                      = 1329, // PPCInstrInfo.td:4513
    ICBIEP                                    = 1330, // PPCInstrInfo.td:4789
    ICBLC                                     = 1331, // PPCInstrInfo.td:2017
    ICBLQ                                     = 1332, // PPCInstrInfo.td:2019
    ICBT                                      = 1333, // PPCInstrInfo.td:2021
    ICBTLS                                    = 1334, // PPCInstrInfo.td:2023
    ICCCI                                     = 1335, // PPCInstrInfo.td:4552
    ISEL                                      = 1336, // PPCInstrInfo.td:3330
    ISEL8                                     = 1337, // PPCInstr64Bit.td:1166
    ISYNC                                     = 1338, // PPCInstrInfo.td:4510
    LA                                        = 1339, // PPCInstrInfo.td:2547
    LA8                                       = 1340, // PPCInstr64Bit.td:782
    LBARX                                     = 1341, // PPCInstrInfo.td:2104
    LBARXL                                    = 1342, // PPCInstrInfo.td:2117
    LBEPX                                     = 1343, // PPCInstrInfo.td:4737
    LBZ                                       = 1344, // PPCInstrInfo.td:2207
    LBZ8                                      = 1345, // PPCInstr64Bit.td:1338
    LBZCIX                                    = 1346, // PPCInstrInfo.td:4709
    LBZU                                      = 1347, // PPCInstrInfo.td:2235
    LBZU8                                     = 1348, // PPCInstr64Bit.td:1367
    LBZUX                                     = 1349, // PPCInstrInfo.td:2263
    LBZUX8                                    = 1350, // PPCInstr64Bit.td:1380
    LBZX                                      = 1351, // PPCInstrInfo.td:2300
    LBZX8                                     = 1352, // PPCInstr64Bit.td:1351
    LBZXTLS                                   = 1353, // PPCInstr64Bit.td:701
    LBZXTLS_                                  = 1354, // PPCInstr64Bit.td:833
    LBZXTLS_32                                = 1355, // PPCInstr64Bit.td:713
    LD                                        = 1356, // PPCInstr64Bit.td:1399
    LDARX                                     = 1357, // PPCInstr64Bit.td:319
    LDARXL                                    = 1358, // PPCInstr64Bit.td:328
    LDAT                                      = 1359, // PPCInstr64Bit.td:339
    LDAT_CSNE                                 = 1360, // PPCInstr64Bit.td:346
    LDBRX                                     = 1361, // PPCInstr64Bit.td:1427
    LDCIX                                     = 1362, // PPCInstrInfo.td:4718
    LDU                                       = 1363, // PPCInstr64Bit.td:1440
    LDUX                                      = 1364, // PPCInstr64Bit.td:1445
    LDX                                       = 1365, // PPCInstr64Bit.td:1422
    LDXTLS                                    = 1366, // PPCInstr64Bit.td:711
    LDXTLS_                                   = 1367, // PPCInstr64Bit.td:843
    LDgotTprelL                               = 1368, // PPCInstr64Bit.td:1506
    LDgotTprelL32                             = 1369, // PPCInstrInfo.td:3499
    LDtoc                                     = 1370, // PPCInstr64Bit.td:1405
    LDtocBA                                   = 1371, // PPCInstr64Bit.td:1417
    LDtocCPT                                  = 1372, // PPCInstr64Bit.td:1413
    LDtocJTI                                  = 1373, // PPCInstr64Bit.td:1409
    LDtocL                                    = 1374, // PPCInstr64Bit.td:1495
    LFD                                       = 1375, // PPCInstrInfo.td:2227
    LFDEPX                                    = 1376, // PPCInstrInfo.td:4741
    LFDU                                      = 1377, // PPCInstrInfo.td:2256
    LFDUX                                     = 1378, // PPCInstrInfo.td:2289
    LFDX                                      = 1379, // PPCInstrInfo.td:2326
    LFDXTLS                                   = 1380, // PPCInstr64Bit.td:728
    LFDXTLS_                                  = 1381, // PPCInstr64Bit.td:850
    LFIWAX                                    = 1382, // PPCInstrInfo.td:2330
    LFIWZX                                    = 1383, // PPCInstrInfo.td:2333
    LFS                                       = 1384, // PPCInstrInfo.td:2224
    LFSU                                      = 1385, // PPCInstrInfo.td:2252
    LFSUX                                     = 1386, // PPCInstrInfo.td:2284
    LFSX                                      = 1387, // PPCInstrInfo.td:2323
    LFSXTLS                                   = 1388, // PPCInstr64Bit.td:726
    LFSXTLS_                                  = 1389, // PPCInstr64Bit.td:848
    LHA                                       = 1390, // PPCInstrInfo.td:2211
    LHA8                                      = 1391, // PPCInstr64Bit.td:1286
    LHARX                                     = 1392, // PPCInstrInfo.td:2108
    LHARXL                                    = 1393, // PPCInstrInfo.td:2121
    LHAU                                      = 1394, // PPCInstrInfo.td:2239
    LHAU8                                     = 1395, // PPCInstr64Bit.td:1317
    LHAUX                                     = 1396, // PPCInstrInfo.td:2268
    LHAUX8                                    = 1397, // PPCInstr64Bit.td:1324
    LHAX                                      = 1398, // PPCInstrInfo.td:2304
    LHAX8                                     = 1399, // PPCInstr64Bit.td:1296
    LHAXTLS                                   = 1400, // PPCInstr64Bit.td:705
    LHAXTLS_                                  = 1401, // PPCInstr64Bit.td:837
    LHAXTLS_32                                = 1402, // PPCInstr64Bit.td:717
    LHBRX                                     = 1403, // PPCInstrInfo.td:2315
    LHBRX8                                    = 1404, // PPCInstr64Bit.td:1433
    LHEPX                                     = 1405, // PPCInstrInfo.td:4745
    LHZ                                       = 1406, // PPCInstrInfo.td:2215
    LHZ8                                      = 1407, // PPCInstr64Bit.td:1342
    LHZCIX                                    = 1408, // PPCInstrInfo.td:4712
    LHZU                                      = 1409, // PPCInstrInfo.td:2243
    LHZU8                                     = 1410, // PPCInstr64Bit.td:1371
    LHZUX                                     = 1411, // PPCInstrInfo.td:2273
    LHZUX8                                    = 1412, // PPCInstr64Bit.td:1384
    LHZX                                      = 1413, // PPCInstrInfo.td:2308
    LHZX8                                     = 1414, // PPCInstr64Bit.td:1355
    LHZXTLS                                   = 1415, // PPCInstr64Bit.td:703
    LHZXTLS_                                  = 1416, // PPCInstr64Bit.td:835
    LHZXTLS_32                                = 1417, // PPCInstr64Bit.td:715
    LI                                        = 1418, // PPCInstrInfo.td:2561
    LI8                                       = 1419, // PPCInstr64Bit.td:625
    LIS                                       = 1420, // PPCInstrInfo.td:2564
    LIS8                                      = 1421, // PPCInstr64Bit.td:628
    LMW                                       = 1422, // PPCInstrInfo.td:2341
    LQ                                        = 1423, // PPCInstr64Bit.td:1455
    LQARX                                     = 1424, // PPCInstr64Bit.td:323
    LQARXL                                    = 1425, // PPCInstr64Bit.td:334
    LQX_PSEUDO                                = 1426, // PPCInstr64Bit.td:1466
    LSWI                                      = 1427, // PPCInstrInfo.td:4500
    LVEBX                                     = 1428, // PPCInstrAltivec.td:424
    LVEHX                                     = 1429, // PPCInstrAltivec.td:427
    LVEWX                                     = 1430, // PPCInstrAltivec.td:430
    LVSL                                      = 1431, // PPCInstrAltivec.td:441
    LVSR                                      = 1432, // PPCInstrAltivec.td:445
    LVX                                       = 1433, // PPCInstrAltivec.td:433
    LVXL                                      = 1434, // PPCInstrAltivec.td:436
    LWA                                       = 1435, // PPCInstr64Bit.td:1290
    LWARX                                     = 1436, // PPCInstrInfo.td:2112
    LWARXL                                    = 1437, // PPCInstrInfo.td:2125
    LWAT                                      = 1438, // PPCInstrInfo.td:2132
    LWAT_CSNE                                 = 1439, // PPCInstrInfo.td:2139
    LWAUX                                     = 1440, // PPCInstr64Bit.td:1328
    LWAX                                      = 1441, // PPCInstr64Bit.td:1300
    LWAXTLS                                   = 1442, // PPCInstr64Bit.td:709
    LWAXTLS_                                  = 1443, // PPCInstr64Bit.td:841
    LWAXTLS_32                                = 1444, // PPCInstr64Bit.td:721
    LWAX_32                                   = 1445, // PPCInstr64Bit.td:1309
    LWA_32                                    = 1446, // PPCInstr64Bit.td:1306
    LWBRX                                     = 1447, // PPCInstrInfo.td:2318
    LWBRX8                                    = 1448, // PPCInstr64Bit.td:1435
    LWEPX                                     = 1449, // PPCInstrInfo.td:4749
    LWZ                                       = 1450, // PPCInstrInfo.td:2219
    LWZ8                                      = 1451, // PPCInstr64Bit.td:1346
    LWZCIX                                    = 1452, // PPCInstrInfo.td:4715
    LWZU                                      = 1453, // PPCInstrInfo.td:2247
    LWZU8                                     = 1454, // PPCInstr64Bit.td:1375
    LWZUX                                     = 1455, // PPCInstrInfo.td:2278
    LWZUX8                                    = 1456, // PPCInstr64Bit.td:1388
    LWZX                                      = 1457, // PPCInstrInfo.td:2312
    LWZX8                                     = 1458, // PPCInstr64Bit.td:1359
    LWZXTLS                                   = 1459, // PPCInstr64Bit.td:707
    LWZXTLS_                                  = 1460, // PPCInstr64Bit.td:839
    LWZXTLS_32                                = 1461, // PPCInstr64Bit.td:719
    LWZtoc                                    = 1462, // PPCInstrInfo.td:3605
    LWZtocL                                   = 1463, // PPCInstrInfo.td:3609
    LXSD                                      = 1464, // PPCInstrVSX.td:1719
    LXSDX                                     = 1465, // PPCInstrVSX.td:344
    LXSIBZX                                   = 1466, // PPCInstrVSX.td:1726
    LXSIHZX                                   = 1467, // PPCInstrVSX.td:1728
    LXSIWAX                                   = 1468, // PPCInstrVSX.td:1164
    LXSIWZX                                   = 1469, // PPCInstrVSX.td:1166
    LXSSP                                     = 1470, // PPCInstrVSX.td:1722
    LXSSPX                                    = 1471, // PPCInstrVSX.td:1162
    LXV                                       = 1472, // PPCInstrVSX.td:1716
    LXVB16X                                   = 1473, // PPCInstrVSX.td:1733
    LXVD2X                                    = 1474, // PPCInstrVSX.td:355
    LXVDSX                                    = 1475, // PPCInstrVSX.td:360
    LXVH8X                                    = 1476, // PPCInstrVSX.td:1732
    LXVKQ                                     = 1477, // PPCInstrP10.td:1941
    LXVL                                      = 1478, // PPCInstrVSX.td:1739
    LXVLL                                     = 1479, // PPCInstrVSX.td:1742
    LXVP                                      = 1480, // PPCInstrP10.td:1172
    LXVPB32X                                  = 1481, // PPCInstrFuture.td:407
    LXVPRL                                    = 1482, // PPCInstrFuture.td:401
    LXVPRLL                                   = 1483, // PPCInstrFuture.td:404
    LXVPX                                     = 1484, // PPCInstrP10.td:1175
    LXVRBX                                    = 1485, // PPCInstrP10.td:1855
    LXVRDX                                    = 1486, // PPCInstrP10.td:1858
    LXVRHX                                    = 1487, // PPCInstrP10.td:1856
    LXVRL                                     = 1488, // PPCInstrFuture.td:395
    LXVRLL                                    = 1489, // PPCInstrFuture.td:398
    LXVRWX                                    = 1490, // PPCInstrP10.td:1857
    LXVW4X                                    = 1491, // PPCInstrVSX.td:365
    LXVWSX                                    = 1492, // PPCInstrVSX.td:1747
    LXVX                                      = 1493, // PPCInstrVSX.td:1736
    MADDHD                                    = 1494, // PPCInstr64Bit.td:1052
    MADDHDU                                   = 1495, // PPCInstr64Bit.td:1054
    MADDLD                                    = 1496, // PPCInstr64Bit.td:1057
    MADDLD8                                   = 1497, // PPCInstr64Bit.td:1062
    MBAR                                      = 1498, // PPCInstrInfo.td:4519
    MCRF                                      = 1499, // PPCInstrInfo.td:2842
    MCRFS                                     = 1500, // PPCInstrInfo.td:4566
    MCRXRX                                    = 1501, // PPCInstrInfo.td:3053
    MFBHRBE                                   = 1502, // PPCInstrInfo.td:1978
    MFCR                                      = 1503, // PPCInstrInfo.td:3048
    MFCR8                                     = 1504, // PPCInstr64Bit.td:511
    MFCTR                                     = 1505, // PPCInstrInfo.td:2948
    MFCTR8                                    = 1506, // PPCInstr64Bit.td:545
    MFDCR                                     = 1507, // PPCInstrInfo.td:4699
    MFFS                                      = 1508, // PPCInstrInfo.td:3090
    MFFSCDRN                                  = 1509, // PPCInstrInfo.td:3103
    MFFSCDRNI                                 = 1510, // PPCInstrInfo.td:3108
    MFFSCE                                    = 1511, // PPCInstrInfo.td:3099
    MFFSCRN                                   = 1512, // PPCInstrInfo.td:3114
    MFFSCRNI                                  = 1513, // PPCInstrInfo.td:3119
    MFFSL                                     = 1514, // PPCInstrInfo.td:3124
    MFFS_rec                                  = 1515, // PPCInstrInfo.td:3096
    MFLR                                      = 1516, // PPCInstrInfo.td:2975
    MFLR8                                     = 1517, // PPCInstr64Bit.td:608
    MFMSR                                     = 1518, // PPCInstrInfo.td:4560
    MFOCRF                                    = 1519, // PPCInstrInfo.td:3042
    MFOCRF8                                   = 1520, // PPCInstr64Bit.td:505
    MFPMR                                     = 1521, // PPCInstrInfo.td:2934
    MFSPR                                     = 1522, // PPCInstrInfo.td:2926
    MFSPR8                                    = 1523, // PPCInstr64Bit.td:535
    MFSR                                      = 1524, // PPCInstrInfo.td:4525
    MFSRIN                                    = 1525, // PPCInstrInfo.td:4531
    MFTB                                      = 1526, // PPCInstrInfo.td:2931
    MFTB8                                     = 1527, // PPCInstr64Bit.td:568
    MFUDSCR                                   = 1528, // PPCInstrInfo.td:2985
    MFVRD                                     = 1529, // PPCInstrVSX.td:1344
    MFVRSAVE                                  = 1530, // PPCInstrInfo.td:3004
    MFVRSAVEv                                 = 1531, // PPCInstrInfo.td:3012
    MFVRWZ                                    = 1532, // PPCInstrVSX.td:1353
    MFVSCR                                    = 1533, // PPCInstrAltivec.td:415
    MFVSRD                                    = 1534, // PPCInstrVSX.td:1338
    MFVSRLD                                   = 1535, // PPCInstrVSX.td:1394
    MFVSRWZ                                   = 1536, // PPCInstrVSX.td:1348
    MODSD                                     = 1537, // PPCInstr64Bit.td:1072
    MODSW                                     = 1538, // PPCInstrInfo.td:3131
    MODUD                                     = 1539, // PPCInstr64Bit.td:1075
    MODUW                                     = 1540, // PPCInstrInfo.td:3134
    MSGSNDP                                   = 1541, // PPCInstrInfo.td:4650
    MSGSNDP8                                  = 1542, // PPCInstrInfo.td:4653
    MSGSYNC                                   = 1543, // PPCInstrInfo.td:5389
    MSYNC                                     = 1544, // PPCInstrInfo.td:2498
    MTCRF                                     = 1545, // PPCInstrInfo.td:3033
    MTCRF8                                    = 1546, // PPCInstr64Bit.td:496
    MTCTR                                     = 1547, // PPCInstrInfo.td:2953
    MTCTR8                                    = 1548, // PPCInstr64Bit.td:550
    MTCTR8loop                                = 1549, // PPCInstr64Bit.td:558
    MTCTRloop                                 = 1550, // PPCInstrInfo.td:2959
    MTDCR                                     = 1551, // PPCInstrInfo.td:4701
    MTFSB0                                    = 1552, // PPCInstrInfo.td:3072
    MTFSB1                                    = 1553, // PPCInstrInfo.td:3076
    MTFSF                                     = 1554, // PPCInstrInfo.td:4583
    MTFSFI                                    = 1555, // PPCInstrInfo.td:4577
    MTFSFI_rec                                = 1556, // PPCInstrInfo.td:4580
    MTFSFIb                                   = 1557, // PPCInstrInfo.td:4575
    MTFSF_rec                                 = 1558, // PPCInstrInfo.td:4587
    MTFSFb                                    = 1559, // PPCInstrInfo.td:3084
    MTLPL                                     = 1560, // PPCInstrFuture.td:368
    MTLPL8                                    = 1561, // PPCInstrFuture.td:376
    MTLR                                      = 1562, // PPCInstrInfo.td:2970
    MTLR8                                     = 1563, // PPCInstr64Bit.td:603
    MTMSR                                     = 1564, // PPCInstrInfo.td:4534
    MTMSRD                                    = 1565, // PPCInstrInfo.td:4563
    MTOCRF                                    = 1566, // PPCInstrInfo.td:3027
    MTOCRF8                                   = 1567, // PPCInstr64Bit.td:490
    MTPMR                                     = 1568, // PPCInstrInfo.td:2937
    MTSPR                                     = 1569, // PPCInstrInfo.td:2928
    MTSPR8                                    = 1570, // PPCInstr64Bit.td:537
    MTSR                                      = 1571, // PPCInstrInfo.td:4522
    MTSRIN                                    = 1572, // PPCInstrInfo.td:4528
    MTUDSCR                                   = 1573, // PPCInstrInfo.td:2982
    MTVRD                                     = 1574, // PPCInstrVSX.td:1362
    MTVRSAVE                                  = 1575, // PPCInstrInfo.td:3001
    MTVRSAVEv                                 = 1576, // PPCInstrInfo.td:3008
    MTVRWA                                    = 1577, // PPCInstrVSX.td:1371
    MTVRWZ                                    = 1578, // PPCInstrVSX.td:1379
    MTVSCR                                    = 1579, // PPCInstrAltivec.td:418
    MTVSRBM                                   = 1580, // PPCInstrP10.td:1605
    MTVSRBMI                                  = 1581, // PPCInstrP10.td:1625
    MTVSRD                                    = 1582, // PPCInstrVSX.td:1356
    MTVSRDD                                   = 1583, // PPCInstrVSX.td:1390
    MTVSRDM                                   = 1584, // PPCInstrP10.td:1617
    MTVSRHM                                   = 1585, // PPCInstrP10.td:1609
    MTVSRQM                                   = 1586, // PPCInstrP10.td:1621
    MTVSRWA                                   = 1587, // PPCInstrVSX.td:1366
    MTVSRWM                                   = 1588, // PPCInstrP10.td:1613
    MTVSRWS                                   = 1589, // PPCInstrVSX.td:1387
    MTVSRWZ                                   = 1590, // PPCInstrVSX.td:1374
    MULHD                                     = 1591, // PPCInstrInfo.td:1104
    MULHDU                                    = 1592, // PPCInstrInfo.td:1104
    MULHDU_rec                                = 1593, // PPCInstrInfo.td:1108
    MULHD_rec                                 = 1594, // PPCInstrInfo.td:1108
    MULHW                                     = 1595, // PPCInstrInfo.td:1104
    MULHWU                                    = 1596, // PPCInstrInfo.td:1104
    MULHWU_rec                                = 1597, // PPCInstrInfo.td:1108
    MULHW_rec                                 = 1598, // PPCInstrInfo.td:1108
    MULLD                                     = 1599, // PPCInstrInfo.td:1120
    MULLDO                                    = 1600, // PPCInstrInfo.td:1130
    MULLDO_rec                                = 1601, // PPCInstrInfo.td:1134
    MULLD_rec                                 = 1602, // PPCInstrInfo.td:1124
    MULLI                                     = 1603, // PPCInstrInfo.td:2551
    MULLI8                                    = 1604, // PPCInstr64Bit.td:1089
    MULLW                                     = 1605, // PPCInstrInfo.td:1120
    MULLWO                                    = 1606, // PPCInstrInfo.td:1130
    MULLWO_rec                                = 1607, // PPCInstrInfo.td:1134
    MULLW_rec                                 = 1608, // PPCInstrInfo.td:1124
    MoveGOTtoLR                               = 1609, // PPCInstrInfo.td:1634
    MovePCtoLR                                = 1610, // PPCInstrInfo.td:1631
    MovePCtoLR8                               = 1611, // PPCInstr64Bit.td:76
    NAND                                      = 1612, // PPCInstrInfo.td:1046
    NAND8                                     = 1613, // PPCInstrInfo.td:1046
    NAND8_rec                                 = 1614, // PPCInstrInfo.td:1050
    NAND_rec                                  = 1615, // PPCInstrInfo.td:1050
    NAP                                       = 1616, // PPCInstrInfo.td:4705
    NEG                                       = 1617, // PPCInstrInfo.td:1196
    NEG8                                      = 1618, // PPCInstrInfo.td:1196
    NEG8O                                     = 1619, // PPCInstrInfo.td:1206
    NEG8O_rec                                 = 1620, // PPCInstrInfo.td:1210
    NEG8_rec                                  = 1621, // PPCInstrInfo.td:1200
    NEGO                                      = 1622, // PPCInstrInfo.td:1206
    NEGO_rec                                  = 1623, // PPCInstrInfo.td:1210
    NEG_rec                                   = 1624, // PPCInstrInfo.td:1200
    NOP                                       = 1625, // PPCInstrInfo.td:2597
    NOP_GT_PWR6                               = 1626, // PPCInstrInfo.td:2601
    NOP_GT_PWR7                               = 1627, // PPCInstrInfo.td:2603
    NOR                                       = 1628, // PPCInstrInfo.td:1046
    NOR8                                      = 1629, // PPCInstrInfo.td:1046
    NOR8_rec                                  = 1630, // PPCInstrInfo.td:1050
    NOR_rec                                   = 1631, // PPCInstrInfo.td:1050
    OR                                        = 1632, // PPCInstrInfo.td:1046
    OR8                                       = 1633, // PPCInstrInfo.td:1046
    OR8_rec                                   = 1634, // PPCInstrInfo.td:1050
    ORC                                       = 1635, // PPCInstrInfo.td:1046
    ORC8                                      = 1636, // PPCInstrInfo.td:1046
    ORC8_rec                                  = 1637, // PPCInstrInfo.td:1050
    ORC_rec                                   = 1638, // PPCInstrInfo.td:1050
    ORI                                       = 1639, // PPCInstrInfo.td:2584
    ORI8                                      = 1640, // PPCInstr64Bit.td:676
    ORIS                                      = 1641, // PPCInstrInfo.td:2587
    ORIS8                                     = 1642, // PPCInstr64Bit.td:679
    OR_rec                                    = 1643, // PPCInstrInfo.td:1050
    PADDI                                     = 1644, // PPCInstrP10.td:276
    PADDI8                                    = 1645, // PPCInstrP10.td:276
    PADDI8pc                                  = 1646, // PPCInstrP10.td:278
    PADDIS                                    = 1647, // PPCInstrFuture.td:339
    PADDIS8                                   = 1648, // PPCInstrFuture.td:339
    PADDIS8pc                                 = 1649, // PPCInstrFuture.td:341
    PADDISpc                                  = 1650, // PPCInstrFuture.td:341
    PADDIdtprel                               = 1651, // PPCInstr64Bit.td:1634
    PADDIpc                                   = 1652, // PPCInstrP10.td:278
    PDEPD                                     = 1653, // PPCInstrP10.td:1721
    PEXTD                                     = 1654, // PPCInstrP10.td:1724
    PLA                                       = 1655, // PPCInstrP10.td:2984
    PLA8                                      = 1656, // PPCInstrP10.td:2973
    PLA8pc                                    = 1657, // PPCInstrP10.td:2976
    PLApc                                     = 1658, // PPCInstrP10.td:2987
    PLBZ                                      = 1659, // PPCInstrP10.td:605
    PLBZ8                                     = 1660, // PPCInstrP10.td:605
    PLBZ8nopc                                 = 1661, // PPCInstrP10.td:611
    PLBZ8onlypc                               = 1662, // PPCInstrP10.td:613
    PLBZ8pc                                   = 1663, // PPCInstrP10.td:607
    PLBZnopc                                  = 1664, // PPCInstrP10.td:611
    PLBZonlypc                                = 1665, // PPCInstrP10.td:613
    PLBZpc                                    = 1666, // PPCInstrP10.td:607
    PLD                                       = 1667, // PPCInstrP10.td:622
    PLDnopc                                   = 1668, // PPCInstrP10.td:628
    PLDonlypc                                 = 1669, // PPCInstrP10.td:630
    PLDpc                                     = 1670, // PPCInstrP10.td:624
    PLFD                                      = 1671, // PPCInstrP10.td:605
    PLFDnopc                                  = 1672, // PPCInstrP10.td:611
    PLFDonlypc                                = 1673, // PPCInstrP10.td:613
    PLFDpc                                    = 1674, // PPCInstrP10.td:607
    PLFS                                      = 1675, // PPCInstrP10.td:605
    PLFSnopc                                  = 1676, // PPCInstrP10.td:611
    PLFSonlypc                                = 1677, // PPCInstrP10.td:613
    PLFSpc                                    = 1678, // PPCInstrP10.td:607
    PLHA                                      = 1679, // PPCInstrP10.td:605
    PLHA8                                     = 1680, // PPCInstrP10.td:605
    PLHA8nopc                                 = 1681, // PPCInstrP10.td:611
    PLHA8onlypc                               = 1682, // PPCInstrP10.td:613
    PLHA8pc                                   = 1683, // PPCInstrP10.td:607
    PLHAnopc                                  = 1684, // PPCInstrP10.td:611
    PLHAonlypc                                = 1685, // PPCInstrP10.td:613
    PLHApc                                    = 1686, // PPCInstrP10.td:607
    PLHZ                                      = 1687, // PPCInstrP10.td:605
    PLHZ8                                     = 1688, // PPCInstrP10.td:605
    PLHZ8nopc                                 = 1689, // PPCInstrP10.td:611
    PLHZ8onlypc                               = 1690, // PPCInstrP10.td:613
    PLHZ8pc                                   = 1691, // PPCInstrP10.td:607
    PLHZnopc                                  = 1692, // PPCInstrP10.td:611
    PLHZonlypc                                = 1693, // PPCInstrP10.td:613
    PLHZpc                                    = 1694, // PPCInstrP10.td:607
    PLI                                       = 1695, // PPCInstrP10.td:675
    PLI8                                      = 1696, // PPCInstrP10.td:665
    PLWA                                      = 1697, // PPCInstrP10.td:622
    PLWA8                                     = 1698, // PPCInstrP10.td:622
    PLWA8nopc                                 = 1699, // PPCInstrP10.td:628
    PLWA8onlypc                               = 1700, // PPCInstrP10.td:630
    PLWA8pc                                   = 1701, // PPCInstrP10.td:624
    PLWAnopc                                  = 1702, // PPCInstrP10.td:628
    PLWAonlypc                                = 1703, // PPCInstrP10.td:630
    PLWApc                                    = 1704, // PPCInstrP10.td:624
    PLWZ                                      = 1705, // PPCInstrP10.td:605
    PLWZ8                                     = 1706, // PPCInstrP10.td:605
    PLWZ8nopc                                 = 1707, // PPCInstrP10.td:611
    PLWZ8onlypc                               = 1708, // PPCInstrP10.td:613
    PLWZ8pc                                   = 1709, // PPCInstrP10.td:607
    PLWZnopc                                  = 1710, // PPCInstrP10.td:611
    PLWZonlypc                                = 1711, // PPCInstrP10.td:613
    PLWZpc                                    = 1712, // PPCInstrP10.td:607
    PLXSD                                     = 1713, // PPCInstrP10.td:622
    PLXSDnopc                                 = 1714, // PPCInstrP10.td:628
    PLXSDonlypc                               = 1715, // PPCInstrP10.td:630
    PLXSDpc                                   = 1716, // PPCInstrP10.td:624
    PLXSSP                                    = 1717, // PPCInstrP10.td:622
    PLXSSPnopc                                = 1718, // PPCInstrP10.td:628
    PLXSSPonlypc                              = 1719, // PPCInstrP10.td:630
    PLXSSPpc                                  = 1720, // PPCInstrP10.td:624
    PLXV                                      = 1721, // PPCInstrP10.td:639
    PLXVP                                     = 1722, // PPCInstrP10.td:928
    PLXVPnopc                                 = 1723, // PPCInstrP10.td:934
    PLXVPonlypc                               = 1724, // PPCInstrP10.td:936
    PLXVPpc                                   = 1725, // PPCInstrP10.td:930
    PLXVnopc                                  = 1726, // PPCInstrP10.td:645
    PLXVonlypc                                = 1727, // PPCInstrP10.td:647
    PLXVpc                                    = 1728, // PPCInstrP10.td:641
    PMDMXVBF16GERX2                           = 1729, // PPCInstrFutureMMA.td:237
    PMDMXVBF16GERX2NN                         = 1730, // PPCInstrFutureMMA.td:314
    PMDMXVBF16GERX2NP                         = 1731, // PPCInstrFutureMMA.td:306
    PMDMXVBF16GERX2PN                         = 1732, // PPCInstrFutureMMA.td:298
    PMDMXVBF16GERX2PP                         = 1733, // PPCInstrFutureMMA.td:244
    PMDMXVF16GERX2                            = 1734, // PPCInstrFutureMMA.td:259
    PMDMXVF16GERX2NN                          = 1735, // PPCInstrFutureMMA.td:362
    PMDMXVF16GERX2NP                          = 1736, // PPCInstrFutureMMA.td:354
    PMDMXVF16GERX2PN                          = 1737, // PPCInstrFutureMMA.td:346
    PMDMXVF16GERX2PP                          = 1738, // PPCInstrFutureMMA.td:266
    PMDMXVI8GERX4                             = 1739, // PPCInstrFutureMMA.td:200
    PMDMXVI8GERX4PP                           = 1740, // PPCInstrFutureMMA.td:207
    PMDMXVI8GERX4SPP                          = 1741, // PPCInstrFutureMMA.td:541
    PMXVBF16GER2                              = 1742, // PPCInstrMMA.td:119
    PMXVBF16GER2NN                            = 1743, // PPCInstrMMA.td:262
    PMXVBF16GER2NP                            = 1744, // PPCInstrMMA.td:255
    PMXVBF16GER2PN                            = 1745, // PPCInstrMMA.td:248
    PMXVBF16GER2PP                            = 1746, // PPCInstrMMA.td:126
    PMXVBF16GER2W                             = 1747, // PPCInstrMMA.td:135
    PMXVBF16GER2WNN                           = 1748, // PPCInstrMMA.td:285
    PMXVBF16GER2WNP                           = 1749, // PPCInstrMMA.td:278
    PMXVBF16GER2WPN                           = 1750, // PPCInstrMMA.td:271
    PMXVBF16GER2WPP                           = 1751, // PPCInstrMMA.td:142
    PMXVF16GER2                               = 1752, // PPCInstrMMA.td:119
    PMXVF16GER2NN                             = 1753, // PPCInstrMMA.td:262
    PMXVF16GER2NP                             = 1754, // PPCInstrMMA.td:255
    PMXVF16GER2PN                             = 1755, // PPCInstrMMA.td:248
    PMXVF16GER2PP                             = 1756, // PPCInstrMMA.td:126
    PMXVF16GER2W                              = 1757, // PPCInstrMMA.td:135
    PMXVF16GER2WNN                            = 1758, // PPCInstrMMA.td:285
    PMXVF16GER2WNP                            = 1759, // PPCInstrMMA.td:278
    PMXVF16GER2WPN                            = 1760, // PPCInstrMMA.td:271
    PMXVF16GER2WPP                            = 1761, // PPCInstrMMA.td:142
    PMXVF32GER                                = 1762, // PPCInstrMMA.td:336
    PMXVF32GERNN                              = 1763, // PPCInstrMMA.td:364
    PMXVF32GERNP                              = 1764, // PPCInstrMMA.td:357
    PMXVF32GERPN                              = 1765, // PPCInstrMMA.td:350
    PMXVF32GERPP                              = 1766, // PPCInstrMMA.td:343
    PMXVF32GERW                               = 1767, // PPCInstrMMA.td:373
    PMXVF32GERWNN                             = 1768, // PPCInstrMMA.td:401
    PMXVF32GERWNP                             = 1769, // PPCInstrMMA.td:394
    PMXVF32GERWPN                             = 1770, // PPCInstrMMA.td:387
    PMXVF32GERWPP                             = 1771, // PPCInstrMMA.td:380
    PMXVF64GER                                = 1772, // PPCInstrMMA.td:417
    PMXVF64GERNN                              = 1773, // PPCInstrMMA.td:445
    PMXVF64GERNP                              = 1774, // PPCInstrMMA.td:438
    PMXVF64GERPN                              = 1775, // PPCInstrMMA.td:431
    PMXVF64GERPP                              = 1776, // PPCInstrMMA.td:424
    PMXVF64GERW                               = 1777, // PPCInstrMMA.td:454
    PMXVF64GERWNN                             = 1778, // PPCInstrMMA.td:482
    PMXVF64GERWNP                             = 1779, // PPCInstrMMA.td:475
    PMXVF64GERWPN                             = 1780, // PPCInstrMMA.td:468
    PMXVF64GERWPP                             = 1781, // PPCInstrMMA.td:461
    PMXVI16GER2                               = 1782, // PPCInstrMMA.td:168
    PMXVI16GER2PP                             = 1783, // PPCInstrMMA.td:175
    PMXVI16GER2S                              = 1784, // PPCInstrMMA.td:119
    PMXVI16GER2SPP                            = 1785, // PPCInstrMMA.td:126
    PMXVI16GER2SW                             = 1786, // PPCInstrMMA.td:135
    PMXVI16GER2SWPP                           = 1787, // PPCInstrMMA.td:142
    PMXVI16GER2W                              = 1788, // PPCInstrMMA.td:196
    PMXVI16GER2WPP                            = 1789, // PPCInstrMMA.td:203
    PMXVI4GER8                                = 1790, // PPCInstrMMA.td:37
    PMXVI4GER8PP                              = 1791, // PPCInstrMMA.td:44
    PMXVI4GER8W                               = 1792, // PPCInstrMMA.td:54
    PMXVI4GER8WPP                             = 1793, // PPCInstrMMA.td:61
    PMXVI8GER4                                = 1794, // PPCInstrMMA.td:78
    PMXVI8GER4PP                              = 1795, // PPCInstrMMA.td:85
    PMXVI8GER4SPP                             = 1796, // PPCInstrMMA.td:589
    PMXVI8GER4W                               = 1797, // PPCInstrMMA.td:95
    PMXVI8GER4WPP                             = 1798, // PPCInstrMMA.td:102
    PMXVI8GER4WSPP                            = 1799, // PPCInstrMMA.td:599
    POPCNTB                                   = 1800, // PPCInstrInfo.td:2187
    POPCNTB8                                  = 1801, // PPCInstr64Bit.td:1025
    POPCNTD                                   = 1802, // PPCInstr64Bit.td:1003
    POPCNTW                                   = 1803, // PPCInstr64Bit.td:1020
    PPC32GOT                                  = 1804, // PPCInstrInfo.td:3485
    PPC32PICGOT                               = 1805, // PPCInstrInfo.td:3494
    PREPARE_PROBED_ALLOCA_32                  = 1806, // PPCInstrInfo.td:1510
    PREPARE_PROBED_ALLOCA_64                  = 1807, // PPCInstr64Bit.td:588
    PREPARE_PROBED_ALLOCA_NEGSIZE_SAME_REG_32 = 1808, // PPCInstrInfo.td:1513
    PREPARE_PROBED_ALLOCA_NEGSIZE_SAME_REG_64 = 1809, // PPCInstr64Bit.td:591
    PROBED_ALLOCA_32                          = 1810, // PPCInstrInfo.td:1506
    PROBED_ALLOCA_64                          = 1811, // PPCInstr64Bit.td:584
    PROBED_STACKALLOC_32                      = 1812, // PPCInstrInfo.td:1518
    PROBED_STACKALLOC_64                      = 1813, // PPCInstr64Bit.td:596
    PSTB                                      = 1814, // PPCInstrP10.td:605
    PSTB8                                     = 1815, // PPCInstrP10.td:605
    PSTB8nopc                                 = 1816, // PPCInstrP10.td:611
    PSTB8onlypc                               = 1817, // PPCInstrP10.td:613
    PSTB8pc                                   = 1818, // PPCInstrP10.td:607
    PSTBnopc                                  = 1819, // PPCInstrP10.td:611
    PSTBonlypc                                = 1820, // PPCInstrP10.td:613
    PSTBpc                                    = 1821, // PPCInstrP10.td:607
    PSTD                                      = 1822, // PPCInstrP10.td:622
    PSTDnopc                                  = 1823, // PPCInstrP10.td:628
    PSTDonlypc                                = 1824, // PPCInstrP10.td:630
    PSTDpc                                    = 1825, // PPCInstrP10.td:624
    PSTFD                                     = 1826, // PPCInstrP10.td:605
    PSTFDnopc                                 = 1827, // PPCInstrP10.td:611
    PSTFDonlypc                               = 1828, // PPCInstrP10.td:613
    PSTFDpc                                   = 1829, // PPCInstrP10.td:607
    PSTFS                                     = 1830, // PPCInstrP10.td:605
    PSTFSnopc                                 = 1831, // PPCInstrP10.td:611
    PSTFSonlypc                               = 1832, // PPCInstrP10.td:613
    PSTFSpc                                   = 1833, // PPCInstrP10.td:607
    PSTH                                      = 1834, // PPCInstrP10.td:605
    PSTH8                                     = 1835, // PPCInstrP10.td:605
    PSTH8nopc                                 = 1836, // PPCInstrP10.td:611
    PSTH8onlypc                               = 1837, // PPCInstrP10.td:613
    PSTH8pc                                   = 1838, // PPCInstrP10.td:607
    PSTHnopc                                  = 1839, // PPCInstrP10.td:611
    PSTHonlypc                                = 1840, // PPCInstrP10.td:613
    PSTHpc                                    = 1841, // PPCInstrP10.td:607
    PSTW                                      = 1842, // PPCInstrP10.td:605
    PSTW8                                     = 1843, // PPCInstrP10.td:605
    PSTW8nopc                                 = 1844, // PPCInstrP10.td:611
    PSTW8onlypc                               = 1845, // PPCInstrP10.td:613
    PSTW8pc                                   = 1846, // PPCInstrP10.td:607
    PSTWnopc                                  = 1847, // PPCInstrP10.td:611
    PSTWonlypc                                = 1848, // PPCInstrP10.td:613
    PSTWpc                                    = 1849, // PPCInstrP10.td:607
    PSTXSD                                    = 1850, // PPCInstrP10.td:622
    PSTXSDnopc                                = 1851, // PPCInstrP10.td:628
    PSTXSDonlypc                              = 1852, // PPCInstrP10.td:630
    PSTXSDpc                                  = 1853, // PPCInstrP10.td:624
    PSTXSSP                                   = 1854, // PPCInstrP10.td:622
    PSTXSSPnopc                               = 1855, // PPCInstrP10.td:628
    PSTXSSPonlypc                             = 1856, // PPCInstrP10.td:630
    PSTXSSPpc                                 = 1857, // PPCInstrP10.td:624
    PSTXV                                     = 1858, // PPCInstrP10.td:639
    PSTXVP                                    = 1859, // PPCInstrP10.td:928
    PSTXVPnopc                                = 1860, // PPCInstrP10.td:934
    PSTXVPonlypc                              = 1861, // PPCInstrP10.td:936
    PSTXVPpc                                  = 1862, // PPCInstrP10.td:930
    PSTXVnopc                                 = 1863, // PPCInstrP10.td:645
    PSTXVonlypc                               = 1864, // PPCInstrP10.td:647
    PSTXVpc                                   = 1865, // PPCInstrP10.td:641
    PTESYNCIO                                 = 1866, // PPCInstrFuture.td:359
    PseudoEIEIO                               = 1867, // PPCInstrInfo.td:2508
    RESTORE_ACC                               = 1868, // PPCInstrMMA.td:529
    RESTORE_CR                                = 1869, // PPCInstrInfo.td:1587
    RESTORE_CRBIT                             = 1870, // PPCInstrInfo.td:1589
    RESTORE_DMR                               = 1871, // PPCInstrMMA.td:577
    RESTORE_DMRP                              = 1872, // PPCInstrMMA.td:575
    RESTORE_QUADWORD                          = 1873, // PPCInstr64Bit.td:1469
    RESTORE_UACC                              = 1874, // PPCInstrMMA.td:531
    RESTORE_WACC                              = 1875, // PPCInstrMMA.td:573
    RFCI                                      = 1876, // PPCInstrInfo.td:4691
    RFDI                                      = 1877, // PPCInstrInfo.td:4694
    RFEBB                                     = 1878, // PPCInstrInfo.td:1982
    RFI                                       = 1879, // PPCInstrInfo.td:4689
    RFID                                      = 1880, // PPCInstrInfo.td:4687
    RFMCI                                     = 1881, // PPCInstrInfo.td:4696
    RLDCL                                     = 1882, // PPCInstrInfo.td:1287
    RLDCL_rec                                 = 1883, // PPCInstrInfo.td:1291
    RLDCR                                     = 1884, // PPCInstrInfo.td:1287
    RLDCR_rec                                 = 1885, // PPCInstrInfo.td:1291
    RLDIC                                     = 1886, // PPCInstrInfo.td:1273
    RLDICL                                    = 1887, // PPCInstrInfo.td:1273
    RLDICL_32                                 = 1888, // PPCInstrInfo.td:1273
    RLDICL_32_64                              = 1889, // PPCInstr64Bit.td:1120
    RLDICL_32_rec                             = 1890, // PPCInstrInfo.td:1277
    RLDICL_rec                                = 1891, // PPCInstrInfo.td:1277
    RLDICR                                    = 1892, // PPCInstrInfo.td:1273
    RLDICR_32                                 = 1893, // PPCInstr64Bit.td:1137
    RLDICR_rec                                = 1894, // PPCInstrInfo.td:1277
    RLDIC_rec                                 = 1895, // PPCInstrInfo.td:1277
    RLDIMI                                    = 1896, // PPCInstrInfo.td:1273
    RLDIMI_rec                                = 1897, // PPCInstrInfo.td:1277
    RLWIMI                                    = 1898, // PPCInstrInfo.td:1259
    RLWIMI8                                   = 1899, // PPCInstrInfo.td:1259
    RLWIMI8_rec                               = 1900, // PPCInstrInfo.td:1263
    RLWIMI_rec                                = 1901, // PPCInstrInfo.td:1263
    RLWINM                                    = 1902, // PPCInstrInfo.td:3348
    RLWINM8                                   = 1903, // PPCInstrInfo.td:1259
    RLWINM8_rec                               = 1904, // PPCInstrInfo.td:1263
    RLWINM_rec                                = 1905, // PPCInstrInfo.td:3353
    RLWNM                                     = 1906, // PPCInstrInfo.td:1245
    RLWNM8                                    = 1907, // PPCInstrInfo.td:1245
    RLWNM8_rec                                = 1908, // PPCInstrInfo.td:1249
    RLWNM_rec                                 = 1909, // PPCInstrInfo.td:1249
    ReadTB                                    = 1910, // PPCInstrInfo.td:2944
    SC                                        = 1911, // PPCInstrInfo.td:1962
    SCV                                       = 1912, // PPCInstrInfo.td:1970
    SELECT_CC_F16                             = 1913, // PPCInstrInfo.td:1543
    SELECT_CC_F4                              = 1914, // PPCInstrInfo.td:1537
    SELECT_CC_F8                              = 1915, // PPCInstrInfo.td:1540
    SELECT_CC_I4                              = 1916, // PPCInstrInfo.td:1529
    SELECT_CC_I8                              = 1917, // PPCInstrInfo.td:1533
    SELECT_CC_SPE                             = 1918, // PPCInstrSPE.td:819
    SELECT_CC_SPE4                            = 1919, // PPCInstrSPE.td:815
    SELECT_CC_VRRC                            = 1920, // PPCInstrInfo.td:1546
    SELECT_CC_VSFRC                           = 1921, // PPCInstrVSX.td:1828
    SELECT_CC_VSRC                            = 1922, // PPCInstrVSX.td:1819
    SELECT_CC_VSSRC                           = 1923, // PPCInstrVSX.td:1837
    SELECT_F16                                = 1924, // PPCInstrInfo.td:1565
    SELECT_F4                                 = 1925, // PPCInstrInfo.td:1559
    SELECT_F8                                 = 1926, // PPCInstrInfo.td:1562
    SELECT_I4                                 = 1927, // PPCInstrInfo.td:1552
    SELECT_I8                                 = 1928, // PPCInstrInfo.td:1555
    SELECT_SPE                                = 1929, // PPCInstrSPE.td:826
    SELECT_SPE4                               = 1930, // PPCInstrSPE.td:823
    SELECT_VRRC                               = 1931, // PPCInstrInfo.td:1569
    SELECT_VSFRC                              = 1932, // PPCInstrVSX.td:1832
    SELECT_VSRC                               = 1933, // PPCInstrVSX.td:1823
    SELECT_VSSRC                              = 1934, // PPCInstrVSX.td:1841
    SETB                                      = 1935, // PPCInstrInfo.td:5394
    SETB8                                     = 1936, // PPCInstr64Bit.td:1067
    SETBC                                     = 1937, // PPCInstrP10.td:1415
    SETBC8                                    = 1938, // PPCInstrP10.td:1431
    SETBCR                                    = 1939, // PPCInstrP10.td:1419
    SETBCR8                                   = 1940, // PPCInstrP10.td:1434
    SETFLM                                    = 1941, // PPCInstrInfo.td:1623
    SETNBC                                    = 1942, // PPCInstrP10.td:1423
    SETNBC8                                   = 1943, // PPCInstrP10.td:1437
    SETNBCR                                   = 1944, // PPCInstrP10.td:1426
    SETNBCR8                                  = 1945, // PPCInstrP10.td:1440
    SETRND                                    = 1946, // PPCInstrInfo.td:1620
    SETRNDi                                   = 1947, // PPCInstrInfo.td:1617
    SLBFEE_rec                                = 1948, // PPCInstrInfo.td:4613
    SLBIA                                     = 1949, // PPCInstrInfo.td:4610
    SLBIE                                     = 1950, // PPCInstrInfo.td:4598
    SLBIEG                                    = 1951, // PPCInstr64Bit.td:2008
    SLBMFEE                                   = 1952, // PPCInstrInfo.td:4604
    SLBMFEV                                   = 1953, // PPCInstrInfo.td:4607
    SLBMTE                                    = 1954, // PPCInstrInfo.td:4601
    SLBSYNC                                   = 1955, // PPCInstr64Bit.td:2011
    SLD                                       = 1956, // PPCInstrInfo.td:1046
    SLD_rec                                   = 1957, // PPCInstrInfo.td:1050
    SLW                                       = 1958, // PPCInstrInfo.td:1046
    SLW8                                      = 1959, // PPCInstrInfo.td:1046
    SLW8_rec                                  = 1960, // PPCInstrInfo.td:1050
    SLW_rec                                   = 1961, // PPCInstrInfo.td:1050
    SPELWZ                                    = 1962, // PPCInstrSPE.td:798
    SPELWZX                                   = 1963, // PPCInstrSPE.td:801
    SPESTW                                    = 1964, // PPCInstrSPE.td:804
    SPESTWX                                   = 1965, // PPCInstrSPE.td:807
    SPILL_ACC                                 = 1966, // PPCInstrMMA.td:523
    SPILL_CR                                  = 1967, // PPCInstrInfo.td:1578
    SPILL_CRBIT                               = 1968, // PPCInstrInfo.td:1580
    SPILL_DMR                                 = 1969, // PPCInstrMMA.td:569
    SPILL_DMRP                                = 1970, // PPCInstrMMA.td:567
    SPILL_QUADWORD                            = 1971, // PPCInstr64Bit.td:1693
    SPILL_UACC                                = 1972, // PPCInstrMMA.td:525
    SPILL_WACC                                = 1973, // PPCInstrMMA.td:565
    SPLIT_QUADWORD                            = 1974, // PPCInstr64Bit.td:373
    SRAD                                      = 1975, // PPCInstrInfo.td:1061
    SRADI                                     = 1976, // PPCInstrInfo.td:1302
    SRADI_32                                  = 1977, // PPCInstr64Bit.td:992
    SRADI_rec                                 = 1978, // PPCInstrInfo.td:1306
    SRAD_rec                                  = 1979, // PPCInstrInfo.td:1065
    SRAW                                      = 1980, // PPCInstrInfo.td:1061
    SRAW8                                     = 1981, // PPCInstrInfo.td:1061
    SRAW8_rec                                 = 1982, // PPCInstrInfo.td:1065
    SRAWI                                     = 1983, // PPCInstrInfo.td:1076
    SRAWI8                                    = 1984, // PPCInstrInfo.td:1076
    SRAWI8_rec                                = 1985, // PPCInstrInfo.td:1080
    SRAWI_rec                                 = 1986, // PPCInstrInfo.td:1080
    SRAW_rec                                  = 1987, // PPCInstrInfo.td:1065
    SRD                                       = 1988, // PPCInstrInfo.td:1046
    SRD_rec                                   = 1989, // PPCInstrInfo.td:1050
    SRW                                       = 1990, // PPCInstrInfo.td:1046
    SRW8                                      = 1991, // PPCInstrInfo.td:1046
    SRW8_rec                                  = 1992, // PPCInstrInfo.td:1050
    SRW_rec                                   = 1993, // PPCInstrInfo.td:1050
    STB                                       = 1994, // PPCInstrInfo.td:2350
    STB8                                      = 1995, // PPCInstr64Bit.td:1643
    STBCIX                                    = 1996, // PPCInstrInfo.td:4722
    STBCX                                     = 1997, // PPCInstrInfo.td:2157
    STBEPX                                    = 1998, // PPCInstrInfo.td:4753
    STBU                                      = 1999, // PPCInstrInfo.td:2371
    STBU8                                     = 2000, // PPCInstr64Bit.td:1712
    STBUX                                     = 2001, // PPCInstrInfo.td:2444
    STBUX8                                    = 2002, // PPCInstr64Bit.td:1722
    STBX                                      = 2003, // PPCInstrInfo.td:2406
    STBX8                                     = 2004, // PPCInstr64Bit.td:1652
    STBXTLS                                   = 2005, // PPCInstr64Bit.td:733
    STBXTLS_                                  = 2006, // PPCInstr64Bit.td:855
    STBXTLS_32                                = 2007, // PPCInstr64Bit.td:745
    STD                                       = 2008, // PPCInstr64Bit.td:1667
    STDAT                                     = 2009, // PPCInstr64Bit.td:428
    STDBRX                                    = 2010, // PPCInstr64Bit.td:1676
    STDCIX                                    = 2011, // PPCInstrInfo.td:4731
    STDCX                                     = 2012, // PPCInstr64Bit.td:364
    STDU                                      = 2013, // PPCInstr64Bit.td:1739
    STDUX                                     = 2014, // PPCInstr64Bit.td:1745
    STDX                                      = 2015, // PPCInstr64Bit.td:1670
    STDXTLS                                   = 2016, // PPCInstr64Bit.td:742
    STDXTLS_                                  = 2017, // PPCInstr64Bit.td:864
    STFD                                      = 2018, // PPCInstrInfo.td:2363
    STFDEPX                                   = 2019, // PPCInstrInfo.td:4757
    STFDU                                     = 2020, // PPCInstrInfo.td:2384
    STFDUX                                    = 2021, // PPCInstrInfo.td:2465
    STFDX                                     = 2022, // PPCInstrInfo.td:2436
    STFDXTLS                                  = 2023, // PPCInstr64Bit.td:760
    STFDXTLS_                                 = 2024, // PPCInstr64Bit.td:873
    STFIWX                                    = 2025, // PPCInstrInfo.td:2429
    STFS                                      = 2026, // PPCInstrInfo.td:2360
    STFSU                                     = 2027, // PPCInstrInfo.td:2381
    STFSUX                                    = 2028, // PPCInstrInfo.td:2460
    STFSX                                     = 2029, // PPCInstrInfo.td:2433
    STFSXTLS                                  = 2030, // PPCInstr64Bit.td:757
    STFSXTLS_                                 = 2031, // PPCInstr64Bit.td:870
    STH                                       = 2032, // PPCInstrInfo.td:2353
    STH8                                      = 2033, // PPCInstr64Bit.td:1646
    STHBRX                                    = 2034, // PPCInstrInfo.td:2419
    STHCIX                                    = 2035, // PPCInstrInfo.td:4725
    STHCX                                     = 2036, // PPCInstrInfo.td:2161
    STHEPX                                    = 2037, // PPCInstrInfo.td:4761
    STHU                                      = 2038, // PPCInstrInfo.td:2374
    STHU8                                     = 2039, // PPCInstr64Bit.td:1715
    STHUX                                     = 2040, // PPCInstrInfo.td:2449
    STHUX8                                    = 2041, // PPCInstr64Bit.td:1727
    STHX                                      = 2042, // PPCInstrInfo.td:2410
    STHX8                                     = 2043, // PPCInstr64Bit.td:1656
    STHXTLS                                   = 2044, // PPCInstr64Bit.td:736
    STHXTLS_                                  = 2045, // PPCInstr64Bit.td:858
    STHXTLS_32                                = 2046, // PPCInstr64Bit.td:748
    STMW                                      = 2047, // PPCInstrInfo.td:2491
    STOP                                      = 2048, // PPCInstrInfo.td:5392
    STQ                                       = 2049, // PPCInstr64Bit.td:1685
    STQCX                                     = 2050, // PPCInstr64Bit.td:368
    STQX_PSEUDO                               = 2051, // PPCInstr64Bit.td:1689
    STSWI                                     = 2052, // PPCInstrInfo.td:4506
    STVEBX                                    = 2053, // PPCInstrAltivec.td:451
    STVEHX                                    = 2054, // PPCInstrAltivec.td:454
    STVEWX                                    = 2055, // PPCInstrAltivec.td:457
    STVX                                      = 2056, // PPCInstrAltivec.td:460
    STVXL                                     = 2057, // PPCInstrAltivec.td:463
    STW                                       = 2058, // PPCInstrInfo.td:2356
    STW8                                      = 2059, // PPCInstr64Bit.td:1649
    STWAT                                     = 2060, // PPCInstrInfo.td:2170
    STWBRX                                    = 2061, // PPCInstrInfo.td:2423
    STWCIX                                    = 2062, // PPCInstrInfo.td:4728
    STWCX                                     = 2063, // PPCInstrInfo.td:2165
    STWEPX                                    = 2064, // PPCInstrInfo.td:4765
    STWU                                      = 2065, // PPCInstrInfo.td:2377
    STWU8                                     = 2066, // PPCInstr64Bit.td:1718
    STWUX                                     = 2067, // PPCInstrInfo.td:2454
    STWUX8                                    = 2068, // PPCInstr64Bit.td:1732
    STWX                                      = 2069, // PPCInstrInfo.td:2414
    STWX8                                     = 2070, // PPCInstr64Bit.td:1660
    STWXTLS                                   = 2071, // PPCInstr64Bit.td:739
    STWXTLS_                                  = 2072, // PPCInstr64Bit.td:861
    STWXTLS_32                                = 2073, // PPCInstr64Bit.td:751
    STXSD                                     = 2074, // PPCInstrVSX.td:1757
    STXSDX                                    = 2075, // PPCInstrVSX.td:374
    STXSIBX                                   = 2076, // PPCInstrVSX.td:1764
    STXSIBXv                                  = 2077, // PPCInstrVSX.td:1769
    STXSIHX                                   = 2078, // PPCInstrVSX.td:1766
    STXSIHXv                                  = 2079, // PPCInstrVSX.td:1770
    STXSIWX                                   = 2080, // PPCInstrVSX.td:1186
    STXSSP                                    = 2081, // PPCInstrVSX.td:1760
    STXSSPX                                   = 2082, // PPCInstrVSX.td:1184
    STXV                                      = 2083, // PPCInstrVSX.td:1754
    STXVB16X                                  = 2084, // PPCInstrVSX.td:1775
    STXVD2X                                   = 2085, // PPCInstrVSX.td:387
    STXVH8X                                   = 2086, // PPCInstrVSX.td:1774
    STXVL                                     = 2087, // PPCInstrVSX.td:1782
    STXVLL                                    = 2088, // PPCInstrVSX.td:1787
    STXVP                                     = 2089, // PPCInstrP10.td:1181
    STXVPB32X                                 = 2090, // PPCInstrFuture.td:427
    STXVPRL                                   = 2091, // PPCInstrFuture.td:420
    STXVPRLL                                  = 2092, // PPCInstrFuture.td:423
    STXVPX                                    = 2093, // PPCInstrP10.td:1184
    STXVRBX                                   = 2094, // PPCInstrP10.td:1862
    STXVRDX                                   = 2095, // PPCInstrP10.td:1865
    STXVRHX                                   = 2096, // PPCInstrP10.td:1863
    STXVRL                                    = 2097, // PPCInstrFuture.td:414
    STXVRLL                                   = 2098, // PPCInstrFuture.td:417
    STXVRWX                                   = 2099, // PPCInstrP10.td:1864
    STXVW4X                                   = 2100, // PPCInstrVSX.td:392
    STXVX                                     = 2101, // PPCInstrVSX.td:1778
    SUBF                                      = 2102, // PPCInstrInfo.td:1120
    SUBF8                                     = 2103, // PPCInstrInfo.td:1120
    SUBF8O                                    = 2104, // PPCInstrInfo.td:1130
    SUBF8O_rec                                = 2105, // PPCInstrInfo.td:1134
    SUBF8_rec                                 = 2106, // PPCInstrInfo.td:1124
    SUBFC                                     = 2107, // PPCInstrInfo.td:1172
    SUBFC8                                    = 2108, // PPCInstrInfo.td:1172
    SUBFC8O                                   = 2109, // PPCInstrInfo.td:1182
    SUBFC8O_rec                               = 2110, // PPCInstrInfo.td:1186
    SUBFC8_rec                                = 2111, // PPCInstrInfo.td:1176
    SUBFCO                                    = 2112, // PPCInstrInfo.td:1182
    SUBFCO_rec                                = 2113, // PPCInstrInfo.td:1186
    SUBFC_rec                                 = 2114, // PPCInstrInfo.td:1176
    SUBFE                                     = 2115, // PPCInstrInfo.td:1172
    SUBFE8                                    = 2116, // PPCInstrInfo.td:1172
    SUBFE8O                                   = 2117, // PPCInstrInfo.td:1182
    SUBFE8O_rec                               = 2118, // PPCInstrInfo.td:1186
    SUBFE8_rec                                = 2119, // PPCInstrInfo.td:1176
    SUBFEO                                    = 2120, // PPCInstrInfo.td:1182
    SUBFEO_rec                                = 2121, // PPCInstrInfo.td:1186
    SUBFE_rec                                 = 2122, // PPCInstrInfo.td:1176
    SUBFIC                                    = 2123, // PPCInstrInfo.td:2555
    SUBFIC8                                   = 2124, // PPCInstr64Bit.td:788
    SUBFME                                    = 2125, // PPCInstrInfo.td:1221
    SUBFME8                                   = 2126, // PPCInstrInfo.td:1221
    SUBFME8O                                  = 2127, // PPCInstrInfo.td:1231
    SUBFME8O_rec                              = 2128, // PPCInstrInfo.td:1235
    SUBFME8_rec                               = 2129, // PPCInstrInfo.td:1225
    SUBFMEO                                   = 2130, // PPCInstrInfo.td:1231
    SUBFMEO_rec                               = 2131, // PPCInstrInfo.td:1235
    SUBFME_rec                                = 2132, // PPCInstrInfo.td:1225
    SUBFO                                     = 2133, // PPCInstrInfo.td:1130
    SUBFO_rec                                 = 2134, // PPCInstrInfo.td:1134
    SUBFUS                                    = 2135, // PPCInstrFuture.td:49
    SUBFUS_rec                                = 2136, // PPCInstrFuture.td:53
    SUBFZE                                    = 2137, // PPCInstrInfo.td:1221
    SUBFZE8                                   = 2138, // PPCInstrInfo.td:1221
    SUBFZE8O                                  = 2139, // PPCInstrInfo.td:1231
    SUBFZE8O_rec                              = 2140, // PPCInstrInfo.td:1235
    SUBFZE8_rec                               = 2141, // PPCInstrInfo.td:1225
    SUBFZEO                                   = 2142, // PPCInstrInfo.td:1231
    SUBFZEO_rec                               = 2143, // PPCInstrInfo.td:1235
    SUBFZE_rec                                = 2144, // PPCInstrInfo.td:1225
    SUBF_rec                                  = 2145, // PPCInstrInfo.td:1124
    SYNC                                      = 2146, // PPCInstrInfo.td:2494
    SYNCP10                                   = 2147, // PPCInstrP10.td:1957
    TABORT                                    = 2148, // PPCInstrHTM.td:33
    TABORTDC                                  = 2149, // PPCInstrHTM.td:50
    TABORTDCI                                 = 2150, // PPCInstrHTM.td:55
    TABORTWC                                  = 2151, // PPCInstrHTM.td:40
    TABORTWCI                                 = 2152, // PPCInstrHTM.td:45
    TAILB                                     = 2153, // PPCInstrInfo.td:1922
    TAILB8                                    = 2154, // PPCInstr64Bit.td:461
    TAILBA                                    = 2155, // PPCInstrInfo.td:1928
    TAILBA8                                   = 2156, // PPCInstr64Bit.td:467
    TAILBCTR                                  = 2157, // PPCInstrInfo.td:1917
    TAILBCTR8                                 = 2158, // PPCInstr64Bit.td:455
    TBEGIN                                    = 2159, // PPCInstrHTM.td:27
    TBEGIN_RET                                = 2160, // PPCInstrHTM.td:20
    TCHECK                                    = 2161, // PPCInstrHTM.td:82
    TCHECK_RET                                = 2162, // PPCInstrHTM.td:19
    TCRETURNai                                = 2163, // PPCInstrInfo.td:1867
    TCRETURNai8                               = 2164, // PPCInstr64Bit.td:443
    TCRETURNdi                                = 2165, // PPCInstrInfo.td:1860
    TCRETURNdi8                               = 2166, // PPCInstr64Bit.td:437
    TCRETURNri                                = 2167, // PPCInstrInfo.td:1872
    TCRETURNri8                               = 2168, // PPCInstr64Bit.td:448
    TD                                        = 2169, // PPCInstrInfo.td:2184
    TDI                                       = 2170, // PPCInstrInfo.td:2182
    TEND                                      = 2171, // PPCInstrHTM.td:30
    TLBIA                                     = 2172, // PPCInstrInfo.td:4616
    TLBIE                                     = 2173, // PPCInstrInfo.td:4630
    TLBIE8P9                                  = 2174, // PPCInstrInfo.td:4640
    TLBIEIO                                   = 2175, // PPCInstrFuture.td:365
    TLBIEL                                    = 2176, // PPCInstrInfo.td:4622
    TLBIEP                                    = 2177, // PPCInstrFuture.td:361
    TLBIEP8                                   = 2178, // PPCInstrFuture.td:371
    TLBIEP9                                   = 2179, // PPCInstrInfo.td:4635
    TLBILX                                    = 2180, // PPCInstrInfo.td:4664
    TLBIVAX                                   = 2181, // PPCInstrInfo.td:4661
    TLBLD                                     = 2182, // PPCInstrInfo.td:4625
    TLBLI                                     = 2183, // PPCInstrInfo.td:4627
    TLBRE                                     = 2184, // PPCInstrInfo.td:4667
    TLBRE2                                    = 2185, // PPCInstrInfo.td:4673
    TLBSX                                     = 2186, // PPCInstrInfo.td:4658
    TLBSX2                                    = 2187, // PPCInstrInfo.td:4679
    TLBSX2D                                   = 2188, // PPCInstrInfo.td:4682
    TLBSYNC                                   = 2189, // PPCInstrInfo.td:4619
    TLBSYNCIO                                 = 2190, // PPCInstrFuture.td:357
    TLBWE                                     = 2191, // PPCInstrInfo.td:4670
    TLBWE2                                    = 2192, // PPCInstrInfo.td:4676
    TLSGDAIX                                  = 2193, // PPCInstrInfo.td:3567
    TLSGDAIX8                                 = 2194, // PPCInstr64Bit.td:1601
    TLSLDAIX                                  = 2195, // PPCInstrInfo.td:3572
    TLSLDAIX8                                 = 2196, // PPCInstr64Bit.td:1607
    TRAP                                      = 2197, // PPCInstrInfo.td:2176
    TRECHKPT                                  = 2198, // PPCInstrHTM.td:72
    TRECLAIM                                  = 2199, // PPCInstrHTM.td:64
    TSR                                       = 2200, // PPCInstrHTM.td:60
    TW                                        = 2201, // PPCInstrInfo.td:2180
    TWI                                       = 2202, // PPCInstrInfo.td:2178
    UNENCODED_NOP                             = 2203, // PPCInstrInfo.td:3631
    UpdateGBR                                 = 2204, // PPCInstrInfo.td:3623
    VABSDUB                                   = 2205, // PPCInstrAltivec.td:1697
    VABSDUH                                   = 2206, // PPCInstrAltivec.td:1700
    VABSDUW                                   = 2207, // PPCInstrAltivec.td:1703
    VADDCUQ                                   = 2208, // PPCInstrAltivec.td:1307
    VADDCUW                                   = 2209, // PPCInstrAltivec.td:516
    VADDECUQ                                  = 2210, // PPCInstrAltivec.td:1308
    VADDEUQM                                  = 2211, // PPCInstrAltivec.td:1306
    VADDFP                                    = 2212, // PPCInstrAltivec.td:502
    VADDSBS                                   = 2213, // PPCInstrAltivec.td:517
    VADDSHS                                   = 2214, // PPCInstrAltivec.td:518
    VADDSWS                                   = 2215, // PPCInstrAltivec.td:519
    VADDUBM                                   = 2216, // PPCInstrAltivec.td:506
    VADDUBS                                   = 2217, // PPCInstrAltivec.td:520
    VADDUDM                                   = 2218, // PPCInstrAltivec.td:1297
    VADDUHM                                   = 2219, // PPCInstrAltivec.td:509
    VADDUHS                                   = 2220, // PPCInstrAltivec.td:521
    VADDUQM                                   = 2221, // PPCInstrAltivec.td:1300
    VADDUWM                                   = 2222, // PPCInstrAltivec.td:512
    VADDUWS                                   = 2223, // PPCInstrAltivec.td:522
    VAND                                      = 2224, // PPCInstrAltivec.td:526
    VANDC                                     = 2225, // PPCInstrAltivec.td:529
    VAVGSB                                    = 2226, // PPCInstrAltivec.td:576
    VAVGSH                                    = 2227, // PPCInstrAltivec.td:577
    VAVGSW                                    = 2228, // PPCInstrAltivec.td:578
    VAVGUB                                    = 2229, // PPCInstrAltivec.td:579
    VAVGUH                                    = 2230, // PPCInstrAltivec.td:580
    VAVGUW                                    = 2231, // PPCInstrAltivec.td:581
    VBPERMD                                   = 2232, // PPCInstrAltivec.td:1585
    VBPERMQ                                   = 2233, // PPCInstrAltivec.td:1427
    VCFSX                                     = 2234, // PPCInstrAltivec.td:534
    VCFSX_0                                   = 2235, // PPCInstrAltivec.td:555
    VCFUGED                                   = 2236, // PPCInstrP10.td:1727
    VCFUX                                     = 2237, // PPCInstrAltivec.td:538
    VCFUX_0                                   = 2238, // PPCInstrAltivec.td:563
    VCIPHER                                   = 2239, // PPCInstrAltivec.td:1437
    VCIPHERLAST                               = 2240, // PPCInstrAltivec.td:1439
    VCLRLB                                    = 2241, // PPCInstrP10.td:1772
    VCLRRB                                    = 2242, // PPCInstrP10.td:1776
    VCLZB                                     = 2243, // PPCInstrAltivec.td:1324
    VCLZD                                     = 2244, // PPCInstrAltivec.td:1333
    VCLZDM                                    = 2245, // PPCInstrP10.td:1744
    VCLZH                                     = 2246, // PPCInstrAltivec.td:1327
    VCLZLSBB                                  = 2247, // PPCInstrAltivec.td:1524
    VCLZW                                     = 2248, // PPCInstrAltivec.td:1330
    VCMPBFP                                   = 2249, // PPCInstrAltivec.td:814
    VCMPBFP_rec                               = 2250, // PPCInstrAltivec.td:815
    VCMPEQFP                                  = 2251, // PPCInstrAltivec.td:816
    VCMPEQFP_rec                              = 2252, // PPCInstrAltivec.td:817
    VCMPEQUB                                  = 2253, // PPCInstrAltivec.td:824
    VCMPEQUB_rec                              = 2254, // PPCInstrAltivec.td:825
    VCMPEQUD                                  = 2255, // PPCInstrAltivec.td:1376
    VCMPEQUD_rec                              = 2256, // PPCInstrAltivec.td:1377
    VCMPEQUH                                  = 2257, // PPCInstrAltivec.td:832
    VCMPEQUH_rec                              = 2258, // PPCInstrAltivec.td:833
    VCMPEQUQ                                  = 2259, // PPCInstrP10.td:1902
    VCMPEQUQ_rec                              = 2260, // PPCInstrP10.td:1905
    VCMPEQUW                                  = 2261, // PPCInstrAltivec.td:840
    VCMPEQUW_rec                              = 2262, // PPCInstrAltivec.td:841
    VCMPGEFP                                  = 2263, // PPCInstrAltivec.td:818
    VCMPGEFP_rec                              = 2264, // PPCInstrAltivec.td:819
    VCMPGTFP                                  = 2265, // PPCInstrAltivec.td:820
    VCMPGTFP_rec                              = 2266, // PPCInstrAltivec.td:821
    VCMPGTSB                                  = 2267, // PPCInstrAltivec.td:826
    VCMPGTSB_rec                              = 2268, // PPCInstrAltivec.td:827
    VCMPGTSD                                  = 2269, // PPCInstrAltivec.td:1378
    VCMPGTSD_rec                              = 2270, // PPCInstrAltivec.td:1379
    VCMPGTSH                                  = 2271, // PPCInstrAltivec.td:834
    VCMPGTSH_rec                              = 2272, // PPCInstrAltivec.td:835
    VCMPGTSQ                                  = 2273, // PPCInstrP10.td:1903
    VCMPGTSQ_rec                              = 2274, // PPCInstrP10.td:1906
    VCMPGTSW                                  = 2275, // PPCInstrAltivec.td:842
    VCMPGTSW_rec                              = 2276, // PPCInstrAltivec.td:843
    VCMPGTUB                                  = 2277, // PPCInstrAltivec.td:828
    VCMPGTUB_rec                              = 2278, // PPCInstrAltivec.td:829
    VCMPGTUD                                  = 2279, // PPCInstrAltivec.td:1380
    VCMPGTUD_rec                              = 2280, // PPCInstrAltivec.td:1381
    VCMPGTUH                                  = 2281, // PPCInstrAltivec.td:836
    VCMPGTUH_rec                              = 2282, // PPCInstrAltivec.td:837
    VCMPGTUQ                                  = 2283, // PPCInstrP10.td:1904
    VCMPGTUQ_rec                              = 2284, // PPCInstrP10.td:1907
    VCMPGTUW                                  = 2285, // PPCInstrAltivec.td:844
    VCMPGTUW_rec                              = 2286, // PPCInstrAltivec.td:845
    VCMPNEB                                   = 2287, // PPCInstrAltivec.td:1456
    VCMPNEB_rec                               = 2288, // PPCInstrAltivec.td:1457
    VCMPNEH                                   = 2289, // PPCInstrAltivec.td:1462
    VCMPNEH_rec                               = 2290, // PPCInstrAltivec.td:1463
    VCMPNEW                                   = 2291, // PPCInstrAltivec.td:1468
    VCMPNEW_rec                               = 2292, // PPCInstrAltivec.td:1469
    VCMPNEZB                                  = 2293, // PPCInstrAltivec.td:1458
    VCMPNEZB_rec                              = 2294, // PPCInstrAltivec.td:1459
    VCMPNEZH                                  = 2295, // PPCInstrAltivec.td:1464
    VCMPNEZH_rec                              = 2296, // PPCInstrAltivec.td:1465
    VCMPNEZW                                  = 2297, // PPCInstrAltivec.td:1470
    VCMPNEZW_rec                              = 2298, // PPCInstrAltivec.td:1471
    VCMPSQ                                    = 2299, // PPCInstrP10.td:1919
    VCMPUQ                                    = 2300, // PPCInstrP10.td:1917
    VCNTMBB                                   = 2301, // PPCInstrP10.td:1629
    VCNTMBD                                   = 2302, // PPCInstrP10.td:1644
    VCNTMBH                                   = 2303, // PPCInstrP10.td:1634
    VCNTMBW                                   = 2304, // PPCInstrP10.td:1639
    VCTSXS                                    = 2305, // PPCInstrAltivec.td:542
    VCTSXS_0                                  = 2306, // PPCInstrAltivec.td:567
    VCTUXS                                    = 2307, // PPCInstrAltivec.td:546
    VCTUXS_0                                  = 2308, // PPCInstrAltivec.td:559
    VCTZB                                     = 2309, // PPCInstrAltivec.td:1533
    VCTZD                                     = 2310, // PPCInstrAltivec.td:1539
    VCTZDM                                    = 2311, // PPCInstrP10.td:1748
    VCTZH                                     = 2312, // PPCInstrAltivec.td:1535
    VCTZLSBB                                  = 2313, // PPCInstrAltivec.td:1528
    VCTZW                                     = 2314, // PPCInstrAltivec.td:1537
    VDIVESD                                   = 2315, // PPCInstrP10.td:1827
    VDIVESQ                                   = 2316, // PPCInstrP10.td:1894
    VDIVESW                                   = 2317, // PPCInstrP10.td:1819
    VDIVEUD                                   = 2318, // PPCInstrP10.td:1831
    VDIVEUQ                                   = 2319, // PPCInstrP10.td:1898
    VDIVEUW                                   = 2320, // PPCInstrP10.td:1823
    VDIVSD                                    = 2321, // PPCInstrP10.td:1813
    VDIVSQ                                    = 2322, // PPCInstrP10.td:1888
    VDIVSW                                    = 2323, // PPCInstrP10.td:1807
    VDIVUD                                    = 2324, // PPCInstrP10.td:1816
    VDIVUQ                                    = 2325, // PPCInstrP10.td:1891
    VDIVUW                                    = 2326, // PPCInstrP10.td:1810
    VEQV                                      = 2327, // PPCInstrAltivec.td:1362
    VEXPANDBM                                 = 2328, // PPCInstrP10.td:1585
    VEXPANDDM                                 = 2329, // PPCInstrP10.td:1597
    VEXPANDHM                                 = 2330, // PPCInstrP10.td:1589
    VEXPANDQM                                 = 2331, // PPCInstrP10.td:1601
    VEXPANDWM                                 = 2332, // PPCInstrP10.td:1593
    VEXPTEFP                                  = 2333, // PPCInstrAltivec.td:572
    VEXTDDVLX                                 = 2334, // PPCInstrP10.td:1697
    VEXTDDVRX                                 = 2335, // PPCInstrP10.td:1705
    VEXTDUBVLX                                = 2336, // PPCInstrP10.td:1649
    VEXTDUBVRX                                = 2337, // PPCInstrP10.td:1657
    VEXTDUHVLX                                = 2338, // PPCInstrP10.td:1665
    VEXTDUHVRX                                = 2339, // PPCInstrP10.td:1673
    VEXTDUWVLX                                = 2340, // PPCInstrP10.td:1681
    VEXTDUWVRX                                = 2341, // PPCInstrP10.td:1689
    VEXTRACTBM                                = 2342, // PPCInstrP10.td:1561
    VEXTRACTD                                 = 2343, // PPCInstrAltivec.td:1488
    VEXTRACTDM                                = 2344, // PPCInstrP10.td:1576
    VEXTRACTHM                                = 2345, // PPCInstrP10.td:1566
    VEXTRACTQM                                = 2346, // PPCInstrP10.td:1581
    VEXTRACTUB                                = 2347, // PPCInstrAltivec.td:1485
    VEXTRACTUH                                = 2348, // PPCInstrAltivec.td:1486
    VEXTRACTUW                                = 2349, // PPCInstrAltivec.td:1487
    VEXTRACTWM                                = 2350, // PPCInstrP10.td:1571
    VEXTSB2D                                  = 2351, // PPCInstrAltivec.td:1547
    VEXTSB2Ds                                 = 2352, // PPCInstrAltivec.td:1556
    VEXTSB2W                                  = 2353, // PPCInstrAltivec.td:1543
    VEXTSB2Ws                                 = 2354, // PPCInstrAltivec.td:1554
    VEXTSD2Q                                  = 2355, // PPCInstrP10.td:1914
    VEXTSH2D                                  = 2356, // PPCInstrAltivec.td:1549
    VEXTSH2Ds                                 = 2357, // PPCInstrAltivec.td:1557
    VEXTSH2W                                  = 2358, // PPCInstrAltivec.td:1545
    VEXTSH2Ws                                 = 2359, // PPCInstrAltivec.td:1555
    VEXTSW2D                                  = 2360, // PPCInstrAltivec.td:1551
    VEXTSW2Ds                                 = 2361, // PPCInstrAltivec.td:1558
    VEXTUBLX                                  = 2362, // PPCInstrAltivec.td:1492
    VEXTUBRX                                  = 2363, // PPCInstrAltivec.td:1493
    VEXTUHLX                                  = 2364, // PPCInstrAltivec.td:1494
    VEXTUHRX                                  = 2365, // PPCInstrAltivec.td:1495
    VEXTUWLX                                  = 2366, // PPCInstrAltivec.td:1496
    VEXTUWRX                                  = 2367, // PPCInstrAltivec.td:1497
    VGBBD                                     = 2368, // PPCInstrAltivec.td:1426
    VGNB                                      = 2369, // PPCInstrP10.td:1731
    VINSBLX                                   = 2370, // PPCInstrP10.td:1519
    VINSBRX                                   = 2371, // PPCInstrP10.td:1524
    VINSBVLX                                  = 2372, // PPCInstrP10.td:1489
    VINSBVRX                                  = 2373, // PPCInstrP10.td:1494
    VINSD                                     = 2374, // PPCInstrP10.td:1483
    VINSDLX                                   = 2375, // PPCInstrP10.td:1549
    VINSDRX                                   = 2376, // PPCInstrP10.td:1555
    VINSERTB                                  = 2377, // PPCInstrAltivec.td:1501
    VINSERTD                                  = 2378, // PPCInstrAltivec.td:1514
    VINSERTH                                  = 2379, // PPCInstrAltivec.td:1507
    VINSERTW                                  = 2380, // PPCInstrAltivec.td:1513
    VINSHLX                                   = 2381, // PPCInstrP10.td:1529
    VINSHRX                                   = 2382, // PPCInstrP10.td:1534
    VINSHVLX                                  = 2383, // PPCInstrP10.td:1499
    VINSHVRX                                  = 2384, // PPCInstrP10.td:1504
    VINSW                                     = 2385, // PPCInstrP10.td:1477
    VINSWLX                                   = 2386, // PPCInstrP10.td:1539
    VINSWRX                                   = 2387, // PPCInstrP10.td:1544
    VINSWVLX                                  = 2388, // PPCInstrP10.td:1509
    VINSWVRX                                  = 2389, // PPCInstrP10.td:1514
    VLOGEFP                                   = 2390, // PPCInstrAltivec.td:573
    VMADDFP                                   = 2391, // PPCInstrAltivec.td:471
    VMAXFP                                    = 2392, // PPCInstrAltivec.td:583
    VMAXSB                                    = 2393, // PPCInstrAltivec.td:584
    VMAXSD                                    = 2394, // PPCInstrAltivec.td:1238
    VMAXSH                                    = 2395, // PPCInstrAltivec.td:585
    VMAXSW                                    = 2396, // PPCInstrAltivec.td:586
    VMAXUB                                    = 2397, // PPCInstrAltivec.td:587
    VMAXUD                                    = 2398, // PPCInstrAltivec.td:1239
    VMAXUH                                    = 2399, // PPCInstrAltivec.td:588
    VMAXUW                                    = 2400, // PPCInstrAltivec.td:589
    VMHADDSHS                                 = 2401, // PPCInstrAltivec.td:483
    VMHRADDSHS                                = 2402, // PPCInstrAltivec.td:484
    VMINFP                                    = 2403, // PPCInstrAltivec.td:590
    VMINSB                                    = 2404, // PPCInstrAltivec.td:591
    VMINSD                                    = 2405, // PPCInstrAltivec.td:1240
    VMINSH                                    = 2406, // PPCInstrAltivec.td:592
    VMINSW                                    = 2407, // PPCInstrAltivec.td:593
    VMINUB                                    = 2408, // PPCInstrAltivec.td:594
    VMINUD                                    = 2409, // PPCInstrAltivec.td:1241
    VMINUH                                    = 2410, // PPCInstrAltivec.td:595
    VMINUW                                    = 2411, // PPCInstrAltivec.td:596
    VMLADDUHM                                 = 2412, // PPCInstrAltivec.td:487
    VMODSD                                    = 2413, // PPCInstrP10.td:1801
    VMODSQ                                    = 2414, // PPCInstrP10.td:1908
    VMODSW                                    = 2415, // PPCInstrP10.td:1795
    VMODUD                                    = 2416, // PPCInstrP10.td:1804
    VMODUQ                                    = 2417, // PPCInstrP10.td:1911
    VMODUW                                    = 2418, // PPCInstrP10.td:1798
    VMRGEW                                    = 2419, // PPCInstrAltivec.td:1245
    VMRGHB                                    = 2420, // PPCInstrAltivec.td:599
    VMRGHH                                    = 2421, // PPCInstrAltivec.td:602
    VMRGHW                                    = 2422, // PPCInstrAltivec.td:605
    VMRGLB                                    = 2423, // PPCInstrAltivec.td:608
    VMRGLH                                    = 2424, // PPCInstrAltivec.td:611
    VMRGLW                                    = 2425, // PPCInstrAltivec.td:614
    VMRGOW                                    = 2426, // PPCInstrAltivec.td:1249
    VMSUMCUD                                  = 2427, // PPCInstrP10.td:1884
    VMSUMMBM                                  = 2428, // PPCInstrAltivec.td:618
    VMSUMSHM                                  = 2429, // PPCInstrAltivec.td:620
    VMSUMSHS                                  = 2430, // PPCInstrAltivec.td:627
    VMSUMUBM                                  = 2431, // PPCInstrAltivec.td:622
    VMSUMUDM                                  = 2432, // PPCInstrAltivec.td:1452
    VMSUMUHM                                  = 2433, // PPCInstrAltivec.td:624
    VMSUMUHS                                  = 2434, // PPCInstrAltivec.td:629
    VMUL10CUQ                                 = 2435, // PPCInstrAltivec.td:1625
    VMUL10ECUQ                                = 2436, // PPCInstrAltivec.td:1630
    VMUL10EUQ                                 = 2437, // PPCInstrAltivec.td:1629
    VMUL10UQ                                  = 2438, // PPCInstrAltivec.td:1623
    VMULESB                                   = 2439, // PPCInstrAltivec.td:634
    VMULESD                                   = 2440, // PPCInstrP10.td:1868
    VMULESH                                   = 2441, // PPCInstrAltivec.td:636
    VMULESW                                   = 2442, // PPCInstrAltivec.td:1227
    VMULEUB                                   = 2443, // PPCInstrAltivec.td:638
    VMULEUD                                   = 2444, // PPCInstrP10.td:1872
    VMULEUH                                   = 2445, // PPCInstrAltivec.td:640
    VMULEUW                                   = 2446, // PPCInstrAltivec.td:1229
    VMULHSD                                   = 2447, // PPCInstrP10.td:1789
    VMULHSW                                   = 2448, // PPCInstrP10.td:1783
    VMULHUD                                   = 2449, // PPCInstrP10.td:1792
    VMULHUW                                   = 2450, // PPCInstrP10.td:1786
    VMULLD                                    = 2451, // PPCInstrP10.td:1780
    VMULOSB                                   = 2452, // PPCInstrAltivec.td:642
    VMULOSD                                   = 2453, // PPCInstrP10.td:1876
    VMULOSH                                   = 2454, // PPCInstrAltivec.td:644
    VMULOSW                                   = 2455, // PPCInstrAltivec.td:1231
    VMULOUB                                   = 2456, // PPCInstrAltivec.td:646
    VMULOUD                                   = 2457, // PPCInstrP10.td:1880
    VMULOUH                                   = 2458, // PPCInstrAltivec.td:648
    VMULOUW                                   = 2459, // PPCInstrAltivec.td:1233
    VMULUWM                                   = 2460, // PPCInstrAltivec.td:1235
    VNAND                                     = 2461, // PPCInstrAltivec.td:1365
    VNCIPHER                                  = 2462, // PPCInstrAltivec.td:1441
    VNCIPHERLAST                              = 2463, // PPCInstrAltivec.td:1443
    VNEGD                                     = 2464, // PPCInstrAltivec.td:1572
    VNEGW                                     = 2465, // PPCInstrAltivec.td:1568
    VNMSUBFP                                  = 2466, // PPCInstrAltivec.td:477
    VNOR                                      = 2467, // PPCInstrAltivec.td:693
    VOR                                       = 2468, // PPCInstrAltivec.td:698
    VORC                                      = 2469, // PPCInstrAltivec.td:1370
    VPDEPD                                    = 2470, // PPCInstrP10.td:1713
    VPERM                                     = 2471, // PPCInstrAltivec.td:490
    VPERMR                                    = 2472, // PPCInstrAltivec.td:1587
    VPERMXOR                                  = 2473, // PPCInstrAltivec.td:1392
    VPEXTD                                    = 2474, // PPCInstrP10.td:1717
    VPKPX                                     = 2475, // PPCInstrAltivec.td:759
    VPKSDSS                                   = 2476, // PPCInstrAltivec.td:1397
    VPKSDUS                                   = 2477, // PPCInstrAltivec.td:1399
    VPKSHSS                                   = 2478, // PPCInstrAltivec.td:762
    VPKSHUS                                   = 2479, // PPCInstrAltivec.td:764
    VPKSWSS                                   = 2480, // PPCInstrAltivec.td:766
    VPKSWUS                                   = 2481, // PPCInstrAltivec.td:768
    VPKUDUM                                   = 2482, // PPCInstrAltivec.td:1404
    VPKUDUS                                   = 2483, // PPCInstrAltivec.td:1401
    VPKUHUM                                   = 2484, // PPCInstrAltivec.td:775
    VPKUHUS                                   = 2485, // PPCInstrAltivec.td:770
    VPKUWUM                                   = 2486, // PPCInstrAltivec.td:779
    VPKUWUS                                   = 2487, // PPCInstrAltivec.td:772
    VPMSUMB                                   = 2488, // PPCInstrAltivec.td:1384
    VPMSUMD                                   = 2489, // PPCInstrAltivec.td:1390
    VPMSUMH                                   = 2490, // PPCInstrAltivec.td:1386
    VPMSUMW                                   = 2491, // PPCInstrAltivec.td:1388
    VPOPCNTB                                  = 2492, // PPCInstrAltivec.td:1338
    VPOPCNTD                                  = 2493, // PPCInstrAltivec.td:1347
    VPOPCNTH                                  = 2494, // PPCInstrAltivec.td:1341
    VPOPCNTW                                  = 2495, // PPCInstrAltivec.td:1344
    VPRTYBD                                   = 2496, // PPCInstrAltivec.td:1579
    VPRTYBQ                                   = 2497, // PPCInstrAltivec.td:1581
    VPRTYBW                                   = 2498, // PPCInstrAltivec.td:1577
    VREFP                                     = 2499, // PPCInstrAltivec.td:652
    VRFIM                                     = 2500, // PPCInstrAltivec.td:653
    VRFIN                                     = 2501, // PPCInstrAltivec.td:654
    VRFIP                                     = 2502, // PPCInstrAltivec.td:655
    VRFIZ                                     = 2503, // PPCInstrAltivec.td:656
    VRLB                                      = 2504, // PPCInstrAltivec.td:706
    VRLD                                      = 2505, // PPCInstrAltivec.td:1269
    VRLDMI                                    = 2506, // PPCInstrAltivec.td:1609
    VRLDNM                                    = 2507, // PPCInstrAltivec.td:1605
    VRLH                                      = 2508, // PPCInstrAltivec.td:707
    VRLQ                                      = 2509, // PPCInstrP10.td:1936
    VRLQMI                                    = 2510, // PPCInstrP10.td:1925
    VRLQNM                                    = 2511, // PPCInstrP10.td:1921
    VRLW                                      = 2512, // PPCInstrAltivec.td:708
    VRLWMI                                    = 2513, // PPCInstrAltivec.td:1599
    VRLWNM                                    = 2514, // PPCInstrAltivec.td:1595
    VRSQRTEFP                                 = 2515, // PPCInstrAltivec.td:657
    VSBOX                                     = 2516, // PPCInstrAltivec.td:1445
    VSEL                                      = 2517, // PPCInstrAltivec.td:492
    VSHASIGMAD                                = 2518, // PPCInstrAltivec.td:1435
    VSHASIGMAW                                = 2519, // PPCInstrAltivec.td:1433
    VSL                                       = 2520, // PPCInstrAltivec.td:711
    VSLB                                      = 2521, // PPCInstrAltivec.td:714
    VSLD                                      = 2522, // PPCInstrAltivec.td:1275
    VSLDBI                                    = 2523, // PPCInstrP10.td:1445
    VSLDOI                                    = 2524, // PPCInstrAltivec.td:495
    VSLH                                      = 2525, // PPCInstrAltivec.td:715
    VSLO                                      = 2526, // PPCInstrAltivec.td:712
    VSLQ                                      = 2527, // PPCInstrP10.td:1932
    VSLV                                      = 2528, // PPCInstrAltivec.td:1617
    VSLW                                      = 2529, // PPCInstrAltivec.td:716
    VSPLTB                                    = 2530, // PPCInstrAltivec.td:718
    VSPLTBs                                   = 2531, // PPCInstrAltivec.td:731
    VSPLTH                                    = 2532, // PPCInstrAltivec.td:722
    VSPLTHs                                   = 2533, // PPCInstrAltivec.td:733
    VSPLTISB                                  = 2534, // PPCInstrAltivec.td:748
    VSPLTISH                                  = 2535, // PPCInstrAltivec.td:751
    VSPLTISW                                  = 2536, // PPCInstrAltivec.td:754
    VSPLTW                                    = 2537, // PPCInstrAltivec.td:726
    VSR                                       = 2538, // PPCInstrAltivec.td:737
    VSRAB                                     = 2539, // PPCInstrAltivec.td:740
    VSRAD                                     = 2540, // PPCInstrAltivec.td:1279
    VSRAH                                     = 2541, // PPCInstrAltivec.td:741
    VSRAQ                                     = 2542, // PPCInstrP10.td:1933
    VSRAW                                     = 2543, // PPCInstrAltivec.td:742
    VSRB                                      = 2544, // PPCInstrAltivec.td:743
    VSRD                                      = 2545, // PPCInstrAltivec.td:1277
    VSRDBI                                    = 2546, // PPCInstrP10.td:1453
    VSRH                                      = 2547, // PPCInstrAltivec.td:744
    VSRO                                      = 2548, // PPCInstrAltivec.td:738
    VSRQ                                      = 2549, // PPCInstrP10.td:1934
    VSRV                                      = 2550, // PPCInstrAltivec.td:1619
    VSRW                                      = 2551, // PPCInstrAltivec.td:745
    VSTRIBL                                   = 2552, // PPCInstrP10.td:198
    VSTRIBL_rec                               = 2553, // PPCInstrP10.td:202
    VSTRIBR                                   = 2554, // PPCInstrP10.td:198
    VSTRIBR_rec                               = 2555, // PPCInstrP10.td:202
    VSTRIHL                                   = 2556, // PPCInstrP10.td:198
    VSTRIHL_rec                               = 2557, // PPCInstrP10.td:202
    VSTRIHR                                   = 2558, // PPCInstrP10.td:198
    VSTRIHR_rec                               = 2559, // PPCInstrP10.td:202
    VSUBCUQ                                   = 2560, // PPCInstrAltivec.td:1320
    VSUBCUW                                   = 2561, // PPCInstrAltivec.td:659
    VSUBECUQ                                  = 2562, // PPCInstrAltivec.td:1321
    VSUBEUQM                                  = 2563, // PPCInstrAltivec.td:1319
    VSUBFP                                    = 2564, // PPCInstrAltivec.td:661
    VSUBSBS                                   = 2565, // PPCInstrAltivec.td:674
    VSUBSHS                                   = 2566, // PPCInstrAltivec.td:675
    VSUBSWS                                   = 2567, // PPCInstrAltivec.td:676
    VSUBUBM                                   = 2568, // PPCInstrAltivec.td:664
    VSUBUBS                                   = 2569, // PPCInstrAltivec.td:677
    VSUBUDM                                   = 2570, // PPCInstrAltivec.td:1311
    VSUBUHM                                   = 2571, // PPCInstrAltivec.td:667
    VSUBUHS                                   = 2572, // PPCInstrAltivec.td:678
    VSUBUQM                                   = 2573, // PPCInstrAltivec.td:1316
    VSUBUWM                                   = 2574, // PPCInstrAltivec.td:670
    VSUBUWS                                   = 2575, // PPCInstrAltivec.td:679
    VSUM2SWS                                  = 2576, // PPCInstrAltivec.td:683
    VSUM4SBS                                  = 2577, // PPCInstrAltivec.td:685
    VSUM4SHS                                  = 2578, // PPCInstrAltivec.td:687
    VSUM4UBS                                  = 2579, // PPCInstrAltivec.td:689
    VSUMSWS                                   = 2580, // PPCInstrAltivec.td:682
    VUCMPRHB                                  = 2581, // PPCInstrFuture.td:470
    VUCMPRHH                                  = 2582, // PPCInstrFuture.td:480
    VUCMPRHN                                  = 2583, // PPCInstrFuture.td:462
    VUCMPRLB                                  = 2584, // PPCInstrFuture.td:475
    VUCMPRLH                                  = 2585, // PPCInstrFuture.td:485
    VUCMPRLN                                  = 2586, // PPCInstrFuture.td:466
    VUPKHPX                                   = 2587, // PPCInstrAltivec.td:785
    VUPKHSB                                   = 2588, // PPCInstrAltivec.td:787
    VUPKHSH                                   = 2589, // PPCInstrAltivec.td:789
    VUPKHSNTOB                                = 2590, // PPCInstrFuture.td:433
    VUPKHSW                                   = 2591, // PPCInstrAltivec.td:1408
    VUPKINT4TOBF16                            = 2592, // PPCInstrFuture.td:441
    VUPKINT4TOFP32                            = 2593, // PPCInstrFuture.td:456
    VUPKINT8TOBF16                            = 2594, // PPCInstrFuture.td:446
    VUPKINT8TOFP32                            = 2595, // PPCInstrFuture.td:451
    VUPKLPX                                   = 2596, // PPCInstrAltivec.td:791
    VUPKLSB                                   = 2597, // PPCInstrAltivec.td:793
    VUPKLSH                                   = 2598, // PPCInstrAltivec.td:795
    VUPKLSNTOB                                = 2599, // PPCInstrFuture.td:437
    VUPKLSW                                   = 2600, // PPCInstrAltivec.td:1410
    VXOR                                      = 2601, // PPCInstrAltivec.td:701
    V_SET0                                    = 2602, // PPCInstrAltivec.td:856
    V_SET0B                                   = 2603, // PPCInstrAltivec.td:850
    V_SET0H                                   = 2604, // PPCInstrAltivec.td:853
    V_SETALLONES                              = 2605, // PPCInstrAltivec.td:867
    V_SETALLONESB                             = 2606, // PPCInstrAltivec.td:861
    V_SETALLONESH                             = 2607, // PPCInstrAltivec.td:864
    WAIT                                      = 2608, // PPCInstrInfo.td:4516
    WAITP10                                   = 2609, // PPCInstrP10.td:1955
    WRTEE                                     = 2610, // PPCInstrInfo.td:4537
    WRTEEI                                    = 2611, // PPCInstrInfo.td:4542
    XOR                                       = 2612, // PPCInstrInfo.td:1046
    XOR8                                      = 2613, // PPCInstrInfo.td:1046
    XOR8_rec                                  = 2614, // PPCInstrInfo.td:1050
    XORI                                      = 2615, // PPCInstrInfo.td:2590
    XORI8                                     = 2616, // PPCInstr64Bit.td:682
    XORIS                                     = 2617, // PPCInstrInfo.td:2593
    XORIS8                                    = 2618, // PPCInstr64Bit.td:685
    XOR_rec                                   = 2619, // PPCInstrInfo.td:1050
    XSABSDP                                   = 2620, // PPCInstrVSX.td:750
    XSABSQP                                   = 2621, // PPCInstrVSX.td:1408
    XSADDADDSUQM                              = 2622, // PPCInstrFuture.td:567
    XSADDADDUQM                               = 2623, // PPCInstrFuture.td:564
    XSADDDP                                   = 2624, // PPCInstrVSX.td:403
    XSADDQP                                   = 2625, // PPCInstrVSX.td:1421
    XSADDQPO                                  = 2626, // PPCInstrVSX.td:1451
    XSADDSP                                   = 2627, // PPCInstrVSX.td:1201
    XSADDSUBSUQM                              = 2628, // PPCInstrFuture.td:573
    XSADDSUBUQM                               = 2629, // PPCInstrFuture.td:570
    XSCMPEQDP                                 = 2630, // PPCInstrVSX.td:1508
    XSCMPEQQP                                 = 2631, // PPCInstrP10.td:1225
    XSCMPEXPDP                                = 2632, // PPCInstrVSX.td:1496
    XSCMPEXPQP                                = 2633, // PPCInstrVSX.td:1499
    XSCMPGEDP                                 = 2634, // PPCInstrVSX.td:1510
    XSCMPGEQP                                 = 2635, // PPCInstrP10.td:1226
    XSCMPGTDP                                 = 2636, // PPCInstrVSX.td:1512
    XSCMPGTQP                                 = 2637, // PPCInstrP10.td:1227
    XSCMPODP                                  = 2638, // PPCInstrVSX.td:722
    XSCMPOQP                                  = 2639, // PPCInstrVSX.td:1502
    XSCMPUDP                                  = 2640, // PPCInstrVSX.td:725
    XSCMPUQP                                  = 2641, // PPCInstrVSX.td:1503
    XSCPSGNDP                                 = 2642, // PPCInstrVSX.td:767
    XSCPSGNQP                                 = 2643, // PPCInstrVSX.td:1403
    XSCVDPHP                                  = 2644, // PPCInstrVSX.td:1555
    XSCVDPQP                                  = 2645, // PPCInstrVSX.td:1522
    XSCVDPSP                                  = 2646, // PPCInstrVSX.td:811
    XSCVDPSPN                                 = 2647, // PPCInstrVSX.td:1331
    XSCVDPSXDS                                = 2648, // PPCInstrVSX.td:814
    XSCVDPSXDSs                               = 2649, // PPCInstrVSX.td:819
    XSCVDPSXWS                                = 2650, // PPCInstrVSX.td:823
    XSCVDPSXWSs                               = 2651, // PPCInstrVSX.td:828
    XSCVDPUXDS                                = 2652, // PPCInstrVSX.td:832
    XSCVDPUXDSs                               = 2653, // PPCInstrVSX.td:837
    XSCVDPUXWS                                = 2654, // PPCInstrVSX.td:841
    XSCVDPUXWSs                               = 2655, // PPCInstrVSX.td:846
    XSCVHPDP                                  = 2656, // PPCInstrVSX.td:1556
    XSCVQPDP                                  = 2657, // PPCInstrVSX.td:1526
    XSCVQPDPO                                 = 2658, // PPCInstrVSX.td:1527
    XSCVQPSDZ                                 = 2659, // PPCInstrVSX.td:1535
    XSCVQPSQZ                                 = 2660, // PPCInstrP10.td:1938
    XSCVQPSWZ                                 = 2661, // PPCInstrVSX.td:1537
    XSCVQPUDZ                                 = 2662, // PPCInstrVSX.td:1539
    XSCVQPUQZ                                 = 2663, // PPCInstrP10.td:1937
    XSCVQPUWZ                                 = 2664, // PPCInstrVSX.td:1541
    XSCVSDQP                                  = 2665, // PPCInstrVSX.td:1546
    XSCVSPDP                                  = 2666, // PPCInstrVSX.td:850
    XSCVSPDPN                                 = 2667, // PPCInstrVSX.td:1333
    XSCVSQQP                                  = 2668, // PPCInstrP10.td:1940
    XSCVSXDDP                                 = 2669, // PPCInstrVSX.td:853
    XSCVSXDSP                                 = 2670, // PPCInstrVSX.td:1320
    XSCVUDQP                                  = 2671, // PPCInstrVSX.td:1547
    XSCVUQQP                                  = 2672, // PPCInstrP10.td:1939
    XSCVUXDDP                                 = 2673, // PPCInstrVSX.td:857
    XSCVUXDSP                                 = 2674, // PPCInstrVSX.td:1324
    XSDIVDP                                   = 2675, // PPCInstrVSX.td:642
    XSDIVQP                                   = 2676, // PPCInstrVSX.td:1428
    XSDIVQPO                                  = 2677, // PPCInstrVSX.td:1464
    XSDIVSP                                   = 2678, // PPCInstrVSX.td:1215
    XSIEXPDP                                  = 2679, // PPCInstrVSX.td:1583
    XSIEXPQP                                  = 2680, // PPCInstrVSX.td:1589
    XSMADDADP                                 = 2681, // PPCInstrVSX.td:451
    XSMADDASP                                 = 2682, // PPCInstrVSX.td:1242
    XSMADDMDP                                 = 2683, // PPCInstrVSX.td:458
    XSMADDMSP                                 = 2684, // PPCInstrVSX.td:1251
    XSMADDQP                                  = 2685, // PPCInstrVSX.td:1434
    XSMADDQPO                                 = 2686, // PPCInstrVSX.td:1473
    XSMAXCDP                                  = 2687, // PPCInstrVSX.td:1670
    XSMAXCQP                                  = 2688, // PPCInstrP10.td:1948
    XSMAXDP                                   = 2689, // PPCInstrVSX.td:951
    XSMAXJDP                                  = 2690, // PPCInstrVSX.td:1679
    XSMERGE2T1UQM                             = 2691, // PPCInstrFuture.td:576
    XSMERGE2T2UQM                             = 2692, // PPCInstrFuture.td:579
    XSMERGE2T3UQM                             = 2693, // PPCInstrFuture.td:582
    XSMERGE3T1UQM                             = 2694, // PPCInstrFuture.td:585
    XSMINCDP                                  = 2695, // PPCInstrVSX.td:1673
    XSMINCQP                                  = 2696, // PPCInstrP10.td:1950
    XSMINDP                                   = 2697, // PPCInstrVSX.td:956
    XSMINJDP                                  = 2698, // PPCInstrVSX.td:1681
    XSMSUBADP                                 = 2699, // PPCInstrVSX.td:467
    XSMSUBASP                                 = 2700, // PPCInstrVSX.td:1261
    XSMSUBMDP                                 = 2701, // PPCInstrVSX.td:474
    XSMSUBMSP                                 = 2702, // PPCInstrVSX.td:1271
    XSMSUBQP                                  = 2703, // PPCInstrVSX.td:1437
    XSMSUBQPO                                 = 2704, // PPCInstrVSX.td:1478
    XSMULDP                                   = 2705, // PPCInstrVSX.td:407
    XSMULQP                                   = 2706, // PPCInstrVSX.td:1423
    XSMULQPO                                  = 2707, // PPCInstrVSX.td:1455
    XSMULSP                                   = 2708, // PPCInstrVSX.td:1205
    XSNABSDP                                  = 2709, // PPCInstrVSX.td:754
    XSNABSDPs                                 = 2710, // PPCInstrVSX.td:759
    XSNABSQP                                  = 2711, // PPCInstrVSX.td:1410
    XSNEGDP                                   = 2712, // PPCInstrVSX.td:763
    XSNEGQP                                   = 2713, // PPCInstrVSX.td:1412
    XSNMADDADP                                = 2714, // PPCInstrVSX.td:483
    XSNMADDASP                                = 2715, // PPCInstrVSX.td:1281
    XSNMADDMDP                                = 2716, // PPCInstrVSX.td:490
    XSNMADDMSP                                = 2717, // PPCInstrVSX.td:1291
    XSNMADDQP                                 = 2718, // PPCInstrVSX.td:1441
    XSNMADDQPO                                = 2719, // PPCInstrVSX.td:1482
    XSNMSUBADP                                = 2720, // PPCInstrVSX.td:499
    XSNMSUBASP                                = 2721, // PPCInstrVSX.td:1301
    XSNMSUBMDP                                = 2722, // PPCInstrVSX.td:506
    XSNMSUBMSP                                = 2723, // PPCInstrVSX.td:1311
    XSNMSUBQP                                 = 2724, // PPCInstrVSX.td:1445
    XSNMSUBQPO                                = 2725, // PPCInstrVSX.td:1486
    XSRDPI                                    = 2726, // PPCInstrVSX.td:987
    XSRDPIC                                   = 2727, // PPCInstrVSX.td:940
    XSRDPIM                                   = 2728, // PPCInstrVSX.td:991
    XSRDPIP                                   = 2729, // PPCInstrVSX.td:995
    XSRDPIZ                                   = 2730, // PPCInstrVSX.td:999
    XSREBASE2T1UQM                            = 2731, // PPCInstrFuture.td:588
    XSREBASE2T2UQM                            = 2732, // PPCInstrFuture.td:591
    XSREBASE2T3UQM                            = 2733, // PPCInstrFuture.td:594
    XSREBASE2T4UQM                            = 2734, // PPCInstrFuture.td:597
    XSREBASE3T1UQM                            = 2735, // PPCInstrFuture.td:600
    XSREBASE3T2UQM                            = 2736, // PPCInstrFuture.td:603
    XSREBASE3T3UQM                            = 2737, // PPCInstrFuture.td:606
    XSREDP                                    = 2738, // PPCInstrVSX.td:651
    XSRESP                                    = 2739, // PPCInstrVSX.td:1220
    XSRQPI                                    = 2740, // PPCInstrVSX.td:1569
    XSRQPIX                                   = 2741, // PPCInstrVSX.td:1570
    XSRQPXP                                   = 2742, // PPCInstrVSX.td:1575
    XSRSP                                     = 2743, // PPCInstrVSX.td:1226
    XSRSQRTEDP                                = 2744, // PPCInstrVSX.td:655
    XSRSQRTESP                                = 2745, // PPCInstrVSX.td:1234
    XSSQRTDP                                  = 2746, // PPCInstrVSX.td:646
    XSSQRTQP                                  = 2747, // PPCInstrVSX.td:1431
    XSSQRTQPO                                 = 2748, // PPCInstrVSX.td:1468
    XSSQRTSP                                  = 2749, // PPCInstrVSX.td:1230
    XSSUBDP                                   = 2750, // PPCInstrVSX.td:434
    XSSUBQP                                   = 2751, // PPCInstrVSX.td:1426
    XSSUBQPO                                  = 2752, // PPCInstrVSX.td:1460
    XSSUBSP                                   = 2753, // PPCInstrVSX.td:1211
    XSTDIVDP                                  = 2754, // PPCInstrVSX.td:661
    XSTSQRTDP                                 = 2755, // PPCInstrVSX.td:664
    XSTSTDCDP                                 = 2756, // PPCInstrVSX.td:1646
    XSTSTDCQP                                 = 2757, // PPCInstrVSX.td:1649
    XSTSTDCSP                                 = 2758, // PPCInstrVSX.td:1643
    XSXEXPDP                                  = 2759, // PPCInstrVSX.td:1594
    XSXEXPQP                                  = 2760, // PPCInstrVSX.td:1599
    XSXSIGDP                                  = 2761, // PPCInstrVSX.td:1595
    XSXSIGQP                                  = 2762, // PPCInstrVSX.td:1600
    XVABSDP                                   = 2763, // PPCInstrVSX.td:772
    XVABSSP                                   = 2764, // PPCInstrVSX.td:777
    XVADDDP                                   = 2765, // PPCInstrVSX.td:412
    XVADDSP                                   = 2766, // PPCInstrVSX.td:417
    XVADDUHM                                  = 2767, // PPCInstrFuture.td:526
    XVADDUWM                                  = 2768, // PPCInstrFuture.td:524
    XVBF16GER2                                = 2769, // PPCInstrMMA.td:10
    XVBF16GER2NN                              = 2770, // PPCInstrMMA.td:228
    XVBF16GER2NP                              = 2771, // PPCInstrMMA.td:224
    XVBF16GER2PN                              = 2772, // PPCInstrMMA.td:220
    XVBF16GER2PP                              = 2773, // PPCInstrMMA.td:14
    XVBF16GER2W                               = 2774, // PPCInstrMMA.td:20
    XVBF16GER2WNN                             = 2775, // PPCInstrMMA.td:242
    XVBF16GER2WNP                             = 2776, // PPCInstrMMA.td:238
    XVBF16GER2WPN                             = 2777, // PPCInstrMMA.td:234
    XVBF16GER2WPP                             = 2778, // PPCInstrMMA.td:24
    XVCMPEQDP                                 = 2779, // PPCInstrVSX.td:199
    XVCMPEQDP_rec                             = 2780, // PPCInstrVSX.td:203
    XVCMPEQSP                                 = 2781, // PPCInstrVSX.td:199
    XVCMPEQSP_rec                             = 2782, // PPCInstrVSX.td:203
    XVCMPGEDP                                 = 2783, // PPCInstrVSX.td:199
    XVCMPGEDP_rec                             = 2784, // PPCInstrVSX.td:203
    XVCMPGESP                                 = 2785, // PPCInstrVSX.td:199
    XVCMPGESP_rec                             = 2786, // PPCInstrVSX.td:203
    XVCMPGTDP                                 = 2787, // PPCInstrVSX.td:199
    XVCMPGTDP_rec                             = 2788, // PPCInstrVSX.td:203
    XVCMPGTSP                                 = 2789, // PPCInstrVSX.td:199
    XVCMPGTSP_rec                             = 2790, // PPCInstrVSX.td:203
    XVCPSGNDP                                 = 2791, // PPCInstrVSX.td:782
    XVCPSGNSP                                 = 2792, // PPCInstrVSX.td:786
    XVCVBF16SPN                               = 2793, // PPCInstrP10.td:1947
    XVCVDPSP                                  = 2794, // PPCInstrVSX.td:862
    XVCVDPSXDS                                = 2795, // PPCInstrVSX.td:866
    XVCVDPSXWS                                = 2796, // PPCInstrVSX.td:870
    XVCVDPUXDS                                = 2797, // PPCInstrVSX.td:874
    XVCVDPUXWS                                = 2798, // PPCInstrVSX.td:878
    XVCVHPSP                                  = 2799, // PPCInstrVSX.td:1563
    XVCVSPBF16                                = 2800, // PPCInstrP10.td:1946
    XVCVSPDP                                  = 2801, // PPCInstrVSX.td:883
    XVCVSPHP                                  = 2802, // PPCInstrVSX.td:1564
    XVCVSPSXDS                                = 2803, // PPCInstrVSX.td:887
    XVCVSPSXWS                                = 2804, // PPCInstrVSX.td:891
    XVCVSPUXDS                                = 2805, // PPCInstrVSX.td:895
    XVCVSPUXWS                                = 2806, // PPCInstrVSX.td:899
    XVCVSXDDP                                 = 2807, // PPCInstrVSX.td:903
    XVCVSXDSP                                 = 2808, // PPCInstrVSX.td:907
    XVCVSXWDP                                 = 2809, // PPCInstrVSX.td:929
    XVCVSXWSP                                 = 2810, // PPCInstrVSX.td:911
    XVCVUXDDP                                 = 2811, // PPCInstrVSX.td:915
    XVCVUXDSP                                 = 2812, // PPCInstrVSX.td:919
    XVCVUXWDP                                 = 2813, // PPCInstrVSX.td:933
    XVCVUXWSP                                 = 2814, // PPCInstrVSX.td:923
    XVDIVDP                                   = 2815, // PPCInstrVSX.td:685
    XVDIVSP                                   = 2816, // PPCInstrVSX.td:689
    XVF16GER2                                 = 2817, // PPCInstrMMA.td:10
    XVF16GER2NN                               = 2818, // PPCInstrMMA.td:228
    XVF16GER2NP                               = 2819, // PPCInstrMMA.td:224
    XVF16GER2PN                               = 2820, // PPCInstrMMA.td:220
    XVF16GER2PP                               = 2821, // PPCInstrMMA.td:14
    XVF16GER2W                                = 2822, // PPCInstrMMA.td:20
    XVF16GER2WNN                              = 2823, // PPCInstrMMA.td:242
    XVF16GER2WNP                              = 2824, // PPCInstrMMA.td:238
    XVF16GER2WPN                              = 2825, // PPCInstrMMA.td:234
    XVF16GER2WPP                              = 2826, // PPCInstrMMA.td:24
    XVF32GER                                  = 2827, // PPCInstrMMA.td:10
    XVF32GERNN                                = 2828, // PPCInstrMMA.td:309
    XVF32GERNP                                = 2829, // PPCInstrMMA.td:305
    XVF32GERPN                                = 2830, // PPCInstrMMA.td:301
    XVF32GERPP                                = 2831, // PPCInstrMMA.td:14
    XVF32GERW                                 = 2832, // PPCInstrMMA.td:20
    XVF32GERWNN                               = 2833, // PPCInstrMMA.td:323
    XVF32GERWNP                               = 2834, // PPCInstrMMA.td:319
    XVF32GERWPN                               = 2835, // PPCInstrMMA.td:315
    XVF32GERWPP                               = 2836, // PPCInstrMMA.td:24
    XVF64GER                                  = 2837, // PPCInstrMMA.td:10
    XVF64GERNN                                = 2838, // PPCInstrMMA.td:309
    XVF64GERNP                                = 2839, // PPCInstrMMA.td:305
    XVF64GERPN                                = 2840, // PPCInstrMMA.td:301
    XVF64GERPP                                = 2841, // PPCInstrMMA.td:14
    XVF64GERW                                 = 2842, // PPCInstrMMA.td:20
    XVF64GERWNN                               = 2843, // PPCInstrMMA.td:323
    XVF64GERWNP                               = 2844, // PPCInstrMMA.td:319
    XVF64GERWPN                               = 2845, // PPCInstrMMA.td:315
    XVF64GERWPP                               = 2846, // PPCInstrMMA.td:24
    XVI16GER2                                 = 2847, // PPCInstrMMA.td:157
    XVI16GER2PP                               = 2848, // PPCInstrMMA.td:161
    XVI16GER2S                                = 2849, // PPCInstrMMA.td:10
    XVI16GER2SPP                              = 2850, // PPCInstrMMA.td:14
    XVI16GER2SW                               = 2851, // PPCInstrMMA.td:20
    XVI16GER2SWPP                             = 2852, // PPCInstrMMA.td:24
    XVI16GER2W                                = 2853, // PPCInstrMMA.td:185
    XVI16GER2WPP                              = 2854, // PPCInstrMMA.td:189
    XVI4GER8                                  = 2855, // PPCInstrMMA.td:10
    XVI4GER8PP                                = 2856, // PPCInstrMMA.td:14
    XVI4GER8W                                 = 2857, // PPCInstrMMA.td:20
    XVI4GER8WPP                               = 2858, // PPCInstrMMA.td:24
    XVI8GER4                                  = 2859, // PPCInstrMMA.td:10
    XVI8GER4PP                                = 2860, // PPCInstrMMA.td:14
    XVI8GER4SPP                               = 2861, // PPCInstrMMA.td:518
    XVI8GER4W                                 = 2862, // PPCInstrMMA.td:20
    XVI8GER4WPP                               = 2863, // PPCInstrMMA.td:24
    XVI8GER4WSPP                              = 2864, // PPCInstrMMA.td:558
    XVIEXPDP                                  = 2865, // PPCInstrVSX.td:1621
    XVIEXPSP                                  = 2866, // PPCInstrVSX.td:1623
    XVMADDADP                                 = 2867, // PPCInstrVSX.td:515
    XVMADDASP                                 = 2868, // PPCInstrVSX.td:531
    XVMADDMDP                                 = 2869, // PPCInstrVSX.td:522
    XVMADDMSP                                 = 2870, // PPCInstrVSX.td:538
    XVMAXDP                                   = 2871, // PPCInstrVSX.td:962
    XVMAXSP                                   = 2872, // PPCInstrVSX.td:973
    XVMINDP                                   = 2873, // PPCInstrVSX.td:967
    XVMINSP                                   = 2874, // PPCInstrVSX.td:978
    XVMSUBADP                                 = 2875, // PPCInstrVSX.td:547
    XVMSUBASP                                 = 2876, // PPCInstrVSX.td:563
    XVMSUBMDP                                 = 2877, // PPCInstrVSX.td:554
    XVMSUBMSP                                 = 2878, // PPCInstrVSX.td:570
    XVMULDP                                   = 2879, // PPCInstrVSX.td:422
    XVMULHSH                                  = 2880, // PPCInstrFuture.td:538
    XVMULHSW                                  = 2881, // PPCInstrFuture.td:536
    XVMULHUH                                  = 2882, // PPCInstrFuture.td:542
    XVMULHUW                                  = 2883, // PPCInstrFuture.td:540
    XVMULSP                                   = 2884, // PPCInstrVSX.td:427
    XVMULUHM                                  = 2885, // PPCInstrFuture.td:534
    XVMULUWM                                  = 2886, // PPCInstrFuture.td:532
    XVNABSDP                                  = 2887, // PPCInstrVSX.td:791
    XVNABSSP                                  = 2888, // PPCInstrVSX.td:795
    XVNEGDP                                   = 2889, // PPCInstrVSX.td:800
    XVNEGSP                                   = 2890, // PPCInstrVSX.td:804
    XVNMADDADP                                = 2891, // PPCInstrVSX.td:579
    XVNMADDASP                                = 2892, // PPCInstrVSX.td:595
    XVNMADDMDP                                = 2893, // PPCInstrVSX.td:586
    XVNMADDMSP                                = 2894, // PPCInstrVSX.td:602
    XVNMSUBADP                                = 2895, // PPCInstrVSX.td:611
    XVNMSUBASP                                = 2896, // PPCInstrVSX.td:627
    XVNMSUBMDP                                = 2897, // PPCInstrVSX.td:618
    XVNMSUBMSP                                = 2898, // PPCInstrVSX.td:634
    XVRDPI                                    = 2899, // PPCInstrVSX.td:1004
    XVRDPIC                                   = 2900, // PPCInstrVSX.td:943
    XVRDPIM                                   = 2901, // PPCInstrVSX.td:1008
    XVRDPIP                                   = 2902, // PPCInstrVSX.td:1012
    XVRDPIZ                                   = 2903, // PPCInstrVSX.td:1016
    XVREDP                                    = 2904, // PPCInstrVSX.td:703
    XVRESP                                    = 2905, // PPCInstrVSX.td:707
    XVRLW                                     = 2906, // PPCInstrFuture.td:491
    XVRSPI                                    = 2907, // PPCInstrVSX.td:1021
    XVRSPIC                                   = 2908, // PPCInstrVSX.td:946
    XVRSPIM                                   = 2909, // PPCInstrVSX.td:1025
    XVRSPIP                                   = 2910, // PPCInstrVSX.td:1029
    XVRSPIZ                                   = 2911, // PPCInstrVSX.td:1033
    XVRSQRTEDP                                = 2912, // PPCInstrVSX.td:712
    XVRSQRTESP                                = 2913, // PPCInstrVSX.td:716
    XVSQRTDP                                  = 2914, // PPCInstrVSX.td:694
    XVSQRTSP                                  = 2915, // PPCInstrVSX.td:698
    XVSUBDP                                   = 2916, // PPCInstrVSX.td:439
    XVSUBSP                                   = 2917, // PPCInstrVSX.td:443
    XVSUBUHM                                  = 2918, // PPCInstrFuture.td:530
    XVSUBUWM                                  = 2919, // PPCInstrFuture.td:528
    XVTDIVDP                                  = 2920, // PPCInstrVSX.td:668
    XVTDIVSP                                  = 2921, // PPCInstrVSX.td:671
    XVTLSBB                                   = 2922, // PPCInstrP10.td:1835
    XVTSQRTDP                                 = 2923, // PPCInstrVSX.td:675
    XVTSQRTSP                                 = 2924, // PPCInstrVSX.td:679
    XVTSTDCDP                                 = 2925, // PPCInstrVSX.td:1661
    XVTSTDCSP                                 = 2926, // PPCInstrVSX.td:1655
    XVXEXPDP                                  = 2927, // PPCInstrVSX.td:1627
    XVXEXPSP                                  = 2928, // PPCInstrVSX.td:1630
    XVXSIGDP                                  = 2929, // PPCInstrVSX.td:1633
    XVXSIGSP                                  = 2930, // PPCInstrVSX.td:1636
    XXAESDECP                                 = 2931, // PPCInstrFuture.td:505
    XXAESENCP                                 = 2932, // PPCInstrFuture.td:499
    XXAESGENLKP                               = 2933, // PPCInstrFuture.td:511
    XXBLENDVB                                 = 2934, // PPCInstrP10.td:852
    XXBLENDVD                                 = 2935, // PPCInstrP10.td:864
    XXBLENDVH                                 = 2936, // PPCInstrP10.td:856
    XXBLENDVW                                 = 2937, // PPCInstrP10.td:860
    XXBRD                                     = 2938, // PPCInstrVSX.td:1692
    XXBRH                                     = 2939, // PPCInstrVSX.td:1689
    XXBRQ                                     = 2940, // PPCInstrVSX.td:1696
    XXBRW                                     = 2941, // PPCInstrVSX.td:1690
    XXEVAL                                    = 2942, // PPCInstrP10.td:1738
    XXEXTRACTUW                               = 2943, // PPCInstrVSX.td:1616
    XXGENPCVBM                                = 2944, // PPCInstrP10.td:1760
    XXGENPCVDM                                = 2945, // PPCInstrP10.td:1769
    XXGENPCVHM                                = 2946, // PPCInstrP10.td:1763
    XXGENPCVWM                                = 2947, // PPCInstrP10.td:1766
    XXGFMUL128                                = 2948, // PPCInstrFuture.td:519
    XXINSERTW                                 = 2949, // PPCInstrVSX.td:1605
    XXLAND                                    = 2950, // PPCInstrVSX.td:1041
    XXLANDC                                   = 2951, // PPCInstrVSX.td:1045
    XXLEQV                                    = 2952, // PPCInstrVSX.td:1137
    XXLEQVOnes                                = 2953, // PPCInstrVSX.td:1149
    XXLNAND                                   = 2954, // PPCInstrVSX.td:1141
    XXLNOR                                    = 2955, // PPCInstrVSX.td:1051
    XXLOR                                     = 2956, // PPCInstrVSX.td:1056
    XXLORC                                    = 2957, // PPCInstrVSX.td:1154
    XXLORf                                    = 2958, // PPCInstrVSX.td:1061
    XXLXOR                                    = 2959, // PPCInstrVSX.td:1064
    XXLXORdpz                                 = 2960, // PPCInstrVSX.td:1075
    XXLXORspz                                 = 2961, // PPCInstrVSX.td:1079
    XXLXORz                                   = 2962, // PPCInstrVSX.td:1072
    XXMFACC                                   = 2963, // PPCInstrMMA.td:496
    XXMFACCW                                  = 2964, // PPCInstrMMA.td:543
    XXMRGHW                                   = 2965, // PPCInstrVSX.td:1086
    XXMRGLW                                   = 2966, // PPCInstrVSX.td:1089
    XXMTACC                                   = 2967, // PPCInstrMMA.td:501
    XXMTACCW                                  = 2968, // PPCInstrMMA.td:547
    XXMULMUL                                  = 2969, // PPCInstrFuture.td:546
    XXMULMULHIADD                             = 2970, // PPCInstrFuture.td:549
    XXMULMULLOADD                             = 2971, // PPCInstrFuture.td:554
    XXPERM                                    = 2972, // PPCInstrVSX.td:1699
    XXPERMDI                                  = 2973, // PPCInstrVSX.td:1093
    XXPERMDIs                                 = 2974, // PPCInstrVSX.td:1107
    XXPERMR                                   = 2975, // PPCInstrVSX.td:1703
    XXPERMX                                   = 2976, // PPCInstrP10.td:847
    XXSEL                                     = 2977, // PPCInstrVSX.td:1109
    XXSETACCZ                                 = 2978, // PPCInstrMMA.td:514
    XXSLDWI                                   = 2979, // PPCInstrVSX.td:1113
    XXSLDWIs                                  = 2980, // PPCInstrVSX.td:1120
    XXSPLTI32DX                               = 2981, // PPCInstrP10.td:1404
    XXSPLTIB                                  = 2982, // PPCInstrVSX.td:1709
    XXSPLTIDP                                 = 2983, // PPCInstrP10.td:1399
    XXSPLTIW                                  = 2984, // PPCInstrP10.td:1395
    XXSPLTW                                   = 2985, // PPCInstrVSX.td:1124
    XXSPLTWs                                  = 2986, // PPCInstrVSX.td:1130
    XXSSUMUDM                                 = 2987, // PPCInstrFuture.td:558
    XXSSUMUDMC                                = 2988, // PPCInstrFuture.td:561
    XXSSUMUDMCEXT                             = 2989, // PPCInstrFuture.td:612
    gBC                                       = 2990, // PPCInstrInfo.td:5162
    gBCA                                      = 2991, // PPCInstrInfo.td:5165
    gBCAat                                    = 2992, // PPCInstrInfo.td:5173
    gBCCTR                                    = 2993, // PPCInstrInfo.td:5206
    gBCCTRL                                   = 2994, // PPCInstrInfo.td:5210
    gBCL                                      = 2995, // PPCInstrInfo.td:5180
    gBCLA                                     = 2996, // PPCInstrInfo.td:5183
    gBCLAat                                   = 2997, // PPCInstrInfo.td:5191
    gBCLR                                     = 2998, // PPCInstrInfo.td:5198
    gBCLRL                                    = 2999, // PPCInstrInfo.td:5202
    gBCLat                                    = 3000, // PPCInstrInfo.td:5187
    gBCat                                     = 3001, // PPCInstrInfo.td:5169
    INSTRUCTION_LIST_END = 3002
  };
  enum RegClassByHwModeUses : uint16_t {
    ppc_ptr_rc,
    ptr_rc_idx_by_hwmode,
    ptr_rc_nor0_by_hwmode,
  };

} // namespace llvm_ks::PPC

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::PPC::Sched {

  enum {
    NoInstrModel	= 0,
    IIC_LdStSync	= 1,
    IIC_IntSimple	= 2,
    IIC_IntGeneral	= 3,
    IIC_BrB	= 4,
    IIC_VecFP	= 5,
    IIC_IntRotate	= 6,
    IIC_IntCompare	= 7,
    IIC_SprABORT	= 8,
    IIC_LdStCOPY	= 9,
    IIC_LdStPASTE	= 10,
    IIC_BrCR	= 11,
    IIC_FPGeneral	= 12,
    IIC_LdStLD	= 13,
    IIC_LdStDCBF	= 14,
    IIC_LdStLoad	= 15,
    IIC_FPCompare	= 16,
    IIC_IntDivD	= 17,
    IIC_IntDivW	= 18,
    IIC_VecGeneral	= 19,
    IIC_FPDGeneral	= 20,
    IIC_FPAddSub	= 21,
    IIC_FPDivD	= 22,
    IIC_FPSGeneral	= 23,
    IIC_VecComplex	= 24,
    IIC_LdStStore	= 25,
    IIC_IntRotateDI	= 26,
    IIC_FPDivS	= 27,
    IIC_FPFused	= 28,
    IIC_FPSqrtD	= 29,
    IIC_FPSqrtS	= 30,
    IIC_LdStICBI	= 31,
    IIC_IntISEL	= 32,
    IIC_SprISYNC	= 33,
    IIC_LdStLWARX	= 34,
    IIC_LdStLoadUpd	= 35,
    IIC_LdStLoadUpdX	= 36,
    IIC_LdStLDARX	= 37,
    IIC_LdStLDU	= 38,
    IIC_LdStLDUX	= 39,
    IIC_LdStLFD	= 40,
    IIC_LdStLFDU	= 41,
    IIC_LdStLFDUX	= 42,
    IIC_LdStLHA	= 43,
    IIC_LdStLHAU	= 44,
    IIC_LdStLHAUX	= 45,
    IIC_LdStLMW	= 46,
    IIC_LdStLQ	= 47,
    IIC_LdStLQARX	= 48,
    IIC_LdStLWA	= 49,
    IIC_IntMulHD	= 50,
    IIC_BrMCR	= 51,
    IIC_BrMCRX	= 52,
    IIC_SprMFCR	= 53,
    IIC_SprMFSPR	= 54,
    IIC_IntMFFS	= 55,
    IIC_SprMFMSR	= 56,
    IIC_SprMFCRF	= 57,
    IIC_SprMFPMR	= 58,
    IIC_SprMFSR	= 59,
    IIC_SprMFTB	= 60,
    IIC_SprMSGSNDP	= 61,
    IIC_SprMSGSYNC	= 62,
    IIC_SprMTSPR	= 63,
    IIC_IntMTFSB0	= 64,
    IIC_SprMTMSR	= 65,
    IIC_SprMTMSRD	= 66,
    IIC_SprMTPMR	= 67,
    IIC_SprMTSR	= 68,
    IIC_IntMulHW	= 69,
    IIC_IntMulHWU	= 70,
    IIC_IntMulLI	= 71,
    IIC_SprRFI	= 72,
    IIC_IntRFID	= 73,
    IIC_IntRotateD	= 74,
    IIC_SprSLBFEE	= 75,
    IIC_SprSLBIA	= 76,
    IIC_SprSLBIE	= 77,
    IIC_SprSLBIEG	= 78,
    IIC_SprSLBMFEE	= 79,
    IIC_SprSLBMFEV	= 80,
    IIC_SprSLBMTE	= 81,
    IIC_SprSLBSYNC	= 82,
    IIC_IntShift	= 83,
    IIC_LdStSTWCX	= 84,
    IIC_LdStSTU	= 85,
    IIC_LdStSTUX	= 86,
    IIC_LdStSTD	= 87,
    IIC_LdStSTDCX	= 88,
    IIC_LdStSTFD	= 89,
    IIC_LdStSTFDU	= 90,
    IIC_SprSTOP	= 91,
    IIC_LdStSTQ	= 92,
    IIC_LdStSTQCX	= 93,
    IIC_IntTrapD	= 94,
    IIC_SprTLBIA	= 95,
    IIC_SprTLBIE	= 96,
    IIC_SprTLBIEL	= 97,
    IIC_SprTLBSYNC	= 98,
    IIC_IntTrapW	= 99,
    IIC_VecFPCompare	= 100,
    IIC_VecPerm	= 101,
    B_BA_BL_BL8_BL8_NOP_BL8_NOP_RM_BL8_NOP_TLS_BL8_NOTOC_BL8_NOTOC_RM_BL8_NOTOC_TLS_BL8_RM_BL8_TLS_BL8_TLS__BLA_BLA8_BLA8_NOP_BLA8_NOP_RM_BLA8_RM_BLA_RM_BL_NOP_BL_NOP_RM_BL_RM_BL_TLS	= 102,
    BL_LWZinto_toc_BL_LWZinto_toc_RM_BL8_LDinto_toc_BL8_LDinto_toc_RM	= 103,
    BDZLRLp_BDZLRm_BDZLRp_BDZLm_BDZLp_BDZm_BDZp_BDNZ_BDNZ8_BDNZA_BDNZAm_BDNZAp_BDNZL_BDNZLA_BDNZLAm_BDNZLAp_BDNZLR_BDNZLR8_BDNZLRL_BDNZLRLm_BDNZLRLp_BDNZLRm_BDNZLRp_BDNZLm_BDNZLp_BDNZm_BDNZp_BDZ_BDZ8_BDZA_BDZAm_BDZAp_BDZL_BDZLA_BDZLAm_BDZLAp_BDZLR_BDZLR8_BDZLRL_BDZLRLm_BLR_BLR8_BLRL_BCL_BCLR_BCLRL_BCLRLn_BCLRn_BCLalways_BCLn_BCTR_BCTR8_BCTRL_BCTRL8_BCTRL8_LDinto_toc_BCTRL8_LDinto_toc_RM_BCTRL8_RM_BCTRL_LWZinto_toc_BCTRL_LWZinto_toc_RM_BCTRL_RM_BCn_BC_BCC_BCCA_BCCCTR_BCCCTR8_BCCCTRL_BCCCTRL8_BCCL_BCCLA_BCCLR_BCCLRL_BCCTR_BCCTR8_BCCTR8n_BCCTRL_BCCTRL8_BCCTRL8n_BCCTRLn_BCCTRn_gBC_gBCA_gBCAat_gBCCTR_gBCCTRL_gBCL_gBCLA_gBCLAat_gBCLR_gBCLRL_gBCLat_gBCat	= 104,
    MFCTR_MFCTR8_MFLR_MFLR8	= 105,
    MTLR_MTLR8_MTCTR_MTCTR8_MTCTR8loop_MTCTRloop	= 106,
    MFCR_MFCR8	= 107,
    MCRF	= 108,
    CR6SET_CR6UNSET_CRSET_CRUNSET_CRAND_CRANDC_CREQV_CRNAND_CRNOR_CRNOT_CROR_CRORC	= 109,
    LMW	= 110,
    LWARX_LWARXL	= 111,
    LDARX_LDARXL	= 112,
    LHBRX_LHBRX8_LWBRX_LWBRX8	= 113,
    MFSR_MFSRIN	= 114,
    LFS_LFSX_LFSXTLS_LFSXTLS__LFD_LFDX_LFDXTLS_LFDXTLS__LXSDX_LXVD2X_LXVW4X_LXVDSX	= 115,
    LFSU_LFDU	= 116,
    LFSUX_LFDUX	= 117,
    STXSDX_STXVD2X_STXVW4X	= 118,
    LBARX_LHARX	= 119,
    LBZCIX_LDBRX_LDCIX_LHZCIX_LSWI_LVEBX_LVEHX_LVEWX_LVSL_LVSR_LVX_LVXL_LWZCIX_STHCIX_STSWI_STWCIX	= 120,
    LFIWAX_LFIWZX	= 121,
    STFD_STFDX_STFIWX_STFS_STFSX	= 122,
    STFDU_STFDUX_STFSU_STFSUX	= 123,
    STVEBX_STVEHX_STVEWX_STVX_STVXL	= 124,
    LHA_LHA8_LHAX_LHAX8_LWAX_LWAX_32	= 125,
    LWA_LWA_32	= 126,
    LHAU_LHAU8	= 127,
    LHAUX_LHAUX8_LWAUX	= 128,
    STB_STB8_STH_STH8_STW_STW8_STBX_STBX8_STHX_STHX8_STWX_STWX8_STHBRX_STWBRX	= 129,
    STD_STDX	= 130,
    STMW	= 131,
    STWCX	= 132,
    STDCX	= 133,
    STDU_STHU_STHU8_STBU_STBU8_STWU_STWU8	= 134,
    STDUX_STWUX_STWUX8_STHUX_STHUX8_STBUX_STBUX8	= 135,
    LWZU_LWZU8_LHZU_LHZU8_LBZU_LBZU8	= 136,
    LDU	= 137,
    LWZUX_LWZUX8_LHZUX_LHZUX8_LBZUX_LBZUX8	= 138,
    LDUX	= 139,
    ADDI_ADDI8_ADDIS_ADDIS8_LI_LI8_LIS_LIS8_ADD4_ADD4TLS_ADD4_rec_ADD8_ADD8TLS_ADD8TLS__ADD8_rec_ORI_ORI8_ORIS_ORIS8_XORI_XORI8_XORIS_XORIS8_XOR_XOR8_XOR8_rec_XOR_rec_NEG_NEG8_NEG8_rec_NEG_rec_NEG8O_NEGO_AND_AND8_AND_rec_AND8_rec_NAND_NAND8_NAND_rec_NAND8_rec_NOR_NOR8_NOR_rec_NOR8_rec_EQV_EQV8_EQV_rec_EQV8_rec_ANDC_ANDC8_ANDC_rec_ANDC8_rec_ORC_ORC8_ORC_rec_ORC8_rec	= 140,
    SUBF8_SUBF8_rec_ADDIC_ADDIC8_SUBFIC_SUBFIC8_SUBFZE_SUBFZE8_ADDE_ADDE8_ADDME_ADDME8_SUBFME_SUBFME8_ANDI_rec_ANDIS_rec	= 141,
    CMPD_CMPDI_CMPLD_CMPLDI_CMPLW_CMPLWI_CMPW_CMPWI	= 142,
    EXTSB8_32_64_EXTSB8_rec_EXTSH8_32_64_EXTSH8_rec_EXTSW_32_EXTSW_32_64_EXTSW_32_64_rec_ADD4O_ADD8O_ADD8O_rec_ADD4O_rec_NEG8O_rec_NEGO_rec_EXTSB_EXTSB8_EXTSB_rec_EXTSH_EXTSH8_EXTSH_rec_EXTSW_EXTSW_rec	= 143,
    POPCNTB_POPCNTB8_POPCNTD_POPCNTW_ANDI8_rec_ANDIS8_rec_ADDC_ADDC8_SUBFO_SUBF8O_SUBFC_SUBFC8_ADDIC_rec_ADDE8_rec_ADDE_rec_SUBFE8_rec_SUBFE_rec_ADDME8_rec_ADDME_rec_SUBFME8_rec_SUBFME_rec_ADDZE8_rec_ADDZE_rec_SUBFZE_rec_SUBFZE8_rec_SUBFO_rec_SUBF8O_rec_ADDE8O_ADDEO_SUBFE8O_SUBFEO_ADDME8O_ADDMEO_SUBFME8O_SUBFMEO_ADDZE8O_ADDZEO_SUBFZE8O_SUBFZEO_ADDE8O_rec_ADDEO_rec_ADDMEO_rec_ADDME8O_rec_SUBFMEO_rec_SUBFME8O_rec_ADDZEO_rec_ADDZE8O_rec_SUBFZEO_rec_SUBFZE8O_rec_ADDC8_rec_ADDC_rec_ADDCO_ADDCO_rec_ADDC8O_ADDC8O_rec_SUBFC8_rec_SUBFC_rec_SUBFCO_SUBFC8O_SUBFCO_rec_SUBFC8O_rec_RLWINM_RLWINM8_RLWINM_rec_RLWNM_RLWNM8_RLWNM_rec_RLWINM8_rec_RLWNM8_rec_SLW_SLW8_SLW_rec_SLW8_rec_SRW_SRW8_SRW_rec_SRW8_rec_SUBFE_SUBFE8_SUBFE8O_rec_SUBFEO_rec	= 144,
    ADDPCIS	= 145,
    SUBFUS_SUBFUS_rec	= 146,
    RLDICL_RLDICL_rec_RLDICR_RLDICR_rec_RLDIC_RLDIC_rec_RLDIMI_RLDIMI_rec_RLDICL_32_RLDICL_32_64_RLDICL_32_rec_RLDICR_32_SRADI_SRADI_rec_SRADI_32	= 147,
    RLDCL_RLDCL_rec_RLDCR_RLDCR_rec_SLD_SLD_rec_SRD_SRD_rec_SRAD_SRAD_rec	= 148,
    SRAWI_SRAWI_rec_SRAWI8_SRAWI8_rec_SRAW_SRAW_rec_SRAW8_SRAW8_rec	= 149,
    CNTLZD_CNTLZDM_CNTLZD_rec_CNTLZW_CNTLZW8_CNTLZW8_rec_CNTLZW_rec_CNTTZD_CNTTZDM_CNTTZD_rec_CNTTZW_CNTTZW8_CNTTZW8_rec_CNTTZW_rec	= 150,
    MULLI_MULLI8	= 151,
    MULLW_MULHW_MULHD_MULLWO_MULLW_rec_MULHD_rec_MULHW_rec_MULLWO_rec	= 152,
    MULHWU_MULHDU_MULHDU_rec_MULHWU_rec	= 153,
    MULLD_MULLDO_MULLD_rec_MULLDO_rec	= 154,
    DIVDE_DIVDEO_DIVDEO_rec_DIVDEU_DIVDEUO_DIVDEUO_rec_DIVDEU_rec_DIVDE_rec	= 155,
    DIVWE_DIVWEO_DIVWEO_rec_DIVWEU_DIVWEUO_DIVWEUO_rec_DIVWEU_rec_DIVWE_rec_DIVW_DIVWU_DIVWU_rec_DIVWO_DIVWO_rec_DIVWUO_DIVWUO_rec_DIVW_rec	= 156,
    DIVD_DIVDU_DIVDO_DIVDO_rec_DIVDUO_DIVDUO_rec_DIVDU_rec_DIVD_rec	= 157,
    FABSD_FABSD_rec_FABSS_FABSS_rec_FADDS_FADDS_rec_FMADDS_FMADDS_rec_FMR_FMR_rec_FMSUBS_FMSUBS_rec_FMULS_FMULS_rec_FNABSD_FNABSD_rec_FNABSS_FNABSS_rec_FNEGD_FNEGD_rec_FNEGS_FNEGS_rec_FNMADDS_FNMADDS_rec_FNMSUBS_FNMSUBS_rec_FSUBS_FSUBS_rec_FCFID_FCFIDS_FCFIDS_rec_FCFIDU_FCFIDUS_FCFIDUS_rec_FCFIDU_rec_FCFID_rec_FCTID_FCTIDU_FCTIDUZ_FCTIDUZ_rec_FCTIDU_rec_FCTIDZ_FCTIDZ_rec_FCTID_rec_FCTIW_FCTIWU_FCTIWUZ_FCTIWUZ_rec_FCTIWU_rec_FCTIWZ_FCTIWZ_rec_FCTIW_rec_FRE_FRES_rec_FRE_rec_FRSP_rec_FRSP_FRES_FRSQRTE_FRSQRTES_FRSQRTES_rec_FRSQRTE_rec_FSELD_FSELS_FSELD_rec_FSELS_rec_FCPSGND_FCPSGND_rec_FCPSGNS_FCPSGNS_rec_FRIMD_FRIMD_rec_FRIMS_FRIMS_rec_FRIND_FRIND_rec_FRINS_FRINS_rec_FRIPD_FRIPD_rec_FRIPS_FRIPS_rec_FRIZD_FRIZD_rec_FRIZS_FRIZS_rec	= 158,
    FADD_FADD_rec_FSUB_FSUB_rec	= 159,
    FMADD_FMADD_rec_FMSUB_FMSUB_rec_FMUL_FMUL_rec_FNMADD_FNMADD_rec_FNMSUB_FNMSUB_rec	= 160,
    XSMADDADP_XSMADDASP_XSMADDMDP_XSMADDMSP_XSMSUBADP_XSMSUBASP_XSMSUBMDP_XSMSUBMSP_XSNMADDADP_XSNMADDASP_XSNMADDMDP_XSNMADDMSP_XSNMSUBADP_XSNMSUBASP_XSNMSUBMDP_XSNMSUBMSP_XSABSDP_XSADDDP_XSADDSP_XSMULDP_XSMULSP_XSNABSDP_XSNABSDPs_XSNEGDP_XSSUBDP_XSSUBSP_XSCPSGNDP_XSCVDPSP_XSCVDPSXDS_XSCVDPSXDSs_XSCVDPSXWS_XSCVDPSXWSs_XSCVDPUXDS_XSCVDPUXDSs_XSCVDPUXWS_XSCVDPUXWSs_XSCVSPDP_XSCVSXDDP_XSCVUXDDP_XSMAXDP_XSMINDP_XSRDPI_XSRDPIC_XSRDPIM_XSRDPIP_XSRDPIZ_XSREDP_XSRSQRTEDP	= 161,
    FTDIV_FTSQRT_XSTDIVDP_XSTSQRTDP_XSCMPODP_XSCMPUDP	= 162,
    XVADDDP_XVADDSP_XVMADDADP_XVMADDASP_XVMADDMDP_XVMADDMSP_XVMSUBADP_XVMSUBASP_XVMSUBMDP_XVMSUBMSP_XVNMADDADP_XVNMADDASP_XVNMADDMDP_XVNMADDMSP_XVNMSUBADP_XVNMSUBASP_XVNMSUBMDP_XVNMSUBMSP_XVSUBDP_XVSUBSP_XVABSDP_XVABSSP_XVMAXDP_XVMAXSP_XVMINDP_XVMINSP_XVMULDP_XVMULSP_XVNABSDP_XVNABSSP_XVNEGDP_XVNEGSP_XVCPSGNDP_XVCVDPSXDS_XVCVDPSXWS_XVCVDPUXDS_XVCVDPUXWS_XVCVSPSXDS_XVCVSPSXWS_XVCVSPUXDS_XVCVSPUXWS_XVCVSXDDP_XVCVSXWDP_XVCVUXDDP_XVCVUXWDP_XVRDPI_XVRDPIC_XVRDPIM_XVRDPIP_XVRDPIZ_XVREDP_XVRSPI_XVRSPIC_XVRSPIM_XVRSPIP_XVRSPIZ_XVRSQRTEDP	= 163,
    XVCMPEQDP_XVCMPEQDP_rec_XVCMPGEDP_XVCMPGEDP_rec_XVCMPGTDP_XVCMPGTDP_rec	= 164,
    XVTDIVDP_XVTSQRTDP	= 165,
    VPKSHSS_VPKSHUS_VPKSWSS_VPKSWUS_VPKUHUM_VPKUHUS_VPKUWUM_VPKUWUS_VUPKHPX_VUPKHSB_VUPKHSH_VUPKLPX_VUPKLSB_VUPKLSH_VPERM_VSEL_VPKPX	= 166,
    XXMRGHW_XXMRGLW_XXPERMDI_XXPERMDIs_XXSLDWI_XXSLDWIs_VSPLTB_VSPLTBs_VSPLTH_VSPLTHs_VSPLTISB_VSPLTISH_VSPLTISW_VSPLTW_XXSPLTW_XXSPLTWs_XXSEL	= 167,
    VADDSBS_VADDSHS_VADDSWS_VADDUBS_VADDUHS_VADDUWS_VMAXSB_VMAXSH_VMAXSW_VMAXUB_VMAXUH_VMAXUW_VMINSB_VMINSH_VMINSW_VMINUB_VMINUH_VMINUW_VMRGHB_VMRGHH_VMRGHW_VMRGLB_VMRGLH_VMRGLW_XVRSQRTESP_XVRESP_XVCVSXDSP_XVCVSXWSP_XVCVUXDSP_XVCVUXWSP_XVCPSGNSP_XVCVDPSP_VADDCUW_VADDFP_VAND_VANDC_VAVGSB_VAVGSH_VAVGSW_VAVGUB_VAVGUH_VAVGUW_VCFSX_VCFUX_VCTSXS_VCTUXS_VEXPTEFP_VLOGEFP_VNOR_VOR_VMADDFP_VMHADDSHS_VMHRADDSHS_VMLADDUHM_VNMSUBFP_VMAXFP_VMINFP_VMSUMMBM_VMSUMSHM_VMSUMSHS_VMSUMUBM_VMSUMUDM_VMSUMUHM_VMSUMUHS_VMULESB_VMULESH_VMULEUB_VMULEUH_VMULOSB_VMULOSH_VMULOUB_VMULOUH_VREFP_VRFIM_VRFIN_VRFIP_VRFIZ_VRLB_VRLH_VRLW_VRSQRTEFP_VSR_VSRAB_VSRAH_VSRAW_VSRB_VSRH_VSRO_VSRW_VSUBCUW_VSL_VSLB_VSLDOI_VSLH_VSLO_VSLW_VSUBSBS_VSUBSHS_VSUBSWS_VSUBUBS_VSUBUHS_VSUBUWS_VSUM2SWS_VSUM4SBS_VSUM4SHS_VSUM4UBS_VSUMSWS_VXOR	= 168,
    VADDUBM_VADDUHM_VADDUWM_XXLORf_XXLXORdpz_XXLXORspz_XXLXORz_VSUBFP_VSUBUBM_VSUBUHM_VSUBUWM_XXLAND_XXLANDC_XXLNOR_XXLOR_XXLXOR	= 169,
    XVTDIVSP_XVTSQRTSP	= 170,
    XVCMPEQSP_XVCMPEQSP_rec_XVCMPGESP_XVCMPGESP_rec_XVCMPGTSP_XVCMPGTSP_rec_VCMPBFP_VCMPBFP_rec_VCMPEQFP_VCMPEQFP_rec_VCMPEQUB_VCMPEQUB_rec_VCMPEQUH_VCMPEQUH_rec_VCMPEQUW_VCMPEQUW_rec_VCMPGEFP_VCMPGEFP_rec_VCMPGTFP_VCMPGTFP_rec_VCMPGTSB_VCMPGTSB_rec_VCMPGTSH_VCMPGTSH_rec_VCMPGTSW_VCMPGTSW_rec_VCMPGTUB_VCMPGTUB_rec_VCMPGTUH_VCMPGTUH_rec_VCMPGTUW_VCMPGTUW_rec	= 171,
    FCMPOD_FCMPOS_FCMPUD_FCMPUS	= 172,
    FDIVS_FDIVS_rec	= 173,
    XSDIVDP	= 174,
    FSQRTS_XSSQRTSP_FSQRTS_rec	= 175,
    FDIV_FDIV_rec	= 176,
    XSSQRTDP	= 177,
    FSQRT_FSQRT_rec	= 178,
    XVDIVSP	= 179,
    XVSQRTSP	= 180,
    XVDIVDP	= 181,
    XVSQRTDP	= 182,
    MFOCRF_MFOCRF8	= 183,
    VCIPHER_VCIPHERLAST_VNCIPHER_VNCIPHERLAST_VPMSUMB_VPMSUMD_VPMSUMH_VPMSUMW_VSBOX	= 184,
    XSDIVSP	= 185,
    FSQRTS_FSQRTS_rec	= 186,
    MTFSFI_rec_MTFSF_rec_MTFSFI_MTFSFIb_MTFSF	= 187,
    MTFSFb_MTFSB0_MTFSB1	= 188,
    XSMADDADP_XSMADDASP_XSMADDMDP_XSMADDMSP_XSMSUBADP_XSMSUBASP_XSMSUBMDP_XSMSUBMSP_XSNMADDADP_XSNMADDASP_XSNMADDMDP_XSNMADDMSP_XSNMSUBADP_XSNMSUBASP_XSNMSUBMDP_XSNMSUBMSP_XSABSDP_XSADDDP_XSADDSP_XSCPSGNDP_XSMULDP_XSMULSP_XSNABSDP_XSNABSDPs_XSNEGDP_XSREDP_XSRSQRTEDP_XSSUBDP_XSSUBSP_XSCVDPSXDS_XSCVDPSXDSs_XSCVDPSXWS_XSCVDPSXWSs_XSCVDPUXDS_XSCVDPUXDSs_XSCVDPUXWS_XSCVDPUXWSs_XSCVSXDDP_XSCVUXDDP_XSCVDPSP_XSCVSPDP_XSRDPI_XSRDPIC_XSRDPIM_XSRDPIP_XSRDPIZ	= 189,
    XSRESP_XSRSQRTESP_XSCVSXDSP_XSCVUXDSP_XSCVDPSPN_XSCVSPDPN_XSRSP	= 190,
    XVMADDASP_XVMADDMSP_XVMSUBASP_XVMSUBMSP_XVNMADDASP_XVNMADDMSP_XVNMSUBASP_XVNMSUBMSP_XVSUBSP_XVMULSP_XVNABSSP_XVNEGSP_XVABSSP_XVADDSP	= 191,
    VRFIM_VRFIN_VRFIP_VRFIZ_XVRSQRTESP_VADDFP_VEXPTEFP_VLOGEFP_VMADDFP_VNMSUBFP_VREFP_VRSQRTEFP_XVCVSXWSP_XVCVUXWSP_XVRESP_XVCVDPSP_XVCVSXDSP_XVCVUXDSP_XVCPSGNSP	= 192,
    VSUBFP	= 193,
    XVRDPI_XVRDPIC_XVRDPIM_XVRDPIP_XVRDPIZ_XVRSPI_XVRSPIC_XVRSPIM_XVRSPIP_XVRSPIZ_XVCVSXDDP_XVCVSXWDP_XVCVUXDDP_XVCVUXWDP_XVCVDPSXDS_XVCVDPSXWS_XVCVDPUXDS_XVCVDPUXWS_XVCVSPSXDS_XVCVSPSXWS_XVCVSPUXDS_XVCVSPUXWS_XVABSDP_XVADDDP_XVCPSGNDP_XVMADDADP_XVMADDMDP_XVMSUBADP_XVMSUBMDP_XVMULDP_XVNABSDP_XVNEGDP_XVNMADDADP_XVNMADDMDP_XVNMSUBADP_XVNMSUBMDP_XVREDP_XVRSQRTEDP_XVSUBDP	= 194,
    XVCVSPDP	= 195,
    TDI_TD	= 196,
    TWI_TW	= 197,
    MTCRF_MTCRF8_MTOCRF_MTOCRF8	= 198,
    RLWIMI_RLWIMI8	= 199,
    AND_AND8_AND8_rec_ANDC_ANDC8_ANDC8_rec_ANDC_rec_AND_rec_EQV_EQV8_EQV8_rec_EQV_rec_NAND_NAND8_NAND8_rec_NAND_rec_NOR_NOR8_NOR8_rec_NOR_rec_ORC_ORC8_ORC8_rec_ORC_rec_ORI_ORI8_ORIS_ORIS8_XOR_XOR8_XOR8_rec_XORI_XORI8_XORIS_XORIS8_XOR_rec_ADD4_rec_ADD8_rec_NEG8_rec_NEG_rec	= 200,
    ANDI8_rec_ANDIS8_rec_RLWINM_RLWINM8_RLWINM8_rec_RLWINM_rec_RLWNM_RLWNM8_RLWNM8_rec_RLWNM_rec_SLW_SLW8_SLW8_rec_SLW_rec_SRW_SRW8_SRW8_rec_SRW_rec_ADDC8O_ADDC8O_rec_ADDCO_ADDCO_rec_ADDE8O_ADDE8O_rec_ADDEO_ADDEO_rec_ADDME8O_ADDME8O_rec_ADDMEO_ADDMEO_rec_ADDZE8O_ADDZE8O_rec_ADDZEO_ADDZEO_rec_SUBF8O_SUBF8O_rec_SUBFC8O_SUBFC8O_rec_SUBFCO_SUBFCO_rec_SUBFE8O_SUBFE8O_rec_SUBFEO_SUBFEO_rec_SUBFME8O_SUBFME8O_rec_SUBFMEO_SUBFMEO_rec_SUBFO_SUBFO_rec_SUBFZE8O_SUBFZE8O_rec_SUBFZEO_SUBFZEO_rec_ADDE8_rec_ADDE_rec_ADDME8_rec_ADDME_rec_ADDZE8_rec_ADDZE_rec_SUBFE8_rec_SUBFE_rec_SUBFME8_rec_SUBFME_rec_SUBFZE8_rec_SUBFZE_rec_ADDIC_rec_ADDC_ADDC8_SUBFC_SUBFC8_ADDC_rec_ADDC8_rec_SUBFC_rec_SUBFC8_rec	= 201,
    ANDIS_rec_ANDI_rec_SUBF8_rec	= 202,
    OR_OR8_OR8_rec_OR_rec_NOP	= 203,
    SLDI_SLDI_rec_SLWI_SLWI_rec_SRDI_SRDI_rec_SRWI_SRWI_rec_COPY	= 204,
    SUBF_rec_ADDG6S_ADDG6S8_ADDZE_ADDZE8	= 205,
    RLWIMI8_rec_RLWIMI_rec	= 206,
    CNTLZD_CNTLZD_rec_CNTLZW_CNTLZW8_CNTLZW8_rec_CNTLZW_rec	= 207,
    POPCNTB_POPCNTB8_POPCNTD_POPCNTW	= 208,
    ISEL_ISEL8	= 209,
    MFTB_MFTB8	= 210,
    DIVW_DIVWU	= 211,
    DIVD_DIVDU	= 212,
    DIVWE_DIVWEU	= 213,
    LVEBX_LVEHX_LVEWX_LVX_LVXL	= 214,
    LXVB16X_LXSIWZX	= 215,
    DFLOADf64_XFLOADf64_LIWZX	= 216,
    LQ	= 217,
    STFDEPX_STFDXTLS_STFDXTLS__STFSXTLS_STFSXTLS__STXSIWX_STXSSP_STXSSPX	= 218,
    STBXTLS_STBXTLS__STBXTLS_32_STHXTLS_STHXTLS__STHXTLS_32_STWXTLS_STWXTLS__STWXTLS_32_STBEPX_STDBRX_STHEPX_STWEPX	= 219,
    STDXTLS_STDXTLS_	= 220,
    STBCIX_STDCIX	= 221,
    STBCX_STHCX	= 222,
    STHCIX_STSWI_STWCIX	= 223,
    LBZ_LBZ8_LBZX_LBZX8_LBZXTLS_LBZXTLS__LBZXTLS_32_LHAXTLS_LHAXTLS__LHAXTLS_32_LHZ_LHZ8_LHZX_LHZX8_LHZXTLS_LHZXTLS__LHZXTLS_32_LWAXTLS_LWAXTLS__LWAXTLS_32_LWZ_LWZ8_LWZX_LWZX8_LWZXTLS_LWZXTLS__LWZXTLS_32	= 224,
    LD_LDX_LDXTLS_LDXTLS_	= 225,
    LBARXL_LHARXL	= 226,
    LBEPX_LHEPX_LWEPX	= 227,
    LFDEPX_LXSIWAX	= 228,
    ADDIdtprelL_ADDIdtprelL32_ADDItlsgdL_ADDItlsgdL32_ADDItlsgdLADDR_ADDItlsgdLADDR32_ADDItoc_ADDItoc8_ADDItocL_ADDItocL8_ADDISdtprelHA_ADDISdtprelHA32_ADDISgotTprelHA_ADDIStlsgdHA_ADDIStocHA_ADDIStocHA8	= 229,
    SUBF	= 230,
    VPKSDSS_VPKSDUS_VPKUDUM_VPKUDUS_VUPKHSW_VUPKLSW_VMRGEW_VMRGOW_VPERMXOR_VBPERMQ_VGBBD	= 231,
    VMRGHB_VMRGHH_VMRGHW_VMRGLB_VMRGLH_VMRGLW_VSL_VSLDOI_VSLO_VSR_VSRO	= 232,
    VADDSBS_VADDSHS_VADDSWS_VADDUBS_VADDUHS_VADDUWS_VSUBSBS_VSUBSHS_VSUBSWS_VSUBUBS_VSUBUHS_VSUBUWS_VRLB_VRLH_VRLW_VSLB_VSLH_VSLW_VSRAB_VSRAH_VSRAW_VSRB_VSRH_VSRW_VAVGSB_VAVGSH_VAVGSW_VAVGUB_VAVGUH_VAVGUW_VMAXSB_VMAXSH_VMAXSW_VMAXUB_VMAXUH_VMAXUW_VMINSB_VMINSH_VMINSW_VMINUB_VMINUH_VMINUW_VAND_VANDC_VNOR_VOR_VXOR_VMAXFP_VMINFP_VSUBCUW_VADDCUW	= 233,
    VADDUDM_VSUBUDM_VSLD_VSRAD_VSRD_VEQV_VNAND_VORC_XXLEQV_XXLNAND_XXLORC_VCLZB_VCLZD_VCLZH_VCLZW_VPOPCNTB_VPOPCNTH_VPOPCNTW	= 234,
    VRLD_VMAXSD_VMAXUD_VMINSD_VMINUD_VSHASIGMAD_VSHASIGMAW	= 235,
    VCMPEQUD_VCMPEQUD_rec_VCMPGTSD_VCMPGTSD_rec_VCMPGTUD_VCMPGTUD_rec	= 236,
    MFVSCR	= 237,
    MTVSCR	= 238,
    VADDCUQ_VADDECUQ_VADDEUQM_VSUBCUQ_VSUBECUQ_VSUBEUQM	= 239,
    VADDUQM_VSUBUQM_VPOPCNTD	= 240,
    VMSUMMBM_VMSUMSHM_VMSUMSHS_VMSUMUBM_VMSUMUHM_VMSUMUHS_VSUM2SWS_VSUM4SBS_VSUM4SHS_VSUM4UBS_VSUMSWS_VMULESB_VMULESH_VMULEUB_VMULEUH_VMULOSB_VMULOSH_VMULOUB_VMULOUH_VMHADDSHS_VMHRADDSHS_VMLADDUHM	= 241,
    VMULESW_VMULEUW_VMULOSW_VMULOUW	= 242,
    VMULUWM	= 243,
    B_BA_BL_BL8_BL8_RM_BLA_BLA8_BLA8_RM_BLA_RM_BL_RM_BL8_NOP_BL8_NOP_RM_BL8_NOP_TLS_BL8_TLS_BL8_TLS__BLA8_NOP_BLA8_NOP_RM_BL_NOP_BL_NOP_RM_BL_TLS	= 244,
    DTSTDC_DTSTDCQ_DTSTDG_DTSTDGQ_DTSTSF_DTSTSFQ_DCMPO_DCMPU_DTSTEX	= 245,
    DXEX_DXEXQ_DXEXQ_rec_DXEX_rec_DDEDPD_DDEDPD_rec_DENBCD_DENBCD_rec_DIEX_DIEX_rec_DQUA_DQUA_rec_DRINTN_DRINTN_rec_DRINTX_DRINTX_rec_DRRND_DRRND_rec_DSCLI_DSCLI_rec_DSCRI_DSCRI_rec_DQUAI	= 246,
    DADD_DADD_rec_DCTDP_DCTDP_rec_DSUB_DSUB_rec	= 247,
    BCDADD_rec_BCDSUB_rec	= 248,
    DRINTNQ_DRINTNQ_rec_DRINTXQ_DRINTXQ_rec_DRRNDQ_DRRNDQ_rec_DIEXQ_DIEXQ_rec_DQUAIQ_DQUAIQ_rec_DDEDPDQ_DDEDPDQ_rec_DENBCDQ_DENBCDQ_rec_DSCLIQ_DSCLIQ_rec_DSCRIQ_DSCRIQ_rec	= 249,
    DCMPOQ_DCMPUQ_DTSTEXQ	= 250,
    DCTQPQ_DCTQPQ_rec	= 251,
    DADDQ_DADDQ_rec_DSUBQ_DSUBQ_rec	= 252,
    DQUAQ_DQUAQ_rec	= 253,
    DRSP_DRSP_rec_DCTFIX_DCTFIX_rec	= 254,
    DCFFIX_DCFFIX_rec	= 255,
    DCFFIXQ_DCFFIXQ_rec	= 256,
    DMUL_DMUL_rec	= 257,
    DMULQ_DMULQ_rec	= 258,
    DDIV_DDIV_rec	= 259,
    DDIVQ_DDIVQ_rec	= 260,
    MFVRD_MFVSRD_MFVRWZ_MFVSRWZ_MTVRD_MTVSRD_MTVRWA_MTVSRWA_MTVRWZ_MTVSRWZ	= 261,
    VADDUDM_VSLD_VSRD_VSUBUDM_VPOPCNTB_VPOPCNTH_VSRAD_VEQV_VNAND_VORC_XXLEQV_XXLNAND_XXLORC	= 262,
    VAND_VANDC_VSLB_VSLH_VSLW_VSRB_VSRH_VSRW_VRLB_VRLH_VRLW_VSRAB_VSRAH_VSRAW_VNOR_VOR_VXOR	= 263,
    VEXTSB2D_VEXTSB2Ds_VEXTSB2W_VEXTSB2Ws_VEXTSH2D_VEXTSH2Ds_VEXTSH2W_VEXTSH2Ws_VEXTSW2D_VEXTSW2Ds_MTVSRDD_VNEGD_VNEGW_XXLEQVOnes	= 264,
    V_SET0_V_SET0B_V_SET0H_XVIEXPDP_XVIEXPSP_XVXEXPDP_XVXEXPSP_VRLDMI_VRLDNM_VRLWMI_VRLWNM_XSABSQP_XSCPSGNQP_XSIEXPQP_XSNABSQP_XSNEGQP_XSXEXPQP	= 265,
    VRLD	= 266,
    XVABSDP_XVNABSDP_XVCPSGNDP_XVNEGDP	= 267,
    XVABSSP_XVNABSSP_XVNEGSP	= 268,
    XVCPSGNSP	= 269,
    VMRGEW_VMRGOW	= 270,
    VSEL	= 271,
    XXSEL	= 272,
    TABORTDC_TABORTDCI_TABORTWC_TABORTWCI	= 273,
    MTFSB0_MTFSB1	= 274,
    MFFSCDRN_MFFSCDRNI_MFFSCRN_MFFSCRNI	= 275,
    CMPRB_CMPRB8_CMPEQB	= 276,
    XSTSTDCDP_XSTSTDCSP	= 277,
    FTDIV_FTSQRT	= 278,
    XSMAXCDP_XSMAXJDP_XSMINCDP_XSMINJDP_XSXSIGDP	= 279,
    XSCMPEQDP_XSCMPEXPDP_XSCMPGEDP_XSCMPGTDP	= 280,
    CNTTZD_CNTTZD_rec_CNTTZW_CNTTZW8_CNTTZW8_rec_CNTTZW_rec	= 281,
    POPCNTD_POPCNTW	= 282,
    CMPB_CMPB8_SETB_SETB8_BPERMD	= 283,
    XSCVSPDPN	= 284,
    SLD_SRD_SRAD	= 285,
    SRADI_SRADI_32_RLDIC	= 286,
    EXTSWSLI_32_64_EXTSWSLI	= 287,
    SUBFC_SUBFC8_SUBFC8O_SUBFCO_ANDI8_rec_ANDIS8_rec_ADDC_ADDC8_ADDC8O_ADDCO_ADDIC_rec_ADDE8O_ADDE8O_rec_ADDE8_rec_ADDEO_ADDEO_rec_ADDE_rec_ADDME8O_ADDME8O_rec_ADDME8_rec_ADDMEO_ADDMEO_rec_ADDME_rec_ADDZE8O_ADDZE8O_rec_ADDZE8_rec_ADDZEO_ADDZEO_rec_ADDZE_rec_SUBF8O_SUBF8O_rec_SUBFE8O_SUBFE8O_rec_SUBFE8_rec_SUBFEO_SUBFEO_rec_SUBFE_rec_SUBFME8O_SUBFME8O_rec_SUBFME8_rec_SUBFMEO_SUBFMEO_rec_SUBFME_rec_SUBFO_SUBFO_rec_SUBFZE8O_SUBFZE8O_rec_SUBFZE8_rec_SUBFZEO_SUBFZEO_rec_SUBFZE_rec	= 288,
    ADDZE_ADDZE8_SUBF_rec	= 289,
    ADDIStocHA_ADDIStocHA8_ADDItocL_ADDItocL8	= 290,
    LA_LA8	= 291,
    COPY	= 292,
    MCRXRX	= 293,
    XSNABSDP_XSNABSDPs_XSABSDP_XSNEGDP_XSCPSGNDP	= 294,
    XSXEXPDP	= 295,
    RFEBB	= 296,
    TBEGIN_TRECHKPT	= 297,
    WAIT	= 298,
    RLDCL_RLDCR	= 299,
    RLDICL_RLDICL_32_RLDICL_32_64_RLDICR_RLDICR_32_RLDIMI	= 300,
    MTOCRF_MTOCRF8	= 301,
    SLW_SLW8_SRW_SRW8_RLWINM_RLWINM8_RLWNM_RLWNM8	= 302,
    FABSD_FABSS_FNABSD_FNABSS_FNEGD_FNEGS_FCPSGND_FCPSGNS_FMR	= 303,
    SRAW_SRAW8_SRAWI_SRAWI8	= 304,
    XSIEXPDP	= 305,
    CRXOR	= 306,
    TRECLAIM_TSR_TABORT	= 307,
    VCMPNEZB_VCMPNEZH_VCMPNEZW_VCMPNEB_VCMPNEH_VCMPNEW_VCMPNEB_rec_VCMPNEH_rec_VCMPNEW_rec_VCMPNEZB_rec_VCMPNEZH_rec_VCMPNEZW_rec	= 308,
    VABSDUB_VABSDUH_VABSDUW_VCTZB_VCTZD_VCTZH_VCTZW_VPRTYBD_VPRTYBW	= 309,
    VBPERMD_XVTSTDCDP_XVTSTDCSP_XVXSIGDP_XVXSIGSP	= 310,
    VPOPCNTD	= 311,
    VCTSXS_0_VCTUXS_0_XVCVHPSP_XVCVSPHP_VCFSX_0_VCFUX_0	= 312,
    MADDHD_MADDHDU_MADDLD_MADDLD8	= 313,
    MULHD_MULHW_MULLW_MULLWO	= 314,
    MULHDU_MULHWU	= 315,
    MULLD_MULLDO	= 316,
    FRSP_FRIMD_FRIMS_FRIND_FRINS_FRIPD_FRIPS_FRIZD_FRIZS_FRE_FRES_FADDS_FMSUBS_FMADDS_FSUBS_FCFID_FCFIDS_FCFIDU_FCFIDUS_FCTID_FCTIDU_FCTIDUZ_FCTIDZ_FCTIW_FCTIWU_FCTIWUZ_FCTIWZ_FRSQRTE_FRSQRTES_FNMADDS_FNMSUBS_FSELD_FSELS_FMULS	= 317,
    FADD_FSUB	= 318,
    FMSUB_FMADD_FNMADD_FNMSUB_FMUL	= 319,
    XSMADDADP_XSMADDASP_XSMADDMDP_XSMADDMSP_XSMSUBADP_XSMSUBASP_XSMSUBMDP_XSMSUBMSP_XSMULDP_XSMULSP_XSNMADDADP_XSNMADDASP_XSNMADDMDP_XSNMADDMSP_XSNMSUBADP_XSNMSUBASP_XSNMSUBMDP_XSNMSUBMSP	= 320,
    FSELD_rec_FSELS_rec	= 321,
    FRIMD_rec_FRIMS_rec_FRIND_rec_FRINS_rec_FRIPD_rec_FRIPS_rec_FRIZD_rec_FRIZS_rec_FRES_rec_FRE_rec_FADDS_rec_FSUBS_rec_FMSUBS_rec_FNMSUBS_rec_FMADDS_rec_FNMADDS_rec_FCFIDS_rec_FCFIDUS_rec_FCFIDU_rec_FCFID_rec_FCTIDUZ_rec_FCTIDU_rec_FCTIDZ_rec_FCTID_rec_FCTIWUZ_rec_FCTIWU_rec_FCTIWZ_rec_FCTIW_rec_FMULS_rec_FRSQRTES_rec_FRSQRTE_rec_FRSP_rec	= 322,
    XSCVDPHP_XSCVHPDP	= 323,
    LVSL_LVSR	= 324,
    V_SETALLONES_V_SETALLONESB_V_SETALLONESH_VPERMR_VSLV_VSRV_XXBRD_XXBRH_XXBRQ_XXBRW_XXEXTRACTUW_XXINSERTW_VMUL10CUQ_VMUL10ECUQ_VMUL10EUQ_VMUL10UQ_XSTSTDCQP_XSXSIGQP_BCDCFN_rec_BCDCFZ_rec_BCDCPSGN_rec_BCDCTN_rec_BCDCTZ_rec_BCDSETSGN_rec_BCDS_rec_BCDTRUNC_rec_BCDUS_rec_BCDUTRUNC_rec	= 325,
    VEXTRACTUB_VEXTRACTUH_VEXTRACTUW_VINSERTB_VINSERTD_VINSERTH_VINSERTW_MFVSRLD_MTVSRWS_VCLZLSBB_VCTZLSBB_VEXTRACTD_VEXTUBLX_VEXTUBRX_VEXTUHLX_VEXTUHRX_VEXTUWLX_VEXTUWRX_VPRTYBQ	= 326,
    XXPERM_XXPERMR_XXSPLTIB	= 327,
    XSCMPEXPQP_XSCMPOQP_XSCMPUQP	= 328,
    BCDSR_rec_XSADDQP_XSADDQPO_XSCVDPQP_XSCVQPDP_XSCVQPDPO_XSCVQPSDZ_XSCVQPSWZ_XSCVQPUDZ_XSCVQPUWZ_XSCVSDQP_XSCVUDQP_XSRQPI_XSRQPIX_XSRQPXP_XSSUBQP_XSSUBQPO	= 329,
    BCDCTSQ_rec	= 330,
    XSMADDQP_XSMADDQPO_XSMSUBQP_XSMSUBQPO_XSMULQP_XSMULQPO_XSNMADDQP_XSNMADDQPO_XSNMSUBQP_XSNMSUBQPO	= 331,
    BCDCFSQ_rec	= 332,
    XSDIVQP_XSDIVQPO	= 333,
    XSSQRTQP_XSSQRTQPO	= 334,
    LXVL_LXVLL	= 335,
    LXSIBZX_LXSIHZX_LXVWSX_LXV_LXVX_LXSD	= 336,
    LXSDX_LXVD2X	= 337,
    DCBF_DCBFEP_DCBST_DCBSTEP_DCBT_DCBTEP_DCBZ_DCBZEP_DCBZL_DCBZLEP_DCBTST_DCBTSTEP	= 338,
    CP_COPY_CP_COPY8	= 339,
    ICBI_ICBIEP	= 340,
    ICBT_ICBTLS_EnforceIEIO	= 341,
    LBZ_LBZ8_LBZX_LBZX8_LBZXTLS_LBZXTLS__LBZXTLS_32_LHZ_LHZ8_LHZX_LHZX8_LHZXTLS_LHZXTLS__LHZXTLS_32_LWZ_LWZ8_LWZX_LWZX8_LWZXTLS_LWZXTLS__LWZXTLS_32	= 342,
    CP_ABORT	= 343,
    DARN	= 344,
    ISYNC	= 345,
    MSGSYNC	= 346,
    TLBSYNC	= 347,
    SYNC	= 348,
    LFIWZX	= 349,
    LFDX_LFDXTLS_LFDXTLS__LFD	= 350,
    SLBIA	= 351,
    SLBIE	= 352,
    SLBMFEE	= 353,
    SLBMFEV	= 354,
    SLBMTE	= 355,
    TLBIEL	= 356,
    LHZU_LHZU8_LWZU_LWZU8	= 357,
    LHZUX_LHZUX8_LWZUX_LWZUX8	= 358,
    TEND	= 359,
    CP_PASTE8_rec_CP_PASTE_rec	= 360,
    TCHECK	= 361,
    LXSIWAX	= 362,
    LIWAX	= 363,
    LFSX_LFSXTLS_LFSXTLS__LFS	= 364,
    LXSSP_LXSSPX	= 365,
    XFLOADf32_DFLOADf32	= 366,
    LXVH8X	= 367,
    STFDXTLS_STFDXTLS__STFSXTLS_STFSXTLS__STXSIWX_STXSSP_STXSSPX	= 368,
    STXSD_STXSIBX_STXSIBXv_STXSIHX_STXSIHXv	= 369,
    STXSDX	= 370,
    DFSTOREf32_DFSTOREf64_XFSTOREf32_XFSTOREf64_STIWX_TLBIEP9_TLBIE8P9	= 371,
    STDBRX_STBXTLS_STBXTLS__STBXTLS_32_STHXTLS_STHXTLS__STHXTLS_32_STWXTLS_STWXTLS__STWXTLS_32	= 372,
    SLBIEG	= 373,
    TLBIE	= 374,
    STXV_STXVB16X_STXVH8X_STXVX	= 375,
    STXVL_STXVLL	= 376,
    MFVRSAVE_MFVRSAVEv_MTVRSAVE_MTVRSAVEv	= 377,
    MFPMR	= 378,
    MTPMR	= 379,
    MFSPR_MFSPR8_MFUDSCR	= 380,
    MFMSR	= 381,
    MTMSR	= 382,
    MTMSRD	= 383,
    MTUDSCR_MTSPR_MTSPR8	= 384,
    MSGSNDP_MSGSNDP8	= 385,
    DIVWO_DIVWUO	= 386,
    MODSW	= 387,
    DIVWEO_DIVWEUO	= 388,
    DIVDO_DIVDUO	= 389,
    MODSD_MODUD_MODUW	= 390,
    DIVDE_DIVDEO_DIVDEU_DIVDEUO	= 391,
    DIVWO_rec_DIVWUO_rec_DIVWU_rec_DIVW_rec	= 392,
    ADDC8O_rec_ADDC8_rec_ADDCO_rec_ADDC_rec_SUBFC8O_rec_SUBFC8_rec_SUBFCO_rec_SUBFC_rec	= 393,
    MCRFS	= 394,
    RLDCL_rec_RLDCR_rec	= 395,
    RLDICL_rec_RLDICR_rec_RLDICL_32_rec_RLDIMI_rec	= 396,
    MFFS_MFFSCE_MFFSL_MFFS_rec	= 397,
    EXTSWSLI_32_64_rec_EXTSWSLI_rec	= 398,
    FDIV	= 399,
    FSQRT	= 400,
    FSQRTS	= 401,
    FDIVS	= 402,
    LFSU	= 403,
    LFSUX	= 404,
    TAILB_TAILB8_TAILBA_TAILBA8_TAILBCTR_TAILBCTR8_CTRL_DEP	= 405,
    LDAT_LWAT	= 406,
    STDAT_STWAT	= 407,
    BRINC	= 408,
    EVABS_EVEQV_EVNAND_EVNEG_EVADDIW_EVADDW_EVAND_EVANDC_EVCMPEQ_EVCMPGTS_EVCMPGTU_EVCMPLTS_EVCMPLTU_EVCNTLSW_EVCNTLZW_EVEXTSB_EVEXTSH_EVMERGEHI_EVMERGEHILO_EVMERGELO_EVMERGELOHI_EVNOR_EVOR_EVORC_EVXOR_EVRLW_EVRLWI_EVRNDW_EVSLW_EVSLWI_EVSPLATFI_EVSPLATI_EVSRWIS_EVSRWIU_EVSRWS_EVSRWU_EVSUBFW_EVSUBIFW	= 409,
    EVMRA_EVADDSMIAAW_EVADDSSIAAW_EVADDUMIAAW_EVADDUSIAAW_EVDIVWS_EVDIVWU_EVMHEGSMFAA_EVMHEGSMFAN_EVMHEGSMIAA_EVMHEGSMIAN_EVMHEGUMIAA_EVMHEGUMIAN_EVMHESMF_EVMHESMFA_EVMHESMFAAW_EVMHESMFANW_EVMHESMI_EVMHESMIA_EVMHESMIAAW_EVMHESMIANW_EVMHESSF_EVMHESSFA_EVMHESSFAAW_EVMHESSFANW_EVMHESSIAAW_EVMHESSIANW_EVMHEUMI_EVMHEUMIA_EVMHEUMIAAW_EVMHEUMIANW_EVMHEUSIAAW_EVMHEUSIANW_EVMHOGSMFAA_EVMHOGSMFAN_EVMHOGSMIAA_EVMHOGSMIAN_EVMHOGUMIAA_EVMHOGUMIAN_EVMHOSMF_EVMHOSMFA_EVMHOSMFAAW_EVMHOSMFANW_EVMHOSMI_EVMHOSMIA_EVMHOSMIAAW_EVMHOSMIANW_EVMHOSSF_EVMHOSSFA_EVMHOSSFAAW_EVMHOSSFANW_EVMHOSSIAAW_EVMHOSSIANW_EVMHOUMI_EVMHOUMIA_EVMHOUMIAAW_EVMHOUMIANW_EVMHOUSIAAW_EVMHOUSIANW_EVMWHSMF_EVMWHSMFA_EVMWHSMI_EVMWHSMIA_EVMWHSSF_EVMWHSSFA_EVMWHUMI_EVMWHUMIA_EVMWLSMIAAW_EVMWLSMIANW_EVMWLSSIAAW_EVMWLSSIANW_EVMWLUMI_EVMWLUMIA_EVMWLUMIAAW_EVMWLUMIANW_EVMWLUSIAAW_EVMWLUSIANW_EVMWSMF_EVMWSMFA_EVMWSMFAA_EVMWSMFAN_EVMWSMI_EVMWSMIA_EVMWSMIAA_EVMWSMIAN_EVMWSSF_EVMWSSFA_EVMWSSFAA_EVMWSSFAN_EVMWUMI_EVMWUMIA_EVMWUMIAA_EVMWUMIAN_EVSUBFSMIAAW_EVSUBFSSIAAW_EVSUBFUMIAAW_EVSUBFUSIAAW	= 410,
    EVLDD_EVLDDX_EVLDH_EVLDHX_EVLDW_EVLDWX_EVLHHESPLAT_EVLHHESPLATX_EVLHHOSSPLAT_EVLHHOSSPLATX_EVLHHOUSPLAT_EVLHHOUSPLATX_EVLWHE_EVLWHEX_EVLWHOS_EVLWHOSX_EVLWHOU_EVLWHOUX_EVLWHSPLAT_EVLWHSPLATX_EVLWWSPLAT_EVLWWSPLATX	= 411,
    EVSTDD_EVSTDDX_EVSTDH_EVSTDHX_EVSTDW_EVSTDWX_EVSTWHE_EVSTWHEX_EVSTWHO_EVSTWHOX_EVSTWWE_EVSTWWEX_EVSTWWO_EVSTWWOX	= 412,
    HRFID_ATTN_CLRBHRB_MFBHRBE_NAP_RFCI_RFDI_RFMCI_SC	= 413,
    RFI	= 414,
    RFID	= 415,
    DSS_DSSALL_DST_DST64_DSTST_DSTST64_DSTSTT_DSTSTT64_DSTT_DSTT64_ICBLQ_TLBIVAX_TLBLD_TLBLI_TLBRE_TLBRE2_TLBSX_TLBSX2_TLBSX2D_TLBWE_TLBWE2_MBAR_TRAP_DCCCI_ICCCI	= 416,
    ICBLC	= 417,
    MTSR_MTSRIN	= 418,
    MFDCR	= 419,
    MTDCR	= 420,
    NOP_GT_PWR6_NOP_GT_PWR7	= 421,
    TLBIA	= 422,
    WRTEE_WRTEEI	= 423,
    HASHCHK_HASHCHK8_HASHCHKP_HASHCHKP8_HASHST_HASHST8_HASHSTP_HASHSTP8_ADDEX_ADDEX8_CDTBCD_CDTBCD8_CBCDTD_CBCDTD8	= 424,
    MSYNC	= 425,
    SLBSYNC	= 426,
    SLBFEE_rec	= 427,
    STOP	= 428,
    DCBA_DCBI	= 429,
    FCFID_FCFIDS_FCFIDU_FCFIDUS_FCTID_FCTIDU_FCTIDUZ_FCTIDZ_FCTIW_FCTIWU_FCTIWUZ_FCTIWZ_FRE_FRES_FRIMD_FRIMS_FRIND_FRINS_FRIPD_FRIPS_FRIZD_FRIZS_FRSP_FRSQRTE_FRSQRTES	= 430,
    VCFSX_VCFUX_VCTSXS_VCTUXS	= 431,
    VCFSX_0_VCFUX_0_VCTSXS_0_VCTUXS_0_XVCVSPHP	= 432,
    VLOGEFP_VREFP_VRFIM_VRFIN_VRFIP_VRFIZ_VRSQRTEFP_XVCVDPSP_XVCVSXDSP_XVCVSXWSP_XVCVUXDSP_XVCVUXWSP_XVRESP_XVRSQRTESP	= 433,
    XSCVDPHP	= 434,
    XSCVDPSP_XSCVDPSXDS_XSCVDPSXDSs_XSCVDPSXWS_XSCVDPSXWSs_XSCVDPUXDS_XSCVDPUXDSs_XSCVDPUXWS_XSCVDPUXWSs_XSCVSPDP_XSCVSXDDP_XSCVUXDDP_XSRDPI_XSRDPIC_XSRDPIM_XSRDPIP_XSRDPIZ_XSREDP_XSRSQRTEDP	= 435,
    XVCVDPSXDS_XVCVDPSXWS_XVCVDPUXDS_XVCVDPUXWS_XVCVSPSXDS_XVCVSPSXWS_XVCVSPUXDS_XVCVSPUXWS_XVCVSXDDP_XVCVSXWDP_XVCVUXDDP_XVCVUXWDP_XVRDPI_XVRDPIC_XVRDPIM_XVRDPIP_XVRDPIZ_XVREDP_XVRSPI_XVRSPIC_XVRSPIM_XVRSPIP_XVRSPIZ_XVRSQRTEDP	= 436,
    XVCVSPBF16	= 437,
    FADDS_FMULS_FSUBS	= 438,
    FMUL	= 439,
    VADDFP	= 440,
    XSMULDP_XSMULSP	= 441,
    XVADDDP_XVMULDP_XVSUBDP	= 442,
    XVADDSP_XVMULSP_XVSUBSP	= 443,
    VMADDFP_VNMSUBFP	= 444,
    FADDS_rec_FMULS_rec_FSUBS_rec	= 445,
    FMUL_rec	= 446,
    FCFID_rec_FCFIDS_rec_FCFIDU_rec_FCFIDUS_rec_FCTID_rec_FCTIDU_rec_FCTIDUZ_rec_FCTIDZ_rec_FCTIW_rec_FCTIWU_rec_FCTIWUZ_rec_FCTIWZ_rec_FRE_rec_FRES_rec_FRIMD_rec_FRIMS_rec_FRIND_rec_FRINS_rec_FRIPD_rec_FRIPS_rec_FRIZD_rec_FRIZS_rec_FRSP_rec_FRSQRTE_rec_FRSQRTES_rec	= 447,
    BCC_BCCA_BCCCTR_BCCCTR8_BCCCTRL_BCCCTRL8_BCCL_BCCLA_BCCLR_BCCLRL_BCCTR_BCCTR8_BCCTR8n_BCCTRn_gBCCTR_BCCTRL_BCCTRL8_BCCTRL8n_BCCTRLn_gBCCTRL_BCLR_BCLRn_BDNZLR_BDNZLR8_BDNZLRm_BDNZLRp_BDZLR_BDZLR8_BDZLRm_BDZLRp_gBCLR_BCLRL_BCLRLn_BDNZLRL_BDNZLRLm_BDNZLRLp_BDZLRL_BDZLRLm_BDZLRLp_gBCLRL_BLR_BLR8_BLRL	= 448,
    CTRL_DEP_TAILB_TAILB8_TAILBA_TAILBA8	= 449,
    VGNB	= 450,
    VSBOX	= 451,
    CFUGED_PDEPD_PEXTD	= 452,
    VCFUGED_VCLZDM_VCTZDM_VPDEPD_VPEXTD	= 453,
    XSCVDPQP_XSCVQPDP_XSCVQPDPO_XSCVQPSDZ_XSCVQPSWZ_XSCVQPUDZ_XSCVQPUWZ_XSCVSDQP_XSCVUDQP_XSRQPI_XSRQPIX_XSRQPXP	= 454,
    XSCVQPSQZ_XSCVQPUQZ_XSCVSQQP_XSCVUQQP	= 455,
    HASHST_HASHST8_HASHSTP_HASHSTP8	= 456,
    XSMULQP_XSMULQPO	= 457,
    VDIVESQ_VDIVEUQ_VDIVSQ_VDIVUQ	= 458,
    VMODSQ_VMODUQ	= 459,
    VDIVSD_VDIVUD	= 460,
    VMODSD_VMODUD	= 461,
    VDIVSW_VDIVUW	= 462,
    VMODSW_VMODUW	= 463,
    VDIVESD_VDIVEUD	= 464,
    VDIVESW_VDIVEUW	= 465,
    BCDCFN_rec_BCDCFZ_rec_BCDCTN_rec_BCDCTZ_rec_BCDSETSGN_rec_VMUL10CUQ_VMUL10UQ_XSTSTDCQP_XSXSIGQP	= 466,
    XXGENPCVBM	= 467,
    BCDCPSGN_rec_BCDS_rec_BCDTRUNC_rec_BCDUS_rec_BCDUTRUNC_rec_VMUL10ECUQ_VMUL10EUQ	= 468,
    VADDCUQ_VSUBCUQ	= 469,
    XSCMPEQQP_XSCMPGEQP_XSCMPGTQP_XSMAXCQP_XSMINCQP	= 470,
    MTVSRBMI	= 471,
    CBCDTD_CBCDTD8_CDTBCD_CDTBCD8	= 472,
    FTSQRT	= 473,
    MTVSRBM_MTVSRDM_MTVSRHM_MTVSRQM_MTVSRWM_VCNTMBB_VCNTMBD_VCNTMBH_VCNTMBW_VEXPANDBM_VEXPANDDM_VEXPANDHM_VEXPANDQM_VEXPANDWM_VEXTRACTBM_VEXTRACTDM_VEXTRACTHM_VEXTRACTQM_VEXTRACTWM_XVTLSBB	= 474,
    RLDIC_rec	= 475,
    RLDICL_32_rec_RLDICL_rec_RLDICR_rec	= 476,
    RLWINM8_rec_RLWINM_rec	= 477,
    VCTZB_VCTZD_VCTZH_VCTZW_VPRTYBD_VPRTYBW	= 478,
    VPOPCNTB_VPOPCNTH	= 479,
    VSHASIGMAD_VSHASIGMAW	= 480,
    XSTSQRTDP	= 481,
    XVTSQRTDP	= 482,
    XVTSQRTSP	= 483,
    XVTSTDCDP_XVTSTDCSP	= 484,
    SLD_rec_SRD_rec	= 485,
    TDI	= 486,
    TWI	= 487,
    VADDCUW_VADDSBS_VADDSHS_VADDSWS_VADDUBS_VADDUHS_VADDUWS_VAVGSB_VAVGSH_VAVGSW_VAVGUB_VAVGUH_VAVGUW_VMAXFP_VMINFP_VSUBCUW_VSUBSBS_VSUBSHS_VSUBSWS_VSUBUBS_VSUBUHS_VSUBUWS	= 488,
    VCMPBFP_VCMPBFP_rec_VCMPEQFP_VCMPEQFP_rec_VCMPEQUB_rec_VCMPEQUH_rec_VCMPEQUW_rec_VCMPGEFP_VCMPGEFP_rec_VCMPGTFP_VCMPGTFP_rec_VCMPGTSB_rec_VCMPGTSH_rec_VCMPGTSW_rec_VCMPGTUB_rec_VCMPGTUH_rec_VCMPGTUW_rec_XVCMPEQSP_XVCMPEQSP_rec_XVCMPGESP_XVCMPGESP_rec_XVCMPGTSP_XVCMPGTSP_rec	= 489,
    VCMPEQUD_rec_VCMPGTSD_rec_VCMPGTUD_rec	= 490,
    VCMPEQUQ_VCMPEQUQ_rec_VCMPGTSQ_VCMPGTSQ_rec_VCMPGTUQ_VCMPGTUQ_rec	= 491,
    VCMPNEB_rec_VCMPNEH_rec_VCMPNEW_rec_VCMPNEZB_rec_VCMPNEZH_rec_VCMPNEZW_rec	= 492,
    VCMPSQ_VCMPUQ	= 493,
    XSMAXCDP_XSMAXJDP_XSMINCDP_XSMINJDP	= 494,
    TRAP	= 495,
    SRAWI8_rec_SRAWI_rec	= 496,
    VRLQ_VRLQNM_VSLQ_VSRAQ_VSRQ	= 497,
    VRLQMI	= 498,
    DSS_DSSALL	= 499,
    WAITP10	= 500,
    ADDI_ADDI8_LI_LI8_ADDIS_ADDIS8_LIS_LIS8_NEG_NEG8_NEG8O_NEGO	= 501,
    ADDIdtprelL32_ADDISdtprelHA32	= 502,
    ADDItlsldLADDR32	= 503,
    ADDItocL_ADDIStocHA_ADDIStocHA8	= 504,
    ADDIC_ADDIC8_ADDME_ADDME8_SUBFIC_SUBFIC8_SUBFME_SUBFME8_SUBFZE_SUBFZE8	= 505,
    ADDME8O_ADDMEO_ADDZE8O_ADDZEO_ANDI8_rec_ANDIS8_rec_SUBFME8O_SUBFMEO_SUBFZE8O_SUBFZEO	= 506,
    ADDZE_ADDZE8	= 507,
    ANDI_rec_ANDIS_rec	= 508,
    CMPDI_CMPWI_CMPLDI_CMPLWI	= 509,
    EXTSB_EXTSB8_EXTSB8_32_64_EXTSB8_rec_EXTSB_rec_EXTSH_EXTSH8_EXTSH8_32_64_EXTSH8_rec_EXTSH_rec_EXTSW_EXTSW_32_EXTSW_32_64_EXTSW_32_64_rec_EXTSW_rec	= 510,
    FABSD_FABSS_FMR_FNABSD_FNABSS_FNEGD_FNEGS	= 511,
    NEG8_rec_NEG_rec_ORI_ORI8_ORIS_ORIS8_XORI_XORI8_XORIS_XORIS8	= 512,
    NOP	= 513,
    RLDICL_RLDICL_32_RLDICL_32_64_RLDICR_RLDICR_32	= 514,
    RLWINM_RLWINM8	= 515,
    SETB_SETB8	= 516,
    SETBC_SETBC8_SETBCR_SETBCR8_SETNBC_SETNBC8_SETNBCR_SETNBCR8	= 517,
    SRAWI_SRAWI8	= 518,
    VEXTSB2D_VEXTSB2Ds_VEXTSB2W_VEXTSB2Ws_VEXTSH2D_VEXTSH2Ds_VEXTSH2W_VEXTSH2Ws_VEXTSW2D_VEXTSW2Ds_VNEGD_VNEGW	= 519,
    VEXTSD2Q	= 520,
    XSABSDP_XSNABSDP_XSNABSDPs_XSNEGDP	= 521,
    XSABSQP_XSNABSQP_XSNEGQP_XSXEXPQP_XVXEXPDP_XVXEXPSP	= 522,
    XVABSDP_XVNABSDP_XVNEGDP	= 523,
    XVXSIGDP_XVXSIGSP	= 524,
    ADDE8O_ADDEO_SUBFE8O_SUBFEO_SUBF8O_SUBFO	= 525,
    ADDEX_ADDEX8	= 526,
    ADD4O_ADD8O	= 527,
    CMPB_CMPB8	= 528,
    CRAND_CRANDC_CR6SET_CREQV_CRSET_CRNAND_CRNOR_CROR_CRORC_CR6UNSET_CRUNSET	= 529,
    DST_DST64_DSTT_DSTT64_DSTST_DSTST64_DSTSTT_DSTSTT64	= 530,
    VRLDNM_VRLWNM_V_SET0_V_SET0B_V_SET0H_XSCPSGNQP_XSIEXPQP_XVIEXPDP_XVIEXPSP	= 531,
    XXLEQVOnes	= 532,
    MFFS_MFFS_rec_MFFSL	= 533,
    MFFSCDRNI_MFFSCRNI	= 534,
    MTFSB0	= 535,
    ADDIC_rec_ADDME8_rec_ADDME_rec_ADDME8O_rec_ADDMEO_rec_ADDZE8_rec_ADDZE_rec_ADDZE8O_rec_ADDZEO_rec_SUBFME8_rec_SUBFME_rec_SUBFME8O_rec_SUBFMEO_rec_SUBFZE8_rec_SUBFZE_rec_SUBFZE8O_rec_SUBFZEO_rec	= 536,
    NEG8O_rec_NEGO_rec	= 537,
    ADDE8_rec_ADDE_rec_ADDE8O_rec_ADDEO_rec_SUBFE8_rec_SUBFE_rec_SUBFE8O_rec_SUBFEO_rec_SUBF8O_rec_SUBFO_rec	= 538,
    HRFID_SC	= 539,
    MTFSFI_MTFSFIb_MTFSFI_rec	= 540,
    FABSD_rec_FABSS_rec_FMR_rec_FNABSD_rec_FNABSS_rec_FNEGD_rec_FNEGS_rec	= 541,
    ADDC8_rec_ADDC_rec_SUBFC8_rec_SUBFC_rec	= 542,
    VSTRIBL_rec_VSTRIBR_rec_VSTRIHL_rec_VSTRIHR_rec	= 543,
    LBZ_LBZ8_LHZ_LHZ8_LWZ_LWZ8	= 544,
    LD	= 545,
    LDtoc_LDtocBA_LDtocCPT_LDtocJTI_LDtocL_SPILLTOVSR_LD_LWZtoc_LWZtocL	= 546,
    DFLOADf32	= 547,
    DFLOADf64	= 548,
    LFD	= 549,
    LHA_LHA8	= 550,
    LXSD_LXV	= 551,
    DCBT_DCBTST	= 552,
    ICBT	= 553,
    LDBRX	= 554,
    SPILLTOVSR_LDX	= 555,
    LXVRBX_LXVRDX_LXVRHX_LXVRWX	= 556,
    MTSR	= 557,
    MTVRSAVE_MTVRSAVEv	= 558,
    LBZCIX_LDCIX_LHZCIX_LWZCIX	= 559,
    PLBZ_PLBZ8_PLBZ8pc_PLBZpc_PLD_PLDpc_PLFD_PLFDpc_PLFS_PLFSpc_PLHA_PLHA8_PLHA8pc_PLHApc_PLHZ_PLHZ8_PLHZ8pc_PLHZpc_PLWA_PLWA8_PLWA8pc_PLWApc_PLWZ_PLWZ8_PLWZ8pc_PLWZpc_PLXSD_PLXSDpc_PLXSSP_PLXSSPpc_PLXV_PLXVpc_PLXVP_PLXVPpc	= 560,
    LFS	= 561,
    LXSSP	= 562,
    LXVP	= 563,
    LXVPX	= 564,
    MFSR	= 565,
    MFTB8	= 566,
    XXSETACCZ	= 567,
    XVBF16GER2_XVF16GER2_XVF32GER_XVF64GER_XVI16GER2_XVI16GER2S_XVI4GER8_XVI8GER4	= 568,
    XVBF16GER2NN_XVBF16GER2NP_XVBF16GER2PN_XVBF16GER2PP_XVF16GER2NN_XVF16GER2NP_XVF16GER2PN_XVF16GER2PP_XVF32GERNN_XVF32GERNP_XVF32GERPN_XVF32GERPP_XVF64GERNN_XVF64GERNP_XVF64GERPN_XVF64GERPP_XVI16GER2PP_XVI16GER2SPP_XVI4GER8PP_XVI8GER4PP	= 569,
    XVI8GER4SPP	= 570,
    PMXVBF16GER2_PMXVF16GER2_PMXVF32GER_PMXVF64GER_PMXVI16GER2_PMXVI16GER2S_PMXVI4GER8_PMXVI8GER4	= 571,
    PMXVBF16GER2NN_PMXVBF16GER2NP_PMXVBF16GER2PN_PMXVBF16GER2PP_PMXVF16GER2NN_PMXVF16GER2NP_PMXVF16GER2PN_PMXVF16GER2PP_PMXVF32GERNN_PMXVF32GERNP_PMXVF32GERPN_PMXVF32GERPP_PMXVF64GERNN_PMXVF64GERNP_PMXVF64GERPN_PMXVF64GERPP_PMXVI16GER2PP_PMXVI16GER2SPP_PMXVI4GER8PP_PMXVI8GER4PP	= 572,
    PMXVI8GER4SPP	= 573,
    XXMTACC	= 574,
    XXMFACC	= 575,
    VMULHSD_VMULHUD_VMULLD	= 576,
    LXVKQ	= 577,
    VSPLTISB_VSPLTISH_VSPLTISW	= 578,
    V_SETALLONES_V_SETALLONESB_V_SETALLONESH	= 579,
    XXSPLTIB	= 580,
    BRD_BRH_BRH8_BRW_BRW8	= 581,
    MFVSRLD_MTVSRWS_VCLZLSBB_VCTZLSBB_VEXTRACTD_VEXTRACTUB_VEXTRACTUH_VEXTRACTUW_VINSERTD_VINSERTW_VPRTYBQ	= 582,
    VGBBD_VUPKHSW_VUPKLSW	= 583,
    VSPLTB_VSPLTBs_VSPLTH_VSPLTHs_VSPLTW_XXSPLTW_XXSPLTWs	= 584,
    VSTRIBL_VSTRIBR_VSTRIHL_VSTRIHR_XXGENPCVDM_XXGENPCVHM_XXGENPCVWM	= 585,
    VUPKHPX_VUPKHSB_VUPKHSH_VUPKLPX_VUPKLSB_VUPKLSH	= 586,
    XVCVBF16SPN	= 587,
    XXBRD_XXBRH_XXBRQ_XXBRW_XXEXTRACTUW	= 588,
    VBPERMQ_VPKSDSS_VPKSDUS_VPKUDUM_VPKUDUS	= 589,
    VCLRLB_VCLRRB_VINSD_VINSW_VSLDBI_VSRDBI	= 590,
    VPKPX_VPKSHSS_VPKSHUS_VPKSWSS_VPKSWUS_VPKUHUM_VPKUHUS_VPKUWUM_VPKUWUS	= 591,
    VSLV_VSRV_XXINSERTW	= 592,
    VEXTDDVLX_VEXTDDVRX_VEXTDUBVLX_VEXTDUBVRX_VEXTDUHVLX_VEXTDUHVRX_VEXTDUWVLX_VEXTDUWVRX_VINSBLX_VINSBRX_VINSBVLX_VINSBVRX_VINSDLX_VINSDRX_VINSHLX_VINSHRX_VINSHVLX_VINSHVRX_VINSWLX_VINSWRX_VINSWVLX_VINSWVRX	= 593,
    VSUMSWS	= 594,
    XXSPLTIDP_XXSPLTIW	= 595,
    XXSPLTI32DX	= 596,
    XXBLENDVB_XXBLENDVD_XXBLENDVH_XXBLENDVW_XXEVAL	= 597,
    XXPERMX	= 598,
    PSTXVP_PSTXVPpc	= 599,
    STB_STB8_STH_STH8_STW_STW8	= 600,
    SPILLTOVSR_ST	= 601,
    STD	= 602,
    DFSTOREf32_DFSTOREf64	= 603,
    STFD_STFS	= 604,
    STFDU_STFSU	= 605,
    STXSD	= 606,
    STXSSP	= 607,
    STXV	= 608,
    DCBF_DCBST_DCBZ	= 609,
    ICBI	= 610,
    SPILLTOVSR_STX	= 611,
    STIWX	= 612,
    STXVRBX_STXVRDX_STXVRHX_STXVRWX	= 613,
    EnforceIEIO	= 614,
    TLBIE8P9_TLBIEP9	= 615,
    STHCIX_STWCIX	= 616,
    SYNCP10	= 617,
    PSTB_PSTB8_PSTB8pc_PSTBpc_PSTD_PSTDpc_PSTFD_PSTFDpc_PSTFS_PSTFSpc_PSTH_PSTH8_PSTH8pc_PSTHpc_PSTW_PSTW8_PSTW8pc_PSTWpc_PSTXSD_PSTXSDpc_PSTXSSP_PSTXSSPpc_PSTXV_PSTXVpc	= 618,
    STXVP	= 619,
    STXVPX	= 620,
    ATTN_NAP	= 621,
    DCBZL	= 622,
    DCCCI_ICBLQ_ICCCI_TLBLD_TLBLI_TLBRE2_TLBSX2_TLBSX2D_TLBWE2	= 623,
    CLRBHRB_MFBHRBE	= 624,
    PADDI_PADDI8_PADDI8pc_PADDIpc	= 625,
    PLI_PLI8	= 626,
    VMULESB_VMULESH_VMULEUB_VMULEUH_VMULOSB_VMULOSH_VMULOUB_VMULOUH_VSUM2SWS_VSUM4SBS_VSUM4SHS_VSUM4UBS	= 627,
    VMULESD_VMULEUD_VMULHSW_VMULHUW_VMULOSD_VMULOUD	= 628,
    VMSUMCUD	= 629,
    SCHED_LIST_END = 630
  };

} // namespace llvm_ks::PPC::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct PPCInstrTable {
  MCInstrDesc Insts[3002];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[250];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[1350];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof PPCInstrTable::ImplicitOps + sizeof PPCInstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned PPCOpInfoBase = (sizeof PPCInstrTable::ImplicitOps + sizeof PPCInstrTable::Padding) / sizeof(MCOperandInfo);

extern const PPCInstrTable PPCDescs = {
  {
    { 3001,	4,	0,	4,	104,	2,	1,	PPCOpInfoBase + 1346,	119,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCat
    { 3000,	4,	0,	4,	104,	2,	2,	PPCOpInfoBase + 1346,	246,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCLat
    { 2999,	3,	0,	4,	448,	3,	2,	PPCOpInfoBase + 1343,	241,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCLRL
    { 2998,	3,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1343,	122,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCLR
    { 2997,	4,	0,	4,	104,	2,	2,	PPCOpInfoBase + 1339,	246,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCLAat
    { 2996,	3,	0,	4,	104,	2,	2,	PPCOpInfoBase + 1336,	246,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCLA
    { 2995,	3,	0,	4,	104,	2,	2,	PPCOpInfoBase + 1333,	246,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCL
    { 2994,	3,	0,	4,	448,	3,	2,	PPCOpInfoBase + 1343,	241,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCCTRL
    { 2993,	3,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1343,	122,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCCTR
    { 2992,	4,	0,	4,	104,	2,	1,	PPCOpInfoBase + 1339,	119,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCAat
    { 2991,	3,	0,	4,	104,	2,	1,	PPCOpInfoBase + 1336,	119,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBCA
    { 2990,	3,	0,	4,	104,	2,	1,	PPCOpInfoBase + 1333,	119,	0|(1ULL<<MCID::Branch), 0x38ULL },  // gBC
    { 2989,	5,	1,	8,	19,	0,	0,	PPCOpInfoBase + 1281,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // XXSSUMUDMCEXT
    { 2988,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1292,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXSSUMUDMC
    { 2987,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1292,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXSSUMUDM
    { 2986,	3,	1,	4,	584,	0,	0,	PPCOpInfoBase + 1322,	0,	0, 0x0ULL },  // XXSPLTWs
    { 2985,	3,	1,	4,	584,	0,	0,	PPCOpInfoBase + 1330,	0,	0, 0x0ULL },  // XXSPLTW
    { 2984,	2,	1,	8,	595,	0,	0,	PPCOpInfoBase + 660,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x80ULL },  // XXSPLTIW
    { 2983,	2,	1,	8,	595,	0,	0,	PPCOpInfoBase + 660,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x80ULL },  // XXSPLTIDP
    { 2982,	2,	1,	4,	580,	0,	0,	PPCOpInfoBase + 660,	0,	0, 0x0ULL },  // XXSPLTIB
    { 2981,	4,	1,	8,	596,	0,	0,	PPCOpInfoBase + 1326,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x80ULL },  // XXSPLTI32DX
    { 2980,	3,	1,	4,	167,	0,	0,	PPCOpInfoBase + 1322,	0,	0, 0x0ULL },  // XXSLDWIs
    { 2979,	4,	1,	4,	167,	0,	0,	PPCOpInfoBase + 1292,	0,	0, 0x0ULL },  // XXSLDWI
    { 2978,	1,	1,	4,	567,	0,	0,	PPCOpInfoBase + 1325,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // XXSETACCZ
    { 2977,	4,	1,	4,	272,	0,	0,	PPCOpInfoBase + 1277,	0,	0, 0x0ULL },  // XXSEL
    { 2976,	5,	1,	8,	598,	0,	0,	PPCOpInfoBase + 1281,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // XXPERMX
    { 2975,	4,	1,	4,	327,	0,	0,	PPCOpInfoBase + 1318,	0,	0, 0x0ULL },  // XXPERMR
    { 2974,	3,	1,	4,	167,	0,	0,	PPCOpInfoBase + 1322,	0,	0, 0x0ULL },  // XXPERMDIs
    { 2973,	4,	1,	4,	167,	0,	0,	PPCOpInfoBase + 1292,	0,	0, 0x0ULL },  // XXPERMDI
    { 2972,	4,	1,	4,	327,	0,	0,	PPCOpInfoBase + 1318,	0,	0, 0x0ULL },  // XXPERM
    { 2971,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1313,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXMULMULLOADD
    { 2970,	6,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1307,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXMULMULHIADD
    { 2969,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1292,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXMULMUL
    { 2968,	2,	1,	4,	19,	0,	0,	PPCOpInfoBase + 1305,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXMTACCW
    { 2967,	2,	1,	4,	574,	0,	0,	PPCOpInfoBase + 1303,	0,	0, 0x0ULL },  // XXMTACC
    { 2966,	3,	1,	4,	167,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XXMRGLW
    { 2965,	3,	1,	4,	167,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XXMRGHW
    { 2964,	2,	1,	4,	19,	0,	0,	PPCOpInfoBase + 1305,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXMFACCW
    { 2963,	2,	1,	4,	575,	0,	0,	PPCOpInfoBase + 1303,	0,	0, 0x0ULL },  // XXMFACC
    { 2962,	1,	1,	4,	169,	0,	0,	PPCOpInfoBase + 1300,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // XXLXORz
    { 2961,	1,	1,	4,	169,	0,	0,	PPCOpInfoBase + 1302,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // XXLXORspz
    { 2960,	1,	1,	4,	169,	0,	0,	PPCOpInfoBase + 1301,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // XXLXORdpz
    { 2959,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // XXLXOR
    { 2958,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 1171,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // XXLORf
    { 2957,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XXLORC
    { 2956,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // XXLOR
    { 2955,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // XXLNOR
    { 2954,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // XXLNAND
    { 2953,	1,	1,	4,	532,	0,	0,	PPCOpInfoBase + 1300,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Bitcast)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // XXLEQVOnes
    { 2952,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // XXLEQV
    { 2951,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XXLANDC
    { 2950,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // XXLAND
    { 2949,	4,	1,	4,	592,	0,	0,	PPCOpInfoBase + 1296,	0,	0, 0x0ULL },  // XXINSERTW
    { 2948,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1292,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXGFMUL128
    { 2947,	3,	1,	4,	585,	0,	0,	PPCOpInfoBase + 1289,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXGENPCVWM
    { 2946,	3,	1,	4,	585,	0,	0,	PPCOpInfoBase + 1289,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXGENPCVHM
    { 2945,	3,	1,	4,	585,	0,	0,	PPCOpInfoBase + 1289,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXGENPCVDM
    { 2944,	3,	1,	4,	467,	0,	0,	PPCOpInfoBase + 1289,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXGENPCVBM
    { 2943,	3,	1,	4,	588,	0,	0,	PPCOpInfoBase + 1286,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXEXTRACTUW
    { 2942,	5,	1,	8,	597,	0,	0,	PPCOpInfoBase + 1281,	0,	0, 0x80ULL },  // XXEVAL
    { 2941,	2,	1,	4,	588,	0,	0,	PPCOpInfoBase + 1228,	0,	0, 0x0ULL },  // XXBRW
    { 2940,	2,	1,	4,	588,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXBRQ
    { 2939,	2,	1,	4,	588,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XXBRH
    { 2938,	2,	1,	4,	588,	0,	0,	PPCOpInfoBase + 1228,	0,	0, 0x0ULL },  // XXBRD
    { 2937,	4,	1,	8,	597,	0,	0,	PPCOpInfoBase + 1277,	0,	0, 0x80ULL },  // XXBLENDVW
    { 2936,	4,	1,	8,	597,	0,	0,	PPCOpInfoBase + 1277,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // XXBLENDVH
    { 2935,	4,	1,	8,	597,	0,	0,	PPCOpInfoBase + 1277,	0,	0, 0x80ULL },  // XXBLENDVD
    { 2934,	4,	1,	8,	597,	0,	0,	PPCOpInfoBase + 1277,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // XXBLENDVB
    { 2933,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1274,	0,	0, 0x0ULL },  // XXAESGENLKP
    { 2932,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1270,	0,	0, 0x0ULL },  // XXAESENCP
    { 2931,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1270,	0,	0, 0x0ULL },  // XXAESDECP
    { 2930,	2,	1,	4,	524,	0,	0,	PPCOpInfoBase + 1228,	0,	0, 0x0ULL },  // XVXSIGSP
    { 2929,	2,	1,	4,	524,	0,	0,	PPCOpInfoBase + 1228,	0,	0, 0x0ULL },  // XVXSIGDP
    { 2928,	2,	1,	4,	522,	0,	0,	PPCOpInfoBase + 1228,	0,	0, 0x0ULL },  // XVXEXPSP
    { 2927,	2,	1,	4,	522,	0,	0,	PPCOpInfoBase + 1228,	0,	0, 0x0ULL },  // XVXEXPDP
    { 2926,	3,	1,	4,	484,	0,	0,	PPCOpInfoBase + 1267,	0,	0, 0x0ULL },  // XVTSTDCSP
    { 2925,	3,	1,	4,	484,	0,	0,	PPCOpInfoBase + 1267,	0,	0, 0x0ULL },  // XVTSTDCDP
    { 2924,	2,	1,	4,	483,	1,	0,	PPCOpInfoBase + 1265,	162,	0, 0x0ULL },  // XVTSQRTSP
    { 2923,	2,	1,	4,	482,	1,	0,	PPCOpInfoBase + 1265,	162,	0, 0x0ULL },  // XVTSQRTDP
    { 2922,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 1265,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVTLSBB
    { 2921,	3,	1,	4,	170,	1,	0,	PPCOpInfoBase + 1262,	162,	0, 0x0ULL },  // XVTDIVSP
    { 2920,	3,	1,	4,	165,	1,	0,	PPCOpInfoBase + 1262,	162,	0, 0x0ULL },  // XVTDIVDP
    { 2919,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XVSUBUWM
    { 2918,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVSUBUHM
    { 2917,	3,	1,	4,	443,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVSUBSP
    { 2916,	3,	1,	4,	442,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVSUBDP
    { 2915,	2,	1,	4,	180,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVSQRTSP
    { 2914,	2,	1,	4,	182,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVSQRTDP
    { 2913,	2,	1,	4,	433,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRSQRTESP
    { 2912,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRSQRTEDP
    { 2911,	2,	1,	4,	436,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRSPIZ
    { 2910,	2,	1,	4,	436,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRSPIP
    { 2909,	2,	1,	4,	436,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRSPIM
    { 2908,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRSPIC
    { 2907,	2,	1,	4,	436,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRSPI
    { 2906,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XVRLW
    { 2905,	2,	1,	4,	433,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRESP
    { 2904,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVREDP
    { 2903,	2,	1,	4,	436,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRDPIZ
    { 2902,	2,	1,	4,	436,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRDPIP
    { 2901,	2,	1,	4,	436,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRDPIM
    { 2900,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRDPIC
    { 2899,	2,	1,	4,	436,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVRDPI
    { 2898,	4,	1,	4,	191,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVNMSUBMSP
    { 2897,	4,	1,	4,	194,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVNMSUBMDP
    { 2896,	4,	1,	4,	191,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVNMSUBASP
    { 2895,	4,	1,	4,	194,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVNMSUBADP
    { 2894,	4,	1,	4,	191,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVNMADDMSP
    { 2893,	4,	1,	4,	194,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVNMADDMDP
    { 2892,	4,	1,	4,	191,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVNMADDASP
    { 2891,	4,	1,	4,	194,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVNMADDADP
    { 2890,	2,	1,	4,	268,	1,	0,	PPCOpInfoBase + 1228,	162,	0, 0x0ULL },  // XVNEGSP
    { 2889,	2,	1,	4,	523,	1,	0,	PPCOpInfoBase + 1228,	162,	0, 0x0ULL },  // XVNEGDP
    { 2888,	2,	1,	4,	268,	1,	0,	PPCOpInfoBase + 1228,	162,	0, 0x0ULL },  // XVNABSSP
    { 2887,	2,	1,	4,	523,	1,	0,	PPCOpInfoBase + 1228,	162,	0, 0x0ULL },  // XVNABSDP
    { 2886,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XVMULUWM
    { 2885,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVMULUHM
    { 2884,	3,	1,	4,	443,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVMULSP
    { 2883,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XVMULHUW
    { 2882,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVMULHUH
    { 2881,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XVMULHSW
    { 2880,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVMULHSH
    { 2879,	3,	1,	4,	442,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVMULDP
    { 2878,	4,	1,	4,	191,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVMSUBMSP
    { 2877,	4,	1,	4,	194,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVMSUBMDP
    { 2876,	4,	1,	4,	191,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVMSUBASP
    { 2875,	4,	1,	4,	194,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVMSUBADP
    { 2874,	3,	1,	4,	163,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVMINSP
    { 2873,	3,	1,	4,	163,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVMINDP
    { 2872,	3,	1,	4,	163,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVMAXSP
    { 2871,	3,	1,	4,	163,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVMAXDP
    { 2870,	4,	1,	4,	191,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVMADDMSP
    { 2869,	4,	1,	4,	194,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVMADDMDP
    { 2868,	4,	1,	4,	191,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVMADDASP
    { 2867,	4,	1,	4,	194,	1,	0,	PPCOpInfoBase + 1258,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVMADDADP
    { 2866,	3,	1,	4,	531,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XVIEXPSP
    { 2865,	3,	1,	4,	531,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XVIEXPDP
    { 2864,	4,	1,	4,	19,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI8GER4WSPP
    { 2863,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI8GER4WPP
    { 2862,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1237,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI8GER4W
    { 2861,	4,	1,	4,	570,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI8GER4SPP
    { 2860,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI8GER4PP
    { 2859,	3,	1,	4,	568,	0,	0,	PPCOpInfoBase + 1230,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI8GER4
    { 2858,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI4GER8WPP
    { 2857,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1237,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI4GER8W
    { 2856,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI4GER8PP
    { 2855,	3,	1,	4,	568,	0,	0,	PPCOpInfoBase + 1230,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI4GER8
    { 2854,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI16GER2WPP
    { 2853,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1237,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI16GER2W
    { 2852,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI16GER2SWPP
    { 2851,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1237,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI16GER2SW
    { 2850,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI16GER2SPP
    { 2849,	3,	1,	4,	568,	0,	0,	PPCOpInfoBase + 1230,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI16GER2S
    { 2848,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI16GER2PP
    { 2847,	3,	1,	4,	568,	0,	0,	PPCOpInfoBase + 1230,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVI16GER2
    { 2846,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1254,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF64GERWPP
    { 2845,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1254,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF64GERWPN
    { 2844,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1254,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF64GERWNP
    { 2843,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1254,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF64GERWNN
    { 2842,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF64GERW
    { 2841,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1247,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF64GERPP
    { 2840,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1247,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF64GERPN
    { 2839,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1247,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF64GERNP
    { 2838,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1247,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF64GERNN
    { 2837,	3,	1,	4,	568,	0,	0,	PPCOpInfoBase + 1244,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF64GER
    { 2836,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF32GERWPP
    { 2835,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF32GERWPN
    { 2834,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF32GERWNP
    { 2833,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF32GERWNN
    { 2832,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1237,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF32GERW
    { 2831,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF32GERPP
    { 2830,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF32GERPN
    { 2829,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF32GERNP
    { 2828,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF32GERNN
    { 2827,	3,	1,	4,	568,	0,	0,	PPCOpInfoBase + 1230,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF32GER
    { 2826,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF16GER2WPP
    { 2825,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF16GER2WPN
    { 2824,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF16GER2WNP
    { 2823,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF16GER2WNN
    { 2822,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1237,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF16GER2W
    { 2821,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF16GER2PP
    { 2820,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF16GER2PN
    { 2819,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF16GER2NP
    { 2818,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF16GER2NN
    { 2817,	3,	1,	4,	568,	0,	0,	PPCOpInfoBase + 1230,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVF16GER2
    { 2816,	3,	1,	4,	179,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVDIVSP
    { 2815,	3,	1,	4,	181,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVDIVDP
    { 2814,	2,	1,	4,	433,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVUXWSP
    { 2813,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0, 0x0ULL },  // XVCVUXWDP
    { 2812,	2,	1,	4,	433,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVUXDSP
    { 2811,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVUXDDP
    { 2810,	2,	1,	4,	433,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVSXWSP
    { 2809,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0, 0x0ULL },  // XVCVSXWDP
    { 2808,	2,	1,	4,	433,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVSXDSP
    { 2807,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVSXDDP
    { 2806,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVSPUXWS
    { 2805,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVSPUXDS
    { 2804,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVSPSXWS
    { 2803,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVSPSXDS
    { 2802,	2,	1,	4,	432,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVSPHP
    { 2801,	2,	1,	4,	195,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVSPDP
    { 2800,	2,	1,	4,	437,	0,	0,	PPCOpInfoBase + 1228,	0,	0, 0x0ULL },  // XVCVSPBF16
    { 2799,	2,	1,	4,	312,	0,	0,	PPCOpInfoBase + 1228,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVCVHPSP
    { 2798,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVDPUXWS
    { 2797,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVDPUXDS
    { 2796,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVDPSXWS
    { 2795,	2,	1,	4,	436,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVDPSXDS
    { 2794,	2,	1,	4,	433,	1,	0,	PPCOpInfoBase + 1228,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCVDPSP
    { 2793,	2,	1,	4,	587,	0,	0,	PPCOpInfoBase + 1228,	0,	0, 0x0ULL },  // XVCVBF16SPN
    { 2792,	3,	1,	4,	269,	1,	0,	PPCOpInfoBase + 1168,	162,	0, 0x0ULL },  // XVCPSGNSP
    { 2791,	3,	1,	4,	267,	1,	0,	PPCOpInfoBase + 1168,	162,	0, 0x0ULL },  // XVCPSGNDP
    { 2790,	3,	1,	4,	489,	1,	1,	PPCOpInfoBase + 1168,	239,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPGTSP_rec
    { 2789,	3,	1,	4,	489,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPGTSP
    { 2788,	3,	1,	4,	164,	1,	1,	PPCOpInfoBase + 1168,	239,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPGTDP_rec
    { 2787,	3,	1,	4,	164,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPGTDP
    { 2786,	3,	1,	4,	489,	1,	1,	PPCOpInfoBase + 1168,	239,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPGESP_rec
    { 2785,	3,	1,	4,	489,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPGESP
    { 2784,	3,	1,	4,	164,	1,	1,	PPCOpInfoBase + 1168,	239,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPGEDP_rec
    { 2783,	3,	1,	4,	164,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPGEDP
    { 2782,	3,	1,	4,	489,	1,	1,	PPCOpInfoBase + 1168,	239,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPEQSP_rec
    { 2781,	3,	1,	4,	489,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPEQSP
    { 2780,	3,	1,	4,	164,	1,	1,	PPCOpInfoBase + 1168,	239,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPEQDP_rec
    { 2779,	3,	1,	4,	164,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XVCMPEQDP
    { 2778,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVBF16GER2WPP
    { 2777,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVBF16GER2WPN
    { 2776,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVBF16GER2WNP
    { 2775,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVBF16GER2WNN
    { 2774,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 1237,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVBF16GER2W
    { 2773,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVBF16GER2PP
    { 2772,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVBF16GER2PN
    { 2771,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVBF16GER2NP
    { 2770,	4,	1,	4,	569,	0,	0,	PPCOpInfoBase + 1233,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVBF16GER2NN
    { 2769,	3,	1,	4,	568,	0,	0,	PPCOpInfoBase + 1230,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVBF16GER2
    { 2768,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0, 0x0ULL },  // XVADDUWM
    { 2767,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XVADDUHM
    { 2766,	3,	1,	4,	443,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVADDSP
    { 2765,	3,	1,	4,	442,	1,	0,	PPCOpInfoBase + 1168,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XVADDDP
    { 2764,	2,	1,	4,	268,	1,	0,	PPCOpInfoBase + 1228,	162,	0, 0x0ULL },  // XVABSSP
    { 2763,	2,	1,	4,	523,	1,	0,	PPCOpInfoBase + 1228,	162,	0, 0x0ULL },  // XVABSDP
    { 2762,	2,	1,	4,	466,	0,	0,	PPCOpInfoBase + 312,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSXSIGQP
    { 2761,	2,	1,	4,	279,	0,	0,	PPCOpInfoBase + 699,	0,	0, 0x0ULL },  // XSXSIGDP
    { 2760,	2,	1,	4,	522,	0,	0,	PPCOpInfoBase + 312,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSXEXPQP
    { 2759,	2,	1,	4,	295,	0,	0,	PPCOpInfoBase + 699,	0,	0, 0x0ULL },  // XSXEXPDP
    { 2758,	3,	1,	4,	277,	0,	0,	PPCOpInfoBase + 1225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSTSTDCSP
    { 2757,	3,	1,	4,	466,	0,	0,	PPCOpInfoBase + 1222,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSTSTDCQP
    { 2756,	3,	1,	4,	277,	0,	0,	PPCOpInfoBase + 1219,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSTSTDCDP
    { 2755,	2,	1,	4,	481,	1,	0,	PPCOpInfoBase + 1217,	162,	0, 0x0ULL },  // XSTSQRTDP
    { 2754,	3,	1,	4,	162,	1,	0,	PPCOpInfoBase + 1180,	162,	0, 0x0ULL },  // XSTDIVDP
    { 2753,	3,	1,	4,	189,	0,	0,	PPCOpInfoBase + 1174,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSSUBSP
    { 2752,	3,	1,	4,	329,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSSUBQPO
    { 2751,	3,	1,	4,	329,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSSUBQP
    { 2750,	3,	1,	4,	189,	1,	0,	PPCOpInfoBase + 1171,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSSUBDP
    { 2749,	2,	1,	4,	175,	0,	0,	PPCOpInfoBase + 1187,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSSQRTSP
    { 2748,	2,	1,	4,	334,	0,	0,	PPCOpInfoBase + 312,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSSQRTQPO
    { 2747,	2,	1,	4,	334,	0,	0,	PPCOpInfoBase + 312,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSSQRTQP
    { 2746,	2,	1,	4,	177,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSSQRTDP
    { 2745,	2,	1,	4,	190,	0,	0,	PPCOpInfoBase + 1187,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSRSQRTESP
    { 2744,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSRSQRTEDP
    { 2743,	2,	1,	4,	190,	0,	0,	PPCOpInfoBase + 1193,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSRSP
    { 2742,	4,	1,	4,	454,	0,	0,	PPCOpInfoBase + 1213,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSRQPXP
    { 2741,	4,	1,	4,	454,	0,	0,	PPCOpInfoBase + 1213,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSRQPIX
    { 2740,	4,	1,	4,	454,	0,	0,	PPCOpInfoBase + 1213,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSRQPI
    { 2739,	2,	1,	4,	190,	0,	0,	PPCOpInfoBase + 1187,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSRESP
    { 2738,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSREDP
    { 2737,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSREBASE3T3UQM
    { 2736,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSREBASE3T2UQM
    { 2735,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSREBASE3T1UQM
    { 2734,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSREBASE2T4UQM
    { 2733,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSREBASE2T3UQM
    { 2732,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSREBASE2T2UQM
    { 2731,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSREBASE2T1UQM
    { 2730,	2,	1,	4,	435,	0,	0,	PPCOpInfoBase + 1166,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSRDPIZ
    { 2729,	2,	1,	4,	435,	0,	0,	PPCOpInfoBase + 1166,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSRDPIP
    { 2728,	2,	1,	4,	435,	0,	0,	PPCOpInfoBase + 1166,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSRDPIM
    { 2727,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSRDPIC
    { 2726,	2,	1,	4,	435,	0,	0,	PPCOpInfoBase + 1166,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSRDPI
    { 2725,	4,	1,	4,	331,	0,	0,	PPCOpInfoBase + 1209,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSNMSUBQPO
    { 2724,	4,	1,	4,	331,	0,	0,	PPCOpInfoBase + 1209,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSNMSUBQP
    { 2723,	4,	1,	4,	320,	0,	0,	PPCOpInfoBase + 1205,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSNMSUBMSP
    { 2722,	4,	1,	4,	320,	1,	0,	PPCOpInfoBase + 1201,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSNMSUBMDP
    { 2721,	4,	1,	4,	320,	0,	0,	PPCOpInfoBase + 1205,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSNMSUBASP
    { 2720,	4,	1,	4,	320,	1,	0,	PPCOpInfoBase + 1201,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSNMSUBADP
    { 2719,	4,	1,	4,	331,	0,	0,	PPCOpInfoBase + 1209,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSNMADDQPO
    { 2718,	4,	1,	4,	331,	0,	0,	PPCOpInfoBase + 1209,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSNMADDQP
    { 2717,	4,	1,	4,	320,	0,	0,	PPCOpInfoBase + 1205,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSNMADDMSP
    { 2716,	4,	1,	4,	320,	1,	0,	PPCOpInfoBase + 1201,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSNMADDMDP
    { 2715,	4,	1,	4,	320,	0,	0,	PPCOpInfoBase + 1205,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSNMADDASP
    { 2714,	4,	1,	4,	320,	1,	0,	PPCOpInfoBase + 1201,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSNMADDADP
    { 2713,	2,	1,	4,	522,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // XSNEGQP
    { 2712,	2,	1,	4,	521,	1,	0,	PPCOpInfoBase + 1166,	162,	0, 0x0ULL },  // XSNEGDP
    { 2711,	2,	1,	4,	522,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // XSNABSQP
    { 2710,	2,	1,	4,	521,	1,	0,	PPCOpInfoBase + 1187,	162,	0, 0x0ULL },  // XSNABSDPs
    { 2709,	2,	1,	4,	521,	1,	0,	PPCOpInfoBase + 1166,	162,	0, 0x0ULL },  // XSNABSDP
    { 2708,	3,	1,	4,	441,	0,	0,	PPCOpInfoBase + 1174,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSMULSP
    { 2707,	3,	1,	4,	457,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSMULQPO
    { 2706,	3,	1,	4,	457,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSMULQP
    { 2705,	3,	1,	4,	441,	1,	0,	PPCOpInfoBase + 1171,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSMULDP
    { 2704,	4,	1,	4,	331,	0,	0,	PPCOpInfoBase + 1209,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSMSUBQPO
    { 2703,	4,	1,	4,	331,	0,	0,	PPCOpInfoBase + 1209,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSMSUBQP
    { 2702,	4,	1,	4,	320,	0,	0,	PPCOpInfoBase + 1205,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSMSUBMSP
    { 2701,	4,	1,	4,	320,	1,	0,	PPCOpInfoBase + 1201,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSMSUBMDP
    { 2700,	4,	1,	4,	320,	0,	0,	PPCOpInfoBase + 1205,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSMSUBASP
    { 2699,	4,	1,	4,	320,	1,	0,	PPCOpInfoBase + 1201,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSMSUBADP
    { 2698,	3,	1,	4,	494,	0,	0,	PPCOpInfoBase + 1177,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSMINJDP
    { 2697,	3,	1,	4,	161,	1,	0,	PPCOpInfoBase + 1171,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSMINDP
    { 2696,	3,	1,	4,	470,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // XSMINCQP
    { 2695,	3,	1,	4,	494,	0,	0,	PPCOpInfoBase + 1171,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSMINCDP
    { 2694,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSMERGE3T1UQM
    { 2693,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSMERGE2T3UQM
    { 2692,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSMERGE2T2UQM
    { 2691,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSMERGE2T1UQM
    { 2690,	3,	1,	4,	494,	0,	0,	PPCOpInfoBase + 1177,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSMAXJDP
    { 2689,	3,	1,	4,	161,	1,	0,	PPCOpInfoBase + 1171,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSMAXDP
    { 2688,	3,	1,	4,	470,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // XSMAXCQP
    { 2687,	3,	1,	4,	494,	0,	0,	PPCOpInfoBase + 1171,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSMAXCDP
    { 2686,	4,	1,	4,	331,	0,	0,	PPCOpInfoBase + 1209,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSMADDQPO
    { 2685,	4,	1,	4,	331,	0,	0,	PPCOpInfoBase + 1209,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSMADDQP
    { 2684,	4,	1,	4,	320,	0,	0,	PPCOpInfoBase + 1205,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSMADDMSP
    { 2683,	4,	1,	4,	320,	1,	0,	PPCOpInfoBase + 1201,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSMADDMDP
    { 2682,	4,	1,	4,	320,	0,	0,	PPCOpInfoBase + 1205,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSMADDASP
    { 2681,	4,	1,	4,	320,	1,	0,	PPCOpInfoBase + 1201,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSMADDADP
    { 2680,	3,	1,	4,	531,	0,	0,	PPCOpInfoBase + 1198,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSIEXPQP
    { 2679,	3,	1,	4,	305,	0,	0,	PPCOpInfoBase + 1195,	0,	0, 0x0ULL },  // XSIEXPDP
    { 2678,	3,	1,	4,	185,	0,	0,	PPCOpInfoBase + 1174,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSDIVSP
    { 2677,	3,	1,	4,	333,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSDIVQPO
    { 2676,	3,	1,	4,	333,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSDIVQP
    { 2675,	3,	1,	4,	174,	1,	0,	PPCOpInfoBase + 1171,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSDIVDP
    { 2674,	2,	1,	4,	190,	0,	0,	PPCOpInfoBase + 1193,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVUXDSP
    { 2673,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVUXDDP
    { 2672,	2,	1,	4,	455,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // XSCVUQQP
    { 2671,	2,	1,	4,	454,	0,	0,	PPCOpInfoBase + 1183,	0,	0, 0x0ULL },  // XSCVUDQP
    { 2670,	2,	1,	4,	190,	0,	0,	PPCOpInfoBase + 1193,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVSXDSP
    { 2669,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVSXDDP
    { 2668,	2,	1,	4,	455,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // XSCVSQQP
    { 2667,	2,	1,	4,	284,	0,	0,	PPCOpInfoBase + 1191,	0,	0, 0x0ULL },  // XSCVSPDPN
    { 2666,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVSPDP
    { 2665,	2,	1,	4,	454,	0,	0,	PPCOpInfoBase + 1183,	0,	0, 0x0ULL },  // XSCVSDQP
    { 2664,	2,	1,	4,	454,	0,	0,	PPCOpInfoBase + 312,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVQPUWZ
    { 2663,	2,	1,	4,	455,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // XSCVQPUQZ
    { 2662,	2,	1,	4,	454,	0,	0,	PPCOpInfoBase + 312,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVQPUDZ
    { 2661,	2,	1,	4,	454,	0,	0,	PPCOpInfoBase + 312,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVQPSWZ
    { 2660,	2,	1,	4,	455,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // XSCVQPSQZ
    { 2659,	2,	1,	4,	454,	0,	0,	PPCOpInfoBase + 312,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVQPSDZ
    { 2658,	2,	1,	4,	454,	0,	0,	PPCOpInfoBase + 1189,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVQPDPO
    { 2657,	2,	1,	4,	454,	0,	0,	PPCOpInfoBase + 1189,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVQPDP
    { 2656,	2,	1,	4,	323,	0,	0,	PPCOpInfoBase + 1166,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSCVHPDP
    { 2655,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1187,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVDPUXWSs
    { 2654,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVDPUXWS
    { 2653,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1187,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVDPUXDSs
    { 2652,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVDPUXDS
    { 2651,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1187,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVDPSXWSs
    { 2650,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVDPSXWS
    { 2649,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1187,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVDPSXDSs
    { 2648,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVDPSXDS
    { 2647,	2,	1,	4,	190,	0,	0,	PPCOpInfoBase + 1185,	0,	0, 0x0ULL },  // XSCVDPSPN
    { 2646,	2,	1,	4,	435,	1,	0,	PPCOpInfoBase + 1166,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVDPSP
    { 2645,	2,	1,	4,	454,	0,	0,	PPCOpInfoBase + 1183,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCVDPQP
    { 2644,	2,	1,	4,	434,	0,	0,	PPCOpInfoBase + 1166,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSCVDPHP
    { 2643,	3,	1,	4,	531,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // XSCPSGNQP
    { 2642,	3,	1,	4,	294,	1,	0,	PPCOpInfoBase + 1171,	162,	0, 0x0ULL },  // XSCPSGNDP
    { 2641,	3,	1,	4,	328,	0,	0,	PPCOpInfoBase + 1116,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSCMPUQP
    { 2640,	3,	1,	4,	162,	1,	0,	PPCOpInfoBase + 1180,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCMPUDP
    { 2639,	3,	1,	4,	328,	0,	0,	PPCOpInfoBase + 1116,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSCMPOQP
    { 2638,	3,	1,	4,	162,	1,	0,	PPCOpInfoBase + 1180,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // XSCMPODP
    { 2637,	3,	1,	4,	470,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // XSCMPGTQP
    { 2636,	3,	1,	4,	280,	0,	0,	PPCOpInfoBase + 1177,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSCMPGTDP
    { 2635,	3,	1,	4,	470,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // XSCMPGEQP
    { 2634,	3,	1,	4,	280,	0,	0,	PPCOpInfoBase + 1177,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSCMPGEDP
    { 2633,	3,	1,	4,	328,	0,	0,	PPCOpInfoBase + 1116,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSCMPEXPQP
    { 2632,	3,	1,	4,	280,	0,	0,	PPCOpInfoBase + 1180,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSCMPEXPDP
    { 2631,	3,	1,	4,	470,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // XSCMPEQQP
    { 2630,	3,	1,	4,	280,	0,	0,	PPCOpInfoBase + 1177,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSCMPEQDP
    { 2629,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSADDSUBUQM
    { 2628,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSADDSUBSUQM
    { 2627,	3,	1,	4,	189,	0,	0,	PPCOpInfoBase + 1174,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSADDSP
    { 2626,	3,	1,	4,	329,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSADDQPO
    { 2625,	3,	1,	4,	329,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSADDQP
    { 2624,	3,	1,	4,	189,	1,	0,	PPCOpInfoBase + 1171,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // XSADDDP
    { 2623,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSADDADDUQM
    { 2622,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSADDADDSUQM
    { 2621,	2,	1,	4,	522,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // XSABSQP
    { 2620,	2,	1,	4,	521,	1,	0,	PPCOpInfoBase + 1166,	162,	0, 0x0ULL },  // XSABSDP
    { 2619,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // XOR_rec
    { 2618,	3,	1,	4,	512,	0,	0,	PPCOpInfoBase + 180,	0,	0, 0x8ULL },  // XORIS8
    { 2617,	3,	1,	4,	512,	0,	0,	PPCOpInfoBase + 183,	0,	0, 0x8ULL },  // XORIS
    { 2616,	3,	1,	4,	512,	0,	0,	PPCOpInfoBase + 180,	0,	0, 0x8ULL },  // XORI8
    { 2615,	3,	1,	4,	512,	0,	0,	PPCOpInfoBase + 183,	0,	0, 0x8ULL },  // XORI
    { 2614,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // XOR8_rec
    { 2613,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // XOR8
    { 2612,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // XOR
    { 2611,	1,	0,	4,	423,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRTEEI
    { 2610,	1,	0,	4,	423,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRTEE
    { 2609,	2,	0,	4,	500,	0,	0,	PPCOpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WAITP10
    { 2608,	1,	0,	4,	298,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WAIT
    { 2607,	1,	1,	4,	579,	0,	0,	PPCOpInfoBase + 698,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x28ULL },  // V_SETALLONESH
    { 2606,	1,	1,	4,	579,	0,	0,	PPCOpInfoBase + 698,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x28ULL },  // V_SETALLONESB
    { 2605,	1,	1,	4,	579,	0,	0,	PPCOpInfoBase + 698,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x28ULL },  // V_SETALLONES
    { 2604,	1,	1,	4,	531,	0,	0,	PPCOpInfoBase + 698,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x28ULL },  // V_SET0H
    { 2603,	1,	1,	4,	531,	0,	0,	PPCOpInfoBase + 698,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x28ULL },  // V_SET0B
    { 2602,	1,	1,	4,	531,	0,	0,	PPCOpInfoBase + 698,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x28ULL },  // V_SET0
    { 2601,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VXOR
    { 2600,	2,	1,	4,	583,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VUPKLSW
    { 2599,	2,	1,	4,	0,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VUPKLSNTOB
    { 2598,	2,	1,	4,	586,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VUPKLSH
    { 2597,	2,	1,	4,	586,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VUPKLSB
    { 2596,	2,	1,	4,	586,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VUPKLPX
    { 2595,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 306,	0,	0, 0x0ULL },  // VUPKINT8TOFP32
    { 2594,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 306,	0,	0, 0x0ULL },  // VUPKINT8TOBF16
    { 2593,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 306,	0,	0, 0x0ULL },  // VUPKINT4TOFP32
    { 2592,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 306,	0,	0, 0x0ULL },  // VUPKINT4TOBF16
    { 2591,	2,	1,	4,	583,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VUPKHSW
    { 2590,	2,	1,	4,	0,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VUPKHSNTOB
    { 2589,	2,	1,	4,	586,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VUPKHSH
    { 2588,	2,	1,	4,	586,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VUPKHSB
    { 2587,	2,	1,	4,	586,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VUPKHPX
    { 2586,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VUCMPRLN
    { 2585,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VUCMPRLH
    { 2584,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VUCMPRLB
    { 2583,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VUCMPRHN
    { 2582,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VUCMPRHH
    { 2581,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VUCMPRHB
    { 2580,	3,	1,	4,	594,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VSUMSWS
    { 2579,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VSUM4UBS
    { 2578,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VSUM4SHS
    { 2577,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VSUM4SBS
    { 2576,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VSUM2SWS
    { 2575,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBUWS
    { 2574,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBUWM
    { 2573,	3,	1,	4,	240,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VSUBUQM
    { 2572,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBUHS
    { 2571,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBUHM
    { 2570,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VSUBUDM
    { 2569,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBUBS
    { 2568,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBUBM
    { 2567,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBSWS
    { 2566,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBSHS
    { 2565,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBSBS
    { 2564,	3,	1,	4,	193,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBFP
    { 2563,	4,	1,	4,	239,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x0ULL },  // VSUBEUQM
    { 2562,	4,	1,	4,	239,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x0ULL },  // VSUBECUQ
    { 2561,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSUBCUW
    { 2560,	3,	1,	4,	469,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VSUBCUQ
    { 2559,	2,	1,	4,	543,	0,	1,	PPCOpInfoBase + 312,	88,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VSTRIHR_rec
    { 2558,	2,	1,	4,	585,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VSTRIHR
    { 2557,	2,	1,	4,	543,	0,	1,	PPCOpInfoBase + 312,	88,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VSTRIHL_rec
    { 2556,	2,	1,	4,	585,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VSTRIHL
    { 2555,	2,	1,	4,	543,	0,	1,	PPCOpInfoBase + 312,	88,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VSTRIBR_rec
    { 2554,	2,	1,	4,	585,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VSTRIBR
    { 2553,	2,	1,	4,	543,	0,	1,	PPCOpInfoBase + 312,	88,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VSTRIBL_rec
    { 2552,	2,	1,	4,	585,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VSTRIBL
    { 2551,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSRW
    { 2550,	3,	1,	4,	592,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VSRV
    { 2549,	3,	1,	4,	497,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VSRQ
    { 2548,	3,	1,	4,	232,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSRO
    { 2547,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSRH
    { 2546,	4,	1,	4,	590,	0,	0,	PPCOpInfoBase + 302,	0,	0, 0x0ULL },  // VSRDBI
    { 2545,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VSRD
    { 2544,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSRB
    { 2543,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSRAW
    { 2542,	3,	1,	4,	497,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VSRAQ
    { 2541,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSRAH
    { 2540,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VSRAD
    { 2539,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSRAB
    { 2538,	3,	1,	4,	232,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSR
    { 2537,	3,	1,	4,	584,	0,	0,	PPCOpInfoBase + 1108,	0,	0, 0x28ULL },  // VSPLTW
    { 2536,	2,	1,	4,	578,	0,	0,	PPCOpInfoBase + 728,	0,	0, 0x28ULL },  // VSPLTISW
    { 2535,	2,	1,	4,	578,	0,	0,	PPCOpInfoBase + 728,	0,	0, 0x28ULL },  // VSPLTISH
    { 2534,	2,	1,	4,	578,	0,	0,	PPCOpInfoBase + 728,	0,	0, 0x28ULL },  // VSPLTISB
    { 2533,	3,	1,	4,	584,	0,	0,	PPCOpInfoBase + 1163,	0,	0, 0x28ULL },  // VSPLTHs
    { 2532,	3,	1,	4,	584,	0,	0,	PPCOpInfoBase + 1108,	0,	0, 0x28ULL },  // VSPLTH
    { 2531,	3,	1,	4,	584,	0,	0,	PPCOpInfoBase + 1163,	0,	0, 0x28ULL },  // VSPLTBs
    { 2530,	3,	1,	4,	584,	0,	0,	PPCOpInfoBase + 1108,	0,	0, 0x28ULL },  // VSPLTB
    { 2529,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSLW
    { 2528,	3,	1,	4,	592,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VSLV
    { 2527,	3,	1,	4,	497,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VSLQ
    { 2526,	3,	1,	4,	232,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSLO
    { 2525,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSLH
    { 2524,	4,	1,	4,	232,	0,	0,	PPCOpInfoBase + 302,	0,	0, 0x28ULL },  // VSLDOI
    { 2523,	4,	1,	4,	590,	0,	0,	PPCOpInfoBase + 302,	0,	0, 0x0ULL },  // VSLDBI
    { 2522,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VSLD
    { 2521,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSLB
    { 2520,	3,	1,	4,	232,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VSL
    { 2519,	4,	1,	4,	480,	0,	0,	PPCOpInfoBase + 1159,	0,	0, 0x0ULL },  // VSHASIGMAW
    { 2518,	4,	1,	4,	480,	0,	0,	PPCOpInfoBase + 1159,	0,	0, 0x0ULL },  // VSHASIGMAD
    { 2517,	4,	1,	4,	271,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x28ULL },  // VSEL
    { 2516,	2,	1,	4,	451,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VSBOX
    { 2515,	2,	1,	4,	433,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VRSQRTEFP
    { 2514,	3,	1,	4,	531,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VRLWNM
    { 2513,	4,	1,	4,	265,	0,	0,	PPCOpInfoBase + 1155,	0,	0, 0x0ULL },  // VRLWMI
    { 2512,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VRLW
    { 2511,	3,	1,	4,	497,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VRLQNM
    { 2510,	4,	1,	4,	498,	0,	0,	PPCOpInfoBase + 1155,	0,	0, 0x0ULL },  // VRLQMI
    { 2509,	3,	1,	4,	497,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VRLQ
    { 2508,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VRLH
    { 2507,	3,	1,	4,	531,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VRLDNM
    { 2506,	4,	1,	4,	265,	0,	0,	PPCOpInfoBase + 1155,	0,	0, 0x0ULL },  // VRLDMI
    { 2505,	3,	1,	4,	266,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VRLD
    { 2504,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VRLB
    { 2503,	2,	1,	4,	433,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VRFIZ
    { 2502,	2,	1,	4,	433,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VRFIP
    { 2501,	2,	1,	4,	433,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VRFIN
    { 2500,	2,	1,	4,	433,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VRFIM
    { 2499,	2,	1,	4,	433,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VREFP
    { 2498,	2,	1,	4,	478,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VPRTYBW
    { 2497,	2,	1,	4,	582,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VPRTYBQ
    { 2496,	2,	1,	4,	478,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VPRTYBD
    { 2495,	2,	1,	4,	234,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VPOPCNTW
    { 2494,	2,	1,	4,	479,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VPOPCNTH
    { 2493,	2,	1,	4,	311,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VPOPCNTD
    { 2492,	2,	1,	4,	479,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VPOPCNTB
    { 2491,	3,	1,	4,	184,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VPMSUMW
    { 2490,	3,	1,	4,	184,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VPMSUMH
    { 2489,	3,	1,	4,	184,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VPMSUMD
    { 2488,	3,	1,	4,	184,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VPMSUMB
    { 2487,	3,	1,	4,	591,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VPKUWUS
    { 2486,	3,	1,	4,	591,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VPKUWUM
    { 2485,	3,	1,	4,	591,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VPKUHUS
    { 2484,	3,	1,	4,	591,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VPKUHUM
    { 2483,	3,	1,	4,	589,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VPKUDUS
    { 2482,	3,	1,	4,	589,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VPKUDUM
    { 2481,	3,	1,	4,	591,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VPKSWUS
    { 2480,	3,	1,	4,	591,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VPKSWSS
    { 2479,	3,	1,	4,	591,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VPKSHUS
    { 2478,	3,	1,	4,	591,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VPKSHSS
    { 2477,	3,	1,	4,	589,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VPKSDUS
    { 2476,	3,	1,	4,	589,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VPKSDSS
    { 2475,	3,	1,	4,	591,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VPKPX
    { 2474,	3,	1,	4,	453,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VPEXTD
    { 2473,	4,	1,	4,	231,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x0ULL },  // VPERMXOR
    { 2472,	4,	1,	4,	325,	0,	0,	PPCOpInfoBase + 1104,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VPERMR
    { 2471,	4,	1,	4,	166,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x28ULL },  // VPERM
    { 2470,	3,	1,	4,	453,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VPDEPD
    { 2469,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VORC
    { 2468,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VOR
    { 2467,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VNOR
    { 2466,	4,	1,	4,	444,	0,	0,	PPCOpInfoBase + 1104,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VNMSUBFP
    { 2465,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VNEGW
    { 2464,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VNEGD
    { 2463,	3,	1,	4,	184,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VNCIPHERLAST
    { 2462,	3,	1,	4,	184,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VNCIPHER
    { 2461,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VNAND
    { 2460,	3,	1,	4,	243,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMULUWM
    { 2459,	3,	1,	4,	242,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMULOUW
    { 2458,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMULOUH
    { 2457,	3,	1,	4,	628,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMULOUD
    { 2456,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMULOUB
    { 2455,	3,	1,	4,	242,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMULOSW
    { 2454,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMULOSH
    { 2453,	3,	1,	4,	628,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMULOSD
    { 2452,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMULOSB
    { 2451,	3,	1,	4,	576,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMULLD
    { 2450,	3,	1,	4,	628,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMULHUW
    { 2449,	3,	1,	4,	576,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMULHUD
    { 2448,	3,	1,	4,	628,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMULHSW
    { 2447,	3,	1,	4,	576,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMULHSD
    { 2446,	3,	1,	4,	242,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMULEUW
    { 2445,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMULEUH
    { 2444,	3,	1,	4,	628,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMULEUD
    { 2443,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMULEUB
    { 2442,	3,	1,	4,	242,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMULESW
    { 2441,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMULESH
    { 2440,	3,	1,	4,	628,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMULESD
    { 2439,	3,	1,	4,	627,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMULESB
    { 2438,	2,	1,	4,	466,	0,	0,	PPCOpInfoBase + 312,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VMUL10UQ
    { 2437,	3,	1,	4,	468,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VMUL10EUQ
    { 2436,	3,	1,	4,	468,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VMUL10ECUQ
    { 2435,	2,	1,	4,	466,	0,	0,	PPCOpInfoBase + 312,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VMUL10CUQ
    { 2434,	4,	1,	4,	241,	0,	0,	PPCOpInfoBase + 1104,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VMSUMUHS
    { 2433,	4,	1,	4,	241,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x28ULL },  // VMSUMUHM
    { 2432,	4,	1,	4,	168,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x0ULL },  // VMSUMUDM
    { 2431,	4,	1,	4,	241,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x28ULL },  // VMSUMUBM
    { 2430,	4,	1,	4,	241,	0,	0,	PPCOpInfoBase + 1104,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VMSUMSHS
    { 2429,	4,	1,	4,	241,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x28ULL },  // VMSUMSHM
    { 2428,	4,	1,	4,	241,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x28ULL },  // VMSUMMBM
    { 2427,	4,	1,	4,	629,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x0ULL },  // VMSUMCUD
    { 2426,	3,	1,	4,	270,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMRGOW
    { 2425,	3,	1,	4,	232,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VMRGLW
    { 2424,	3,	1,	4,	232,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VMRGLH
    { 2423,	3,	1,	4,	232,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VMRGLB
    { 2422,	3,	1,	4,	232,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VMRGHW
    { 2421,	3,	1,	4,	232,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VMRGHH
    { 2420,	3,	1,	4,	232,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VMRGHB
    { 2419,	3,	1,	4,	270,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMRGEW
    { 2418,	3,	1,	4,	463,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMODUW
    { 2417,	3,	1,	4,	459,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMODUQ
    { 2416,	3,	1,	4,	461,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMODUD
    { 2415,	3,	1,	4,	463,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMODSW
    { 2414,	3,	1,	4,	459,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMODSQ
    { 2413,	3,	1,	4,	461,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VMODSD
    { 2412,	4,	1,	4,	241,	0,	0,	PPCOpInfoBase + 1104,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMLADDUHM
    { 2411,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMINUW
    { 2410,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMINUH
    { 2409,	3,	1,	4,	235,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMINUD
    { 2408,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMINUB
    { 2407,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMINSW
    { 2406,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMINSH
    { 2405,	3,	1,	4,	235,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMINSD
    { 2404,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMINSB
    { 2403,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMINFP
    { 2402,	4,	1,	4,	241,	0,	0,	PPCOpInfoBase + 1104,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VMHRADDSHS
    { 2401,	4,	1,	4,	241,	0,	0,	PPCOpInfoBase + 1104,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x28ULL },  // VMHADDSHS
    { 2400,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMAXUW
    { 2399,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMAXUH
    { 2398,	3,	1,	4,	235,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAXUD
    { 2397,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMAXUB
    { 2396,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMAXSW
    { 2395,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMAXSH
    { 2394,	3,	1,	4,	235,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAXSD
    { 2393,	3,	1,	4,	233,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMAXSB
    { 2392,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMAXFP
    { 2391,	4,	1,	4,	444,	0,	0,	PPCOpInfoBase + 1104,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VMADDFP
    { 2390,	2,	1,	4,	433,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VLOGEFP
    { 2389,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1135,	0,	0, 0x0ULL },  // VINSWVRX
    { 2388,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1135,	0,	0, 0x0ULL },  // VINSWVLX
    { 2387,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1131,	0,	0, 0x0ULL },  // VINSWRX
    { 2386,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1131,	0,	0, 0x0ULL },  // VINSWLX
    { 2385,	4,	1,	4,	590,	0,	0,	PPCOpInfoBase + 1151,	0,	0, 0x0ULL },  // VINSW
    { 2384,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1135,	0,	0, 0x0ULL },  // VINSHVRX
    { 2383,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1135,	0,	0, 0x0ULL },  // VINSHVLX
    { 2382,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1131,	0,	0, 0x0ULL },  // VINSHRX
    { 2381,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1131,	0,	0, 0x0ULL },  // VINSHLX
    { 2380,	3,	1,	4,	582,	0,	0,	PPCOpInfoBase + 1108,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VINSERTW
    { 2379,	4,	1,	4,	326,	0,	0,	PPCOpInfoBase + 1147,	0,	0, 0x0ULL },  // VINSERTH
    { 2378,	3,	1,	4,	582,	0,	0,	PPCOpInfoBase + 1108,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VINSERTD
    { 2377,	4,	1,	4,	326,	0,	0,	PPCOpInfoBase + 1147,	0,	0, 0x0ULL },  // VINSERTB
    { 2376,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1143,	0,	0, 0x0ULL },  // VINSDRX
    { 2375,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1143,	0,	0, 0x0ULL },  // VINSDLX
    { 2374,	4,	1,	4,	590,	0,	0,	PPCOpInfoBase + 1139,	0,	0, 0x0ULL },  // VINSD
    { 2373,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1135,	0,	0, 0x0ULL },  // VINSBVRX
    { 2372,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1135,	0,	0, 0x0ULL },  // VINSBVLX
    { 2371,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1131,	0,	0, 0x0ULL },  // VINSBRX
    { 2370,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1131,	0,	0, 0x0ULL },  // VINSBLX
    { 2369,	3,	1,	4,	450,	0,	0,	PPCOpInfoBase + 1119,	0,	0, 0x0ULL },  // VGNB
    { 2368,	2,	1,	4,	583,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VGBBD
    { 2367,	3,	1,	4,	326,	0,	0,	PPCOpInfoBase + 1128,	0,	0, 0x200ULL },  // VEXTUWRX
    { 2366,	3,	1,	4,	326,	0,	0,	PPCOpInfoBase + 1128,	0,	0, 0x200ULL },  // VEXTUWLX
    { 2365,	3,	1,	4,	326,	0,	0,	PPCOpInfoBase + 1128,	0,	0, 0x200ULL },  // VEXTUHRX
    { 2364,	3,	1,	4,	326,	0,	0,	PPCOpInfoBase + 1128,	0,	0, 0x200ULL },  // VEXTUHLX
    { 2363,	3,	1,	4,	326,	0,	0,	PPCOpInfoBase + 1128,	0,	0, 0x200ULL },  // VEXTUBRX
    { 2362,	3,	1,	4,	326,	0,	0,	PPCOpInfoBase + 1128,	0,	0, 0x200ULL },  // VEXTUBLX
    { 2361,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 1126,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VEXTSW2Ds
    { 2360,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXTSW2D
    { 2359,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 1126,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VEXTSH2Ws
    { 2358,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXTSH2W
    { 2357,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 1126,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VEXTSH2Ds
    { 2356,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXTSH2D
    { 2355,	2,	1,	4,	520,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXTSD2Q
    { 2354,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 1126,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VEXTSB2Ws
    { 2353,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXTSB2W
    { 2352,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 1126,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VEXTSB2Ds
    { 2351,	2,	1,	4,	519,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXTSB2D
    { 2350,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 1114,	0,	0, 0x200ULL },  // VEXTRACTWM
    { 2349,	3,	1,	4,	582,	0,	0,	PPCOpInfoBase + 1108,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VEXTRACTUW
    { 2348,	3,	1,	4,	582,	0,	0,	PPCOpInfoBase + 1108,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VEXTRACTUH
    { 2347,	3,	1,	4,	582,	0,	0,	PPCOpInfoBase + 1108,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VEXTRACTUB
    { 2346,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 1114,	0,	0, 0x0ULL },  // VEXTRACTQM
    { 2345,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 1114,	0,	0, 0x200ULL },  // VEXTRACTHM
    { 2344,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 1114,	0,	0, 0x200ULL },  // VEXTRACTDM
    { 2343,	3,	1,	4,	582,	0,	0,	PPCOpInfoBase + 1108,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VEXTRACTD
    { 2342,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 1114,	0,	0, 0x200ULL },  // VEXTRACTBM
    { 2341,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1122,	0,	0, 0x0ULL },  // VEXTDUWVRX
    { 2340,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1122,	0,	0, 0x0ULL },  // VEXTDUWVLX
    { 2339,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1122,	0,	0, 0x0ULL },  // VEXTDUHVRX
    { 2338,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1122,	0,	0, 0x0ULL },  // VEXTDUHVLX
    { 2337,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1122,	0,	0, 0x0ULL },  // VEXTDUBVRX
    { 2336,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1122,	0,	0, 0x0ULL },  // VEXTDUBVLX
    { 2335,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1122,	0,	0, 0x0ULL },  // VEXTDDVRX
    { 2334,	4,	1,	4,	593,	0,	0,	PPCOpInfoBase + 1122,	0,	0, 0x0ULL },  // VEXTDDVLX
    { 2333,	2,	1,	4,	192,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VEXPTEFP
    { 2332,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXPANDWM
    { 2331,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXPANDQM
    { 2330,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXPANDHM
    { 2329,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXPANDDM
    { 2328,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VEXPANDBM
    { 2327,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VEQV
    { 2326,	3,	1,	4,	462,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVUW
    { 2325,	3,	1,	4,	458,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVUQ
    { 2324,	3,	1,	4,	460,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVUD
    { 2323,	3,	1,	4,	462,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVSW
    { 2322,	3,	1,	4,	458,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVSQ
    { 2321,	3,	1,	4,	460,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVSD
    { 2320,	3,	1,	4,	465,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVEUW
    { 2319,	3,	1,	4,	458,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVEUQ
    { 2318,	3,	1,	4,	464,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVEUD
    { 2317,	3,	1,	4,	465,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVESW
    { 2316,	3,	1,	4,	458,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVESQ
    { 2315,	3,	1,	4,	464,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VDIVESD
    { 2314,	2,	1,	4,	478,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VCTZW
    { 2313,	2,	1,	4,	582,	0,	0,	PPCOpInfoBase + 1114,	0,	0, 0x0ULL },  // VCTZLSBB
    { 2312,	2,	1,	4,	478,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VCTZH
    { 2311,	3,	1,	4,	453,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VCTZDM
    { 2310,	2,	1,	4,	478,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VCTZD
    { 2309,	2,	1,	4,	478,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VCTZB
    { 2308,	2,	1,	4,	432,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VCTUXS_0
    { 2307,	3,	1,	4,	431,	0,	0,	PPCOpInfoBase + 1108,	0,	0, 0x28ULL },  // VCTUXS
    { 2306,	2,	1,	4,	432,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VCTSXS_0
    { 2305,	3,	1,	4,	431,	0,	0,	PPCOpInfoBase + 1108,	0,	0, 0x28ULL },  // VCTSXS
    { 2304,	3,	1,	4,	474,	0,	0,	PPCOpInfoBase + 1119,	0,	0, 0x0ULL },  // VCNTMBW
    { 2303,	3,	1,	4,	474,	0,	0,	PPCOpInfoBase + 1119,	0,	0, 0x0ULL },  // VCNTMBH
    { 2302,	3,	1,	4,	474,	0,	0,	PPCOpInfoBase + 1119,	0,	0, 0x0ULL },  // VCNTMBD
    { 2301,	3,	1,	4,	474,	0,	0,	PPCOpInfoBase + 1119,	0,	0, 0x0ULL },  // VCNTMBB
    { 2300,	3,	1,	4,	493,	0,	0,	PPCOpInfoBase + 1116,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VCMPUQ
    { 2299,	3,	1,	4,	493,	0,	0,	PPCOpInfoBase + 1116,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VCMPSQ
    { 2298,	3,	1,	4,	492,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPNEZW_rec
    { 2297,	3,	1,	4,	308,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPNEZW
    { 2296,	3,	1,	4,	492,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPNEZH_rec
    { 2295,	3,	1,	4,	308,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPNEZH
    { 2294,	3,	1,	4,	492,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPNEZB_rec
    { 2293,	3,	1,	4,	308,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPNEZB
    { 2292,	3,	1,	4,	492,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPNEW_rec
    { 2291,	3,	1,	4,	308,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPNEW
    { 2290,	3,	1,	4,	492,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPNEH_rec
    { 2289,	3,	1,	4,	308,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPNEH
    { 2288,	3,	1,	4,	492,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPNEB_rec
    { 2287,	3,	1,	4,	308,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPNEB
    { 2286,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTUW_rec
    { 2285,	3,	1,	4,	171,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTUW
    { 2284,	3,	1,	4,	491,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTUQ_rec
    { 2283,	3,	1,	4,	491,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTUQ
    { 2282,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTUH_rec
    { 2281,	3,	1,	4,	171,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTUH
    { 2280,	3,	1,	4,	490,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTUD_rec
    { 2279,	3,	1,	4,	236,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTUD
    { 2278,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTUB_rec
    { 2277,	3,	1,	4,	171,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTUB
    { 2276,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTSW_rec
    { 2275,	3,	1,	4,	171,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTSW
    { 2274,	3,	1,	4,	491,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTSQ_rec
    { 2273,	3,	1,	4,	491,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTSQ
    { 2272,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTSH_rec
    { 2271,	3,	1,	4,	171,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTSH
    { 2270,	3,	1,	4,	490,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTSD_rec
    { 2269,	3,	1,	4,	236,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTSD
    { 2268,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTSB_rec
    { 2267,	3,	1,	4,	171,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTSB
    { 2266,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGTFP_rec
    { 2265,	3,	1,	4,	489,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGTFP
    { 2264,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPGEFP_rec
    { 2263,	3,	1,	4,	489,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPGEFP
    { 2262,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPEQUW_rec
    { 2261,	3,	1,	4,	171,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPEQUW
    { 2260,	3,	1,	4,	491,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPEQUQ_rec
    { 2259,	3,	1,	4,	491,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPEQUQ
    { 2258,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPEQUH_rec
    { 2257,	3,	1,	4,	171,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPEQUH
    { 2256,	3,	1,	4,	490,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPEQUD_rec
    { 2255,	3,	1,	4,	236,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPEQUD
    { 2254,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPEQUB_rec
    { 2253,	3,	1,	4,	171,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPEQUB
    { 2252,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPEQFP_rec
    { 2251,	3,	1,	4,	489,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPEQFP
    { 2250,	3,	1,	4,	489,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x28ULL },  // VCMPBFP_rec
    { 2249,	3,	1,	4,	489,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VCMPBFP
    { 2248,	2,	1,	4,	234,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VCLZW
    { 2247,	2,	1,	4,	582,	0,	0,	PPCOpInfoBase + 1114,	0,	0, 0x0ULL },  // VCLZLSBB
    { 2246,	2,	1,	4,	234,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VCLZH
    { 2245,	3,	1,	4,	453,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VCLZDM
    { 2244,	2,	1,	4,	234,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VCLZD
    { 2243,	2,	1,	4,	234,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x0ULL },  // VCLZB
    { 2242,	3,	1,	4,	590,	0,	0,	PPCOpInfoBase + 1111,	0,	0, 0x0ULL },  // VCLRRB
    { 2241,	3,	1,	4,	590,	0,	0,	PPCOpInfoBase + 1111,	0,	0, 0x0ULL },  // VCLRLB
    { 2240,	3,	1,	4,	184,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VCIPHERLAST
    { 2239,	3,	1,	4,	184,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VCIPHER
    { 2238,	2,	1,	4,	432,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VCFUX_0
    { 2237,	3,	1,	4,	431,	0,	0,	PPCOpInfoBase + 1108,	0,	0, 0x28ULL },  // VCFUX
    { 2236,	3,	1,	4,	453,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VCFUGED
    { 2235,	2,	1,	4,	432,	0,	0,	PPCOpInfoBase + 312,	0,	0, 0x28ULL },  // VCFSX_0
    { 2234,	3,	1,	4,	431,	0,	0,	PPCOpInfoBase + 1108,	0,	0, 0x28ULL },  // VCFSX
    { 2233,	3,	1,	4,	589,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VBPERMQ
    { 2232,	3,	1,	4,	310,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VBPERMD
    { 2231,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VAVGUW
    { 2230,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VAVGUH
    { 2229,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VAVGUB
    { 2228,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VAVGSW
    { 2227,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VAVGSH
    { 2226,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VAVGSB
    { 2225,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x28ULL },  // VANDC
    { 2224,	3,	1,	4,	263,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VAND
    { 2223,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDUWS
    { 2222,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDUWM
    { 2221,	3,	1,	4,	240,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VADDUQM
    { 2220,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDUHS
    { 2219,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDUHM
    { 2218,	3,	1,	4,	262,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VADDUDM
    { 2217,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDUBS
    { 2216,	3,	1,	4,	169,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDUBM
    { 2215,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDSWS
    { 2214,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDSHS
    { 2213,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDSBS
    { 2212,	3,	1,	4,	440,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDFP
    { 2211,	4,	1,	4,	239,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x0ULL },  // VADDEUQM
    { 2210,	4,	1,	4,	239,	0,	0,	PPCOpInfoBase + 1104,	0,	0, 0x0ULL },  // VADDECUQ
    { 2209,	3,	1,	4,	488,	0,	0,	PPCOpInfoBase + 309,	0,	0|(1ULL<<MCID::Commutable), 0x28ULL },  // VADDCUW
    { 2208,	3,	1,	4,	469,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VADDCUQ
    { 2207,	3,	1,	4,	309,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VABSDUW
    { 2206,	3,	1,	4,	309,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VABSDUH
    { 2205,	3,	1,	4,	309,	0,	0,	PPCOpInfoBase + 309,	0,	0, 0x0ULL },  // VABSDUB
    { 2204,	3,	2,	8,	0,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UpdateGBR
    { 2203,	0,	0,	4,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UNENCODED_NOP
    { 2202,	3,	0,	4,	487,	0,	0,	PPCOpInfoBase + 1089,	0,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TWI
    { 2201,	3,	0,	4,	197,	0,	0,	PPCOpInfoBase + 448,	0,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TW
    { 2200,	1,	0,	4,	307,	0,	1,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TSR
    { 2199,	1,	0,	4,	307,	0,	1,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TRECLAIM
    { 2198,	0,	0,	4,	297,	0,	1,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TRECHKPT
    { 2197,	0,	0,	4,	495,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Trap)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TRAP
    { 2196,	2,	1,	4,	0,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x0ULL },  // TLSLDAIX8
    { 2195,	2,	1,	4,	0,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // TLSLDAIX
    { 2194,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x0ULL },  // TLSGDAIX8
    { 2193,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x0ULL },  // TLSGDAIX
    { 2192,	3,	0,	4,	623,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBWE2
    { 2191,	0,	0,	4,	416,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBWE
    { 2190,	1,	0,	4,	0,	0,	0,	PPCOpInfoBase + 171,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBSYNCIO
    { 2189,	0,	0,	4,	347,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBSYNC
    { 2188,	3,	0,	4,	623,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBSX2D
    { 2187,	3,	0,	4,	623,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBSX2
    { 2186,	2,	0,	4,	416,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBSX
    { 2185,	3,	1,	4,	623,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBRE2
    { 2184,	0,	0,	4,	416,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBRE
    { 2183,	1,	0,	4,	623,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBLI
    { 2182,	1,	0,	4,	623,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBLD
    { 2181,	2,	0,	4,	416,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBIVAX
    { 2180,	3,	0,	4,	15,	0,	0,	PPCOpInfoBase + 448,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBILX
    { 2179,	5,	0,	4,	615,	0,	0,	PPCOpInfoBase + 943,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBIEP9
    { 2178,	5,	0,	4,	0,	0,	0,	PPCOpInfoBase + 948,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBIEP8
    { 2177,	5,	0,	4,	0,	0,	0,	PPCOpInfoBase + 943,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBIEP
    { 2176,	1,	0,	4,	356,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBIEL
    { 2175,	3,	0,	4,	0,	0,	0,	PPCOpInfoBase + 180,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBIEIO
    { 2174,	5,	0,	4,	615,	0,	0,	PPCOpInfoBase + 948,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBIE8P9
    { 2173,	2,	0,	4,	374,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBIE
    { 2172,	0,	0,	4,	422,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBIA
    { 2171,	1,	0,	4,	359,	0,	1,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TEND
    { 2170,	3,	0,	4,	486,	0,	0,	PPCOpInfoBase + 1101,	0,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TDI
    { 2169,	3,	0,	4,	196,	0,	0,	PPCOpInfoBase + 1098,	0,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TD
    { 2168,	2,	0,	4,	0,	1,	0,	PPCOpInfoBase + 1096,	162,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // TCRETURNri8
    { 2167,	2,	0,	4,	0,	1,	0,	PPCOpInfoBase + 1094,	162,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // TCRETURNri
    { 2166,	2,	0,	4,	0,	1,	0,	PPCOpInfoBase + 1092,	162,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // TCRETURNdi8
    { 2165,	2,	0,	4,	0,	1,	0,	PPCOpInfoBase + 1092,	162,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // TCRETURNdi
    { 2164,	2,	0,	4,	0,	1,	0,	PPCOpInfoBase + 32,	162,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // TCRETURNai8
    { 2163,	2,	0,	4,	0,	1,	0,	PPCOpInfoBase + 32,	162,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // TCRETURNai
    { 2162,	1,	1,	4,	0,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TCHECK_RET
    { 2161,	1,	1,	4,	361,	0,	0,	PPCOpInfoBase + 684,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TCHECK
    { 2160,	2,	1,	4,	0,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TBEGIN_RET
    { 2159,	1,	0,	4,	297,	0,	1,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TBEGIN
    { 2158,	0,	0,	4,	405,	2,	0,	PPCOpInfoBase + 1,	237,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x38ULL },  // TAILBCTR8
    { 2157,	0,	0,	4,	405,	2,	0,	PPCOpInfoBase + 1,	235,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x38ULL },  // TAILBCTR
    { 2156,	1,	0,	4,	449,	1,	0,	PPCOpInfoBase + 0,	162,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x38ULL },  // TAILBA8
    { 2155,	1,	0,	4,	449,	1,	0,	PPCOpInfoBase + 0,	162,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x38ULL },  // TAILBA
    { 2154,	1,	0,	4,	449,	1,	0,	PPCOpInfoBase + 290,	162,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x38ULL },  // TAILB8
    { 2153,	1,	0,	4,	449,	1,	0,	PPCOpInfoBase + 290,	162,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x38ULL },  // TAILB
    { 2152,	3,	0,	4,	273,	0,	1,	PPCOpInfoBase + 1089,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TABORTWCI
    { 2151,	3,	0,	4,	273,	0,	1,	PPCOpInfoBase + 448,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TABORTWC
    { 2150,	3,	0,	4,	273,	0,	1,	PPCOpInfoBase + 1089,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TABORTDCI
    { 2149,	3,	0,	4,	273,	0,	1,	PPCOpInfoBase + 448,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TABORTDC
    { 2148,	1,	0,	4,	307,	0,	1,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TABORT
    { 2147,	2,	0,	4,	617,	0,	0,	PPCOpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SYNCP10
    { 2146,	1,	0,	4,	348,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SYNC
    { 2145,	3,	1,	4,	289,	0,	1,	PPCOpInfoBase + 225,	0,	0, 0x8ULL },  // SUBF_rec
    { 2144,	2,	1,	4,	536,	1,	2,	PPCOpInfoBase + 262,	32,	0, 0x8ULL },  // SUBFZE_rec
    { 2143,	2,	1,	4,	536,	1,	3,	PPCOpInfoBase + 262,	28,	0, 0x8ULL },  // SUBFZEO_rec
    { 2142,	2,	1,	4,	506,	1,	2,	PPCOpInfoBase + 262,	25,	0, 0x8ULL },  // SUBFZEO
    { 2141,	2,	1,	4,	536,	1,	2,	PPCOpInfoBase + 264,	32,	0, 0x8ULL },  // SUBFZE8_rec
    { 2140,	2,	1,	4,	536,	1,	3,	PPCOpInfoBase + 264,	28,	0, 0x8ULL },  // SUBFZE8O_rec
    { 2139,	2,	1,	4,	506,	1,	2,	PPCOpInfoBase + 264,	25,	0, 0x8ULL },  // SUBFZE8O
    { 2138,	2,	1,	4,	505,	1,	1,	PPCOpInfoBase + 264,	23,	0, 0x8ULL },  // SUBFZE8
    { 2137,	2,	1,	4,	505,	1,	1,	PPCOpInfoBase + 262,	23,	0, 0x8ULL },  // SUBFZE
    { 2136,	4,	1,	4,	146,	0,	1,	PPCOpInfoBase + 244,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBFUS_rec
    { 2135,	4,	1,	4,	146,	0,	0,	PPCOpInfoBase + 244,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBFUS
    { 2134,	3,	1,	4,	538,	0,	2,	PPCOpInfoBase + 225,	13,	0, 0x8ULL },  // SUBFO_rec
    { 2133,	3,	1,	4,	525,	0,	1,	PPCOpInfoBase + 225,	12,	0, 0x8ULL },  // SUBFO
    { 2132,	2,	1,	4,	536,	1,	2,	PPCOpInfoBase + 262,	32,	0, 0x8ULL },  // SUBFME_rec
    { 2131,	2,	1,	4,	536,	1,	3,	PPCOpInfoBase + 262,	28,	0, 0x8ULL },  // SUBFMEO_rec
    { 2130,	2,	1,	4,	506,	1,	2,	PPCOpInfoBase + 262,	25,	0, 0x8ULL },  // SUBFMEO
    { 2129,	2,	1,	4,	536,	1,	2,	PPCOpInfoBase + 264,	32,	0, 0x8ULL },  // SUBFME8_rec
    { 2128,	2,	1,	4,	536,	1,	3,	PPCOpInfoBase + 264,	28,	0, 0x8ULL },  // SUBFME8O_rec
    { 2127,	2,	1,	4,	506,	1,	2,	PPCOpInfoBase + 264,	25,	0, 0x8ULL },  // SUBFME8O
    { 2126,	2,	1,	4,	505,	1,	1,	PPCOpInfoBase + 264,	23,	0, 0x8ULL },  // SUBFME8
    { 2125,	2,	1,	4,	505,	1,	1,	PPCOpInfoBase + 262,	23,	0, 0x8ULL },  // SUBFME
    { 2124,	3,	1,	4,	505,	0,	1,	PPCOpInfoBase + 180,	15,	0, 0x8ULL },  // SUBFIC8
    { 2123,	3,	1,	4,	505,	0,	1,	PPCOpInfoBase + 183,	15,	0, 0x8ULL },  // SUBFIC
    { 2122,	3,	1,	4,	538,	1,	2,	PPCOpInfoBase + 225,	32,	0, 0x8ULL },  // SUBFE_rec
    { 2121,	3,	1,	4,	538,	1,	3,	PPCOpInfoBase + 225,	28,	0, 0x8ULL },  // SUBFEO_rec
    { 2120,	3,	1,	4,	525,	1,	2,	PPCOpInfoBase + 225,	25,	0, 0x8ULL },  // SUBFEO
    { 2119,	3,	1,	4,	538,	1,	2,	PPCOpInfoBase + 231,	32,	0, 0x8ULL },  // SUBFE8_rec
    { 2118,	3,	1,	4,	538,	1,	3,	PPCOpInfoBase + 231,	28,	0, 0x8ULL },  // SUBFE8O_rec
    { 2117,	3,	1,	4,	525,	1,	2,	PPCOpInfoBase + 231,	25,	0, 0x8ULL },  // SUBFE8O
    { 2116,	3,	1,	4,	144,	1,	1,	PPCOpInfoBase + 231,	23,	0, 0x8ULL },  // SUBFE8
    { 2115,	3,	1,	4,	144,	1,	1,	PPCOpInfoBase + 225,	23,	0, 0x8ULL },  // SUBFE
    { 2114,	3,	1,	4,	542,	0,	2,	PPCOpInfoBase + 225,	21,	0, 0xcULL },  // SUBFC_rec
    { 2113,	3,	1,	4,	393,	0,	3,	PPCOpInfoBase + 225,	18,	0, 0xcULL },  // SUBFCO_rec
    { 2112,	3,	1,	4,	288,	0,	2,	PPCOpInfoBase + 225,	16,	0, 0xcULL },  // SUBFCO
    { 2111,	3,	1,	4,	542,	0,	2,	PPCOpInfoBase + 231,	21,	0, 0xcULL },  // SUBFC8_rec
    { 2110,	3,	1,	4,	393,	0,	3,	PPCOpInfoBase + 231,	18,	0, 0xcULL },  // SUBFC8O_rec
    { 2109,	3,	1,	4,	288,	0,	2,	PPCOpInfoBase + 231,	16,	0, 0xcULL },  // SUBFC8O
    { 2108,	3,	1,	4,	288,	0,	1,	PPCOpInfoBase + 231,	15,	0, 0xcULL },  // SUBFC8
    { 2107,	3,	1,	4,	288,	0,	1,	PPCOpInfoBase + 225,	15,	0, 0xcULL },  // SUBFC
    { 2106,	3,	1,	4,	202,	0,	1,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // SUBF8_rec
    { 2105,	3,	1,	4,	538,	0,	2,	PPCOpInfoBase + 231,	13,	0, 0x8ULL },  // SUBF8O_rec
    { 2104,	3,	1,	4,	525,	0,	1,	PPCOpInfoBase + 231,	12,	0, 0x8ULL },  // SUBF8O
    { 2103,	3,	1,	4,	141,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // SUBF8
    { 2102,	3,	1,	4,	230,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x8ULL },  // SUBF
    { 2101,	3,	0,	4,	375,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVX
    { 2100,	3,	0,	4,	118,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVW4X
    { 2099,	3,	0,	4,	613,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVRWX
    { 2098,	3,	0,	4,	15,	0,	0,	PPCOpInfoBase + 662,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVRLL
    { 2097,	3,	0,	4,	15,	0,	0,	PPCOpInfoBase + 662,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVRL
    { 2096,	3,	0,	4,	613,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVRHX
    { 2095,	3,	0,	4,	613,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVRDX
    { 2094,	3,	0,	4,	613,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVRBX
    { 2093,	3,	0,	4,	620,	0,	0,	PPCOpInfoBase + 671,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVPX
    { 2092,	3,	0,	4,	40,	0,	0,	PPCOpInfoBase + 668,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVPRLL
    { 2091,	3,	0,	4,	40,	0,	0,	PPCOpInfoBase + 668,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVPRL
    { 2090,	3,	0,	4,	40,	0,	0,	PPCOpInfoBase + 668,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STXVPB32X
    { 2089,	3,	0,	4,	619,	0,	0,	PPCOpInfoBase + 665,	0,	0|(1ULL<<MCID::MayStore), 0x400ULL },  // STXVP
    { 2088,	3,	0,	4,	376,	0,	0,	PPCOpInfoBase + 662,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVLL
    { 2087,	3,	0,	4,	376,	0,	0,	PPCOpInfoBase + 662,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVL
    { 2086,	3,	0,	4,	375,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVH8X
    { 2085,	3,	0,	4,	118,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVD2X
    { 2084,	3,	0,	4,	375,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXVB16X
    { 2083,	3,	0,	4,	608,	0,	0,	PPCOpInfoBase + 654,	0,	0|(1ULL<<MCID::MayStore), 0x400ULL },  // STXV
    { 2082,	3,	0,	4,	368,	0,	0,	PPCOpInfoBase + 222,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXSSPX
    { 2081,	3,	0,	4,	607,	0,	0,	PPCOpInfoBase + 651,	0,	0|(1ULL<<MCID::MayStore), 0x400ULL },  // STXSSP
    { 2080,	3,	0,	4,	368,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXSIWX
    { 2079,	3,	0,	4,	369,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXSIHXv
    { 2078,	3,	0,	4,	369,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXSIHX
    { 2077,	3,	0,	4,	369,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXSIBXv
    { 2076,	3,	0,	4,	369,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXSIBX
    { 2075,	3,	0,	4,	370,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // STXSDX
    { 2074,	3,	0,	4,	606,	0,	0,	PPCOpInfoBase + 651,	0,	0|(1ULL<<MCID::MayStore), 0x400ULL },  // STXSD
    { 2073,	3,	0,	4,	372,	0,	0,	PPCOpInfoBase + 583,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STWXTLS_32
    { 2072,	3,	0,	4,	372,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STWXTLS_
    { 2071,	3,	0,	4,	372,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STWXTLS
    { 2070,	3,	0,	4,	129,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STWX8
    { 2069,	3,	0,	4,	129,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STWX
    { 2068,	4,	1,	4,	135,	0,	0,	PPCOpInfoBase + 1063,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STWUX8
    { 2067,	4,	1,	4,	135,	0,	0,	PPCOpInfoBase + 1059,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STWUX
    { 2066,	4,	1,	4,	134,	0,	0,	PPCOpInfoBase + 1055,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STWU8
    { 2065,	4,	1,	4,	134,	0,	0,	PPCOpInfoBase + 1051,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STWU
    { 2064,	3,	0,	4,	219,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STWEPX
    { 2063,	3,	0,	4,	132,	0,	1,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STWCX
    { 2062,	3,	0,	4,	616,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STWCIX
    { 2061,	3,	0,	4,	129,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STWBRX
    { 2060,	3,	0,	4,	407,	0,	0,	PPCOpInfoBase + 1086,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x40ULL },  // STWAT
    { 2059,	3,	0,	4,	600,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STW8
    { 2058,	3,	0,	4,	600,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STW
    { 2057,	3,	0,	4,	124,	0,	0,	PPCOpInfoBase + 642,	0,	0|(1ULL<<MCID::MayStore), 0x50ULL },  // STVXL
    { 2056,	3,	0,	4,	124,	0,	0,	PPCOpInfoBase + 642,	0,	0|(1ULL<<MCID::MayStore), 0x50ULL },  // STVX
    { 2055,	3,	0,	4,	124,	0,	0,	PPCOpInfoBase + 642,	0,	0|(1ULL<<MCID::MayStore), 0x50ULL },  // STVEWX
    { 2054,	3,	0,	4,	124,	0,	0,	PPCOpInfoBase + 642,	0,	0|(1ULL<<MCID::MayStore), 0x50ULL },  // STVEHX
    { 2053,	3,	0,	4,	124,	0,	0,	PPCOpInfoBase + 642,	0,	0|(1ULL<<MCID::MayStore), 0x50ULL },  // STVEBX
    { 2052,	3,	0,	4,	223,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STSWI
    { 2051,	3,	0,	4,	0,	0,	0,	PPCOpInfoBase + 639,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x10ULL },  // STQX_PSEUDO
    { 2050,	3,	0,	4,	93,	0,	1,	PPCOpInfoBase + 639,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STQCX
    { 2049,	3,	0,	4,	92,	0,	0,	PPCOpInfoBase + 909,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x410ULL },  // STQ
    { 2048,	0,	0,	4,	428,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STOP
    { 2047,	3,	0,	4,	131,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayStore), 0x400ULL },  // STMW
    { 2046,	3,	0,	4,	372,	0,	0,	PPCOpInfoBase + 583,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STHXTLS_32
    { 2045,	3,	0,	4,	372,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STHXTLS_
    { 2044,	3,	0,	4,	372,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STHXTLS
    { 2043,	3,	0,	4,	129,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STHX8
    { 2042,	3,	0,	4,	129,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STHX
    { 2041,	4,	1,	4,	135,	0,	0,	PPCOpInfoBase + 1063,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STHUX8
    { 2040,	4,	1,	4,	135,	0,	0,	PPCOpInfoBase + 1059,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STHUX
    { 2039,	4,	1,	4,	134,	0,	0,	PPCOpInfoBase + 1055,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STHU8
    { 2038,	4,	1,	4,	134,	0,	0,	PPCOpInfoBase + 1051,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STHU
    { 2037,	3,	0,	4,	219,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STHEPX
    { 2036,	3,	0,	4,	222,	0,	1,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STHCX
    { 2035,	3,	0,	4,	616,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STHCIX
    { 2034,	3,	0,	4,	129,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STHBRX
    { 2033,	3,	0,	4,	600,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STH8
    { 2032,	3,	0,	4,	600,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STH
    { 2031,	3,	0,	4,	368,	0,	0,	PPCOpInfoBase + 633,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STFSXTLS_
    { 2030,	3,	0,	4,	368,	0,	0,	PPCOpInfoBase + 633,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STFSXTLS
    { 2029,	3,	0,	4,	122,	0,	0,	PPCOpInfoBase + 630,	0,	0|(1ULL<<MCID::MayStore), 0x50ULL },  // STFSX
    { 2028,	4,	1,	4,	123,	0,	0,	PPCOpInfoBase + 1082,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STFSUX
    { 2027,	4,	1,	4,	605,	0,	0,	PPCOpInfoBase + 1078,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STFSU
    { 2026,	3,	0,	4,	604,	0,	0,	PPCOpInfoBase + 619,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STFS
    { 2025,	3,	0,	4,	122,	0,	0,	PPCOpInfoBase + 605,	0,	0|(1ULL<<MCID::MayStore), 0x50ULL },  // STFIWX
    { 2024,	3,	0,	4,	368,	0,	0,	PPCOpInfoBase + 616,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STFDXTLS_
    { 2023,	3,	0,	4,	368,	0,	0,	PPCOpInfoBase + 616,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STFDXTLS
    { 2022,	3,	0,	4,	122,	0,	0,	PPCOpInfoBase + 605,	0,	0|(1ULL<<MCID::MayStore), 0x50ULL },  // STFDX
    { 2021,	4,	1,	4,	123,	0,	0,	PPCOpInfoBase + 1074,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STFDUX
    { 2020,	4,	1,	4,	605,	0,	0,	PPCOpInfoBase + 1070,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STFDU
    { 2019,	3,	0,	4,	218,	0,	0,	PPCOpInfoBase + 605,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STFDEPX
    { 2018,	3,	0,	4,	604,	0,	0,	PPCOpInfoBase + 602,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STFD
    { 2017,	3,	0,	4,	220,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STDXTLS_
    { 2016,	3,	0,	4,	220,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STDXTLS
    { 2015,	3,	0,	4,	130,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STDX
    { 2014,	4,	1,	4,	135,	0,	0,	PPCOpInfoBase + 1063,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STDUX
    { 2013,	4,	1,	4,	134,	0,	0,	PPCOpInfoBase + 1055,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STDU
    { 2012,	3,	0,	4,	133,	0,	1,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STDCX
    { 2011,	3,	0,	4,	221,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STDCIX
    { 2010,	3,	0,	4,	372,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STDBRX
    { 2009,	3,	0,	4,	407,	0,	0,	PPCOpInfoBase + 1067,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x40ULL },  // STDAT
    { 2008,	3,	0,	4,	602,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STD
    { 2007,	3,	0,	4,	372,	0,	0,	PPCOpInfoBase + 583,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STBXTLS_32
    { 2006,	3,	0,	4,	372,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STBXTLS_
    { 2005,	3,	0,	4,	372,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayStore), 0xcULL },  // STBXTLS
    { 2004,	3,	0,	4,	129,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STBX8
    { 2003,	3,	0,	4,	129,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STBX
    { 2002,	4,	1,	4,	135,	0,	0,	PPCOpInfoBase + 1063,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STBUX8
    { 2001,	4,	1,	4,	135,	0,	0,	PPCOpInfoBase + 1059,	0,	0|(1ULL<<MCID::MayStore), 0x54ULL },  // STBUX
    { 2000,	4,	1,	4,	134,	0,	0,	PPCOpInfoBase + 1055,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STBU8
    { 1999,	4,	1,	4,	134,	0,	0,	PPCOpInfoBase + 1051,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STBU
    { 1998,	3,	0,	4,	219,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STBEPX
    { 1997,	3,	0,	4,	222,	0,	1,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STBCX
    { 1996,	3,	0,	4,	221,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STBCIX
    { 1995,	3,	0,	4,	600,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STB8
    { 1994,	3,	0,	4,	600,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayStore), 0x410ULL },  // STB
    { 1993,	3,	1,	4,	201,	0,	1,	PPCOpInfoBase + 225,	0,	0, 0x208ULL },  // SRW_rec
    { 1992,	3,	1,	4,	201,	0,	1,	PPCOpInfoBase + 231,	0,	0, 0x208ULL },  // SRW8_rec
    { 1991,	3,	1,	4,	302,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x208ULL },  // SRW8
    { 1990,	3,	1,	4,	302,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x208ULL },  // SRW
    { 1989,	3,	1,	4,	485,	0,	1,	PPCOpInfoBase + 1045,	0,	0, 0x8ULL },  // SRD_rec
    { 1988,	3,	1,	4,	285,	0,	0,	PPCOpInfoBase + 1045,	0,	0, 0x8ULL },  // SRD
    { 1987,	3,	1,	4,	149,	0,	2,	PPCOpInfoBase + 225,	21,	0, 0x108ULL },  // SRAW_rec
    { 1986,	3,	1,	4,	496,	0,	2,	PPCOpInfoBase + 183,	21,	0, 0x108ULL },  // SRAWI_rec
    { 1985,	3,	1,	4,	496,	0,	2,	PPCOpInfoBase + 180,	21,	0, 0x108ULL },  // SRAWI8_rec
    { 1984,	3,	1,	4,	518,	0,	1,	PPCOpInfoBase + 180,	15,	0, 0x108ULL },  // SRAWI8
    { 1983,	3,	1,	4,	518,	0,	1,	PPCOpInfoBase + 183,	15,	0, 0x108ULL },  // SRAWI
    { 1982,	3,	1,	4,	149,	0,	2,	PPCOpInfoBase + 231,	21,	0, 0x108ULL },  // SRAW8_rec
    { 1981,	3,	1,	4,	304,	0,	1,	PPCOpInfoBase + 231,	15,	0, 0x108ULL },  // SRAW8
    { 1980,	3,	1,	4,	304,	0,	1,	PPCOpInfoBase + 225,	15,	0, 0x108ULL },  // SRAW
    { 1979,	3,	1,	4,	148,	0,	2,	PPCOpInfoBase + 1045,	21,	0, 0x8ULL },  // SRAD_rec
    { 1978,	3,	1,	4,	147,	0,	2,	PPCOpInfoBase + 180,	21,	0, 0x8ULL },  // SRADI_rec
    { 1977,	3,	1,	4,	286,	0,	1,	PPCOpInfoBase + 183,	15,	0, 0x8ULL },  // SRADI_32
    { 1976,	3,	1,	4,	286,	0,	1,	PPCOpInfoBase + 180,	15,	0, 0x8ULL },  // SRADI
    { 1975,	3,	1,	4,	285,	0,	1,	PPCOpInfoBase + 1045,	15,	0, 0x8ULL },  // SRAD
    { 1974,	3,	2,	4,	0,	0,	0,	PPCOpInfoBase + 1048,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPLIT_QUADWORD
    { 1973,	3,	0,	4,	0,	0,	0,	PPCOpInfoBase + 915,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPILL_WACC
    { 1972,	3,	0,	4,	0,	0,	0,	PPCOpInfoBase + 912,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPILL_UACC
    { 1971,	3,	0,	4,	0,	0,	0,	PPCOpInfoBase + 909,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10ULL },  // SPILL_QUADWORD
    { 1970,	3,	0,	4,	0,	0,	0,	PPCOpInfoBase + 906,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPILL_DMRP
    { 1969,	3,	0,	4,	0,	0,	0,	PPCOpInfoBase + 903,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPILL_DMR
    { 1968,	3,	0,	4,	0,	0,	0,	PPCOpInfoBase + 900,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPILL_CRBIT
    { 1967,	3,	0,	4,	0,	0,	0,	PPCOpInfoBase + 897,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPILL_CR
    { 1966,	3,	0,	4,	0,	0,	0,	PPCOpInfoBase + 894,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPILL_ACC
    { 1965,	3,	0,	4,	25,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // SPESTWX
    { 1964,	3,	0,	4,	25,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayStore), 0x400ULL },  // SPESTW
    { 1963,	3,	1,	4,	15,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // SPELWZX
    { 1962,	3,	1,	4,	15,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayLoad), 0x400ULL },  // SPELWZ
    { 1961,	3,	1,	4,	201,	0,	1,	PPCOpInfoBase + 225,	0,	0, 0x208ULL },  // SLW_rec
    { 1960,	3,	1,	4,	201,	0,	1,	PPCOpInfoBase + 231,	0,	0, 0x208ULL },  // SLW8_rec
    { 1959,	3,	1,	4,	302,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x208ULL },  // SLW8
    { 1958,	3,	1,	4,	302,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x208ULL },  // SLW
    { 1957,	3,	1,	4,	485,	0,	1,	PPCOpInfoBase + 1045,	0,	0, 0x8ULL },  // SLD_rec
    { 1956,	3,	1,	4,	285,	0,	0,	PPCOpInfoBase + 1045,	0,	0, 0x8ULL },  // SLD
    { 1955,	0,	0,	4,	426,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLBSYNC
    { 1954,	2,	0,	4,	355,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLBMTE
    { 1953,	2,	1,	4,	354,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLBMFEV
    { 1952,	2,	1,	4,	353,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLBMFEE
    { 1951,	2,	0,	4,	373,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLBIEG
    { 1950,	1,	0,	4,	352,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLBIE
    { 1949,	0,	0,	4,	351,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLBIA
    { 1948,	2,	1,	4,	427,	0,	1,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLBFEE_rec
    { 1947,	2,	1,	4,	0,	1,	1,	PPCOpInfoBase + 686,	233,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SETRNDi
    { 1946,	2,	1,	4,	0,	1,	1,	PPCOpInfoBase + 1043,	233,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SETRND
    { 1945,	2,	1,	4,	517,	0,	0,	PPCOpInfoBase + 1041,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // SETNBCR8
    { 1944,	2,	1,	4,	517,	0,	0,	PPCOpInfoBase + 1039,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // SETNBCR
    { 1943,	2,	1,	4,	517,	0,	0,	PPCOpInfoBase + 1041,	0,	0, 0x100ULL },  // SETNBC8
    { 1942,	2,	1,	4,	517,	0,	0,	PPCOpInfoBase + 1039,	0,	0, 0x100ULL },  // SETNBC
    { 1941,	2,	1,	4,	0,	1,	1,	PPCOpInfoBase + 350,	233,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SETFLM
    { 1940,	2,	1,	4,	517,	0,	0,	PPCOpInfoBase + 1041,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x300ULL },  // SETBCR8
    { 1939,	2,	1,	4,	517,	0,	0,	PPCOpInfoBase + 1039,	0,	0, 0x300ULL },  // SETBCR
    { 1938,	2,	1,	4,	517,	0,	0,	PPCOpInfoBase + 1041,	0,	0, 0x300ULL },  // SETBC8
    { 1937,	2,	1,	4,	517,	0,	0,	PPCOpInfoBase + 1039,	0,	0, 0x300ULL },  // SETBC
    { 1936,	2,	1,	4,	516,	0,	0,	PPCOpInfoBase + 1037,	0,	0, 0x108ULL },  // SETB8
    { 1935,	2,	1,	4,	516,	0,	0,	PPCOpInfoBase + 1035,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // SETB
    { 1934,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1007,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL },  // SELECT_VSSRC
    { 1933,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1031,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL },  // SELECT_VSRC
    { 1932,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1011,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL },  // SELECT_VSFRC
    { 1931,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1003,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL },  // SELECT_VRRC
    { 1930,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1027,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_SPE4
    { 1929,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1023,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_SPE
    { 1928,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1019,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL },  // SELECT_I8
    { 1927,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1015,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL },  // SELECT_I4
    { 1926,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1011,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL },  // SELECT_F8
    { 1925,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1007,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL },  // SELECT_F4
    { 1924,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 1003,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x2ULL },  // SELECT_F16
    { 1923,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 968,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // SELECT_CC_VSSRC
    { 1922,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 998,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // SELECT_CC_VSRC
    { 1921,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 973,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // SELECT_CC_VSFRC
    { 1920,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 963,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // SELECT_CC_VRRC
    { 1919,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 993,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SELECT_CC_SPE4
    { 1918,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 988,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SELECT_CC_SPE
    { 1917,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 983,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // SELECT_CC_I8
    { 1916,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 978,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // SELECT_CC_I4
    { 1915,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 973,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // SELECT_CC_F8
    { 1914,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 968,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // SELECT_CC_F4
    { 1913,	5,	1,	4,	0,	0,	0,	PPCOpInfoBase + 963,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // SELECT_CC_F16
    { 1912,	1,	0,	4,	4,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SCV
    { 1911,	1,	0,	4,	539,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // SC
    { 1910,	2,	2,	4,	0,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ReadTB
    { 1909,	5,	1,	4,	201,	0,	1,	PPCOpInfoBase + 953,	0,	0, 0x8ULL },  // RLWNM_rec
    { 1908,	5,	1,	4,	201,	0,	1,	PPCOpInfoBase + 958,	0,	0, 0x8ULL },  // RLWNM8_rec
    { 1907,	5,	1,	4,	302,	0,	0,	PPCOpInfoBase + 958,	0,	0, 0x8ULL },  // RLWNM8
    { 1906,	5,	1,	4,	302,	0,	0,	PPCOpInfoBase + 953,	0,	0, 0x8ULL },  // RLWNM
    { 1905,	5,	1,	4,	477,	0,	1,	PPCOpInfoBase + 943,	0,	0, 0xcULL },  // RLWINM_rec
    { 1904,	5,	1,	4,	477,	0,	1,	PPCOpInfoBase + 948,	0,	0, 0x8ULL },  // RLWINM8_rec
    { 1903,	5,	1,	4,	515,	0,	0,	PPCOpInfoBase + 948,	0,	0, 0x8ULL },  // RLWINM8
    { 1902,	5,	1,	4,	515,	0,	0,	PPCOpInfoBase + 943,	0,	0, 0x8ULL },  // RLWINM
    { 1901,	6,	1,	4,	206,	0,	1,	PPCOpInfoBase + 931,	0,	0|(1ULL<<MCID::Commutable), 0xcULL },  // RLWIMI_rec
    { 1900,	6,	1,	4,	206,	0,	1,	PPCOpInfoBase + 937,	0,	0, 0xcULL },  // RLWIMI8_rec
    { 1899,	6,	1,	4,	199,	0,	0,	PPCOpInfoBase + 937,	0,	0, 0xcULL },  // RLWIMI8
    { 1898,	6,	1,	4,	199,	0,	0,	PPCOpInfoBase + 931,	0,	0|(1ULL<<MCID::Commutable), 0xcULL },  // RLWIMI
    { 1897,	5,	1,	4,	396,	0,	1,	PPCOpInfoBase + 926,	0,	0, 0x8ULL },  // RLDIMI_rec
    { 1896,	5,	1,	4,	300,	0,	0,	PPCOpInfoBase + 926,	0,	0, 0x8ULL },  // RLDIMI
    { 1895,	4,	1,	4,	475,	0,	1,	PPCOpInfoBase + 172,	0,	0, 0x8ULL },  // RLDIC_rec
    { 1894,	4,	1,	4,	476,	0,	1,	PPCOpInfoBase + 172,	0,	0, 0x8ULL },  // RLDICR_rec
    { 1893,	4,	1,	4,	514,	0,	0,	PPCOpInfoBase + 176,	0,	0, 0x8ULL },  // RLDICR_32
    { 1892,	4,	1,	4,	514,	0,	0,	PPCOpInfoBase + 172,	0,	0, 0x8ULL },  // RLDICR
    { 1891,	4,	1,	4,	476,	0,	1,	PPCOpInfoBase + 172,	0,	0, 0x8ULL },  // RLDICL_rec
    { 1890,	4,	1,	4,	476,	0,	1,	PPCOpInfoBase + 176,	0,	0, 0x8ULL },  // RLDICL_32_rec
    { 1889,	4,	1,	4,	514,	0,	0,	PPCOpInfoBase + 922,	0,	0, 0x8ULL },  // RLDICL_32_64
    { 1888,	4,	1,	4,	514,	0,	0,	PPCOpInfoBase + 176,	0,	0, 0x8ULL },  // RLDICL_32
    { 1887,	4,	1,	4,	514,	0,	0,	PPCOpInfoBase + 172,	0,	0, 0x8ULL },  // RLDICL
    { 1886,	4,	1,	4,	286,	0,	0,	PPCOpInfoBase + 172,	0,	0, 0x8ULL },  // RLDIC
    { 1885,	4,	1,	4,	395,	0,	1,	PPCOpInfoBase + 918,	0,	0, 0x8ULL },  // RLDCR_rec
    { 1884,	4,	1,	4,	299,	0,	0,	PPCOpInfoBase + 918,	0,	0, 0x8ULL },  // RLDCR
    { 1883,	4,	1,	4,	395,	0,	1,	PPCOpInfoBase + 918,	0,	0, 0x8ULL },  // RLDCL_rec
    { 1882,	4,	1,	4,	299,	0,	0,	PPCOpInfoBase + 918,	0,	0, 0x8ULL },  // RLDCL
    { 1881,	0,	0,	4,	413,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RFMCI
    { 1880,	0,	0,	4,	415,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RFID
    { 1879,	0,	0,	4,	414,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RFI
    { 1878,	1,	0,	4,	296,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // RFEBB
    { 1877,	0,	0,	4,	413,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RFDI
    { 1876,	0,	0,	4,	413,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RFCI
    { 1875,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 915,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // RESTORE_WACC
    { 1874,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 912,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // RESTORE_UACC
    { 1873,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 909,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x10ULL },  // RESTORE_QUADWORD
    { 1872,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 906,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // RESTORE_DMRP
    { 1871,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 903,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // RESTORE_DMR
    { 1870,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 900,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RESTORE_CRBIT
    { 1869,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 897,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RESTORE_CR
    { 1868,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 894,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // RESTORE_ACC
    { 1867,	0,	0,	12,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PseudoEIEIO
    { 1866,	1,	0,	4,	0,	0,	0,	PPCOpInfoBase + 171,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PTESYNCIO
    { 1865,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 788,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTXVpc
    { 1864,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 660,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTXVonlypc
    { 1863,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 777,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTXVnopc
    { 1862,	3,	0,	8,	599,	0,	0,	PPCOpInfoBase + 785,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTXVPpc
    { 1861,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 783,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTXVPonlypc
    { 1860,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 780,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTXVPnopc
    { 1859,	3,	0,	8,	599,	0,	0,	PPCOpInfoBase + 780,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTXVP
    { 1858,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 777,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTXV
    { 1857,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 774,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTXSSPpc
    { 1856,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 772,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTXSSPonlypc
    { 1855,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 769,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTXSSPnopc
    { 1854,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 769,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTXSSP
    { 1853,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 774,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTXSDpc
    { 1852,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 772,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTXSDonlypc
    { 1851,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 769,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTXSDnopc
    { 1850,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 769,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTXSD
    { 1849,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 752,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTWpc
    { 1848,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTWonlypc
    { 1847,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTWnopc
    { 1846,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 749,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTW8pc
    { 1845,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTW8onlypc
    { 1844,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTW8nopc
    { 1843,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTW8
    { 1842,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTW
    { 1841,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 752,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTHpc
    { 1840,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTHonlypc
    { 1839,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTHnopc
    { 1838,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 749,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTH8pc
    { 1837,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTH8onlypc
    { 1836,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTH8nopc
    { 1835,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTH8
    { 1834,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTH
    { 1833,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 766,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTFSpc
    { 1832,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 764,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTFSonlypc
    { 1831,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 761,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTFSnopc
    { 1830,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 761,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTFS
    { 1829,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 758,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTFDpc
    { 1828,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 686,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTFDonlypc
    { 1827,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 755,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTFDnopc
    { 1826,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 755,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTFD
    { 1825,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 749,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTDpc
    { 1824,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTDonlypc
    { 1823,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTDnopc
    { 1822,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTD
    { 1821,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 752,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTBpc
    { 1820,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTBonlypc
    { 1819,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTBnopc
    { 1818,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 749,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTB8pc
    { 1817,	2,	0,	8,	40,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PSTB8onlypc
    { 1816,	3,	0,	8,	40,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PSTB8nopc
    { 1815,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTB8
    { 1814,	3,	0,	8,	618,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayStore), 0x480ULL },  // PSTB
    { 1813,	3,	2,	4,	0,	1,	1,	PPCOpInfoBase + 180,	160,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PROBED_STACKALLOC_64
    { 1812,	3,	2,	4,	0,	1,	1,	PPCOpInfoBase + 183,	71,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PROBED_STACKALLOC_32
    { 1811,	4,	1,	4,	0,	1,	1,	PPCOpInfoBase + 473,	160,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PROBED_ALLOCA_64
    { 1810,	4,	1,	4,	0,	1,	1,	PPCOpInfoBase + 469,	71,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PROBED_ALLOCA_32
    { 1809,	5,	2,	4,	0,	1,	1,	PPCOpInfoBase + 889,	160,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREPARE_PROBED_ALLOCA_NEGSIZE_SAME_REG_64
    { 1808,	5,	2,	4,	0,	1,	1,	PPCOpInfoBase + 884,	71,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREPARE_PROBED_ALLOCA_NEGSIZE_SAME_REG_32
    { 1807,	5,	2,	4,	0,	1,	1,	PPCOpInfoBase + 879,	160,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREPARE_PROBED_ALLOCA_64
    { 1806,	5,	2,	4,	0,	1,	1,	PPCOpInfoBase + 874,	71,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREPARE_PROBED_ALLOCA_32
    { 1805,	2,	2,	20,	0,	0,	1,	PPCOpInfoBase + 262,	231,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PPC32PICGOT
    { 1804,	1,	1,	8,	0,	0,	0,	PPCOpInfoBase + 170,	0,	0, 0x0ULL },  // PPC32GOT
    { 1803,	2,	1,	4,	282,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x8ULL },  // POPCNTW
    { 1802,	2,	1,	4,	282,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x308ULL },  // POPCNTD
    { 1801,	2,	1,	4,	208,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x8ULL },  // POPCNTB8
    { 1800,	2,	1,	4,	208,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // POPCNTB
    { 1799,	7,	1,	8,	19,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI8GER4WSPP
    { 1798,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI8GER4WPP
    { 1797,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 817,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI8GER4W
    { 1796,	7,	1,	8,	573,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI8GER4SPP
    { 1795,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI8GER4PP
    { 1794,	6,	1,	8,	571,	0,	0,	PPCOpInfoBase + 804,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI8GER4
    { 1793,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI4GER8WPP
    { 1792,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 817,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI4GER8W
    { 1791,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI4GER8PP
    { 1790,	6,	1,	8,	571,	0,	0,	PPCOpInfoBase + 804,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI4GER8
    { 1789,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI16GER2WPP
    { 1788,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 817,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI16GER2W
    { 1787,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI16GER2SWPP
    { 1786,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 817,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI16GER2SW
    { 1785,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI16GER2SPP
    { 1784,	6,	1,	8,	571,	0,	0,	PPCOpInfoBase + 804,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI16GER2S
    { 1783,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI16GER2PP
    { 1782,	6,	1,	8,	571,	0,	0,	PPCOpInfoBase + 804,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVI16GER2
    { 1781,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 868,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF64GERWPP
    { 1780,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 868,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF64GERWPN
    { 1779,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 868,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF64GERWNP
    { 1778,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 868,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF64GERWNN
    { 1777,	5,	1,	8,	5,	0,	0,	PPCOpInfoBase + 863,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF64GERW
    { 1776,	6,	1,	8,	572,	0,	0,	PPCOpInfoBase + 857,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF64GERPP
    { 1775,	6,	1,	8,	572,	0,	0,	PPCOpInfoBase + 857,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF64GERPN
    { 1774,	6,	1,	8,	572,	0,	0,	PPCOpInfoBase + 857,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF64GERNP
    { 1773,	6,	1,	8,	572,	0,	0,	PPCOpInfoBase + 857,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF64GERNN
    { 1772,	5,	1,	8,	571,	0,	0,	PPCOpInfoBase + 852,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF64GER
    { 1771,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 846,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF32GERWPP
    { 1770,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 846,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF32GERWPN
    { 1769,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 846,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF32GERWNP
    { 1768,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 846,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF32GERWNN
    { 1767,	5,	1,	8,	5,	0,	0,	PPCOpInfoBase + 841,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF32GERW
    { 1766,	6,	1,	8,	572,	0,	0,	PPCOpInfoBase + 835,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF32GERPP
    { 1765,	6,	1,	8,	572,	0,	0,	PPCOpInfoBase + 835,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF32GERPN
    { 1764,	6,	1,	8,	572,	0,	0,	PPCOpInfoBase + 835,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF32GERNP
    { 1763,	6,	1,	8,	572,	0,	0,	PPCOpInfoBase + 835,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF32GERNN
    { 1762,	5,	1,	8,	571,	0,	0,	PPCOpInfoBase + 830,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF32GER
    { 1761,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF16GER2WPP
    { 1760,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF16GER2WPN
    { 1759,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF16GER2WNP
    { 1758,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF16GER2WNN
    { 1757,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 817,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF16GER2W
    { 1756,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF16GER2PP
    { 1755,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF16GER2PN
    { 1754,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF16GER2NP
    { 1753,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF16GER2NN
    { 1752,	6,	1,	8,	571,	0,	0,	PPCOpInfoBase + 804,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVF16GER2
    { 1751,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVBF16GER2WPP
    { 1750,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVBF16GER2WPN
    { 1749,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVBF16GER2WNP
    { 1748,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 823,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVBF16GER2WNN
    { 1747,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 817,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVBF16GER2W
    { 1746,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVBF16GER2PP
    { 1745,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVBF16GER2PN
    { 1744,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVBF16GER2NP
    { 1743,	7,	1,	8,	572,	0,	0,	PPCOpInfoBase + 810,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVBF16GER2NN
    { 1742,	6,	1,	8,	571,	0,	0,	PPCOpInfoBase + 804,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMXVBF16GER2
    { 1741,	7,	1,	8,	19,	0,	0,	PPCOpInfoBase + 797,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVI8GERX4SPP
    { 1740,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 797,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVI8GERX4PP
    { 1739,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 791,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVI8GERX4
    { 1738,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 797,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVF16GERX2PP
    { 1737,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 797,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVF16GERX2PN
    { 1736,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 797,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVF16GERX2NP
    { 1735,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 797,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVF16GERX2NN
    { 1734,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 791,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVF16GERX2
    { 1733,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 797,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVBF16GERX2PP
    { 1732,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 797,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVBF16GERX2PN
    { 1731,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 797,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVBF16GERX2NP
    { 1730,	7,	1,	8,	5,	0,	0,	PPCOpInfoBase + 797,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVBF16GERX2NN
    { 1729,	6,	1,	8,	5,	0,	0,	PPCOpInfoBase + 791,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PMDMXVBF16GERX2
    { 1728,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 788,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLXVpc
    { 1727,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 660,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLXVonlypc
    { 1726,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 777,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLXVnopc
    { 1725,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 785,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLXVPpc
    { 1724,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 783,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLXVPonlypc
    { 1723,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 780,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLXVPnopc
    { 1722,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 780,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLXVP
    { 1721,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 777,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLXV
    { 1720,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 774,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLXSSPpc
    { 1719,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 772,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLXSSPonlypc
    { 1718,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 769,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLXSSPnopc
    { 1717,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 769,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLXSSP
    { 1716,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 774,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLXSDpc
    { 1715,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 772,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLXSDonlypc
    { 1714,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 769,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLXSDnopc
    { 1713,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 769,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLXSD
    { 1712,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 752,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLWZpc
    { 1711,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLWZonlypc
    { 1710,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLWZnopc
    { 1709,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 749,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLWZ8pc
    { 1708,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLWZ8onlypc
    { 1707,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLWZ8nopc
    { 1706,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLWZ8
    { 1705,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLWZ
    { 1704,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 752,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLWApc
    { 1703,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLWAonlypc
    { 1702,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLWAnopc
    { 1701,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 749,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLWA8pc
    { 1700,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLWA8onlypc
    { 1699,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLWA8nopc
    { 1698,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLWA8
    { 1697,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLWA
    { 1696,	2,	1,	8,	626,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x80ULL },  // PLI8
    { 1695,	2,	1,	8,	626,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x80ULL },  // PLI
    { 1694,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 752,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLHZpc
    { 1693,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLHZonlypc
    { 1692,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLHZnopc
    { 1691,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 749,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLHZ8pc
    { 1690,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLHZ8onlypc
    { 1689,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLHZ8nopc
    { 1688,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLHZ8
    { 1687,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLHZ
    { 1686,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 752,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLHApc
    { 1685,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLHAonlypc
    { 1684,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLHAnopc
    { 1683,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 749,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLHA8pc
    { 1682,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLHA8onlypc
    { 1681,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLHA8nopc
    { 1680,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLHA8
    { 1679,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLHA
    { 1678,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 766,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLFSpc
    { 1677,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 764,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLFSonlypc
    { 1676,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 761,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLFSnopc
    { 1675,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 761,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLFS
    { 1674,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 758,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLFDpc
    { 1673,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 686,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLFDonlypc
    { 1672,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 755,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLFDnopc
    { 1671,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 755,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLFD
    { 1670,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 749,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLDpc
    { 1669,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLDonlypc
    { 1668,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLDnopc
    { 1667,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLD
    { 1666,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 752,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLBZpc
    { 1665,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLBZonlypc
    { 1664,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLBZnopc
    { 1663,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 749,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLBZ8pc
    { 1662,	2,	1,	8,	40,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLBZ8onlypc
    { 1661,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLBZ8nopc
    { 1660,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 746,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLBZ8
    { 1659,	3,	1,	8,	560,	0,	0,	PPCOpInfoBase + 743,	0,	0|(1ULL<<MCID::MayLoad), 0x480ULL },  // PLBZ
    { 1658,	2,	1,	8,	2,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLApc
    { 1657,	2,	1,	8,	2,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PLA8pc
    { 1656,	3,	1,	8,	2,	0,	0,	PPCOpInfoBase + 211,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLA8
    { 1655,	3,	1,	8,	2,	0,	0,	PPCOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x480ULL },  // PLA
    { 1654,	3,	1,	4,	452,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x0ULL },  // PEXTD
    { 1653,	3,	1,	4,	452,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x0ULL },  // PDEPD
    { 1652,	3,	1,	8,	625,	0,	0,	PPCOpInfoBase + 740,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PADDIpc
    { 1651,	3,	1,	8,	0,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x0ULL },  // PADDIdtprel
    { 1650,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 740,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PADDISpc
    { 1649,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 737,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PADDIS8pc
    { 1648,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 211,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PADDIS8
    { 1647,	3,	1,	8,	40,	0,	0,	PPCOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PADDIS
    { 1646,	3,	1,	8,	625,	0,	0,	PPCOpInfoBase + 737,	0,	0, 0x80ULL },  // PADDI8pc
    { 1645,	3,	1,	8,	625,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x80ULL },  // PADDI8
    { 1644,	3,	1,	8,	625,	0,	0,	PPCOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // PADDI
    { 1643,	3,	1,	4,	203,	0,	1,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // OR_rec
    { 1642,	3,	1,	4,	512,	0,	0,	PPCOpInfoBase + 180,	0,	0, 0x8ULL },  // ORIS8
    { 1641,	3,	1,	4,	512,	0,	0,	PPCOpInfoBase + 183,	0,	0, 0x8ULL },  // ORIS
    { 1640,	3,	1,	4,	512,	0,	0,	PPCOpInfoBase + 180,	0,	0, 0x8ULL },  // ORI8
    { 1639,	3,	1,	4,	512,	0,	0,	PPCOpInfoBase + 183,	0,	0, 0x8ULL },  // ORI
    { 1638,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 225,	0,	0, 0x8ULL },  // ORC_rec
    { 1637,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // ORC8_rec
    { 1636,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // ORC8
    { 1635,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x8ULL },  // ORC
    { 1634,	3,	1,	4,	203,	0,	1,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // OR8_rec
    { 1633,	3,	1,	4,	203,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // OR8
    { 1632,	3,	1,	4,	203,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // OR
    { 1631,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // NOR_rec
    { 1630,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // NOR8_rec
    { 1629,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // NOR8
    { 1628,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // NOR
    { 1627,	0,	0,	4,	421,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL },  // NOP_GT_PWR7
    { 1626,	0,	0,	4,	421,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL },  // NOP_GT_PWR6
    { 1625,	0,	0,	4,	513,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL },  // NOP
    { 1624,	2,	1,	4,	512,	0,	1,	PPCOpInfoBase + 262,	0,	0, 0x8ULL },  // NEG_rec
    { 1623,	2,	1,	4,	537,	0,	2,	PPCOpInfoBase + 262,	13,	0, 0x8ULL },  // NEGO_rec
    { 1622,	2,	1,	4,	501,	0,	1,	PPCOpInfoBase + 262,	12,	0, 0x8ULL },  // NEGO
    { 1621,	2,	1,	4,	512,	0,	1,	PPCOpInfoBase + 264,	0,	0, 0x8ULL },  // NEG8_rec
    { 1620,	2,	1,	4,	537,	0,	2,	PPCOpInfoBase + 264,	13,	0, 0x8ULL },  // NEG8O_rec
    { 1619,	2,	1,	4,	501,	0,	1,	PPCOpInfoBase + 264,	12,	0, 0x8ULL },  // NEG8O
    { 1618,	2,	1,	4,	501,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x8ULL },  // NEG8
    { 1617,	2,	1,	4,	501,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x8ULL },  // NEG
    { 1616,	0,	0,	4,	621,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // NAP
    { 1615,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // NAND_rec
    { 1614,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // NAND8_rec
    { 1613,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // NAND8
    { 1612,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // NAND
    { 1611,	0,	0,	4,	0,	0,	1,	PPCOpInfoBase + 1,	232,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // MovePCtoLR8
    { 1610,	0,	0,	4,	0,	0,	1,	PPCOpInfoBase + 1,	231,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // MovePCtoLR
    { 1609,	0,	0,	4,	0,	0,	1,	PPCOpInfoBase + 1,	231,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // MoveGOTtoLR
    { 1608,	3,	1,	4,	152,	0,	1,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULLW_rec
    { 1607,	3,	1,	4,	152,	0,	2,	PPCOpInfoBase + 225,	13,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULLWO_rec
    { 1606,	3,	1,	4,	314,	0,	1,	PPCOpInfoBase + 225,	12,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULLWO
    { 1605,	3,	1,	4,	314,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULLW
    { 1604,	3,	1,	4,	151,	0,	0,	PPCOpInfoBase + 180,	0,	0, 0x8ULL },  // MULLI8
    { 1603,	3,	1,	4,	151,	0,	0,	PPCOpInfoBase + 183,	0,	0, 0x8ULL },  // MULLI
    { 1602,	3,	1,	4,	154,	0,	1,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULLD_rec
    { 1601,	3,	1,	4,	154,	0,	2,	PPCOpInfoBase + 231,	13,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULLDO_rec
    { 1600,	3,	1,	4,	316,	0,	1,	PPCOpInfoBase + 231,	12,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULLDO
    { 1599,	3,	1,	4,	316,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULLD
    { 1598,	3,	1,	4,	152,	0,	1,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULHW_rec
    { 1597,	3,	1,	4,	153,	0,	1,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULHWU_rec
    { 1596,	3,	1,	4,	315,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULHWU
    { 1595,	3,	1,	4,	314,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULHW
    { 1594,	3,	1,	4,	152,	0,	1,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULHD_rec
    { 1593,	3,	1,	4,	153,	0,	1,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULHDU_rec
    { 1592,	3,	1,	4,	315,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULHDU
    { 1591,	3,	1,	4,	314,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // MULHD
    { 1590,	2,	1,	4,	261,	0,	0,	PPCOpInfoBase + 735,	0,	0, 0x0ULL },  // MTVSRWZ
    { 1589,	2,	1,	4,	582,	0,	0,	PPCOpInfoBase + 724,	0,	0, 0x0ULL },  // MTVSRWS
    { 1588,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 726,	0,	0, 0x0ULL },  // MTVSRWM
    { 1587,	2,	1,	4,	261,	0,	0,	PPCOpInfoBase + 735,	0,	0, 0x0ULL },  // MTVSRWA
    { 1586,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 726,	0,	0, 0x0ULL },  // MTVSRQM
    { 1585,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 726,	0,	0, 0x0ULL },  // MTVSRHM
    { 1584,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 726,	0,	0, 0x0ULL },  // MTVSRDM
    { 1583,	3,	1,	4,	264,	0,	0,	PPCOpInfoBase + 732,	0,	0, 0x0ULL },  // MTVSRDD
    { 1582,	2,	1,	4,	261,	0,	0,	PPCOpInfoBase + 730,	0,	0, 0x0ULL },  // MTVSRD
    { 1581,	2,	1,	4,	471,	0,	0,	PPCOpInfoBase + 728,	0,	0, 0x0ULL },  // MTVSRBMI
    { 1580,	2,	1,	4,	474,	0,	0,	PPCOpInfoBase + 726,	0,	0, 0x0ULL },  // MTVSRBM
    { 1579,	1,	0,	4,	238,	0,	0,	PPCOpInfoBase + 698,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTVSCR
    { 1578,	2,	1,	4,	261,	0,	0,	PPCOpInfoBase + 724,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTVRWZ
    { 1577,	2,	1,	4,	261,	0,	0,	PPCOpInfoBase + 724,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTVRWA
    { 1576,	2,	1,	4,	558,	0,	0,	PPCOpInfoBase + 722,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xaULL },  // MTVRSAVEv
    { 1575,	1,	0,	4,	558,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xaULL },  // MTVRSAVE
    { 1574,	2,	1,	4,	261,	0,	0,	PPCOpInfoBase + 720,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTVRD
    { 1573,	1,	0,	4,	384,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xaULL },  // MTUDSCR
    { 1572,	2,	0,	4,	418,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTSRIN
    { 1571,	2,	0,	4,	557,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTSR
    { 1570,	2,	0,	4,	384,	0,	0,	PPCOpInfoBase + 705,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTSPR8
    { 1569,	2,	0,	4,	384,	0,	0,	PPCOpInfoBase + 703,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTSPR
    { 1568,	2,	0,	4,	379,	0,	0,	PPCOpInfoBase + 703,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTPMR
    { 1567,	2,	1,	4,	301,	0,	0,	PPCOpInfoBase + 718,	0,	0|(1ULL<<MCID::ExtraDefRegAllocReq), 0x21ULL },  // MTOCRF8
    { 1566,	2,	1,	4,	301,	0,	0,	PPCOpInfoBase + 716,	0,	0|(1ULL<<MCID::ExtraDefRegAllocReq), 0x21ULL },  // MTOCRF
    { 1565,	2,	0,	4,	383,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTMSRD
    { 1564,	2,	0,	4,	382,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTMSR
    { 1563,	1,	0,	4,	106,	0,	1,	PPCOpInfoBase + 171,	232,	0, 0x9ULL },  // MTLR8
    { 1562,	1,	0,	4,	106,	0,	1,	PPCOpInfoBase + 170,	231,	0, 0x9ULL },  // MTLR
    { 1561,	2,	0,	4,	63,	0,	0,	PPCOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTLPL8
    { 1560,	2,	0,	4,	63,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTLPL
    { 1559,	2,	0,	4,	188,	0,	1,	PPCOpInfoBase + 714,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL },  // MTFSFb
    { 1558,	4,	0,	4,	187,	0,	1,	PPCOpInfoBase + 707,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTFSF_rec
    { 1557,	2,	0,	4,	540,	0,	1,	PPCOpInfoBase + 20,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTFSFIb
    { 1556,	3,	0,	4,	540,	0,	1,	PPCOpInfoBase + 711,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTFSFI_rec
    { 1555,	3,	0,	4,	540,	0,	1,	PPCOpInfoBase + 711,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTFSFI
    { 1554,	4,	0,	4,	187,	0,	1,	PPCOpInfoBase + 707,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTFSF
    { 1553,	1,	0,	4,	274,	0,	1,	PPCOpInfoBase + 1,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL },  // MTFSB1
    { 1552,	1,	0,	4,	535,	0,	1,	PPCOpInfoBase + 1,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL },  // MTFSB0
    { 1551,	2,	0,	4,	420,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTDCR
    { 1550,	1,	0,	4,	106,	0,	1,	PPCOpInfoBase + 170,	73,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL },  // MTCTRloop
    { 1549,	1,	0,	4,	106,	0,	1,	PPCOpInfoBase + 171,	74,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL },  // MTCTR8loop
    { 1548,	1,	0,	4,	106,	0,	1,	PPCOpInfoBase + 171,	74,	0, 0x9ULL },  // MTCTR8
    { 1547,	1,	0,	4,	106,	0,	1,	PPCOpInfoBase + 170,	73,	0, 0x9ULL },  // MTCTR
    { 1546,	2,	0,	4,	198,	0,	0,	PPCOpInfoBase + 705,	0,	0|(1ULL<<MCID::ExtraDefRegAllocReq), 0x20ULL },  // MTCRF8
    { 1545,	2,	0,	4,	198,	0,	0,	PPCOpInfoBase + 703,	0,	0|(1ULL<<MCID::ExtraDefRegAllocReq), 0x20ULL },  // MTCRF
    { 1544,	0,	0,	4,	425,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MSYNC
    { 1543,	0,	0,	4,	346,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MSGSYNC
    { 1542,	1,	0,	4,	385,	0,	0,	PPCOpInfoBase + 171,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MSGSNDP8
    { 1541,	1,	0,	4,	385,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MSGSNDP
    { 1540,	3,	1,	4,	390,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x0ULL },  // MODUW
    { 1539,	3,	1,	4,	390,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // MODUD
    { 1538,	3,	1,	4,	387,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x0ULL },  // MODSW
    { 1537,	3,	1,	4,	390,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // MODSD
    { 1536,	2,	1,	4,	261,	0,	0,	PPCOpInfoBase + 701,	0,	0, 0x200ULL },  // MFVSRWZ
    { 1535,	2,	1,	4,	582,	0,	0,	PPCOpInfoBase + 692,	0,	0, 0x0ULL },  // MFVSRLD
    { 1534,	2,	1,	4,	261,	0,	0,	PPCOpInfoBase + 699,	0,	0, 0x0ULL },  // MFVSRD
    { 1533,	1,	1,	4,	237,	0,	0,	PPCOpInfoBase + 698,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFVSCR
    { 1532,	2,	1,	4,	261,	0,	0,	PPCOpInfoBase + 696,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFVRWZ
    { 1531,	2,	1,	4,	377,	0,	0,	PPCOpInfoBase + 694,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL },  // MFVRSAVEv
    { 1530,	1,	1,	4,	377,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL },  // MFVRSAVE
    { 1529,	2,	1,	4,	261,	0,	0,	PPCOpInfoBase + 692,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFVRD
    { 1528,	1,	1,	4,	380,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL },  // MFUDSCR
    { 1527,	1,	1,	4,	566,	0,	0,	PPCOpInfoBase + 171,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL },  // MFTB8
    { 1526,	2,	1,	4,	210,	0,	0,	PPCOpInfoBase + 209,	0,	0, 0x0ULL },  // MFTB
    { 1525,	2,	1,	4,	114,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFSRIN
    { 1524,	2,	1,	4,	565,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFSR
    { 1523,	2,	1,	4,	380,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFSPR8
    { 1522,	2,	1,	4,	380,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFSPR
    { 1521,	2,	1,	4,	378,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFPMR
    { 1520,	2,	1,	4,	183,	0,	0,	PPCOpInfoBase + 690,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x21ULL },  // MFOCRF8
    { 1519,	2,	1,	4,	183,	0,	0,	PPCOpInfoBase + 688,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x21ULL },  // MFOCRF
    { 1518,	1,	1,	4,	381,	0,	0,	PPCOpInfoBase + 170,	0,	0, 0x0ULL },  // MFMSR
    { 1517,	1,	1,	4,	105,	1,	0,	PPCOpInfoBase + 171,	232,	0, 0x9ULL },  // MFLR8
    { 1516,	1,	1,	4,	105,	1,	0,	PPCOpInfoBase + 170,	231,	0, 0x9ULL },  // MFLR
    { 1515,	1,	1,	4,	533,	1,	1,	PPCOpInfoBase + 685,	163,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFFS_rec
    { 1514,	1,	1,	4,	533,	1,	0,	PPCOpInfoBase + 685,	162,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL },  // MFFSL
    { 1513,	2,	1,	4,	534,	1,	0,	PPCOpInfoBase + 686,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL },  // MFFSCRNI
    { 1512,	2,	1,	4,	275,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL },  // MFFSCRN
    { 1511,	1,	1,	4,	397,	1,	0,	PPCOpInfoBase + 685,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL },  // MFFSCE
    { 1510,	2,	1,	4,	534,	1,	0,	PPCOpInfoBase + 686,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL },  // MFFSCDRNI
    { 1509,	2,	1,	4,	275,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL },  // MFFSCDRN
    { 1508,	1,	1,	4,	533,	1,	0,	PPCOpInfoBase + 685,	162,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1aULL },  // MFFS
    { 1507,	2,	1,	4,	419,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFDCR
    { 1506,	1,	1,	4,	105,	1,	0,	PPCOpInfoBase + 171,	74,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL },  // MFCTR8
    { 1505,	1,	1,	4,	105,	1,	0,	PPCOpInfoBase + 170,	73,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x9ULL },  // MFCTR
    { 1504,	1,	1,	4,	107,	0,	0,	PPCOpInfoBase + 171,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x20ULL },  // MFCR8
    { 1503,	1,	1,	4,	107,	0,	0,	PPCOpInfoBase + 170,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x20ULL },  // MFCR
    { 1502,	2,	1,	4,	624,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL },  // MFBHRBE
    { 1501,	1,	1,	4,	293,	0,	0,	PPCOpInfoBase + 684,	0,	0, 0x0ULL },  // MCRXRX
    { 1500,	2,	1,	4,	394,	0,	0,	PPCOpInfoBase + 682,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MCRFS
    { 1499,	2,	1,	4,	108,	0,	0,	PPCOpInfoBase + 682,	0,	0, 0x21ULL },  // MCRF
    { 1498,	1,	0,	4,	416,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MBAR
    { 1497,	4,	1,	4,	313,	0,	0,	PPCOpInfoBase + 674,	0,	0, 0x8ULL },  // MADDLD8
    { 1496,	4,	1,	4,	313,	0,	0,	PPCOpInfoBase + 678,	0,	0, 0x8ULL },  // MADDLD
    { 1495,	4,	1,	4,	313,	0,	0,	PPCOpInfoBase + 674,	0,	0, 0x8ULL },  // MADDHDU
    { 1494,	4,	1,	4,	313,	0,	0,	PPCOpInfoBase + 674,	0,	0, 0x8ULL },  // MADDHD
    { 1493,	3,	1,	4,	336,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVX
    { 1492,	3,	1,	4,	336,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVWSX
    { 1491,	3,	1,	4,	115,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVW4X
    { 1490,	3,	1,	4,	556,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVRWX
    { 1489,	3,	1,	4,	15,	0,	0,	PPCOpInfoBase + 662,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVRLL
    { 1488,	3,	1,	4,	15,	0,	0,	PPCOpInfoBase + 662,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVRL
    { 1487,	3,	1,	4,	556,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVRHX
    { 1486,	3,	1,	4,	556,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVRDX
    { 1485,	3,	1,	4,	556,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVRBX
    { 1484,	3,	1,	4,	564,	0,	0,	PPCOpInfoBase + 671,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVPX
    { 1483,	3,	1,	4,	40,	0,	0,	PPCOpInfoBase + 668,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVPRLL
    { 1482,	3,	1,	4,	40,	0,	0,	PPCOpInfoBase + 668,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVPRL
    { 1481,	3,	1,	4,	40,	0,	0,	PPCOpInfoBase + 668,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LXVPB32X
    { 1480,	3,	1,	4,	563,	0,	0,	PPCOpInfoBase + 665,	0,	0|(1ULL<<MCID::MayLoad), 0x400ULL },  // LXVP
    { 1479,	3,	1,	4,	335,	0,	0,	PPCOpInfoBase + 662,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVLL
    { 1478,	3,	1,	4,	335,	0,	0,	PPCOpInfoBase + 662,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVL
    { 1477,	2,	1,	4,	577,	0,	0,	PPCOpInfoBase + 660,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LXVKQ
    { 1476,	3,	1,	4,	367,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVH8X
    { 1475,	3,	1,	4,	115,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVDSX
    { 1474,	3,	1,	4,	337,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVD2X
    { 1473,	3,	1,	4,	215,	0,	0,	PPCOpInfoBase + 657,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXVB16X
    { 1472,	3,	1,	4,	551,	0,	0,	PPCOpInfoBase + 654,	0,	0|(1ULL<<MCID::MayLoad), 0x400ULL },  // LXV
    { 1471,	3,	1,	4,	365,	0,	0,	PPCOpInfoBase + 222,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXSSPX
    { 1470,	3,	1,	4,	562,	0,	0,	PPCOpInfoBase + 651,	0,	0|(1ULL<<MCID::MayLoad), 0x400ULL },  // LXSSP
    { 1469,	3,	1,	4,	215,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXSIWZX
    { 1468,	3,	1,	4,	362,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXSIWAX
    { 1467,	3,	1,	4,	336,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXSIHZX
    { 1466,	3,	1,	4,	336,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXSIBZX
    { 1465,	3,	1,	4,	337,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // LXSDX
    { 1464,	3,	1,	4,	551,	0,	0,	PPCOpInfoBase + 651,	0,	0|(1ULL<<MCID::MayLoad), 0x400ULL },  // LXSD
    { 1463,	3,	1,	4,	546,	0,	0,	PPCOpInfoBase + 648,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LWZtocL
    { 1462,	3,	1,	4,	546,	0,	0,	PPCOpInfoBase + 645,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LWZtoc
    { 1461,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 583,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LWZXTLS_32
    { 1460,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LWZXTLS_
    { 1459,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LWZXTLS
    { 1458,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad), 0x250ULL },  // LWZX8
    { 1457,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad), 0x250ULL },  // LWZX
    { 1456,	4,	2,	4,	358,	0,	0,	PPCOpInfoBase + 573,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LWZUX8
    { 1455,	4,	2,	4,	358,	0,	0,	PPCOpInfoBase + 569,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LWZUX
    { 1454,	4,	2,	4,	357,	0,	0,	PPCOpInfoBase + 565,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LWZU8
    { 1453,	4,	2,	4,	357,	0,	0,	PPCOpInfoBase + 561,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LWZU
    { 1452,	3,	1,	4,	559,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LWZCIX
    { 1451,	3,	1,	4,	544,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayLoad), 0x610ULL },  // LWZ8
    { 1450,	3,	1,	4,	544,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayLoad), 0x610ULL },  // LWZ
    { 1449,	3,	1,	4,	227,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LWEPX
    { 1448,	3,	1,	4,	113,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad), 0x250ULL },  // LWBRX8
    { 1447,	3,	1,	4,	113,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad), 0x250ULL },  // LWBRX
    { 1446,	3,	1,	4,	126,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayLoad), 0x514ULL },  // LWA_32
    { 1445,	3,	1,	4,	125,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad), 0x154ULL },  // LWAX_32
    { 1444,	3,	1,	4,	224,	0,	0,	PPCOpInfoBase + 583,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LWAXTLS_32
    { 1443,	3,	1,	4,	224,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LWAXTLS_
    { 1442,	3,	1,	4,	224,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LWAXTLS
    { 1441,	3,	1,	4,	125,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad), 0x154ULL },  // LWAX
    { 1440,	4,	2,	4,	128,	0,	0,	PPCOpInfoBase + 573,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LWAUX
    { 1439,	2,	1,	4,	15,	0,	0,	PPCOpInfoBase + 202,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x40ULL },  // LWAT_CSNE
    { 1438,	4,	1,	4,	406,	0,	0,	PPCOpInfoBase + 586,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x40ULL },  // LWAT
    { 1437,	3,	1,	4,	111,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LWARXL
    { 1436,	3,	1,	4,	111,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LWARX
    { 1435,	3,	1,	4,	126,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayLoad), 0x514ULL },  // LWA
    { 1434,	3,	1,	4,	214,	0,	0,	PPCOpInfoBase + 642,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LVXL
    { 1433,	3,	1,	4,	214,	0,	0,	PPCOpInfoBase + 642,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LVX
    { 1432,	3,	1,	4,	324,	0,	0,	PPCOpInfoBase + 642,	0,	0, 0x50ULL },  // LVSR
    { 1431,	3,	1,	4,	324,	0,	0,	PPCOpInfoBase + 642,	0,	0, 0x50ULL },  // LVSL
    { 1430,	3,	1,	4,	214,	0,	0,	PPCOpInfoBase + 642,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LVEWX
    { 1429,	3,	1,	4,	214,	0,	0,	PPCOpInfoBase + 642,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LVEHX
    { 1428,	3,	1,	4,	214,	0,	0,	PPCOpInfoBase + 642,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LVEBX
    { 1427,	3,	1,	4,	120,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LSWI
    { 1426,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 639,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x10ULL },  // LQX_PSEUDO
    { 1425,	3,	1,	4,	48,	0,	0,	PPCOpInfoBase + 639,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LQARXL
    { 1424,	3,	1,	4,	48,	0,	0,	PPCOpInfoBase + 639,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LQARX
    { 1423,	3,	1,	4,	217,	0,	0,	PPCOpInfoBase + 636,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x410ULL },  // LQ
    { 1422,	3,	1,	4,	110,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayLoad), 0x400ULL },  // LMW
    { 1421,	2,	1,	4,	501,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x108ULL },  // LIS8
    { 1420,	2,	1,	4,	501,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x108ULL },  // LIS
    { 1419,	2,	1,	4,	501,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x108ULL },  // LI8
    { 1418,	2,	1,	4,	501,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x108ULL },  // LI
    { 1417,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 583,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LHZXTLS_32
    { 1416,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LHZXTLS_
    { 1415,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LHZXTLS
    { 1414,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad), 0x350ULL },  // LHZX8
    { 1413,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad), 0x350ULL },  // LHZX
    { 1412,	4,	2,	4,	358,	0,	0,	PPCOpInfoBase + 573,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LHZUX8
    { 1411,	4,	2,	4,	358,	0,	0,	PPCOpInfoBase + 569,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LHZUX
    { 1410,	4,	2,	4,	357,	0,	0,	PPCOpInfoBase + 565,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LHZU8
    { 1409,	4,	2,	4,	357,	0,	0,	PPCOpInfoBase + 561,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LHZU
    { 1408,	3,	1,	4,	559,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LHZCIX
    { 1407,	3,	1,	4,	544,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayLoad), 0x710ULL },  // LHZ8
    { 1406,	3,	1,	4,	544,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayLoad), 0x710ULL },  // LHZ
    { 1405,	3,	1,	4,	227,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LHEPX
    { 1404,	3,	1,	4,	113,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad), 0x250ULL },  // LHBRX8
    { 1403,	3,	1,	4,	113,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad), 0x250ULL },  // LHBRX
    { 1402,	3,	1,	4,	224,	0,	0,	PPCOpInfoBase + 583,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LHAXTLS_32
    { 1401,	3,	1,	4,	224,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LHAXTLS_
    { 1400,	3,	1,	4,	224,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LHAXTLS
    { 1399,	3,	1,	4,	125,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad), 0x154ULL },  // LHAX8
    { 1398,	3,	1,	4,	125,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad), 0x154ULL },  // LHAX
    { 1397,	4,	2,	4,	128,	0,	0,	PPCOpInfoBase + 573,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LHAUX8
    { 1396,	4,	2,	4,	128,	0,	0,	PPCOpInfoBase + 569,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LHAUX
    { 1395,	4,	2,	4,	127,	0,	0,	PPCOpInfoBase + 565,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LHAU8
    { 1394,	4,	2,	4,	127,	0,	0,	PPCOpInfoBase + 561,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LHAU
    { 1393,	3,	1,	4,	226,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LHARXL
    { 1392,	3,	1,	4,	119,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LHARX
    { 1391,	3,	1,	4,	550,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayLoad), 0x514ULL },  // LHA8
    { 1390,	3,	1,	4,	550,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayLoad), 0x514ULL },  // LHA
    { 1389,	3,	1,	4,	364,	0,	0,	PPCOpInfoBase + 633,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LFSXTLS_
    { 1388,	3,	1,	4,	364,	0,	0,	PPCOpInfoBase + 633,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LFSXTLS
    { 1387,	3,	1,	4,	364,	0,	0,	PPCOpInfoBase + 630,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LFSX
    { 1386,	4,	2,	4,	404,	0,	0,	PPCOpInfoBase + 626,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LFSUX
    { 1385,	4,	2,	4,	403,	0,	0,	PPCOpInfoBase + 622,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LFSU
    { 1384,	3,	1,	4,	561,	0,	0,	PPCOpInfoBase + 619,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LFS
    { 1383,	3,	1,	4,	349,	0,	0,	PPCOpInfoBase + 605,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LFIWZX
    { 1382,	3,	1,	4,	121,	0,	0,	PPCOpInfoBase + 605,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LFIWAX
    { 1381,	3,	1,	4,	350,	0,	0,	PPCOpInfoBase + 616,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LFDXTLS_
    { 1380,	3,	1,	4,	350,	0,	0,	PPCOpInfoBase + 616,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LFDXTLS
    { 1379,	3,	1,	4,	350,	0,	0,	PPCOpInfoBase + 605,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LFDX
    { 1378,	4,	2,	4,	117,	0,	0,	PPCOpInfoBase + 612,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LFDUX
    { 1377,	4,	2,	4,	116,	0,	0,	PPCOpInfoBase + 608,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LFDU
    { 1376,	3,	1,	4,	228,	0,	0,	PPCOpInfoBase + 605,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LFDEPX
    { 1375,	3,	1,	4,	549,	0,	0,	PPCOpInfoBase + 602,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LFD
    { 1374,	3,	1,	4,	546,	0,	0,	PPCOpInfoBase + 599,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDtocL
    { 1373,	3,	1,	4,	546,	0,	0,	PPCOpInfoBase + 596,	0,	0|(1ULL<<MCID::MayLoad), 0x10ULL },  // LDtocJTI
    { 1372,	3,	1,	4,	546,	0,	0,	PPCOpInfoBase + 596,	0,	0|(1ULL<<MCID::MayLoad), 0x10ULL },  // LDtocCPT
    { 1371,	3,	1,	4,	546,	0,	0,	PPCOpInfoBase + 596,	0,	0|(1ULL<<MCID::MayLoad), 0x10ULL },  // LDtocBA
    { 1370,	3,	1,	4,	546,	0,	0,	PPCOpInfoBase + 596,	0,	0|(1ULL<<MCID::MayLoad), 0x10ULL },  // LDtoc
    { 1369,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 593,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDgotTprelL32
    { 1368,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 590,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDgotTprelL
    { 1367,	3,	1,	4,	225,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LDXTLS_
    { 1366,	3,	1,	4,	225,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LDXTLS
    { 1365,	3,	1,	4,	225,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LDX
    { 1364,	4,	2,	4,	139,	0,	0,	PPCOpInfoBase + 573,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LDUX
    { 1363,	4,	2,	4,	137,	0,	0,	PPCOpInfoBase + 565,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LDU
    { 1362,	3,	1,	4,	559,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LDCIX
    { 1361,	3,	1,	4,	554,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LDBRX
    { 1360,	2,	1,	4,	15,	0,	0,	PPCOpInfoBase + 202,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq), 0x40ULL },  // LDAT_CSNE
    { 1359,	4,	1,	4,	406,	0,	0,	PPCOpInfoBase + 586,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x40ULL },  // LDAT
    { 1358,	3,	1,	4,	112,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDARXL
    { 1357,	3,	1,	4,	112,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LDARX
    { 1356,	3,	1,	4,	545,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LD
    { 1355,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 583,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LBZXTLS_32
    { 1354,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LBZXTLS_
    { 1353,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 580,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // LBZXTLS
    { 1352,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 577,	0,	0|(1ULL<<MCID::MayLoad), 0x350ULL },  // LBZX8
    { 1351,	3,	1,	4,	342,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad), 0x350ULL },  // LBZX
    { 1350,	4,	2,	4,	138,	0,	0,	PPCOpInfoBase + 573,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LBZUX8
    { 1349,	4,	2,	4,	138,	0,	0,	PPCOpInfoBase + 569,	0,	0|(1ULL<<MCID::MayLoad), 0x50ULL },  // LBZUX
    { 1348,	4,	2,	4,	136,	0,	0,	PPCOpInfoBase + 565,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LBZU8
    { 1347,	4,	2,	4,	136,	0,	0,	PPCOpInfoBase + 561,	0,	0|(1ULL<<MCID::MayLoad), 0x410ULL },  // LBZU
    { 1346,	3,	1,	4,	559,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LBZCIX
    { 1345,	3,	1,	4,	544,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayLoad), 0x710ULL },  // LBZ8
    { 1344,	3,	1,	4,	544,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayLoad), 0x710ULL },  // LBZ
    { 1343,	3,	1,	4,	227,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LBEPX
    { 1342,	3,	1,	4,	226,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LBARXL
    { 1341,	3,	1,	4,	119,	0,	0,	PPCOpInfoBase + 558,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // LBARX
    { 1340,	3,	1,	4,	291,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x408ULL },  // LA8
    { 1339,	3,	1,	4,	291,	0,	0,	PPCOpInfoBase + 248,	0,	0, 0x408ULL },  // LA
    { 1338,	0,	0,	4,	345,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ISYNC
    { 1337,	4,	1,	4,	209,	0,	0,	PPCOpInfoBase + 554,	0,	0|(1ULL<<MCID::Select), 0x8ULL },  // ISEL8
    { 1336,	4,	1,	4,	209,	0,	0,	PPCOpInfoBase + 550,	0,	0|(1ULL<<MCID::Select), 0x8ULL },  // ISEL
    { 1335,	2,	0,	4,	623,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICCCI
    { 1334,	3,	0,	4,	341,	0,	0,	PPCOpInfoBase + 347,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICBTLS
    { 1333,	3,	0,	4,	553,	0,	0,	PPCOpInfoBase + 347,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICBT
    { 1332,	3,	0,	4,	623,	0,	0,	PPCOpInfoBase + 347,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICBLQ
    { 1331,	3,	0,	4,	417,	0,	0,	PPCOpInfoBase + 347,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICBLC
    { 1330,	2,	0,	4,	340,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICBIEP
    { 1329,	2,	0,	4,	610,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICBI
    { 1328,	0,	0,	4,	539,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // HRFID
    { 1327,	3,	0,	4,	456,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // HASHSTP8
    { 1326,	3,	0,	4,	456,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // HASHSTP
    { 1325,	3,	0,	4,	456,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // HASHST8
    { 1324,	3,	0,	4,	456,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // HASHST
    { 1323,	3,	0,	4,	424,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // HASHCHKP8
    { 1322,	3,	0,	4,	424,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // HASHCHKP
    { 1321,	3,	0,	4,	424,	0,	0,	PPCOpInfoBase + 547,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // HASHCHK8
    { 1320,	3,	0,	4,	424,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // HASHCHK
    { 1319,	3,	1,	4,	0,	0,	18,	PPCOpInfoBase + 237,	211,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsldADDRPCREL
    { 1318,	3,	1,	4,	0,	0,	17,	PPCOpInfoBase + 228,	182,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsldADDR32
    { 1317,	3,	1,	8,	0,	0,	17,	PPCOpInfoBase + 237,	165,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsldADDR
    { 1316,	1,	1,	4,	0,	0,	2,	PPCOpInfoBase + 170,	229,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsTpointer32AIX
    { 1315,	2,	1,	4,	0,	0,	6,	PPCOpInfoBase + 264,	205,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsMOD64AIX
    { 1314,	2,	1,	4,	0,	0,	6,	PPCOpInfoBase + 262,	199,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsMOD32AIX
    { 1313,	3,	1,	4,	0,	0,	18,	PPCOpInfoBase + 237,	211,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsADDRPCREL
    { 1312,	3,	1,	4,	0,	0,	6,	PPCOpInfoBase + 231,	205,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsADDR64AIX
    { 1311,	3,	1,	4,	0,	0,	6,	PPCOpInfoBase + 225,	199,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsADDR32AIX
    { 1310,	3,	1,	4,	0,	0,	17,	PPCOpInfoBase + 228,	182,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsADDR32
    { 1309,	3,	1,	8,	0,	0,	17,	PPCOpInfoBase + 237,	165,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GETtlsADDR
    { 1308,	2,	1,	4,	473,	0,	0,	PPCOpInfoBase + 545,	0,	0, 0x18ULL },  // FTSQRT
    { 1307,	3,	1,	4,	278,	0,	0,	PPCOpInfoBase + 356,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x18ULL },  // FTDIV
    { 1306,	3,	1,	4,	159,	1,	1,	PPCOpInfoBase + 341,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FSUB_rec
    { 1305,	3,	1,	4,	445,	1,	1,	PPCOpInfoBase + 525,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FSUBS_rec
    { 1304,	3,	1,	4,	438,	1,	0,	PPCOpInfoBase + 525,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FSUBS
    { 1303,	3,	1,	4,	318,	1,	0,	PPCOpInfoBase + 341,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FSUB
    { 1302,	2,	1,	4,	178,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FSQRT_rec
    { 1301,	2,	1,	4,	186,	1,	1,	PPCOpInfoBase + 523,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FSQRTS_rec
    { 1300,	2,	1,	4,	401,	1,	0,	PPCOpInfoBase + 523,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FSQRTS
    { 1299,	2,	1,	4,	400,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FSQRT
    { 1298,	4,	1,	4,	321,	0,	1,	PPCOpInfoBase + 541,	159,	0, 0x18ULL },  // FSELS_rec
    { 1297,	4,	1,	4,	317,	0,	0,	PPCOpInfoBase + 541,	0,	0, 0x18ULL },  // FSELS
    { 1296,	4,	1,	4,	321,	0,	1,	PPCOpInfoBase + 533,	159,	0, 0x18ULL },  // FSELD_rec
    { 1295,	4,	1,	4,	317,	0,	0,	PPCOpInfoBase + 533,	0,	0, 0x18ULL },  // FSELD
    { 1294,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRSQRTE_rec
    { 1293,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 523,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRSQRTES_rec
    { 1292,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 523,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRSQRTES
    { 1291,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRSQRTE
    { 1290,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 528,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRSP_rec
    { 1289,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 528,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRSP
    { 1288,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 523,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIZS_rec
    { 1287,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 523,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIZS
    { 1286,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIZD_rec
    { 1285,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIZD
    { 1284,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 523,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIPS_rec
    { 1283,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 523,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIPS
    { 1282,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIPD_rec
    { 1281,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIPD
    { 1280,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 523,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRINS_rec
    { 1279,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 523,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRINS
    { 1278,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIND_rec
    { 1277,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIND
    { 1276,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 523,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIMS_rec
    { 1275,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 523,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIMS
    { 1274,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIMD_rec
    { 1273,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRIMD
    { 1272,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRE_rec
    { 1271,	2,	1,	4,	447,	0,	1,	PPCOpInfoBase + 523,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRES_rec
    { 1270,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 523,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRES
    { 1269,	2,	1,	4,	430,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FRE
    { 1268,	4,	1,	4,	160,	1,	1,	PPCOpInfoBase + 533,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FNMSUB_rec
    { 1267,	4,	1,	4,	322,	1,	1,	PPCOpInfoBase + 537,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FNMSUBS_rec
    { 1266,	4,	1,	4,	317,	1,	0,	PPCOpInfoBase + 537,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FNMSUBS
    { 1265,	4,	1,	4,	319,	1,	0,	PPCOpInfoBase + 533,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FNMSUB
    { 1264,	4,	1,	4,	160,	1,	1,	PPCOpInfoBase + 533,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FNMADD_rec
    { 1263,	4,	1,	4,	322,	1,	1,	PPCOpInfoBase + 537,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FNMADDS_rec
    { 1262,	4,	1,	4,	317,	1,	0,	PPCOpInfoBase + 537,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FNMADDS
    { 1261,	4,	1,	4,	319,	1,	0,	PPCOpInfoBase + 533,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FNMADD
    { 1260,	2,	1,	4,	541,	0,	1,	PPCOpInfoBase + 523,	159,	0, 0x18ULL },  // FNEGS_rec
    { 1259,	2,	1,	4,	511,	0,	0,	PPCOpInfoBase + 523,	0,	0, 0x18ULL },  // FNEGS
    { 1258,	2,	1,	4,	541,	0,	1,	PPCOpInfoBase + 350,	159,	0, 0x18ULL },  // FNEGD_rec
    { 1257,	2,	1,	4,	511,	0,	0,	PPCOpInfoBase + 350,	0,	0, 0x18ULL },  // FNEGD
    { 1256,	2,	1,	4,	541,	0,	1,	PPCOpInfoBase + 523,	159,	0, 0x18ULL },  // FNABSS_rec
    { 1255,	2,	1,	4,	511,	0,	0,	PPCOpInfoBase + 523,	0,	0, 0x18ULL },  // FNABSS
    { 1254,	2,	1,	4,	541,	0,	1,	PPCOpInfoBase + 350,	159,	0, 0x18ULL },  // FNABSD_rec
    { 1253,	2,	1,	4,	511,	0,	0,	PPCOpInfoBase + 350,	0,	0, 0x18ULL },  // FNABSD
    { 1252,	3,	1,	4,	446,	1,	1,	PPCOpInfoBase + 341,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMUL_rec
    { 1251,	3,	1,	4,	445,	1,	1,	PPCOpInfoBase + 525,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMULS_rec
    { 1250,	3,	1,	4,	438,	1,	0,	PPCOpInfoBase + 525,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMULS
    { 1249,	3,	1,	4,	439,	1,	0,	PPCOpInfoBase + 341,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMUL
    { 1248,	4,	1,	4,	160,	1,	1,	PPCOpInfoBase + 533,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMSUB_rec
    { 1247,	4,	1,	4,	322,	1,	1,	PPCOpInfoBase + 537,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMSUBS_rec
    { 1246,	4,	1,	4,	317,	1,	0,	PPCOpInfoBase + 537,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMSUBS
    { 1245,	4,	1,	4,	319,	1,	0,	PPCOpInfoBase + 533,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMSUB
    { 1244,	2,	1,	4,	541,	0,	1,	PPCOpInfoBase + 523,	159,	0, 0x0ULL },  // FMR_rec
    { 1243,	2,	1,	4,	511,	0,	0,	PPCOpInfoBase + 523,	0,	0, 0x0ULL },  // FMR
    { 1242,	4,	1,	4,	160,	1,	1,	PPCOpInfoBase + 533,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMADD_rec
    { 1241,	4,	1,	4,	322,	1,	1,	PPCOpInfoBase + 537,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMADDS_rec
    { 1240,	4,	1,	4,	317,	1,	0,	PPCOpInfoBase + 537,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMADDS
    { 1239,	4,	1,	4,	319,	1,	0,	PPCOpInfoBase + 533,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FMADD
    { 1238,	0,	0,	4,	0,	0,	1,	PPCOpInfoBase + 1,	162,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FENCE
    { 1237,	3,	1,	4,	176,	1,	1,	PPCOpInfoBase + 341,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FDIV_rec
    { 1236,	3,	1,	4,	173,	1,	1,	PPCOpInfoBase + 525,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FDIVS_rec
    { 1235,	3,	1,	4,	402,	1,	0,	PPCOpInfoBase + 525,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FDIVS
    { 1234,	3,	1,	4,	399,	1,	0,	PPCOpInfoBase + 341,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FDIV
    { 1233,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIW_rec
    { 1232,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIWZ_rec
    { 1231,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIWZ
    { 1230,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIWU_rec
    { 1229,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIWUZ_rec
    { 1228,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIWUZ
    { 1227,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIWU
    { 1226,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIW
    { 1225,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTID_rec
    { 1224,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIDZ_rec
    { 1223,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIDZ
    { 1222,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIDU_rec
    { 1221,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIDUZ_rec
    { 1220,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIDUZ
    { 1219,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTIDU
    { 1218,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCTID
    { 1217,	3,	1,	4,	158,	0,	1,	PPCOpInfoBase + 525,	159,	0, 0x18ULL },  // FCPSGNS_rec
    { 1216,	3,	1,	4,	303,	0,	0,	PPCOpInfoBase + 525,	0,	0, 0x18ULL },  // FCPSGNS
    { 1215,	3,	1,	4,	158,	0,	1,	PPCOpInfoBase + 341,	159,	0, 0x18ULL },  // FCPSGND_rec
    { 1214,	3,	1,	4,	303,	0,	0,	PPCOpInfoBase + 341,	0,	0, 0x18ULL },  // FCPSGND
    { 1213,	3,	1,	4,	172,	0,	0,	PPCOpInfoBase + 530,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCMPUS
    { 1212,	3,	1,	4,	172,	0,	0,	PPCOpInfoBase + 356,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCMPUD
    { 1211,	3,	1,	4,	172,	0,	0,	PPCOpInfoBase + 530,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCMPOS
    { 1210,	3,	1,	4,	172,	0,	0,	PPCOpInfoBase + 356,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCMPOD
    { 1209,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCFID_rec
    { 1208,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 350,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCFIDU_rec
    { 1207,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 528,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCFIDUS_rec
    { 1206,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 528,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCFIDUS
    { 1205,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCFIDU
    { 1204,	2,	1,	4,	447,	1,	1,	PPCOpInfoBase + 528,	163,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCFIDS_rec
    { 1203,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 528,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCFIDS
    { 1202,	2,	1,	4,	430,	1,	0,	PPCOpInfoBase + 350,	162,	0|(1ULL<<MCID::MayRaiseFPException), 0x18ULL },  // FCFID
    { 1201,	3,	1,	4,	0,	1,	0,	PPCOpInfoBase + 341,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // FADDrtz
    { 1200,	3,	1,	4,	159,	1,	1,	PPCOpInfoBase + 341,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FADD_rec
    { 1199,	3,	1,	4,	445,	1,	1,	PPCOpInfoBase + 525,	163,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FADDS_rec
    { 1198,	3,	1,	4,	438,	1,	0,	PPCOpInfoBase + 525,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FADDS
    { 1197,	3,	1,	4,	318,	1,	0,	PPCOpInfoBase + 341,	162,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x18ULL },  // FADD
    { 1196,	2,	1,	4,	541,	0,	1,	PPCOpInfoBase + 523,	159,	0, 0x18ULL },  // FABSS_rec
    { 1195,	2,	1,	4,	511,	0,	0,	PPCOpInfoBase + 523,	0,	0, 0x18ULL },  // FABSS
    { 1194,	2,	1,	4,	541,	0,	1,	PPCOpInfoBase + 350,	159,	0, 0x18ULL },  // FABSD_rec
    { 1193,	2,	1,	4,	511,	0,	0,	PPCOpInfoBase + 350,	0,	0, 0x18ULL },  // FABSD
    { 1192,	0,	0,	4,	614,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EnforceIEIO
    { 1191,	2,	1,	4,	510,	0,	1,	PPCOpInfoBase + 264,	0,	0, 0x108ULL },  // EXTSW_rec
    { 1190,	2,	1,	4,	510,	0,	1,	PPCOpInfoBase + 518,	0,	0, 0x108ULL },  // EXTSW_32_64_rec
    { 1189,	2,	1,	4,	510,	0,	0,	PPCOpInfoBase + 518,	0,	0, 0x108ULL },  // EXTSW_32_64
    { 1188,	2,	1,	4,	510,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x8ULL },  // EXTSW_32
    { 1187,	3,	1,	4,	398,	0,	2,	PPCOpInfoBase + 180,	21,	0, 0x8ULL },  // EXTSWSLI_rec
    { 1186,	3,	1,	4,	398,	0,	1,	PPCOpInfoBase + 520,	0,	0, 0x8ULL },  // EXTSWSLI_32_64_rec
    { 1185,	3,	1,	4,	287,	0,	0,	PPCOpInfoBase + 520,	0,	0, 0x8ULL },  // EXTSWSLI_32_64
    { 1184,	3,	1,	4,	287,	0,	1,	PPCOpInfoBase + 180,	15,	0, 0x8ULL },  // EXTSWSLI
    { 1183,	2,	1,	4,	510,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x108ULL },  // EXTSW
    { 1182,	2,	1,	4,	510,	0,	1,	PPCOpInfoBase + 262,	0,	0, 0x108ULL },  // EXTSH_rec
    { 1181,	2,	1,	4,	510,	0,	1,	PPCOpInfoBase + 264,	0,	0, 0x108ULL },  // EXTSH8_rec
    { 1180,	2,	1,	4,	510,	0,	0,	PPCOpInfoBase + 518,	0,	0, 0x108ULL },  // EXTSH8_32_64
    { 1179,	2,	1,	4,	510,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x108ULL },  // EXTSH8
    { 1178,	2,	1,	4,	510,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x108ULL },  // EXTSH
    { 1177,	2,	1,	4,	510,	0,	1,	PPCOpInfoBase + 262,	0,	0, 0x108ULL },  // EXTSB_rec
    { 1176,	2,	1,	4,	510,	0,	1,	PPCOpInfoBase + 264,	0,	0, 0x108ULL },  // EXTSB8_rec
    { 1175,	2,	1,	4,	510,	0,	0,	PPCOpInfoBase + 518,	0,	0, 0x108ULL },  // EXTSB8_32_64
    { 1174,	2,	1,	4,	510,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x108ULL },  // EXTSB8
    { 1173,	2,	1,	4,	510,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x108ULL },  // EXTSB
    { 1172,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVXOR
    { 1171,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 515,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSUBIFW
    { 1170,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSUBFW
    { 1169,	2,	1,	4,	410,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSUBFUSIAAW
    { 1168,	2,	1,	4,	410,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSUBFUMIAAW
    { 1167,	2,	1,	4,	410,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSUBFSSIAAW
    { 1166,	2,	1,	4,	410,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSUBFSMIAAW
    { 1165,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSTWWOX
    { 1164,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVSTWWO
    { 1163,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSTWWEX
    { 1162,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVSTWWE
    { 1161,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSTWHOX
    { 1160,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVSTWHO
    { 1159,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSTWHEX
    { 1158,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVSTWHE
    { 1157,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSTDWX
    { 1156,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVSTDW
    { 1155,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSTDHX
    { 1154,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVSTDH
    { 1153,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // EVSTDDX
    { 1152,	3,	0,	4,	412,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::MayStore), 0x400ULL },  // EVSTDD
    { 1151,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSRWU
    { 1150,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSRWS
    { 1149,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 497,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSRWIU
    { 1148,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 497,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSRWIS
    { 1147,	2,	1,	4,	409,	0,	0,	PPCOpInfoBase + 513,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSPLATI
    { 1146,	2,	1,	4,	409,	0,	0,	PPCOpInfoBase + 513,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSPLATFI
    { 1145,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 497,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSLWI
    { 1144,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSLW
    { 1143,	4,	1,	4,	19,	0,	0,	PPCOpInfoBase + 509,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVSEL
    { 1142,	2,	1,	4,	409,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVRNDW
    { 1141,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 497,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVRLWI
    { 1140,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVRLW
    { 1139,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVORC
    { 1138,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVOR
    { 1137,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVNOR
    { 1136,	2,	1,	4,	409,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVNEG
    { 1135,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVNAND
    { 1134,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWUMIAN
    { 1133,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWUMIAA
    { 1132,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWUMIA
    { 1131,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWUMI
    { 1130,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSSFAN
    { 1129,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSSFAA
    { 1128,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSSFA
    { 1127,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSSF
    { 1126,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSMIAN
    { 1125,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSMIAA
    { 1124,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSMIA
    { 1123,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSMI
    { 1122,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSMFAN
    { 1121,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSMFAA
    { 1120,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSMFA
    { 1119,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWSMF
    { 1118,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWLUSIANW
    { 1117,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWLUSIAAW
    { 1116,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWLUMIANW
    { 1115,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWLUMIAAW
    { 1114,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWLUMIA
    { 1113,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWLUMI
    { 1112,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWLSSIANW
    { 1111,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWLSSIAAW
    { 1110,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWLSMIANW
    { 1109,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWLSMIAAW
    { 1108,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWHUMIA
    { 1107,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWHUMI
    { 1106,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWHSSFA
    { 1105,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWHSSF
    { 1104,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWHSMIA
    { 1103,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWHSMI
    { 1102,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWHSMFA
    { 1101,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMWHSMF
    { 1100,	2,	1,	4,	410,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMRA
    { 1099,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOUSIANW
    { 1098,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOUSIAAW
    { 1097,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOUMIANW
    { 1096,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOUMIAAW
    { 1095,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOUMIA
    { 1094,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOUMI
    { 1093,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSSIANW
    { 1092,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSSIAAW
    { 1091,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSSFANW
    { 1090,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSSFAAW
    { 1089,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSSFA
    { 1088,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSSF
    { 1087,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSMIANW
    { 1086,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSMIAAW
    { 1085,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSMIA
    { 1084,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSMI
    { 1083,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSMFANW
    { 1082,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSMFAAW
    { 1081,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSMFA
    { 1080,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOSMF
    { 1079,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOGUMIAN
    { 1078,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOGUMIAA
    { 1077,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOGSMIAN
    { 1076,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOGSMIAA
    { 1075,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOGSMFAN
    { 1074,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHOGSMFAA
    { 1073,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEUSIANW
    { 1072,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEUSIAAW
    { 1071,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEUMIANW
    { 1070,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEUMIAAW
    { 1069,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEUMIA
    { 1068,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEUMI
    { 1067,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESSIANW
    { 1066,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESSIAAW
    { 1065,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESSFANW
    { 1064,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESSFAAW
    { 1063,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESSFA
    { 1062,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESSF
    { 1061,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESMIANW
    { 1060,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESMIAAW
    { 1059,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESMIA
    { 1058,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESMI
    { 1057,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESMFANW
    { 1056,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESMFAAW
    { 1055,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESMFA
    { 1054,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHESMF
    { 1053,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEGUMIAN
    { 1052,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEGUMIAA
    { 1051,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEGSMIAN
    { 1050,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEGSMIAA
    { 1049,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEGSMFAN
    { 1048,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMHEGSMFAA
    { 1047,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMERGELOHI
    { 1046,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 506,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMERGELO
    { 1045,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMERGEHILO
    { 1044,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVMERGEHI
    { 1043,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVLWWSPLATX
    { 1042,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVLWWSPLAT
    { 1041,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVLWHSPLATX
    { 1040,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVLWHSPLAT
    { 1039,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVLWHOUX
    { 1038,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVLWHOU
    { 1037,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVLWHOSX
    { 1036,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVLWHOS
    { 1035,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVLWHEX
    { 1034,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVLWHE
    { 1033,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVLHHOUSPLATX
    { 1032,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVLHHOUSPLAT
    { 1031,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVLHHOSSPLATX
    { 1030,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVLHHOSSPLAT
    { 1029,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVLHHESPLATX
    { 1028,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVLHHESPLAT
    { 1027,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVLDWX
    { 1026,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVLDW
    { 1025,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVLDHX
    { 1024,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // EVLDH
    { 1023,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 503,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // EVLDDX
    { 1022,	3,	1,	4,	411,	0,	0,	PPCOpInfoBase + 500,	0,	0|(1ULL<<MCID::MayLoad), 0x400ULL },  // EVLDD
    { 1021,	3,	1,	4,	19,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSTSTLT
    { 1020,	3,	1,	4,	19,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSTSTGT
    { 1019,	3,	1,	4,	19,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSTSTEQ
    { 1018,	3,	1,	4,	24,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSSUB
    { 1017,	2,	1,	4,	19,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSNEG
    { 1016,	2,	1,	4,	19,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSNABS
    { 1015,	3,	1,	4,	24,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSMUL
    { 1014,	3,	1,	4,	22,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSDIV
    { 1013,	2,	1,	4,	24,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCTUIZ
    { 1012,	2,	1,	4,	24,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCTUI
    { 1011,	2,	1,	4,	24,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCTUF
    { 1010,	2,	1,	4,	24,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCTSIZ
    { 1009,	2,	1,	4,	24,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCTSI
    { 1008,	2,	1,	4,	24,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCTSF
    { 1007,	3,	1,	4,	23,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCMPLT
    { 1006,	3,	1,	4,	23,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCMPGT
    { 1005,	3,	1,	4,	23,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCMPEQ
    { 1004,	2,	1,	4,	24,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCFUI
    { 1003,	2,	1,	4,	24,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCFUF
    { 1002,	2,	1,	4,	24,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCFSI
    { 1001,	2,	1,	4,	24,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSCFSF
    { 1000,	3,	1,	4,	24,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSADD
    { 999,	2,	1,	4,	19,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVFSABS
    { 998,	2,	1,	4,	409,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVEXTSH
    { 997,	2,	1,	4,	409,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVEXTSB
    { 996,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVEQV
    { 995,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVDIVWU
    { 994,	3,	1,	4,	410,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVDIVWS
    { 993,	2,	1,	4,	409,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVCNTLZW
    { 992,	2,	1,	4,	409,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVCNTLSW
    { 991,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVCMPLTU
    { 990,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVCMPLTS
    { 989,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVCMPGTU
    { 988,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVCMPGTS
    { 987,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVCMPEQ
    { 986,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVANDC
    { 985,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVAND
    { 984,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 484,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVADDW
    { 983,	2,	1,	4,	410,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVADDUSIAAW
    { 982,	2,	1,	4,	410,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVADDUMIAAW
    { 981,	2,	1,	4,	410,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVADDSSIAAW
    { 980,	2,	1,	4,	410,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVADDSMIAAW
    { 979,	3,	1,	4,	409,	0,	0,	PPCOpInfoBase + 497,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVADDIW
    { 978,	2,	1,	4,	409,	0,	0,	PPCOpInfoBase + 482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EVABS
    { 977,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // EQV_rec
    { 976,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // EQV8_rec
    { 975,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // EQV8
    { 974,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // EQV
    { 973,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 290,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EH_SjLj_Setup
    { 972,	2,	1,	4,	0,	0,	1,	PPCOpInfoBase + 495,	74,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EH_SjLj_SetJmp64
    { 971,	2,	1,	4,	0,	0,	1,	PPCOpInfoBase + 495,	73,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EH_SjLj_SetJmp32
    { 970,	1,	0,	4,	0,	0,	0,	PPCOpInfoBase + 494,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EH_SjLj_LongJmp64
    { 969,	1,	0,	4,	0,	0,	0,	PPCOpInfoBase + 494,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EH_SjLj_LongJmp32
    { 968,	3,	1,	4,	16,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSTSTLT
    { 967,	3,	1,	4,	16,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSTSTGT
    { 966,	3,	1,	4,	16,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSTSTEQ
    { 965,	3,	1,	4,	23,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x0ULL },  // EFSSUB
    { 964,	2,	1,	4,	12,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // EFSNEG
    { 963,	2,	1,	4,	12,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // EFSNABS
    { 962,	3,	1,	4,	12,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x0ULL },  // EFSMUL
    { 961,	3,	1,	4,	22,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x0ULL },  // EFSDIV
    { 960,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // EFSCTUIZ
    { 959,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSCTUI
    { 958,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 487,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSCTUF
    { 957,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // EFSCTSIZ
    { 956,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSCTSI
    { 955,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSCTSF
    { 954,	3,	1,	4,	16,	0,	0,	PPCOpInfoBase + 322,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSCMPLT
    { 953,	3,	1,	4,	16,	0,	0,	PPCOpInfoBase + 322,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSCMPGT
    { 952,	3,	1,	4,	16,	0,	0,	PPCOpInfoBase + 322,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSCMPEQ
    { 951,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // EFSCFUI
    { 950,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSCFUF
    { 949,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // EFSCFSI
    { 948,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFSCFSF
    { 947,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 492,	0,	0, 0x0ULL },  // EFSCFD
    { 946,	3,	1,	4,	21,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x0ULL },  // EFSADD
    { 945,	2,	1,	4,	23,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // EFSABS
    { 944,	3,	1,	4,	20,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDTSTLT
    { 943,	3,	1,	4,	20,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDTSTGT
    { 942,	3,	1,	4,	20,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDTSTEQ
    { 941,	3,	1,	4,	20,	0,	0,	PPCOpInfoBase + 484,	0,	0, 0x0ULL },  // EFDSUB
    { 940,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 482,	0,	0, 0x0ULL },  // EFDNEG
    { 939,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 482,	0,	0, 0x0ULL },  // EFDNABS
    { 938,	3,	1,	4,	20,	0,	0,	PPCOpInfoBase + 484,	0,	0, 0x0ULL },  // EFDMUL
    { 937,	3,	1,	4,	22,	0,	0,	PPCOpInfoBase + 484,	0,	0, 0x0ULL },  // EFDDIV
    { 936,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 492,	0,	0, 0x0ULL },  // EFDCTUIZ
    { 935,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 492,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCTUIDZ
    { 934,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 492,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCTUI
    { 933,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 487,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCTUF
    { 932,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 492,	0,	0, 0x0ULL },  // EFDCTSIZ
    { 931,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 492,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCTSIDZ
    { 930,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 492,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCTSI
    { 929,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 487,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCTSF
    { 928,	3,	1,	4,	20,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCMPLT
    { 927,	3,	1,	4,	20,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCMPGT
    { 926,	3,	1,	4,	20,	0,	0,	PPCOpInfoBase + 489,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCMPEQ
    { 925,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 487,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCFUID
    { 924,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 487,	0,	0, 0x0ULL },  // EFDCFUI
    { 923,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 487,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCFUF
    { 922,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 487,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCFSID
    { 921,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 487,	0,	0, 0x0ULL },  // EFDCFSI
    { 920,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 487,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFDCFSF
    { 919,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 487,	0,	0, 0x0ULL },  // EFDCFS
    { 918,	3,	1,	4,	21,	0,	0,	PPCOpInfoBase + 484,	0,	0, 0x0ULL },  // EFDADD
    { 917,	2,	1,	4,	20,	0,	0,	PPCOpInfoBase + 482,	0,	0, 0x0ULL },  // EFDABS
    { 916,	2,	1,	4,	0,	1,	1,	PPCOpInfoBase + 480,	115,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DecreaseCTRloop
    { 915,	2,	1,	4,	0,	1,	1,	PPCOpInfoBase + 480,	117,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DecreaseCTR8loop
    { 914,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 477,	0,	0, 0x0ULL },  // DYNAREAOFFSET8
    { 913,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 477,	0,	0, 0x0ULL },  // DYNAREAOFFSET
    { 912,	4,	1,	4,	0,	1,	1,	PPCOpInfoBase + 473,	160,	0, 0x0ULL },  // DYNALLOC8
    { 911,	4,	1,	4,	0,	1,	1,	PPCOpInfoBase + 469,	71,	0, 0x0ULL },  // DYNALLOC
    { 910,	2,	1,	4,	246,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DXEX_rec
    { 909,	2,	1,	4,	246,	0,	1,	PPCOpInfoBase + 362,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DXEXQ_rec
    { 908,	2,	1,	4,	246,	0,	0,	PPCOpInfoBase + 362,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DXEXQ
    { 907,	2,	1,	4,	246,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DXEX
    { 906,	3,	1,	4,	245,	0,	0,	PPCOpInfoBase + 466,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DTSTSFQ
    { 905,	3,	1,	4,	16,	0,	0,	PPCOpInfoBase + 463,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DTSTSFIQ
    { 904,	3,	1,	4,	16,	0,	0,	PPCOpInfoBase + 460,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DTSTSFI
    { 903,	3,	1,	4,	245,	0,	0,	PPCOpInfoBase + 356,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DTSTSF
    { 902,	3,	1,	4,	250,	0,	0,	PPCOpInfoBase + 359,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DTSTEXQ
    { 901,	3,	1,	4,	245,	0,	0,	PPCOpInfoBase + 356,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DTSTEX
    { 900,	3,	1,	4,	245,	0,	0,	PPCOpInfoBase + 457,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DTSTDGQ
    { 899,	3,	1,	4,	245,	0,	0,	PPCOpInfoBase + 454,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DTSTDG
    { 898,	3,	1,	4,	245,	0,	0,	PPCOpInfoBase + 457,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DTSTDCQ
    { 897,	3,	1,	4,	245,	0,	0,	PPCOpInfoBase + 454,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DTSTDC
    { 896,	3,	1,	4,	247,	0,	1,	PPCOpInfoBase + 341,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DSUB_rec
    { 895,	3,	1,	4,	252,	0,	1,	PPCOpInfoBase + 344,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DSUBQ_rec
    { 894,	3,	1,	4,	252,	0,	0,	PPCOpInfoBase + 344,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DSUBQ
    { 893,	3,	1,	4,	247,	0,	0,	PPCOpInfoBase + 341,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DSUB
    { 892,	3,	0,	4,	530,	0,	0,	PPCOpInfoBase + 451,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSTT64
    { 891,	3,	0,	4,	530,	0,	0,	PPCOpInfoBase + 448,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSTT
    { 890,	3,	0,	4,	530,	0,	0,	PPCOpInfoBase + 451,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSTSTT64
    { 889,	3,	0,	4,	530,	0,	0,	PPCOpInfoBase + 448,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSTSTT
    { 888,	3,	0,	4,	530,	0,	0,	PPCOpInfoBase + 451,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSTST64
    { 887,	3,	0,	4,	530,	0,	0,	PPCOpInfoBase + 448,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSTST
    { 886,	3,	0,	4,	530,	0,	0,	PPCOpInfoBase + 451,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DST64
    { 885,	3,	0,	4,	530,	0,	0,	PPCOpInfoBase + 448,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DST
    { 884,	0,	0,	4,	499,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSSALL
    { 883,	1,	0,	4,	499,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSS
    { 882,	3,	1,	4,	246,	0,	1,	PPCOpInfoBase + 442,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSCRI_rec
    { 881,	3,	1,	4,	249,	0,	1,	PPCOpInfoBase + 445,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSCRIQ_rec
    { 880,	3,	1,	4,	249,	0,	0,	PPCOpInfoBase + 445,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSCRIQ
    { 879,	3,	1,	4,	246,	0,	0,	PPCOpInfoBase + 442,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSCRI
    { 878,	3,	1,	4,	246,	0,	1,	PPCOpInfoBase + 442,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSCLI_rec
    { 877,	3,	1,	4,	249,	0,	1,	PPCOpInfoBase + 445,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSCLIQ_rec
    { 876,	3,	1,	4,	249,	0,	0,	PPCOpInfoBase + 445,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSCLIQ
    { 875,	3,	1,	4,	246,	0,	0,	PPCOpInfoBase + 442,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSCLI
    { 874,	2,	1,	4,	254,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRSP_rec
    { 873,	2,	1,	4,	254,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRSP
    { 872,	4,	1,	4,	246,	0,	1,	PPCOpInfoBase + 420,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRRND_rec
    { 871,	4,	1,	4,	249,	0,	1,	PPCOpInfoBase + 438,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRRNDQ_rec
    { 870,	4,	1,	4,	249,	0,	0,	PPCOpInfoBase + 438,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRRNDQ
    { 869,	4,	1,	4,	246,	0,	0,	PPCOpInfoBase + 420,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRRND
    { 868,	4,	1,	4,	246,	0,	1,	PPCOpInfoBase + 424,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRINTX_rec
    { 867,	4,	1,	4,	249,	0,	1,	PPCOpInfoBase + 428,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRINTXQ_rec
    { 866,	4,	1,	4,	249,	0,	0,	PPCOpInfoBase + 428,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRINTXQ
    { 865,	4,	1,	4,	246,	0,	0,	PPCOpInfoBase + 424,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRINTX
    { 864,	4,	1,	4,	246,	0,	1,	PPCOpInfoBase + 424,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRINTN_rec
    { 863,	4,	1,	4,	249,	0,	1,	PPCOpInfoBase + 428,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRINTNQ_rec
    { 862,	4,	1,	4,	249,	0,	0,	PPCOpInfoBase + 428,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRINTNQ
    { 861,	4,	1,	4,	246,	0,	0,	PPCOpInfoBase + 424,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRINTN
    { 860,	2,	1,	4,	12,	0,	1,	PPCOpInfoBase + 436,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRDPQ_rec
    { 859,	2,	1,	4,	12,	0,	0,	PPCOpInfoBase + 436,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DRDPQ
    { 858,	4,	1,	4,	246,	0,	1,	PPCOpInfoBase + 420,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DQUA_rec
    { 857,	4,	1,	4,	253,	0,	1,	PPCOpInfoBase + 432,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DQUAQ_rec
    { 856,	4,	1,	4,	253,	0,	0,	PPCOpInfoBase + 432,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DQUAQ
    { 855,	4,	1,	4,	0,	0,	1,	PPCOpInfoBase + 424,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DQUAI_rec
    { 854,	4,	1,	4,	249,	0,	1,	PPCOpInfoBase + 428,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DQUAIQ_rec
    { 853,	4,	1,	4,	249,	0,	0,	PPCOpInfoBase + 428,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DQUAIQ
    { 852,	4,	1,	4,	246,	0,	0,	PPCOpInfoBase + 424,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DQUAI
    { 851,	4,	1,	4,	246,	0,	0,	PPCOpInfoBase + 420,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DQUA
    { 850,	6,	1,	4,	0,	0,	0,	PPCOpInfoBase + 414,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXXSHAPAD
    { 849,	1,	1,	4,	19,	0,	0,	PPCOpInfoBase + 413,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // DMXXSETACCZ
    { 848,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 410,	0,	0, 0x0ULL },  // DMXXINSTDMR512_HI
    { 847,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 407,	0,	0, 0x0ULL },  // DMXXINSTDMR512
    { 846,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 404,	0,	0, 0x0ULL },  // DMXXINSTDMR256
    { 845,	3,	2,	4,	0,	0,	0,	PPCOpInfoBase + 401,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXXEXTFDMR512_HI
    { 844,	3,	2,	4,	0,	0,	0,	PPCOpInfoBase + 398,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXXEXTFDMR512
    { 843,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 395,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXXEXTFDMR256
    { 842,	4,	1,	4,	19,	0,	0,	PPCOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVI8GERX4SPP
    { 841,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVI8GERX4PP
    { 840,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVI8GERX4
    { 839,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVF16GERX2PP
    { 838,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVF16GERX2PN
    { 837,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVF16GERX2NP
    { 836,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVF16GERX2NN
    { 835,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVF16GERX2
    { 834,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVBF16GERX2PP
    { 833,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVBF16GERX2PN
    { 832,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVBF16GERX2NP
    { 831,	4,	1,	4,	5,	0,	0,	PPCOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVBF16GERX2NN
    { 830,	3,	1,	4,	5,	0,	0,	PPCOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DMXVBF16GERX2
    { 829,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 385,	0,	0, 0x0ULL },  // DMXOR
    { 828,	3,	1,	4,	257,	0,	1,	PPCOpInfoBase + 341,	159,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // DMUL_rec
    { 827,	3,	1,	4,	258,	0,	1,	PPCOpInfoBase + 344,	159,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // DMULQ_rec
    { 826,	3,	1,	4,	258,	0,	0,	PPCOpInfoBase + 344,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // DMULQ
    { 825,	3,	1,	4,	257,	0,	0,	PPCOpInfoBase + 341,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // DMUL
    { 824,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 382,	0,	0, 0x0ULL },  // DMSHA3HASH
    { 823,	4,	1,	4,	0,	0,	0,	PPCOpInfoBase + 378,	0,	0, 0x0ULL },  // DMSHA2HASH
    { 822,	1,	1,	4,	0,	0,	0,	PPCOpInfoBase + 377,	0,	0, 0x0ULL },  // DMSETDMRZ
    { 821,	2,	1,	4,	0,	0,	0,	PPCOpInfoBase + 375,	0,	0, 0x0ULL },  // DMMR
    { 820,	3,	1,	4,	392,	0,	1,	PPCOpInfoBase + 225,	0,	0, 0xdULL },  // DIVW_rec
    { 819,	3,	1,	4,	392,	0,	1,	PPCOpInfoBase + 225,	0,	0, 0xdULL },  // DIVWU_rec
    { 818,	3,	1,	4,	392,	0,	2,	PPCOpInfoBase + 225,	13,	0, 0x8ULL },  // DIVWUO_rec
    { 817,	3,	1,	4,	386,	0,	1,	PPCOpInfoBase + 225,	12,	0, 0x8ULL },  // DIVWUO
    { 816,	3,	1,	4,	211,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x8ULL },  // DIVWU
    { 815,	3,	1,	4,	392,	0,	2,	PPCOpInfoBase + 225,	13,	0, 0x8ULL },  // DIVWO_rec
    { 814,	3,	1,	4,	386,	0,	1,	PPCOpInfoBase + 225,	12,	0, 0x8ULL },  // DIVWO
    { 813,	3,	1,	4,	156,	0,	1,	PPCOpInfoBase + 225,	0,	0, 0xdULL },  // DIVWE_rec
    { 812,	3,	1,	4,	156,	0,	1,	PPCOpInfoBase + 225,	0,	0, 0xdULL },  // DIVWEU_rec
    { 811,	3,	1,	4,	156,	0,	2,	PPCOpInfoBase + 225,	13,	0, 0x8ULL },  // DIVWEUO_rec
    { 810,	3,	1,	4,	388,	0,	1,	PPCOpInfoBase + 225,	12,	0, 0x8ULL },  // DIVWEUO
    { 809,	3,	1,	4,	213,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x8ULL },  // DIVWEU
    { 808,	3,	1,	4,	156,	0,	2,	PPCOpInfoBase + 225,	13,	0, 0x8ULL },  // DIVWEO_rec
    { 807,	3,	1,	4,	388,	0,	1,	PPCOpInfoBase + 225,	12,	0, 0x8ULL },  // DIVWEO
    { 806,	3,	1,	4,	213,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x8ULL },  // DIVWE
    { 805,	3,	1,	4,	211,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x8ULL },  // DIVW
    { 804,	3,	1,	4,	157,	0,	1,	PPCOpInfoBase + 231,	0,	0, 0xdULL },  // DIVD_rec
    { 803,	3,	1,	4,	157,	0,	1,	PPCOpInfoBase + 231,	0,	0, 0xdULL },  // DIVDU_rec
    { 802,	3,	1,	4,	157,	0,	2,	PPCOpInfoBase + 231,	13,	0, 0x8ULL },  // DIVDUO_rec
    { 801,	3,	1,	4,	389,	0,	1,	PPCOpInfoBase + 231,	12,	0, 0x8ULL },  // DIVDUO
    { 800,	3,	1,	4,	212,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // DIVDU
    { 799,	3,	1,	4,	157,	0,	2,	PPCOpInfoBase + 231,	13,	0, 0x8ULL },  // DIVDO_rec
    { 798,	3,	1,	4,	389,	0,	1,	PPCOpInfoBase + 231,	12,	0, 0x8ULL },  // DIVDO
    { 797,	3,	1,	4,	155,	0,	1,	PPCOpInfoBase + 231,	0,	0, 0xdULL },  // DIVDE_rec
    { 796,	3,	1,	4,	155,	0,	1,	PPCOpInfoBase + 231,	0,	0, 0xdULL },  // DIVDEU_rec
    { 795,	3,	1,	4,	155,	0,	2,	PPCOpInfoBase + 231,	13,	0, 0x8ULL },  // DIVDEUO_rec
    { 794,	3,	1,	4,	391,	0,	1,	PPCOpInfoBase + 231,	12,	0, 0x8ULL },  // DIVDEUO
    { 793,	3,	1,	4,	391,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // DIVDEU
    { 792,	3,	1,	4,	155,	0,	2,	PPCOpInfoBase + 231,	13,	0, 0x8ULL },  // DIVDEO_rec
    { 791,	3,	1,	4,	391,	0,	1,	PPCOpInfoBase + 231,	12,	0, 0x8ULL },  // DIVDEO
    { 790,	3,	1,	4,	391,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // DIVDE
    { 789,	3,	1,	4,	212,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // DIVD
    { 788,	3,	1,	4,	246,	0,	1,	PPCOpInfoBase + 341,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DIEX_rec
    { 787,	3,	1,	4,	249,	0,	1,	PPCOpInfoBase + 372,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DIEXQ_rec
    { 786,	3,	1,	4,	249,	0,	0,	PPCOpInfoBase + 372,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DIEXQ
    { 785,	3,	1,	4,	246,	0,	0,	PPCOpInfoBase + 341,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DIEX
    { 784,	3,	1,	4,	246,	0,	1,	PPCOpInfoBase + 366,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DENBCD_rec
    { 783,	3,	1,	4,	249,	0,	1,	PPCOpInfoBase + 369,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DENBCDQ_rec
    { 782,	3,	1,	4,	249,	0,	0,	PPCOpInfoBase + 369,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DENBCDQ
    { 781,	3,	1,	4,	246,	0,	0,	PPCOpInfoBase + 366,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DENBCD
    { 780,	3,	1,	4,	259,	0,	1,	PPCOpInfoBase + 341,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DDIV_rec
    { 779,	3,	1,	4,	260,	0,	1,	PPCOpInfoBase + 344,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DDIVQ_rec
    { 778,	3,	1,	4,	260,	0,	0,	PPCOpInfoBase + 344,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DDIVQ
    { 777,	3,	1,	4,	259,	0,	0,	PPCOpInfoBase + 341,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DDIV
    { 776,	3,	1,	4,	246,	0,	1,	PPCOpInfoBase + 366,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DDEDPD_rec
    { 775,	3,	1,	4,	249,	0,	1,	PPCOpInfoBase + 369,	159,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DDEDPDQ_rec
    { 774,	3,	1,	4,	249,	0,	0,	PPCOpInfoBase + 369,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DDEDPDQ
    { 773,	3,	1,	4,	246,	0,	0,	PPCOpInfoBase + 366,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DDEDPD
    { 772,	2,	1,	4,	251,	0,	1,	PPCOpInfoBase + 352,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCTQPQ_rec
    { 771,	2,	1,	4,	251,	0,	0,	PPCOpInfoBase + 352,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCTQPQ
    { 770,	2,	1,	4,	254,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCTFIX_rec
    { 769,	2,	1,	4,	12,	0,	1,	PPCOpInfoBase + 362,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCTFIXQ_rec
    { 768,	2,	1,	4,	12,	0,	0,	PPCOpInfoBase + 364,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCTFIXQQ
    { 767,	2,	1,	4,	12,	0,	0,	PPCOpInfoBase + 362,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCTFIXQ
    { 766,	2,	1,	4,	254,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCTFIX
    { 765,	2,	1,	4,	247,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCTDP_rec
    { 764,	2,	1,	4,	247,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCTDP
    { 763,	3,	1,	4,	250,	0,	0,	PPCOpInfoBase + 359,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCMPUQ
    { 762,	3,	1,	4,	245,	0,	0,	PPCOpInfoBase + 356,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCMPU
    { 761,	3,	1,	4,	250,	0,	0,	PPCOpInfoBase + 359,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCMPOQ
    { 760,	3,	1,	4,	245,	0,	0,	PPCOpInfoBase + 356,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCMPO
    { 759,	2,	1,	4,	255,	0,	1,	PPCOpInfoBase + 350,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCFFIX_rec
    { 758,	2,	1,	4,	256,	0,	1,	PPCOpInfoBase + 352,	159,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCFFIXQ_rec
    { 757,	2,	1,	4,	12,	0,	0,	PPCOpInfoBase + 354,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCFFIXQQ
    { 756,	2,	1,	4,	256,	0,	0,	PPCOpInfoBase + 352,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCFFIXQ
    { 755,	2,	1,	4,	255,	0,	0,	PPCOpInfoBase + 350,	0,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DCFFIX
    { 754,	2,	0,	4,	623,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCCCI
    { 753,	2,	0,	4,	338,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBZLEP
    { 752,	2,	0,	4,	622,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // DCBZL
    { 751,	2,	0,	4,	338,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBZEP
    { 750,	2,	0,	4,	609,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // DCBZ
    { 749,	3,	0,	4,	338,	0,	0,	PPCOpInfoBase + 188,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBTSTEP
    { 748,	3,	0,	4,	552,	0,	0,	PPCOpInfoBase + 347,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x2ULL },  // DCBTST
    { 747,	3,	0,	4,	338,	0,	0,	PPCOpInfoBase + 188,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBTEP
    { 746,	3,	0,	4,	552,	0,	0,	PPCOpInfoBase + 347,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x2ULL },  // DCBT
    { 745,	2,	0,	4,	338,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBSTEP
    { 744,	2,	0,	4,	609,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // DCBST
    { 743,	2,	0,	4,	429,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // DCBI
    { 742,	2,	0,	4,	338,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBFEP
    { 741,	3,	0,	4,	609,	0,	0,	PPCOpInfoBase + 347,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x2ULL },  // DCBF
    { 740,	2,	0,	4,	429,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // DCBA
    { 739,	2,	1,	4,	344,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL },  // DARN
    { 738,	3,	1,	4,	247,	0,	1,	PPCOpInfoBase + 341,	159,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // DADD_rec
    { 737,	3,	1,	4,	252,	0,	1,	PPCOpInfoBase + 344,	159,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // DADDQ_rec
    { 736,	3,	1,	4,	252,	0,	0,	PPCOpInfoBase + 344,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // DADDQ
    { 735,	3,	1,	4,	247,	0,	0,	PPCOpInfoBase + 341,	0,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // DADD
    { 734,	3,	0,	4,	449,	0,	0,	PPCOpInfoBase + 293,	0,	0|(1ULL<<MCID::Branch), 0x38ULL },  // CTRL_DEP
    { 733,	3,	1,	4,	306,	0,	0,	PPCOpInfoBase + 336,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // CRXOR
    { 732,	1,	1,	4,	529,	0,	0,	PPCOpInfoBase + 301,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // CRUNSET
    { 731,	1,	1,	4,	529,	0,	0,	PPCOpInfoBase + 301,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // CRSET
    { 730,	3,	1,	4,	529,	0,	0,	PPCOpInfoBase + 336,	0,	0, 0x0ULL },  // CRORC
    { 729,	3,	1,	4,	529,	0,	0,	PPCOpInfoBase + 336,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // CROR
    { 728,	2,	1,	4,	109,	0,	0,	PPCOpInfoBase + 339,	0,	0, 0x0ULL },  // CRNOT
    { 727,	3,	1,	4,	529,	0,	0,	PPCOpInfoBase + 336,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // CRNOR
    { 726,	3,	1,	4,	529,	0,	0,	PPCOpInfoBase + 336,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // CRNAND
    { 725,	3,	1,	4,	529,	0,	0,	PPCOpInfoBase + 336,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // CREQV
    { 724,	3,	1,	4,	529,	0,	0,	PPCOpInfoBase + 336,	0,	0, 0x0ULL },  // CRANDC
    { 723,	3,	1,	4,	529,	0,	0,	PPCOpInfoBase + 336,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // CRAND
    { 722,	0,	0,	4,	529,	0,	1,	PPCOpInfoBase + 1,	158,	0, 0x0ULL },  // CR6UNSET
    { 721,	0,	0,	4,	529,	0,	1,	PPCOpInfoBase + 1,	158,	0, 0x0ULL },  // CR6SET
    { 720,	3,	0,	4,	360,	0,	1,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CP_PASTE_rec
    { 719,	3,	0,	4,	360,	0,	0,	PPCOpInfoBase + 180,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CP_PASTE8_rec
    { 718,	2,	0,	4,	339,	0,	0,	PPCOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CP_COPY8
    { 717,	2,	0,	4,	339,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CP_COPY
    { 716,	0,	0,	4,	343,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CP_ABORT
    { 715,	2,	1,	4,	281,	0,	1,	PPCOpInfoBase + 262,	0,	0, 0x208ULL },  // CNTTZW_rec
    { 714,	2,	1,	4,	281,	0,	1,	PPCOpInfoBase + 264,	0,	0, 0x308ULL },  // CNTTZW8_rec
    { 713,	2,	1,	4,	281,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x308ULL },  // CNTTZW8
    { 712,	2,	1,	4,	281,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x208ULL },  // CNTTZW
    { 711,	2,	1,	4,	281,	0,	1,	PPCOpInfoBase + 264,	0,	0, 0x308ULL },  // CNTTZD_rec
    { 710,	3,	1,	4,	150,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x0ULL },  // CNTTZDM
    { 709,	2,	1,	4,	281,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x308ULL },  // CNTTZD
    { 708,	2,	1,	4,	207,	0,	1,	PPCOpInfoBase + 262,	0,	0, 0x208ULL },  // CNTLZW_rec
    { 707,	2,	1,	4,	207,	0,	1,	PPCOpInfoBase + 264,	0,	0, 0x308ULL },  // CNTLZW8_rec
    { 706,	2,	1,	4,	207,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x308ULL },  // CNTLZW8
    { 705,	2,	1,	4,	207,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x208ULL },  // CNTLZW
    { 704,	2,	1,	4,	207,	0,	1,	PPCOpInfoBase + 264,	0,	0, 0x308ULL },  // CNTLZD_rec
    { 703,	3,	1,	4,	150,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x0ULL },  // CNTLZDM
    { 702,	2,	1,	4,	207,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x308ULL },  // CNTLZD
    { 701,	3,	1,	4,	509,	0,	0,	PPCOpInfoBase + 325,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPWI
    { 700,	3,	1,	4,	142,	0,	0,	PPCOpInfoBase + 322,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPW
    { 699,	4,	1,	4,	276,	0,	0,	PPCOpInfoBase + 332,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPRB8
    { 698,	4,	1,	4,	276,	0,	0,	PPCOpInfoBase + 328,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPRB
    { 697,	3,	1,	4,	509,	0,	0,	PPCOpInfoBase + 325,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPLWI
    { 696,	3,	1,	4,	142,	0,	0,	PPCOpInfoBase + 322,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPLW
    { 695,	3,	1,	4,	509,	0,	0,	PPCOpInfoBase + 319,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPLDI
    { 694,	3,	1,	4,	142,	0,	0,	PPCOpInfoBase + 316,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPLD
    { 693,	3,	1,	4,	276,	0,	0,	PPCOpInfoBase + 316,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPEQB
    { 692,	3,	1,	4,	509,	0,	0,	PPCOpInfoBase + 319,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPDI
    { 691,	3,	1,	4,	142,	0,	0,	PPCOpInfoBase + 316,	0,	0|(1ULL<<MCID::Compare), 0x8ULL },  // CMPD
    { 690,	3,	1,	4,	528,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // CMPB8
    { 689,	3,	1,	4,	528,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // CMPB
    { 688,	0,	0,	4,	624,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x2ULL },  // CLRBHRB
    { 687,	3,	1,	4,	452,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x0ULL },  // CFUGED
    { 686,	2,	1,	4,	472,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x8ULL },  // CDTBCD8
    { 685,	2,	1,	4,	472,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // CDTBCD
    { 684,	2,	1,	4,	472,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x8ULL },  // CBCDTD8
    { 683,	2,	1,	4,	472,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // CBCDTD
    { 682,	2,	1,	4,	581,	0,	0,	PPCOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRW8
    { 681,	2,	1,	4,	581,	0,	0,	PPCOpInfoBase + 262,	0,	0, 0x0ULL },  // BRW
    { 680,	3,	1,	4,	408,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRINC
    { 679,	2,	1,	4,	581,	0,	0,	PPCOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRH8
    { 678,	2,	1,	4,	581,	0,	0,	PPCOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRH
    { 677,	2,	1,	4,	581,	0,	0,	PPCOpInfoBase + 264,	0,	0, 0x0ULL },  // BRD
    { 676,	3,	1,	4,	283,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // BPERMD
    { 675,	2,	0,	4,	244,	1,	1,	PPCOpInfoBase + 9,	81,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BL_TLS
    { 674,	1,	0,	4,	244,	1,	2,	PPCOpInfoBase + 290,	144,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL_RM
    { 673,	1,	0,	8,	244,	1,	2,	PPCOpInfoBase + 290,	144,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL_NOP_RM
    { 672,	1,	0,	8,	244,	1,	1,	PPCOpInfoBase + 290,	81,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL_NOP
    { 671,	1,	0,	8,	103,	2,	3,	PPCOpInfoBase + 290,	153,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL_LWZinto_toc_RM
    { 670,	1,	0,	8,	103,	2,	2,	PPCOpInfoBase + 290,	149,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL_LWZinto_toc
    { 669,	0,	0,	4,	448,	2,	1,	PPCOpInfoBase + 1,	85,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BLRL
    { 668,	0,	0,	4,	448,	2,	0,	PPCOpInfoBase + 1,	147,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0x38ULL },  // BLR8
    { 667,	0,	0,	4,	448,	2,	0,	PPCOpInfoBase + 1,	83,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0x38ULL },  // BLR
    { 666,	1,	0,	4,	244,	1,	2,	PPCOpInfoBase + 0,	144,	0|(1ULL<<MCID::Call), 0x38ULL },  // BLA_RM
    { 665,	1,	0,	4,	244,	1,	2,	PPCOpInfoBase + 0,	141,	0|(1ULL<<MCID::Call), 0x38ULL },  // BLA8_RM
    { 664,	1,	0,	8,	244,	1,	2,	PPCOpInfoBase + 0,	141,	0|(1ULL<<MCID::Call), 0x38ULL },  // BLA8_NOP_RM
    { 663,	1,	0,	8,	244,	1,	1,	PPCOpInfoBase + 0,	130,	0|(1ULL<<MCID::Call), 0x38ULL },  // BLA8_NOP
    { 662,	1,	0,	4,	244,	1,	1,	PPCOpInfoBase + 0,	130,	0|(1ULL<<MCID::Call), 0x38ULL },  // BLA8
    { 661,	1,	0,	4,	244,	1,	1,	PPCOpInfoBase + 0,	81,	0|(1ULL<<MCID::Call), 0x38ULL },  // BLA
    { 660,	2,	0,	4,	244,	1,	1,	PPCOpInfoBase + 9,	130,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_TLS_
    { 659,	2,	0,	4,	244,	1,	1,	PPCOpInfoBase + 9,	130,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_TLS
    { 658,	1,	0,	4,	244,	1,	2,	PPCOpInfoBase + 290,	141,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_RM
    { 657,	2,	0,	4,	102,	1,	1,	PPCOpInfoBase + 9,	130,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_NOTOC_TLS
    { 656,	1,	0,	4,	102,	1,	2,	PPCOpInfoBase + 290,	141,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_NOTOC_RM
    { 655,	1,	0,	4,	102,	1,	1,	PPCOpInfoBase + 290,	130,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_NOTOC
    { 654,	2,	0,	8,	244,	1,	1,	PPCOpInfoBase + 9,	130,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_NOP_TLS
    { 653,	1,	0,	8,	244,	1,	2,	PPCOpInfoBase + 290,	141,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_NOP_RM
    { 652,	1,	0,	8,	244,	1,	1,	PPCOpInfoBase + 290,	130,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_NOP
    { 651,	1,	0,	8,	103,	2,	3,	PPCOpInfoBase + 290,	136,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_LDinto_toc_RM
    { 650,	1,	0,	8,	103,	2,	2,	PPCOpInfoBase + 290,	132,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8_LDinto_toc
    { 649,	1,	0,	4,	244,	1,	1,	PPCOpInfoBase + 290,	130,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL8
    { 648,	1,	0,	4,	244,	1,	1,	PPCOpInfoBase + 290,	81,	0|(1ULL<<MCID::Call), 0x38ULL },  // BL
    { 647,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 290,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZp
    { 646,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 290,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZm
    { 645,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 290,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDZLp
    { 644,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 290,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDZLm
    { 643,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZLRp
    { 642,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZLRm
    { 641,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDZLRLp
    { 640,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDZLRLm
    { 639,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDZLRL
    { 638,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	126,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZLR8
    { 637,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZLR
    { 636,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 0,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDZLAp
    { 635,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 0,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDZLAm
    { 634,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 0,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDZLA
    { 633,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 290,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDZL
    { 632,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 0,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZAp
    { 631,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 0,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZAm
    { 630,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 0,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZA
    { 629,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 290,	117,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZ8
    { 628,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 290,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDZ
    { 627,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 290,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZp
    { 626,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 290,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZm
    { 625,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 290,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDNZLp
    { 624,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 290,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDNZLm
    { 623,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZLRp
    { 622,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZLRm
    { 621,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDNZLRLp
    { 620,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDNZLRLm
    { 619,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDNZLRL
    { 618,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	126,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZLR8
    { 617,	0,	0,	4,	448,	3,	1,	PPCOpInfoBase + 1,	122,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZLR
    { 616,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 0,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDNZLAp
    { 615,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 0,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDNZLAm
    { 614,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 0,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDNZLA
    { 613,	1,	0,	4,	104,	2,	1,	PPCOpInfoBase + 290,	119,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BDNZL
    { 612,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 0,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZAp
    { 611,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 0,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZAm
    { 610,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 0,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZA
    { 609,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 290,	117,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZ8
    { 608,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 290,	115,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BDNZ
    { 607,	2,	0,	4,	104,	0,	0,	PPCOpInfoBase + 291,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCn
    { 606,	0,	0,	4,	104,	2,	2,	PPCOpInfoBase + 1,	111,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable), 0x38ULL },  // BCTRL_RM
    { 605,	2,	0,	8,	104,	2,	3,	PPCOpInfoBase + 314,	106,	0|(1ULL<<MCID::Call), 0x38ULL },  // BCTRL_LWZinto_toc_RM
    { 604,	2,	0,	8,	104,	2,	2,	PPCOpInfoBase + 314,	102,	0|(1ULL<<MCID::Call), 0x38ULL },  // BCTRL_LWZinto_toc
    { 603,	0,	0,	4,	104,	2,	2,	PPCOpInfoBase + 1,	98,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable), 0x38ULL },  // BCTRL8_RM
    { 602,	2,	0,	8,	104,	2,	3,	PPCOpInfoBase + 314,	93,	0|(1ULL<<MCID::Call), 0x38ULL },  // BCTRL8_LDinto_toc_RM
    { 601,	2,	0,	8,	104,	2,	2,	PPCOpInfoBase + 314,	89,	0|(1ULL<<MCID::Call), 0x38ULL },  // BCTRL8_LDinto_toc
    { 600,	0,	0,	4,	104,	2,	1,	PPCOpInfoBase + 1,	78,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable), 0x38ULL },  // BCTRL8
    { 599,	0,	0,	4,	104,	2,	1,	PPCOpInfoBase + 1,	75,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable), 0x38ULL },  // BCTRL
    { 598,	0,	0,	4,	104,	1,	0,	PPCOpInfoBase + 1,	74,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCTR8
    { 597,	0,	0,	4,	104,	1,	0,	PPCOpInfoBase + 1,	73,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCTR
    { 596,	2,	0,	4,	104,	1,	1,	PPCOpInfoBase + 291,	81,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BCLn
    { 595,	1,	0,	4,	104,	1,	1,	PPCOpInfoBase + 290,	81,	0|(1ULL<<MCID::Call), 0x38ULL },  // BCLalways
    { 594,	1,	0,	4,	448,	2,	0,	PPCOpInfoBase + 301,	83,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCLRn
    { 593,	1,	0,	4,	448,	2,	1,	PPCOpInfoBase + 301,	85,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BCLRLn
    { 592,	1,	0,	4,	448,	2,	1,	PPCOpInfoBase + 301,	85,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BCLRL
    { 591,	1,	0,	4,	448,	2,	0,	PPCOpInfoBase + 301,	83,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCLR
    { 590,	2,	0,	4,	104,	1,	1,	PPCOpInfoBase + 291,	81,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BCL
    { 589,	3,	1,	4,	468,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x0ULL },  // BCDUTRUNC_rec
    { 588,	3,	1,	4,	468,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x0ULL },  // BCDUS_rec
    { 587,	4,	1,	4,	468,	0,	1,	PPCOpInfoBase + 302,	88,	0, 0x0ULL },  // BCDTRUNC_rec
    { 586,	4,	1,	4,	468,	0,	1,	PPCOpInfoBase + 302,	88,	0, 0x0ULL },  // BCDS_rec
    { 585,	4,	1,	4,	248,	0,	1,	PPCOpInfoBase + 302,	88,	0, 0x0ULL },  // BCDSUB_rec
    { 584,	4,	1,	4,	329,	0,	1,	PPCOpInfoBase + 302,	88,	0, 0x0ULL },  // BCDSR_rec
    { 583,	3,	1,	4,	466,	0,	1,	PPCOpInfoBase + 306,	88,	0, 0x0ULL },  // BCDSETSGN_rec
    { 582,	3,	1,	4,	466,	0,	1,	PPCOpInfoBase + 306,	88,	0, 0x0ULL },  // BCDCTZ_rec
    { 581,	2,	1,	4,	330,	0,	1,	PPCOpInfoBase + 312,	88,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BCDCTSQ_rec
    { 580,	2,	1,	4,	466,	0,	1,	PPCOpInfoBase + 312,	88,	0, 0x0ULL },  // BCDCTN_rec
    { 579,	3,	1,	4,	468,	0,	1,	PPCOpInfoBase + 309,	88,	0, 0x0ULL },  // BCDCPSGN_rec
    { 578,	3,	1,	4,	466,	0,	1,	PPCOpInfoBase + 306,	88,	0, 0x0ULL },  // BCDCFZ_rec
    { 577,	3,	1,	4,	332,	0,	1,	PPCOpInfoBase + 306,	88,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BCDCFSQ_rec
    { 576,	3,	1,	4,	466,	0,	1,	PPCOpInfoBase + 306,	88,	0, 0x0ULL },  // BCDCFN_rec
    { 575,	4,	1,	4,	248,	0,	1,	PPCOpInfoBase + 302,	88,	0, 0x0ULL },  // BCDADD_rec
    { 574,	1,	0,	4,	448,	1,	0,	PPCOpInfoBase + 301,	73,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCCTRn
    { 573,	1,	0,	4,	448,	2,	1,	PPCOpInfoBase + 301,	75,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BCCTRLn
    { 572,	1,	0,	4,	448,	2,	1,	PPCOpInfoBase + 301,	78,	0|(1ULL<<MCID::Call), 0x38ULL },  // BCCTRL8n
    { 571,	1,	0,	4,	448,	2,	1,	PPCOpInfoBase + 301,	78,	0|(1ULL<<MCID::Call), 0x38ULL },  // BCCTRL8
    { 570,	1,	0,	4,	448,	2,	1,	PPCOpInfoBase + 301,	75,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BCCTRL
    { 569,	1,	0,	4,	448,	1,	0,	PPCOpInfoBase + 301,	74,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCCTR8n
    { 568,	1,	0,	4,	448,	1,	0,	PPCOpInfoBase + 301,	74,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCCTR8
    { 567,	1,	0,	4,	448,	1,	0,	PPCOpInfoBase + 301,	73,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCCTR
    { 566,	2,	0,	4,	448,	2,	1,	PPCOpInfoBase + 299,	85,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BCCLRL
    { 565,	2,	0,	4,	448,	2,	0,	PPCOpInfoBase + 299,	83,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCCLR
    { 564,	3,	0,	4,	448,	1,	1,	PPCOpInfoBase + 296,	81,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BCCLA
    { 563,	3,	0,	4,	448,	1,	1,	PPCOpInfoBase + 293,	81,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BCCL
    { 562,	2,	0,	4,	448,	2,	1,	PPCOpInfoBase + 299,	78,	0|(1ULL<<MCID::Call), 0x38ULL },  // BCCCTRL8
    { 561,	2,	0,	4,	448,	2,	1,	PPCOpInfoBase + 299,	75,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x38ULL },  // BCCCTRL
    { 560,	2,	0,	4,	448,	1,	0,	PPCOpInfoBase + 299,	74,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCCCTR8
    { 559,	2,	0,	4,	448,	1,	0,	PPCOpInfoBase + 299,	73,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCCCTR
    { 558,	3,	0,	4,	448,	0,	0,	PPCOpInfoBase + 296,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCCA
    { 557,	3,	0,	4,	448,	0,	0,	PPCOpInfoBase + 293,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BCC
    { 556,	2,	0,	4,	104,	0,	0,	PPCOpInfoBase + 291,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x38ULL },  // BC
    { 555,	1,	0,	4,	244,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x38ULL },  // BA
    { 554,	1,	0,	4,	244,	0,	0,	PPCOpInfoBase + 290,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0x38ULL },  // B
    { 553,	0,	0,	4,	621,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ATTN
    { 552,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_SWAP_NOWP
    { 551,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_SWAP_I64
    { 550,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_SWAP
    { 549,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_XOR_NOWP
    { 548,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_XOR_I64
    { 547,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_XOR
    { 546,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_UMIN_NOWP
    { 545,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_UMIN_I64
    { 544,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_UMIN
    { 543,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_UMAX_NOWP
    { 542,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_UMAX_I64
    { 541,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_UMAX
    { 540,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_SUB_NOWP
    { 539,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_SUB_I64
    { 538,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_SUB
    { 537,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_OR_NOWP
    { 536,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_OR_I64
    { 535,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_OR
    { 534,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_NAND_NOWP
    { 533,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_NAND_I64
    { 532,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_NAND
    { 531,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_MIN_NOWP
    { 530,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_MIN_I64
    { 529,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_MIN
    { 528,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_MAX_NOWP
    { 527,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_MAX_I64
    { 526,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_MAX
    { 525,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_AND_NOWP
    { 524,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_AND_I64
    { 523,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_AND
    { 522,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_ADD_NOWP
    { 521,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 285,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_ADD_I64
    { 520,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 280,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_LOAD_ADD
    { 519,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 270,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_CMP_SWAP_I8
    { 518,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 275,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_CMP_SWAP_I64
    { 517,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 270,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_CMP_SWAP_I32
    { 516,	5,	1,	4,	0,	0,	1,	PPCOpInfoBase + 270,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_CMP_SWAP_I16
    { 515,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // AND_rec
    { 514,	2,	1,	4,	0,	0,	1,	PPCOpInfoBase + 268,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ANDI_rec_1_GT_BIT8
    { 513,	2,	1,	4,	0,	0,	1,	PPCOpInfoBase + 266,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ANDI_rec_1_GT_BIT
    { 512,	2,	1,	4,	0,	0,	1,	PPCOpInfoBase + 268,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ANDI_rec_1_EQ_BIT8
    { 511,	2,	1,	4,	0,	0,	1,	PPCOpInfoBase + 266,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ANDI_rec_1_EQ_BIT
    { 510,	3,	1,	4,	508,	0,	1,	PPCOpInfoBase + 183,	0,	0, 0x308ULL },  // ANDI_rec
    { 509,	3,	1,	4,	508,	0,	1,	PPCOpInfoBase + 183,	0,	0, 0x208ULL },  // ANDIS_rec
    { 508,	3,	1,	4,	506,	0,	1,	PPCOpInfoBase + 180,	0,	0, 0x208ULL },  // ANDIS8_rec
    { 507,	3,	1,	4,	506,	0,	1,	PPCOpInfoBase + 180,	0,	0, 0x308ULL },  // ANDI8_rec
    { 506,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 225,	0,	0, 0x8ULL },  // ANDC_rec
    { 505,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // ANDC8_rec
    { 504,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // ANDC8
    { 503,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x8ULL },  // ANDC
    { 502,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // AND8_rec
    { 501,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // AND8
    { 500,	3,	1,	4,	200,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // AND
    { 499,	2,	0,	4,	0,	1,	1,	PPCOpInfoBase + 20,	71,	0, 0x0ULL },  // ADJCALLSTACKUP
    { 498,	2,	0,	4,	0,	1,	1,	PPCOpInfoBase + 20,	71,	0, 0x0ULL },  // ADJCALLSTACKDOWN
    { 497,	2,	1,	4,	536,	1,	2,	PPCOpInfoBase + 262,	32,	0, 0x8ULL },  // ADDZE_rec
    { 496,	2,	1,	4,	536,	1,	3,	PPCOpInfoBase + 262,	28,	0, 0x8ULL },  // ADDZEO_rec
    { 495,	2,	1,	4,	506,	1,	2,	PPCOpInfoBase + 262,	25,	0, 0x8ULL },  // ADDZEO
    { 494,	2,	1,	4,	536,	1,	2,	PPCOpInfoBase + 264,	32,	0, 0x8ULL },  // ADDZE8_rec
    { 493,	2,	1,	4,	536,	1,	3,	PPCOpInfoBase + 264,	28,	0, 0x8ULL },  // ADDZE8O_rec
    { 492,	2,	1,	4,	506,	1,	2,	PPCOpInfoBase + 264,	25,	0, 0x8ULL },  // ADDZE8O
    { 491,	2,	1,	4,	507,	1,	1,	PPCOpInfoBase + 264,	23,	0, 0x8ULL },  // ADDZE8
    { 490,	2,	1,	4,	507,	1,	1,	PPCOpInfoBase + 262,	23,	0, 0x8ULL },  // ADDZE
    { 489,	2,	1,	4,	145,	0,	0,	PPCOpInfoBase + 220,	0,	0, 0x8ULL },  // ADDPCIS
    { 488,	2,	1,	4,	536,	1,	2,	PPCOpInfoBase + 262,	32,	0, 0x8ULL },  // ADDME_rec
    { 487,	2,	1,	4,	536,	1,	3,	PPCOpInfoBase + 262,	28,	0, 0x8ULL },  // ADDMEO_rec
    { 486,	2,	1,	4,	506,	1,	2,	PPCOpInfoBase + 262,	25,	0, 0x8ULL },  // ADDMEO
    { 485,	2,	1,	4,	536,	1,	2,	PPCOpInfoBase + 264,	32,	0, 0x8ULL },  // ADDME8_rec
    { 484,	2,	1,	4,	536,	1,	3,	PPCOpInfoBase + 264,	28,	0, 0x8ULL },  // ADDME8O_rec
    { 483,	2,	1,	4,	506,	1,	2,	PPCOpInfoBase + 264,	25,	0, 0x8ULL },  // ADDME8O
    { 482,	2,	1,	4,	505,	1,	1,	PPCOpInfoBase + 264,	23,	0, 0x8ULL },  // ADDME8
    { 481,	2,	1,	4,	505,	1,	1,	PPCOpInfoBase + 262,	23,	0, 0x8ULL },  // ADDME
    { 480,	3,	1,	4,	290,	0,	0,	PPCOpInfoBase + 234,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // ADDItocL8
    { 479,	3,	1,	4,	504,	0,	0,	PPCOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDItocL
    { 478,	3,	1,	4,	229,	0,	0,	PPCOpInfoBase + 234,	0,	0, 0x0ULL },  // ADDItoc8
    { 477,	3,	1,	4,	229,	0,	0,	PPCOpInfoBase + 228,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDItoc
    { 476,	4,	1,	4,	503,	0,	18,	PPCOpInfoBase + 258,	53,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDItlsldLADDR32
    { 475,	4,	1,	4,	0,	0,	18,	PPCOpInfoBase + 254,	35,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDItlsldLADDR
    { 474,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 248,	0,	0, 0x0ULL },  // ADDItlsldL32
    { 473,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x0ULL },  // ADDItlsldL
    { 472,	4,	1,	4,	229,	0,	18,	PPCOpInfoBase + 258,	53,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDItlsgdLADDR32
    { 471,	4,	1,	4,	229,	0,	18,	PPCOpInfoBase + 254,	35,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDItlsgdLADDR
    { 470,	3,	1,	4,	229,	0,	0,	PPCOpInfoBase + 248,	0,	0, 0x0ULL },  // ADDItlsgdL32
    { 469,	3,	1,	4,	229,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x0ULL },  // ADDItlsgdL
    { 468,	3,	1,	4,	502,	0,	0,	PPCOpInfoBase + 248,	0,	0, 0x0ULL },  // ADDIdtprelL32
    { 467,	3,	1,	4,	229,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x0ULL },  // ADDIdtprelL
    { 466,	3,	1,	4,	504,	0,	0,	PPCOpInfoBase + 234,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // ADDIStocHA8
    { 465,	3,	1,	4,	504,	0,	0,	PPCOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDIStocHA
    { 464,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x0ULL },  // ADDIStlsldHA
    { 463,	3,	1,	4,	229,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x0ULL },  // ADDIStlsgdHA
    { 462,	3,	1,	4,	229,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x0ULL },  // ADDISgotTprelHA
    { 461,	3,	1,	4,	502,	0,	0,	PPCOpInfoBase + 248,	0,	0, 0x0ULL },  // ADDISdtprelHA32
    { 460,	3,	1,	4,	229,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x0ULL },  // ADDISdtprelHA
    { 459,	3,	1,	4,	501,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x8ULL },  // ADDIS8
    { 458,	3,	1,	4,	501,	0,	0,	PPCOpInfoBase + 248,	0,	0, 0x8ULL },  // ADDIS
    { 457,	3,	1,	4,	536,	0,	2,	PPCOpInfoBase + 183,	21,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL },  // ADDIC_rec
    { 456,	3,	1,	4,	505,	0,	1,	PPCOpInfoBase + 180,	15,	0, 0x8ULL },  // ADDIC8
    { 455,	3,	1,	4,	505,	0,	1,	PPCOpInfoBase + 183,	15,	0, 0xcULL },  // ADDIC
    { 454,	3,	1,	4,	501,	0,	0,	PPCOpInfoBase + 211,	0,	0, 0x8ULL },  // ADDI8
    { 453,	3,	1,	4,	501,	0,	0,	PPCOpInfoBase + 248,	0,	0, 0x8ULL },  // ADDI
    { 452,	3,	1,	4,	205,	0,	0,	PPCOpInfoBase + 231,	0,	0, 0x8ULL },  // ADDG6S8
    { 451,	3,	1,	4,	205,	0,	0,	PPCOpInfoBase + 225,	0,	0, 0x0ULL },  // ADDG6S
    { 450,	3,	1,	4,	538,	1,	2,	PPCOpInfoBase + 225,	32,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADDE_rec
    { 449,	4,	1,	4,	526,	0,	0,	PPCOpInfoBase + 244,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDEX8
    { 448,	4,	1,	4,	526,	0,	0,	PPCOpInfoBase + 240,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDEX
    { 447,	3,	1,	4,	538,	1,	3,	PPCOpInfoBase + 225,	28,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADDEO_rec
    { 446,	3,	1,	4,	525,	1,	2,	PPCOpInfoBase + 225,	25,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADDEO
    { 445,	3,	1,	4,	538,	1,	2,	PPCOpInfoBase + 231,	32,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADDE8_rec
    { 444,	3,	1,	4,	538,	1,	3,	PPCOpInfoBase + 231,	28,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADDE8O_rec
    { 443,	3,	1,	4,	525,	1,	2,	PPCOpInfoBase + 231,	25,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADDE8O
    { 442,	3,	1,	4,	141,	1,	1,	PPCOpInfoBase + 231,	23,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADDE8
    { 441,	3,	1,	4,	141,	1,	1,	PPCOpInfoBase + 225,	23,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADDE
    { 440,	3,	1,	4,	542,	0,	2,	PPCOpInfoBase + 225,	21,	0|(1ULL<<MCID::Commutable), 0xcULL },  // ADDC_rec
    { 439,	3,	1,	4,	393,	0,	3,	PPCOpInfoBase + 225,	18,	0|(1ULL<<MCID::Commutable), 0xcULL },  // ADDCO_rec
    { 438,	3,	1,	4,	288,	0,	2,	PPCOpInfoBase + 225,	16,	0|(1ULL<<MCID::Commutable), 0xcULL },  // ADDCO
    { 437,	3,	1,	4,	542,	0,	2,	PPCOpInfoBase + 231,	21,	0|(1ULL<<MCID::Commutable), 0xcULL },  // ADDC8_rec
    { 436,	3,	1,	4,	393,	0,	3,	PPCOpInfoBase + 231,	18,	0|(1ULL<<MCID::Commutable), 0xcULL },  // ADDC8O_rec
    { 435,	3,	1,	4,	288,	0,	2,	PPCOpInfoBase + 231,	16,	0|(1ULL<<MCID::Commutable), 0xcULL },  // ADDC8O
    { 434,	3,	1,	4,	288,	0,	1,	PPCOpInfoBase + 231,	15,	0|(1ULL<<MCID::Commutable), 0xcULL },  // ADDC8
    { 433,	3,	1,	4,	288,	0,	1,	PPCOpInfoBase + 225,	15,	0|(1ULL<<MCID::Commutable), 0xcULL },  // ADDC
    { 432,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADD8_rec
    { 431,	3,	1,	4,	140,	0,	0,	PPCOpInfoBase + 237,	0,	0, 0x8ULL },  // ADD8TLS_
    { 430,	3,	1,	4,	140,	0,	0,	PPCOpInfoBase + 234,	0,	0, 0x8ULL },  // ADD8TLS
    { 429,	3,	1,	4,	143,	0,	2,	PPCOpInfoBase + 231,	13,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADD8O_rec
    { 428,	3,	1,	4,	527,	0,	1,	PPCOpInfoBase + 231,	12,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADD8O
    { 427,	3,	1,	4,	140,	0,	0,	PPCOpInfoBase + 231,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADD8
    { 426,	3,	1,	4,	200,	0,	1,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADD4_rec
    { 425,	3,	1,	4,	140,	0,	0,	PPCOpInfoBase + 228,	0,	0, 0x8ULL },  // ADD4TLS
    { 424,	3,	1,	4,	143,	0,	2,	PPCOpInfoBase + 225,	13,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADD4O_rec
    { 423,	3,	1,	4,	527,	0,	1,	PPCOpInfoBase + 225,	12,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADD4O
    { 422,	3,	1,	4,	140,	0,	0,	PPCOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x8ULL },  // ADD4
    { 421,	3,	0,	4,	371,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x40ULL },  // XFSTOREf64
    { 420,	3,	0,	4,	371,	0,	0,	PPCOpInfoBase + 222,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x40ULL },  // XFSTOREf32
    { 419,	3,	1,	4,	216,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x40ULL },  // XFLOADf64
    { 418,	3,	1,	4,	366,	0,	0,	PPCOpInfoBase + 222,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x40ULL },  // XFLOADf32
    { 417,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 220,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBPCIS
    { 416,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBIS
    { 415,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBIC_rec
    { 414,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBIC
    { 413,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBI
    { 412,	3,	0,	4,	612,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x40ULL },  // STIWX
    { 411,	3,	0,	0,	204,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SRWI_rec
    { 410,	3,	0,	0,	204,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SRWI
    { 409,	3,	0,	0,	204,	0,	0,	PPCOpInfoBase + 180,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SRDI_rec
    { 408,	3,	0,	0,	204,	0,	0,	PPCOpInfoBase + 180,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SRDI
    { 407,	3,	0,	4,	611,	0,	0,	PPCOpInfoBase + 217,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x40ULL },  // SPILLTOVSR_STX
    { 406,	3,	0,	4,	601,	0,	0,	PPCOpInfoBase + 214,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // SPILLTOVSR_ST
    { 405,	3,	1,	4,	555,	0,	0,	PPCOpInfoBase + 217,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x40ULL },  // SPILLTOVSR_LDX
    { 404,	3,	1,	4,	546,	0,	0,	PPCOpInfoBase + 214,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // SPILLTOVSR_LD
    { 403,	3,	0,	0,	204,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLWI_rec
    { 402,	3,	0,	0,	204,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLWI
    { 401,	3,	0,	0,	204,	0,	0,	PPCOpInfoBase + 180,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLDI_rec
    { 400,	3,	0,	0,	204,	0,	0,	PPCOpInfoBase + 180,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SLDI
    { 399,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ROTRWI_rec
    { 398,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ROTRWI
    { 397,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 180,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ROTRDI_rec
    { 396,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 180,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ROTRDI
    { 395,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RLWNMbm_rec
    { 394,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RLWNMbm
    { 393,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RLWINMbm_rec
    { 392,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RLWINMbm
    { 391,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RLWIMIbm_rec
    { 390,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RLWIMIbm
    { 389,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 211,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PSUBI
    { 388,	2,	1,	4,	0,	0,	0,	PPCOpInfoBase + 209,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PPCLdFixedAddr
    { 387,	2,	1,	4,	0,	2,	3,	PPCOpInfoBase + 207,	7,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // LWAT_CSNE_PSEUDO
    { 386,	3,	1,	4,	216,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x40ULL },  // LIWZX
    { 385,	3,	1,	4,	363,	0,	0,	PPCOpInfoBase + 204,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x40ULL },  // LIWAX
    { 384,	2,	1,	4,	0,	2,	3,	PPCOpInfoBase + 202,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // LDAT_CSNE_PSEUDO
    { 383,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 199,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x400ULL },  // LAx
    { 382,	2,	1,	4,	0,	0,	0,	PPCOpInfoBase + 197,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // KILL_PAIR
    { 381,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INSRWI_rec
    { 380,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INSRWI
    { 379,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INSRDI_rec
    { 378,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INSRDI
    { 377,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INSLWI_rec
    { 376,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INSLWI
    { 375,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EXTRWI_rec
    { 374,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EXTRWI
    { 373,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EXTRDI_rec
    { 372,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EXTRDI
    { 371,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EXTLWI_rec
    { 370,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EXTLWI
    { 369,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EXTLDI_rec
    { 368,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EXTLDI
    { 367,	3,	0,	4,	603,	0,	0,	PPCOpInfoBase + 194,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // DFSTOREf64
    { 366,	3,	0,	4,	603,	0,	0,	PPCOpInfoBase + 191,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // DFSTOREf32
    { 365,	3,	1,	4,	548,	0,	0,	PPCOpInfoBase + 194,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // DFLOADf64
    { 364,	3,	1,	4,	547,	0,	0,	PPCOpInfoBase + 191,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // DFLOADf32
    { 363,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBTx
    { 362,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBTT
    { 361,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBTSTx
    { 360,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBTSTT
    { 359,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 188,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBTSTDS
    { 358,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 188,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBTSTCT
    { 357,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 188,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBTDS
    { 356,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 188,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBTCT
    { 355,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBSTPS
    { 354,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBFx
    { 353,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBFPS
    { 352,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBFLP
    { 351,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCBFL
    { 350,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRRWI_rec
    { 349,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 183,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRRWI
    { 348,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 180,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRRDI_rec
    { 347,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 180,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRRDI
    { 346,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRLSLWI_rec
    { 345,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRLSLWI
    { 344,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRLSLDI_rec
    { 343,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRLSLDI
    { 342,	1,	0,	4,	1,	0,	1,	PPCOpInfoBase + 171,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CFENCE8
    { 341,	1,	0,	4,	1,	0,	1,	PPCOpInfoBase + 170,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CFENCE
    { 340,	2,	1,	4,	0,	0,	0,	PPCOpInfoBase + 168,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BUILD_UACC
    { 339,	3,	1,	4,	0,	0,	0,	PPCOpInfoBase + 165,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BUILD_QUADWORD
    { 338,	6,	2,	4,	0,	0,	1,	PPCOpInfoBase + 159,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ATOMIC_SWAP_I128
    { 337,	6,	2,	4,	0,	0,	1,	PPCOpInfoBase + 159,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ATOMIC_LOAD_XOR_I128
    { 336,	6,	2,	4,	0,	0,	1,	PPCOpInfoBase + 159,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ATOMIC_LOAD_SUB_I128
    { 335,	6,	2,	4,	0,	0,	1,	PPCOpInfoBase + 159,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ATOMIC_LOAD_OR_I128
    { 334,	6,	2,	4,	0,	0,	1,	PPCOpInfoBase + 159,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ATOMIC_LOAD_NAND_I128
    { 333,	6,	2,	4,	0,	0,	1,	PPCOpInfoBase + 159,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ATOMIC_LOAD_AND_I128
    { 332,	6,	2,	4,	0,	0,	1,	PPCOpInfoBase + 159,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ATOMIC_LOAD_ADD_I128
    { 331,	8,	2,	4,	0,	0,	1,	PPCOpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ATOMIC_CMP_SWAP_I128
    { 330,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	PPCOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	PPCOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	PPCOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	PPCOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	PPCOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	PPCOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	PPCOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	PPCOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	PPCOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	PPCOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	PPCOpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	PPCOpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	PPCOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	PPCOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	PPCOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	PPCOpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	PPCOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	PPCOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	PPCOpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_20206
    { 41,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_20205
    { 40,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_20204
    { 31,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	PPCOpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	PPCOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	PPCOpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	292,	0,	0,	PPCOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	0,	0,	0,	PPCOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	0,	0,	0,	PPCOpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	0,	0,	0,	PPCOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	PPCOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	PPCOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // PHI
  }, {
    /* 0 */
    /* 0 */ PPC::CR0,
    /* 1 */ PPC::CR7,
    /* 2 */ PPC::X9, PPC::X10, PPC::X8, PPC::X9, PPC::X10,
    /* 7 */ PPC::R9, PPC::R10, PPC::R8, PPC::R9, PPC::R10,
    /* 12 */ PPC::XER,
    /* 13 */ PPC::XER, PPC::CR0,
    /* 15 */ PPC::CARRY,
    /* 16 */ PPC::CARRY, PPC::XER,
    /* 18 */ PPC::CARRY, PPC::XER, PPC::CR0,
    /* 21 */ PPC::CARRY, PPC::CR0,
    /* 23 */ PPC::CARRY, PPC::CARRY,
    /* 25 */ PPC::CARRY, PPC::CARRY, PPC::XER,
    /* 28 */ PPC::CARRY, PPC::CARRY, PPC::XER, PPC::CR0,
    /* 32 */ PPC::CARRY, PPC::CARRY, PPC::CR0,
    /* 35 */ PPC::X0, PPC::X3, PPC::X4, PPC::X5, PPC::X6, PPC::X7, PPC::X8, PPC::X9, PPC::X10, PPC::X11, PPC::X12, PPC::LR8, PPC::CTR8, PPC::CR0, PPC::CR1, PPC::CR5, PPC::CR6, PPC::CR7,
    /* 53 */ PPC::R0, PPC::R3, PPC::R4, PPC::R5, PPC::R6, PPC::R7, PPC::R8, PPC::R9, PPC::R10, PPC::R11, PPC::R12, PPC::LR, PPC::CTR, PPC::CR0, PPC::CR1, PPC::CR5, PPC::CR6, PPC::CR7,
    /* 71 */ PPC::R1, PPC::R1,
    /* 73 */ PPC::CTR,
    /* 74 */ PPC::CTR8,
    /* 75 */ PPC::CTR, PPC::RM, PPC::LR,
    /* 78 */ PPC::CTR8, PPC::RM, PPC::LR8,
    /* 81 */ PPC::RM, PPC::LR,
    /* 83 */ PPC::LR, PPC::RM,
    /* 85 */ PPC::LR, PPC::RM, PPC::LR,
    /* 88 */ PPC::CR6,
    /* 89 */ PPC::CTR8, PPC::RM, PPC::LR8, PPC::X2,
    /* 93 */ PPC::CTR8, PPC::RM, PPC::LR8, PPC::X2, PPC::RM,
    /* 98 */ PPC::CTR8, PPC::RM, PPC::LR8, PPC::RM,
    /* 102 */ PPC::CTR, PPC::RM, PPC::LR, PPC::R2,
    /* 106 */ PPC::CTR, PPC::RM, PPC::LR, PPC::R2, PPC::RM,
    /* 111 */ PPC::CTR, PPC::RM, PPC::LR, PPC::RM,
    /* 115 */ PPC::CTR, PPC::CTR,
    /* 117 */ PPC::CTR8, PPC::CTR8,
    /* 119 */ PPC::CTR, PPC::RM, PPC::CTR,
    /* 122 */ PPC::CTR, PPC::LR, PPC::RM, PPC::CTR,
    /* 126 */ PPC::CTR8, PPC::LR8, PPC::RM, PPC::CTR8,
    /* 130 */ PPC::RM, PPC::LR8,
    /* 132 */ PPC::RM, PPC::X1, PPC::LR8, PPC::X2,
    /* 136 */ PPC::RM, PPC::X1, PPC::LR8, PPC::X2, PPC::RM,
    /* 141 */ PPC::RM, PPC::LR8, PPC::RM,
    /* 144 */ PPC::RM, PPC::LR, PPC::RM,
    /* 147 */ PPC::LR8, PPC::RM,
    /* 149 */ PPC::RM, PPC::R1, PPC::LR, PPC::R2,
    /* 153 */ PPC::RM, PPC::R1, PPC::LR, PPC::R2, PPC::RM,
    /* 158 */ PPC::CR1EQ,
    /* 159 */ PPC::CR1,
    /* 160 */ PPC::X1, PPC::X1,
    /* 162 */ PPC::RM,
    /* 163 */ PPC::RM, PPC::CR1,
    /* 165 */ PPC::X0, PPC::X4, PPC::X5, PPC::X6, PPC::X7, PPC::X8, PPC::X9, PPC::X10, PPC::X11, PPC::X12, PPC::LR8, PPC::CTR8, PPC::CR0, PPC::CR1, PPC::CR5, PPC::CR6, PPC::CR7,
    /* 182 */ PPC::R0, PPC::R4, PPC::R5, PPC::R6, PPC::R7, PPC::R8, PPC::R9, PPC::R10, PPC::R11, PPC::R12, PPC::LR, PPC::CTR, PPC::CR0, PPC::CR1, PPC::CR5, PPC::CR6, PPC::CR7,
    /* 199 */ PPC::R0, PPC::R4, PPC::R5, PPC::R11, PPC::LR, PPC::CR0,
    /* 205 */ PPC::X0, PPC::X4, PPC::X5, PPC::X11, PPC::LR8, PPC::CR0,
    /* 211 */ PPC::X0, PPC::X2, PPC::X4, PPC::X5, PPC::X6, PPC::X7, PPC::X8, PPC::X9, PPC::X10, PPC::X11, PPC::X12, PPC::LR8, PPC::CTR8, PPC::CR0, PPC::CR1, PPC::CR5, PPC::CR6, PPC::CR7,
    /* 229 */ PPC::R3, PPC::LR,
    /* 231 */ PPC::LR,
    /* 232 */ PPC::LR8,
    /* 233 */ PPC::RM, PPC::RM,
    /* 235 */ PPC::CTR, PPC::RM,
    /* 237 */ PPC::CTR8, PPC::RM,
    /* 239 */ PPC::RM, PPC::CR6,
    /* 241 */ PPC::CTR, PPC::LR, PPC::RM, PPC::LR, PPC::CTR,
    /* 246 */ PPC::CTR, PPC::RM, PPC::LR, PPC::CTR,
  }, {
    0
  }, {
    /* 0 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 1 */
    /* 1 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 2 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 5 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 9 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 11 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 14 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 18 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, MCOI_TIED_TO(0) },
    /* 20 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 22 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 28 */ { PPC::ppc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { PPC::ppc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { PPC::ppc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::ppc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 39 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_IMM_0, 0 },
    /* 42 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 },
    /* 45 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 },
    /* 49 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 },
    /* 50 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 52 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 57 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_IMM_0, 0 },
    /* 60 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 },
    /* 62 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_IMM_0, 0 },
    /* 66 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 },
    /* 68 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 71 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 76 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 81 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 },
    /* 86 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 },
    /* 90 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 },
    /* 93 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 97 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 100 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 },
    /* 103 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 },
    /* 107 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 },
    /* 111 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 },
    /* 114 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 },
    /* 119 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_IMM_0, 0 },
    /* 123 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 },
    /* 126 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 },
    /* 130 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 },
    /* 133 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 137 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 },
    /* 141 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 },
    /* 143 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_IMM_0, 0 },
    /* 147 */ { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 },
    /* 151 */ { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 159 */ { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 165 */ { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 168 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::UACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 170 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 171 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 172 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 176 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 180 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 183 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 186 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 188 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 191 */ { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 194 */ { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 197 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 199 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 202 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 },
    /* 204 */ { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 207 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 },
    /* 209 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 211 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 214 */ { PPC::SPILLTOVSRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 217 */ { PPC::SPILLTOVSRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 220 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 222 */ { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 225 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 228 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 231 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 234 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 237 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 240 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 244 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 248 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 251 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 254 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 258 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 262 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 264 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 266 */ { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 268 */ { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 270 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 275 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 280 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 285 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 290 */ { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 291 */ { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 293 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 296 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 299 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 301 */ { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 302 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 306 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 309 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 312 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 314 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 316 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 319 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 322 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 325 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 328 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 332 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 336 */ { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 339 */ { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 341 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 344 */ { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 347 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 350 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 352 */ { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 354 */ { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 356 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 359 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 362 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 364 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 366 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 369 */ { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 372 */ { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 375 */ { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 377 */ { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 378 */ { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 382 */ { PPC::DMRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::DMRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 385 */ { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 388 */ { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 391 */ { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 395 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::DMRROWpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 398 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 401 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::WACC_HIRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 404 */ { PPC::DMRROWpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 407 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 410 */ { PPC::WACC_HIRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 413 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 414 */ { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 420 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 424 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 428 */ { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 432 */ { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 436 */ { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 438 */ { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 442 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 445 */ { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 448 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 451 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 454 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 457 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 460 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 463 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 466 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::FpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 469 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 473 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 477 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 480 */ { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 482 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 484 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 487 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 489 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 492 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 494 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 495 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 497 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 500 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 503 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 506 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 509 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 513 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 515 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 518 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 520 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 523 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 525 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 528 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 530 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 533 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 537 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 541 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 545 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 547 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 550 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 554 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 558 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 561 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(1) },
    /* 565 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(1) },
    /* 569 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(1) }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 573 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(1) }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 577 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 580 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 583 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 586 */ { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 590 */ { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 593 */ { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 596 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 599 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 602 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 605 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 608 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(1) },
    /* 612 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(1) }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 616 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 619 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 622 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(1) },
    /* 626 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(1) }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 630 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 633 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 636 */ { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 639 */ { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 642 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 645 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 648 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 651 */ { PPC::VFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 654 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 657 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 660 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 662 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 665 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 668 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 671 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 674 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 678 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 682 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 684 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 685 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 686 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 688 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 690 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 692 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 694 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRSAVERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 696 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 698 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 699 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 701 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 703 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 705 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 707 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 711 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 714 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 716 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 718 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 720 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 722 */ { PPC::VRSAVERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 724 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 726 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 728 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 730 */ { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 732 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 735 */ { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 737 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 740 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 743 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 746 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 749 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 752 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 755 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 758 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 761 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 764 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 766 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 769 */ { PPC::VFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 772 */ { PPC::VFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 774 */ { PPC::VFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 777 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 780 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 783 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 785 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 788 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 791 */ { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 797 */ { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 804 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 810 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 817 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 823 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 830 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 835 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 841 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 846 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 852 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 857 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 863 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 868 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 874 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 879 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 884 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 889 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 894 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 897 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 900 */ { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 903 */ { PPC::DMRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 906 */ { PPC::DMRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 909 */ { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 912 */ { PPC::UACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 915 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 918 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 922 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 926 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 931 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 937 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 943 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 948 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 953 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 958 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 963 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 968 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 973 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 978 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 983 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 988 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 993 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 998 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1003 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1007 */ { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1011 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1015 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRC_NOR0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1019 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RC_NOX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1023 */ { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::SPERCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1027 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1031 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1035 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1037 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1039 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1041 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1043 */ { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1045 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1048 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8pRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1051 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(0) },
    /* 1055 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(0) },
    /* 1059 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(0) }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 1063 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(0) }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 1067 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1070 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(0) },
    /* 1074 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::F8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(0) }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 1078 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(0) },
    /* 1082 */ { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { PPC::F4RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, MCOI_TIED_TO(0) }, { PPC::ptr_rc_idx_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_MEMORY, 0 },
    /* 1086 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ptr_rc_nor0_by_hwmode, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1089 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1092 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1094 */ { PPC::CTRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1096 */ { PPC::CTRRC8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1098 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1101 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1104 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1108 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1111 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1114 */ { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1116 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1119 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1122 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1126 */ { PPC::VFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1128 */ { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1131 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1135 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1139 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1143 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1147 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1151 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1155 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 1159 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1163 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::VFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1166 */ { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1168 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1171 */ { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1174 */ { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1177 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1180 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1183 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1185 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1187 */ { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1189 */ { PPC::VFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1191 */ { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1193 */ { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1195 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::G8RCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1198 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1201 */ { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1205 */ { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1209 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1213 */ { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1217 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1219 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1222 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1225 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1228 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1230 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1233 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1237 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1240 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1244 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1247 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1251 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1254 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1258 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1262 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1265 */ { PPC::CRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1267 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1270 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1274 */ { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRpRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1277 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1281 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1286 */ { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1289 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VRRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1292 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1296 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1300 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1301 */ { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1302 */ { PPC::VSSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1303 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 1305 */ { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::WACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 1307 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1313 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1318 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1322 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSFRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1325 */ { PPC::ACCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1326 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1330 */ { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { PPC::VSRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1333 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 1336 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 1339 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 1343 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1346 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { PPC::CRBITRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
  }
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char PPCInstrNameData[] = {
  /* 0 */ "G_FLOG10\000"
  /* 9 */ "SYNCP10\000"
  /* 17 */ "WAITP10\000"
  /* 25 */ "G_FEXP10\000"
  /* 34 */ "MTFSB0\000"
  /* 41 */ "V_SET0\000"
  /* 48 */ "VCTSXS_0\000"
  /* 57 */ "VCTUXS_0\000"
  /* 66 */ "VCFSX_0\000"
  /* 74 */ "VCFUX_0\000"
  /* 82 */ "MTFSB1\000"
  /* 89 */ "DMXXEXTFDMR512\000"
  /* 104 */ "DMXXINSTDMR512\000"
  /* 119 */ "ADDISdtprelHA32\000"
  /* 135 */ "ATOMIC_CMP_SWAP_I32\000"
  /* 155 */ "ADDItlsgdL32\000"
  /* 168 */ "ADDItlsldL32\000"
  /* 181 */ "LDgotTprelL32\000"
  /* 195 */ "ADDIdtprelL32\000"
  /* 209 */ "VUPKINT4TOFP32\000"
  /* 224 */ "VUPKINT8TOFP32\000"
  /* 239 */ "ADDItlsgdLADDR32\000"
  /* 256 */ "ADDItlsldLADDR32\000"
  /* 273 */ "GETtlsldADDR32\000"
  /* 288 */ "GETtlsADDR32\000"
  /* 301 */ "PREPARE_PROBED_ALLOCA_32\000"
  /* 326 */ "LWA_32\000"
  /* 333 */ "PROBED_STACKALLOC_32\000"
  /* 354 */ "PREPARE_PROBED_ALLOCA_NEGSIZE_SAME_REG_32\000"
  /* 396 */ "SRADI_32\000"
  /* 405 */ "RLDICL_32\000"
  /* 415 */ "RLDICR_32\000"
  /* 425 */ "LHAXTLS_32\000"
  /* 436 */ "LWAXTLS_32\000"
  /* 447 */ "STBXTLS_32\000"
  /* 458 */ "STHXTLS_32\000"
  /* 469 */ "STWXTLS_32\000"
  /* 480 */ "LBZXTLS_32\000"
  /* 491 */ "LHZXTLS_32\000"
  /* 502 */ "LWZXTLS_32\000"
  /* 513 */ "EXTSW_32\000"
  /* 522 */ "LWAX_32\000"
  /* 530 */ "DFLOADf32\000"
  /* 540 */ "XFLOADf32\000"
  /* 550 */ "DFSTOREf32\000"
  /* 561 */ "XFSTOREf32\000"
  /* 572 */ "EH_SjLj_LongJmp32\000"
  /* 590 */ "EH_SjLj_SetJmp32\000"
  /* 607 */ "TLBRE2\000"
  /* 614 */ "TLBWE2\000"
  /* 621 */ "G_FLOG2\000"
  /* 629 */ "G_FATAN2\000"
  /* 638 */ "G_FEXP2\000"
  /* 646 */ "PMXVBF16GER2\000"
  /* 659 */ "PMXVF16GER2\000"
  /* 671 */ "PMXVI16GER2\000"
  /* 683 */ "PMDMXVBF16GERX2\000"
  /* 699 */ "PMDMXVF16GERX2\000"
  /* 714 */ "TLBSX2\000"
  /* 721 */ "ATOMIC_LOAD_SUB_I64\000"
  /* 741 */ "ATOMIC_LOAD_ADD_I64\000"
  /* 761 */ "ATOMIC_LOAD_NAND_I64\000"
  /* 782 */ "ATOMIC_LOAD_AND_I64\000"
  /* 802 */ "ATOMIC_LOAD_UMIN_I64\000"
  /* 823 */ "ATOMIC_LOAD_MIN_I64\000"
  /* 843 */ "ATOMIC_SWAP_I64\000"
  /* 859 */ "ATOMIC_CMP_SWAP_I64\000"
  /* 879 */ "ATOMIC_LOAD_XOR_I64\000"
  /* 899 */ "ATOMIC_LOAD_OR_I64\000"
  /* 918 */ "ATOMIC_LOAD_UMAX_I64\000"
  /* 939 */ "ATOMIC_LOAD_MAX_I64\000"
  /* 959 */ "DST64\000"
  /* 965 */ "DSTST64\000"
  /* 973 */ "DSTT64\000"
  /* 980 */ "DSTSTT64\000"
  /* 989 */ "EXTSB8_32_64\000"
  /* 1002 */ "EXTSH8_32_64\000"
  /* 1015 */ "EXTSWSLI_32_64\000"
  /* 1030 */ "RLDICL_32_64\000"
  /* 1043 */ "EXTSW_32_64\000"
  /* 1055 */ "PREPARE_PROBED_ALLOCA_64\000"
  /* 1080 */ "PROBED_STACKALLOC_64\000"
  /* 1101 */ "PREPARE_PROBED_ALLOCA_NEGSIZE_SAME_REG_64\000"
  /* 1143 */ "DFLOADf64\000"
  /* 1153 */ "XFLOADf64\000"
  /* 1163 */ "DFSTOREf64\000"
  /* 1174 */ "XFSTOREf64\000"
  /* 1185 */ "EH_SjLj_LongJmp64\000"
  /* 1203 */ "EH_SjLj_SetJmp64\000"
  /* 1220 */ "ADD4\000"
  /* 1225 */ "SELECT_CC_SPE4\000"
  /* 1240 */ "SELECT_SPE4\000"
  /* 1252 */ "SELECT_CC_F4\000"
  /* 1265 */ "SELECT_F4\000"
  /* 1275 */ "SELECT_CC_I4\000"
  /* 1288 */ "SELECT_I4\000"
  /* 1298 */ "PMXVI8GER4\000"
  /* 1309 */ "PMDMXVI8GERX4\000"
  /* 1323 */ "VUPKINT4TOBF16\000"
  /* 1338 */ "VUPKINT8TOBF16\000"
  /* 1353 */ "XVCVSPBF16\000"
  /* 1364 */ "SELECT_CC_F16\000"
  /* 1378 */ "SELECT_F16\000"
  /* 1389 */ "ATOMIC_CMP_SWAP_I16\000"
  /* 1409 */ "DMXXEXTFDMR256\000"
  /* 1424 */ "DMXXINSTDMR256\000"
  /* 1439 */ "NOP_GT_PWR6\000"
  /* 1451 */ "NOP_GT_PWR7\000"
  /* 1463 */ "ATOMIC_LOAD_SUB_I128\000"
  /* 1484 */ "ATOMIC_LOAD_ADD_I128\000"
  /* 1505 */ "ATOMIC_LOAD_NAND_I128\000"
  /* 1527 */ "ATOMIC_LOAD_AND_I128\000"
  /* 1548 */ "ATOMIC_SWAP_I128\000"
  /* 1565 */ "ATOMIC_CMP_SWAP_I128\000"
  /* 1586 */ "ATOMIC_LOAD_XOR_I128\000"
  /* 1607 */ "ATOMIC_LOAD_OR_I128\000"
  /* 1627 */ "XXGFMUL128\000"
  /* 1638 */ "TAILBA8\000"
  /* 1646 */ "PLHA8\000"
  /* 1652 */ "ADDIStocHA8\000"
  /* 1664 */ "BLA8\000"
  /* 1669 */ "PLA8\000"
  /* 1674 */ "PLWA8\000"
  /* 1680 */ "TAILB8\000"
  /* 1687 */ "CMPB8\000"
  /* 1693 */ "CMPRB8\000"
  /* 1700 */ "EXTSB8\000"
  /* 1707 */ "SETB8\000"
  /* 1713 */ "MFTB8\000"
  /* 1719 */ "POPCNTB8\000"
  /* 1728 */ "PSTB8\000"
  /* 1734 */ "SETNBC8\000"
  /* 1742 */ "SETBC8\000"
  /* 1749 */ "ADDC8\000"
  /* 1755 */ "ANDC8\000"
  /* 1761 */ "SUBFC8\000"
  /* 1768 */ "ADDIC8\000"
  /* 1775 */ "SUBFIC8\000"
  /* 1783 */ "DYNALLOC8\000"
  /* 1793 */ "ORC8\000"
  /* 1798 */ "CDTBCD8\000"
  /* 1806 */ "ADD8\000"
  /* 1811 */ "MADDLD8\000"
  /* 1819 */ "NAND8\000"
  /* 1825 */ "CBCDTD8\000"
  /* 1833 */ "CFENCE8\000"
  /* 1841 */ "ADDE8\000"
  /* 1847 */ "SUBFE8\000"
  /* 1854 */ "ADDME8\000"
  /* 1861 */ "SUBFME8\000"
  /* 1869 */ "ADDZE8\000"
  /* 1876 */ "SUBFZE8\000"
  /* 1884 */ "SUBF8\000"
  /* 1890 */ "MFOCRF8\000"
  /* 1898 */ "MTOCRF8\000"
  /* 1906 */ "MTCRF8\000"
  /* 1913 */ "SELECT_CC_F8\000"
  /* 1926 */ "SELECT_F8\000"
  /* 1936 */ "NEG8\000"
  /* 1941 */ "BRH8\000"
  /* 1946 */ "EXTSH8\000"
  /* 1953 */ "PSTH8\000"
  /* 1959 */ "PADDI8\000"
  /* 1966 */ "MULLI8\000"
  /* 1973 */ "PLI8\000"
  /* 1978 */ "RLWIMI8\000"
  /* 1986 */ "XORI8\000"
  /* 1992 */ "SRAWI8\000"
  /* 1999 */ "SELECT_CC_I8\000"
  /* 2012 */ "ATOMIC_CMP_SWAP_I8\000"
  /* 2031 */ "SELECT_I8\000"
  /* 2041 */ "HASHCHK8\000"
  /* 2050 */ "BL8\000"
  /* 2054 */ "ISEL8\000"
  /* 2060 */ "MTLPL8\000"
  /* 2067 */ "BCTRL8\000"
  /* 2074 */ "BCCTRL8\000"
  /* 2082 */ "BCCCTRL8\000"
  /* 2091 */ "ADDItocL8\000"
  /* 2101 */ "RLWINM8\000"
  /* 2109 */ "RLWNM8\000"
  /* 2116 */ "MSGSNDP8\000"
  /* 2125 */ "TLBIEP8\000"
  /* 2133 */ "HASHCHKP8\000"
  /* 2143 */ "HASHSTP8\000"
  /* 2152 */ "SETNBCR8\000"
  /* 2161 */ "SETBCR8\000"
  /* 2169 */ "MFCR8\000"
  /* 2175 */ "PMXVI4GER8\000"
  /* 2186 */ "BLR8\000"
  /* 2191 */ "MFLR8\000"
  /* 2197 */ "MTLR8\000"
  /* 2203 */ "BDZLR8\000"
  /* 2210 */ "BDNZLR8\000"
  /* 2218 */ "MovePCtoLR8\000"
  /* 2230 */ "NOR8\000"
  /* 2235 */ "XOR8\000"
  /* 2240 */ "MFSPR8\000"
  /* 2247 */ "MTSPR8\000"
  /* 2254 */ "TAILBCTR8\000"
  /* 2264 */ "BCCTR8\000"
  /* 2271 */ "BCCCTR8\000"
  /* 2279 */ "MFCTR8\000"
  /* 2286 */ "MTCTR8\000"
  /* 2293 */ "ADDG6S8\000"
  /* 2301 */ "PADDIS8\000"
  /* 2309 */ "LIS8\000"
  /* 2314 */ "XORIS8\000"
  /* 2321 */ "DYNAREAOFFSET8\000"
  /* 2336 */ "ANDI_rec_1_EQ_BIT8\000"
  /* 2355 */ "ANDI_rec_1_GT_BIT8\000"
  /* 2374 */ "HASHST8\000"
  /* 2382 */ "LHAU8\000"
  /* 2388 */ "STBU8\000"
  /* 2394 */ "STHU8\000"
  /* 2400 */ "STWU8\000"
  /* 2406 */ "LBZU8\000"
  /* 2412 */ "LHZU8\000"
  /* 2418 */ "LWZU8\000"
  /* 2424 */ "EQV8\000"
  /* 2429 */ "SRAW8\000"
  /* 2435 */ "SLW8\000"
  /* 2440 */ "BRW8\000"
  /* 2445 */ "SRW8\000"
  /* 2450 */ "PSTW8\000"
  /* 2456 */ "CNTLZW8\000"
  /* 2464 */ "CNTTZW8\000"
  /* 2472 */ "LHAX8\000"
  /* 2478 */ "STBX8\000"
  /* 2484 */ "ADDEX8\000"
  /* 2491 */ "STHX8\000"
  /* 2497 */ "TLSGDAIX8\000"
  /* 2507 */ "TLSLDAIX8\000"
  /* 2517 */ "LHBRX8\000"
  /* 2524 */ "LWBRX8\000"
  /* 2531 */ "LHAUX8\000"
  /* 2538 */ "STBUX8\000"
  /* 2545 */ "STHUX8\000"
  /* 2552 */ "STWUX8\000"
  /* 2559 */ "LBZUX8\000"
  /* 2566 */ "LHZUX8\000"
  /* 2573 */ "LWZUX8\000"
  /* 2580 */ "STWX8\000"
  /* 2586 */ "LBZX8\000"
  /* 2592 */ "LHZX8\000"
  /* 2598 */ "LWZX8\000"
  /* 2604 */ "CP_COPY8\000"
  /* 2613 */ "PLBZ8\000"
  /* 2619 */ "BDZ8\000"
  /* 2624 */ "PLHZ8\000"
  /* 2630 */ "BDNZ8\000"
  /* 2636 */ "PLWZ8\000"
  /* 2642 */ "ADDItoc8\000"
  /* 2651 */ "TCRETURNai8\000"
  /* 2663 */ "TCRETURNdi8\000"
  /* 2675 */ "TCRETURNri8\000"
  /* 2687 */ "TLBIE8P9\000"
  /* 2696 */ "TLBIEP9\000"
  /* 2704 */ "EVMHEGSMFAA\000"
  /* 2716 */ "EVMHOGSMFAA\000"
  /* 2728 */ "EVMWSMFAA\000"
  /* 2738 */ "EVMWSSFAA\000"
  /* 2748 */ "EVMHEGSMIAA\000"
  /* 2760 */ "EVMHOGSMIAA\000"
  /* 2772 */ "EVMWSMIAA\000"
  /* 2782 */ "EVMHEGUMIAA\000"
  /* 2794 */ "EVMHOGUMIAA\000"
  /* 2806 */ "EVMWUMIAA\000"
  /* 2816 */ "DCBA\000"
  /* 2821 */ "TAILBA\000"
  /* 2828 */ "LDtocBA\000"
  /* 2836 */ "gBCA\000"
  /* 2841 */ "BCCA\000"
  /* 2846 */ "EVMHESMFA\000"
  /* 2856 */ "EVMWHSMFA\000"
  /* 2866 */ "EVMHOSMFA\000"
  /* 2876 */ "EVMWSMFA\000"
  /* 2885 */ "EVMHESSFA\000"
  /* 2895 */ "EVMWHSSFA\000"
  /* 2905 */ "EVMHOSSFA\000"
  /* 2915 */ "EVMWSSFA\000"
  /* 2924 */ "PLHA\000"
  /* 2929 */ "ADDIStocHA\000"
  /* 2940 */ "ADDIStlsgdHA\000"
  /* 2953 */ "ADDIStlsldHA\000"
  /* 2966 */ "ADDISgotTprelHA\000"
  /* 2982 */ "ADDISdtprelHA\000"
  /* 2996 */ "SLBIA\000"
  /* 3002 */ "TLBIA\000"
  /* 3008 */ "EVMHESMIA\000"
  /* 3018 */ "EVMWHSMIA\000"
  /* 3028 */ "EVMHOSMIA\000"
  /* 3038 */ "EVMWSMIA\000"
  /* 3047 */ "EVMHEUMIA\000"
  /* 3057 */ "EVMWHUMIA\000"
  /* 3067 */ "EVMWLUMIA\000"
  /* 3077 */ "EVMHOUMIA\000"
  /* 3087 */ "EVMWUMIA\000"
  /* 3096 */ "BLA\000"
  /* 3100 */ "gBCLA\000"
  /* 3106 */ "BCCLA\000"
  /* 3112 */ "PLA\000"
  /* 3116 */ "BDZLA\000"
  /* 3122 */ "BDNZLA\000"
  /* 3129 */ "G_FMA\000"
  /* 3135 */ "G_STRICT_FMA\000"
  /* 3148 */ "EVMRA\000"
  /* 3154 */ "DQUA\000"
  /* 3159 */ "PLWA\000"
  /* 3164 */ "MTVSRWA\000"
  /* 3172 */ "MTVRWA\000"
  /* 3179 */ "BDZA\000"
  /* 3184 */ "BDNZA\000"
  /* 3190 */ "V_SET0B\000"
  /* 3198 */ "VSRAB\000"
  /* 3204 */ "RFEBB\000"
  /* 3210 */ "VCNTMBB\000"
  /* 3218 */ "XVTLSBB\000"
  /* 3226 */ "VCLZLSBB\000"
  /* 3235 */ "VCTZLSBB\000"
  /* 3244 */ "VCMPNEB\000"
  /* 3252 */ "VMRGHB\000"
  /* 3259 */ "VUCMPRHB\000"
  /* 3268 */ "XXSPLTIB\000"
  /* 3277 */ "VMRGLB\000"
  /* 3284 */ "TAILB\000"
  /* 3290 */ "VCLRLB\000"
  /* 3297 */ "VUCMPRLB\000"
  /* 3306 */ "VRLB\000"
  /* 3311 */ "VSLB\000"
  /* 3316 */ "VPMSUMB\000"
  /* 3324 */ "VGNB\000"
  /* 3329 */ "VUPKHSNTOB\000"
  /* 3340 */ "VUPKLSNTOB\000"
  /* 3351 */ "CMPB\000"
  /* 3356 */ "CMPEQB\000"
  /* 3363 */ "CLRBHRB\000"
  /* 3371 */ "CMPRB\000"
  /* 3377 */ "VCLRRB\000"
  /* 3384 */ "VSRB\000"
  /* 3389 */ "VMULESB\000"
  /* 3397 */ "V_SETALLONESB\000"
  /* 3411 */ "VAVGSB\000"
  /* 3418 */ "VUPKHSB\000"
  /* 3426 */ "VSPLTISB\000"
  /* 3435 */ "VUPKLSB\000"
  /* 3443 */ "VMINSB\000"
  /* 3450 */ "VMULOSB\000"
  /* 3458 */ "VCMPGTSB\000"
  /* 3467 */ "EVEXTSB\000"
  /* 3475 */ "VMAXSB\000"
  /* 3482 */ "SETB\000"
  /* 3487 */ "MFTB\000"
  /* 3492 */ "VSPLTB\000"
  /* 3499 */ "VPOPCNTB\000"
  /* 3508 */ "VINSERTB\000"
  /* 3517 */ "PSTB\000"
  /* 3522 */ "ReadTB\000"
  /* 3529 */ "VABSDUB\000"
  /* 3537 */ "VMULEUB\000"
  /* 3545 */ "VAVGUB\000"
  /* 3552 */ "VMINUB\000"
  /* 3559 */ "VMULOUB\000"
  /* 3567 */ "VCMPEQUB\000"
  /* 3576 */ "EFDSUB\000"
  /* 3583 */ "G_FSUB\000"
  /* 3590 */ "G_STRICT_FSUB\000"
  /* 3604 */ "G_ATOMICRMW_FSUB\000"
  /* 3621 */ "FMSUB\000"
  /* 3627 */ "FNMSUB\000"
  /* 3634 */ "EFSSUB\000"
  /* 3641 */ "EVFSSUB\000"
  /* 3649 */ "ATOMIC_LOAD_SUB\000"
  /* 3665 */ "G_SUB\000"
  /* 3671 */ "G_ATOMICRMW_SUB\000"
  /* 3687 */ "VEXTRACTUB\000"
  /* 3698 */ "VCMPGTUB\000"
  /* 3707 */ "VMAXUB\000"
  /* 3714 */ "XXBLENDVB\000"
  /* 3724 */ "VCMPNEZB\000"
  /* 3733 */ "VCLZB\000"
  /* 3739 */ "VCTZB\000"
  /* 3745 */ "SETNBC\000"
  /* 3752 */ "SETBC\000"
  /* 3758 */ "gBC\000"
  /* 3762 */ "XXMFACC\000"
  /* 3770 */ "XXMTACC\000"
  /* 3778 */ "BUILD_UACC\000"
  /* 3789 */ "RESTORE_UACC\000"
  /* 3802 */ "SPILL_UACC\000"
  /* 3813 */ "RESTORE_WACC\000"
  /* 3826 */ "SPILL_WACC\000"
  /* 3837 */ "RESTORE_ACC\000"
  /* 3849 */ "SPILL_ACC\000"
  /* 3859 */ "BCC\000"
  /* 3863 */ "ADDC\000"
  /* 3868 */ "XXLANDC\000"
  /* 3876 */ "CRANDC\000"
  /* 3883 */ "EVANDC\000"
  /* 3890 */ "TABORTDC\000"
  /* 3899 */ "DTSTDC\000"
  /* 3906 */ "SUBFC\000"
  /* 3912 */ "SUBIC\000"
  /* 3918 */ "ADDIC\000"
  /* 3924 */ "RLDIC\000"
  /* 3930 */ "SUBFIC\000"
  /* 3937 */ "XSRDPIC\000"
  /* 3945 */ "XVRDPIC\000"
  /* 3953 */ "XVRSPIC\000"
  /* 3961 */ "G_INTRINSIC\000"
  /* 3973 */ "ICBLC\000"
  /* 3979 */ "XXSSUMUDMC\000"
  /* 3990 */ "BRINC\000"
  /* 3996 */ "G_FPTRUNC\000"
  /* 4006 */ "G_INTRINSIC_TRUNC\000"
  /* 4024 */ "G_TRUNC\000"
  /* 4032 */ "G_BUILD_VECTOR_TRUNC\000"
  /* 4053 */ "SLBSYNC\000"
  /* 4061 */ "TLBSYNC\000"
  /* 4069 */ "MSGSYNC\000"
  /* 4077 */ "ISYNC\000"
  /* 4083 */ "MSYNC\000"
  /* 4089 */ "G_DYN_STACKALLOC\000"
  /* 4106 */ "DYNALLOC\000"
  /* 4115 */ "BL8_NOTOC\000"
  /* 4125 */ "SELECT_CC_VSFRC\000"
  /* 4141 */ "SELECT_VSFRC\000"
  /* 4154 */ "XXLORC\000"
  /* 4161 */ "CRORC\000"
  /* 4167 */ "EVORC\000"
  /* 4173 */ "SELECT_CC_VRRC\000"
  /* 4188 */ "SELECT_VRRC\000"
  /* 4200 */ "SELECT_CC_VSSRC\000"
  /* 4216 */ "SELECT_VSSRC\000"
  /* 4229 */ "SELECT_CC_VSRC\000"
  /* 4244 */ "SELECT_VSRC\000"
  /* 4256 */ "SC\000"
  /* 4259 */ "TABORTWC\000"
  /* 4268 */ "VEXTSB2D\000"
  /* 4277 */ "VEXTSH2D\000"
  /* 4286 */ "VEXTSW2D\000"
  /* 4295 */ "TLBSX2D\000"
  /* 4303 */ "G_FMAD\000"
  /* 4310 */ "VSHASIGMAD\000"
  /* 4321 */ "G_FPEXTLOAD\000"
  /* 4333 */ "G_INDEXED_SEXTLOAD\000"
  /* 4352 */ "G_SEXTLOAD\000"
  /* 4363 */ "G_INDEXED_ZEXTLOAD\000"
  /* 4382 */ "G_ZEXTLOAD\000"
  /* 4393 */ "G_INDEXED_LOAD\000"
  /* 4408 */ "G_LOAD\000"
  /* 4415 */ "DMXXSHAPAD\000"
  /* 4426 */ "VSRAD\000"
  /* 4432 */ "VGBBD\000"
  /* 4438 */ "VCNTMBD\000"
  /* 4446 */ "VPRTYBD\000"
  /* 4454 */ "DENBCD\000"
  /* 4461 */ "CDTBCD\000"
  /* 4468 */ "EFDADD\000"
  /* 4475 */ "G_VECREDUCE_FADD\000"
  /* 4492 */ "G_FADD\000"
  /* 4499 */ "G_VECREDUCE_SEQ_FADD\000"
  /* 4520 */ "G_STRICT_FADD\000"
  /* 4534 */ "G_ATOMICRMW_FADD\000"
  /* 4551 */ "XXMULMULHIADD\000"
  /* 4565 */ "FMADD\000"
  /* 4571 */ "FNMADD\000"
  /* 4578 */ "XXMULMULLOADD\000"
  /* 4592 */ "EFSADD\000"
  /* 4599 */ "EVFSADD\000"
  /* 4607 */ "ATOMIC_LOAD_ADD\000"
  /* 4623 */ "G_VECREDUCE_ADD\000"
  /* 4639 */ "G_ADD\000"
  /* 4645 */ "G_PTR_ADD\000"
  /* 4655 */ "G_ATOMICRMW_ADD\000"
  /* 4671 */ "EVLDD\000"
  /* 4677 */ "MTVSRDD\000"
  /* 4685 */ "EVSTDD\000"
  /* 4692 */ "VCFUGED\000"
  /* 4700 */ "EFSCFD\000"
  /* 4707 */ "PLFD\000"
  /* 4712 */ "PSTFD\000"
  /* 4718 */ "FNEGD\000"
  /* 4724 */ "VNEGD\000"
  /* 4730 */ "MADDHD\000"
  /* 4737 */ "MULHD\000"
  /* 4743 */ "FCFID\000"
  /* 4749 */ "HRFID\000"
  /* 4755 */ "EFDCFSID\000"
  /* 4764 */ "FCTID\000"
  /* 4770 */ "EFDCFUID\000"
  /* 4779 */ "TLBLD\000"
  /* 4785 */ "MADDLD\000"
  /* 4792 */ "FSELD\000"
  /* 4798 */ "VMULLD\000"
  /* 4805 */ "CMPLD\000"
  /* 4811 */ "MFVSRLD\000"
  /* 4819 */ "VRLD\000"
  /* 4824 */ "VSLD\000"
  /* 4829 */ "SPILLTOVSR_LD\000"
  /* 4843 */ "FRIMD\000"
  /* 4849 */ "VBPERMD\000"
  /* 4857 */ "VPMSUMD\000"
  /* 4865 */ "XXLAND\000"
  /* 4872 */ "XXLNAND\000"
  /* 4880 */ "CRNAND\000"
  /* 4887 */ "EVNAND\000"
  /* 4894 */ "ATOMIC_LOAD_NAND\000"
  /* 4911 */ "G_ATOMICRMW_NAND\000"
  /* 4928 */ "CRAND\000"
  /* 4934 */ "EVAND\000"
  /* 4940 */ "ATOMIC_LOAD_AND\000"
  /* 4956 */ "G_VECREDUCE_AND\000"
  /* 4972 */ "G_AND\000"
  /* 4978 */ "G_ATOMICRMW_AND\000"
  /* 4994 */ "TEND\000"
  /* 4999 */ "LIFETIME_END\000"
  /* 5012 */ "FCPSGND\000"
  /* 5020 */ "FRIND\000"
  /* 5026 */ "G_BRCOND\000"
  /* 5035 */ "G_ATOMICRMW_USUB_COND\000"
  /* 5057 */ "DRRND\000"
  /* 5063 */ "SETRND\000"
  /* 5070 */ "G_LLROUND\000"
  /* 5080 */ "G_LROUND\000"
  /* 5089 */ "G_INTRINSIC_ROUND\000"
  /* 5107 */ "G_INTRINSIC_FPTRUNC_ROUND\000"
  /* 5133 */ "FCMPOD\000"
  /* 5140 */ "DDEDPD\000"
  /* 5147 */ "VPDEPD\000"
  /* 5154 */ "FRIPD\000"
  /* 5160 */ "CMPD\000"
  /* 5165 */ "LOAD_STACK_GUARD\000"
  /* 5182 */ "XXBRD\000"
  /* 5188 */ "BUILD_QUADWORD\000"
  /* 5203 */ "RESTORE_QUADWORD\000"
  /* 5220 */ "SPILL_QUADWORD\000"
  /* 5235 */ "SPLIT_QUADWORD\000"
  /* 5250 */ "MTMSRD\000"
  /* 5257 */ "MFVSRD\000"
  /* 5264 */ "MTVSRD\000"
  /* 5271 */ "MFVRD\000"
  /* 5277 */ "MTVRD\000"
  /* 5283 */ "FABSD\000"
  /* 5289 */ "FNABSD\000"
  /* 5296 */ "VMODSD\000"
  /* 5303 */ "VMULESD\000"
  /* 5311 */ "VDIVESD\000"
  /* 5319 */ "VMULHSD\000"
  /* 5327 */ "VMINSD\000"
  /* 5334 */ "VINSD\000"
  /* 5340 */ "VMULOSD\000"
  /* 5348 */ "VCMPGTSD\000"
  /* 5357 */ "VDIVSD\000"
  /* 5364 */ "VMAXSD\000"
  /* 5371 */ "PLXSD\000"
  /* 5377 */ "PSTXSD\000"
  /* 5384 */ "VEXTRACTD\000"
  /* 5394 */ "CBCDTD\000"
  /* 5401 */ "VPOPCNTD\000"
  /* 5410 */ "VINSERTD\000"
  /* 5419 */ "PSTD\000"
  /* 5424 */ "VPEXTD\000"
  /* 5431 */ "VMSUMCUD\000"
  /* 5440 */ "VMODUD\000"
  /* 5447 */ "VMULEUD\000"
  /* 5455 */ "VDIVEUD\000"
  /* 5463 */ "VMULHUD\000"
  /* 5471 */ "VMINUD\000"
  /* 5478 */ "VMULOUD\000"
  /* 5486 */ "FCMPUD\000"
  /* 5493 */ "VCMPEQUD\000"
  /* 5502 */ "VCMPGTUD\000"
  /* 5511 */ "VDIVUD\000"
  /* 5518 */ "VMAXUD\000"
  /* 5525 */ "XXBLENDVD\000"
  /* 5535 */ "DIVD\000"
  /* 5540 */ "FRIZD\000"
  /* 5546 */ "VCLZD\000"
  /* 5552 */ "CNTLZD\000"
  /* 5559 */ "VCTZD\000"
  /* 5565 */ "CNTTZD\000"
  /* 5572 */ "PSEUDO_PROBE\000"
  /* 5585 */ "MFBHRBE\000"
  /* 5593 */ "G_SSUBE\000"
  /* 5601 */ "G_USUBE\000"
  /* 5609 */ "CFENCE\000"
  /* 5616 */ "G_FENCE\000"
  /* 5624 */ "ARITH_FENCE\000"
  /* 5636 */ "REG_SEQUENCE\000"
  /* 5649 */ "MFFSCE\000"
  /* 5656 */ "G_SADDE\000"
  /* 5664 */ "G_UADDE\000"
  /* 5672 */ "G_GET_FPMODE\000"
  /* 5685 */ "G_RESET_FPMODE\000"
  /* 5700 */ "G_SET_FPMODE\000"
  /* 5713 */ "DIVDE\000"
  /* 5719 */ "G_FMINNUM_IEEE\000"
  /* 5734 */ "G_FMAXNUM_IEEE\000"
  /* 5749 */ "SLBMFEE\000"
  /* 5757 */ "WRTEE\000"
  /* 5763 */ "SUBFE\000"
  /* 5769 */ "EVLWHE\000"
  /* 5776 */ "EVSTWHE\000"
  /* 5784 */ "SLBIE\000"
  /* 5790 */ "TLBIE\000"
  /* 5796 */ "G_VSCALE\000"
  /* 5805 */ "G_JUMP_TABLE\000"
  /* 5818 */ "BUNDLE\000"
  /* 5825 */ "ADDME\000"
  /* 5831 */ "SUBFME\000"
  /* 5838 */ "G_MEMSET_INLINE\000"
  /* 5854 */ "G_MEMCPY_INLINE\000"
  /* 5870 */ "RELOC_NONE\000"
  /* 5881 */ "LDAT_CSNE\000"
  /* 5891 */ "LWAT_CSNE\000"
  /* 5901 */ "LOCAL_ESCAPE\000"
  /* 5914 */ "SELECT_CC_SPE\000"
  /* 5928 */ "SELECT_SPE\000"
  /* 5939 */ "TLBRE\000"
  /* 5945 */ "FRE\000"
  /* 5949 */ "G_FPTRUNCSTORE\000"
  /* 5964 */ "G_STACKRESTORE\000"
  /* 5979 */ "G_INDEXED_STORE\000"
  /* 5995 */ "G_STORE\000"
  /* 6003 */ "G_BITREVERSE\000"
  /* 6016 */ "FAKE_USE\000"
  /* 6025 */ "SLBMTE\000"
  /* 6032 */ "FRSQRTE\000"
  /* 6040 */ "DBG_VALUE\000"
  /* 6050 */ "G_GLOBAL_VALUE\000"
  /* 6065 */ "G_PTRAUTH_GLOBAL_VALUE\000"
  /* 6088 */ "CONVERGENCECTRL_GLUE\000"
  /* 6109 */ "G_STACKSAVE\000"
  /* 6121 */ "MFVRSAVE\000"
  /* 6130 */ "MTVRSAVE\000"
  /* 6139 */ "G_MEMMOVE\000"
  /* 6149 */ "TLBWE\000"
  /* 6155 */ "DIVWE\000"
  /* 6161 */ "EVSTWWE\000"
  /* 6169 */ "ADDZE\000"
  /* 6175 */ "G_FREEZE\000"
  /* 6184 */ "SUBFZE\000"
  /* 6191 */ "G_FCANONICALIZE\000"
  /* 6207 */ "DCBF\000"
  /* 6212 */ "SUBF\000"
  /* 6217 */ "G_FMODF\000"
  /* 6225 */ "INIT_UNDEF\000"
  /* 6236 */ "G_IMPLICIT_DEF\000"
  /* 6251 */ "DBG_INSTR_REF\000"
  /* 6265 */ "EVMHESMF\000"
  /* 6274 */ "EVMWHSMF\000"
  /* 6283 */ "EVMHOSMF\000"
  /* 6292 */ "EVMWSMF\000"
  /* 6300 */ "MCRF\000"
  /* 6305 */ "MFOCRF\000"
  /* 6312 */ "MTOCRF\000"
  /* 6319 */ "MTCRF\000"
  /* 6325 */ "EFDCFSF\000"
  /* 6333 */ "EFSCFSF\000"
  /* 6341 */ "EVFSCFSF\000"
  /* 6350 */ "MTFSF\000"
  /* 6356 */ "EVMHESSF\000"
  /* 6365 */ "EVMWHSSF\000"
  /* 6374 */ "EVMHOSSF\000"
  /* 6383 */ "EVMWSSF\000"
  /* 6391 */ "EFDCTSF\000"
  /* 6399 */ "EFSCTSF\000"
  /* 6407 */ "EVFSCTSF\000"
  /* 6416 */ "DTSTSF\000"
  /* 6423 */ "EFDCFUF\000"
  /* 6431 */ "EFSCFUF\000"
  /* 6439 */ "EVFSCFUF\000"
  /* 6448 */ "EFDCTUF\000"
  /* 6456 */ "EFSCTUF\000"
  /* 6464 */ "EVFSCTUF\000"
  /* 6473 */ "DTSTDG\000"
  /* 6480 */ "SLBIEG\000"
  /* 6487 */ "EFDNEG\000"
  /* 6494 */ "G_FNEG\000"
  /* 6501 */ "EFSNEG\000"
  /* 6508 */ "EVFSNEG\000"
  /* 6516 */ "EVNEG\000"
  /* 6522 */ "EXTRACT_SUBREG\000"
  /* 6537 */ "INSERT_SUBREG\000"
  /* 6551 */ "G_SEXT_INREG\000"
  /* 6564 */ "SUBREG_TO_REG\000"
  /* 6578 */ "G_ATOMIC_CMPXCHG\000"
  /* 6595 */ "G_ATOMICRMW_XCHG\000"
  /* 6612 */ "G_GET_ROUNDING\000"
  /* 6627 */ "G_SET_ROUNDING\000"
  /* 6642 */ "G_FLOG\000"
  /* 6649 */ "G_VAARG\000"
  /* 6657 */ "PREALLOCATED_ARG\000"
  /* 6674 */ "V_SET0H\000"
  /* 6682 */ "VSRAH\000"
  /* 6688 */ "VCNTMBH\000"
  /* 6696 */ "G_PREFETCH\000"
  /* 6707 */ "EVLDH\000"
  /* 6713 */ "EVSTDH\000"
  /* 6720 */ "VCMPNEH\000"
  /* 6728 */ "VMRGHH\000"
  /* 6735 */ "VUCMPRHH\000"
  /* 6744 */ "VMRGLH\000"
  /* 6751 */ "VUCMPRLH\000"
  /* 6760 */ "VRLH\000"
  /* 6765 */ "VSLH\000"
  /* 6770 */ "G_SMULH\000"
  /* 6778 */ "G_UMULH\000"
  /* 6786 */ "VPMSUMH\000"
  /* 6794 */ "G_FTANH\000"
  /* 6802 */ "G_FSINH\000"
  /* 6810 */ "XXBRH\000"
  /* 6816 */ "VSRH\000"
  /* 6821 */ "DMSHA2HASH\000"
  /* 6832 */ "DMSHA3HASH\000"
  /* 6843 */ "VMULESH\000"
  /* 6851 */ "V_SETALLONESH\000"
  /* 6865 */ "VAVGSH\000"
  /* 6872 */ "VUPKHSH\000"
  /* 6880 */ "XVMULHSH\000"
  /* 6889 */ "VSPLTISH\000"
  /* 6898 */ "VUPKLSH\000"
  /* 6906 */ "VMINSH\000"
  /* 6913 */ "G_FCOSH\000"
  /* 6921 */ "VMULOSH\000"
  /* 6929 */ "VCMPGTSH\000"
  /* 6938 */ "EVEXTSH\000"
  /* 6946 */ "VMAXSH\000"
  /* 6953 */ "VSPLTH\000"
  /* 6960 */ "VPOPCNTH\000"
  /* 6969 */ "VINSERTH\000"
  /* 6978 */ "PSTH\000"
  /* 6983 */ "VABSDUH\000"
  /* 6991 */ "VMULEUH\000"
  /* 6999 */ "VAVGUH\000"
  /* 7006 */ "XVMULHUH\000"
  /* 7015 */ "VMINUH\000"
  /* 7022 */ "VMULOUH\000"
  /* 7030 */ "VCMPEQUH\000"
  /* 7039 */ "VEXTRACTUH\000"
  /* 7050 */ "VCMPGTUH\000"
  /* 7059 */ "VMAXUH\000"
  /* 7066 */ "XXBLENDVH\000"
  /* 7076 */ "VCMPNEZH\000"
  /* 7085 */ "VCLZH\000"
  /* 7091 */ "VCTZH\000"
  /* 7097 */ "DQUAI\000"
  /* 7103 */ "DCBI\000"
  /* 7108 */ "ICBI\000"
  /* 7113 */ "VSLDBI\000"
  /* 7120 */ "VSRDBI\000"
  /* 7127 */ "PSUBI\000"
  /* 7133 */ "DCCCI\000"
  /* 7139 */ "ICCCI\000"
  /* 7145 */ "TABORTDCI\000"
  /* 7155 */ "RFCI\000"
  /* 7160 */ "RFMCI\000"
  /* 7166 */ "TABORTWCI\000"
  /* 7176 */ "SRADI\000"
  /* 7182 */ "PADDI\000"
  /* 7188 */ "RFDI\000"
  /* 7193 */ "CMPLDI\000"
  /* 7200 */ "CLRLSLDI\000"
  /* 7209 */ "EXTLDI\000"
  /* 7216 */ "XXPERMDI\000"
  /* 7225 */ "CMPDI\000"
  /* 7231 */ "CLRRDI\000"
  /* 7238 */ "INSRDI\000"
  /* 7245 */ "ROTRDI\000"
  /* 7252 */ "EXTRDI\000"
  /* 7259 */ "TDI\000"
  /* 7263 */ "WRTEEI\000"
  /* 7270 */ "RFI\000"
  /* 7274 */ "MTFSFI\000"
  /* 7281 */ "DTSTSFI\000"
  /* 7289 */ "EVSPLATFI\000"
  /* 7299 */ "EVMERGEHI\000"
  /* 7309 */ "EVMERGELOHI\000"
  /* 7321 */ "DBG_PHI\000"
  /* 7329 */ "DMXXEXTFDMR512_HI\000"
  /* 7347 */ "DMXXINSTDMR512_HI\000"
  /* 7365 */ "TLBLI\000"
  /* 7371 */ "DSCLI\000"
  /* 7377 */ "MULLI\000"
  /* 7383 */ "PLI\000"
  /* 7387 */ "EXTSWSLI\000"
  /* 7396 */ "MTVSRBMI\000"
  /* 7405 */ "VRLDMI\000"
  /* 7412 */ "RLDIMI\000"
  /* 7419 */ "RLWIMI\000"
  /* 7426 */ "VRLQMI\000"
  /* 7433 */ "EVMHESMI\000"
  /* 7442 */ "EVMWHSMI\000"
  /* 7451 */ "EVMHOSMI\000"
  /* 7460 */ "EVMWSMI\000"
  /* 7468 */ "EVMHEUMI\000"
  /* 7477 */ "EVMWHUMI\000"
  /* 7486 */ "EVMWLUMI\000"
  /* 7495 */ "EVMHOUMI\000"
  /* 7504 */ "EVMWUMI\000"
  /* 7512 */ "VRLWMI\000"
  /* 7519 */ "MFFSCRNI\000"
  /* 7528 */ "MFFSCDRNI\000"
  /* 7538 */ "VSLDOI\000"
  /* 7545 */ "XSRDPI\000"
  /* 7552 */ "XVRDPI\000"
  /* 7559 */ "XSRQPI\000"
  /* 7566 */ "XVRSPI\000"
  /* 7573 */ "DSCRI\000"
  /* 7579 */ "XORI\000"
  /* 7584 */ "EFDCFSI\000"
  /* 7592 */ "EFSCFSI\000"
  /* 7600 */ "EVFSCFSI\000"
  /* 7609 */ "G_FPTOSI\000"
  /* 7618 */ "EFDCTSI\000"
  /* 7626 */ "EFSCTSI\000"
  /* 7634 */ "EVFSCTSI\000"
  /* 7643 */ "EVSPLATI\000"
  /* 7652 */ "LDtocJTI\000"
  /* 7661 */ "EFDCFUI\000"
  /* 7669 */ "EFSCFUI\000"
  /* 7677 */ "EVFSCFUI\000"
  /* 7686 */ "G_FPTOUI\000"
  /* 7695 */ "EFDCTUI\000"
  /* 7703 */ "EFSCTUI\000"
  /* 7711 */ "EVFSCTUI\000"
  /* 7720 */ "SRAWI\000"
  /* 7726 */ "XXSLDWI\000"
  /* 7734 */ "CMPLWI\000"
  /* 7741 */ "EVRLWI\000"
  /* 7748 */ "CLRLSLWI\000"
  /* 7757 */ "INSLWI\000"
  /* 7764 */ "EVSLWI\000"
  /* 7771 */ "EXTLWI\000"
  /* 7778 */ "G_FPOWI\000"
  /* 7786 */ "CMPWI\000"
  /* 7792 */ "CLRRWI\000"
  /* 7799 */ "INSRWI\000"
  /* 7806 */ "ROTRWI\000"
  /* 7813 */ "EXTRWI\000"
  /* 7820 */ "LSWI\000"
  /* 7825 */ "STSWI\000"
  /* 7831 */ "TWI\000"
  /* 7835 */ "TCHECK\000"
  /* 7842 */ "HASHCHK\000"
  /* 7850 */ "COPY_LANEMASK\000"
  /* 7864 */ "G_PTRMASK\000"
  /* 7874 */ "XXEVAL\000"
  /* 7881 */ "VSTRIBL\000"
  /* 7889 */ "gBCL\000"
  /* 7894 */ "BCCL\000"
  /* 7899 */ "RLDCL\000"
  /* 7905 */ "RLDICL\000"
  /* 7912 */ "GC_LABEL\000"
  /* 7921 */ "DBG_LABEL\000"
  /* 7931 */ "EH_LABEL\000"
  /* 7940 */ "ANNOTATION_LABEL\000"
  /* 7957 */ "TLBIEL\000"
  /* 7964 */ "ICALL_BRANCH_FUNNEL\000"
  /* 7984 */ "GETtlsldADDRPCREL\000"
  /* 8002 */ "GETtlsADDRPCREL\000"
  /* 8018 */ "ISEL\000"
  /* 8023 */ "EVSEL\000"
  /* 8029 */ "XXSEL\000"
  /* 8035 */ "DCBFL\000"
  /* 8041 */ "VSTRIHL\000"
  /* 8049 */ "G_FSHL\000"
  /* 8056 */ "G_SHL\000"
  /* 8062 */ "G_FCEIL\000"
  /* 8070 */ "G_SAVGCEIL\000"
  /* 8081 */ "G_UAVGCEIL\000"
  /* 8092 */ "PATCHABLE_TAIL_CALL\000"
  /* 8112 */ "PATCHABLE_TYPED_EVENT_CALL\000"
  /* 8139 */ "PATCHABLE_EVENT_CALL\000"
  /* 8160 */ "FENTRY_CALL\000"
  /* 8172 */ "DSSALL\000"
  /* 8179 */ "KILL\000"
  /* 8184 */ "LXVPRLL\000"
  /* 8192 */ "STXVPRLL\000"
  /* 8201 */ "LXVRLL\000"
  /* 8208 */ "STXVRLL\000"
  /* 8216 */ "LXVLL\000"
  /* 8222 */ "STXVLL\000"
  /* 8229 */ "G_CONSTANT_POOL\000"
  /* 8245 */ "MTLPL\000"
  /* 8251 */ "BLRL\000"
  /* 8256 */ "gBCLRL\000"
  /* 8263 */ "BCCLRL\000"
  /* 8270 */ "BDZLRL\000"
  /* 8277 */ "BDNZLRL\000"
  /* 8285 */ "LXVPRL\000"
  /* 8292 */ "STXVPRL\000"
  /* 8300 */ "BCTRL\000"
  /* 8306 */ "gBCCTRL\000"
  /* 8314 */ "BCCCTRL\000"
  /* 8322 */ "LXVRL\000"
  /* 8328 */ "STXVRL\000"
  /* 8335 */ "MFFSL\000"
  /* 8341 */ "LVSL\000"
  /* 8346 */ "G_ROTL\000"
  /* 8353 */ "EFDMUL\000"
  /* 8360 */ "G_VECREDUCE_FMUL\000"
  /* 8377 */ "G_FMUL\000"
  /* 8384 */ "G_VECREDUCE_SEQ_FMUL\000"
  /* 8405 */ "G_STRICT_FMUL\000"
  /* 8419 */ "G_CLMUL\000"
  /* 8427 */ "XXMULMUL\000"
  /* 8436 */ "EFSMUL\000"
  /* 8443 */ "EVFSMUL\000"
  /* 8451 */ "G_VECREDUCE_MUL\000"
  /* 8467 */ "G_MUL\000"
  /* 8473 */ "LXVL\000"
  /* 8478 */ "STXVL\000"
  /* 8484 */ "LBARXL\000"
  /* 8491 */ "LDARXL\000"
  /* 8498 */ "LHARXL\000"
  /* 8505 */ "LQARXL\000"
  /* 8512 */ "LWARXL\000"
  /* 8519 */ "LVXL\000"
  /* 8524 */ "STVXL\000"
  /* 8530 */ "DCBZL\000"
  /* 8536 */ "BDZL\000"
  /* 8541 */ "BDNZL\000"
  /* 8547 */ "LDtocL\000"
  /* 8554 */ "ADDItocL\000"
  /* 8563 */ "LWZtocL\000"
  /* 8571 */ "ADDItlsgdL\000"
  /* 8582 */ "ADDItlsldL\000"
  /* 8593 */ "LDgotTprelL\000"
  /* 8605 */ "ADDIdtprelL\000"
  /* 8617 */ "VEXPANDBM\000"
  /* 8627 */ "VMSUMMBM\000"
  /* 8636 */ "MTVSRBM\000"
  /* 8644 */ "VEXTRACTBM\000"
  /* 8655 */ "VSUBUBM\000"
  /* 8663 */ "VADDUBM\000"
  /* 8671 */ "VMSUMUBM\000"
  /* 8680 */ "XXGENPCVBM\000"
  /* 8691 */ "VEXPANDDM\000"
  /* 8701 */ "MTVSRDM\000"
  /* 8709 */ "VEXTRACTDM\000"
  /* 8720 */ "VSUBUDM\000"
  /* 8728 */ "VADDUDM\000"
  /* 8736 */ "VMSUMUDM\000"
  /* 8745 */ "XXSSUMUDM\000"
  /* 8755 */ "XXGENPCVDM\000"
  /* 8766 */ "VCLZDM\000"
  /* 8773 */ "CNTLZDM\000"
  /* 8781 */ "VCTZDM\000"
  /* 8788 */ "CNTTZDM\000"
  /* 8796 */ "G_FREM\000"
  /* 8803 */ "G_STRICT_FREM\000"
  /* 8817 */ "G_SREM\000"
  /* 8824 */ "G_UREM\000"
  /* 8831 */ "G_SDIVREM\000"
  /* 8841 */ "G_UDIVREM\000"
  /* 8851 */ "VEXPANDHM\000"
  /* 8861 */ "MTVSRHM\000"
  /* 8869 */ "VMSUMSHM\000"
  /* 8878 */ "VEXTRACTHM\000"
  /* 8889 */ "XVSUBUHM\000"
  /* 8898 */ "VMLADDUHM\000"
  /* 8908 */ "XVADDUHM\000"
  /* 8917 */ "XVMULUHM\000"
  /* 8926 */ "VMSUMUHM\000"
  /* 8935 */ "XXGENPCVHM\000"
  /* 8946 */ "TRECLAIM\000"
  /* 8955 */ "VRFIM\000"
  /* 8961 */ "XSRDPIM\000"
  /* 8969 */ "XVRDPIM\000"
  /* 8977 */ "XVRSPIM\000"
  /* 8985 */ "SETFLM\000"
  /* 8992 */ "VRLDNM\000"
  /* 8999 */ "RLWINM\000"
  /* 9006 */ "VRLQNM\000"
  /* 9013 */ "VRLWNM\000"
  /* 9020 */ "VEXPANDQM\000"
  /* 9030 */ "MTVSRQM\000"
  /* 9038 */ "VEXTRACTQM\000"
  /* 9049 */ "XSMERGE2T1UQM\000"
  /* 9063 */ "XSREBASE2T1UQM\000"
  /* 9078 */ "XSMERGE3T1UQM\000"
  /* 9092 */ "XSREBASE3T1UQM\000"
  /* 9107 */ "XSMERGE2T2UQM\000"
  /* 9121 */ "XSREBASE2T2UQM\000"
  /* 9136 */ "XSREBASE3T2UQM\000"
  /* 9151 */ "XSMERGE2T3UQM\000"
  /* 9165 */ "XSREBASE2T3UQM\000"
  /* 9180 */ "XSREBASE3T3UQM\000"
  /* 9195 */ "XSREBASE2T4UQM\000"
  /* 9210 */ "XSADDSUBUQM\000"
  /* 9222 */ "VSUBUQM\000"
  /* 9230 */ "XSADDADDUQM\000"
  /* 9242 */ "VADDUQM\000"
  /* 9250 */ "VSUBEUQM\000"
  /* 9259 */ "VADDEUQM\000"
  /* 9268 */ "XSADDSUBSUQM\000"
  /* 9281 */ "XSADDADDSUQM\000"
  /* 9294 */ "VPERM\000"
  /* 9300 */ "XXPERM\000"
  /* 9307 */ "BLA8_RM\000"
  /* 9315 */ "BL8_RM\000"
  /* 9322 */ "BCTRL8_RM\000"
  /* 9332 */ "BLA_RM\000"
  /* 9339 */ "BL8_NOTOC_RM\000"
  /* 9352 */ "BL_RM\000"
  /* 9358 */ "BCTRL_RM\000"
  /* 9367 */ "BLA8_NOP_RM\000"
  /* 9379 */ "BL8_NOP_RM\000"
  /* 9390 */ "BL_NOP_RM\000"
  /* 9400 */ "BL8_LDinto_toc_RM\000"
  /* 9418 */ "BCTRL8_LDinto_toc_RM\000"
  /* 9439 */ "BL_LWZinto_toc_RM\000"
  /* 9457 */ "BCTRL_LWZinto_toc_RM\000"
  /* 9478 */ "INLINEASM\000"
  /* 9488 */ "VPKUDUM\000"
  /* 9496 */ "VPKUHUM\000"
  /* 9504 */ "G_VECREDUCE_FMINIMUM\000"
  /* 9525 */ "G_FMINIMUM\000"
  /* 9536 */ "G_ATOMICRMW_FMINIMUM\000"
  /* 9557 */ "G_VECREDUCE_FMAXIMUM\000"
  /* 9578 */ "G_FMAXIMUM\000"
  /* 9589 */ "G_ATOMICRMW_FMAXIMUM\000"
  /* 9610 */ "G_FMINIMUMNUM\000"
  /* 9624 */ "G_ATOMICRMW_FMINIMUMNUM\000"
  /* 9648 */ "G_FMAXIMUMNUM\000"
  /* 9662 */ "G_ATOMICRMW_FMAXIMUMNUM\000"
  /* 9686 */ "G_FMINNUM\000"
  /* 9696 */ "G_FMAXNUM\000"
  /* 9706 */ "VPKUWUM\000"
  /* 9714 */ "VEXPANDWM\000"
  /* 9724 */ "MTVSRWM\000"
  /* 9732 */ "VEXTRACTWM\000"
  /* 9743 */ "XVSUBUWM\000"
  /* 9752 */ "XVADDUWM\000"
  /* 9761 */ "XVMULUWM\000"
  /* 9770 */ "XXGENPCVWM\000"
  /* 9781 */ "EVMHEGSMFAN\000"
  /* 9793 */ "EVMHOGSMFAN\000"
  /* 9805 */ "EVMWSMFAN\000"
  /* 9815 */ "EVMWSSFAN\000"
  /* 9825 */ "EVMHEGSMIAN\000"
  /* 9837 */ "EVMHOGSMIAN\000"
  /* 9849 */ "EVMWSMIAN\000"
  /* 9859 */ "EVMHEGUMIAN\000"
  /* 9871 */ "EVMHOGUMIAN\000"
  /* 9883 */ "EVMWUMIAN\000"
  /* 9893 */ "G_FATAN\000"
  /* 9901 */ "G_FTAN\000"
  /* 9908 */ "G_INTRINSIC_ROUNDEVEN\000"
  /* 9930 */ "G_ASSERT_ALIGN\000"
  /* 9945 */ "G_FCOPYSIGN\000"
  /* 9957 */ "VUCMPRHN\000"
  /* 9966 */ "VRFIN\000"
  /* 9972 */ "TBEGIN\000"
  /* 9979 */ "G_VECREDUCE_FMIN\000"
  /* 9996 */ "G_ATOMICRMW_FMIN\000"
  /* 10013 */ "G_VECREDUCE_SMIN\000"
  /* 10030 */ "G_SMIN\000"
  /* 10037 */ "ATOMIC_LOAD_UMIN\000"
  /* 10054 */ "G_VECREDUCE_UMIN\000"
  /* 10071 */ "G_UMIN\000"
  /* 10078 */ "G_ATOMICRMW_UMIN\000"
  /* 10095 */ "ATOMIC_LOAD_MIN\000"
  /* 10111 */ "G_ATOMICRMW_MIN\000"
  /* 10127 */ "MFSRIN\000"
  /* 10134 */ "MTSRIN\000"
  /* 10141 */ "G_FASIN\000"
  /* 10149 */ "G_FSIN\000"
  /* 10156 */ "VUCMPRLN\000"
  /* 10165 */ "PMXVBF16GER2NN\000"
  /* 10180 */ "PMXVF16GER2NN\000"
  /* 10194 */ "PMDMXVBF16GERX2NN\000"
  /* 10212 */ "PMDMXVF16GERX2NN\000"
  /* 10229 */ "PMXVF32GERNN\000"
  /* 10242 */ "PMXVF64GERNN\000"
  /* 10255 */ "PMXVBF16GER2WNN\000"
  /* 10271 */ "PMXVF16GER2WNN\000"
  /* 10286 */ "PMXVF32GERWNN\000"
  /* 10300 */ "PMXVF64GERWNN\000"
  /* 10314 */ "CFI_INSTRUCTION\000"
  /* 10330 */ "G_CTLZ_ZERO_POISON\000"
  /* 10349 */ "G_CTTZ_ZERO_POISON\000"
  /* 10368 */ "PMXVBF16GER2PN\000"
  /* 10383 */ "PMXVF16GER2PN\000"
  /* 10397 */ "PMDMXVBF16GERX2PN\000"
  /* 10415 */ "PMDMXVF16GERX2PN\000"
  /* 10432 */ "XSCVSPDPN\000"
  /* 10442 */ "PMXVF32GERPN\000"
  /* 10455 */ "PMXVF64GERPN\000"
  /* 10468 */ "XVCVBF16SPN\000"
  /* 10480 */ "XSCVDPSPN\000"
  /* 10490 */ "PMXVBF16GER2WPN\000"
  /* 10506 */ "PMXVF16GER2WPN\000"
  /* 10521 */ "PMXVF32GERWPN\000"
  /* 10535 */ "PMXVF64GERWPN\000"
  /* 10549 */ "DARN\000"
  /* 10554 */ "MFFSCRN\000"
  /* 10562 */ "MFFSCDRN\000"
  /* 10571 */ "DRINTN\000"
  /* 10578 */ "ATTN\000"
  /* 10583 */ "ADJCALLSTACKDOWN\000"
  /* 10600 */ "ADD4O\000"
  /* 10606 */ "ADDC8O\000"
  /* 10613 */ "SUBFC8O\000"
  /* 10621 */ "ADD8O\000"
  /* 10627 */ "ADDE8O\000"
  /* 10634 */ "SUBFE8O\000"
  /* 10642 */ "ADDME8O\000"
  /* 10650 */ "SUBFME8O\000"
  /* 10659 */ "ADDZE8O\000"
  /* 10667 */ "SUBFZE8O\000"
  /* 10676 */ "SUBF8O\000"
  /* 10683 */ "NEG8O\000"
  /* 10689 */ "G_SSUBO\000"
  /* 10697 */ "G_USUBO\000"
  /* 10705 */ "ADDCO\000"
  /* 10711 */ "SUBFCO\000"
  /* 10718 */ "G_SADDO\000"
  /* 10726 */ "G_UADDO\000"
  /* 10734 */ "MULLDO\000"
  /* 10741 */ "LDAT_CSNE_PSEUDO\000"
  /* 10758 */ "LWAT_CSNE_PSEUDO\000"
  /* 10775 */ "LQX_PSEUDO\000"
  /* 10786 */ "STQX_PSEUDO\000"
  /* 10798 */ "DIVDO\000"
  /* 10804 */ "ADDEO\000"
  /* 10810 */ "DIVDEO\000"
  /* 10817 */ "SUBFEO\000"
  /* 10824 */ "ADDMEO\000"
  /* 10831 */ "SUBFMEO\000"
  /* 10839 */ "DIVWEO\000"
  /* 10846 */ "ADDZEO\000"
  /* 10853 */ "SUBFZEO\000"
  /* 10861 */ "SUBFO\000"
  /* 10867 */ "JUMP_TABLE_DEBUG_INFO\000"
  /* 10889 */ "NEGO\000"
  /* 10894 */ "EVSTWHO\000"
  /* 10902 */ "TLBSYNCIO\000"
  /* 10912 */ "PTESYNCIO\000"
  /* 10922 */ "TLBIEIO\000"
  /* 10930 */ "PseudoEIEIO\000"
  /* 10942 */ "EnforceIEIO\000"
  /* 10954 */ "EVMERGELO\000"
  /* 10964 */ "EVMERGEHILO\000"
  /* 10976 */ "VSLO\000"
  /* 10981 */ "G_SMULO\000"
  /* 10989 */ "G_UMULO\000"
  /* 10997 */ "XSCVQPDPO\000"
  /* 11007 */ "DCMPO\000"
  /* 11013 */ "XSNMSUBQPO\000"
  /* 11024 */ "XSMSUBQPO\000"
  /* 11034 */ "XSSUBQPO\000"
  /* 11043 */ "XSNMADDQPO\000"
  /* 11054 */ "XSMADDQPO\000"
  /* 11064 */ "XSADDQPO\000"
  /* 11073 */ "XSMULQPO\000"
  /* 11082 */ "XSSQRTQPO\000"
  /* 11092 */ "XSDIVQPO\000"
  /* 11101 */ "G_BZERO\000"
  /* 11109 */ "VSRO\000"
  /* 11114 */ "DIVDUO\000"
  /* 11121 */ "DIVDEUO\000"
  /* 11129 */ "DIVWEUO\000"
  /* 11137 */ "DIVWUO\000"
  /* 11144 */ "MULLWO\000"
  /* 11151 */ "DIVWO\000"
  /* 11157 */ "EVSTWWO\000"
  /* 11165 */ "STACKMAP\000"
  /* 11174 */ "NAP\000"
  /* 11178 */ "G_DEBUGTRAP\000"
  /* 11190 */ "G_UBSANTRAP\000"
  /* 11202 */ "G_TRAP\000"
  /* 11209 */ "G_ATOMICRMW_UDEC_WRAP\000"
  /* 11231 */ "G_ATOMICRMW_UINC_WRAP\000"
  /* 11253 */ "G_BSWAP\000"
  /* 11261 */ "ATOMIC_SWAP\000"
  /* 11273 */ "XXAESDECP\000"
  /* 11283 */ "XXAESENCP\000"
  /* 11293 */ "XSNMSUBADP\000"
  /* 11304 */ "XVNMSUBADP\000"
  /* 11315 */ "XSMSUBADP\000"
  /* 11325 */ "XVMSUBADP\000"
  /* 11335 */ "XSNMADDADP\000"
  /* 11346 */ "XVNMADDADP\000"
  /* 11357 */ "XSMADDADP\000"
  /* 11367 */ "XVMADDADP\000"
  /* 11377 */ "XSSUBDP\000"
  /* 11385 */ "XVSUBDP\000"
  /* 11393 */ "XSTSTDCDP\000"
  /* 11403 */ "XVTSTDCDP\000"
  /* 11413 */ "XSMINCDP\000"
  /* 11422 */ "XSMAXCDP\000"
  /* 11431 */ "XSADDDP\000"
  /* 11439 */ "XVADDDP\000"
  /* 11447 */ "XSCVSXDDP\000"
  /* 11457 */ "XVCVSXDDP\000"
  /* 11467 */ "XSCVUXDDP\000"
  /* 11477 */ "XVCVUXDDP\000"
  /* 11487 */ "XSCMPGEDP\000"
  /* 11497 */ "XVCMPGEDP\000"
  /* 11507 */ "XSREDP\000"
  /* 11514 */ "XVREDP\000"
  /* 11521 */ "XSRSQRTEDP\000"
  /* 11532 */ "XVRSQRTEDP\000"
  /* 11543 */ "XSNEGDP\000"
  /* 11551 */ "XVNEGDP\000"
  /* 11559 */ "XSXSIGDP\000"
  /* 11568 */ "XVXSIGDP\000"
  /* 11577 */ "XXSPLTIDP\000"
  /* 11587 */ "XSMINJDP\000"
  /* 11596 */ "XSMAXJDP\000"
  /* 11605 */ "XSMULDP\000"
  /* 11613 */ "XVMULDP\000"
  /* 11621 */ "XSNMSUBMDP\000"
  /* 11632 */ "XVNMSUBMDP\000"
  /* 11643 */ "XSMSUBMDP\000"
  /* 11653 */ "XVMSUBMDP\000"
  /* 11663 */ "XSNMADDMDP\000"
  /* 11674 */ "XVNMADDMDP\000"
  /* 11685 */ "XSMADDMDP\000"
  /* 11695 */ "XVMADDMDP\000"
  /* 11705 */ "XSCPSGNDP\000"
  /* 11715 */ "XVCPSGNDP\000"
  /* 11725 */ "XSMINDP\000"
  /* 11733 */ "XVMINDP\000"
  /* 11741 */ "MSGSNDP\000"
  /* 11749 */ "XSCMPODP\000"
  /* 11758 */ "XSCVHPDP\000"
  /* 11767 */ "XSCVQPDP\000"
  /* 11776 */ "XSCVSPDP\000"
  /* 11785 */ "XVCVSPDP\000"
  /* 11794 */ "XSIEXPDP\000"
  /* 11803 */ "XVIEXPDP\000"
  /* 11812 */ "XSCMPEXPDP\000"
  /* 11823 */ "XSXEXPDP\000"
  /* 11832 */ "XVXEXPDP\000"
  /* 11841 */ "XSCMPEQDP\000"
  /* 11851 */ "XVCMPEQDP\000"
  /* 11861 */ "XSNABSDP\000"
  /* 11870 */ "XVNABSDP\000"
  /* 11879 */ "XSABSDP\000"
  /* 11887 */ "XVABSDP\000"
  /* 11895 */ "DCTDP\000"
  /* 11901 */ "XSCMPGTDP\000"
  /* 11911 */ "XVCMPGTDP\000"
  /* 11921 */ "XSSQRTDP\000"
  /* 11930 */ "XSTSQRTDP\000"
  /* 11940 */ "XVTSQRTDP\000"
  /* 11950 */ "XVSQRTDP\000"
  /* 11959 */ "XSCMPUDP\000"
  /* 11968 */ "XSDIVDP\000"
  /* 11976 */ "XSTDIVDP\000"
  /* 11985 */ "XVTDIVDP\000"
  /* 11994 */ "XVDIVDP\000"
  /* 12002 */ "XVCVSXWDP\000"
  /* 12012 */ "XVCVUXWDP\000"
  /* 12022 */ "XSMAXDP\000"
  /* 12030 */ "XVMAXDP\000"
  /* 12038 */ "CTRL_DEP\000"
  /* 12047 */ "DCBFEP\000"
  /* 12054 */ "ICBIEP\000"
  /* 12061 */ "TLBIEP\000"
  /* 12068 */ "DCBZLEP\000"
  /* 12076 */ "DCBTEP\000"
  /* 12083 */ "DCBSTEP\000"
  /* 12091 */ "DCBTSTEP\000"
  /* 12100 */ "DCBZEP\000"
  /* 12107 */ "VCMPBFP\000"
  /* 12115 */ "VNMSUBFP\000"
  /* 12124 */ "VSUBFP\000"
  /* 12131 */ "VMADDFP\000"
  /* 12139 */ "VADDFP\000"
  /* 12146 */ "VLOGEFP\000"
  /* 12154 */ "VCMPGEFP\000"
  /* 12163 */ "VREFP\000"
  /* 12169 */ "VEXPTEFP\000"
  /* 12178 */ "VRSQRTEFP\000"
  /* 12188 */ "VMINFP\000"
  /* 12195 */ "G_SITOFP\000"
  /* 12204 */ "G_UITOFP\000"
  /* 12213 */ "VCMPEQFP\000"
  /* 12222 */ "VCMPGTFP\000"
  /* 12231 */ "VMAXFP\000"
  /* 12238 */ "XSCVDPHP\000"
  /* 12247 */ "XVCVSPHP\000"
  /* 12256 */ "VRFIP\000"
  /* 12262 */ "XSRDPIP\000"
  /* 12270 */ "XVRDPIP\000"
  /* 12278 */ "XVRSPIP\000"
  /* 12286 */ "HASHCHKP\000"
  /* 12295 */ "XXAESGENLKP\000"
  /* 12307 */ "DCBFLP\000"
  /* 12314 */ "G_FCMP\000"
  /* 12321 */ "G_STRICT_FCMP\000"
  /* 12335 */ "G_ICMP\000"
  /* 12342 */ "G_SCMP\000"
  /* 12349 */ "G_UCMP\000"
  /* 12356 */ "PMXVBF16GER2NP\000"
  /* 12371 */ "PMXVF16GER2NP\000"
  /* 12385 */ "PMDMXVBF16GERX2NP\000"
  /* 12403 */ "PMDMXVF16GERX2NP\000"
  /* 12420 */ "PMXVF32GERNP\000"
  /* 12433 */ "PMXVF64GERNP\000"
  /* 12446 */ "PMXVBF16GER2WNP\000"
  /* 12462 */ "PMXVF16GER2WNP\000"
  /* 12477 */ "PMXVF32GERWNP\000"
  /* 12491 */ "PMXVF64GERWNP\000"
  /* 12505 */ "BLA8_NOP\000"
  /* 12514 */ "BL8_NOP\000"
  /* 12522 */ "UNENCODED_NOP\000"
  /* 12536 */ "BL_NOP\000"
  /* 12543 */ "CONVERGENCECTRL_LOOP\000"
  /* 12564 */ "G_CTPOP\000"
  /* 12572 */ "STOP\000"
  /* 12577 */ "PATCHABLE_OP\000"
  /* 12590 */ "FAULTING_OP\000"
  /* 12602 */ "PMXVBF16GER2PP\000"
  /* 12617 */ "PMXVF16GER2PP\000"
  /* 12631 */ "PMXVI16GER2PP\000"
  /* 12645 */ "PMDMXVBF16GERX2PP\000"
  /* 12663 */ "PMDMXVF16GERX2PP\000"
  /* 12680 */ "PMXVI8GER4PP\000"
  /* 12693 */ "PMDMXVI8GERX4PP\000"
  /* 12709 */ "PMXVI4GER8PP\000"
  /* 12722 */ "PMXVF32GERPP\000"
  /* 12735 */ "PMXVF64GERPP\000"
  /* 12748 */ "PMXVI16GER2SPP\000"
  /* 12763 */ "PMXVI8GER4SPP\000"
  /* 12777 */ "PMDMXVI8GERX4SPP\000"
  /* 12794 */ "PMXVI8GER4WSPP\000"
  /* 12809 */ "PMXVBF16GER2WPP\000"
  /* 12825 */ "PMXVF16GER2WPP\000"
  /* 12840 */ "PMXVI16GER2WPP\000"
  /* 12855 */ "PMXVI8GER4WPP\000"
  /* 12869 */ "PMXVI4GER8WPP\000"
  /* 12883 */ "PMXVF32GERWPP\000"
  /* 12897 */ "PMXVF64GERWPP\000"
  /* 12911 */ "PMXVI16GER2SWPP\000"
  /* 12927 */ "XSNMSUBQP\000"
  /* 12937 */ "XSMSUBQP\000"
  /* 12946 */ "XSSUBQP\000"
  /* 12954 */ "XSTSTDCQP\000"
  /* 12964 */ "XSMINCQP\000"
  /* 12973 */ "XSMAXCQP\000"
  /* 12982 */ "XSNMADDQP\000"
  /* 12992 */ "XSMADDQP\000"
  /* 13001 */ "XSADDQP\000"
  /* 13009 */ "XSCVSDQP\000"
  /* 13018 */ "XSCVUDQP\000"
  /* 13027 */ "XSCMPGEQP\000"
  /* 13037 */ "XSNEGQP\000"
  /* 13045 */ "XSXSIGQP\000"
  /* 13054 */ "XSMULQP\000"
  /* 13062 */ "XSCPSGNQP\000"
  /* 13072 */ "XSCMPOQP\000"
  /* 13081 */ "XSCVDPQP\000"
  /* 13090 */ "XSIEXPQP\000"
  /* 13099 */ "XSCMPEXPQP\000"
  /* 13110 */ "XSXEXPQP\000"
  /* 13119 */ "XSCMPEQQP\000"
  /* 13129 */ "XSCVSQQP\000"
  /* 13138 */ "XSCVUQQP\000"
  /* 13147 */ "XSNABSQP\000"
  /* 13156 */ "XSABSQP\000"
  /* 13164 */ "XSCMPGTQP\000"
  /* 13174 */ "XSSQRTQP\000"
  /* 13183 */ "XSCMPUQP\000"
  /* 13192 */ "XSDIVQP\000"
  /* 13200 */ "RESTORE_DMRP\000"
  /* 13213 */ "SPILL_DMRP\000"
  /* 13224 */ "XSNMSUBASP\000"
  /* 13235 */ "XVNMSUBASP\000"
  /* 13246 */ "XSMSUBASP\000"
  /* 13256 */ "XVMSUBASP\000"
  /* 13266 */ "XSNMADDASP\000"
  /* 13277 */ "XVNMADDASP\000"
  /* 13288 */ "XSMADDASP\000"
  /* 13298 */ "XVMADDASP\000"
  /* 13308 */ "XSSUBSP\000"
  /* 13316 */ "XVSUBSP\000"
  /* 13324 */ "XSTSTDCSP\000"
  /* 13334 */ "XVTSTDCSP\000"
  /* 13344 */ "XSADDSP\000"
  /* 13352 */ "XVADDSP\000"
  /* 13360 */ "XSCVSXDSP\000"
  /* 13370 */ "XVCVSXDSP\000"
  /* 13380 */ "XSCVUXDSP\000"
  /* 13390 */ "XVCVUXDSP\000"
  /* 13400 */ "XVCMPGESP\000"
  /* 13410 */ "XSRESP\000"
  /* 13417 */ "XVRESP\000"
  /* 13424 */ "XSRSQRTESP\000"
  /* 13435 */ "XVRSQRTESP\000"
  /* 13446 */ "XVNEGSP\000"
  /* 13454 */ "XVXSIGSP\000"
  /* 13463 */ "XSMULSP\000"
  /* 13471 */ "XVMULSP\000"
  /* 13479 */ "XSNMSUBMSP\000"
  /* 13490 */ "XVNMSUBMSP\000"
  /* 13501 */ "XSMSUBMSP\000"
  /* 13511 */ "XVMSUBMSP\000"
  /* 13521 */ "XSNMADDMSP\000"
  /* 13532 */ "XVNMADDMSP\000"
  /* 13543 */ "XSMADDMSP\000"
  /* 13553 */ "XVMADDMSP\000"
  /* 13563 */ "XVCPSGNSP\000"
  /* 13573 */ "XVMINSP\000"
  /* 13581 */ "XSCVDPSP\000"
  /* 13590 */ "XVCVDPSP\000"
  /* 13599 */ "XVCVHPSP\000"
  /* 13608 */ "XVIEXPSP\000"
  /* 13617 */ "XVXEXPSP\000"
  /* 13626 */ "XVCMPEQSP\000"
  /* 13636 */ "DRSP\000"
  /* 13641 */ "FRSP\000"
  /* 13646 */ "XSRSP\000"
  /* 13652 */ "XVNABSSP\000"
  /* 13661 */ "XVABSSP\000"
  /* 13669 */ "PLXSSP\000"
  /* 13676 */ "PSTXSSP\000"
  /* 13684 */ "XVCMPGTSP\000"
  /* 13694 */ "XSSQRTSP\000"
  /* 13703 */ "XVTSQRTSP\000"
  /* 13713 */ "XVSQRTSP\000"
  /* 13722 */ "XSDIVSP\000"
  /* 13730 */ "XVTDIVSP\000"
  /* 13739 */ "XVDIVSP\000"
  /* 13747 */ "XVCVSXWSP\000"
  /* 13757 */ "XVCVUXWSP\000"
  /* 13767 */ "XVMAXSP\000"
  /* 13775 */ "HASHSTP\000"
  /* 13783 */ "ADJCALLSTACKUP\000"
  /* 13798 */ "PREALLOCATED_SETUP\000"
  /* 13817 */ "PLXVP\000"
  /* 13823 */ "PSTXVP\000"
  /* 13830 */ "ATOMIC_LOAD_SUB_NOWP\000"
  /* 13851 */ "ATOMIC_LOAD_ADD_NOWP\000"
  /* 13872 */ "ATOMIC_LOAD_NAND_NOWP\000"
  /* 13894 */ "ATOMIC_LOAD_AND_NOWP\000"
  /* 13915 */ "ATOMIC_LOAD_UMIN_NOWP\000"
  /* 13937 */ "ATOMIC_LOAD_MIN_NOWP\000"
  /* 13958 */ "ATOMIC_SWAP_NOWP\000"
  /* 13975 */ "ATOMIC_LOAD_XOR_NOWP\000"
  /* 13996 */ "ATOMIC_LOAD_OR_NOWP\000"
  /* 14016 */ "ATOMIC_LOAD_UMAX_NOWP\000"
  /* 14038 */ "ATOMIC_LOAD_MAX_NOWP\000"
  /* 14059 */ "G_FLDEXP\000"
  /* 14068 */ "G_STRICT_FLDEXP\000"
  /* 14084 */ "G_FEXP\000"
  /* 14091 */ "G_FFREXP\000"
  /* 14100 */ "XSRQPXP\000"
  /* 14108 */ "VEXTSD2Q\000"
  /* 14117 */ "VSRAQ\000"
  /* 14123 */ "DQUAQ\000"
  /* 14129 */ "DSUBQ\000"
  /* 14135 */ "VPRTYBQ\000"
  /* 14143 */ "DTSTDCQ\000"
  /* 14151 */ "DENBCDQ\000"
  /* 14159 */ "DADDQ\000"
  /* 14165 */ "DRRNDQ\000"
  /* 14172 */ "DDEDPDQ\000"
  /* 14180 */ "EFDCMPEQ\000"
  /* 14189 */ "EFSCMPEQ\000"
  /* 14198 */ "EVFSCMPEQ\000"
  /* 14208 */ "EVCMPEQ\000"
  /* 14216 */ "EFDTSTEQ\000"
  /* 14225 */ "EFSTSTEQ\000"
  /* 14234 */ "EVFSTSTEQ\000"
  /* 14244 */ "DTSTSFQ\000"
  /* 14252 */ "DTSTDGQ\000"
  /* 14260 */ "DQUAIQ\000"
  /* 14267 */ "DTSTSFIQ\000"
  /* 14276 */ "DSCLIQ\000"
  /* 14283 */ "DSCRIQ\000"
  /* 14290 */ "LXVKQ\000"
  /* 14296 */ "ICBLQ\000"
  /* 14302 */ "VRLQ\000"
  /* 14307 */ "VSLQ\000"
  /* 14312 */ "DMULQ\000"
  /* 14318 */ "VBPERMQ\000"
  /* 14326 */ "DRINTNQ\000"
  /* 14334 */ "DCMPOQ\000"
  /* 14341 */ "DRDPQ\000"
  /* 14347 */ "DCTQPQ\000"
  /* 14354 */ "DCFFIXQQ\000"
  /* 14363 */ "DCTFIXQQ\000"
  /* 14372 */ "XXBRQ\000"
  /* 14378 */ "VSRQ\000"
  /* 14383 */ "VMODSQ\000"
  /* 14390 */ "VDIVESQ\000"
  /* 14398 */ "VCMPSQ\000"
  /* 14405 */ "VCMPGTSQ\000"
  /* 14414 */ "VDIVSQ\000"
  /* 14421 */ "STQ\000"
  /* 14425 */ "VMUL10UQ\000"
  /* 14434 */ "VMUL10CUQ\000"
  /* 14444 */ "VSUBCUQ\000"
  /* 14452 */ "VADDCUQ\000"
  /* 14460 */ "VMUL10ECUQ\000"
  /* 14471 */ "VSUBECUQ\000"
  /* 14480 */ "VADDECUQ\000"
  /* 14489 */ "VMODUQ\000"
  /* 14496 */ "VMUL10EUQ\000"
  /* 14506 */ "VDIVEUQ\000"
  /* 14514 */ "DCMPUQ\000"
  /* 14521 */ "VCMPUQ\000"
  /* 14528 */ "VCMPEQUQ\000"
  /* 14537 */ "VCMPGTUQ\000"
  /* 14546 */ "VDIVUQ\000"
  /* 14553 */ "DDIVQ\000"
  /* 14559 */ "DIEXQ\000"
  /* 14565 */ "DTSTEXQ\000"
  /* 14573 */ "DXEXQ\000"
  /* 14579 */ "DCFFIXQ\000"
  /* 14587 */ "DCTFIXQ\000"
  /* 14595 */ "DRINTXQ\000"
  /* 14603 */ "MBAR\000"
  /* 14608 */ "UpdateGBR\000"
  /* 14618 */ "VSTRIBR\000"
  /* 14626 */ "G_BR\000"
  /* 14631 */ "INLINEASM_BR\000"
  /* 14644 */ "SETNBCR\000"
  /* 14652 */ "SETBCR\000"
  /* 14659 */ "MFDCR\000"
  /* 14665 */ "RLDCR\000"
  /* 14671 */ "MTDCR\000"
  /* 14677 */ "MFCR\000"
  /* 14682 */ "RLDICR\000"
  /* 14689 */ "MFUDSCR\000"
  /* 14697 */ "MTUDSCR\000"
  /* 14705 */ "MFVSCR\000"
  /* 14712 */ "MTVSCR\000"
  /* 14719 */ "RESTORE_CR\000"
  /* 14730 */ "SPILL_CR\000"
  /* 14739 */ "ADDItlsgdLADDR\000"
  /* 14754 */ "ADDItlsldLADDR\000"
  /* 14769 */ "G_BLOCK_ADDR\000"
  /* 14782 */ "GETtlsldADDR\000"
  /* 14795 */ "GETtlsADDR\000"
  /* 14806 */ "PMXVF32GER\000"
  /* 14817 */ "PMXVF64GER\000"
  /* 14828 */ "VNCIPHER\000"
  /* 14837 */ "VCIPHER\000"
  /* 14845 */ "MEMBARRIER\000"
  /* 14856 */ "G_CONSTANT_FOLD_BARRIER\000"
  /* 14880 */ "PATCHABLE_FUNCTION_ENTER\000"
  /* 14905 */ "G_READCYCLECOUNTER\000"
  /* 14924 */ "G_READSTEADYCOUNTER\000"
  /* 14944 */ "G_READ_REGISTER\000"
  /* 14960 */ "G_WRITE_REGISTER\000"
  /* 14977 */ "VSTRIHR\000"
  /* 14985 */ "G_ASHR\000"
  /* 14992 */ "G_FSHR\000"
  /* 14999 */ "G_LSHR\000"
  /* 15006 */ "KILL_PAIR\000"
  /* 15016 */ "BLR\000"
  /* 15020 */ "gBCLR\000"
  /* 15026 */ "BCCLR\000"
  /* 15032 */ "MFLR\000"
  /* 15037 */ "MTLR\000"
  /* 15042 */ "BDZLR\000"
  /* 15048 */ "BDNZLR\000"
  /* 15055 */ "MovePCtoLR\000"
  /* 15066 */ "MoveGOTtoLR\000"
  /* 15078 */ "RESTORE_DMR\000"
  /* 15090 */ "SPILL_DMR\000"
  /* 15100 */ "FMR\000"
  /* 15104 */ "DMMR\000"
  /* 15109 */ "MFPMR\000"
  /* 15115 */ "MTPMR\000"
  /* 15121 */ "VPERMR\000"
  /* 15128 */ "XXPERMR\000"
  /* 15136 */ "CONVERGENCECTRL_ANCHOR\000"
  /* 15159 */ "XXLOR\000"
  /* 15165 */ "XXLNOR\000"
  /* 15172 */ "CRNOR\000"
  /* 15178 */ "EVNOR\000"
  /* 15184 */ "G_FFLOOR\000"
  /* 15193 */ "G_SAVGFLOOR\000"
  /* 15205 */ "G_UAVGFLOOR\000"
  /* 15217 */ "CROR\000"
  /* 15222 */ "G_EXTRACT_SUBVECTOR\000"
  /* 15242 */ "G_INSERT_SUBVECTOR\000"
  /* 15261 */ "G_BUILD_VECTOR\000"
  /* 15276 */ "G_SHUFFLE_VECTOR\000"
  /* 15293 */ "G_STEP_VECTOR\000"
  /* 15307 */ "G_SPLAT_VECTOR\000"
  /* 15322 */ "EVOR\000"
  /* 15327 */ "XXLXOR\000"
  /* 15334 */ "DMXOR\000"
  /* 15340 */ "VPERMXOR\000"
  /* 15349 */ "CRXOR\000"
  /* 15355 */ "EVXOR\000"
  /* 15361 */ "ATOMIC_LOAD_XOR\000"
  /* 15377 */ "G_VECREDUCE_XOR\000"
  /* 15393 */ "G_XOR\000"
  /* 15399 */ "G_ATOMICRMW_XOR\000"
  /* 15415 */ "ATOMIC_LOAD_OR\000"
  /* 15430 */ "G_VECREDUCE_OR\000"
  /* 15445 */ "G_OR\000"
  /* 15450 */ "G_ATOMICRMW_OR\000"
  /* 15465 */ "MFSPR\000"
  /* 15471 */ "MTSPR\000"
  /* 15477 */ "MFSR\000"
  /* 15482 */ "MFMSR\000"
  /* 15488 */ "MTMSR\000"
  /* 15494 */ "MTSR\000"
  /* 15499 */ "LVSR\000"
  /* 15504 */ "TAILBCTR\000"
  /* 15513 */ "gBCCTR\000"
  /* 15520 */ "BCCCTR\000"
  /* 15527 */ "MFCTR\000"
  /* 15533 */ "MTCTR\000"
  /* 15539 */ "G_ROTR\000"
  /* 15546 */ "G_INTTOPTR\000"
  /* 15557 */ "PMXVI16GER2S\000"
  /* 15570 */ "ADDG6S\000"
  /* 15577 */ "EFDABS\000"
  /* 15584 */ "G_FABS\000"
  /* 15591 */ "EFDNABS\000"
  /* 15599 */ "EFSNABS\000"
  /* 15607 */ "EVFSNABS\000"
  /* 15616 */ "EFSABS\000"
  /* 15623 */ "EVFSABS\000"
  /* 15631 */ "EVABS\000"
  /* 15637 */ "G_ABS\000"
  /* 15643 */ "VSUM4SBS\000"
  /* 15652 */ "VSUBSBS\000"
  /* 15660 */ "VADDSBS\000"
  /* 15668 */ "VSUM4UBS\000"
  /* 15677 */ "VSUBUBS\000"
  /* 15685 */ "VADDUBS\000"
  /* 15693 */ "FSUBS\000"
  /* 15699 */ "FMSUBS\000"
  /* 15706 */ "FNMSUBS\000"
  /* 15714 */ "G_ABDS\000"
  /* 15721 */ "FADDS\000"
  /* 15727 */ "FMADDS\000"
  /* 15734 */ "FNMADDS\000"
  /* 15742 */ "FCFIDS\000"
  /* 15749 */ "DCBTDS\000"
  /* 15756 */ "DCBTSTDS\000"
  /* 15765 */ "XSCVDPSXDS\000"
  /* 15776 */ "XVCVDPSXDS\000"
  /* 15787 */ "XVCVSPSXDS\000"
  /* 15798 */ "XSCVDPUXDS\000"
  /* 15809 */ "XVCVDPUXDS\000"
  /* 15820 */ "XVCVSPUXDS\000"
  /* 15831 */ "V_SETALLONES\000"
  /* 15844 */ "FRES\000"
  /* 15849 */ "FRSQRTES\000"
  /* 15858 */ "G_UNMERGE_VALUES\000"
  /* 15875 */ "G_MERGE_VALUES\000"
  /* 15890 */ "EFDCFS\000"
  /* 15897 */ "MFFS\000"
  /* 15902 */ "PLFS\000"
  /* 15907 */ "MCRFS\000"
  /* 15913 */ "PSTFS\000"
  /* 15919 */ "FNEGS\000"
  /* 15925 */ "VSUM4SHS\000"
  /* 15934 */ "VSUBSHS\000"
  /* 15942 */ "VMHADDSHS\000"
  /* 15952 */ "VMHRADDSHS\000"
  /* 15963 */ "VADDSHS\000"
  /* 15971 */ "VMSUMSHS\000"
  /* 15980 */ "VSUBUHS\000"
  /* 15988 */ "VADDUHS\000"
  /* 15996 */ "VMSUMUHS\000"
  /* 16005 */ "SUBIS\000"
  /* 16011 */ "SUBPCIS\000"
  /* 16019 */ "ADDPCIS\000"
  /* 16027 */ "PADDIS\000"
  /* 16034 */ "LIS\000"
  /* 16038 */ "XORIS\000"
  /* 16044 */ "EVSRWIS\000"
  /* 16052 */ "FSELS\000"
  /* 16058 */ "ADD4TLS\000"
  /* 16066 */ "ADD8TLS\000"
  /* 16074 */ "ICBTLS\000"
  /* 16081 */ "G_CTLS\000"
  /* 16088 */ "LHAXTLS\000"
  /* 16096 */ "LWAXTLS\000"
  /* 16104 */ "STBXTLS\000"
  /* 16112 */ "LFDXTLS\000"
  /* 16120 */ "STFDXTLS\000"
  /* 16129 */ "LDXTLS\000"
  /* 16136 */ "STDXTLS\000"
  /* 16144 */ "STHXTLS\000"
  /* 16152 */ "LFSXTLS\000"
  /* 16160 */ "STFSXTLS\000"
  /* 16169 */ "STWXTLS\000"
  /* 16177 */ "LBZXTLS\000"
  /* 16185 */ "LHZXTLS\000"
  /* 16193 */ "LWZXTLS\000"
  /* 16201 */ "BL8_TLS\000"
  /* 16209 */ "BL8_NOTOC_TLS\000"
  /* 16223 */ "BL_TLS\000"
  /* 16230 */ "BL8_NOP_TLS\000"
  /* 16242 */ "FMULS\000"
  /* 16248 */ "FRIMS\000"
  /* 16254 */ "FCPSGNS\000"
  /* 16262 */ "FRINS\000"
  /* 16268 */ "G_FACOS\000"
  /* 16276 */ "G_FCOS\000"
  /* 16283 */ "G_FSINCOS\000"
  /* 16293 */ "EVLWHOS\000"
  /* 16301 */ "FCMPOS\000"
  /* 16308 */ "DCBFPS\000"
  /* 16315 */ "FRIPS\000"
  /* 16321 */ "G_STRICT_FCMPS\000"
  /* 16336 */ "DCBSTPS\000"
  /* 16344 */ "G_CONCAT_VECTORS\000"
  /* 16361 */ "COPY_TO_REGCLASS\000"
  /* 16378 */ "G_IS_FPCLASS\000"
  /* 16391 */ "FABSS\000"
  /* 16397 */ "FNABSS\000"
  /* 16404 */ "VPKSDSS\000"
  /* 16412 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\000"
  /* 16442 */ "G_VECTOR_COMPRESS\000"
  /* 16460 */ "VPKSHSS\000"
  /* 16468 */ "VPKSWSS\000"
  /* 16476 */ "G_INTRINSIC_W_SIDE_EFFECTS\000"
  /* 16503 */ "G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS\000"
  /* 16541 */ "EVCMPGTS\000"
  /* 16550 */ "EVCMPLTS\000"
  /* 16559 */ "FSQRTS\000"
  /* 16566 */ "FCFIDUS\000"
  /* 16574 */ "VPKSDUS\000"
  /* 16582 */ "VPKUDUS\000"
  /* 16590 */ "SUBFUS\000"
  /* 16597 */ "VPKSHUS\000"
  /* 16605 */ "VPKUHUS\000"
  /* 16613 */ "FCMPUS\000"
  /* 16620 */ "VPKSWUS\000"
  /* 16628 */ "VPKUWUS\000"
  /* 16636 */ "FDIVS\000"
  /* 16642 */ "EVSRWS\000"
  /* 16649 */ "MTVSRWS\000"
  /* 16657 */ "VSUM2SWS\000"
  /* 16666 */ "VSUBSWS\000"
  /* 16674 */ "VADDSWS\000"
  /* 16682 */ "VSUMSWS\000"
  /* 16690 */ "VSUBUWS\000"
  /* 16698 */ "VADDUWS\000"
  /* 16706 */ "EVDIVWS\000"
  /* 16714 */ "XSCVDPSXWS\000"
  /* 16725 */ "XVCVDPSXWS\000"
  /* 16736 */ "XVCVSPSXWS\000"
  /* 16747 */ "XSCVDPUXWS\000"
  /* 16758 */ "XVCVDPUXWS\000"
  /* 16769 */ "XVCVSPUXWS\000"
  /* 16780 */ "VCTSXS\000"
  /* 16787 */ "VCTUXS\000"
  /* 16794 */ "FRIZS\000"
  /* 16800 */ "G_TRUNC_SSAT_S\000"
  /* 16815 */ "LDAT\000"
  /* 16820 */ "STDAT\000"
  /* 16826 */ "EVLHHESPLAT\000"
  /* 16838 */ "EVLWHSPLAT\000"
  /* 16849 */ "EVLHHOSSPLAT\000"
  /* 16862 */ "EVLHHOUSPLAT\000"
  /* 16875 */ "EVLWWSPLAT\000"
  /* 16886 */ "G_SSUBSAT\000"
  /* 16896 */ "G_USUBSAT\000"
  /* 16906 */ "G_SADDSAT\000"
  /* 16916 */ "G_UADDSAT\000"
  /* 16926 */ "G_SSHLSAT\000"
  /* 16936 */ "G_USHLSAT\000"
  /* 16946 */ "G_SMULFIXSAT\000"
  /* 16959 */ "G_UMULFIXSAT\000"
  /* 16972 */ "G_SDIVFIXSAT\000"
  /* 16985 */ "G_UDIVFIXSAT\000"
  /* 16998 */ "G_ATOMICRMW_USUB_SAT\000"
  /* 17019 */ "G_FPTOSI_SAT\000"
  /* 17032 */ "G_FPTOUI_SAT\000"
  /* 17045 */ "LWAT\000"
  /* 17050 */ "STWAT\000"
  /* 17056 */ "DCBT\000"
  /* 17061 */ "ICBT\000"
  /* 17066 */ "G_EXTRACT\000"
  /* 17076 */ "G_SELECT\000"
  /* 17085 */ "G_BRINDIRECT\000"
  /* 17098 */ "DCBTCT\000"
  /* 17105 */ "DCBTSTCT\000"
  /* 17114 */ "PATCHABLE_RET\000"
  /* 17128 */ "TCHECK_RET\000"
  /* 17139 */ "TBEGIN_RET\000"
  /* 17150 */ "CR6SET\000"
  /* 17157 */ "DYNAREAOFFSET\000"
  /* 17171 */ "G_MEMSET\000"
  /* 17180 */ "CR6UNSET\000"
  /* 17189 */ "CRUNSET\000"
  /* 17197 */ "CRSET\000"
  /* 17203 */ "EFDCMPGT\000"
  /* 17212 */ "EFSCMPGT\000"
  /* 17221 */ "EVFSCMPGT\000"
  /* 17231 */ "EFDTSTGT\000"
  /* 17240 */ "EFSTSTGT\000"
  /* 17249 */ "EVFSTSTGT\000"
  /* 17259 */ "WAIT\000"
  /* 17264 */ "RESTORE_CRBIT\000"
  /* 17278 */ "SPILL_CRBIT\000"
  /* 17290 */ "ANDI_rec_1_EQ_BIT\000"
  /* 17308 */ "ANDI_rec_1_GT_BIT\000"
  /* 17326 */ "PATCHABLE_FUNCTION_EXIT\000"
  /* 17350 */ "G_BRJT\000"
  /* 17357 */ "G_EXTRACT_VECTOR_ELT\000"
  /* 17378 */ "G_INSERT_VECTOR_ELT\000"
  /* 17398 */ "EFDCMPLT\000"
  /* 17407 */ "EFSCMPLT\000"
  /* 17416 */ "EVFSCMPLT\000"
  /* 17426 */ "EFDTSTLT\000"
  /* 17435 */ "EFSTSTLT\000"
  /* 17444 */ "EVFSTSTLT\000"
  /* 17454 */ "G_FCONSTANT\000"
  /* 17466 */ "G_CONSTANT\000"
  /* 17477 */ "G_INTRINSIC_CONVERGENT\000"
  /* 17500 */ "STATEPOINT\000"
  /* 17511 */ "PATCHPOINT\000"
  /* 17522 */ "G_PTRTOINT\000"
  /* 17533 */ "G_FRINT\000"
  /* 17541 */ "G_INTRINSIC_LLRINT\000"
  /* 17560 */ "G_INTRINSIC_LRINT\000"
  /* 17578 */ "G_FNEARBYINT\000"
  /* 17591 */ "PPC32GOT\000"
  /* 17600 */ "PPC32PICGOT\000"
  /* 17612 */ "CRNOT\000"
  /* 17618 */ "LDtocCPT\000"
  /* 17627 */ "TRECHKPT\000"
  /* 17636 */ "G_VASTART\000"
  /* 17646 */ "LIFETIME_START\000"
  /* 17661 */ "G_INVOKE_REGION_START\000"
  /* 17683 */ "G_INSERT\000"
  /* 17692 */ "TABORT\000"
  /* 17699 */ "CP_ABORT\000"
  /* 17708 */ "G_FSQRT\000"
  /* 17716 */ "G_STRICT_FSQRT\000"
  /* 17731 */ "FTSQRT\000"
  /* 17738 */ "G_BITCAST\000"
  /* 17748 */ "G_ADDRSPACE_CAST\000"
  /* 17765 */ "VNCIPHERLAST\000"
  /* 17778 */ "VCIPHERLAST\000"
  /* 17790 */ "DCBST\000"
  /* 17796 */ "DST\000"
  /* 17800 */ "HASHST\000"
  /* 17807 */ "DBG_VALUE_LIST\000"
  /* 17822 */ "DCBTST\000"
  /* 17829 */ "DSTST\000"
  /* 17835 */ "SPILLTOVSR_ST\000"
  /* 17849 */ "DCBTT\000"
  /* 17855 */ "DSTT\000"
  /* 17860 */ "DCBTSTT\000"
  /* 17868 */ "DSTSTT\000"
  /* 17875 */ "XXSSUMUDMCEXT\000"
  /* 17889 */ "G_FPEXT\000"
  /* 17897 */ "G_SEXT\000"
  /* 17904 */ "G_ASSERT_SEXT\000"
  /* 17918 */ "G_ANYEXT\000"
  /* 17927 */ "G_ZEXT\000"
  /* 17934 */ "G_ASSERT_ZEXT\000"
  /* 17948 */ "LHAU\000"
  /* 17953 */ "STBU\000"
  /* 17958 */ "G_ABDU\000"
  /* 17965 */ "LFDU\000"
  /* 17970 */ "STFDU\000"
  /* 17976 */ "MADDHDU\000"
  /* 17984 */ "MULHDU\000"
  /* 17991 */ "FCFIDU\000"
  /* 17998 */ "FCTIDU\000"
  /* 18005 */ "LDU\000"
  /* 18009 */ "STDU\000"
  /* 18014 */ "DIVDU\000"
  /* 18020 */ "DIVDEU\000"
  /* 18027 */ "DIVWEU\000"
  /* 18034 */ "STHU\000"
  /* 18039 */ "EVSRWIU\000"
  /* 18047 */ "EVLWHOU\000"
  /* 18055 */ "DCMPU\000"
  /* 18061 */ "LFSU\000"
  /* 18066 */ "STFSU\000"
  /* 18072 */ "EVCMPGTU\000"
  /* 18081 */ "EVCMPLTU\000"
  /* 18090 */ "MULHWU\000"
  /* 18097 */ "FCTIWU\000"
  /* 18104 */ "EVSRWU\000"
  /* 18111 */ "STWU\000"
  /* 18116 */ "EVDIVWU\000"
  /* 18124 */ "LBZU\000"
  /* 18129 */ "LHZU\000"
  /* 18134 */ "LWZU\000"
  /* 18139 */ "G_TRUNC_SSAT_U\000"
  /* 18154 */ "G_TRUNC_USAT_U\000"
  /* 18169 */ "SCV\000"
  /* 18173 */ "SLBMFEV\000"
  /* 18181 */ "EFDDIV\000"
  /* 18188 */ "G_FDIV\000"
  /* 18195 */ "G_STRICT_FDIV\000"
  /* 18209 */ "EFSDIV\000"
  /* 18216 */ "EVFSDIV\000"
  /* 18224 */ "G_SDIV\000"
  /* 18231 */ "FTDIV\000"
  /* 18237 */ "G_UDIV\000"
  /* 18244 */ "VSLV\000"
  /* 18249 */ "G_GET_FPENV\000"
  /* 18261 */ "G_RESET_FPENV\000"
  /* 18275 */ "G_SET_FPENV\000"
  /* 18287 */ "XXLEQV\000"
  /* 18294 */ "CREQV\000"
  /* 18300 */ "EVEQV\000"
  /* 18306 */ "VSRV\000"
  /* 18311 */ "PLXV\000"
  /* 18316 */ "PSTXV\000"
  /* 18322 */ "VEXTSB2W\000"
  /* 18331 */ "VEXTSH2W\000"
  /* 18340 */ "PMXVBF16GER2W\000"
  /* 18354 */ "PMXVF16GER2W\000"
  /* 18367 */ "PMXVI16GER2W\000"
  /* 18380 */ "PMXVI8GER4W\000"
  /* 18392 */ "PMXVI4GER8W\000"
  /* 18404 */ "EVMHESMFAAW\000"
  /* 18416 */ "EVMHOSMFAAW\000"
  /* 18428 */ "EVMHESSFAAW\000"
  /* 18440 */ "EVMHOSSFAAW\000"
  /* 18452 */ "EVADDSMIAAW\000"
  /* 18464 */ "EVMHESMIAAW\000"
  /* 18476 */ "EVSUBFSMIAAW\000"
  /* 18489 */ "EVMWLSMIAAW\000"
  /* 18501 */ "EVMHOSMIAAW\000"
  /* 18513 */ "EVADDUMIAAW\000"
  /* 18525 */ "EVMHEUMIAAW\000"
  /* 18537 */ "EVSUBFUMIAAW\000"
  /* 18550 */ "EVMWLUMIAAW\000"
  /* 18562 */ "EVMHOUMIAAW\000"
  /* 18574 */ "EVADDSSIAAW\000"
  /* 18586 */ "EVMHESSIAAW\000"
  /* 18598 */ "EVSUBFSSIAAW\000"
  /* 18611 */ "EVMWLSSIAAW\000"
  /* 18623 */ "EVMHOSSIAAW\000"
  /* 18635 */ "EVADDUSIAAW\000"
  /* 18647 */ "EVMHEUSIAAW\000"
  /* 18659 */ "EVSUBFUSIAAW\000"
  /* 18672 */ "EVMWLUSIAAW\000"
  /* 18684 */ "EVMHOUSIAAW\000"
  /* 18696 */ "VSHASIGMAW\000"
  /* 18707 */ "VSRAW\000"
  /* 18713 */ "VCNTMBW\000"
  /* 18721 */ "VPRTYBW\000"
  /* 18729 */ "XXMFACCW\000"
  /* 18738 */ "XXMTACCW\000"
  /* 18747 */ "EVADDW\000"
  /* 18754 */ "EVLDW\000"
  /* 18760 */ "EVRNDW\000"
  /* 18767 */ "EVSTDW\000"
  /* 18774 */ "VMRGEW\000"
  /* 18781 */ "VCMPNEW\000"
  /* 18789 */ "EVSUBFW\000"
  /* 18797 */ "EVSUBIFW\000"
  /* 18806 */ "VNEGW\000"
  /* 18812 */ "VMRGHW\000"
  /* 18819 */ "XXMRGHW\000"
  /* 18827 */ "MULHW\000"
  /* 18833 */ "EVADDIW\000"
  /* 18841 */ "FCTIW\000"
  /* 18847 */ "XXSPLTIW\000"
  /* 18856 */ "VMRGLW\000"
  /* 18863 */ "XXMRGLW\000"
  /* 18871 */ "MULLW\000"
  /* 18877 */ "CMPLW\000"
  /* 18883 */ "EVRLW\000"
  /* 18889 */ "XVRLW\000"
  /* 18895 */ "EVSLW\000"
  /* 18901 */ "LMW\000"
  /* 18905 */ "STMW\000"
  /* 18910 */ "VPMSUMW\000"
  /* 18918 */ "EVMHESMFANW\000"
  /* 18930 */ "EVMHOSMFANW\000"
  /* 18942 */ "EVMHESSFANW\000"
  /* 18954 */ "EVMHOSSFANW\000"
  /* 18966 */ "EVMHESMIANW\000"
  /* 18978 */ "EVMWLSMIANW\000"
  /* 18990 */ "EVMHOSMIANW\000"
  /* 19002 */ "EVMHEUMIANW\000"
  /* 19014 */ "EVMWLUMIANW\000"
  /* 19026 */ "EVMHOUMIANW\000"
  /* 19038 */ "EVMHESSIANW\000"
  /* 19050 */ "EVMWLSSIANW\000"
  /* 19062 */ "EVMHOSSIANW\000"
  /* 19074 */ "EVMHEUSIANW\000"
  /* 19086 */ "EVMWLUSIANW\000"
  /* 19098 */ "EVMHOUSIANW\000"
  /* 19110 */ "VMRGOW\000"
  /* 19117 */ "G_FPOW\000"
  /* 19124 */ "CMPW\000"
  /* 19129 */ "XXBRW\000"
  /* 19135 */ "PMXVF32GERW\000"
  /* 19147 */ "PMXVF64GERW\000"
  /* 19159 */ "VSRW\000"
  /* 19164 */ "PMXVI16GER2SW\000"
  /* 19178 */ "VMODSW\000"
  /* 19185 */ "VMULESW\000"
  /* 19193 */ "VDIVESW\000"
  /* 19201 */ "VAVGSW\000"
  /* 19208 */ "VUPKHSW\000"
  /* 19216 */ "XVMULHSW\000"
  /* 19225 */ "VSPLTISW\000"
  /* 19234 */ "VUPKLSW\000"
  /* 19242 */ "EVCNTLSW\000"
  /* 19251 */ "VMINSW\000"
  /* 19258 */ "VINSW\000"
  /* 19264 */ "VMULOSW\000"
  /* 19272 */ "VCMPGTSW\000"
  /* 19281 */ "EXTSW\000"
  /* 19287 */ "VDIVSW\000"
  /* 19294 */ "VMAXSW\000"
  /* 19301 */ "VSPLTW\000"
  /* 19308 */ "XXSPLTW\000"
  /* 19316 */ "VPOPCNTW\000"
  /* 19325 */ "VINSERTW\000"
  /* 19334 */ "XXINSERTW\000"
  /* 19344 */ "SPESTW\000"
  /* 19351 */ "PSTW\000"
  /* 19356 */ "VSUBCUW\000"
  /* 19364 */ "VADDCUW\000"
  /* 19372 */ "VMODUW\000"
  /* 19379 */ "VABSDUW\000"
  /* 19387 */ "VMULEUW\000"
  /* 19395 */ "VDIVEUW\000"
  /* 19403 */ "VAVGUW\000"
  /* 19410 */ "XVMULHUW\000"
  /* 19419 */ "VMINUW\000"
  /* 19426 */ "VMULOUW\000"
  /* 19434 */ "VCMPEQUW\000"
  /* 19443 */ "VEXTRACTUW\000"
  /* 19454 */ "XXEXTRACTUW\000"
  /* 19466 */ "VCMPGTUW\000"
  /* 19475 */ "VDIVUW\000"
  /* 19482 */ "VMAXUW\000"
  /* 19489 */ "XXBLENDVW\000"
  /* 19499 */ "DIVW\000"
  /* 19504 */ "VCMPNEZW\000"
  /* 19513 */ "VCLZW\000"
  /* 19519 */ "EVCNTLZW\000"
  /* 19528 */ "VCTZW\000"
  /* 19534 */ "CNTTZW\000"
  /* 19541 */ "LXVPB32X\000"
  /* 19550 */ "STXVPB32X\000"
  /* 19560 */ "LXVD2X\000"
  /* 19567 */ "STXVD2X\000"
  /* 19575 */ "LXVW4X\000"
  /* 19582 */ "STXVW4X\000"
  /* 19590 */ "LXVB16X\000"
  /* 19598 */ "STXVB16X\000"
  /* 19607 */ "LXVH8X\000"
  /* 19614 */ "STXVH8X\000"
  /* 19622 */ "LHAX\000"
  /* 19627 */ "G_VECREDUCE_FMAX\000"
  /* 19644 */ "G_ATOMICRMW_FMAX\000"
  /* 19661 */ "G_VECREDUCE_SMAX\000"
  /* 19678 */ "G_SMAX\000"
  /* 19685 */ "ATOMIC_LOAD_UMAX\000"
  /* 19702 */ "G_VECREDUCE_UMAX\000"
  /* 19719 */ "G_UMAX\000"
  /* 19726 */ "G_ATOMICRMW_UMAX\000"
  /* 19743 */ "ATOMIC_LOAD_MAX\000"
  /* 19759 */ "G_ATOMICRMW_MAX\000"
  /* 19775 */ "TLBIVAX\000"
  /* 19783 */ "LFIWAX\000"
  /* 19790 */ "LIWAX\000"
  /* 19796 */ "LXSIWAX\000"
  /* 19804 */ "LWAX\000"
  /* 19809 */ "LVEBX\000"
  /* 19815 */ "STVEBX\000"
  /* 19822 */ "STXSIBX\000"
  /* 19830 */ "LXVRBX\000"
  /* 19837 */ "STXVRBX\000"
  /* 19845 */ "STBX\000"
  /* 19850 */ "STBCX\000"
  /* 19856 */ "STDCX\000"
  /* 19862 */ "STHCX\000"
  /* 19868 */ "STQCX\000"
  /* 19874 */ "STWCX\000"
  /* 19880 */ "XXSPLTI32DX\000"
  /* 19892 */ "EVLDDX\000"
  /* 19899 */ "EVSTDDX\000"
  /* 19907 */ "LFDX\000"
  /* 19912 */ "STFDX\000"
  /* 19918 */ "SPILLTOVSR_LDX\000"
  /* 19933 */ "LXVRDX\000"
  /* 19940 */ "STXVRDX\000"
  /* 19948 */ "LXSDX\000"
  /* 19954 */ "STXSDX\000"
  /* 19961 */ "STDX\000"
  /* 19966 */ "ADDEX\000"
  /* 19972 */ "G_FRAME_INDEX\000"
  /* 19986 */ "EVLWHEX\000"
  /* 19994 */ "EVSTWHEX\000"
  /* 20003 */ "DIEX\000"
  /* 20008 */ "DTSTEX\000"
  /* 20015 */ "EVSTWWEX\000"
  /* 20024 */ "DXEX\000"
  /* 20029 */ "G_SBFX\000"
  /* 20036 */ "G_UBFX\000"
  /* 20043 */ "EVLDHX\000"
  /* 20050 */ "EVSTDHX\000"
  /* 20058 */ "LVEHX\000"
  /* 20064 */ "STVEHX\000"
  /* 20071 */ "STXSIHX\000"
  /* 20079 */ "LXVRHX\000"
  /* 20086 */ "STXVRHX\000"
  /* 20094 */ "STHX\000"
  /* 20099 */ "GETtlsMOD32AIX\000"
  /* 20114 */ "GETtlsADDR32AIX\000"
  /* 20130 */ "GETtlsTpointer32AIX\000"
  /* 20150 */ "GETtlsMOD64AIX\000"
  /* 20165 */ "GETtlsADDR64AIX\000"
  /* 20181 */ "TLSGDAIX\000"
  /* 20190 */ "TLSLDAIX\000"
  /* 20199 */ "STBCIX\000"
  /* 20206 */ "LDCIX\000"
  /* 20212 */ "STDCIX\000"
  /* 20219 */ "STHCIX\000"
  /* 20226 */ "STWCIX\000"
  /* 20233 */ "LBZCIX\000"
  /* 20240 */ "LHZCIX\000"
  /* 20247 */ "LWZCIX\000"
  /* 20254 */ "DCFFIX\000"
  /* 20261 */ "G_SMULFIX\000"
  /* 20271 */ "G_UMULFIX\000"
  /* 20281 */ "DCTFIX\000"
  /* 20288 */ "G_SDIVFIX\000"
  /* 20298 */ "G_UDIVFIX\000"
  /* 20308 */ "XSRQPIX\000"
  /* 20316 */ "VINSBLX\000"
  /* 20324 */ "VEXTUBLX\000"
  /* 20333 */ "VINSDLX\000"
  /* 20341 */ "VINSHLX\000"
  /* 20349 */ "VEXTUHLX\000"
  /* 20358 */ "TLBILX\000"
  /* 20365 */ "VINSBVLX\000"
  /* 20374 */ "VEXTDUBVLX\000"
  /* 20385 */ "VEXTDDVLX\000"
  /* 20395 */ "VINSHVLX\000"
  /* 20404 */ "VEXTDUHVLX\000"
  /* 20415 */ "VINSWVLX\000"
  /* 20424 */ "VEXTDUWVLX\000"
  /* 20435 */ "VINSWLX\000"
  /* 20443 */ "VEXTUWLX\000"
  /* 20452 */ "XXPERMX\000"
  /* 20460 */ "VSBOX\000"
  /* 20466 */ "EVSTWHOX\000"
  /* 20475 */ "EVSTWWOX\000"
  /* 20484 */ "LBEPX\000"
  /* 20490 */ "STBEPX\000"
  /* 20497 */ "LFDEPX\000"
  /* 20504 */ "STFDEPX\000"
  /* 20512 */ "LHEPX\000"
  /* 20518 */ "STHEPX\000"
  /* 20525 */ "LWEPX\000"
  /* 20531 */ "STWEPX\000"
  /* 20538 */ "VUPKHPX\000"
  /* 20546 */ "VPKPX\000"
  /* 20552 */ "VUPKLPX\000"
  /* 20560 */ "LXSSPX\000"
  /* 20567 */ "STXSSPX\000"
  /* 20575 */ "LXVPX\000"
  /* 20581 */ "STXVPX\000"
  /* 20588 */ "LBARX\000"
  /* 20594 */ "LDARX\000"
  /* 20600 */ "LHARX\000"
  /* 20606 */ "LQARX\000"
  /* 20612 */ "LWARX\000"
  /* 20618 */ "LDBRX\000"
  /* 20624 */ "STDBRX\000"
  /* 20631 */ "LHBRX\000"
  /* 20637 */ "STHBRX\000"
  /* 20644 */ "VINSBRX\000"
  /* 20652 */ "VEXTUBRX\000"
  /* 20661 */ "LWBRX\000"
  /* 20667 */ "STWBRX\000"
  /* 20674 */ "VINSDRX\000"
  /* 20682 */ "VINSHRX\000"
  /* 20690 */ "VEXTUHRX\000"
  /* 20699 */ "VINSBVRX\000"
  /* 20708 */ "VEXTDUBVRX\000"
  /* 20719 */ "VEXTDDVRX\000"
  /* 20729 */ "VINSHVRX\000"
  /* 20738 */ "VEXTDUHVRX\000"
  /* 20749 */ "VINSWVRX\000"
  /* 20758 */ "VEXTDUWVRX\000"
  /* 20769 */ "VINSWRX\000"
  /* 20777 */ "VEXTUWRX\000"
  /* 20786 */ "MCRXRX\000"
  /* 20793 */ "TLBSX\000"
  /* 20799 */ "LXVDSX\000"
  /* 20806 */ "VCFSX\000"
  /* 20812 */ "LFSX\000"
  /* 20817 */ "STFSX\000"
  /* 20823 */ "EVLWHOSX\000"
  /* 20832 */ "LXVWSX\000"
  /* 20839 */ "EVLHHESPLATX\000"
  /* 20852 */ "EVLWHSPLATX\000"
  /* 20864 */ "EVLHHOSSPLATX\000"
  /* 20878 */ "EVLHHOUSPLATX\000"
  /* 20892 */ "EVLWWSPLATX\000"
  /* 20904 */ "DRINTX\000"
  /* 20911 */ "SPILLTOVSR_STX\000"
  /* 20926 */ "LHAUX\000"
  /* 20932 */ "LWAUX\000"
  /* 20938 */ "STBUX\000"
  /* 20944 */ "LFDUX\000"
  /* 20950 */ "STFDUX\000"
  /* 20957 */ "LDUX\000"
  /* 20962 */ "STDUX\000"
  /* 20968 */ "VCFUX\000"
  /* 20974 */ "STHUX\000"
  /* 20980 */ "EVLWHOUX\000"
  /* 20989 */ "LFSUX\000"
  /* 20995 */ "STFSUX\000"
  /* 21002 */ "STWUX\000"
  /* 21008 */ "LBZUX\000"
  /* 21014 */ "LHZUX\000"
  /* 21020 */ "LWZUX\000"
  /* 21026 */ "LVX\000"
  /* 21030 */ "STVX\000"
  /* 21035 */ "LXVX\000"
  /* 21040 */ "STXVX\000"
  /* 21046 */ "EVLDWX\000"
  /* 21053 */ "EVSTDWX\000"
  /* 21061 */ "LVEWX\000"
  /* 21067 */ "STVEWX\000"
  /* 21074 */ "STFIWX\000"
  /* 21081 */ "STXSIWX\000"
  /* 21089 */ "STIWX\000"
  /* 21095 */ "LXVRWX\000"
  /* 21102 */ "STXVRWX\000"
  /* 21110 */ "SPESTWX\000"
  /* 21118 */ "LXSIBZX\000"
  /* 21126 */ "LBZX\000"
  /* 21131 */ "LXSIHZX\000"
  /* 21139 */ "LHZX\000"
  /* 21144 */ "LFIWZX\000"
  /* 21151 */ "LIWZX\000"
  /* 21157 */ "LXSIWZX\000"
  /* 21165 */ "SPELWZX\000"
  /* 21173 */ "G_MEMCPY\000"
  /* 21182 */ "CP_COPY\000"
  /* 21190 */ "CONVERGENCECTRL_ENTRY\000"
  /* 21212 */ "DCBZ\000"
  /* 21217 */ "PLBZ\000"
  /* 21222 */ "DMXXSETACCZ\000"
  /* 21234 */ "BDZ\000"
  /* 21238 */ "EFDCTSIDZ\000"
  /* 21248 */ "FCTIDZ\000"
  /* 21255 */ "EFDCTUIDZ\000"
  /* 21265 */ "XSCVQPSDZ\000"
  /* 21275 */ "XSCVQPUDZ\000"
  /* 21285 */ "PLHZ\000"
  /* 21290 */ "VRFIZ\000"
  /* 21296 */ "XSRDPIZ\000"
  /* 21304 */ "XVRDPIZ\000"
  /* 21312 */ "XVRSPIZ\000"
  /* 21320 */ "EFDCTSIZ\000"
  /* 21329 */ "EFSCTSIZ\000"
  /* 21338 */ "EVFSCTSIZ\000"
  /* 21348 */ "EFDCTUIZ\000"
  /* 21357 */ "EFSCTUIZ\000"
  /* 21366 */ "EVFSCTUIZ\000"
  /* 21376 */ "G_CTLZ\000"
  /* 21383 */ "BDNZ\000"
  /* 21388 */ "XSCVQPSQZ\000"
  /* 21398 */ "XSCVQPUQZ\000"
  /* 21408 */ "DMSETDMRZ\000"
  /* 21418 */ "G_CTTZ\000"
  /* 21425 */ "FCTIDUZ\000"
  /* 21433 */ "FCTIWUZ\000"
  /* 21441 */ "FCTIWZ\000"
  /* 21448 */ "SPELWZ\000"
  /* 21455 */ "PLWZ\000"
  /* 21460 */ "MFVSRWZ\000"
  /* 21468 */ "MTVSRWZ\000"
  /* 21476 */ "MFVRWZ\000"
  /* 21483 */ "MTVRWZ\000"
  /* 21490 */ "XSCVQPSWZ\000"
  /* 21500 */ "XSCVQPUWZ\000"
  /* 21510 */ "ADD8TLS_\000"
  /* 21519 */ "LHAXTLS_\000"
  /* 21528 */ "LWAXTLS_\000"
  /* 21537 */ "STBXTLS_\000"
  /* 21546 */ "LFDXTLS_\000"
  /* 21555 */ "STFDXTLS_\000"
  /* 21565 */ "LDXTLS_\000"
  /* 21573 */ "STDXTLS_\000"
  /* 21582 */ "STHXTLS_\000"
  /* 21591 */ "LFSXTLS_\000"
  /* 21600 */ "STFSXTLS_\000"
  /* 21610 */ "STWXTLS_\000"
  /* 21619 */ "LBZXTLS_\000"
  /* 21628 */ "LHZXTLS_\000"
  /* 21637 */ "LWZXTLS_\000"
  /* 21646 */ "BL8_TLS_\000"
  /* 21655 */ "MTFSFb\000"
  /* 21662 */ "MTFSFIb\000"
  /* 21670 */ "RLDICL_32_rec\000"
  /* 21684 */ "EXTSWSLI_32_64_rec\000"
  /* 21703 */ "EXTSW_32_64_rec\000"
  /* 21719 */ "ADD4_rec\000"
  /* 21728 */ "EXTSB8_rec\000"
  /* 21739 */ "ADDC8_rec\000"
  /* 21749 */ "ANDC8_rec\000"
  /* 21759 */ "SUBFC8_rec\000"
  /* 21770 */ "ORC8_rec\000"
  /* 21779 */ "ADD8_rec\000"
  /* 21788 */ "NAND8_rec\000"
  /* 21798 */ "ADDE8_rec\000"
  /* 21808 */ "SUBFE8_rec\000"
  /* 21819 */ "ADDME8_rec\000"
  /* 21830 */ "SUBFME8_rec\000"
  /* 21842 */ "CP_PASTE8_rec\000"
  /* 21856 */ "ADDZE8_rec\000"
  /* 21867 */ "SUBFZE8_rec\000"
  /* 21879 */ "SUBF8_rec\000"
  /* 21889 */ "NEG8_rec\000"
  /* 21898 */ "EXTSH8_rec\000"
  /* 21909 */ "ANDI8_rec\000"
  /* 21919 */ "RLWIMI8_rec\000"
  /* 21931 */ "SRAWI8_rec\000"
  /* 21942 */ "RLWINM8_rec\000"
  /* 21954 */ "RLWNM8_rec\000"
  /* 21965 */ "NOR8_rec\000"
  /* 21974 */ "XOR8_rec\000"
  /* 21983 */ "ANDIS8_rec\000"
  /* 21994 */ "EQV8_rec\000"
  /* 22003 */ "SRAW8_rec\000"
  /* 22013 */ "SLW8_rec\000"
  /* 22022 */ "SRW8_rec\000"
  /* 22031 */ "CNTLZW8_rec\000"
  /* 22043 */ "CNTTZW8_rec\000"
  /* 22055 */ "DQUA_rec\000"
  /* 22064 */ "VCMPNEB_rec\000"
  /* 22076 */ "VCMPGTSB_rec\000"
  /* 22089 */ "EXTSB_rec\000"
  /* 22099 */ "VCMPEQUB_rec\000"
  /* 22112 */ "BCDSUB_rec\000"
  /* 22123 */ "FSUB_rec\000"
  /* 22132 */ "FMSUB_rec\000"
  /* 22142 */ "FNMSUB_rec\000"
  /* 22153 */ "VCMPGTUB_rec\000"
  /* 22166 */ "VCMPNEZB_rec\000"
  /* 22179 */ "ADDC_rec\000"
  /* 22188 */ "ANDC_rec\000"
  /* 22197 */ "SUBFC_rec\000"
  /* 22207 */ "SUBIC_rec\000"
  /* 22217 */ "ADDIC_rec\000"
  /* 22227 */ "RLDIC_rec\000"
  /* 22237 */ "BCDTRUNC_rec\000"
  /* 22250 */ "BCDUTRUNC_rec\000"
  /* 22264 */ "ORC_rec\000"
  /* 22272 */ "SRAD_rec\000"
  /* 22281 */ "DENBCD_rec\000"
  /* 22292 */ "BCDADD_rec\000"
  /* 22303 */ "FADD_rec\000"
  /* 22312 */ "FMADD_rec\000"
  /* 22322 */ "FNMADD_rec\000"
  /* 22333 */ "FNEGD_rec\000"
  /* 22343 */ "MULHD_rec\000"
  /* 22353 */ "FCFID_rec\000"
  /* 22363 */ "FCTID_rec\000"
  /* 22373 */ "FSELD_rec\000"
  /* 22383 */ "MULLD_rec\000"
  /* 22393 */ "SLD_rec\000"
  /* 22401 */ "FRIMD_rec\000"
  /* 22411 */ "NAND_rec\000"
  /* 22420 */ "FCPSGND_rec\000"
  /* 22432 */ "FRIND_rec\000"
  /* 22442 */ "DRRND_rec\000"
  /* 22452 */ "DDEDPD_rec\000"
  /* 22463 */ "FRIPD_rec\000"
  /* 22473 */ "SRD_rec\000"
  /* 22481 */ "FABSD_rec\000"
  /* 22491 */ "FNABSD_rec\000"
  /* 22502 */ "VCMPGTSD_rec\000"
  /* 22515 */ "VCMPEQUD_rec\000"
  /* 22528 */ "VCMPGTUD_rec\000"
  /* 22541 */ "DIVD_rec\000"
  /* 22550 */ "FRIZD_rec\000"
  /* 22560 */ "CNTLZD_rec\000"
  /* 22571 */ "CNTTZD_rec\000"
  /* 22582 */ "ADDE_rec\000"
  /* 22591 */ "DIVDE_rec\000"
  /* 22601 */ "SLBFEE_rec\000"
  /* 22612 */ "SUBFE_rec\000"
  /* 22622 */ "ADDME_rec\000"
  /* 22632 */ "SUBFME_rec\000"
  /* 22643 */ "FRE_rec\000"
  /* 22651 */ "FRSQRTE_rec\000"
  /* 22663 */ "CP_PASTE_rec\000"
  /* 22676 */ "DIVWE_rec\000"
  /* 22686 */ "ADDZE_rec\000"
  /* 22696 */ "SUBFZE_rec\000"
  /* 22707 */ "SUBF_rec\000"
  /* 22716 */ "MTFSF_rec\000"
  /* 22726 */ "NEG_rec\000"
  /* 22734 */ "VCMPNEH_rec\000"
  /* 22746 */ "VCMPGTSH_rec\000"
  /* 22759 */ "EXTSH_rec\000"
  /* 22769 */ "VCMPEQUH_rec\000"
  /* 22782 */ "VCMPGTUH_rec\000"
  /* 22795 */ "VCMPNEZH_rec\000"
  /* 22808 */ "DQUAI_rec\000"
  /* 22818 */ "SRADI_rec\000"
  /* 22828 */ "CLRLSLDI_rec\000"
  /* 22841 */ "EXTLDI_rec\000"
  /* 22852 */ "ANDI_rec\000"
  /* 22861 */ "CLRRDI_rec\000"
  /* 22872 */ "INSRDI_rec\000"
  /* 22883 */ "ROTRDI_rec\000"
  /* 22894 */ "EXTRDI_rec\000"
  /* 22905 */ "MTFSFI_rec\000"
  /* 22916 */ "DSCLI_rec\000"
  /* 22926 */ "EXTSWSLI_rec\000"
  /* 22939 */ "RLDIMI_rec\000"
  /* 22950 */ "RLWIMI_rec\000"
  /* 22961 */ "DSCRI_rec\000"
  /* 22971 */ "SRAWI_rec\000"
  /* 22981 */ "CLRLSLWI_rec\000"
  /* 22994 */ "INSLWI_rec\000"
  /* 23005 */ "EXTLWI_rec\000"
  /* 23016 */ "CLRRWI_rec\000"
  /* 23027 */ "INSRWI_rec\000"
  /* 23038 */ "ROTRWI_rec\000"
  /* 23049 */ "EXTRWI_rec\000"
  /* 23060 */ "VSTRIBL_rec\000"
  /* 23072 */ "RLDCL_rec\000"
  /* 23082 */ "RLDICL_rec\000"
  /* 23093 */ "VSTRIHL_rec\000"
  /* 23105 */ "DMUL_rec\000"
  /* 23114 */ "FMUL_rec\000"
  /* 23123 */ "RLWINM_rec\000"
  /* 23134 */ "RLWNM_rec\000"
  /* 23144 */ "BCDCFN_rec\000"
  /* 23155 */ "BCDCPSGN_rec\000"
  /* 23168 */ "BCDSETSGN_rec\000"
  /* 23182 */ "BCDCTN_rec\000"
  /* 23193 */ "DRINTN_rec\000"
  /* 23204 */ "ADD4O_rec\000"
  /* 23214 */ "ADDC8O_rec\000"
  /* 23225 */ "SUBFC8O_rec\000"
  /* 23237 */ "ADD8O_rec\000"
  /* 23247 */ "ADDE8O_rec\000"
  /* 23258 */ "SUBFE8O_rec\000"
  /* 23270 */ "ADDME8O_rec\000"
  /* 23282 */ "SUBFME8O_rec\000"
  /* 23295 */ "ADDZE8O_rec\000"
  /* 23307 */ "SUBFZE8O_rec\000"
  /* 23320 */ "SUBF8O_rec\000"
  /* 23331 */ "NEG8O_rec\000"
  /* 23341 */ "ADDCO_rec\000"
  /* 23351 */ "SUBFCO_rec\000"
  /* 23362 */ "MULLDO_rec\000"
  /* 23373 */ "DIVDO_rec\000"
  /* 23383 */ "ADDEO_rec\000"
  /* 23393 */ "DIVDEO_rec\000"
  /* 23404 */ "SUBFEO_rec\000"
  /* 23415 */ "ADDMEO_rec\000"
  /* 23426 */ "SUBFMEO_rec\000"
  /* 23438 */ "DIVWEO_rec\000"
  /* 23449 */ "ADDZEO_rec\000"
  /* 23460 */ "SUBFZEO_rec\000"
  /* 23472 */ "SUBFO_rec\000"
  /* 23482 */ "NEGO_rec\000"
  /* 23491 */ "DIVDUO_rec\000"
  /* 23502 */ "DIVDEUO_rec\000"
  /* 23514 */ "DIVWEUO_rec\000"
  /* 23526 */ "DIVWUO_rec\000"
  /* 23537 */ "MULLWO_rec\000"
  /* 23548 */ "DIVWO_rec\000"
  /* 23558 */ "XVCMPGEDP_rec\000"
  /* 23572 */ "XVCMPEQDP_rec\000"
  /* 23586 */ "DCTDP_rec\000"
  /* 23596 */ "XVCMPGTDP_rec\000"
  /* 23610 */ "VCMPBFP_rec\000"
  /* 23622 */ "VCMPGEFP_rec\000"
  /* 23635 */ "VCMPEQFP_rec\000"
  /* 23648 */ "VCMPGTFP_rec\000"
  /* 23661 */ "XVCMPGESP_rec\000"
  /* 23675 */ "XVCMPEQSP_rec\000"
  /* 23689 */ "DRSP_rec\000"
  /* 23698 */ "FRSP_rec\000"
  /* 23707 */ "XVCMPGTSP_rec\000"
  /* 23721 */ "DQUAQ_rec\000"
  /* 23731 */ "DSUBQ_rec\000"
  /* 23741 */ "DENBCDQ_rec\000"
  /* 23753 */ "DADDQ_rec\000"
  /* 23763 */ "DRRNDQ_rec\000"
  /* 23774 */ "DDEDPDQ_rec\000"
  /* 23786 */ "DQUAIQ_rec\000"
  /* 23797 */ "DSCLIQ_rec\000"
  /* 23808 */ "DSCRIQ_rec\000"
  /* 23819 */ "DMULQ_rec\000"
  /* 23829 */ "DRINTNQ_rec\000"
  /* 23841 */ "DRDPQ_rec\000"
  /* 23851 */ "DCTQPQ_rec\000"
  /* 23862 */ "BCDCFSQ_rec\000"
  /* 23874 */ "BCDCTSQ_rec\000"
  /* 23886 */ "VCMPGTSQ_rec\000"
  /* 23899 */ "VCMPEQUQ_rec\000"
  /* 23912 */ "VCMPGTUQ_rec\000"
  /* 23925 */ "DDIVQ_rec\000"
  /* 23935 */ "DIEXQ_rec\000"
  /* 23945 */ "DXEXQ_rec\000"
  /* 23955 */ "DCFFIXQ_rec\000"
  /* 23967 */ "DCTFIXQ_rec\000"
  /* 23979 */ "DRINTXQ_rec\000"
  /* 23991 */ "VSTRIBR_rec\000"
  /* 24003 */ "RLDCR_rec\000"
  /* 24013 */ "RLDICR_rec\000"
  /* 24024 */ "VSTRIHR_rec\000"
  /* 24036 */ "FMR_rec\000"
  /* 24044 */ "NOR_rec\000"
  /* 24052 */ "XOR_rec\000"
  /* 24060 */ "BCDSR_rec\000"
  /* 24070 */ "FSUBS_rec\000"
  /* 24080 */ "FMSUBS_rec\000"
  /* 24091 */ "FNMSUBS_rec\000"
  /* 24103 */ "BCDS_rec\000"
  /* 24112 */ "FADDS_rec\000"
  /* 24122 */ "FMADDS_rec\000"
  /* 24133 */ "FNMADDS_rec\000"
  /* 24145 */ "FCFIDS_rec\000"
  /* 24156 */ "FRES_rec\000"
  /* 24165 */ "FRSQRTES_rec\000"
  /* 24178 */ "MFFS_rec\000"
  /* 24187 */ "FNEGS_rec\000"
  /* 24197 */ "ANDIS_rec\000"
  /* 24207 */ "FSELS_rec\000"
  /* 24217 */ "FMULS_rec\000"
  /* 24227 */ "FRIMS_rec\000"
  /* 24237 */ "FCPSGNS_rec\000"
  /* 24249 */ "FRINS_rec\000"
  /* 24259 */ "FRIPS_rec\000"
  /* 24269 */ "FABSS_rec\000"
  /* 24279 */ "FNABSS_rec\000"
  /* 24290 */ "FSQRTS_rec\000"
  /* 24301 */ "BCDUS_rec\000"
  /* 24311 */ "FCFIDUS_rec\000"
  /* 24323 */ "SUBFUS_rec\000"
  /* 24334 */ "FDIVS_rec\000"
  /* 24344 */ "FRIZS_rec\000"
  /* 24354 */ "FSQRT_rec\000"
  /* 24364 */ "MULHDU_rec\000"
  /* 24375 */ "FCFIDU_rec\000"
  /* 24386 */ "FCTIDU_rec\000"
  /* 24397 */ "DIVDU_rec\000"
  /* 24407 */ "DIVDEU_rec\000"
  /* 24418 */ "DIVWEU_rec\000"
  /* 24429 */ "MULHWU_rec\000"
  /* 24440 */ "FCTIWU_rec\000"
  /* 24451 */ "DIVWU_rec\000"
  /* 24461 */ "DDIV_rec\000"
  /* 24470 */ "FDIV_rec\000"
  /* 24479 */ "EQV_rec\000"
  /* 24487 */ "SRAW_rec\000"
  /* 24496 */ "VCMPNEW_rec\000"
  /* 24508 */ "MULHW_rec\000"
  /* 24518 */ "FCTIW_rec\000"
  /* 24528 */ "MULLW_rec\000"
  /* 24538 */ "SLW_rec\000"
  /* 24546 */ "SRW_rec\000"
  /* 24554 */ "VCMPGTSW_rec\000"
  /* 24567 */ "EXTSW_rec\000"
  /* 24577 */ "VCMPEQUW_rec\000"
  /* 24590 */ "VCMPGTUW_rec\000"
  /* 24603 */ "DIVW_rec\000"
  /* 24612 */ "VCMPNEZW_rec\000"
  /* 24625 */ "CNTLZW_rec\000"
  /* 24636 */ "CNTTZW_rec\000"
  /* 24647 */ "DIEX_rec\000"
  /* 24656 */ "DXEX_rec\000"
  /* 24665 */ "DCFFIX_rec\000"
  /* 24676 */ "DCTFIX_rec\000"
  /* 24687 */ "DRINTX_rec\000"
  /* 24698 */ "FCTIDZ_rec\000"
  /* 24709 */ "BCDCFZ_rec\000"
  /* 24720 */ "BCDCTZ_rec\000"
  /* 24731 */ "FCTIDUZ_rec\000"
  /* 24743 */ "FCTIWUZ_rec\000"
  /* 24755 */ "FCTIWZ_rec\000"
  /* 24766 */ "RLWIMIbm_rec\000"
  /* 24779 */ "RLWINMbm_rec\000"
  /* 24792 */ "RLWNMbm_rec\000"
  /* 24804 */ "LDtoc\000"
  /* 24810 */ "ADDItoc\000"
  /* 24818 */ "LWZtoc\000"
  /* 24825 */ "BL8_LDinto_toc\000"
  /* 24840 */ "BCTRL8_LDinto_toc\000"
  /* 24858 */ "BL_LWZinto_toc\000"
  /* 24873 */ "BCTRL_LWZinto_toc\000"
  /* 24891 */ "PLHA8pc\000"
  /* 24899 */ "PLA8pc\000"
  /* 24906 */ "PLWA8pc\000"
  /* 24914 */ "PSTB8pc\000"
  /* 24922 */ "PSTH8pc\000"
  /* 24930 */ "PADDI8pc\000"
  /* 24939 */ "PADDIS8pc\000"
  /* 24949 */ "PSTW8pc\000"
  /* 24957 */ "PLBZ8pc\000"
  /* 24965 */ "PLHZ8pc\000"
  /* 24973 */ "PLWZ8pc\000"
  /* 24981 */ "PLHApc\000"
  /* 24988 */ "PLApc\000"
  /* 24994 */ "PLWApc\000"
  /* 25001 */ "PSTBpc\000"
  /* 25008 */ "PLFDpc\000"
  /* 25015 */ "PSTFDpc\000"
  /* 25023 */ "PLDpc\000"
  /* 25029 */ "PLXSDpc\000"
  /* 25037 */ "PSTXSDpc\000"
  /* 25046 */ "PSTDpc\000"
  /* 25053 */ "PSTHpc\000"
  /* 25060 */ "PADDIpc\000"
  /* 25068 */ "PLXSSPpc\000"
  /* 25077 */ "PSTXSSPpc\000"
  /* 25087 */ "PLXVPpc\000"
  /* 25095 */ "PSTXVPpc\000"
  /* 25104 */ "PLFSpc\000"
  /* 25111 */ "PSTFSpc\000"
  /* 25119 */ "PADDISpc\000"
  /* 25128 */ "PLXVpc\000"
  /* 25135 */ "PSTXVpc\000"
  /* 25143 */ "PSTWpc\000"
  /* 25150 */ "PLBZpc\000"
  /* 25157 */ "PLHZpc\000"
  /* 25164 */ "PLWZpc\000"
  /* 25171 */ "PLHA8nopc\000"
  /* 25181 */ "PLWA8nopc\000"
  /* 25191 */ "PSTB8nopc\000"
  /* 25201 */ "PSTH8nopc\000"
  /* 25211 */ "PSTW8nopc\000"
  /* 25221 */ "PLBZ8nopc\000"
  /* 25231 */ "PLHZ8nopc\000"
  /* 25241 */ "PLWZ8nopc\000"
  /* 25251 */ "PLHAnopc\000"
  /* 25260 */ "PLWAnopc\000"
  /* 25269 */ "PSTBnopc\000"
  /* 25278 */ "PLFDnopc\000"
  /* 25287 */ "PSTFDnopc\000"
  /* 25297 */ "PLDnopc\000"
  /* 25305 */ "PLXSDnopc\000"
  /* 25315 */ "PSTXSDnopc\000"
  /* 25326 */ "PSTDnopc\000"
  /* 25335 */ "PSTHnopc\000"
  /* 25344 */ "PLXSSPnopc\000"
  /* 25355 */ "PSTXSSPnopc\000"
  /* 25367 */ "PLXVPnopc\000"
  /* 25377 */ "PSTXVPnopc\000"
  /* 25388 */ "PLFSnopc\000"
  /* 25397 */ "PSTFSnopc\000"
  /* 25407 */ "PLXVnopc\000"
  /* 25416 */ "PSTXVnopc\000"
  /* 25426 */ "PSTWnopc\000"
  /* 25435 */ "PLBZnopc\000"
  /* 25444 */ "PLHZnopc\000"
  /* 25453 */ "PLWZnopc\000"
  /* 25462 */ "PLHA8onlypc\000"
  /* 25474 */ "PLWA8onlypc\000"
  /* 25486 */ "PSTB8onlypc\000"
  /* 25498 */ "PSTH8onlypc\000"
  /* 25510 */ "PSTW8onlypc\000"
  /* 25522 */ "PLBZ8onlypc\000"
  /* 25534 */ "PLHZ8onlypc\000"
  /* 25546 */ "PLWZ8onlypc\000"
  /* 25558 */ "PLHAonlypc\000"
  /* 25569 */ "PLWAonlypc\000"
  /* 25580 */ "PSTBonlypc\000"
  /* 25591 */ "PLFDonlypc\000"
  /* 25602 */ "PSTFDonlypc\000"
  /* 25614 */ "PLDonlypc\000"
  /* 25624 */ "PLXSDonlypc\000"
  /* 25636 */ "PSTXSDonlypc\000"
  /* 25649 */ "PSTDonlypc\000"
  /* 25660 */ "PSTHonlypc\000"
  /* 25671 */ "PLXSSPonlypc\000"
  /* 25684 */ "PSTXSSPonlypc\000"
  /* 25698 */ "PLXVPonlypc\000"
  /* 25710 */ "PSTXVPonlypc\000"
  /* 25723 */ "PLFSonlypc\000"
  /* 25734 */ "PSTFSonlypc\000"
  /* 25746 */ "PLXVonlypc\000"
  /* 25757 */ "PSTXVonlypc\000"
  /* 25769 */ "PSTWonlypc\000"
  /* 25780 */ "PLBZonlypc\000"
  /* 25791 */ "PLHZonlypc\000"
  /* 25802 */ "PLWZonlypc\000"
  /* 25813 */ "XXLORf\000"
  /* 25820 */ "SETRNDi\000"
  /* 25828 */ "TCRETURNai\000"
  /* 25839 */ "TCRETURNdi\000"
  /* 25850 */ "TCRETURNri\000"
  /* 25861 */ "PADDIdtprel\000"
  /* 25873 */ "BDZLAm\000"
  /* 25880 */ "BDNZLAm\000"
  /* 25888 */ "BDZAm\000"
  /* 25894 */ "BDNZAm\000"
  /* 25901 */ "BDZLRLm\000"
  /* 25909 */ "BDNZLRLm\000"
  /* 25918 */ "BDZLm\000"
  /* 25924 */ "BDNZLm\000"
  /* 25931 */ "BDZLRm\000"
  /* 25938 */ "BDNZLRm\000"
  /* 25946 */ "BDZm\000"
  /* 25951 */ "BDNZm\000"
  /* 25957 */ "RLWIMIbm\000"
  /* 25966 */ "RLWINMbm\000"
  /* 25975 */ "RLWNMbm\000"
  /* 25983 */ "BCCTRL8n\000"
  /* 25992 */ "BCCTR8n\000"
  /* 26000 */ "BCn\000"
  /* 26004 */ "BCLn\000"
  /* 26009 */ "BCLRLn\000"
  /* 26016 */ "BCCTRLn\000"
  /* 26024 */ "BCLRn\000"
  /* 26030 */ "BCCTRn\000"
  /* 26037 */ "BDZLAp\000"
  /* 26044 */ "BDNZLAp\000"
  /* 26052 */ "BDZAp\000"
  /* 26058 */ "BDNZAp\000"
  /* 26065 */ "BDZLRLp\000"
  /* 26073 */ "BDNZLRLp\000"
  /* 26082 */ "BDZLp\000"
  /* 26088 */ "BDNZLp\000"
  /* 26095 */ "BDZLRp\000"
  /* 26102 */ "BDNZLRp\000"
  /* 26110 */ "BDZp\000"
  /* 26115 */ "BDNZp\000"
  /* 26121 */ "MTCTR8loop\000"
  /* 26132 */ "DecreaseCTR8loop\000"
  /* 26149 */ "MTCTRloop\000"
  /* 26159 */ "DecreaseCTRloop\000"
  /* 26175 */ "EH_SjLj_Setup\000"
  /* 26189 */ "PPCLdFixedAddr\000"
  /* 26204 */ "VSPLTBs\000"
  /* 26212 */ "VEXTSB2Ds\000"
  /* 26222 */ "VEXTSH2Ds\000"
  /* 26232 */ "VEXTSW2Ds\000"
  /* 26242 */ "VSPLTHs\000"
  /* 26250 */ "XXPERMDIs\000"
  /* 26260 */ "XXSLDWIs\000"
  /* 26269 */ "XSNABSDPs\000"
  /* 26279 */ "XSCVDPSXDSs\000"
  /* 26291 */ "XSCVDPUXDSs\000"
  /* 26303 */ "XSCVDPSXWSs\000"
  /* 26315 */ "XSCVDPUXWSs\000"
  /* 26327 */ "VEXTSB2Ws\000"
  /* 26337 */ "VEXTSH2Ws\000"
  /* 26347 */ "XXSPLTWs\000"
  /* 26356 */ "XXLEQVOnes\000"
  /* 26367 */ "BCLalways\000"
  /* 26377 */ "gBCAat\000"
  /* 26384 */ "gBCLAat\000"
  /* 26392 */ "gBCat\000"
  /* 26398 */ "gBCLat\000"
  /* 26405 */ "MFVRSAVEv\000"
  /* 26415 */ "MTVRSAVEv\000"
  /* 26425 */ "STXSIBXv\000"
  /* 26434 */ "STXSIHXv\000"
  /* 26443 */ "LAx\000"
  /* 26447 */ "DCBFx\000"
  /* 26453 */ "DCBTx\000"
  /* 26459 */ "DCBTSTx\000"
  /* 26467 */ "XXLXORz\000"
  /* 26475 */ "XXLXORdpz\000"
  /* 26485 */ "XXLXORspz\000"
  /* 26495 */ "FADDrtz\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned PPCInstrNameIndices[] = {
    7325U, 9478U, 14631U, 10314U, 7931U, 7912U, 7940U, 8179U, 
    6522U, 6537U, 6238U, 6225U, 6564U, 16361U, 6040U, 17807U, 
    6251U, 7321U, 7921U, 5636U, 21185U, 7850U, 5818U, 17646U, 
    4999U, 5572U, 5624U, 11165U, 8160U, 17511U, 5165U, 13798U, 
    6657U, 17500U, 5901U, 12590U, 12577U, 14880U, 17114U, 17326U, 
    8092U, 8139U, 8112U, 7964U, 6016U, 14845U, 10867U, 5870U, 
    21190U, 15136U, 12543U, 6088U, 17904U, 17934U, 9930U, 4639U, 
    3665U, 8467U, 18224U, 18237U, 8817U, 8824U, 8831U, 8841U, 
    4972U, 15445U, 15393U, 15714U, 17958U, 15205U, 8081U, 15193U, 
    8070U, 6236U, 7323U, 19972U, 6050U, 6065U, 8229U, 17066U, 
    15858U, 17683U, 15875U, 15261U, 4032U, 16344U, 17522U, 15546U, 
    17738U, 6175U, 14856U, 5107U, 4006U, 5089U, 17560U, 17541U, 
    9908U, 14905U, 14924U, 4408U, 4352U, 4382U, 4321U, 4393U, 
    4333U, 4363U, 5995U, 5949U, 5979U, 16412U, 6578U, 6595U, 
    4655U, 3671U, 4978U, 4911U, 15450U, 15399U, 19759U, 10111U, 
    19726U, 10078U, 4534U, 3604U, 19644U, 9996U, 9589U, 9536U, 
    9662U, 9624U, 11231U, 11209U, 5035U, 16998U, 5616U, 6696U, 
    5026U, 17085U, 17661U, 3961U, 16476U, 17477U, 16503U, 17918U, 
    4024U, 16800U, 18139U, 18154U, 17466U, 17454U, 17636U, 6649U, 
    17897U, 6551U, 17927U, 8056U, 14999U, 14985U, 8049U, 14992U, 
    15539U, 8346U, 12335U, 12314U, 12342U, 12349U, 17076U, 10726U, 
    5664U, 10697U, 5601U, 10718U, 5656U, 10689U, 5593U, 10989U, 
    10981U, 6778U, 6770U, 16916U, 16906U, 16896U, 16886U, 16936U, 
    16926U, 20261U, 20271U, 16946U, 16959U, 20288U, 20298U, 16972U, 
    16985U, 4492U, 3583U, 8377U, 3129U, 4303U, 18188U, 8796U, 
    6217U, 19117U, 7778U, 14084U, 638U, 25U, 6642U, 621U, 
    0U, 14059U, 14091U, 6494U, 17889U, 3996U, 7609U, 7686U, 
    12195U, 12204U, 17019U, 17032U, 15584U, 9945U, 16378U, 6191U, 
    9686U, 9696U, 5719U, 5734U, 9525U, 9578U, 9610U, 9648U, 
    18249U, 18275U, 18261U, 5672U, 5700U, 5685U, 6612U, 6627U, 
    4645U, 7864U, 10030U, 19678U, 10071U, 19719U, 15637U, 5080U, 
    5070U, 14626U, 17350U, 5796U, 15242U, 15222U, 17378U, 17357U, 
    15276U, 15307U, 15293U, 16442U, 21418U, 10349U, 21376U, 10330U, 
    16081U, 12564U, 11253U, 6003U, 8419U, 8062U, 16276U, 10149U, 
    16283U, 9901U, 16268U, 10141U, 9893U, 629U, 6913U, 6802U, 
    6794U, 17708U, 15184U, 17533U, 17578U, 17748U, 14769U, 5805U, 
    4089U, 6109U, 5964U, 4520U, 3590U, 8405U, 18195U, 8803U, 
    3135U, 17716U, 14068U, 12321U, 16321U, 14944U, 14960U, 21173U, 
    5854U, 6139U, 17171U, 11101U, 5838U, 11202U, 11178U, 11190U, 
    4499U, 8384U, 4475U, 8360U, 19627U, 9979U, 9557U, 9504U, 
    4623U, 8451U, 4956U, 15430U, 15377U, 19661U, 10013U, 19702U, 
    10054U, 20029U, 20036U, 1565U, 1484U, 1527U, 1505U, 1607U, 
    1463U, 1586U, 1548U, 5188U, 3778U, 5609U, 1833U, 7200U, 
    22828U, 7748U, 22981U, 7231U, 22861U, 7792U, 23016U, 8035U, 
    12307U, 16308U, 26447U, 16336U, 17098U, 15749U, 17105U, 15756U, 
    17860U, 26459U, 17849U, 26453U, 530U, 1143U, 550U, 1163U, 
    7209U, 22841U, 7771U, 23005U, 7252U, 22894U, 7813U, 23049U, 
    7757U, 22994U, 7238U, 22872U, 7799U, 23027U, 15006U, 26443U, 
    10741U, 19790U, 21151U, 10758U, 26189U, 7127U, 25957U, 24766U, 
    25966U, 24779U, 25975U, 24792U, 7245U, 22883U, 7806U, 23038U, 
    7204U, 22832U, 7752U, 22985U, 4829U, 19918U, 17835U, 20911U, 
    7240U, 22874U, 7801U, 23029U, 21089U, 7128U, 3912U, 22207U, 
    16005U, 16011U, 540U, 1153U, 561U, 1174U, 1220U, 10600U, 
    23204U, 16058U, 21719U, 1806U, 10621U, 23237U, 16066U, 21510U, 
    21779U, 3863U, 1749U, 10606U, 23214U, 21739U, 10705U, 23341U, 
    22179U, 5659U, 1841U, 10627U, 23247U, 21798U, 10804U, 23383U, 
    19966U, 2484U, 22582U, 15570U, 2293U, 7183U, 1960U, 3918U, 
    1768U, 22217U, 16028U, 2302U, 2982U, 119U, 2966U, 2940U, 
    2953U, 2929U, 1652U, 8605U, 195U, 8571U, 155U, 14739U, 
    239U, 8582U, 168U, 14754U, 256U, 24810U, 2642U, 8554U, 
    2091U, 5825U, 1854U, 10642U, 23270U, 21819U, 10824U, 23415U, 
    22622U, 16019U, 6169U, 1869U, 10659U, 23295U, 21856U, 10846U, 
    23449U, 22686U, 10583U, 13783U, 4868U, 1820U, 21789U, 3871U, 
    1755U, 21749U, 22188U, 21909U, 21983U, 24197U, 22852U, 17290U, 
    2336U, 17308U, 2355U, 22412U, 1389U, 135U, 859U, 2012U, 
    4607U, 741U, 13851U, 4940U, 782U, 13894U, 19743U, 939U, 
    14038U, 10095U, 823U, 13937U, 4894U, 761U, 13872U, 15415U, 
    899U, 13996U, 3649U, 721U, 13830U, 19685U, 918U, 14016U, 
    10037U, 802U, 13915U, 15361U, 879U, 13975U, 11261U, 843U, 
    13958U, 10578U, 3196U, 2818U, 3749U, 3859U, 2841U, 15520U, 
    2271U, 8314U, 2082U, 7894U, 3106U, 15026U, 8263U, 15514U, 
    2264U, 25992U, 8307U, 2074U, 25983U, 26016U, 26030U, 22292U, 
    23144U, 23862U, 24709U, 23155U, 23182U, 23874U, 24720U, 23168U, 
    24060U, 22112U, 24103U, 22237U, 24301U, 22250U, 7890U, 15021U, 
    8257U, 26009U, 26024U, 26367U, 26004U, 15508U, 2258U, 8300U, 
    2067U, 24840U, 9418U, 9322U, 24873U, 9457U, 9358U, 26000U, 
    21383U, 2630U, 3184U, 25894U, 26058U, 8541U, 3122U, 25880U, 
    26044U, 15048U, 2210U, 8277U, 25909U, 26073U, 25938U, 26102U, 
    25924U, 26088U, 25951U, 26115U, 21234U, 2619U, 3179U, 25888U, 
    26052U, 8536U, 3116U, 25873U, 26037U, 15042U, 2203U, 8270U, 
    25901U, 26065U, 25931U, 26095U, 25918U, 26082U, 25946U, 26110U, 
    7886U, 2050U, 24825U, 9400U, 12514U, 9379U, 16230U, 4115U, 
    9339U, 16209U, 9315U, 16201U, 21646U, 3096U, 1664U, 12505U, 
    9367U, 9307U, 9332U, 15016U, 2186U, 8251U, 24858U, 9439U, 
    12536U, 9390U, 9352U, 16223U, 4850U, 5184U, 6812U, 1941U, 
    3990U, 19131U, 2440U, 5394U, 1825U, 4461U, 1798U, 4693U, 
    3363U, 3351U, 1687U, 5160U, 7225U, 3356U, 4805U, 7193U, 
    18877U, 7734U, 3371U, 1693U, 19124U, 7786U, 5552U, 8773U, 
    22560U, 19521U, 2456U, 22031U, 24625U, 5565U, 8788U, 22571U, 
    19534U, 2464U, 22043U, 24636U, 17699U, 21182U, 2604U, 21842U, 
    22663U, 17150U, 17180U, 4928U, 3876U, 18294U, 4880U, 15172U, 
    17612U, 15217U, 4161U, 17197U, 17189U, 15349U, 12038U, 4470U, 
    14159U, 23753U, 22294U, 10549U, 2816U, 6207U, 12047U, 7103U, 
    17790U, 12083U, 17056U, 12076U, 17822U, 12091U, 21212U, 12100U, 
    8530U, 12068U, 7133U, 20254U, 14579U, 14354U, 23955U, 24665U, 
    11007U, 14334U, 18055U, 14514U, 11895U, 23586U, 20281U, 14587U, 
    14363U, 23967U, 24676U, 14347U, 23851U, 5140U, 14172U, 23774U, 
    22452U, 18183U, 14553U, 23925U, 24461U, 4454U, 14151U, 23741U, 
    22281U, 20003U, 14559U, 23935U, 24647U, 5535U, 5713U, 10810U, 
    23393U, 18020U, 11121U, 23502U, 24407U, 22591U, 10798U, 23373U, 
    18014U, 11114U, 23491U, 24397U, 22541U, 19499U, 6155U, 10839U, 
    23438U, 18027U, 11129U, 23514U, 24418U, 22676U, 11151U, 23548U, 
    18118U, 11137U, 23526U, 24451U, 24603U, 15104U, 21408U, 6821U, 
    6832U, 8355U, 14312U, 23819U, 23105U, 15334U, 685U, 10196U, 
    12387U, 10399U, 12647U, 701U, 10214U, 12405U, 10417U, 12665U, 
    1311U, 12695U, 12779U, 1409U, 89U, 7329U, 1424U, 104U, 
    7347U, 21222U, 4415U, 3154U, 7097U, 14260U, 23786U, 22808U, 
    14123U, 23721U, 22055U, 14341U, 23841U, 10571U, 14326U, 23829U, 
    23193U, 20904U, 14595U, 23979U, 24687U, 5057U, 14165U, 23763U, 
    22442U, 13636U, 23689U, 7371U, 14276U, 23797U, 22916U, 7573U, 
    14283U, 23808U, 22961U, 16408U, 8172U, 17796U, 959U, 17829U, 
    965U, 17868U, 980U, 17855U, 973U, 3578U, 14129U, 23731U, 
    22114U, 3899U, 14143U, 6473U, 14252U, 20008U, 14565U, 6416U, 
    7281U, 14267U, 14244U, 20024U, 14573U, 23945U, 24656U, 4106U, 
    1783U, 17157U, 2321U, 26132U, 26159U, 15577U, 4468U, 15890U, 
    6325U, 7584U, 4755U, 6423U, 7661U, 4770U, 14180U, 17203U, 
    17398U, 6391U, 7618U, 21238U, 21320U, 6448U, 7695U, 21255U, 
    21348U, 18181U, 8353U, 15591U, 6487U, 3576U, 14216U, 17231U, 
    17426U, 15616U, 4592U, 4700U, 6333U, 7592U, 6431U, 7669U, 
    14189U, 17212U, 17407U, 6399U, 7626U, 21329U, 6456U, 7703U, 
    21357U, 18209U, 8436U, 15599U, 6501U, 3634U, 14225U, 17240U, 
    17435U, 572U, 1185U, 590U, 1203U, 26175U, 18290U, 2424U, 
    21994U, 24479U, 15631U, 18833U, 18452U, 18574U, 18513U, 18635U, 
    18747U, 4934U, 3883U, 14208U, 16541U, 18072U, 16550U, 18081U, 
    19242U, 19519U, 16706U, 18116U, 18300U, 3467U, 6938U, 15623U, 
    4599U, 6341U, 7600U, 6439U, 7677U, 14198U, 17221U, 17416U, 
    6407U, 7634U, 21338U, 6464U, 7711U, 21366U, 18216U, 8443U, 
    15607U, 6508U, 3641U, 14234U, 17249U, 17444U, 4671U, 19892U, 
    6707U, 20043U, 18754U, 21046U, 16826U, 20839U, 16849U, 20864U, 
    16862U, 20878U, 5769U, 19986U, 16293U, 20823U, 18047U, 20980U, 
    16838U, 20852U, 16875U, 20892U, 7299U, 10964U, 10954U, 7309U, 
    2704U, 9781U, 2748U, 9825U, 2782U, 9859U, 6265U, 2846U, 
    18404U, 18918U, 7433U, 3008U, 18464U, 18966U, 6356U, 2885U, 
    18428U, 18942U, 18586U, 19038U, 7468U, 3047U, 18525U, 19002U, 
    18647U, 19074U, 2716U, 9793U, 2760U, 9837U, 2794U, 9871U, 
    6283U, 2866U, 18416U, 18930U, 7451U, 3028U, 18501U, 18990U, 
    6374U, 2905U, 18440U, 18954U, 18623U, 19062U, 7495U, 3077U, 
    18562U, 19026U, 18684U, 19098U, 3148U, 6274U, 2856U, 7442U, 
    3018U, 6365U, 2895U, 7477U, 3057U, 18489U, 18978U, 18611U, 
    19050U, 7486U, 3067U, 18550U, 19014U, 18672U, 19086U, 6292U, 
    2876U, 2728U, 9805U, 7460U, 3038U, 2772U, 9849U, 6383U, 
    2915U, 2738U, 9815U, 7504U, 3087U, 2806U, 9883U, 4887U, 
    6516U, 15178U, 15322U, 4167U, 18883U, 7741U, 18760U, 8023U, 
    18895U, 7764U, 7289U, 7643U, 16044U, 18039U, 16642U, 18104U, 
    4685U, 19899U, 6713U, 20050U, 18767U, 21053U, 5776U, 19994U, 
    10894U, 20466U, 6161U, 20015U, 11157U, 20475U, 18476U, 18598U, 
    18537U, 18659U, 18789U, 18797U, 15355U, 3469U, 1700U, 989U, 
    21728U, 22089U, 6940U, 1946U, 1002U, 21898U, 22759U, 19281U, 
    7387U, 1015U, 21684U, 22926U, 513U, 1043U, 21703U, 24567U, 
    10942U, 5283U, 22481U, 16391U, 24269U, 4487U, 15721U, 24112U, 
    22303U, 26495U, 4743U, 15742U, 24145U, 17991U, 16566U, 24311U, 
    24375U, 22353U, 5133U, 16301U, 5486U, 16613U, 5012U, 22420U, 
    16254U, 24237U, 4764U, 17998U, 21425U, 24731U, 24386U, 21248U, 
    24698U, 22363U, 18841U, 18097U, 21433U, 24743U, 24440U, 21441U, 
    24755U, 24518U, 18190U, 16636U, 24334U, 24470U, 5610U, 4565U, 
    15727U, 24122U, 22312U, 15100U, 24036U, 3621U, 15699U, 24080U, 
    22132U, 8372U, 16242U, 24217U, 23114U, 5289U, 22491U, 16397U, 
    24279U, 4718U, 22333U, 15919U, 24187U, 4571U, 15734U, 24133U, 
    22322U, 3627U, 15706U, 24091U, 22142U, 5945U, 15844U, 24156U, 
    22643U, 4843U, 22401U, 16248U, 24227U, 5020U, 22432U, 16262U, 
    24249U, 5154U, 22463U, 16315U, 24259U, 5540U, 22550U, 16794U, 
    24344U, 13641U, 23698U, 6032U, 15849U, 24165U, 22651U, 4792U, 
    22373U, 16052U, 24207U, 17710U, 16559U, 24290U, 24354U, 3585U, 
    15693U, 24070U, 22123U, 18231U, 17731U, 14795U, 288U, 20114U, 
    20165U, 8002U, 20099U, 20150U, 20130U, 14782U, 273U, 7984U, 
    7842U, 2041U, 12286U, 2133U, 17800U, 2374U, 13775U, 2143U, 
    4749U, 7108U, 12054U, 3973U, 14296U, 17061U, 16074U, 7139U, 
    8018U, 2054U, 4077U, 3097U, 1665U, 20588U, 8484U, 20484U, 
    21218U, 2614U, 20233U, 18124U, 2406U, 21008U, 2559U, 21126U, 
    2586U, 16177U, 21619U, 480U, 4782U, 20594U, 8491U, 16815U, 
    5881U, 20618U, 20206U, 18005U, 20957U, 19929U, 16129U, 21565U, 
    8593U, 181U, 24804U, 2828U, 17618U, 7652U, 8547U, 4708U, 
    20497U, 17965U, 20944U, 19907U, 16112U, 21546U, 19783U, 21144U, 
    15903U, 18061U, 20989U, 20812U, 16152U, 21591U, 2925U, 1647U, 
    20600U, 8498U, 17948U, 2382U, 20926U, 2531U, 19622U, 2472U, 
    16088U, 21519U, 425U, 20631U, 2517U, 20512U, 21286U, 2625U, 
    20240U, 18129U, 2412U, 21014U, 2566U, 21139U, 2592U, 16185U, 
    21628U, 491U, 7368U, 1969U, 16034U, 2309U, 18901U, 14299U, 
    20606U, 8505U, 10775U, 7820U, 19809U, 20058U, 21061U, 8341U, 
    15499U, 21026U, 8519U, 3160U, 20612U, 8512U, 17045U, 5891U, 
    20932U, 19804U, 16096U, 21528U, 436U, 522U, 326U, 20661U, 
    2524U, 20525U, 21451U, 2637U, 20247U, 18134U, 2418U, 21020U, 
    2573U, 21168U, 2598U, 16193U, 21637U, 502U, 24818U, 8563U, 
    5372U, 19948U, 21118U, 21131U, 19796U, 21157U, 13670U, 20560U, 
    18312U, 19590U, 19560U, 20799U, 19607U, 14290U, 8473U, 8216U, 
    13818U, 19541U, 8285U, 8184U, 20575U, 19830U, 19933U, 20079U, 
    8322U, 8201U, 21095U, 19575U, 20832U, 21035U, 4730U, 17976U, 
    4785U, 1811U, 14603U, 6300U, 15907U, 20786U, 5585U, 14677U, 
    2169U, 15527U, 2279U, 14659U, 15897U, 10562U, 7528U, 5649U, 
    10554U, 7519U, 8335U, 24178U, 15032U, 2191U, 15482U, 6305U, 
    1890U, 15109U, 15465U, 2240U, 15477U, 10127U, 3487U, 1713U, 
    14689U, 5271U, 6121U, 26405U, 21476U, 14705U, 5257U, 4811U, 
    21460U, 5297U, 19179U, 5441U, 19373U, 11741U, 2116U, 4069U, 
    4083U, 6319U, 1906U, 15533U, 2286U, 26121U, 26149U, 14671U, 
    34U, 82U, 6350U, 7274U, 22905U, 21662U, 22716U, 21655U, 
    8245U, 2060U, 15037U, 2197U, 15488U, 5250U, 6312U, 1898U, 
    15115U, 15471U, 2247U, 15494U, 10134U, 14697U, 5277U, 6130U, 
    26415U, 3172U, 21483U, 14712U, 8636U, 7396U, 5264U, 4677U, 
    8701U, 8861U, 9030U, 3164U, 9724U, 16649U, 21468U, 4737U, 
    17984U, 24364U, 22343U, 18827U, 18090U, 24429U, 24508U, 4799U, 
    10734U, 23362U, 22383U, 7377U, 1966U, 18871U, 11144U, 23537U, 
    24528U, 15066U, 15055U, 2218U, 4875U, 1819U, 21788U, 22411U, 
    11174U, 6490U, 1936U, 10683U, 23331U, 21889U, 10889U, 23482U, 
    22726U, 12510U, 1439U, 1451U, 15168U, 2230U, 21965U, 24044U, 
    15156U, 2231U, 21966U, 4157U, 1793U, 21770U, 22264U, 7580U, 
    1987U, 16039U, 2315U, 24045U, 7182U, 1959U, 24930U, 16027U, 
    2301U, 24939U, 25119U, 25861U, 25060U, 5148U, 5425U, 3112U, 
    1669U, 24899U, 24988U, 21217U, 2613U, 25221U, 25522U, 24957U, 
    25435U, 25780U, 25150U, 4807U, 25297U, 25614U, 25023U, 4707U, 
    25278U, 25591U, 25008U, 15902U, 25388U, 25723U, 25104U, 2924U, 
    1646U, 25171U, 25462U, 24891U, 25251U, 25558U, 24981U, 21285U, 
    2624U, 25231U, 25534U, 24965U, 25444U, 25791U, 25157U, 7383U, 
    1973U, 3159U, 1674U, 25181U, 25474U, 24906U, 25260U, 25569U, 
    24994U, 21455U, 2636U, 25241U, 25546U, 24973U, 25453U, 25802U, 
    25164U, 5371U, 25305U, 25624U, 25029U, 13669U, 25344U, 25671U, 
    25068U, 18311U, 13817U, 25367U, 25698U, 25087U, 25407U, 25746U, 
    25128U, 683U, 10194U, 12385U, 10397U, 12645U, 699U, 10212U, 
    12403U, 10415U, 12663U, 1309U, 12693U, 12777U, 646U, 10165U, 
    12356U, 10368U, 12602U, 18340U, 10255U, 12446U, 10490U, 12809U, 
    659U, 10180U, 12371U, 10383U, 12617U, 18354U, 10271U, 12462U, 
    10506U, 12825U, 14806U, 10229U, 12420U, 10442U, 12722U, 19135U, 
    10286U, 12477U, 10521U, 12883U, 14817U, 10242U, 12433U, 10455U, 
    12735U, 19147U, 10300U, 12491U, 10535U, 12897U, 671U, 12631U, 
    15557U, 12748U, 19164U, 12911U, 18367U, 12840U, 2175U, 12709U, 
    18392U, 12869U, 1298U, 12680U, 12763U, 18380U, 12855U, 12794U, 
    3500U, 1719U, 5402U, 19317U, 17591U, 17600U, 301U, 1055U, 
    354U, 1101U, 309U, 1063U, 333U, 1080U, 3517U, 1728U, 
    25191U, 25486U, 24914U, 25269U, 25580U, 25001U, 5419U, 25326U, 
    25649U, 25046U, 4712U, 25287U, 25602U, 25015U, 15913U, 25397U, 
    25734U, 25111U, 6978U, 1953U, 25201U, 25498U, 24922U, 25335U, 
    25660U, 25053U, 19351U, 2450U, 25211U, 25510U, 24949U, 25426U, 
    25769U, 25143U, 5377U, 25315U, 25636U, 25037U, 13676U, 25355U, 
    25684U, 25077U, 18316U, 13823U, 25377U, 25710U, 25095U, 25416U, 
    25757U, 25135U, 10912U, 10930U, 3837U, 14719U, 17264U, 15078U, 
    13200U, 5203U, 3789U, 3813U, 7155U, 7188U, 3204U, 7270U, 
    4750U, 7160U, 7899U, 23072U, 14665U, 24003U, 3924U, 7905U, 
    405U, 1030U, 21670U, 23082U, 14682U, 415U, 24013U, 22227U, 
    7412U, 22939U, 7419U, 1978U, 21919U, 22950U, 8999U, 2101U, 
    21942U, 23123U, 9014U, 2109U, 21954U, 23134U, 3522U, 4256U, 
    18169U, 1364U, 1252U, 1913U, 1275U, 1999U, 5914U, 1225U, 
    4173U, 4125U, 4229U, 4200U, 1378U, 1265U, 1926U, 1288U, 
    2031U, 5928U, 1240U, 4188U, 4141U, 4244U, 4216U, 3482U, 
    1707U, 3752U, 1742U, 14652U, 2161U, 8985U, 3745U, 1734U, 
    14644U, 2152U, 5063U, 25820U, 22601U, 2996U, 5784U, 6480U, 
    5749U, 18173U, 6025U, 4053U, 4825U, 22393U, 18897U, 2435U, 
    22013U, 24538U, 21448U, 21165U, 19344U, 21110U, 3849U, 14730U, 
    17278U, 15090U, 13213U, 5220U, 3802U, 3826U, 5235U, 4427U, 
    7176U, 396U, 22818U, 22272U, 18708U, 2429U, 22003U, 7720U, 
    1992U, 21931U, 22971U, 24487U, 5253U, 22473U, 19160U, 2445U, 
    22022U, 24546U, 3518U, 1729U, 20199U, 19850U, 20490U, 17953U, 
    2388U, 20938U, 2538U, 19845U, 2478U, 16104U, 21537U, 447U, 
    5420U, 16820U, 20624U, 20212U, 19856U, 18009U, 20962U, 19961U, 
    16136U, 21573U, 4713U, 20504U, 17970U, 20950U, 19912U, 16120U, 
    21555U, 21074U, 15914U, 18066U, 20995U, 20817U, 16160U, 21600U, 
    6979U, 1954U, 20637U, 20219U, 19862U, 20518U, 18034U, 2394U, 
    20974U, 2545U, 20094U, 2491U, 16144U, 21582U, 458U, 18905U, 
    12572U, 14421U, 19868U, 10786U, 7825U, 19815U, 20064U, 21067U, 
    21030U, 8524U, 19347U, 2451U, 17050U, 20667U, 20226U, 19874U, 
    20531U, 18111U, 2400U, 21002U, 2552U, 21113U, 2580U, 16169U, 
    21610U, 469U, 5378U, 19954U, 19822U, 26425U, 20071U, 26434U, 
    21081U, 13677U, 20567U, 18317U, 19598U, 19567U, 19614U, 8478U, 
    8222U, 13824U, 19550U, 8292U, 8192U, 20581U, 19837U, 19940U, 
    20086U, 8328U, 8208U, 21102U, 19582U, 21040U, 6212U, 1884U, 
    10676U, 23320U, 21879U, 3906U, 1761U, 10613U, 23225U, 21759U, 
    10711U, 23351U, 22197U, 5763U, 1847U, 10634U, 23258U, 21808U, 
    10817U, 23404U, 22612U, 3930U, 1775U, 5831U, 1861U, 10650U, 
    23282U, 21830U, 10831U, 23426U, 22632U, 10861U, 23472U, 16590U, 
    24323U, 6184U, 1876U, 10667U, 23307U, 21867U, 10853U, 23460U, 
    22696U, 22707U, 4056U, 9U, 17692U, 3890U, 7145U, 4259U, 
    7166U, 3284U, 1680U, 2821U, 1638U, 15504U, 2254U, 9972U, 
    17139U, 7835U, 17128U, 25828U, 2651U, 25839U, 2663U, 25850U, 
    2675U, 5391U, 7259U, 4994U, 3002U, 5790U, 2687U, 10922U, 
    7957U, 12061U, 2125U, 2696U, 20358U, 19775U, 4779U, 7365U, 
    5939U, 607U, 20793U, 714U, 4295U, 4061U, 10902U, 6149U, 
    614U, 20181U, 2497U, 20190U, 2507U, 11185U, 17627U, 8946U, 
    15495U, 19305U, 7831U, 12522U, 14608U, 3529U, 6983U, 19379U, 
    14452U, 19364U, 14480U, 9259U, 12139U, 15660U, 15963U, 16674U, 
    8663U, 15685U, 8728U, 8909U, 15988U, 9242U, 9753U, 16698U, 
    4935U, 3884U, 3411U, 6865U, 19201U, 3545U, 6999U, 19403U, 
    4849U, 14318U, 20806U, 66U, 4692U, 20968U, 74U, 14837U, 
    17778U, 3290U, 3377U, 3733U, 5546U, 8766U, 7085U, 3226U, 
    19513U, 12107U, 23610U, 12213U, 23635U, 3567U, 22099U, 5493U, 
    22515U, 7030U, 22769U, 14528U, 23899U, 19434U, 24577U, 12154U, 
    23622U, 12222U, 23648U, 3458U, 22076U, 5348U, 22502U, 6929U, 
    22746U, 14405U, 23886U, 19272U, 24554U, 3698U, 22153U, 5502U, 
    22528U, 7050U, 22782U, 14537U, 23912U, 19466U, 24590U, 3244U, 
    22064U, 6720U, 22734U, 18781U, 24496U, 3724U, 22166U, 7076U, 
    22795U, 19504U, 24612U, 14398U, 14521U, 3210U, 4438U, 6688U, 
    18713U, 16780U, 48U, 16787U, 57U, 3739U, 5559U, 8781U, 
    7091U, 3235U, 19528U, 5311U, 14390U, 19193U, 5455U, 14506U, 
    19395U, 5357U, 14414U, 19287U, 5511U, 14546U, 19475U, 18301U, 
    8617U, 8691U, 8851U, 9020U, 9714U, 12169U, 20385U, 20719U, 
    20374U, 20708U, 20404U, 20738U, 20424U, 20758U, 8644U, 5384U, 
    8709U, 8878U, 9038U, 3687U, 7039U, 19443U, 9732U, 4268U, 
    26212U, 18322U, 26327U, 14108U, 4277U, 26222U, 18331U, 26337U, 
    4286U, 26232U, 20324U, 20652U, 20349U, 20690U, 20443U, 20777U, 
    4432U, 3324U, 20316U, 20644U, 20365U, 20699U, 5334U, 20333U, 
    20674U, 3508U, 5410U, 6969U, 19325U, 20341U, 20682U, 20395U, 
    20729U, 19258U, 20435U, 20769U, 20415U, 20749U, 12146U, 12131U, 
    12231U, 3475U, 5364U, 6946U, 19294U, 3707U, 5518U, 7059U, 
    19482U, 15942U, 15952U, 12188U, 3443U, 5327U, 6906U, 19251U, 
    3552U, 5471U, 7015U, 19419U, 8898U, 5296U, 14383U, 19178U, 
    5440U, 14489U, 19372U, 18774U, 3252U, 6728U, 18812U, 3277U, 
    6744U, 18856U, 19110U, 5431U, 8627U, 8869U, 15971U, 8671U, 
    8736U, 8926U, 15996U, 14434U, 14460U, 14496U, 14425U, 3389U, 
    5303U, 6843U, 19185U, 3537U, 5447U, 6991U, 19387U, 5319U, 
    19217U, 5463U, 19411U, 4798U, 3450U, 5340U, 6921U, 19264U, 
    3559U, 5478U, 7022U, 19426U, 9762U, 4888U, 14828U, 17765U, 
    4724U, 18806U, 12115U, 15179U, 15323U, 4168U, 5147U, 9294U, 
    15121U, 15340U, 5424U, 20546U, 16404U, 16574U, 16460U, 16597U, 
    16468U, 16620U, 9488U, 16582U, 9496U, 16605U, 9706U, 16628U, 
    3316U, 4857U, 6786U, 18910U, 3499U, 5401U, 6960U, 19316U, 
    4446U, 14135U, 18721U, 12163U, 8955U, 9966U, 12256U, 21290U, 
    3306U, 4819U, 7405U, 8992U, 6760U, 14302U, 7426U, 9006U, 
    18884U, 7512U, 9013U, 12178U, 20460U, 8024U, 4310U, 18696U, 
    8342U, 3311U, 4824U, 7113U, 7538U, 6765U, 10976U, 14307U, 
    18244U, 18896U, 3492U, 26204U, 6953U, 26242U, 3426U, 6889U, 
    19225U, 19301U, 15500U, 3198U, 4426U, 6682U, 14117U, 18707U, 
    3384U, 5259U, 7120U, 6816U, 11109U, 14378U, 18306U, 19159U, 
    7881U, 23060U, 14618U, 23991U, 8041U, 23093U, 14977U, 24024U, 
    14444U, 19356U, 14471U, 9250U, 12124U, 15652U, 15934U, 16666U, 
    8655U, 15677U, 8720U, 8890U, 15980U, 9222U, 9744U, 16690U, 
    16657U, 15643U, 15925U, 15668U, 16682U, 3259U, 6735U, 9957U, 
    3297U, 6751U, 10156U, 20538U, 3418U, 6872U, 3329U, 19208U, 
    1323U, 209U, 1338U, 224U, 20552U, 3435U, 6898U, 3340U, 
    19234U, 15356U, 41U, 3190U, 6674U, 15831U, 3397U, 6851U, 
    17259U, 17U, 5757U, 7263U, 15330U, 2235U, 21974U, 7579U, 
    1986U, 16038U, 2314U, 24052U, 11879U, 13156U, 9281U, 9230U, 
    11431U, 13001U, 11064U, 13344U, 9268U, 9210U, 11841U, 13119U, 
    11812U, 13099U, 11487U, 13027U, 11901U, 13164U, 11749U, 13072U, 
    11959U, 13183U, 11705U, 13062U, 12238U, 13081U, 13581U, 10480U, 
    15765U, 26279U, 16714U, 26303U, 15798U, 26291U, 16747U, 26315U, 
    11758U, 11767U, 10997U, 21265U, 21388U, 21490U, 21275U, 21398U, 
    21500U, 13009U, 11776U, 10432U, 13129U, 11447U, 13360U, 13018U, 
    13138U, 11467U, 13380U, 11968U, 13192U, 11092U, 13722U, 11794U, 
    13090U, 11357U, 13288U, 11685U, 13543U, 12992U, 11054U, 11422U, 
    12973U, 12022U, 11596U, 9049U, 9107U, 9151U, 9078U, 11413U, 
    12964U, 11725U, 11587U, 11315U, 13246U, 11643U, 13501U, 12937U, 
    11024U, 11605U, 13054U, 11073U, 13463U, 11861U, 26269U, 13147U, 
    11543U, 13037U, 11335U, 13266U, 11663U, 13521U, 12982U, 11043U, 
    11293U, 13224U, 11621U, 13479U, 12927U, 11013U, 7545U, 3937U, 
    8961U, 12262U, 21296U, 9063U, 9121U, 9165U, 9195U, 9092U, 
    9136U, 9180U, 11507U, 13410U, 7559U, 20308U, 14100U, 13646U, 
    11521U, 13424U, 11921U, 13174U, 11082U, 13694U, 11377U, 12946U, 
    11034U, 13308U, 11976U, 11930U, 11393U, 12954U, 13324U, 11823U, 
    13110U, 11559U, 13045U, 11887U, 13661U, 11439U, 13352U, 8908U, 
    9752U, 648U, 10167U, 12358U, 10370U, 12604U, 18342U, 10257U, 
    12448U, 10492U, 12811U, 11851U, 23572U, 13626U, 23675U, 11497U, 
    23558U, 13400U, 23661U, 11911U, 23596U, 13684U, 23707U, 11715U, 
    13563U, 10468U, 13590U, 15776U, 16725U, 15809U, 16758U, 13599U, 
    1353U, 11785U, 12247U, 15787U, 16736U, 15820U, 16769U, 11457U, 
    13370U, 12002U, 13747U, 11477U, 13390U, 12012U, 13757U, 11994U, 
    13739U, 661U, 10182U, 12373U, 10385U, 12619U, 18356U, 10273U, 
    12464U, 10508U, 12827U, 14808U, 10231U, 12422U, 10444U, 12724U, 
    19137U, 10288U, 12479U, 10523U, 12885U, 14819U, 10244U, 12435U, 
    10457U, 12737U, 19149U, 10302U, 12493U, 10537U, 12899U, 673U, 
    12633U, 15559U, 12750U, 19166U, 12913U, 18369U, 12842U, 2177U, 
    12711U, 18394U, 12871U, 1300U, 12682U, 12765U, 18382U, 12857U, 
    12796U, 11803U, 13608U, 11367U, 13298U, 11695U, 13553U, 12030U, 
    13767U, 11733U, 13573U, 11325U, 13256U, 11653U, 13511U, 11613U, 
    6880U, 19216U, 7006U, 19410U, 13471U, 8917U, 9761U, 11870U, 
    13652U, 11551U, 13446U, 11346U, 13277U, 11674U, 13532U, 11304U, 
    13235U, 11632U, 13490U, 7552U, 3945U, 8969U, 12270U, 21304U, 
    11514U, 13417U, 18889U, 7566U, 3953U, 8977U, 12278U, 21312U, 
    11532U, 13435U, 11950U, 13713U, 11385U, 13316U, 8889U, 9743U, 
    11985U, 13730U, 3218U, 11940U, 13703U, 11403U, 13334U, 11832U, 
    13617U, 11568U, 13454U, 11273U, 11283U, 12295U, 3714U, 5525U, 
    7066U, 19489U, 5182U, 6810U, 14372U, 19129U, 7874U, 19454U, 
    8680U, 8755U, 8935U, 9770U, 1627U, 19334U, 4865U, 3868U, 
    18287U, 26356U, 4872U, 15165U, 15159U, 4154U, 25813U, 15327U, 
    26475U, 26485U, 26467U, 3762U, 18729U, 18819U, 18863U, 3770U, 
    18738U, 8427U, 4551U, 4578U, 9300U, 7216U, 26250U, 15128U, 
    20452U, 8029U, 21224U, 7726U, 26260U, 19880U, 3268U, 11577U, 
    18847U, 19308U, 26347U, 8745U, 3979U, 17875U, 3758U, 2836U, 
    26377U, 15513U, 8306U, 7889U, 3100U, 26384U, 15020U, 8256U, 
    26398U, 26392U, 
};

extern const uint8_t PPCInstrDeprecationFeatures[] = {
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), PPC::DeprecatedDST, PPC::DeprecatedDST, PPC::DeprecatedDST, PPC::DeprecatedDST, PPC::DeprecatedDST, 
    PPC::DeprecatedDST, PPC::DeprecatedDST, PPC::DeprecatedDST, PPC::DeprecatedDST, PPC::DeprecatedDST, uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), uint8_t(-1), 
    uint8_t(-1), uint8_t(-1), 
};

extern const int16_t PPCRegClassByHwModeTables[2][3] = {
  { // DefaultMode
    PPC::GPRCRegClassID, // ppc_ptr_rc
    PPC::GPRCRegClassID, // ptr_rc_idx_by_hwmode
    PPC::GPRC_NOR0RegClassID, // ptr_rc_nor0_by_hwmode
  },
  { // PPC64
    PPC::G8RCRegClassID, // ppc_ptr_rc
    PPC::G8RCRegClassID, // ptr_rc_idx_by_hwmode
    PPC::G8RC_NOX0RegClassID, // ptr_rc_nor0_by_hwmode
  },
};

static inline void InitPPCMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(PPCDescs.Insts, PPCInstrNameIndices, PPCInstrNameData, PPCInstrDeprecationFeatures, nullptr, 3002, &PPCRegClassByHwModeTables[0][0], 3);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct PPCGenInstrInfo : public TargetInstrInfo {
  explicit PPCGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~PPCGenInstrInfo() override = default;
};
extern const int16_t PPCRegClassByHwModeTables[2][3];

} // namespace llvm_ks

namespace llvm_ks::PPC {

constexpr unsigned SUBOP_memr_ptrreg = 0;
constexpr unsigned SUBOP_memri_imm = 0;
constexpr unsigned SUBOP_memri_reg = 1;
constexpr unsigned SUBOP_memri34_imm = 0;
constexpr unsigned SUBOP_memri34_reg = 1;
constexpr unsigned SUBOP_memri34_pcrel_imm = 0;
constexpr unsigned SUBOP_memri34_pcrel_reg = 1;
constexpr unsigned SUBOP_memrihash_imm = 0;
constexpr unsigned SUBOP_memrihash_reg = 1;
constexpr unsigned SUBOP_memrix_imm = 0;
constexpr unsigned SUBOP_memrix_reg = 1;
constexpr unsigned SUBOP_memrix16_imm = 0;
constexpr unsigned SUBOP_memrix16_reg = 1;
constexpr unsigned SUBOP_memrr_ptrreg = 0;
constexpr unsigned SUBOP_memrr_offreg = 1;
constexpr unsigned SUBOP_pred_bibo = 0;
constexpr unsigned SUBOP_pred_reg = 1;
constexpr unsigned SUBOP_spe2dis_imm = 0;
constexpr unsigned SUBOP_spe2dis_reg = 1;
constexpr unsigned SUBOP_spe4dis_imm = 0;
constexpr unsigned SUBOP_spe4dis_reg = 1;
constexpr unsigned SUBOP_spe8dis_imm = 0;
constexpr unsigned SUBOP_spe8dis_reg = 1;
constexpr unsigned SUBOP_tlscall_func = 0;
constexpr unsigned SUBOP_tlscall_sym = 1;
constexpr unsigned SUBOP_tlscall32_func = 0;
constexpr unsigned SUBOP_tlscall32_sym = 1;
constexpr unsigned SUBOP_tocentry_imm = 0;
constexpr unsigned SUBOP_tocentry32_imm = 0;

} // namespace llvm_ks::PPC

#endif // GET_INSTRINFO_HEADER

#ifdef GET_INSTRINFO_HELPER_DECLS
#undef GET_INSTRINFO_HELPER_DECLS


#endif // GET_INSTRINFO_HELPER_DECLS

#ifdef GET_INSTRINFO_HELPERS
#undef GET_INSTRINFO_HELPERS


#endif // GET_INSTRINFO_HELPERS

#ifdef GET_INSTRINFO_CTOR_DTOR
#undef GET_INSTRINFO_CTOR_DTOR

namespace llvm_ks {

extern const PPCInstrTable PPCDescs;
extern const unsigned PPCInstrNameIndices[];
extern const char PPCInstrNameData[];
extern const uint8_t PPCInstrDeprecationFeatures[];
PPCGenInstrInfo::PPCGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode, PPCRegClassByHwModeTables[STI.getHwMode(MCSubtargetInfo::HwMode_RegInfo)]) {
  InitMCInstrInfo(PPCDescs.Insts, PPCInstrNameIndices, PPCInstrNameData, PPCInstrDeprecationFeatures, nullptr, 3002, &PPCRegClassByHwModeTables[0][0], 3);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace PPC_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace PPC_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::PPC_MC {


} // namespace llvm_ks::PPC_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::PPC_MC {

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_ModernAsBit = 0,
};

inline FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) {
  FeatureBitset Features;
  if (!FB[PPC::AIXOS] || FB[PPC::FeatureModernAIXAs])
    Features.set(Feature_ModernAsBit);
  return Features;
}

inline FeatureBitset computeRequiredFeatures(unsigned Opcode) {
  enum : uint8_t {
    CEFBS_None,
  };

  static constexpr FeatureBitset FeatureBitsets[] = {
    {}, // CEFBS_None
  };
  static constexpr uint8_t RequiredFeaturesRefs[] = {
    CEFBS_None, // PHI
    CEFBS_None, // INLINEASM
    CEFBS_None, // INLINEASM_BR
    CEFBS_None, // CFI_INSTRUCTION
    CEFBS_None, // EH_LABEL
    CEFBS_None, // GC_LABEL
    CEFBS_None, // ANNOTATION_LABEL
    CEFBS_None, // KILL
    CEFBS_None, // EXTRACT_SUBREG
    CEFBS_None, // INSERT_SUBREG
    CEFBS_None, // IMPLICIT_DEF
    CEFBS_None, // INIT_UNDEF
    CEFBS_None, // SUBREG_TO_REG
    CEFBS_None, // COPY_TO_REGCLASS
    CEFBS_None, // DBG_VALUE
    CEFBS_None, // DBG_VALUE_LIST
    CEFBS_None, // DBG_INSTR_REF
    CEFBS_None, // DBG_PHI
    CEFBS_None, // DBG_LABEL
    CEFBS_None, // REG_SEQUENCE
    CEFBS_None, // COPY
    CEFBS_None, // COPY_LANEMASK
    CEFBS_None, // BUNDLE
    CEFBS_None, // LIFETIME_START
    CEFBS_None, // LIFETIME_END
    CEFBS_None, // PSEUDO_PROBE
    CEFBS_None, // ARITH_FENCE
    CEFBS_None, // STACKMAP
    CEFBS_None, // FENTRY_CALL
    CEFBS_None, // PATCHPOINT
    CEFBS_None, // LOAD_STACK_GUARD
    CEFBS_None, // PREALLOCATED_SETUP
    CEFBS_None, // PREALLOCATED_ARG
    CEFBS_None, // STATEPOINT
    CEFBS_None, // LOCAL_ESCAPE
    CEFBS_None, // FAULTING_OP
    CEFBS_None, // PATCHABLE_OP
    CEFBS_None, // PATCHABLE_FUNCTION_ENTER
    CEFBS_None, // PATCHABLE_RET
    CEFBS_None, // PATCHABLE_FUNCTION_EXIT
    CEFBS_None, // PATCHABLE_TAIL_CALL
    CEFBS_None, // PATCHABLE_EVENT_CALL
    CEFBS_None, // PATCHABLE_TYPED_EVENT_CALL
    CEFBS_None, // ICALL_BRANCH_FUNNEL
    CEFBS_None, // FAKE_USE
    CEFBS_None, // MEMBARRIER
    CEFBS_None, // JUMP_TABLE_DEBUG_INFO
    CEFBS_None, // RELOC_NONE
    CEFBS_None, // CONVERGENCECTRL_ENTRY
    CEFBS_None, // CONVERGENCECTRL_ANCHOR
    CEFBS_None, // CONVERGENCECTRL_LOOP
    CEFBS_None, // CONVERGENCECTRL_GLUE
    CEFBS_None, // G_ASSERT_SEXT
    CEFBS_None, // G_ASSERT_ZEXT
    CEFBS_None, // G_ASSERT_ALIGN
    CEFBS_None, // G_ADD
    CEFBS_None, // G_SUB
    CEFBS_None, // G_MUL
    CEFBS_None, // G_SDIV
    CEFBS_None, // G_UDIV
    CEFBS_None, // G_SREM
    CEFBS_None, // G_UREM
    CEFBS_None, // G_SDIVREM
    CEFBS_None, // G_UDIVREM
    CEFBS_None, // G_AND
    CEFBS_None, // G_OR
    CEFBS_None, // G_XOR
    CEFBS_None, // G_ABDS
    CEFBS_None, // G_ABDU
    CEFBS_None, // G_UAVGFLOOR
    CEFBS_None, // G_UAVGCEIL
    CEFBS_None, // G_SAVGFLOOR
    CEFBS_None, // G_SAVGCEIL
    CEFBS_None, // G_IMPLICIT_DEF
    CEFBS_None, // G_PHI
    CEFBS_None, // G_FRAME_INDEX
    CEFBS_None, // G_GLOBAL_VALUE
    CEFBS_None, // G_PTRAUTH_GLOBAL_VALUE
    CEFBS_None, // G_CONSTANT_POOL
    CEFBS_None, // G_EXTRACT
    CEFBS_None, // G_UNMERGE_VALUES
    CEFBS_None, // G_INSERT
    CEFBS_None, // G_MERGE_VALUES
    CEFBS_None, // G_BUILD_VECTOR
    CEFBS_None, // G_BUILD_VECTOR_TRUNC
    CEFBS_None, // G_CONCAT_VECTORS
    CEFBS_None, // G_PTRTOINT
    CEFBS_None, // G_INTTOPTR
    CEFBS_None, // G_BITCAST
    CEFBS_None, // G_FREEZE
    CEFBS_None, // G_CONSTANT_FOLD_BARRIER
    CEFBS_None, // G_INTRINSIC_FPTRUNC_ROUND
    CEFBS_None, // G_INTRINSIC_TRUNC
    CEFBS_None, // G_INTRINSIC_ROUND
    CEFBS_None, // G_INTRINSIC_LRINT
    CEFBS_None, // G_INTRINSIC_LLRINT
    CEFBS_None, // G_INTRINSIC_ROUNDEVEN
    CEFBS_None, // G_READCYCLECOUNTER
    CEFBS_None, // G_READSTEADYCOUNTER
    CEFBS_None, // G_LOAD
    CEFBS_None, // G_SEXTLOAD
    CEFBS_None, // G_ZEXTLOAD
    CEFBS_None, // G_FPEXTLOAD
    CEFBS_None, // G_INDEXED_LOAD
    CEFBS_None, // G_INDEXED_SEXTLOAD
    CEFBS_None, // G_INDEXED_ZEXTLOAD
    CEFBS_None, // G_STORE
    CEFBS_None, // G_FPTRUNCSTORE
    CEFBS_None, // G_INDEXED_STORE
    CEFBS_None, // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    CEFBS_None, // G_ATOMIC_CMPXCHG
    CEFBS_None, // G_ATOMICRMW_XCHG
    CEFBS_None, // G_ATOMICRMW_ADD
    CEFBS_None, // G_ATOMICRMW_SUB
    CEFBS_None, // G_ATOMICRMW_AND
    CEFBS_None, // G_ATOMICRMW_NAND
    CEFBS_None, // G_ATOMICRMW_OR
    CEFBS_None, // G_ATOMICRMW_XOR
    CEFBS_None, // G_ATOMICRMW_MAX
    CEFBS_None, // G_ATOMICRMW_MIN
    CEFBS_None, // G_ATOMICRMW_UMAX
    CEFBS_None, // G_ATOMICRMW_UMIN
    CEFBS_None, // G_ATOMICRMW_FADD
    CEFBS_None, // G_ATOMICRMW_FSUB
    CEFBS_None, // G_ATOMICRMW_FMAX
    CEFBS_None, // G_ATOMICRMW_FMIN
    CEFBS_None, // G_ATOMICRMW_FMAXIMUM
    CEFBS_None, // G_ATOMICRMW_FMINIMUM
    CEFBS_None, // G_ATOMICRMW_FMAXIMUMNUM
    CEFBS_None, // G_ATOMICRMW_FMINIMUMNUM
    CEFBS_None, // G_ATOMICRMW_UINC_WRAP
    CEFBS_None, // G_ATOMICRMW_UDEC_WRAP
    CEFBS_None, // G_ATOMICRMW_USUB_COND
    CEFBS_None, // G_ATOMICRMW_USUB_SAT
    CEFBS_None, // G_FENCE
    CEFBS_None, // G_PREFETCH
    CEFBS_None, // G_BRCOND
    CEFBS_None, // G_BRINDIRECT
    CEFBS_None, // G_INVOKE_REGION_START
    CEFBS_None, // G_INTRINSIC
    CEFBS_None, // G_INTRINSIC_W_SIDE_EFFECTS
    CEFBS_None, // G_INTRINSIC_CONVERGENT
    CEFBS_None, // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    CEFBS_None, // G_ANYEXT
    CEFBS_None, // G_TRUNC
    CEFBS_None, // G_TRUNC_SSAT_S
    CEFBS_None, // G_TRUNC_SSAT_U
    CEFBS_None, // G_TRUNC_USAT_U
    CEFBS_None, // G_CONSTANT
    CEFBS_None, // G_FCONSTANT
    CEFBS_None, // G_VASTART
    CEFBS_None, // G_VAARG
    CEFBS_None, // G_SEXT
    CEFBS_None, // G_SEXT_INREG
    CEFBS_None, // G_ZEXT
    CEFBS_None, // G_SHL
    CEFBS_None, // G_LSHR
    CEFBS_None, // G_ASHR
    CEFBS_None, // G_FSHL
    CEFBS_None, // G_FSHR
    CEFBS_None, // G_ROTR
    CEFBS_None, // G_ROTL
    CEFBS_None, // G_ICMP
    CEFBS_None, // G_FCMP
    CEFBS_None, // G_SCMP
    CEFBS_None, // G_UCMP
    CEFBS_None, // G_SELECT
    CEFBS_None, // G_UADDO
    CEFBS_None, // G_UADDE
    CEFBS_None, // G_USUBO
    CEFBS_None, // G_USUBE
    CEFBS_None, // G_SADDO
    CEFBS_None, // G_SADDE
    CEFBS_None, // G_SSUBO
    CEFBS_None, // G_SSUBE
    CEFBS_None, // G_UMULO
    CEFBS_None, // G_SMULO
    CEFBS_None, // G_UMULH
    CEFBS_None, // G_SMULH
    CEFBS_None, // G_UADDSAT
    CEFBS_None, // G_SADDSAT
    CEFBS_None, // G_USUBSAT
    CEFBS_None, // G_SSUBSAT
    CEFBS_None, // G_USHLSAT
    CEFBS_None, // G_SSHLSAT
    CEFBS_None, // G_SMULFIX
    CEFBS_None, // G_UMULFIX
    CEFBS_None, // G_SMULFIXSAT
    CEFBS_None, // G_UMULFIXSAT
    CEFBS_None, // G_SDIVFIX
    CEFBS_None, // G_UDIVFIX
    CEFBS_None, // G_SDIVFIXSAT
    CEFBS_None, // G_UDIVFIXSAT
    CEFBS_None, // G_FADD
    CEFBS_None, // G_FSUB
    CEFBS_None, // G_FMUL
    CEFBS_None, // G_FMA
    CEFBS_None, // G_FMAD
    CEFBS_None, // G_FDIV
    CEFBS_None, // G_FREM
    CEFBS_None, // G_FMODF
    CEFBS_None, // G_FPOW
    CEFBS_None, // G_FPOWI
    CEFBS_None, // G_FEXP
    CEFBS_None, // G_FEXP2
    CEFBS_None, // G_FEXP10
    CEFBS_None, // G_FLOG
    CEFBS_None, // G_FLOG2
    CEFBS_None, // G_FLOG10
    CEFBS_None, // G_FLDEXP
    CEFBS_None, // G_FFREXP
    CEFBS_None, // G_FNEG
    CEFBS_None, // G_FPEXT
    CEFBS_None, // G_FPTRUNC
    CEFBS_None, // G_FPTOSI
    CEFBS_None, // G_FPTOUI
    CEFBS_None, // G_SITOFP
    CEFBS_None, // G_UITOFP
    CEFBS_None, // G_FPTOSI_SAT
    CEFBS_None, // G_FPTOUI_SAT
    CEFBS_None, // G_FABS
    CEFBS_None, // G_FCOPYSIGN
    CEFBS_None, // G_IS_FPCLASS
    CEFBS_None, // G_FCANONICALIZE
    CEFBS_None, // G_FMINNUM
    CEFBS_None, // G_FMAXNUM
    CEFBS_None, // G_FMINNUM_IEEE
    CEFBS_None, // G_FMAXNUM_IEEE
    CEFBS_None, // G_FMINIMUM
    CEFBS_None, // G_FMAXIMUM
    CEFBS_None, // G_FMINIMUMNUM
    CEFBS_None, // G_FMAXIMUMNUM
    CEFBS_None, // G_GET_FPENV
    CEFBS_None, // G_SET_FPENV
    CEFBS_None, // G_RESET_FPENV
    CEFBS_None, // G_GET_FPMODE
    CEFBS_None, // G_SET_FPMODE
    CEFBS_None, // G_RESET_FPMODE
    CEFBS_None, // G_GET_ROUNDING
    CEFBS_None, // G_SET_ROUNDING
    CEFBS_None, // G_PTR_ADD
    CEFBS_None, // G_PTRMASK
    CEFBS_None, // G_SMIN
    CEFBS_None, // G_SMAX
    CEFBS_None, // G_UMIN
    CEFBS_None, // G_UMAX
    CEFBS_None, // G_ABS
    CEFBS_None, // G_LROUND
    CEFBS_None, // G_LLROUND
    CEFBS_None, // G_BR
    CEFBS_None, // G_BRJT
    CEFBS_None, // G_VSCALE
    CEFBS_None, // G_INSERT_SUBVECTOR
    CEFBS_None, // G_EXTRACT_SUBVECTOR
    CEFBS_None, // G_INSERT_VECTOR_ELT
    CEFBS_None, // G_EXTRACT_VECTOR_ELT
    CEFBS_None, // G_SHUFFLE_VECTOR
    CEFBS_None, // G_SPLAT_VECTOR
    CEFBS_None, // G_STEP_VECTOR
    CEFBS_None, // G_VECTOR_COMPRESS
    CEFBS_None, // G_CTTZ
    CEFBS_None, // G_CTTZ_ZERO_POISON
    CEFBS_None, // G_CTLZ
    CEFBS_None, // G_CTLZ_ZERO_POISON
    CEFBS_None, // G_CTLS
    CEFBS_None, // G_CTPOP
    CEFBS_None, // G_BSWAP
    CEFBS_None, // G_BITREVERSE
    CEFBS_None, // G_CLMUL
    CEFBS_None, // G_FCEIL
    CEFBS_None, // G_FCOS
    CEFBS_None, // G_FSIN
    CEFBS_None, // G_FSINCOS
    CEFBS_None, // G_FTAN
    CEFBS_None, // G_FACOS
    CEFBS_None, // G_FASIN
    CEFBS_None, // G_FATAN
    CEFBS_None, // G_FATAN2
    CEFBS_None, // G_FCOSH
    CEFBS_None, // G_FSINH
    CEFBS_None, // G_FTANH
    CEFBS_None, // G_FSQRT
    CEFBS_None, // G_FFLOOR
    CEFBS_None, // G_FRINT
    CEFBS_None, // G_FNEARBYINT
    CEFBS_None, // G_ADDRSPACE_CAST
    CEFBS_None, // G_BLOCK_ADDR
    CEFBS_None, // G_JUMP_TABLE
    CEFBS_None, // G_DYN_STACKALLOC
    CEFBS_None, // G_STACKSAVE
    CEFBS_None, // G_STACKRESTORE
    CEFBS_None, // G_STRICT_FADD
    CEFBS_None, // G_STRICT_FSUB
    CEFBS_None, // G_STRICT_FMUL
    CEFBS_None, // G_STRICT_FDIV
    CEFBS_None, // G_STRICT_FREM
    CEFBS_None, // G_STRICT_FMA
    CEFBS_None, // G_STRICT_FSQRT
    CEFBS_None, // G_STRICT_FLDEXP
    CEFBS_None, // G_STRICT_FCMP
    CEFBS_None, // G_STRICT_FCMPS
    CEFBS_None, // G_READ_REGISTER
    CEFBS_None, // G_WRITE_REGISTER
    CEFBS_None, // G_MEMCPY
    CEFBS_None, // G_MEMCPY_INLINE
    CEFBS_None, // G_MEMMOVE
    CEFBS_None, // G_MEMSET
    CEFBS_None, // G_BZERO
    CEFBS_None, // G_MEMSET_INLINE
    CEFBS_None, // G_TRAP
    CEFBS_None, // G_DEBUGTRAP
    CEFBS_None, // G_UBSANTRAP
    CEFBS_None, // G_VECREDUCE_SEQ_FADD
    CEFBS_None, // G_VECREDUCE_SEQ_FMUL
    CEFBS_None, // G_VECREDUCE_FADD
    CEFBS_None, // G_VECREDUCE_FMUL
    CEFBS_None, // G_VECREDUCE_FMAX
    CEFBS_None, // G_VECREDUCE_FMIN
    CEFBS_None, // G_VECREDUCE_FMAXIMUM
    CEFBS_None, // G_VECREDUCE_FMINIMUM
    CEFBS_None, // G_VECREDUCE_ADD
    CEFBS_None, // G_VECREDUCE_MUL
    CEFBS_None, // G_VECREDUCE_AND
    CEFBS_None, // G_VECREDUCE_OR
    CEFBS_None, // G_VECREDUCE_XOR
    CEFBS_None, // G_VECREDUCE_SMAX
    CEFBS_None, // G_VECREDUCE_SMIN
    CEFBS_None, // G_VECREDUCE_UMAX
    CEFBS_None, // G_VECREDUCE_UMIN
    CEFBS_None, // G_SBFX
    CEFBS_None, // G_UBFX
    CEFBS_None, // ATOMIC_CMP_SWAP_I128
    CEFBS_None, // ATOMIC_LOAD_ADD_I128
    CEFBS_None, // ATOMIC_LOAD_AND_I128
    CEFBS_None, // ATOMIC_LOAD_NAND_I128
    CEFBS_None, // ATOMIC_LOAD_OR_I128
    CEFBS_None, // ATOMIC_LOAD_SUB_I128
    CEFBS_None, // ATOMIC_LOAD_XOR_I128
    CEFBS_None, // ATOMIC_SWAP_I128
    CEFBS_None, // BUILD_QUADWORD
    CEFBS_None, // BUILD_UACC
    CEFBS_None, // CFENCE
    CEFBS_None, // CFENCE8
    CEFBS_None, // CLRLSLDI
    CEFBS_None, // CLRLSLDI_rec
    CEFBS_None, // CLRLSLWI
    CEFBS_None, // CLRLSLWI_rec
    CEFBS_None, // CLRRDI
    CEFBS_None, // CLRRDI_rec
    CEFBS_None, // CLRRWI
    CEFBS_None, // CLRRWI_rec
    CEFBS_None, // DCBFL
    CEFBS_None, // DCBFLP
    CEFBS_None, // DCBFPS
    CEFBS_None, // DCBFx
    CEFBS_None, // DCBSTPS
    CEFBS_None, // DCBTCT
    CEFBS_None, // DCBTDS
    CEFBS_None, // DCBTSTCT
    CEFBS_None, // DCBTSTDS
    CEFBS_None, // DCBTSTT
    CEFBS_None, // DCBTSTx
    CEFBS_None, // DCBTT
    CEFBS_None, // DCBTx
    CEFBS_None, // DFLOADf32
    CEFBS_None, // DFLOADf64
    CEFBS_None, // DFSTOREf32
    CEFBS_None, // DFSTOREf64
    CEFBS_None, // EXTLDI
    CEFBS_None, // EXTLDI_rec
    CEFBS_None, // EXTLWI
    CEFBS_None, // EXTLWI_rec
    CEFBS_None, // EXTRDI
    CEFBS_None, // EXTRDI_rec
    CEFBS_None, // EXTRWI
    CEFBS_None, // EXTRWI_rec
    CEFBS_None, // INSLWI
    CEFBS_None, // INSLWI_rec
    CEFBS_None, // INSRDI
    CEFBS_None, // INSRDI_rec
    CEFBS_None, // INSRWI
    CEFBS_None, // INSRWI_rec
    CEFBS_None, // KILL_PAIR
    CEFBS_None, // LAx
    CEFBS_None, // LDAT_CSNE_PSEUDO
    CEFBS_None, // LIWAX
    CEFBS_None, // LIWZX
    CEFBS_None, // LWAT_CSNE_PSEUDO
    CEFBS_None, // PPCLdFixedAddr
    CEFBS_None, // PSUBI
    CEFBS_None, // RLWIMIbm
    CEFBS_None, // RLWIMIbm_rec
    CEFBS_None, // RLWINMbm
    CEFBS_None, // RLWINMbm_rec
    CEFBS_None, // RLWNMbm
    CEFBS_None, // RLWNMbm_rec
    CEFBS_None, // ROTRDI
    CEFBS_None, // ROTRDI_rec
    CEFBS_None, // ROTRWI
    CEFBS_None, // ROTRWI_rec
    CEFBS_None, // SLDI
    CEFBS_None, // SLDI_rec
    CEFBS_None, // SLWI
    CEFBS_None, // SLWI_rec
    CEFBS_None, // SPILLTOVSR_LD
    CEFBS_None, // SPILLTOVSR_LDX
    CEFBS_None, // SPILLTOVSR_ST
    CEFBS_None, // SPILLTOVSR_STX
    CEFBS_None, // SRDI
    CEFBS_None, // SRDI_rec
    CEFBS_None, // SRWI
    CEFBS_None, // SRWI_rec
    CEFBS_None, // STIWX
    CEFBS_None, // SUBI
    CEFBS_None, // SUBIC
    CEFBS_None, // SUBIC_rec
    CEFBS_None, // SUBIS
    CEFBS_None, // SUBPCIS
    CEFBS_None, // XFLOADf32
    CEFBS_None, // XFLOADf64
    CEFBS_None, // XFSTOREf32
    CEFBS_None, // XFSTOREf64
    CEFBS_None, // ADD4
    CEFBS_None, // ADD4O
    CEFBS_None, // ADD4O_rec
    CEFBS_None, // ADD4TLS
    CEFBS_None, // ADD4_rec
    CEFBS_None, // ADD8
    CEFBS_None, // ADD8O
    CEFBS_None, // ADD8O_rec
    CEFBS_None, // ADD8TLS
    CEFBS_None, // ADD8TLS_
    CEFBS_None, // ADD8_rec
    CEFBS_None, // ADDC
    CEFBS_None, // ADDC8
    CEFBS_None, // ADDC8O
    CEFBS_None, // ADDC8O_rec
    CEFBS_None, // ADDC8_rec
    CEFBS_None, // ADDCO
    CEFBS_None, // ADDCO_rec
    CEFBS_None, // ADDC_rec
    CEFBS_None, // ADDE
    CEFBS_None, // ADDE8
    CEFBS_None, // ADDE8O
    CEFBS_None, // ADDE8O_rec
    CEFBS_None, // ADDE8_rec
    CEFBS_None, // ADDEO
    CEFBS_None, // ADDEO_rec
    CEFBS_None, // ADDEX
    CEFBS_None, // ADDEX8
    CEFBS_None, // ADDE_rec
    CEFBS_None, // ADDG6S
    CEFBS_None, // ADDG6S8
    CEFBS_None, // ADDI
    CEFBS_None, // ADDI8
    CEFBS_None, // ADDIC
    CEFBS_None, // ADDIC8
    CEFBS_None, // ADDIC_rec
    CEFBS_None, // ADDIS
    CEFBS_None, // ADDIS8
    CEFBS_None, // ADDISdtprelHA
    CEFBS_None, // ADDISdtprelHA32
    CEFBS_None, // ADDISgotTprelHA
    CEFBS_None, // ADDIStlsgdHA
    CEFBS_None, // ADDIStlsldHA
    CEFBS_None, // ADDIStocHA
    CEFBS_None, // ADDIStocHA8
    CEFBS_None, // ADDIdtprelL
    CEFBS_None, // ADDIdtprelL32
    CEFBS_None, // ADDItlsgdL
    CEFBS_None, // ADDItlsgdL32
    CEFBS_None, // ADDItlsgdLADDR
    CEFBS_None, // ADDItlsgdLADDR32
    CEFBS_None, // ADDItlsldL
    CEFBS_None, // ADDItlsldL32
    CEFBS_None, // ADDItlsldLADDR
    CEFBS_None, // ADDItlsldLADDR32
    CEFBS_None, // ADDItoc
    CEFBS_None, // ADDItoc8
    CEFBS_None, // ADDItocL
    CEFBS_None, // ADDItocL8
    CEFBS_None, // ADDME
    CEFBS_None, // ADDME8
    CEFBS_None, // ADDME8O
    CEFBS_None, // ADDME8O_rec
    CEFBS_None, // ADDME8_rec
    CEFBS_None, // ADDMEO
    CEFBS_None, // ADDMEO_rec
    CEFBS_None, // ADDME_rec
    CEFBS_None, // ADDPCIS
    CEFBS_None, // ADDZE
    CEFBS_None, // ADDZE8
    CEFBS_None, // ADDZE8O
    CEFBS_None, // ADDZE8O_rec
    CEFBS_None, // ADDZE8_rec
    CEFBS_None, // ADDZEO
    CEFBS_None, // ADDZEO_rec
    CEFBS_None, // ADDZE_rec
    CEFBS_None, // ADJCALLSTACKDOWN
    CEFBS_None, // ADJCALLSTACKUP
    CEFBS_None, // AND
    CEFBS_None, // AND8
    CEFBS_None, // AND8_rec
    CEFBS_None, // ANDC
    CEFBS_None, // ANDC8
    CEFBS_None, // ANDC8_rec
    CEFBS_None, // ANDC_rec
    CEFBS_None, // ANDI8_rec
    CEFBS_None, // ANDIS8_rec
    CEFBS_None, // ANDIS_rec
    CEFBS_None, // ANDI_rec
    CEFBS_None, // ANDI_rec_1_EQ_BIT
    CEFBS_None, // ANDI_rec_1_EQ_BIT8
    CEFBS_None, // ANDI_rec_1_GT_BIT
    CEFBS_None, // ANDI_rec_1_GT_BIT8
    CEFBS_None, // AND_rec
    CEFBS_None, // ATOMIC_CMP_SWAP_I16
    CEFBS_None, // ATOMIC_CMP_SWAP_I32
    CEFBS_None, // ATOMIC_CMP_SWAP_I64
    CEFBS_None, // ATOMIC_CMP_SWAP_I8
    CEFBS_None, // ATOMIC_LOAD_ADD
    CEFBS_None, // ATOMIC_LOAD_ADD_I64
    CEFBS_None, // ATOMIC_LOAD_ADD_NOWP
    CEFBS_None, // ATOMIC_LOAD_AND
    CEFBS_None, // ATOMIC_LOAD_AND_I64
    CEFBS_None, // ATOMIC_LOAD_AND_NOWP
    CEFBS_None, // ATOMIC_LOAD_MAX
    CEFBS_None, // ATOMIC_LOAD_MAX_I64
    CEFBS_None, // ATOMIC_LOAD_MAX_NOWP
    CEFBS_None, // ATOMIC_LOAD_MIN
    CEFBS_None, // ATOMIC_LOAD_MIN_I64
    CEFBS_None, // ATOMIC_LOAD_MIN_NOWP
    CEFBS_None, // ATOMIC_LOAD_NAND
    CEFBS_None, // ATOMIC_LOAD_NAND_I64
    CEFBS_None, // ATOMIC_LOAD_NAND_NOWP
    CEFBS_None, // ATOMIC_LOAD_OR
    CEFBS_None, // ATOMIC_LOAD_OR_I64
    CEFBS_None, // ATOMIC_LOAD_OR_NOWP
    CEFBS_None, // ATOMIC_LOAD_SUB
    CEFBS_None, // ATOMIC_LOAD_SUB_I64
    CEFBS_None, // ATOMIC_LOAD_SUB_NOWP
    CEFBS_None, // ATOMIC_LOAD_UMAX
    CEFBS_None, // ATOMIC_LOAD_UMAX_I64
    CEFBS_None, // ATOMIC_LOAD_UMAX_NOWP
    CEFBS_None, // ATOMIC_LOAD_UMIN
    CEFBS_None, // ATOMIC_LOAD_UMIN_I64
    CEFBS_None, // ATOMIC_LOAD_UMIN_NOWP
    CEFBS_None, // ATOMIC_LOAD_XOR
    CEFBS_None, // ATOMIC_LOAD_XOR_I64
    CEFBS_None, // ATOMIC_LOAD_XOR_NOWP
    CEFBS_None, // ATOMIC_SWAP
    CEFBS_None, // ATOMIC_SWAP_I64
    CEFBS_None, // ATOMIC_SWAP_NOWP
    CEFBS_None, // ATTN
    CEFBS_None, // B
    CEFBS_None, // BA
    CEFBS_None, // BC
    CEFBS_None, // BCC
    CEFBS_None, // BCCA
    CEFBS_None, // BCCCTR
    CEFBS_None, // BCCCTR8
    CEFBS_None, // BCCCTRL
    CEFBS_None, // BCCCTRL8
    CEFBS_None, // BCCL
    CEFBS_None, // BCCLA
    CEFBS_None, // BCCLR
    CEFBS_None, // BCCLRL
    CEFBS_None, // BCCTR
    CEFBS_None, // BCCTR8
    CEFBS_None, // BCCTR8n
    CEFBS_None, // BCCTRL
    CEFBS_None, // BCCTRL8
    CEFBS_None, // BCCTRL8n
    CEFBS_None, // BCCTRLn
    CEFBS_None, // BCCTRn
    CEFBS_None, // BCDADD_rec
    CEFBS_None, // BCDCFN_rec
    CEFBS_None, // BCDCFSQ_rec
    CEFBS_None, // BCDCFZ_rec
    CEFBS_None, // BCDCPSGN_rec
    CEFBS_None, // BCDCTN_rec
    CEFBS_None, // BCDCTSQ_rec
    CEFBS_None, // BCDCTZ_rec
    CEFBS_None, // BCDSETSGN_rec
    CEFBS_None, // BCDSR_rec
    CEFBS_None, // BCDSUB_rec
    CEFBS_None, // BCDS_rec
    CEFBS_None, // BCDTRUNC_rec
    CEFBS_None, // BCDUS_rec
    CEFBS_None, // BCDUTRUNC_rec
    CEFBS_None, // BCL
    CEFBS_None, // BCLR
    CEFBS_None, // BCLRL
    CEFBS_None, // BCLRLn
    CEFBS_None, // BCLRn
    CEFBS_None, // BCLalways
    CEFBS_None, // BCLn
    CEFBS_None, // BCTR
    CEFBS_None, // BCTR8
    CEFBS_None, // BCTRL
    CEFBS_None, // BCTRL8
    CEFBS_None, // BCTRL8_LDinto_toc
    CEFBS_None, // BCTRL8_LDinto_toc_RM
    CEFBS_None, // BCTRL8_RM
    CEFBS_None, // BCTRL_LWZinto_toc
    CEFBS_None, // BCTRL_LWZinto_toc_RM
    CEFBS_None, // BCTRL_RM
    CEFBS_None, // BCn
    CEFBS_None, // BDNZ
    CEFBS_None, // BDNZ8
    CEFBS_None, // BDNZA
    CEFBS_None, // BDNZAm
    CEFBS_None, // BDNZAp
    CEFBS_None, // BDNZL
    CEFBS_None, // BDNZLA
    CEFBS_None, // BDNZLAm
    CEFBS_None, // BDNZLAp
    CEFBS_None, // BDNZLR
    CEFBS_None, // BDNZLR8
    CEFBS_None, // BDNZLRL
    CEFBS_None, // BDNZLRLm
    CEFBS_None, // BDNZLRLp
    CEFBS_None, // BDNZLRm
    CEFBS_None, // BDNZLRp
    CEFBS_None, // BDNZLm
    CEFBS_None, // BDNZLp
    CEFBS_None, // BDNZm
    CEFBS_None, // BDNZp
    CEFBS_None, // BDZ
    CEFBS_None, // BDZ8
    CEFBS_None, // BDZA
    CEFBS_None, // BDZAm
    CEFBS_None, // BDZAp
    CEFBS_None, // BDZL
    CEFBS_None, // BDZLA
    CEFBS_None, // BDZLAm
    CEFBS_None, // BDZLAp
    CEFBS_None, // BDZLR
    CEFBS_None, // BDZLR8
    CEFBS_None, // BDZLRL
    CEFBS_None, // BDZLRLm
    CEFBS_None, // BDZLRLp
    CEFBS_None, // BDZLRm
    CEFBS_None, // BDZLRp
    CEFBS_None, // BDZLm
    CEFBS_None, // BDZLp
    CEFBS_None, // BDZm
    CEFBS_None, // BDZp
    CEFBS_None, // BL
    CEFBS_None, // BL8
    CEFBS_None, // BL8_LDinto_toc
    CEFBS_None, // BL8_LDinto_toc_RM
    CEFBS_None, // BL8_NOP
    CEFBS_None, // BL8_NOP_RM
    CEFBS_None, // BL8_NOP_TLS
    CEFBS_None, // BL8_NOTOC
    CEFBS_None, // BL8_NOTOC_RM
    CEFBS_None, // BL8_NOTOC_TLS
    CEFBS_None, // BL8_RM
    CEFBS_None, // BL8_TLS
    CEFBS_None, // BL8_TLS_
    CEFBS_None, // BLA
    CEFBS_None, // BLA8
    CEFBS_None, // BLA8_NOP
    CEFBS_None, // BLA8_NOP_RM
    CEFBS_None, // BLA8_RM
    CEFBS_None, // BLA_RM
    CEFBS_None, // BLR
    CEFBS_None, // BLR8
    CEFBS_None, // BLRL
    CEFBS_None, // BL_LWZinto_toc
    CEFBS_None, // BL_LWZinto_toc_RM
    CEFBS_None, // BL_NOP
    CEFBS_None, // BL_NOP_RM
    CEFBS_None, // BL_RM
    CEFBS_None, // BL_TLS
    CEFBS_None, // BPERMD
    CEFBS_None, // BRD
    CEFBS_None, // BRH
    CEFBS_None, // BRH8
    CEFBS_None, // BRINC
    CEFBS_None, // BRW
    CEFBS_None, // BRW8
    CEFBS_None, // CBCDTD
    CEFBS_None, // CBCDTD8
    CEFBS_None, // CDTBCD
    CEFBS_None, // CDTBCD8
    CEFBS_None, // CFUGED
    CEFBS_None, // CLRBHRB
    CEFBS_None, // CMPB
    CEFBS_None, // CMPB8
    CEFBS_None, // CMPD
    CEFBS_None, // CMPDI
    CEFBS_None, // CMPEQB
    CEFBS_None, // CMPLD
    CEFBS_None, // CMPLDI
    CEFBS_None, // CMPLW
    CEFBS_None, // CMPLWI
    CEFBS_None, // CMPRB
    CEFBS_None, // CMPRB8
    CEFBS_None, // CMPW
    CEFBS_None, // CMPWI
    CEFBS_None, // CNTLZD
    CEFBS_None, // CNTLZDM
    CEFBS_None, // CNTLZD_rec
    CEFBS_None, // CNTLZW
    CEFBS_None, // CNTLZW8
    CEFBS_None, // CNTLZW8_rec
    CEFBS_None, // CNTLZW_rec
    CEFBS_None, // CNTTZD
    CEFBS_None, // CNTTZDM
    CEFBS_None, // CNTTZD_rec
    CEFBS_None, // CNTTZW
    CEFBS_None, // CNTTZW8
    CEFBS_None, // CNTTZW8_rec
    CEFBS_None, // CNTTZW_rec
    CEFBS_None, // CP_ABORT
    CEFBS_None, // CP_COPY
    CEFBS_None, // CP_COPY8
    CEFBS_None, // CP_PASTE8_rec
    CEFBS_None, // CP_PASTE_rec
    CEFBS_None, // CR6SET
    CEFBS_None, // CR6UNSET
    CEFBS_None, // CRAND
    CEFBS_None, // CRANDC
    CEFBS_None, // CREQV
    CEFBS_None, // CRNAND
    CEFBS_None, // CRNOR
    CEFBS_None, // CRNOT
    CEFBS_None, // CROR
    CEFBS_None, // CRORC
    CEFBS_None, // CRSET
    CEFBS_None, // CRUNSET
    CEFBS_None, // CRXOR
    CEFBS_None, // CTRL_DEP
    CEFBS_None, // DADD
    CEFBS_None, // DADDQ
    CEFBS_None, // DADDQ_rec
    CEFBS_None, // DADD_rec
    CEFBS_None, // DARN
    CEFBS_None, // DCBA
    CEFBS_None, // DCBF
    CEFBS_None, // DCBFEP
    CEFBS_None, // DCBI
    CEFBS_None, // DCBST
    CEFBS_None, // DCBSTEP
    CEFBS_None, // DCBT
    CEFBS_None, // DCBTEP
    CEFBS_None, // DCBTST
    CEFBS_None, // DCBTSTEP
    CEFBS_None, // DCBZ
    CEFBS_None, // DCBZEP
    CEFBS_None, // DCBZL
    CEFBS_None, // DCBZLEP
    CEFBS_None, // DCCCI
    CEFBS_None, // DCFFIX
    CEFBS_None, // DCFFIXQ
    CEFBS_None, // DCFFIXQQ
    CEFBS_None, // DCFFIXQ_rec
    CEFBS_None, // DCFFIX_rec
    CEFBS_None, // DCMPO
    CEFBS_None, // DCMPOQ
    CEFBS_None, // DCMPU
    CEFBS_None, // DCMPUQ
    CEFBS_None, // DCTDP
    CEFBS_None, // DCTDP_rec
    CEFBS_None, // DCTFIX
    CEFBS_None, // DCTFIXQ
    CEFBS_None, // DCTFIXQQ
    CEFBS_None, // DCTFIXQ_rec
    CEFBS_None, // DCTFIX_rec
    CEFBS_None, // DCTQPQ
    CEFBS_None, // DCTQPQ_rec
    CEFBS_None, // DDEDPD
    CEFBS_None, // DDEDPDQ
    CEFBS_None, // DDEDPDQ_rec
    CEFBS_None, // DDEDPD_rec
    CEFBS_None, // DDIV
    CEFBS_None, // DDIVQ
    CEFBS_None, // DDIVQ_rec
    CEFBS_None, // DDIV_rec
    CEFBS_None, // DENBCD
    CEFBS_None, // DENBCDQ
    CEFBS_None, // DENBCDQ_rec
    CEFBS_None, // DENBCD_rec
    CEFBS_None, // DIEX
    CEFBS_None, // DIEXQ
    CEFBS_None, // DIEXQ_rec
    CEFBS_None, // DIEX_rec
    CEFBS_None, // DIVD
    CEFBS_None, // DIVDE
    CEFBS_None, // DIVDEO
    CEFBS_None, // DIVDEO_rec
    CEFBS_None, // DIVDEU
    CEFBS_None, // DIVDEUO
    CEFBS_None, // DIVDEUO_rec
    CEFBS_None, // DIVDEU_rec
    CEFBS_None, // DIVDE_rec
    CEFBS_None, // DIVDO
    CEFBS_None, // DIVDO_rec
    CEFBS_None, // DIVDU
    CEFBS_None, // DIVDUO
    CEFBS_None, // DIVDUO_rec
    CEFBS_None, // DIVDU_rec
    CEFBS_None, // DIVD_rec
    CEFBS_None, // DIVW
    CEFBS_None, // DIVWE
    CEFBS_None, // DIVWEO
    CEFBS_None, // DIVWEO_rec
    CEFBS_None, // DIVWEU
    CEFBS_None, // DIVWEUO
    CEFBS_None, // DIVWEUO_rec
    CEFBS_None, // DIVWEU_rec
    CEFBS_None, // DIVWE_rec
    CEFBS_None, // DIVWO
    CEFBS_None, // DIVWO_rec
    CEFBS_None, // DIVWU
    CEFBS_None, // DIVWUO
    CEFBS_None, // DIVWUO_rec
    CEFBS_None, // DIVWU_rec
    CEFBS_None, // DIVW_rec
    CEFBS_None, // DMMR
    CEFBS_None, // DMSETDMRZ
    CEFBS_None, // DMSHA2HASH
    CEFBS_None, // DMSHA3HASH
    CEFBS_None, // DMUL
    CEFBS_None, // DMULQ
    CEFBS_None, // DMULQ_rec
    CEFBS_None, // DMUL_rec
    CEFBS_None, // DMXOR
    CEFBS_None, // DMXVBF16GERX2
    CEFBS_None, // DMXVBF16GERX2NN
    CEFBS_None, // DMXVBF16GERX2NP
    CEFBS_None, // DMXVBF16GERX2PN
    CEFBS_None, // DMXVBF16GERX2PP
    CEFBS_None, // DMXVF16GERX2
    CEFBS_None, // DMXVF16GERX2NN
    CEFBS_None, // DMXVF16GERX2NP
    CEFBS_None, // DMXVF16GERX2PN
    CEFBS_None, // DMXVF16GERX2PP
    CEFBS_None, // DMXVI8GERX4
    CEFBS_None, // DMXVI8GERX4PP
    CEFBS_None, // DMXVI8GERX4SPP
    CEFBS_None, // DMXXEXTFDMR256
    CEFBS_None, // DMXXEXTFDMR512
    CEFBS_None, // DMXXEXTFDMR512_HI
    CEFBS_None, // DMXXINSTDMR256
    CEFBS_None, // DMXXINSTDMR512
    CEFBS_None, // DMXXINSTDMR512_HI
    CEFBS_None, // DMXXSETACCZ
    CEFBS_None, // DMXXSHAPAD
    CEFBS_None, // DQUA
    CEFBS_None, // DQUAI
    CEFBS_None, // DQUAIQ
    CEFBS_None, // DQUAIQ_rec
    CEFBS_None, // DQUAI_rec
    CEFBS_None, // DQUAQ
    CEFBS_None, // DQUAQ_rec
    CEFBS_None, // DQUA_rec
    CEFBS_None, // DRDPQ
    CEFBS_None, // DRDPQ_rec
    CEFBS_None, // DRINTN
    CEFBS_None, // DRINTNQ
    CEFBS_None, // DRINTNQ_rec
    CEFBS_None, // DRINTN_rec
    CEFBS_None, // DRINTX
    CEFBS_None, // DRINTXQ
    CEFBS_None, // DRINTXQ_rec
    CEFBS_None, // DRINTX_rec
    CEFBS_None, // DRRND
    CEFBS_None, // DRRNDQ
    CEFBS_None, // DRRNDQ_rec
    CEFBS_None, // DRRND_rec
    CEFBS_None, // DRSP
    CEFBS_None, // DRSP_rec
    CEFBS_None, // DSCLI
    CEFBS_None, // DSCLIQ
    CEFBS_None, // DSCLIQ_rec
    CEFBS_None, // DSCLI_rec
    CEFBS_None, // DSCRI
    CEFBS_None, // DSCRIQ
    CEFBS_None, // DSCRIQ_rec
    CEFBS_None, // DSCRI_rec
    CEFBS_None, // DSS
    CEFBS_None, // DSSALL
    CEFBS_None, // DST
    CEFBS_None, // DST64
    CEFBS_None, // DSTST
    CEFBS_None, // DSTST64
    CEFBS_None, // DSTSTT
    CEFBS_None, // DSTSTT64
    CEFBS_None, // DSTT
    CEFBS_None, // DSTT64
    CEFBS_None, // DSUB
    CEFBS_None, // DSUBQ
    CEFBS_None, // DSUBQ_rec
    CEFBS_None, // DSUB_rec
    CEFBS_None, // DTSTDC
    CEFBS_None, // DTSTDCQ
    CEFBS_None, // DTSTDG
    CEFBS_None, // DTSTDGQ
    CEFBS_None, // DTSTEX
    CEFBS_None, // DTSTEXQ
    CEFBS_None, // DTSTSF
    CEFBS_None, // DTSTSFI
    CEFBS_None, // DTSTSFIQ
    CEFBS_None, // DTSTSFQ
    CEFBS_None, // DXEX
    CEFBS_None, // DXEXQ
    CEFBS_None, // DXEXQ_rec
    CEFBS_None, // DXEX_rec
    CEFBS_None, // DYNALLOC
    CEFBS_None, // DYNALLOC8
    CEFBS_None, // DYNAREAOFFSET
    CEFBS_None, // DYNAREAOFFSET8
    CEFBS_None, // DecreaseCTR8loop
    CEFBS_None, // DecreaseCTRloop
    CEFBS_None, // EFDABS
    CEFBS_None, // EFDADD
    CEFBS_None, // EFDCFS
    CEFBS_None, // EFDCFSF
    CEFBS_None, // EFDCFSI
    CEFBS_None, // EFDCFSID
    CEFBS_None, // EFDCFUF
    CEFBS_None, // EFDCFUI
    CEFBS_None, // EFDCFUID
    CEFBS_None, // EFDCMPEQ
    CEFBS_None, // EFDCMPGT
    CEFBS_None, // EFDCMPLT
    CEFBS_None, // EFDCTSF
    CEFBS_None, // EFDCTSI
    CEFBS_None, // EFDCTSIDZ
    CEFBS_None, // EFDCTSIZ
    CEFBS_None, // EFDCTUF
    CEFBS_None, // EFDCTUI
    CEFBS_None, // EFDCTUIDZ
    CEFBS_None, // EFDCTUIZ
    CEFBS_None, // EFDDIV
    CEFBS_None, // EFDMUL
    CEFBS_None, // EFDNABS
    CEFBS_None, // EFDNEG
    CEFBS_None, // EFDSUB
    CEFBS_None, // EFDTSTEQ
    CEFBS_None, // EFDTSTGT
    CEFBS_None, // EFDTSTLT
    CEFBS_None, // EFSABS
    CEFBS_None, // EFSADD
    CEFBS_None, // EFSCFD
    CEFBS_None, // EFSCFSF
    CEFBS_None, // EFSCFSI
    CEFBS_None, // EFSCFUF
    CEFBS_None, // EFSCFUI
    CEFBS_None, // EFSCMPEQ
    CEFBS_None, // EFSCMPGT
    CEFBS_None, // EFSCMPLT
    CEFBS_None, // EFSCTSF
    CEFBS_None, // EFSCTSI
    CEFBS_None, // EFSCTSIZ
    CEFBS_None, // EFSCTUF
    CEFBS_None, // EFSCTUI
    CEFBS_None, // EFSCTUIZ
    CEFBS_None, // EFSDIV
    CEFBS_None, // EFSMUL
    CEFBS_None, // EFSNABS
    CEFBS_None, // EFSNEG
    CEFBS_None, // EFSSUB
    CEFBS_None, // EFSTSTEQ
    CEFBS_None, // EFSTSTGT
    CEFBS_None, // EFSTSTLT
    CEFBS_None, // EH_SjLj_LongJmp32
    CEFBS_None, // EH_SjLj_LongJmp64
    CEFBS_None, // EH_SjLj_SetJmp32
    CEFBS_None, // EH_SjLj_SetJmp64
    CEFBS_None, // EH_SjLj_Setup
    CEFBS_None, // EQV
    CEFBS_None, // EQV8
    CEFBS_None, // EQV8_rec
    CEFBS_None, // EQV_rec
    CEFBS_None, // EVABS
    CEFBS_None, // EVADDIW
    CEFBS_None, // EVADDSMIAAW
    CEFBS_None, // EVADDSSIAAW
    CEFBS_None, // EVADDUMIAAW
    CEFBS_None, // EVADDUSIAAW
    CEFBS_None, // EVADDW
    CEFBS_None, // EVAND
    CEFBS_None, // EVANDC
    CEFBS_None, // EVCMPEQ
    CEFBS_None, // EVCMPGTS
    CEFBS_None, // EVCMPGTU
    CEFBS_None, // EVCMPLTS
    CEFBS_None, // EVCMPLTU
    CEFBS_None, // EVCNTLSW
    CEFBS_None, // EVCNTLZW
    CEFBS_None, // EVDIVWS
    CEFBS_None, // EVDIVWU
    CEFBS_None, // EVEQV
    CEFBS_None, // EVEXTSB
    CEFBS_None, // EVEXTSH
    CEFBS_None, // EVFSABS
    CEFBS_None, // EVFSADD
    CEFBS_None, // EVFSCFSF
    CEFBS_None, // EVFSCFSI
    CEFBS_None, // EVFSCFUF
    CEFBS_None, // EVFSCFUI
    CEFBS_None, // EVFSCMPEQ
    CEFBS_None, // EVFSCMPGT
    CEFBS_None, // EVFSCMPLT
    CEFBS_None, // EVFSCTSF
    CEFBS_None, // EVFSCTSI
    CEFBS_None, // EVFSCTSIZ
    CEFBS_None, // EVFSCTUF
    CEFBS_None, // EVFSCTUI
    CEFBS_None, // EVFSCTUIZ
    CEFBS_None, // EVFSDIV
    CEFBS_None, // EVFSMUL
    CEFBS_None, // EVFSNABS
    CEFBS_None, // EVFSNEG
    CEFBS_None, // EVFSSUB
    CEFBS_None, // EVFSTSTEQ
    CEFBS_None, // EVFSTSTGT
    CEFBS_None, // EVFSTSTLT
    CEFBS_None, // EVLDD
    CEFBS_None, // EVLDDX
    CEFBS_None, // EVLDH
    CEFBS_None, // EVLDHX
    CEFBS_None, // EVLDW
    CEFBS_None, // EVLDWX
    CEFBS_None, // EVLHHESPLAT
    CEFBS_None, // EVLHHESPLATX
    CEFBS_None, // EVLHHOSSPLAT
    CEFBS_None, // EVLHHOSSPLATX
    CEFBS_None, // EVLHHOUSPLAT
    CEFBS_None, // EVLHHOUSPLATX
    CEFBS_None, // EVLWHE
    CEFBS_None, // EVLWHEX
    CEFBS_None, // EVLWHOS
    CEFBS_None, // EVLWHOSX
    CEFBS_None, // EVLWHOU
    CEFBS_None, // EVLWHOUX
    CEFBS_None, // EVLWHSPLAT
    CEFBS_None, // EVLWHSPLATX
    CEFBS_None, // EVLWWSPLAT
    CEFBS_None, // EVLWWSPLATX
    CEFBS_None, // EVMERGEHI
    CEFBS_None, // EVMERGEHILO
    CEFBS_None, // EVMERGELO
    CEFBS_None, // EVMERGELOHI
    CEFBS_None, // EVMHEGSMFAA
    CEFBS_None, // EVMHEGSMFAN
    CEFBS_None, // EVMHEGSMIAA
    CEFBS_None, // EVMHEGSMIAN
    CEFBS_None, // EVMHEGUMIAA
    CEFBS_None, // EVMHEGUMIAN
    CEFBS_None, // EVMHESMF
    CEFBS_None, // EVMHESMFA
    CEFBS_None, // EVMHESMFAAW
    CEFBS_None, // EVMHESMFANW
    CEFBS_None, // EVMHESMI
    CEFBS_None, // EVMHESMIA
    CEFBS_None, // EVMHESMIAAW
    CEFBS_None, // EVMHESMIANW
    CEFBS_None, // EVMHESSF
    CEFBS_None, // EVMHESSFA
    CEFBS_None, // EVMHESSFAAW
    CEFBS_None, // EVMHESSFANW
    CEFBS_None, // EVMHESSIAAW
    CEFBS_None, // EVMHESSIANW
    CEFBS_None, // EVMHEUMI
    CEFBS_None, // EVMHEUMIA
    CEFBS_None, // EVMHEUMIAAW
    CEFBS_None, // EVMHEUMIANW
    CEFBS_None, // EVMHEUSIAAW
    CEFBS_None, // EVMHEUSIANW
    CEFBS_None, // EVMHOGSMFAA
    CEFBS_None, // EVMHOGSMFAN
    CEFBS_None, // EVMHOGSMIAA
    CEFBS_None, // EVMHOGSMIAN
    CEFBS_None, // EVMHOGUMIAA
    CEFBS_None, // EVMHOGUMIAN
    CEFBS_None, // EVMHOSMF
    CEFBS_None, // EVMHOSMFA
    CEFBS_None, // EVMHOSMFAAW
    CEFBS_None, // EVMHOSMFANW
    CEFBS_None, // EVMHOSMI
    CEFBS_None, // EVMHOSMIA
    CEFBS_None, // EVMHOSMIAAW
    CEFBS_None, // EVMHOSMIANW
    CEFBS_None, // EVMHOSSF
    CEFBS_None, // EVMHOSSFA
    CEFBS_None, // EVMHOSSFAAW
    CEFBS_None, // EVMHOSSFANW
    CEFBS_None, // EVMHOSSIAAW
    CEFBS_None, // EVMHOSSIANW
    CEFBS_None, // EVMHOUMI
    CEFBS_None, // EVMHOUMIA
    CEFBS_None, // EVMHOUMIAAW
    CEFBS_None, // EVMHOUMIANW
    CEFBS_None, // EVMHOUSIAAW
    CEFBS_None, // EVMHOUSIANW
    CEFBS_None, // EVMRA
    CEFBS_None, // EVMWHSMF
    CEFBS_None, // EVMWHSMFA
    CEFBS_None, // EVMWHSMI
    CEFBS_None, // EVMWHSMIA
    CEFBS_None, // EVMWHSSF
    CEFBS_None, // EVMWHSSFA
    CEFBS_None, // EVMWHUMI
    CEFBS_None, // EVMWHUMIA
    CEFBS_None, // EVMWLSMIAAW
    CEFBS_None, // EVMWLSMIANW
    CEFBS_None, // EVMWLSSIAAW
    CEFBS_None, // EVMWLSSIANW
    CEFBS_None, // EVMWLUMI
    CEFBS_None, // EVMWLUMIA
    CEFBS_None, // EVMWLUMIAAW
    CEFBS_None, // EVMWLUMIANW
    CEFBS_None, // EVMWLUSIAAW
    CEFBS_None, // EVMWLUSIANW
    CEFBS_None, // EVMWSMF
    CEFBS_None, // EVMWSMFA
    CEFBS_None, // EVMWSMFAA
    CEFBS_None, // EVMWSMFAN
    CEFBS_None, // EVMWSMI
    CEFBS_None, // EVMWSMIA
    CEFBS_None, // EVMWSMIAA
    CEFBS_None, // EVMWSMIAN
    CEFBS_None, // EVMWSSF
    CEFBS_None, // EVMWSSFA
    CEFBS_None, // EVMWSSFAA
    CEFBS_None, // EVMWSSFAN
    CEFBS_None, // EVMWUMI
    CEFBS_None, // EVMWUMIA
    CEFBS_None, // EVMWUMIAA
    CEFBS_None, // EVMWUMIAN
    CEFBS_None, // EVNAND
    CEFBS_None, // EVNEG
    CEFBS_None, // EVNOR
    CEFBS_None, // EVOR
    CEFBS_None, // EVORC
    CEFBS_None, // EVRLW
    CEFBS_None, // EVRLWI
    CEFBS_None, // EVRNDW
    CEFBS_None, // EVSEL
    CEFBS_None, // EVSLW
    CEFBS_None, // EVSLWI
    CEFBS_None, // EVSPLATFI
    CEFBS_None, // EVSPLATI
    CEFBS_None, // EVSRWIS
    CEFBS_None, // EVSRWIU
    CEFBS_None, // EVSRWS
    CEFBS_None, // EVSRWU
    CEFBS_None, // EVSTDD
    CEFBS_None, // EVSTDDX
    CEFBS_None, // EVSTDH
    CEFBS_None, // EVSTDHX
    CEFBS_None, // EVSTDW
    CEFBS_None, // EVSTDWX
    CEFBS_None, // EVSTWHE
    CEFBS_None, // EVSTWHEX
    CEFBS_None, // EVSTWHO
    CEFBS_None, // EVSTWHOX
    CEFBS_None, // EVSTWWE
    CEFBS_None, // EVSTWWEX
    CEFBS_None, // EVSTWWO
    CEFBS_None, // EVSTWWOX
    CEFBS_None, // EVSUBFSMIAAW
    CEFBS_None, // EVSUBFSSIAAW
    CEFBS_None, // EVSUBFUMIAAW
    CEFBS_None, // EVSUBFUSIAAW
    CEFBS_None, // EVSUBFW
    CEFBS_None, // EVSUBIFW
    CEFBS_None, // EVXOR
    CEFBS_None, // EXTSB
    CEFBS_None, // EXTSB8
    CEFBS_None, // EXTSB8_32_64
    CEFBS_None, // EXTSB8_rec
    CEFBS_None, // EXTSB_rec
    CEFBS_None, // EXTSH
    CEFBS_None, // EXTSH8
    CEFBS_None, // EXTSH8_32_64
    CEFBS_None, // EXTSH8_rec
    CEFBS_None, // EXTSH_rec
    CEFBS_None, // EXTSW
    CEFBS_None, // EXTSWSLI
    CEFBS_None, // EXTSWSLI_32_64
    CEFBS_None, // EXTSWSLI_32_64_rec
    CEFBS_None, // EXTSWSLI_rec
    CEFBS_None, // EXTSW_32
    CEFBS_None, // EXTSW_32_64
    CEFBS_None, // EXTSW_32_64_rec
    CEFBS_None, // EXTSW_rec
    CEFBS_None, // EnforceIEIO
    CEFBS_None, // FABSD
    CEFBS_None, // FABSD_rec
    CEFBS_None, // FABSS
    CEFBS_None, // FABSS_rec
    CEFBS_None, // FADD
    CEFBS_None, // FADDS
    CEFBS_None, // FADDS_rec
    CEFBS_None, // FADD_rec
    CEFBS_None, // FADDrtz
    CEFBS_None, // FCFID
    CEFBS_None, // FCFIDS
    CEFBS_None, // FCFIDS_rec
    CEFBS_None, // FCFIDU
    CEFBS_None, // FCFIDUS
    CEFBS_None, // FCFIDUS_rec
    CEFBS_None, // FCFIDU_rec
    CEFBS_None, // FCFID_rec
    CEFBS_None, // FCMPOD
    CEFBS_None, // FCMPOS
    CEFBS_None, // FCMPUD
    CEFBS_None, // FCMPUS
    CEFBS_None, // FCPSGND
    CEFBS_None, // FCPSGND_rec
    CEFBS_None, // FCPSGNS
    CEFBS_None, // FCPSGNS_rec
    CEFBS_None, // FCTID
    CEFBS_None, // FCTIDU
    CEFBS_None, // FCTIDUZ
    CEFBS_None, // FCTIDUZ_rec
    CEFBS_None, // FCTIDU_rec
    CEFBS_None, // FCTIDZ
    CEFBS_None, // FCTIDZ_rec
    CEFBS_None, // FCTID_rec
    CEFBS_None, // FCTIW
    CEFBS_None, // FCTIWU
    CEFBS_None, // FCTIWUZ
    CEFBS_None, // FCTIWUZ_rec
    CEFBS_None, // FCTIWU_rec
    CEFBS_None, // FCTIWZ
    CEFBS_None, // FCTIWZ_rec
    CEFBS_None, // FCTIW_rec
    CEFBS_None, // FDIV
    CEFBS_None, // FDIVS
    CEFBS_None, // FDIVS_rec
    CEFBS_None, // FDIV_rec
    CEFBS_None, // FENCE
    CEFBS_None, // FMADD
    CEFBS_None, // FMADDS
    CEFBS_None, // FMADDS_rec
    CEFBS_None, // FMADD_rec
    CEFBS_None, // FMR
    CEFBS_None, // FMR_rec
    CEFBS_None, // FMSUB
    CEFBS_None, // FMSUBS
    CEFBS_None, // FMSUBS_rec
    CEFBS_None, // FMSUB_rec
    CEFBS_None, // FMUL
    CEFBS_None, // FMULS
    CEFBS_None, // FMULS_rec
    CEFBS_None, // FMUL_rec
    CEFBS_None, // FNABSD
    CEFBS_None, // FNABSD_rec
    CEFBS_None, // FNABSS
    CEFBS_None, // FNABSS_rec
    CEFBS_None, // FNEGD
    CEFBS_None, // FNEGD_rec
    CEFBS_None, // FNEGS
    CEFBS_None, // FNEGS_rec
    CEFBS_None, // FNMADD
    CEFBS_None, // FNMADDS
    CEFBS_None, // FNMADDS_rec
    CEFBS_None, // FNMADD_rec
    CEFBS_None, // FNMSUB
    CEFBS_None, // FNMSUBS
    CEFBS_None, // FNMSUBS_rec
    CEFBS_None, // FNMSUB_rec
    CEFBS_None, // FRE
    CEFBS_None, // FRES
    CEFBS_None, // FRES_rec
    CEFBS_None, // FRE_rec
    CEFBS_None, // FRIMD
    CEFBS_None, // FRIMD_rec
    CEFBS_None, // FRIMS
    CEFBS_None, // FRIMS_rec
    CEFBS_None, // FRIND
    CEFBS_None, // FRIND_rec
    CEFBS_None, // FRINS
    CEFBS_None, // FRINS_rec
    CEFBS_None, // FRIPD
    CEFBS_None, // FRIPD_rec
    CEFBS_None, // FRIPS
    CEFBS_None, // FRIPS_rec
    CEFBS_None, // FRIZD
    CEFBS_None, // FRIZD_rec
    CEFBS_None, // FRIZS
    CEFBS_None, // FRIZS_rec
    CEFBS_None, // FRSP
    CEFBS_None, // FRSP_rec
    CEFBS_None, // FRSQRTE
    CEFBS_None, // FRSQRTES
    CEFBS_None, // FRSQRTES_rec
    CEFBS_None, // FRSQRTE_rec
    CEFBS_None, // FSELD
    CEFBS_None, // FSELD_rec
    CEFBS_None, // FSELS
    CEFBS_None, // FSELS_rec
    CEFBS_None, // FSQRT
    CEFBS_None, // FSQRTS
    CEFBS_None, // FSQRTS_rec
    CEFBS_None, // FSQRT_rec
    CEFBS_None, // FSUB
    CEFBS_None, // FSUBS
    CEFBS_None, // FSUBS_rec
    CEFBS_None, // FSUB_rec
    CEFBS_None, // FTDIV
    CEFBS_None, // FTSQRT
    CEFBS_None, // GETtlsADDR
    CEFBS_None, // GETtlsADDR32
    CEFBS_None, // GETtlsADDR32AIX
    CEFBS_None, // GETtlsADDR64AIX
    CEFBS_None, // GETtlsADDRPCREL
    CEFBS_None, // GETtlsMOD32AIX
    CEFBS_None, // GETtlsMOD64AIX
    CEFBS_None, // GETtlsTpointer32AIX
    CEFBS_None, // GETtlsldADDR
    CEFBS_None, // GETtlsldADDR32
    CEFBS_None, // GETtlsldADDRPCREL
    CEFBS_None, // HASHCHK
    CEFBS_None, // HASHCHK8
    CEFBS_None, // HASHCHKP
    CEFBS_None, // HASHCHKP8
    CEFBS_None, // HASHST
    CEFBS_None, // HASHST8
    CEFBS_None, // HASHSTP
    CEFBS_None, // HASHSTP8
    CEFBS_None, // HRFID
    CEFBS_None, // ICBI
    CEFBS_None, // ICBIEP
    CEFBS_None, // ICBLC
    CEFBS_None, // ICBLQ
    CEFBS_None, // ICBT
    CEFBS_None, // ICBTLS
    CEFBS_None, // ICCCI
    CEFBS_None, // ISEL
    CEFBS_None, // ISEL8
    CEFBS_None, // ISYNC
    CEFBS_None, // LA
    CEFBS_None, // LA8
    CEFBS_None, // LBARX
    CEFBS_None, // LBARXL
    CEFBS_None, // LBEPX
    CEFBS_None, // LBZ
    CEFBS_None, // LBZ8
    CEFBS_None, // LBZCIX
    CEFBS_None, // LBZU
    CEFBS_None, // LBZU8
    CEFBS_None, // LBZUX
    CEFBS_None, // LBZUX8
    CEFBS_None, // LBZX
    CEFBS_None, // LBZX8
    CEFBS_None, // LBZXTLS
    CEFBS_None, // LBZXTLS_
    CEFBS_None, // LBZXTLS_32
    CEFBS_None, // LD
    CEFBS_None, // LDARX
    CEFBS_None, // LDARXL
    CEFBS_None, // LDAT
    CEFBS_None, // LDAT_CSNE
    CEFBS_None, // LDBRX
    CEFBS_None, // LDCIX
    CEFBS_None, // LDU
    CEFBS_None, // LDUX
    CEFBS_None, // LDX
    CEFBS_None, // LDXTLS
    CEFBS_None, // LDXTLS_
    CEFBS_None, // LDgotTprelL
    CEFBS_None, // LDgotTprelL32
    CEFBS_None, // LDtoc
    CEFBS_None, // LDtocBA
    CEFBS_None, // LDtocCPT
    CEFBS_None, // LDtocJTI
    CEFBS_None, // LDtocL
    CEFBS_None, // LFD
    CEFBS_None, // LFDEPX
    CEFBS_None, // LFDU
    CEFBS_None, // LFDUX
    CEFBS_None, // LFDX
    CEFBS_None, // LFDXTLS
    CEFBS_None, // LFDXTLS_
    CEFBS_None, // LFIWAX
    CEFBS_None, // LFIWZX
    CEFBS_None, // LFS
    CEFBS_None, // LFSU
    CEFBS_None, // LFSUX
    CEFBS_None, // LFSX
    CEFBS_None, // LFSXTLS
    CEFBS_None, // LFSXTLS_
    CEFBS_None, // LHA
    CEFBS_None, // LHA8
    CEFBS_None, // LHARX
    CEFBS_None, // LHARXL
    CEFBS_None, // LHAU
    CEFBS_None, // LHAU8
    CEFBS_None, // LHAUX
    CEFBS_None, // LHAUX8
    CEFBS_None, // LHAX
    CEFBS_None, // LHAX8
    CEFBS_None, // LHAXTLS
    CEFBS_None, // LHAXTLS_
    CEFBS_None, // LHAXTLS_32
    CEFBS_None, // LHBRX
    CEFBS_None, // LHBRX8
    CEFBS_None, // LHEPX
    CEFBS_None, // LHZ
    CEFBS_None, // LHZ8
    CEFBS_None, // LHZCIX
    CEFBS_None, // LHZU
    CEFBS_None, // LHZU8
    CEFBS_None, // LHZUX
    CEFBS_None, // LHZUX8
    CEFBS_None, // LHZX
    CEFBS_None, // LHZX8
    CEFBS_None, // LHZXTLS
    CEFBS_None, // LHZXTLS_
    CEFBS_None, // LHZXTLS_32
    CEFBS_None, // LI
    CEFBS_None, // LI8
    CEFBS_None, // LIS
    CEFBS_None, // LIS8
    CEFBS_None, // LMW
    CEFBS_None, // LQ
    CEFBS_None, // LQARX
    CEFBS_None, // LQARXL
    CEFBS_None, // LQX_PSEUDO
    CEFBS_None, // LSWI
    CEFBS_None, // LVEBX
    CEFBS_None, // LVEHX
    CEFBS_None, // LVEWX
    CEFBS_None, // LVSL
    CEFBS_None, // LVSR
    CEFBS_None, // LVX
    CEFBS_None, // LVXL
    CEFBS_None, // LWA
    CEFBS_None, // LWARX
    CEFBS_None, // LWARXL
    CEFBS_None, // LWAT
    CEFBS_None, // LWAT_CSNE
    CEFBS_None, // LWAUX
    CEFBS_None, // LWAX
    CEFBS_None, // LWAXTLS
    CEFBS_None, // LWAXTLS_
    CEFBS_None, // LWAXTLS_32
    CEFBS_None, // LWAX_32
    CEFBS_None, // LWA_32
    CEFBS_None, // LWBRX
    CEFBS_None, // LWBRX8
    CEFBS_None, // LWEPX
    CEFBS_None, // LWZ
    CEFBS_None, // LWZ8
    CEFBS_None, // LWZCIX
    CEFBS_None, // LWZU
    CEFBS_None, // LWZU8
    CEFBS_None, // LWZUX
    CEFBS_None, // LWZUX8
    CEFBS_None, // LWZX
    CEFBS_None, // LWZX8
    CEFBS_None, // LWZXTLS
    CEFBS_None, // LWZXTLS_
    CEFBS_None, // LWZXTLS_32
    CEFBS_None, // LWZtoc
    CEFBS_None, // LWZtocL
    CEFBS_None, // LXSD
    CEFBS_None, // LXSDX
    CEFBS_None, // LXSIBZX
    CEFBS_None, // LXSIHZX
    CEFBS_None, // LXSIWAX
    CEFBS_None, // LXSIWZX
    CEFBS_None, // LXSSP
    CEFBS_None, // LXSSPX
    CEFBS_None, // LXV
    CEFBS_None, // LXVB16X
    CEFBS_None, // LXVD2X
    CEFBS_None, // LXVDSX
    CEFBS_None, // LXVH8X
    CEFBS_None, // LXVKQ
    CEFBS_None, // LXVL
    CEFBS_None, // LXVLL
    CEFBS_None, // LXVP
    CEFBS_None, // LXVPB32X
    CEFBS_None, // LXVPRL
    CEFBS_None, // LXVPRLL
    CEFBS_None, // LXVPX
    CEFBS_None, // LXVRBX
    CEFBS_None, // LXVRDX
    CEFBS_None, // LXVRHX
    CEFBS_None, // LXVRL
    CEFBS_None, // LXVRLL
    CEFBS_None, // LXVRWX
    CEFBS_None, // LXVW4X
    CEFBS_None, // LXVWSX
    CEFBS_None, // LXVX
    CEFBS_None, // MADDHD
    CEFBS_None, // MADDHDU
    CEFBS_None, // MADDLD
    CEFBS_None, // MADDLD8
    CEFBS_None, // MBAR
    CEFBS_None, // MCRF
    CEFBS_None, // MCRFS
    CEFBS_None, // MCRXRX
    CEFBS_None, // MFBHRBE
    CEFBS_None, // MFCR
    CEFBS_None, // MFCR8
    CEFBS_None, // MFCTR
    CEFBS_None, // MFCTR8
    CEFBS_None, // MFDCR
    CEFBS_None, // MFFS
    CEFBS_None, // MFFSCDRN
    CEFBS_None, // MFFSCDRNI
    CEFBS_None, // MFFSCE
    CEFBS_None, // MFFSCRN
    CEFBS_None, // MFFSCRNI
    CEFBS_None, // MFFSL
    CEFBS_None, // MFFS_rec
    CEFBS_None, // MFLR
    CEFBS_None, // MFLR8
    CEFBS_None, // MFMSR
    CEFBS_None, // MFOCRF
    CEFBS_None, // MFOCRF8
    CEFBS_None, // MFPMR
    CEFBS_None, // MFSPR
    CEFBS_None, // MFSPR8
    CEFBS_None, // MFSR
    CEFBS_None, // MFSRIN
    CEFBS_None, // MFTB
    CEFBS_None, // MFTB8
    CEFBS_None, // MFUDSCR
    CEFBS_None, // MFVRD
    CEFBS_None, // MFVRSAVE
    CEFBS_None, // MFVRSAVEv
    CEFBS_None, // MFVRWZ
    CEFBS_None, // MFVSCR
    CEFBS_None, // MFVSRD
    CEFBS_None, // MFVSRLD
    CEFBS_None, // MFVSRWZ
    CEFBS_None, // MODSD
    CEFBS_None, // MODSW
    CEFBS_None, // MODUD
    CEFBS_None, // MODUW
    CEFBS_None, // MSGSNDP
    CEFBS_None, // MSGSNDP8
    CEFBS_None, // MSGSYNC
    CEFBS_None, // MSYNC
    CEFBS_None, // MTCRF
    CEFBS_None, // MTCRF8
    CEFBS_None, // MTCTR
    CEFBS_None, // MTCTR8
    CEFBS_None, // MTCTR8loop
    CEFBS_None, // MTCTRloop
    CEFBS_None, // MTDCR
    CEFBS_None, // MTFSB0
    CEFBS_None, // MTFSB1
    CEFBS_None, // MTFSF
    CEFBS_None, // MTFSFI
    CEFBS_None, // MTFSFI_rec
    CEFBS_None, // MTFSFIb
    CEFBS_None, // MTFSF_rec
    CEFBS_None, // MTFSFb
    CEFBS_None, // MTLPL
    CEFBS_None, // MTLPL8
    CEFBS_None, // MTLR
    CEFBS_None, // MTLR8
    CEFBS_None, // MTMSR
    CEFBS_None, // MTMSRD
    CEFBS_None, // MTOCRF
    CEFBS_None, // MTOCRF8
    CEFBS_None, // MTPMR
    CEFBS_None, // MTSPR
    CEFBS_None, // MTSPR8
    CEFBS_None, // MTSR
    CEFBS_None, // MTSRIN
    CEFBS_None, // MTUDSCR
    CEFBS_None, // MTVRD
    CEFBS_None, // MTVRSAVE
    CEFBS_None, // MTVRSAVEv
    CEFBS_None, // MTVRWA
    CEFBS_None, // MTVRWZ
    CEFBS_None, // MTVSCR
    CEFBS_None, // MTVSRBM
    CEFBS_None, // MTVSRBMI
    CEFBS_None, // MTVSRD
    CEFBS_None, // MTVSRDD
    CEFBS_None, // MTVSRDM
    CEFBS_None, // MTVSRHM
    CEFBS_None, // MTVSRQM
    CEFBS_None, // MTVSRWA
    CEFBS_None, // MTVSRWM
    CEFBS_None, // MTVSRWS
    CEFBS_None, // MTVSRWZ
    CEFBS_None, // MULHD
    CEFBS_None, // MULHDU
    CEFBS_None, // MULHDU_rec
    CEFBS_None, // MULHD_rec
    CEFBS_None, // MULHW
    CEFBS_None, // MULHWU
    CEFBS_None, // MULHWU_rec
    CEFBS_None, // MULHW_rec
    CEFBS_None, // MULLD
    CEFBS_None, // MULLDO
    CEFBS_None, // MULLDO_rec
    CEFBS_None, // MULLD_rec
    CEFBS_None, // MULLI
    CEFBS_None, // MULLI8
    CEFBS_None, // MULLW
    CEFBS_None, // MULLWO
    CEFBS_None, // MULLWO_rec
    CEFBS_None, // MULLW_rec
    CEFBS_None, // MoveGOTtoLR
    CEFBS_None, // MovePCtoLR
    CEFBS_None, // MovePCtoLR8
    CEFBS_None, // NAND
    CEFBS_None, // NAND8
    CEFBS_None, // NAND8_rec
    CEFBS_None, // NAND_rec
    CEFBS_None, // NAP
    CEFBS_None, // NEG
    CEFBS_None, // NEG8
    CEFBS_None, // NEG8O
    CEFBS_None, // NEG8O_rec
    CEFBS_None, // NEG8_rec
    CEFBS_None, // NEGO
    CEFBS_None, // NEGO_rec
    CEFBS_None, // NEG_rec
    CEFBS_None, // NOP
    CEFBS_None, // NOP_GT_PWR6
    CEFBS_None, // NOP_GT_PWR7
    CEFBS_None, // NOR
    CEFBS_None, // NOR8
    CEFBS_None, // NOR8_rec
    CEFBS_None, // NOR_rec
    CEFBS_None, // OR
    CEFBS_None, // OR8
    CEFBS_None, // OR8_rec
    CEFBS_None, // ORC
    CEFBS_None, // ORC8
    CEFBS_None, // ORC8_rec
    CEFBS_None, // ORC_rec
    CEFBS_None, // ORI
    CEFBS_None, // ORI8
    CEFBS_None, // ORIS
    CEFBS_None, // ORIS8
    CEFBS_None, // OR_rec
    CEFBS_None, // PADDI
    CEFBS_None, // PADDI8
    CEFBS_None, // PADDI8pc
    CEFBS_None, // PADDIS
    CEFBS_None, // PADDIS8
    CEFBS_None, // PADDIS8pc
    CEFBS_None, // PADDISpc
    CEFBS_None, // PADDIdtprel
    CEFBS_None, // PADDIpc
    CEFBS_None, // PDEPD
    CEFBS_None, // PEXTD
    CEFBS_None, // PLA
    CEFBS_None, // PLA8
    CEFBS_None, // PLA8pc
    CEFBS_None, // PLApc
    CEFBS_None, // PLBZ
    CEFBS_None, // PLBZ8
    CEFBS_None, // PLBZ8nopc
    CEFBS_None, // PLBZ8onlypc
    CEFBS_None, // PLBZ8pc
    CEFBS_None, // PLBZnopc
    CEFBS_None, // PLBZonlypc
    CEFBS_None, // PLBZpc
    CEFBS_None, // PLD
    CEFBS_None, // PLDnopc
    CEFBS_None, // PLDonlypc
    CEFBS_None, // PLDpc
    CEFBS_None, // PLFD
    CEFBS_None, // PLFDnopc
    CEFBS_None, // PLFDonlypc
    CEFBS_None, // PLFDpc
    CEFBS_None, // PLFS
    CEFBS_None, // PLFSnopc
    CEFBS_None, // PLFSonlypc
    CEFBS_None, // PLFSpc
    CEFBS_None, // PLHA
    CEFBS_None, // PLHA8
    CEFBS_None, // PLHA8nopc
    CEFBS_None, // PLHA8onlypc
    CEFBS_None, // PLHA8pc
    CEFBS_None, // PLHAnopc
    CEFBS_None, // PLHAonlypc
    CEFBS_None, // PLHApc
    CEFBS_None, // PLHZ
    CEFBS_None, // PLHZ8
    CEFBS_None, // PLHZ8nopc
    CEFBS_None, // PLHZ8onlypc
    CEFBS_None, // PLHZ8pc
    CEFBS_None, // PLHZnopc
    CEFBS_None, // PLHZonlypc
    CEFBS_None, // PLHZpc
    CEFBS_None, // PLI
    CEFBS_None, // PLI8
    CEFBS_None, // PLWA
    CEFBS_None, // PLWA8
    CEFBS_None, // PLWA8nopc
    CEFBS_None, // PLWA8onlypc
    CEFBS_None, // PLWA8pc
    CEFBS_None, // PLWAnopc
    CEFBS_None, // PLWAonlypc
    CEFBS_None, // PLWApc
    CEFBS_None, // PLWZ
    CEFBS_None, // PLWZ8
    CEFBS_None, // PLWZ8nopc
    CEFBS_None, // PLWZ8onlypc
    CEFBS_None, // PLWZ8pc
    CEFBS_None, // PLWZnopc
    CEFBS_None, // PLWZonlypc
    CEFBS_None, // PLWZpc
    CEFBS_None, // PLXSD
    CEFBS_None, // PLXSDnopc
    CEFBS_None, // PLXSDonlypc
    CEFBS_None, // PLXSDpc
    CEFBS_None, // PLXSSP
    CEFBS_None, // PLXSSPnopc
    CEFBS_None, // PLXSSPonlypc
    CEFBS_None, // PLXSSPpc
    CEFBS_None, // PLXV
    CEFBS_None, // PLXVP
    CEFBS_None, // PLXVPnopc
    CEFBS_None, // PLXVPonlypc
    CEFBS_None, // PLXVPpc
    CEFBS_None, // PLXVnopc
    CEFBS_None, // PLXVonlypc
    CEFBS_None, // PLXVpc
    CEFBS_None, // PMDMXVBF16GERX2
    CEFBS_None, // PMDMXVBF16GERX2NN
    CEFBS_None, // PMDMXVBF16GERX2NP
    CEFBS_None, // PMDMXVBF16GERX2PN
    CEFBS_None, // PMDMXVBF16GERX2PP
    CEFBS_None, // PMDMXVF16GERX2
    CEFBS_None, // PMDMXVF16GERX2NN
    CEFBS_None, // PMDMXVF16GERX2NP
    CEFBS_None, // PMDMXVF16GERX2PN
    CEFBS_None, // PMDMXVF16GERX2PP
    CEFBS_None, // PMDMXVI8GERX4
    CEFBS_None, // PMDMXVI8GERX4PP
    CEFBS_None, // PMDMXVI8GERX4SPP
    CEFBS_None, // PMXVBF16GER2
    CEFBS_None, // PMXVBF16GER2NN
    CEFBS_None, // PMXVBF16GER2NP
    CEFBS_None, // PMXVBF16GER2PN
    CEFBS_None, // PMXVBF16GER2PP
    CEFBS_None, // PMXVBF16GER2W
    CEFBS_None, // PMXVBF16GER2WNN
    CEFBS_None, // PMXVBF16GER2WNP
    CEFBS_None, // PMXVBF16GER2WPN
    CEFBS_None, // PMXVBF16GER2WPP
    CEFBS_None, // PMXVF16GER2
    CEFBS_None, // PMXVF16GER2NN
    CEFBS_None, // PMXVF16GER2NP
    CEFBS_None, // PMXVF16GER2PN
    CEFBS_None, // PMXVF16GER2PP
    CEFBS_None, // PMXVF16GER2W
    CEFBS_None, // PMXVF16GER2WNN
    CEFBS_None, // PMXVF16GER2WNP
    CEFBS_None, // PMXVF16GER2WPN
    CEFBS_None, // PMXVF16GER2WPP
    CEFBS_None, // PMXVF32GER
    CEFBS_None, // PMXVF32GERNN
    CEFBS_None, // PMXVF32GERNP
    CEFBS_None, // PMXVF32GERPN
    CEFBS_None, // PMXVF32GERPP
    CEFBS_None, // PMXVF32GERW
    CEFBS_None, // PMXVF32GERWNN
    CEFBS_None, // PMXVF32GERWNP
    CEFBS_None, // PMXVF32GERWPN
    CEFBS_None, // PMXVF32GERWPP
    CEFBS_None, // PMXVF64GER
    CEFBS_None, // PMXVF64GERNN
    CEFBS_None, // PMXVF64GERNP
    CEFBS_None, // PMXVF64GERPN
    CEFBS_None, // PMXVF64GERPP
    CEFBS_None, // PMXVF64GERW
    CEFBS_None, // PMXVF64GERWNN
    CEFBS_None, // PMXVF64GERWNP
    CEFBS_None, // PMXVF64GERWPN
    CEFBS_None, // PMXVF64GERWPP
    CEFBS_None, // PMXVI16GER2
    CEFBS_None, // PMXVI16GER2PP
    CEFBS_None, // PMXVI16GER2S
    CEFBS_None, // PMXVI16GER2SPP
    CEFBS_None, // PMXVI16GER2SW
    CEFBS_None, // PMXVI16GER2SWPP
    CEFBS_None, // PMXVI16GER2W
    CEFBS_None, // PMXVI16GER2WPP
    CEFBS_None, // PMXVI4GER8
    CEFBS_None, // PMXVI4GER8PP
    CEFBS_None, // PMXVI4GER8W
    CEFBS_None, // PMXVI4GER8WPP
    CEFBS_None, // PMXVI8GER4
    CEFBS_None, // PMXVI8GER4PP
    CEFBS_None, // PMXVI8GER4SPP
    CEFBS_None, // PMXVI8GER4W
    CEFBS_None, // PMXVI8GER4WPP
    CEFBS_None, // PMXVI8GER4WSPP
    CEFBS_None, // POPCNTB
    CEFBS_None, // POPCNTB8
    CEFBS_None, // POPCNTD
    CEFBS_None, // POPCNTW
    CEFBS_None, // PPC32GOT
    CEFBS_None, // PPC32PICGOT
    CEFBS_None, // PREPARE_PROBED_ALLOCA_32
    CEFBS_None, // PREPARE_PROBED_ALLOCA_64
    CEFBS_None, // PREPARE_PROBED_ALLOCA_NEGSIZE_SAME_REG_32
    CEFBS_None, // PREPARE_PROBED_ALLOCA_NEGSIZE_SAME_REG_64
    CEFBS_None, // PROBED_ALLOCA_32
    CEFBS_None, // PROBED_ALLOCA_64
    CEFBS_None, // PROBED_STACKALLOC_32
    CEFBS_None, // PROBED_STACKALLOC_64
    CEFBS_None, // PSTB
    CEFBS_None, // PSTB8
    CEFBS_None, // PSTB8nopc
    CEFBS_None, // PSTB8onlypc
    CEFBS_None, // PSTB8pc
    CEFBS_None, // PSTBnopc
    CEFBS_None, // PSTBonlypc
    CEFBS_None, // PSTBpc
    CEFBS_None, // PSTD
    CEFBS_None, // PSTDnopc
    CEFBS_None, // PSTDonlypc
    CEFBS_None, // PSTDpc
    CEFBS_None, // PSTFD
    CEFBS_None, // PSTFDnopc
    CEFBS_None, // PSTFDonlypc
    CEFBS_None, // PSTFDpc
    CEFBS_None, // PSTFS
    CEFBS_None, // PSTFSnopc
    CEFBS_None, // PSTFSonlypc
    CEFBS_None, // PSTFSpc
    CEFBS_None, // PSTH
    CEFBS_None, // PSTH8
    CEFBS_None, // PSTH8nopc
    CEFBS_None, // PSTH8onlypc
    CEFBS_None, // PSTH8pc
    CEFBS_None, // PSTHnopc
    CEFBS_None, // PSTHonlypc
    CEFBS_None, // PSTHpc
    CEFBS_None, // PSTW
    CEFBS_None, // PSTW8
    CEFBS_None, // PSTW8nopc
    CEFBS_None, // PSTW8onlypc
    CEFBS_None, // PSTW8pc
    CEFBS_None, // PSTWnopc
    CEFBS_None, // PSTWonlypc
    CEFBS_None, // PSTWpc
    CEFBS_None, // PSTXSD
    CEFBS_None, // PSTXSDnopc
    CEFBS_None, // PSTXSDonlypc
    CEFBS_None, // PSTXSDpc
    CEFBS_None, // PSTXSSP
    CEFBS_None, // PSTXSSPnopc
    CEFBS_None, // PSTXSSPonlypc
    CEFBS_None, // PSTXSSPpc
    CEFBS_None, // PSTXV
    CEFBS_None, // PSTXVP
    CEFBS_None, // PSTXVPnopc
    CEFBS_None, // PSTXVPonlypc
    CEFBS_None, // PSTXVPpc
    CEFBS_None, // PSTXVnopc
    CEFBS_None, // PSTXVonlypc
    CEFBS_None, // PSTXVpc
    CEFBS_None, // PTESYNCIO
    CEFBS_None, // PseudoEIEIO
    CEFBS_None, // RESTORE_ACC
    CEFBS_None, // RESTORE_CR
    CEFBS_None, // RESTORE_CRBIT
    CEFBS_None, // RESTORE_DMR
    CEFBS_None, // RESTORE_DMRP
    CEFBS_None, // RESTORE_QUADWORD
    CEFBS_None, // RESTORE_UACC
    CEFBS_None, // RESTORE_WACC
    CEFBS_None, // RFCI
    CEFBS_None, // RFDI
    CEFBS_None, // RFEBB
    CEFBS_None, // RFI
    CEFBS_None, // RFID
    CEFBS_None, // RFMCI
    CEFBS_None, // RLDCL
    CEFBS_None, // RLDCL_rec
    CEFBS_None, // RLDCR
    CEFBS_None, // RLDCR_rec
    CEFBS_None, // RLDIC
    CEFBS_None, // RLDICL
    CEFBS_None, // RLDICL_32
    CEFBS_None, // RLDICL_32_64
    CEFBS_None, // RLDICL_32_rec
    CEFBS_None, // RLDICL_rec
    CEFBS_None, // RLDICR
    CEFBS_None, // RLDICR_32
    CEFBS_None, // RLDICR_rec
    CEFBS_None, // RLDIC_rec
    CEFBS_None, // RLDIMI
    CEFBS_None, // RLDIMI_rec
    CEFBS_None, // RLWIMI
    CEFBS_None, // RLWIMI8
    CEFBS_None, // RLWIMI8_rec
    CEFBS_None, // RLWIMI_rec
    CEFBS_None, // RLWINM
    CEFBS_None, // RLWINM8
    CEFBS_None, // RLWINM8_rec
    CEFBS_None, // RLWINM_rec
    CEFBS_None, // RLWNM
    CEFBS_None, // RLWNM8
    CEFBS_None, // RLWNM8_rec
    CEFBS_None, // RLWNM_rec
    CEFBS_None, // ReadTB
    CEFBS_None, // SC
    CEFBS_None, // SCV
    CEFBS_None, // SELECT_CC_F16
    CEFBS_None, // SELECT_CC_F4
    CEFBS_None, // SELECT_CC_F8
    CEFBS_None, // SELECT_CC_I4
    CEFBS_None, // SELECT_CC_I8
    CEFBS_None, // SELECT_CC_SPE
    CEFBS_None, // SELECT_CC_SPE4
    CEFBS_None, // SELECT_CC_VRRC
    CEFBS_None, // SELECT_CC_VSFRC
    CEFBS_None, // SELECT_CC_VSRC
    CEFBS_None, // SELECT_CC_VSSRC
    CEFBS_None, // SELECT_F16
    CEFBS_None, // SELECT_F4
    CEFBS_None, // SELECT_F8
    CEFBS_None, // SELECT_I4
    CEFBS_None, // SELECT_I8
    CEFBS_None, // SELECT_SPE
    CEFBS_None, // SELECT_SPE4
    CEFBS_None, // SELECT_VRRC
    CEFBS_None, // SELECT_VSFRC
    CEFBS_None, // SELECT_VSRC
    CEFBS_None, // SELECT_VSSRC
    CEFBS_None, // SETB
    CEFBS_None, // SETB8
    CEFBS_None, // SETBC
    CEFBS_None, // SETBC8
    CEFBS_None, // SETBCR
    CEFBS_None, // SETBCR8
    CEFBS_None, // SETFLM
    CEFBS_None, // SETNBC
    CEFBS_None, // SETNBC8
    CEFBS_None, // SETNBCR
    CEFBS_None, // SETNBCR8
    CEFBS_None, // SETRND
    CEFBS_None, // SETRNDi
    CEFBS_None, // SLBFEE_rec
    CEFBS_None, // SLBIA
    CEFBS_None, // SLBIE
    CEFBS_None, // SLBIEG
    CEFBS_None, // SLBMFEE
    CEFBS_None, // SLBMFEV
    CEFBS_None, // SLBMTE
    CEFBS_None, // SLBSYNC
    CEFBS_None, // SLD
    CEFBS_None, // SLD_rec
    CEFBS_None, // SLW
    CEFBS_None, // SLW8
    CEFBS_None, // SLW8_rec
    CEFBS_None, // SLW_rec
    CEFBS_None, // SPELWZ
    CEFBS_None, // SPELWZX
    CEFBS_None, // SPESTW
    CEFBS_None, // SPESTWX
    CEFBS_None, // SPILL_ACC
    CEFBS_None, // SPILL_CR
    CEFBS_None, // SPILL_CRBIT
    CEFBS_None, // SPILL_DMR
    CEFBS_None, // SPILL_DMRP
    CEFBS_None, // SPILL_QUADWORD
    CEFBS_None, // SPILL_UACC
    CEFBS_None, // SPILL_WACC
    CEFBS_None, // SPLIT_QUADWORD
    CEFBS_None, // SRAD
    CEFBS_None, // SRADI
    CEFBS_None, // SRADI_32
    CEFBS_None, // SRADI_rec
    CEFBS_None, // SRAD_rec
    CEFBS_None, // SRAW
    CEFBS_None, // SRAW8
    CEFBS_None, // SRAW8_rec
    CEFBS_None, // SRAWI
    CEFBS_None, // SRAWI8
    CEFBS_None, // SRAWI8_rec
    CEFBS_None, // SRAWI_rec
    CEFBS_None, // SRAW_rec
    CEFBS_None, // SRD
    CEFBS_None, // SRD_rec
    CEFBS_None, // SRW
    CEFBS_None, // SRW8
    CEFBS_None, // SRW8_rec
    CEFBS_None, // SRW_rec
    CEFBS_None, // STB
    CEFBS_None, // STB8
    CEFBS_None, // STBCIX
    CEFBS_None, // STBCX
    CEFBS_None, // STBEPX
    CEFBS_None, // STBU
    CEFBS_None, // STBU8
    CEFBS_None, // STBUX
    CEFBS_None, // STBUX8
    CEFBS_None, // STBX
    CEFBS_None, // STBX8
    CEFBS_None, // STBXTLS
    CEFBS_None, // STBXTLS_
    CEFBS_None, // STBXTLS_32
    CEFBS_None, // STD
    CEFBS_None, // STDAT
    CEFBS_None, // STDBRX
    CEFBS_None, // STDCIX
    CEFBS_None, // STDCX
    CEFBS_None, // STDU
    CEFBS_None, // STDUX
    CEFBS_None, // STDX
    CEFBS_None, // STDXTLS
    CEFBS_None, // STDXTLS_
    CEFBS_None, // STFD
    CEFBS_None, // STFDEPX
    CEFBS_None, // STFDU
    CEFBS_None, // STFDUX
    CEFBS_None, // STFDX
    CEFBS_None, // STFDXTLS
    CEFBS_None, // STFDXTLS_
    CEFBS_None, // STFIWX
    CEFBS_None, // STFS
    CEFBS_None, // STFSU
    CEFBS_None, // STFSUX
    CEFBS_None, // STFSX
    CEFBS_None, // STFSXTLS
    CEFBS_None, // STFSXTLS_
    CEFBS_None, // STH
    CEFBS_None, // STH8
    CEFBS_None, // STHBRX
    CEFBS_None, // STHCIX
    CEFBS_None, // STHCX
    CEFBS_None, // STHEPX
    CEFBS_None, // STHU
    CEFBS_None, // STHU8
    CEFBS_None, // STHUX
    CEFBS_None, // STHUX8
    CEFBS_None, // STHX
    CEFBS_None, // STHX8
    CEFBS_None, // STHXTLS
    CEFBS_None, // STHXTLS_
    CEFBS_None, // STHXTLS_32
    CEFBS_None, // STMW
    CEFBS_None, // STOP
    CEFBS_None, // STQ
    CEFBS_None, // STQCX
    CEFBS_None, // STQX_PSEUDO
    CEFBS_None, // STSWI
    CEFBS_None, // STVEBX
    CEFBS_None, // STVEHX
    CEFBS_None, // STVEWX
    CEFBS_None, // STVX
    CEFBS_None, // STVXL
    CEFBS_None, // STW
    CEFBS_None, // STW8
    CEFBS_None, // STWAT
    CEFBS_None, // STWBRX
    CEFBS_None, // STWCIX
    CEFBS_None, // STWCX
    CEFBS_None, // STWEPX
    CEFBS_None, // STWU
    CEFBS_None, // STWU8
    CEFBS_None, // STWUX
    CEFBS_None, // STWUX8
    CEFBS_None, // STWX
    CEFBS_None, // STWX8
    CEFBS_None, // STWXTLS
    CEFBS_None, // STWXTLS_
    CEFBS_None, // STWXTLS_32
    CEFBS_None, // STXSD
    CEFBS_None, // STXSDX
    CEFBS_None, // STXSIBX
    CEFBS_None, // STXSIBXv
    CEFBS_None, // STXSIHX
    CEFBS_None, // STXSIHXv
    CEFBS_None, // STXSIWX
    CEFBS_None, // STXSSP
    CEFBS_None, // STXSSPX
    CEFBS_None, // STXV
    CEFBS_None, // STXVB16X
    CEFBS_None, // STXVD2X
    CEFBS_None, // STXVH8X
    CEFBS_None, // STXVL
    CEFBS_None, // STXVLL
    CEFBS_None, // STXVP
    CEFBS_None, // STXVPB32X
    CEFBS_None, // STXVPRL
    CEFBS_None, // STXVPRLL
    CEFBS_None, // STXVPX
    CEFBS_None, // STXVRBX
    CEFBS_None, // STXVRDX
    CEFBS_None, // STXVRHX
    CEFBS_None, // STXVRL
    CEFBS_None, // STXVRLL
    CEFBS_None, // STXVRWX
    CEFBS_None, // STXVW4X
    CEFBS_None, // STXVX
    CEFBS_None, // SUBF
    CEFBS_None, // SUBF8
    CEFBS_None, // SUBF8O
    CEFBS_None, // SUBF8O_rec
    CEFBS_None, // SUBF8_rec
    CEFBS_None, // SUBFC
    CEFBS_None, // SUBFC8
    CEFBS_None, // SUBFC8O
    CEFBS_None, // SUBFC8O_rec
    CEFBS_None, // SUBFC8_rec
    CEFBS_None, // SUBFCO
    CEFBS_None, // SUBFCO_rec
    CEFBS_None, // SUBFC_rec
    CEFBS_None, // SUBFE
    CEFBS_None, // SUBFE8
    CEFBS_None, // SUBFE8O
    CEFBS_None, // SUBFE8O_rec
    CEFBS_None, // SUBFE8_rec
    CEFBS_None, // SUBFEO
    CEFBS_None, // SUBFEO_rec
    CEFBS_None, // SUBFE_rec
    CEFBS_None, // SUBFIC
    CEFBS_None, // SUBFIC8
    CEFBS_None, // SUBFME
    CEFBS_None, // SUBFME8
    CEFBS_None, // SUBFME8O
    CEFBS_None, // SUBFME8O_rec
    CEFBS_None, // SUBFME8_rec
    CEFBS_None, // SUBFMEO
    CEFBS_None, // SUBFMEO_rec
    CEFBS_None, // SUBFME_rec
    CEFBS_None, // SUBFO
    CEFBS_None, // SUBFO_rec
    CEFBS_None, // SUBFUS
    CEFBS_None, // SUBFUS_rec
    CEFBS_None, // SUBFZE
    CEFBS_None, // SUBFZE8
    CEFBS_None, // SUBFZE8O
    CEFBS_None, // SUBFZE8O_rec
    CEFBS_None, // SUBFZE8_rec
    CEFBS_None, // SUBFZEO
    CEFBS_None, // SUBFZEO_rec
    CEFBS_None, // SUBFZE_rec
    CEFBS_None, // SUBF_rec
    CEFBS_None, // SYNC
    CEFBS_None, // SYNCP10
    CEFBS_None, // TABORT
    CEFBS_None, // TABORTDC
    CEFBS_None, // TABORTDCI
    CEFBS_None, // TABORTWC
    CEFBS_None, // TABORTWCI
    CEFBS_None, // TAILB
    CEFBS_None, // TAILB8
    CEFBS_None, // TAILBA
    CEFBS_None, // TAILBA8
    CEFBS_None, // TAILBCTR
    CEFBS_None, // TAILBCTR8
    CEFBS_None, // TBEGIN
    CEFBS_None, // TBEGIN_RET
    CEFBS_None, // TCHECK
    CEFBS_None, // TCHECK_RET
    CEFBS_None, // TCRETURNai
    CEFBS_None, // TCRETURNai8
    CEFBS_None, // TCRETURNdi
    CEFBS_None, // TCRETURNdi8
    CEFBS_None, // TCRETURNri
    CEFBS_None, // TCRETURNri8
    CEFBS_None, // TD
    CEFBS_None, // TDI
    CEFBS_None, // TEND
    CEFBS_None, // TLBIA
    CEFBS_None, // TLBIE
    CEFBS_None, // TLBIE8P9
    CEFBS_None, // TLBIEIO
    CEFBS_None, // TLBIEL
    CEFBS_None, // TLBIEP
    CEFBS_None, // TLBIEP8
    CEFBS_None, // TLBIEP9
    CEFBS_None, // TLBILX
    CEFBS_None, // TLBIVAX
    CEFBS_None, // TLBLD
    CEFBS_None, // TLBLI
    CEFBS_None, // TLBRE
    CEFBS_None, // TLBRE2
    CEFBS_None, // TLBSX
    CEFBS_None, // TLBSX2
    CEFBS_None, // TLBSX2D
    CEFBS_None, // TLBSYNC
    CEFBS_None, // TLBSYNCIO
    CEFBS_None, // TLBWE
    CEFBS_None, // TLBWE2
    CEFBS_None, // TLSGDAIX
    CEFBS_None, // TLSGDAIX8
    CEFBS_None, // TLSLDAIX
    CEFBS_None, // TLSLDAIX8
    CEFBS_None, // TRAP
    CEFBS_None, // TRECHKPT
    CEFBS_None, // TRECLAIM
    CEFBS_None, // TSR
    CEFBS_None, // TW
    CEFBS_None, // TWI
    CEFBS_None, // UNENCODED_NOP
    CEFBS_None, // UpdateGBR
    CEFBS_None, // VABSDUB
    CEFBS_None, // VABSDUH
    CEFBS_None, // VABSDUW
    CEFBS_None, // VADDCUQ
    CEFBS_None, // VADDCUW
    CEFBS_None, // VADDECUQ
    CEFBS_None, // VADDEUQM
    CEFBS_None, // VADDFP
    CEFBS_None, // VADDSBS
    CEFBS_None, // VADDSHS
    CEFBS_None, // VADDSWS
    CEFBS_None, // VADDUBM
    CEFBS_None, // VADDUBS
    CEFBS_None, // VADDUDM
    CEFBS_None, // VADDUHM
    CEFBS_None, // VADDUHS
    CEFBS_None, // VADDUQM
    CEFBS_None, // VADDUWM
    CEFBS_None, // VADDUWS
    CEFBS_None, // VAND
    CEFBS_None, // VANDC
    CEFBS_None, // VAVGSB
    CEFBS_None, // VAVGSH
    CEFBS_None, // VAVGSW
    CEFBS_None, // VAVGUB
    CEFBS_None, // VAVGUH
    CEFBS_None, // VAVGUW
    CEFBS_None, // VBPERMD
    CEFBS_None, // VBPERMQ
    CEFBS_None, // VCFSX
    CEFBS_None, // VCFSX_0
    CEFBS_None, // VCFUGED
    CEFBS_None, // VCFUX
    CEFBS_None, // VCFUX_0
    CEFBS_None, // VCIPHER
    CEFBS_None, // VCIPHERLAST
    CEFBS_None, // VCLRLB
    CEFBS_None, // VCLRRB
    CEFBS_None, // VCLZB
    CEFBS_None, // VCLZD
    CEFBS_None, // VCLZDM
    CEFBS_None, // VCLZH
    CEFBS_None, // VCLZLSBB
    CEFBS_None, // VCLZW
    CEFBS_None, // VCMPBFP
    CEFBS_None, // VCMPBFP_rec
    CEFBS_None, // VCMPEQFP
    CEFBS_None, // VCMPEQFP_rec
    CEFBS_None, // VCMPEQUB
    CEFBS_None, // VCMPEQUB_rec
    CEFBS_None, // VCMPEQUD
    CEFBS_None, // VCMPEQUD_rec
    CEFBS_None, // VCMPEQUH
    CEFBS_None, // VCMPEQUH_rec
    CEFBS_None, // VCMPEQUQ
    CEFBS_None, // VCMPEQUQ_rec
    CEFBS_None, // VCMPEQUW
    CEFBS_None, // VCMPEQUW_rec
    CEFBS_None, // VCMPGEFP
    CEFBS_None, // VCMPGEFP_rec
    CEFBS_None, // VCMPGTFP
    CEFBS_None, // VCMPGTFP_rec
    CEFBS_None, // VCMPGTSB
    CEFBS_None, // VCMPGTSB_rec
    CEFBS_None, // VCMPGTSD
    CEFBS_None, // VCMPGTSD_rec
    CEFBS_None, // VCMPGTSH
    CEFBS_None, // VCMPGTSH_rec
    CEFBS_None, // VCMPGTSQ
    CEFBS_None, // VCMPGTSQ_rec
    CEFBS_None, // VCMPGTSW
    CEFBS_None, // VCMPGTSW_rec
    CEFBS_None, // VCMPGTUB
    CEFBS_None, // VCMPGTUB_rec
    CEFBS_None, // VCMPGTUD
    CEFBS_None, // VCMPGTUD_rec
    CEFBS_None, // VCMPGTUH
    CEFBS_None, // VCMPGTUH_rec
    CEFBS_None, // VCMPGTUQ
    CEFBS_None, // VCMPGTUQ_rec
    CEFBS_None, // VCMPGTUW
    CEFBS_None, // VCMPGTUW_rec
    CEFBS_None, // VCMPNEB
    CEFBS_None, // VCMPNEB_rec
    CEFBS_None, // VCMPNEH
    CEFBS_None, // VCMPNEH_rec
    CEFBS_None, // VCMPNEW
    CEFBS_None, // VCMPNEW_rec
    CEFBS_None, // VCMPNEZB
    CEFBS_None, // VCMPNEZB_rec
    CEFBS_None, // VCMPNEZH
    CEFBS_None, // VCMPNEZH_rec
    CEFBS_None, // VCMPNEZW
    CEFBS_None, // VCMPNEZW_rec
    CEFBS_None, // VCMPSQ
    CEFBS_None, // VCMPUQ
    CEFBS_None, // VCNTMBB
    CEFBS_None, // VCNTMBD
    CEFBS_None, // VCNTMBH
    CEFBS_None, // VCNTMBW
    CEFBS_None, // VCTSXS
    CEFBS_None, // VCTSXS_0
    CEFBS_None, // VCTUXS
    CEFBS_None, // VCTUXS_0
    CEFBS_None, // VCTZB
    CEFBS_None, // VCTZD
    CEFBS_None, // VCTZDM
    CEFBS_None, // VCTZH
    CEFBS_None, // VCTZLSBB
    CEFBS_None, // VCTZW
    CEFBS_None, // VDIVESD
    CEFBS_None, // VDIVESQ
    CEFBS_None, // VDIVESW
    CEFBS_None, // VDIVEUD
    CEFBS_None, // VDIVEUQ
    CEFBS_None, // VDIVEUW
    CEFBS_None, // VDIVSD
    CEFBS_None, // VDIVSQ
    CEFBS_None, // VDIVSW
    CEFBS_None, // VDIVUD
    CEFBS_None, // VDIVUQ
    CEFBS_None, // VDIVUW
    CEFBS_None, // VEQV
    CEFBS_None, // VEXPANDBM
    CEFBS_None, // VEXPANDDM
    CEFBS_None, // VEXPANDHM
    CEFBS_None, // VEXPANDQM
    CEFBS_None, // VEXPANDWM
    CEFBS_None, // VEXPTEFP
    CEFBS_None, // VEXTDDVLX
    CEFBS_None, // VEXTDDVRX
    CEFBS_None, // VEXTDUBVLX
    CEFBS_None, // VEXTDUBVRX
    CEFBS_None, // VEXTDUHVLX
    CEFBS_None, // VEXTDUHVRX
    CEFBS_None, // VEXTDUWVLX
    CEFBS_None, // VEXTDUWVRX
    CEFBS_None, // VEXTRACTBM
    CEFBS_None, // VEXTRACTD
    CEFBS_None, // VEXTRACTDM
    CEFBS_None, // VEXTRACTHM
    CEFBS_None, // VEXTRACTQM
    CEFBS_None, // VEXTRACTUB
    CEFBS_None, // VEXTRACTUH
    CEFBS_None, // VEXTRACTUW
    CEFBS_None, // VEXTRACTWM
    CEFBS_None, // VEXTSB2D
    CEFBS_None, // VEXTSB2Ds
    CEFBS_None, // VEXTSB2W
    CEFBS_None, // VEXTSB2Ws
    CEFBS_None, // VEXTSD2Q
    CEFBS_None, // VEXTSH2D
    CEFBS_None, // VEXTSH2Ds
    CEFBS_None, // VEXTSH2W
    CEFBS_None, // VEXTSH2Ws
    CEFBS_None, // VEXTSW2D
    CEFBS_None, // VEXTSW2Ds
    CEFBS_None, // VEXTUBLX
    CEFBS_None, // VEXTUBRX
    CEFBS_None, // VEXTUHLX
    CEFBS_None, // VEXTUHRX
    CEFBS_None, // VEXTUWLX
    CEFBS_None, // VEXTUWRX
    CEFBS_None, // VGBBD
    CEFBS_None, // VGNB
    CEFBS_None, // VINSBLX
    CEFBS_None, // VINSBRX
    CEFBS_None, // VINSBVLX
    CEFBS_None, // VINSBVRX
    CEFBS_None, // VINSD
    CEFBS_None, // VINSDLX
    CEFBS_None, // VINSDRX
    CEFBS_None, // VINSERTB
    CEFBS_None, // VINSERTD
    CEFBS_None, // VINSERTH
    CEFBS_None, // VINSERTW
    CEFBS_None, // VINSHLX
    CEFBS_None, // VINSHRX
    CEFBS_None, // VINSHVLX
    CEFBS_None, // VINSHVRX
    CEFBS_None, // VINSW
    CEFBS_None, // VINSWLX
    CEFBS_None, // VINSWRX
    CEFBS_None, // VINSWVLX
    CEFBS_None, // VINSWVRX
    CEFBS_None, // VLOGEFP
    CEFBS_None, // VMADDFP
    CEFBS_None, // VMAXFP
    CEFBS_None, // VMAXSB
    CEFBS_None, // VMAXSD
    CEFBS_None, // VMAXSH
    CEFBS_None, // VMAXSW
    CEFBS_None, // VMAXUB
    CEFBS_None, // VMAXUD
    CEFBS_None, // VMAXUH
    CEFBS_None, // VMAXUW
    CEFBS_None, // VMHADDSHS
    CEFBS_None, // VMHRADDSHS
    CEFBS_None, // VMINFP
    CEFBS_None, // VMINSB
    CEFBS_None, // VMINSD
    CEFBS_None, // VMINSH
    CEFBS_None, // VMINSW
    CEFBS_None, // VMINUB
    CEFBS_None, // VMINUD
    CEFBS_None, // VMINUH
    CEFBS_None, // VMINUW
    CEFBS_None, // VMLADDUHM
    CEFBS_None, // VMODSD
    CEFBS_None, // VMODSQ
    CEFBS_None, // VMODSW
    CEFBS_None, // VMODUD
    CEFBS_None, // VMODUQ
    CEFBS_None, // VMODUW
    CEFBS_None, // VMRGEW
    CEFBS_None, // VMRGHB
    CEFBS_None, // VMRGHH
    CEFBS_None, // VMRGHW
    CEFBS_None, // VMRGLB
    CEFBS_None, // VMRGLH
    CEFBS_None, // VMRGLW
    CEFBS_None, // VMRGOW
    CEFBS_None, // VMSUMCUD
    CEFBS_None, // VMSUMMBM
    CEFBS_None, // VMSUMSHM
    CEFBS_None, // VMSUMSHS
    CEFBS_None, // VMSUMUBM
    CEFBS_None, // VMSUMUDM
    CEFBS_None, // VMSUMUHM
    CEFBS_None, // VMSUMUHS
    CEFBS_None, // VMUL10CUQ
    CEFBS_None, // VMUL10ECUQ
    CEFBS_None, // VMUL10EUQ
    CEFBS_None, // VMUL10UQ
    CEFBS_None, // VMULESB
    CEFBS_None, // VMULESD
    CEFBS_None, // VMULESH
    CEFBS_None, // VMULESW
    CEFBS_None, // VMULEUB
    CEFBS_None, // VMULEUD
    CEFBS_None, // VMULEUH
    CEFBS_None, // VMULEUW
    CEFBS_None, // VMULHSD
    CEFBS_None, // VMULHSW
    CEFBS_None, // VMULHUD
    CEFBS_None, // VMULHUW
    CEFBS_None, // VMULLD
    CEFBS_None, // VMULOSB
    CEFBS_None, // VMULOSD
    CEFBS_None, // VMULOSH
    CEFBS_None, // VMULOSW
    CEFBS_None, // VMULOUB
    CEFBS_None, // VMULOUD
    CEFBS_None, // VMULOUH
    CEFBS_None, // VMULOUW
    CEFBS_None, // VMULUWM
    CEFBS_None, // VNAND
    CEFBS_None, // VNCIPHER
    CEFBS_None, // VNCIPHERLAST
    CEFBS_None, // VNEGD
    CEFBS_None, // VNEGW
    CEFBS_None, // VNMSUBFP
    CEFBS_None, // VNOR
    CEFBS_None, // VOR
    CEFBS_None, // VORC
    CEFBS_None, // VPDEPD
    CEFBS_None, // VPERM
    CEFBS_None, // VPERMR
    CEFBS_None, // VPERMXOR
    CEFBS_None, // VPEXTD
    CEFBS_None, // VPKPX
    CEFBS_None, // VPKSDSS
    CEFBS_None, // VPKSDUS
    CEFBS_None, // VPKSHSS
    CEFBS_None, // VPKSHUS
    CEFBS_None, // VPKSWSS
    CEFBS_None, // VPKSWUS
    CEFBS_None, // VPKUDUM
    CEFBS_None, // VPKUDUS
    CEFBS_None, // VPKUHUM
    CEFBS_None, // VPKUHUS
    CEFBS_None, // VPKUWUM
    CEFBS_None, // VPKUWUS
    CEFBS_None, // VPMSUMB
    CEFBS_None, // VPMSUMD
    CEFBS_None, // VPMSUMH
    CEFBS_None, // VPMSUMW
    CEFBS_None, // VPOPCNTB
    CEFBS_None, // VPOPCNTD
    CEFBS_None, // VPOPCNTH
    CEFBS_None, // VPOPCNTW
    CEFBS_None, // VPRTYBD
    CEFBS_None, // VPRTYBQ
    CEFBS_None, // VPRTYBW
    CEFBS_None, // VREFP
    CEFBS_None, // VRFIM
    CEFBS_None, // VRFIN
    CEFBS_None, // VRFIP
    CEFBS_None, // VRFIZ
    CEFBS_None, // VRLB
    CEFBS_None, // VRLD
    CEFBS_None, // VRLDMI
    CEFBS_None, // VRLDNM
    CEFBS_None, // VRLH
    CEFBS_None, // VRLQ
    CEFBS_None, // VRLQMI
    CEFBS_None, // VRLQNM
    CEFBS_None, // VRLW
    CEFBS_None, // VRLWMI
    CEFBS_None, // VRLWNM
    CEFBS_None, // VRSQRTEFP
    CEFBS_None, // VSBOX
    CEFBS_None, // VSEL
    CEFBS_None, // VSHASIGMAD
    CEFBS_None, // VSHASIGMAW
    CEFBS_None, // VSL
    CEFBS_None, // VSLB
    CEFBS_None, // VSLD
    CEFBS_None, // VSLDBI
    CEFBS_None, // VSLDOI
    CEFBS_None, // VSLH
    CEFBS_None, // VSLO
    CEFBS_None, // VSLQ
    CEFBS_None, // VSLV
    CEFBS_None, // VSLW
    CEFBS_None, // VSPLTB
    CEFBS_None, // VSPLTBs
    CEFBS_None, // VSPLTH
    CEFBS_None, // VSPLTHs
    CEFBS_None, // VSPLTISB
    CEFBS_None, // VSPLTISH
    CEFBS_None, // VSPLTISW
    CEFBS_None, // VSPLTW
    CEFBS_None, // VSR
    CEFBS_None, // VSRAB
    CEFBS_None, // VSRAD
    CEFBS_None, // VSRAH
    CEFBS_None, // VSRAQ
    CEFBS_None, // VSRAW
    CEFBS_None, // VSRB
    CEFBS_None, // VSRD
    CEFBS_None, // VSRDBI
    CEFBS_None, // VSRH
    CEFBS_None, // VSRO
    CEFBS_None, // VSRQ
    CEFBS_None, // VSRV
    CEFBS_None, // VSRW
    CEFBS_None, // VSTRIBL
    CEFBS_None, // VSTRIBL_rec
    CEFBS_None, // VSTRIBR
    CEFBS_None, // VSTRIBR_rec
    CEFBS_None, // VSTRIHL
    CEFBS_None, // VSTRIHL_rec
    CEFBS_None, // VSTRIHR
    CEFBS_None, // VSTRIHR_rec
    CEFBS_None, // VSUBCUQ
    CEFBS_None, // VSUBCUW
    CEFBS_None, // VSUBECUQ
    CEFBS_None, // VSUBEUQM
    CEFBS_None, // VSUBFP
    CEFBS_None, // VSUBSBS
    CEFBS_None, // VSUBSHS
    CEFBS_None, // VSUBSWS
    CEFBS_None, // VSUBUBM
    CEFBS_None, // VSUBUBS
    CEFBS_None, // VSUBUDM
    CEFBS_None, // VSUBUHM
    CEFBS_None, // VSUBUHS
    CEFBS_None, // VSUBUQM
    CEFBS_None, // VSUBUWM
    CEFBS_None, // VSUBUWS
    CEFBS_None, // VSUM2SWS
    CEFBS_None, // VSUM4SBS
    CEFBS_None, // VSUM4SHS
    CEFBS_None, // VSUM4UBS
    CEFBS_None, // VSUMSWS
    CEFBS_None, // VUCMPRHB
    CEFBS_None, // VUCMPRHH
    CEFBS_None, // VUCMPRHN
    CEFBS_None, // VUCMPRLB
    CEFBS_None, // VUCMPRLH
    CEFBS_None, // VUCMPRLN
    CEFBS_None, // VUPKHPX
    CEFBS_None, // VUPKHSB
    CEFBS_None, // VUPKHSH
    CEFBS_None, // VUPKHSNTOB
    CEFBS_None, // VUPKHSW
    CEFBS_None, // VUPKINT4TOBF16
    CEFBS_None, // VUPKINT4TOFP32
    CEFBS_None, // VUPKINT8TOBF16
    CEFBS_None, // VUPKINT8TOFP32
    CEFBS_None, // VUPKLPX
    CEFBS_None, // VUPKLSB
    CEFBS_None, // VUPKLSH
    CEFBS_None, // VUPKLSNTOB
    CEFBS_None, // VUPKLSW
    CEFBS_None, // VXOR
    CEFBS_None, // V_SET0
    CEFBS_None, // V_SET0B
    CEFBS_None, // V_SET0H
    CEFBS_None, // V_SETALLONES
    CEFBS_None, // V_SETALLONESB
    CEFBS_None, // V_SETALLONESH
    CEFBS_None, // WAIT
    CEFBS_None, // WAITP10
    CEFBS_None, // WRTEE
    CEFBS_None, // WRTEEI
    CEFBS_None, // XOR
    CEFBS_None, // XOR8
    CEFBS_None, // XOR8_rec
    CEFBS_None, // XORI
    CEFBS_None, // XORI8
    CEFBS_None, // XORIS
    CEFBS_None, // XORIS8
    CEFBS_None, // XOR_rec
    CEFBS_None, // XSABSDP
    CEFBS_None, // XSABSQP
    CEFBS_None, // XSADDADDSUQM
    CEFBS_None, // XSADDADDUQM
    CEFBS_None, // XSADDDP
    CEFBS_None, // XSADDQP
    CEFBS_None, // XSADDQPO
    CEFBS_None, // XSADDSP
    CEFBS_None, // XSADDSUBSUQM
    CEFBS_None, // XSADDSUBUQM
    CEFBS_None, // XSCMPEQDP
    CEFBS_None, // XSCMPEQQP
    CEFBS_None, // XSCMPEXPDP
    CEFBS_None, // XSCMPEXPQP
    CEFBS_None, // XSCMPGEDP
    CEFBS_None, // XSCMPGEQP
    CEFBS_None, // XSCMPGTDP
    CEFBS_None, // XSCMPGTQP
    CEFBS_None, // XSCMPODP
    CEFBS_None, // XSCMPOQP
    CEFBS_None, // XSCMPUDP
    CEFBS_None, // XSCMPUQP
    CEFBS_None, // XSCPSGNDP
    CEFBS_None, // XSCPSGNQP
    CEFBS_None, // XSCVDPHP
    CEFBS_None, // XSCVDPQP
    CEFBS_None, // XSCVDPSP
    CEFBS_None, // XSCVDPSPN
    CEFBS_None, // XSCVDPSXDS
    CEFBS_None, // XSCVDPSXDSs
    CEFBS_None, // XSCVDPSXWS
    CEFBS_None, // XSCVDPSXWSs
    CEFBS_None, // XSCVDPUXDS
    CEFBS_None, // XSCVDPUXDSs
    CEFBS_None, // XSCVDPUXWS
    CEFBS_None, // XSCVDPUXWSs
    CEFBS_None, // XSCVHPDP
    CEFBS_None, // XSCVQPDP
    CEFBS_None, // XSCVQPDPO
    CEFBS_None, // XSCVQPSDZ
    CEFBS_None, // XSCVQPSQZ
    CEFBS_None, // XSCVQPSWZ
    CEFBS_None, // XSCVQPUDZ
    CEFBS_None, // XSCVQPUQZ
    CEFBS_None, // XSCVQPUWZ
    CEFBS_None, // XSCVSDQP
    CEFBS_None, // XSCVSPDP
    CEFBS_None, // XSCVSPDPN
    CEFBS_None, // XSCVSQQP
    CEFBS_None, // XSCVSXDDP
    CEFBS_None, // XSCVSXDSP
    CEFBS_None, // XSCVUDQP
    CEFBS_None, // XSCVUQQP
    CEFBS_None, // XSCVUXDDP
    CEFBS_None, // XSCVUXDSP
    CEFBS_None, // XSDIVDP
    CEFBS_None, // XSDIVQP
    CEFBS_None, // XSDIVQPO
    CEFBS_None, // XSDIVSP
    CEFBS_None, // XSIEXPDP
    CEFBS_None, // XSIEXPQP
    CEFBS_None, // XSMADDADP
    CEFBS_None, // XSMADDASP
    CEFBS_None, // XSMADDMDP
    CEFBS_None, // XSMADDMSP
    CEFBS_None, // XSMADDQP
    CEFBS_None, // XSMADDQPO
    CEFBS_None, // XSMAXCDP
    CEFBS_None, // XSMAXCQP
    CEFBS_None, // XSMAXDP
    CEFBS_None, // XSMAXJDP
    CEFBS_None, // XSMERGE2T1UQM
    CEFBS_None, // XSMERGE2T2UQM
    CEFBS_None, // XSMERGE2T3UQM
    CEFBS_None, // XSMERGE3T1UQM
    CEFBS_None, // XSMINCDP
    CEFBS_None, // XSMINCQP
    CEFBS_None, // XSMINDP
    CEFBS_None, // XSMINJDP
    CEFBS_None, // XSMSUBADP
    CEFBS_None, // XSMSUBASP
    CEFBS_None, // XSMSUBMDP
    CEFBS_None, // XSMSUBMSP
    CEFBS_None, // XSMSUBQP
    CEFBS_None, // XSMSUBQPO
    CEFBS_None, // XSMULDP
    CEFBS_None, // XSMULQP
    CEFBS_None, // XSMULQPO
    CEFBS_None, // XSMULSP
    CEFBS_None, // XSNABSDP
    CEFBS_None, // XSNABSDPs
    CEFBS_None, // XSNABSQP
    CEFBS_None, // XSNEGDP
    CEFBS_None, // XSNEGQP
    CEFBS_None, // XSNMADDADP
    CEFBS_None, // XSNMADDASP
    CEFBS_None, // XSNMADDMDP
    CEFBS_None, // XSNMADDMSP
    CEFBS_None, // XSNMADDQP
    CEFBS_None, // XSNMADDQPO
    CEFBS_None, // XSNMSUBADP
    CEFBS_None, // XSNMSUBASP
    CEFBS_None, // XSNMSUBMDP
    CEFBS_None, // XSNMSUBMSP
    CEFBS_None, // XSNMSUBQP
    CEFBS_None, // XSNMSUBQPO
    CEFBS_None, // XSRDPI
    CEFBS_None, // XSRDPIC
    CEFBS_None, // XSRDPIM
    CEFBS_None, // XSRDPIP
    CEFBS_None, // XSRDPIZ
    CEFBS_None, // XSREBASE2T1UQM
    CEFBS_None, // XSREBASE2T2UQM
    CEFBS_None, // XSREBASE2T3UQM
    CEFBS_None, // XSREBASE2T4UQM
    CEFBS_None, // XSREBASE3T1UQM
    CEFBS_None, // XSREBASE3T2UQM
    CEFBS_None, // XSREBASE3T3UQM
    CEFBS_None, // XSREDP
    CEFBS_None, // XSRESP
    CEFBS_None, // XSRQPI
    CEFBS_None, // XSRQPIX
    CEFBS_None, // XSRQPXP
    CEFBS_None, // XSRSP
    CEFBS_None, // XSRSQRTEDP
    CEFBS_None, // XSRSQRTESP
    CEFBS_None, // XSSQRTDP
    CEFBS_None, // XSSQRTQP
    CEFBS_None, // XSSQRTQPO
    CEFBS_None, // XSSQRTSP
    CEFBS_None, // XSSUBDP
    CEFBS_None, // XSSUBQP
    CEFBS_None, // XSSUBQPO
    CEFBS_None, // XSSUBSP
    CEFBS_None, // XSTDIVDP
    CEFBS_None, // XSTSQRTDP
    CEFBS_None, // XSTSTDCDP
    CEFBS_None, // XSTSTDCQP
    CEFBS_None, // XSTSTDCSP
    CEFBS_None, // XSXEXPDP
    CEFBS_None, // XSXEXPQP
    CEFBS_None, // XSXSIGDP
    CEFBS_None, // XSXSIGQP
    CEFBS_None, // XVABSDP
    CEFBS_None, // XVABSSP
    CEFBS_None, // XVADDDP
    CEFBS_None, // XVADDSP
    CEFBS_None, // XVADDUHM
    CEFBS_None, // XVADDUWM
    CEFBS_None, // XVBF16GER2
    CEFBS_None, // XVBF16GER2NN
    CEFBS_None, // XVBF16GER2NP
    CEFBS_None, // XVBF16GER2PN
    CEFBS_None, // XVBF16GER2PP
    CEFBS_None, // XVBF16GER2W
    CEFBS_None, // XVBF16GER2WNN
    CEFBS_None, // XVBF16GER2WNP
    CEFBS_None, // XVBF16GER2WPN
    CEFBS_None, // XVBF16GER2WPP
    CEFBS_None, // XVCMPEQDP
    CEFBS_None, // XVCMPEQDP_rec
    CEFBS_None, // XVCMPEQSP
    CEFBS_None, // XVCMPEQSP_rec
    CEFBS_None, // XVCMPGEDP
    CEFBS_None, // XVCMPGEDP_rec
    CEFBS_None, // XVCMPGESP
    CEFBS_None, // XVCMPGESP_rec
    CEFBS_None, // XVCMPGTDP
    CEFBS_None, // XVCMPGTDP_rec
    CEFBS_None, // XVCMPGTSP
    CEFBS_None, // XVCMPGTSP_rec
    CEFBS_None, // XVCPSGNDP
    CEFBS_None, // XVCPSGNSP
    CEFBS_None, // XVCVBF16SPN
    CEFBS_None, // XVCVDPSP
    CEFBS_None, // XVCVDPSXDS
    CEFBS_None, // XVCVDPSXWS
    CEFBS_None, // XVCVDPUXDS
    CEFBS_None, // XVCVDPUXWS
    CEFBS_None, // XVCVHPSP
    CEFBS_None, // XVCVSPBF16
    CEFBS_None, // XVCVSPDP
    CEFBS_None, // XVCVSPHP
    CEFBS_None, // XVCVSPSXDS
    CEFBS_None, // XVCVSPSXWS
    CEFBS_None, // XVCVSPUXDS
    CEFBS_None, // XVCVSPUXWS
    CEFBS_None, // XVCVSXDDP
    CEFBS_None, // XVCVSXDSP
    CEFBS_None, // XVCVSXWDP
    CEFBS_None, // XVCVSXWSP
    CEFBS_None, // XVCVUXDDP
    CEFBS_None, // XVCVUXDSP
    CEFBS_None, // XVCVUXWDP
    CEFBS_None, // XVCVUXWSP
    CEFBS_None, // XVDIVDP
    CEFBS_None, // XVDIVSP
    CEFBS_None, // XVF16GER2
    CEFBS_None, // XVF16GER2NN
    CEFBS_None, // XVF16GER2NP
    CEFBS_None, // XVF16GER2PN
    CEFBS_None, // XVF16GER2PP
    CEFBS_None, // XVF16GER2W
    CEFBS_None, // XVF16GER2WNN
    CEFBS_None, // XVF16GER2WNP
    CEFBS_None, // XVF16GER2WPN
    CEFBS_None, // XVF16GER2WPP
    CEFBS_None, // XVF32GER
    CEFBS_None, // XVF32GERNN
    CEFBS_None, // XVF32GERNP
    CEFBS_None, // XVF32GERPN
    CEFBS_None, // XVF32GERPP
    CEFBS_None, // XVF32GERW
    CEFBS_None, // XVF32GERWNN
    CEFBS_None, // XVF32GERWNP
    CEFBS_None, // XVF32GERWPN
    CEFBS_None, // XVF32GERWPP
    CEFBS_None, // XVF64GER
    CEFBS_None, // XVF64GERNN
    CEFBS_None, // XVF64GERNP
    CEFBS_None, // XVF64GERPN
    CEFBS_None, // XVF64GERPP
    CEFBS_None, // XVF64GERW
    CEFBS_None, // XVF64GERWNN
    CEFBS_None, // XVF64GERWNP
    CEFBS_None, // XVF64GERWPN
    CEFBS_None, // XVF64GERWPP
    CEFBS_None, // XVI16GER2
    CEFBS_None, // XVI16GER2PP
    CEFBS_None, // XVI16GER2S
    CEFBS_None, // XVI16GER2SPP
    CEFBS_None, // XVI16GER2SW
    CEFBS_None, // XVI16GER2SWPP
    CEFBS_None, // XVI16GER2W
    CEFBS_None, // XVI16GER2WPP
    CEFBS_None, // XVI4GER8
    CEFBS_None, // XVI4GER8PP
    CEFBS_None, // XVI4GER8W
    CEFBS_None, // XVI4GER8WPP
    CEFBS_None, // XVI8GER4
    CEFBS_None, // XVI8GER4PP
    CEFBS_None, // XVI8GER4SPP
    CEFBS_None, // XVI8GER4W
    CEFBS_None, // XVI8GER4WPP
    CEFBS_None, // XVI8GER4WSPP
    CEFBS_None, // XVIEXPDP
    CEFBS_None, // XVIEXPSP
    CEFBS_None, // XVMADDADP
    CEFBS_None, // XVMADDASP
    CEFBS_None, // XVMADDMDP
    CEFBS_None, // XVMADDMSP
    CEFBS_None, // XVMAXDP
    CEFBS_None, // XVMAXSP
    CEFBS_None, // XVMINDP
    CEFBS_None, // XVMINSP
    CEFBS_None, // XVMSUBADP
    CEFBS_None, // XVMSUBASP
    CEFBS_None, // XVMSUBMDP
    CEFBS_None, // XVMSUBMSP
    CEFBS_None, // XVMULDP
    CEFBS_None, // XVMULHSH
    CEFBS_None, // XVMULHSW
    CEFBS_None, // XVMULHUH
    CEFBS_None, // XVMULHUW
    CEFBS_None, // XVMULSP
    CEFBS_None, // XVMULUHM
    CEFBS_None, // XVMULUWM
    CEFBS_None, // XVNABSDP
    CEFBS_None, // XVNABSSP
    CEFBS_None, // XVNEGDP
    CEFBS_None, // XVNEGSP
    CEFBS_None, // XVNMADDADP
    CEFBS_None, // XVNMADDASP
    CEFBS_None, // XVNMADDMDP
    CEFBS_None, // XVNMADDMSP
    CEFBS_None, // XVNMSUBADP
    CEFBS_None, // XVNMSUBASP
    CEFBS_None, // XVNMSUBMDP
    CEFBS_None, // XVNMSUBMSP
    CEFBS_None, // XVRDPI
    CEFBS_None, // XVRDPIC
    CEFBS_None, // XVRDPIM
    CEFBS_None, // XVRDPIP
    CEFBS_None, // XVRDPIZ
    CEFBS_None, // XVREDP
    CEFBS_None, // XVRESP
    CEFBS_None, // XVRLW
    CEFBS_None, // XVRSPI
    CEFBS_None, // XVRSPIC
    CEFBS_None, // XVRSPIM
    CEFBS_None, // XVRSPIP
    CEFBS_None, // XVRSPIZ
    CEFBS_None, // XVRSQRTEDP
    CEFBS_None, // XVRSQRTESP
    CEFBS_None, // XVSQRTDP
    CEFBS_None, // XVSQRTSP
    CEFBS_None, // XVSUBDP
    CEFBS_None, // XVSUBSP
    CEFBS_None, // XVSUBUHM
    CEFBS_None, // XVSUBUWM
    CEFBS_None, // XVTDIVDP
    CEFBS_None, // XVTDIVSP
    CEFBS_None, // XVTLSBB
    CEFBS_None, // XVTSQRTDP
    CEFBS_None, // XVTSQRTSP
    CEFBS_None, // XVTSTDCDP
    CEFBS_None, // XVTSTDCSP
    CEFBS_None, // XVXEXPDP
    CEFBS_None, // XVXEXPSP
    CEFBS_None, // XVXSIGDP
    CEFBS_None, // XVXSIGSP
    CEFBS_None, // XXAESDECP
    CEFBS_None, // XXAESENCP
    CEFBS_None, // XXAESGENLKP
    CEFBS_None, // XXBLENDVB
    CEFBS_None, // XXBLENDVD
    CEFBS_None, // XXBLENDVH
    CEFBS_None, // XXBLENDVW
    CEFBS_None, // XXBRD
    CEFBS_None, // XXBRH
    CEFBS_None, // XXBRQ
    CEFBS_None, // XXBRW
    CEFBS_None, // XXEVAL
    CEFBS_None, // XXEXTRACTUW
    CEFBS_None, // XXGENPCVBM
    CEFBS_None, // XXGENPCVDM
    CEFBS_None, // XXGENPCVHM
    CEFBS_None, // XXGENPCVWM
    CEFBS_None, // XXGFMUL128
    CEFBS_None, // XXINSERTW
    CEFBS_None, // XXLAND
    CEFBS_None, // XXLANDC
    CEFBS_None, // XXLEQV
    CEFBS_None, // XXLEQVOnes
    CEFBS_None, // XXLNAND
    CEFBS_None, // XXLNOR
    CEFBS_None, // XXLOR
    CEFBS_None, // XXLORC
    CEFBS_None, // XXLORf
    CEFBS_None, // XXLXOR
    CEFBS_None, // XXLXORdpz
    CEFBS_None, // XXLXORspz
    CEFBS_None, // XXLXORz
    CEFBS_None, // XXMFACC
    CEFBS_None, // XXMFACCW
    CEFBS_None, // XXMRGHW
    CEFBS_None, // XXMRGLW
    CEFBS_None, // XXMTACC
    CEFBS_None, // XXMTACCW
    CEFBS_None, // XXMULMUL
    CEFBS_None, // XXMULMULHIADD
    CEFBS_None, // XXMULMULLOADD
    CEFBS_None, // XXPERM
    CEFBS_None, // XXPERMDI
    CEFBS_None, // XXPERMDIs
    CEFBS_None, // XXPERMR
    CEFBS_None, // XXPERMX
    CEFBS_None, // XXSEL
    CEFBS_None, // XXSETACCZ
    CEFBS_None, // XXSLDWI
    CEFBS_None, // XXSLDWIs
    CEFBS_None, // XXSPLTI32DX
    CEFBS_None, // XXSPLTIB
    CEFBS_None, // XXSPLTIDP
    CEFBS_None, // XXSPLTIW
    CEFBS_None, // XXSPLTW
    CEFBS_None, // XXSPLTWs
    CEFBS_None, // XXSSUMUDM
    CEFBS_None, // XXSSUMUDMC
    CEFBS_None, // XXSSUMUDMCEXT
    CEFBS_None, // gBC
    CEFBS_None, // gBCA
    CEFBS_None, // gBCAat
    CEFBS_None, // gBCCTR
    CEFBS_None, // gBCCTRL
    CEFBS_None, // gBCL
    CEFBS_None, // gBCLA
    CEFBS_None, // gBCLAat
    CEFBS_None, // gBCLR
    CEFBS_None, // gBCLRL
    CEFBS_None, // gBCLat
    CEFBS_None, // gBCat
  };

  assert(Opcode < 3002);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::PPC_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::PPC_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::PPC_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::PPC_MC {

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_ModernAs",
  nullptr
};

#endif // NDEBUG

void verifyInstructionPredicates(
    unsigned Opcode, const FeatureBitset &Features) {
#ifndef NDEBUG
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  if (MissingFeatures.any()) {
    std::ostringstream Msg;
    Msg << "Attempting to emit " << &PPCInstrNameData[PPCInstrNameIndices[Opcode]]
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::PPC_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

#ifdef GET_INSTRMAP_INFO
#undef GET_INSTRMAP_INFO

namespace llvm_ks::PPC {

enum Interpretation64Bit {
  Interpretation64Bit_1
};

enum IsVSXFMAAlt {
  IsVSXFMAAlt_1
};

enum RC {
  RC_0,
  RC_1
};

// get64BitInstrFromSignedExt32BitInstr
LLVM_READONLY
int32_t get64BitInstrFromSignedExt32BitInstr(uint32_t Opcode) {
  using namespace PPC;
  static constexpr uint32_t Table[][2] = {
    { ANDI_rec, ANDI8_rec },
    { EXTSB, EXTSB8 },
    { EXTSB8_32_64, EXTSB8 },
    { EXTSB_rec, EXTSB8_rec },
    { EXTSH, EXTSH8 },
    { EXTSH8_32_64, EXTSH8 },
    { EXTSH_rec, EXTSH8_rec },
    { EXTSW, EXTSW_32_64 },
    { EXTSW_rec, EXTSW_32_64_rec },
    { LBZ, LBZ8 },
    { LBZX, LBZX8 },
    { LHA, LHA8 },
    { LHAX, LHAX8 },
    { LHZ, LHZ8 },
    { LHZX, LHZX8 },
    { LI, LI8 },
    { LIS, LIS8 },
    { SETB, SETB8 },
    { SETBC, SETBC8 },
    { SETBCR, SETBCR8 },
    { SETNBC, SETNBC8 },
    { SETNBCR, SETNBCR8 },
    { SRAW, SRAW8 },
    { SRAWI, SRAWI8 },
    { SRAWI_rec, SRAWI8_rec },
    { SRAW_rec, SRAW8_rec },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 26;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == Table[mid][0]) 
      break;
    if (Opcode < Table[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return Table[mid][1];
}

// getAltVSXFMAOpcode
LLVM_READONLY
int32_t getAltVSXFMAOpcode(uint32_t Opcode) {
  using namespace PPC;
  static constexpr uint32_t Table[][2] = {
    { XSMADDADP, XSMADDMDP },
    { XSMADDASP, XSMADDMSP },
    { XSMSUBADP, XSMSUBMDP },
    { XSMSUBASP, XSMSUBMSP },
    { XSNMADDADP, XSNMADDMDP },
    { XSNMADDASP, XSNMADDMSP },
    { XSNMSUBADP, XSNMSUBMDP },
    { XSNMSUBASP, XSNMSUBMSP },
    { XVMADDADP, XVMADDMDP },
    { XVMADDASP, XVMADDMSP },
    { XVMSUBADP, XVMSUBMDP },
    { XVMSUBASP, XVMSUBMSP },
    { XVNMADDADP, XVNMADDMDP },
    { XVNMADDASP, XVNMADDMSP },
    { XVNMSUBADP, XVNMSUBMDP },
    { XVNMSUBASP, XVNMSUBMSP },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 16;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == Table[mid][0]) 
      break;
    if (Opcode < Table[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return Table[mid][1];
}

// getNonRecordFormOpcode
LLVM_READONLY
int32_t getNonRecordFormOpcode(uint32_t Opcode) {
  using namespace PPC;
  static constexpr uint32_t Table[][2] = {
    { ADD4O_rec, ADD4O },
    { ADD4_rec, ADD4 },
    { ADD8O_rec, ADD8O },
    { ADD8_rec, ADD8 },
    { ADDC8O_rec, ADDC8O },
    { ADDC8_rec, ADDC8 },
    { ADDCO_rec, ADDCO },
    { ADDC_rec, ADDC },
    { ADDE8O_rec, ADDE8O },
    { ADDE8_rec, ADDE8 },
    { ADDEO_rec, ADDEO },
    { ADDE_rec, ADDE },
    { ADDIC_rec, ADDIC },
    { ADDME8O_rec, ADDME8O },
    { ADDME8_rec, ADDME8 },
    { ADDMEO_rec, ADDMEO },
    { ADDME_rec, ADDME },
    { ADDZE8O_rec, ADDZE8O },
    { ADDZE8_rec, ADDZE8 },
    { ADDZEO_rec, ADDZEO },
    { ADDZE_rec, ADDZE },
    { AND8_rec, AND8 },
    { ANDC8_rec, ANDC8 },
    { ANDC_rec, ANDC },
    { AND_rec, AND },
    { CNTLZD_rec, CNTLZD },
    { CNTLZW8_rec, CNTLZW8 },
    { CNTLZW_rec, CNTLZW },
    { CNTTZD_rec, CNTTZD },
    { CNTTZW8_rec, CNTTZW8 },
    { CNTTZW_rec, CNTTZW },
    { DADDQ_rec, DADDQ },
    { DADD_rec, DADD },
    { DCFFIXQ_rec, DCFFIXQ },
    { DCFFIX_rec, DCFFIX },
    { DCTDP_rec, DCTDP },
    { DCTFIXQ_rec, DCTFIXQ },
    { DCTFIX_rec, DCTFIX },
    { DCTQPQ_rec, DCTQPQ },
    { DDEDPDQ_rec, DDEDPDQ },
    { DDEDPD_rec, DDEDPD },
    { DDIVQ_rec, DDIVQ },
    { DDIV_rec, DDIV },
    { DENBCDQ_rec, DENBCDQ },
    { DENBCD_rec, DENBCD },
    { DIEXQ_rec, DIEXQ },
    { DIEX_rec, DIEX },
    { DIVDEO_rec, DIVDEO },
    { DIVDEUO_rec, DIVDEUO },
    { DIVDEU_rec, DIVDEU },
    { DIVDE_rec, DIVDE },
    { DIVDO_rec, DIVDO },
    { DIVDUO_rec, DIVDUO },
    { DIVDU_rec, DIVDU },
    { DIVD_rec, DIVD },
    { DIVWEO_rec, DIVWEO },
    { DIVWEUO_rec, DIVWEUO },
    { DIVWEU_rec, DIVWEU },
    { DIVWE_rec, DIVWE },
    { DIVWO_rec, DIVWO },
    { DIVWUO_rec, DIVWUO },
    { DIVWU_rec, DIVWU },
    { DIVW_rec, DIVW },
    { DMULQ_rec, DMULQ },
    { DMUL_rec, DMUL },
    { DQUAIQ_rec, DQUAIQ },
    { DQUAI_rec, DQUAI },
    { DQUAQ_rec, DQUAQ },
    { DQUA_rec, DQUA },
    { DRDPQ_rec, DRDPQ },
    { DRINTNQ_rec, DRINTNQ },
    { DRINTN_rec, DRINTN },
    { DRINTXQ_rec, DRINTXQ },
    { DRINTX_rec, DRINTX },
    { DRRNDQ_rec, DRRNDQ },
    { DRRND_rec, DRRND },
    { DRSP_rec, DRSP },
    { DSCLIQ_rec, DSCLIQ },
    { DSCLI_rec, DSCLI },
    { DSCRIQ_rec, DSCRIQ },
    { DSCRI_rec, DSCRI },
    { DSUBQ_rec, DSUBQ },
    { DSUB_rec, DSUB },
    { DXEXQ_rec, DXEXQ },
    { DXEX_rec, DXEX },
    { EQV8_rec, EQV8 },
    { EQV_rec, EQV },
    { EXTSB8_rec, EXTSB8 },
    { EXTSB_rec, EXTSB },
    { EXTSH8_rec, EXTSH8 },
    { EXTSH_rec, EXTSH },
    { EXTSWSLI_32_64_rec, EXTSWSLI_32_64 },
    { EXTSWSLI_rec, EXTSWSLI },
    { EXTSW_32_64_rec, EXTSW_32_64 },
    { EXTSW_rec, EXTSW },
    { FABSD_rec, FABSD },
    { FABSS_rec, FABSS },
    { FADDS_rec, FADDS },
    { FADD_rec, FADD },
    { FCFIDS_rec, FCFIDS },
    { FCFIDUS_rec, FCFIDUS },
    { FCFIDU_rec, FCFIDU },
    { FCFID_rec, FCFID },
    { FCPSGND_rec, FCPSGND },
    { FCPSGNS_rec, FCPSGNS },
    { FCTIDUZ_rec, FCTIDUZ },
    { FCTIDU_rec, FCTIDU },
    { FCTIDZ_rec, FCTIDZ },
    { FCTID_rec, FCTID },
    { FCTIWUZ_rec, FCTIWUZ },
    { FCTIWU_rec, FCTIWU },
    { FCTIWZ_rec, FCTIWZ },
    { FCTIW_rec, FCTIW },
    { FDIVS_rec, FDIVS },
    { FDIV_rec, FDIV },
    { FMADDS_rec, FMADDS },
    { FMADD_rec, FMADD },
    { FMR_rec, FMR },
    { FMSUBS_rec, FMSUBS },
    { FMSUB_rec, FMSUB },
    { FMULS_rec, FMULS },
    { FMUL_rec, FMUL },
    { FNABSD_rec, FNABSD },
    { FNABSS_rec, FNABSS },
    { FNEGD_rec, FNEGD },
    { FNEGS_rec, FNEGS },
    { FNMADDS_rec, FNMADDS },
    { FNMADD_rec, FNMADD },
    { FNMSUBS_rec, FNMSUBS },
    { FNMSUB_rec, FNMSUB },
    { FRES_rec, FRES },
    { FRE_rec, FRE },
    { FRIMD_rec, FRIMD },
    { FRIMS_rec, FRIMS },
    { FRIND_rec, FRIND },
    { FRINS_rec, FRINS },
    { FRIPD_rec, FRIPD },
    { FRIPS_rec, FRIPS },
    { FRIZD_rec, FRIZD },
    { FRIZS_rec, FRIZS },
    { FRSP_rec, FRSP },
    { FRSQRTES_rec, FRSQRTES },
    { FRSQRTE_rec, FRSQRTE },
    { FSELD_rec, FSELD },
    { FSELS_rec, FSELS },
    { FSQRTS_rec, FSQRTS },
    { FSQRT_rec, FSQRT },
    { FSUBS_rec, FSUBS },
    { FSUB_rec, FSUB },
    { MULHDU_rec, MULHDU },
    { MULHD_rec, MULHD },
    { MULHWU_rec, MULHWU },
    { MULHW_rec, MULHW },
    { MULLDO_rec, MULLDO },
    { MULLD_rec, MULLD },
    { MULLWO_rec, MULLWO },
    { MULLW_rec, MULLW },
    { NAND8_rec, NAND8 },
    { NAND_rec, NAND },
    { NEG8O_rec, NEG8O },
    { NEG8_rec, NEG8 },
    { NEGO_rec, NEGO },
    { NEG_rec, NEG },
    { NOR8_rec, NOR8 },
    { NOR_rec, NOR },
    { OR8_rec, OR8 },
    { ORC8_rec, ORC8 },
    { ORC_rec, ORC },
    { OR_rec, OR },
    { RLDCL_rec, RLDCL },
    { RLDCR_rec, RLDCR },
    { RLDICL_32_rec, RLDICL_32 },
    { RLDICL_rec, RLDICL },
    { RLDICR_rec, RLDICR },
    { RLDIC_rec, RLDIC },
    { RLDIMI_rec, RLDIMI },
    { RLWIMI8_rec, RLWIMI8 },
    { RLWIMI_rec, RLWIMI },
    { RLWINM8_rec, RLWINM8 },
    { RLWINM_rec, RLWINM },
    { RLWNM8_rec, RLWNM8 },
    { RLWNM_rec, RLWNM },
    { SLD_rec, SLD },
    { SLW8_rec, SLW8 },
    { SLW_rec, SLW },
    { SRADI_rec, SRADI },
    { SRAD_rec, SRAD },
    { SRAW8_rec, SRAW8 },
    { SRAWI8_rec, SRAWI8 },
    { SRAWI_rec, SRAWI },
    { SRAW_rec, SRAW },
    { SRD_rec, SRD },
    { SRW8_rec, SRW8 },
    { SRW_rec, SRW },
    { SUBF8O_rec, SUBF8O },
    { SUBF8_rec, SUBF8 },
    { SUBFC8O_rec, SUBFC8O },
    { SUBFC8_rec, SUBFC8 },
    { SUBFCO_rec, SUBFCO },
    { SUBFC_rec, SUBFC },
    { SUBFE8O_rec, SUBFE8O },
    { SUBFE8_rec, SUBFE8 },
    { SUBFEO_rec, SUBFEO },
    { SUBFE_rec, SUBFE },
    { SUBFME8O_rec, SUBFME8O },
    { SUBFME8_rec, SUBFME8 },
    { SUBFMEO_rec, SUBFMEO },
    { SUBFME_rec, SUBFME },
    { SUBFO_rec, SUBFO },
    { SUBFUS_rec, SUBFUS },
    { SUBFZE8O_rec, SUBFZE8O },
    { SUBFZE8_rec, SUBFZE8 },
    { SUBFZEO_rec, SUBFZEO },
    { SUBFZE_rec, SUBFZE },
    { SUBF_rec, SUBF },
    { VSTRIBL_rec, VSTRIBL },
    { VSTRIBR_rec, VSTRIBR },
    { VSTRIHL_rec, VSTRIHL },
    { VSTRIHR_rec, VSTRIHR },
    { XOR8_rec, XOR8 },
    { XOR_rec, XOR },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 221;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == Table[mid][0]) 
      break;
    if (Opcode < Table[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return Table[mid][1];
}

// getRecordFormOpcode
LLVM_READONLY
int32_t getRecordFormOpcode(uint32_t Opcode) {
  using namespace PPC;
  static constexpr uint32_t Table[][2] = {
    { ADD4, ADD4_rec },
    { ADD4O, ADD4O_rec },
    { ADD8, ADD8_rec },
    { ADD8O, ADD8O_rec },
    { ADDC, ADDC_rec },
    { ADDC8, ADDC8_rec },
    { ADDC8O, ADDC8O_rec },
    { ADDCO, ADDCO_rec },
    { ADDE, ADDE_rec },
    { ADDE8, ADDE8_rec },
    { ADDE8O, ADDE8O_rec },
    { ADDEO, ADDEO_rec },
    { ADDIC, ADDIC_rec },
    { ADDME, ADDME_rec },
    { ADDME8, ADDME8_rec },
    { ADDME8O, ADDME8O_rec },
    { ADDMEO, ADDMEO_rec },
    { ADDZE, ADDZE_rec },
    { ADDZE8, ADDZE8_rec },
    { ADDZE8O, ADDZE8O_rec },
    { ADDZEO, ADDZEO_rec },
    { AND, AND_rec },
    { AND8, AND8_rec },
    { ANDC, ANDC_rec },
    { ANDC8, ANDC8_rec },
    { CNTLZD, CNTLZD_rec },
    { CNTLZW, CNTLZW_rec },
    { CNTLZW8, CNTLZW8_rec },
    { CNTTZD, CNTTZD_rec },
    { CNTTZW, CNTTZW_rec },
    { CNTTZW8, CNTTZW8_rec },
    { DADD, DADD_rec },
    { DADDQ, DADDQ_rec },
    { DCFFIX, DCFFIX_rec },
    { DCFFIXQ, DCFFIXQ_rec },
    { DCTDP, DCTDP_rec },
    { DCTFIX, DCTFIX_rec },
    { DCTFIXQ, DCTFIXQ_rec },
    { DCTQPQ, DCTQPQ_rec },
    { DDEDPD, DDEDPD_rec },
    { DDEDPDQ, DDEDPDQ_rec },
    { DDIV, DDIV_rec },
    { DDIVQ, DDIVQ_rec },
    { DENBCD, DENBCD_rec },
    { DENBCDQ, DENBCDQ_rec },
    { DIEX, DIEX_rec },
    { DIEXQ, DIEXQ_rec },
    { DIVD, DIVD_rec },
    { DIVDE, DIVDE_rec },
    { DIVDEO, DIVDEO_rec },
    { DIVDEU, DIVDEU_rec },
    { DIVDEUO, DIVDEUO_rec },
    { DIVDO, DIVDO_rec },
    { DIVDU, DIVDU_rec },
    { DIVDUO, DIVDUO_rec },
    { DIVW, DIVW_rec },
    { DIVWE, DIVWE_rec },
    { DIVWEO, DIVWEO_rec },
    { DIVWEU, DIVWEU_rec },
    { DIVWEUO, DIVWEUO_rec },
    { DIVWO, DIVWO_rec },
    { DIVWU, DIVWU_rec },
    { DIVWUO, DIVWUO_rec },
    { DMUL, DMUL_rec },
    { DMULQ, DMULQ_rec },
    { DQUA, DQUA_rec },
    { DQUAI, DQUAI_rec },
    { DQUAIQ, DQUAIQ_rec },
    { DQUAQ, DQUAQ_rec },
    { DRDPQ, DRDPQ_rec },
    { DRINTN, DRINTN_rec },
    { DRINTNQ, DRINTNQ_rec },
    { DRINTX, DRINTX_rec },
    { DRINTXQ, DRINTXQ_rec },
    { DRRND, DRRND_rec },
    { DRRNDQ, DRRNDQ_rec },
    { DRSP, DRSP_rec },
    { DSCLI, DSCLI_rec },
    { DSCLIQ, DSCLIQ_rec },
    { DSCRI, DSCRI_rec },
    { DSCRIQ, DSCRIQ_rec },
    { DSUB, DSUB_rec },
    { DSUBQ, DSUBQ_rec },
    { DXEX, DXEX_rec },
    { DXEXQ, DXEXQ_rec },
    { EQV, EQV_rec },
    { EQV8, EQV8_rec },
    { EXTSB, EXTSB_rec },
    { EXTSB8, EXTSB8_rec },
    { EXTSH, EXTSH_rec },
    { EXTSH8, EXTSH8_rec },
    { EXTSW, EXTSW_rec },
    { EXTSWSLI, EXTSWSLI_rec },
    { EXTSWSLI_32_64, EXTSWSLI_32_64_rec },
    { EXTSW_32_64, EXTSW_32_64_rec },
    { FABSD, FABSD_rec },
    { FABSS, FABSS_rec },
    { FADD, FADD_rec },
    { FADDS, FADDS_rec },
    { FCFID, FCFID_rec },
    { FCFIDS, FCFIDS_rec },
    { FCFIDU, FCFIDU_rec },
    { FCFIDUS, FCFIDUS_rec },
    { FCPSGND, FCPSGND_rec },
    { FCPSGNS, FCPSGNS_rec },
    { FCTID, FCTID_rec },
    { FCTIDU, FCTIDU_rec },
    { FCTIDUZ, FCTIDUZ_rec },
    { FCTIDZ, FCTIDZ_rec },
    { FCTIW, FCTIW_rec },
    { FCTIWU, FCTIWU_rec },
    { FCTIWUZ, FCTIWUZ_rec },
    { FCTIWZ, FCTIWZ_rec },
    { FDIV, FDIV_rec },
    { FDIVS, FDIVS_rec },
    { FMADD, FMADD_rec },
    { FMADDS, FMADDS_rec },
    { FMR, FMR_rec },
    { FMSUB, FMSUB_rec },
    { FMSUBS, FMSUBS_rec },
    { FMUL, FMUL_rec },
    { FMULS, FMULS_rec },
    { FNABSD, FNABSD_rec },
    { FNABSS, FNABSS_rec },
    { FNEGD, FNEGD_rec },
    { FNEGS, FNEGS_rec },
    { FNMADD, FNMADD_rec },
    { FNMADDS, FNMADDS_rec },
    { FNMSUB, FNMSUB_rec },
    { FNMSUBS, FNMSUBS_rec },
    { FRE, FRE_rec },
    { FRES, FRES_rec },
    { FRIMD, FRIMD_rec },
    { FRIMS, FRIMS_rec },
    { FRIND, FRIND_rec },
    { FRINS, FRINS_rec },
    { FRIPD, FRIPD_rec },
    { FRIPS, FRIPS_rec },
    { FRIZD, FRIZD_rec },
    { FRIZS, FRIZS_rec },
    { FRSP, FRSP_rec },
    { FRSQRTE, FRSQRTE_rec },
    { FRSQRTES, FRSQRTES_rec },
    { FSELD, FSELD_rec },
    { FSELS, FSELS_rec },
    { FSQRT, FSQRT_rec },
    { FSQRTS, FSQRTS_rec },
    { FSUB, FSUB_rec },
    { FSUBS, FSUBS_rec },
    { MULHD, MULHD_rec },
    { MULHDU, MULHDU_rec },
    { MULHW, MULHW_rec },
    { MULHWU, MULHWU_rec },
    { MULLD, MULLD_rec },
    { MULLDO, MULLDO_rec },
    { MULLW, MULLW_rec },
    { MULLWO, MULLWO_rec },
    { NAND, NAND_rec },
    { NAND8, NAND8_rec },
    { NEG, NEG_rec },
    { NEG8, NEG8_rec },
    { NEG8O, NEG8O_rec },
    { NEGO, NEGO_rec },
    { NOR, NOR_rec },
    { NOR8, NOR8_rec },
    { OR, OR_rec },
    { OR8, OR8_rec },
    { ORC, ORC_rec },
    { ORC8, ORC8_rec },
    { RLDCL, RLDCL_rec },
    { RLDCR, RLDCR_rec },
    { RLDIC, RLDIC_rec },
    { RLDICL, RLDICL_rec },
    { RLDICL_32, RLDICL_32_rec },
    { RLDICR, RLDICR_rec },
    { RLDIMI, RLDIMI_rec },
    { RLWIMI, RLWIMI_rec },
    { RLWIMI8, RLWIMI8_rec },
    { RLWINM, RLWINM_rec },
    { RLWINM8, RLWINM8_rec },
    { RLWNM, RLWNM_rec },
    { RLWNM8, RLWNM8_rec },
    { SLD, SLD_rec },
    { SLW, SLW_rec },
    { SLW8, SLW8_rec },
    { SRAD, SRAD_rec },
    { SRADI, SRADI_rec },
    { SRAW, SRAW_rec },
    { SRAW8, SRAW8_rec },
    { SRAWI, SRAWI_rec },
    { SRAWI8, SRAWI8_rec },
    { SRD, SRD_rec },
    { SRW, SRW_rec },
    { SRW8, SRW8_rec },
    { SUBF, SUBF_rec },
    { SUBF8, SUBF8_rec },
    { SUBF8O, SUBF8O_rec },
    { SUBFC, SUBFC_rec },
    { SUBFC8, SUBFC8_rec },
    { SUBFC8O, SUBFC8O_rec },
    { SUBFCO, SUBFCO_rec },
    { SUBFE, SUBFE_rec },
    { SUBFE8, SUBFE8_rec },
    { SUBFE8O, SUBFE8O_rec },
    { SUBFEO, SUBFEO_rec },
    { SUBFME, SUBFME_rec },
    { SUBFME8, SUBFME8_rec },
    { SUBFME8O, SUBFME8O_rec },
    { SUBFMEO, SUBFMEO_rec },
    { SUBFO, SUBFO_rec },
    { SUBFUS, SUBFUS_rec },
    { SUBFZE, SUBFZE_rec },
    { SUBFZE8, SUBFZE8_rec },
    { SUBFZE8O, SUBFZE8O_rec },
    { SUBFZEO, SUBFZEO_rec },
    { VSTRIBL, VSTRIBL_rec },
    { VSTRIBR, VSTRIBR_rec },
    { VSTRIHL, VSTRIHL_rec },
    { VSTRIHR, VSTRIHR_rec },
    { XOR, XOR_rec },
    { XOR8, XOR8_rec },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 221;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == Table[mid][0]) 
      break;
    if (Opcode < Table[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return Table[mid][1];
}


} // namespace llvm_ks::PPC

#endif // GET_INSTRMAP_INFO

