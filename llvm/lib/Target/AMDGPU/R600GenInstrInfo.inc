/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::R600 {

  enum {
    PHI                                   = 0, // Target.td:1327
    INLINEASM                             = 1, // Target.td:1333
    INLINEASM_BR                          = 2, // Target.td:1339
    CFI_INSTRUCTION                       = 3, // Target.td:1348
    EH_LABEL                              = 4, // Target.td:1357
    GC_LABEL                              = 5, // Target.td:1366
    ANNOTATION_LABEL                      = 6, // Target.td:1375
    KILL                                  = 7, // Target.td:1383
    EXTRACT_SUBREG                        = 8, // Target.td:1390
    INSERT_SUBREG                         = 9, // Target.td:1396
    IMPLICIT_DEF                          = 10, // Target.td:1403
    INIT_UNDEF                            = 11, // Target.td:1412
    SUBREG_TO_REG                         = 12, // Target.td:1419
    COPY_TO_REGCLASS                      = 13, // Target.td:1425
    DBG_VALUE                             = 14, // Target.td:1432
    DBG_VALUE_LIST                        = 15, // Target.td:1439
    DBG_INSTR_REF                         = 16, // Target.td:1446
    DBG_PHI                               = 17, // Target.td:1453
    DBG_LABEL                             = 18, // Target.td:1460
    REG_SEQUENCE                          = 19, // Target.td:1467
    COPY                                  = 20, // Target.td:1474
    COPY_LANEMASK                         = 21, // Target.td:1482
    BUNDLE                                = 22, // Target.td:1489
    LIFETIME_START                        = 23, // Target.td:1495
    LIFETIME_END                          = 24, // Target.td:1502
    PSEUDO_PROBE                          = 25, // Target.td:1509
    ARITH_FENCE                           = 26, // Target.td:1516
    STACKMAP                              = 27, // Target.td:1525
    FENTRY_CALL                           = 28, // Target.td:1660
    PATCHPOINT                            = 29, // Target.td:1533
    LOAD_STACK_GUARD                      = 30, // Target.td:1551
    PREALLOCATED_SETUP                    = 31, // Target.td:1559
    PREALLOCATED_ARG                      = 32, // Target.td:1565
    STATEPOINT                            = 33, // Target.td:1542
    LOCAL_ESCAPE                          = 34, // Target.td:1571
    FAULTING_OP                           = 35, // Target.td:1580
    PATCHABLE_OP                          = 36, // Target.td:1600
    PATCHABLE_FUNCTION_ENTER              = 37, // Target.td:1608
    PATCHABLE_RET                         = 38, // Target.td:1615
    PATCHABLE_FUNCTION_EXIT               = 39, // Target.td:1624
    PATCHABLE_TAIL_CALL                   = 40, // Target.td:1632
    PATCHABLE_EVENT_CALL                  = 41, // Target.td:1640
    PATCHABLE_TYPED_EVENT_CALL            = 42, // Target.td:1650
    ICALL_BRANCH_FUNNEL                   = 43, // Target.td:1670
    FAKE_USE                              = 44, // Target.td:1590
    MEMBARRIER                            = 45, // Target.td:1676
    JUMP_TABLE_DEBUG_INFO                 = 46, // Target.td:1684
    RELOC_NONE                            = 47, // Target.td:1692
    CONVERGENCECTRL_ENTRY                 = 48, // Target.td:1704
    CONVERGENCECTRL_ANCHOR                = 49, // Target.td:1700
    CONVERGENCECTRL_LOOP                  = 50, // Target.td:1708
    CONVERGENCECTRL_GLUE                  = 51, // Target.td:1712
    G_ASSERT_SEXT                         = 52, // GenericOpcodes.td:1929
    G_ASSERT_ZEXT                         = 53, // GenericOpcodes.td:1921
    G_ASSERT_ALIGN                        = 54, // GenericOpcodes.td:1936
    G_ADD                                 = 55, // GenericOpcodes.td:308
    G_SUB                                 = 56, // GenericOpcodes.td:316
    G_MUL                                 = 57, // GenericOpcodes.td:324
    G_SDIV                                = 58, // GenericOpcodes.td:332
    G_UDIV                                = 59, // GenericOpcodes.td:340
    G_SREM                                = 60, // GenericOpcodes.td:348
    G_UREM                                = 61, // GenericOpcodes.td:356
    G_SDIVREM                             = 62, // GenericOpcodes.td:364
    G_UDIVREM                             = 63, // GenericOpcodes.td:372
    G_AND                                 = 64, // GenericOpcodes.td:380
    G_OR                                  = 65, // GenericOpcodes.td:388
    G_XOR                                 = 66, // GenericOpcodes.td:396
    G_ABDS                                = 67, // GenericOpcodes.td:425
    G_ABDU                                = 68, // GenericOpcodes.td:433
    G_UAVGFLOOR                           = 69, // GenericOpcodes.td:441
    G_UAVGCEIL                            = 70, // GenericOpcodes.td:448
    G_SAVGFLOOR                           = 71, // GenericOpcodes.td:455
    G_SAVGCEIL                            = 72, // GenericOpcodes.td:462
    G_IMPLICIT_DEF                        = 73, // GenericOpcodes.td:111
    G_PHI                                 = 74, // GenericOpcodes.td:118
    G_FRAME_INDEX                         = 75, // GenericOpcodes.td:125
    G_GLOBAL_VALUE                        = 76, // GenericOpcodes.td:131
    G_PTRAUTH_GLOBAL_VALUE                = 77, // GenericOpcodes.td:137
    G_CONSTANT_POOL                       = 78, // GenericOpcodes.td:143
    G_EXTRACT                             = 79, // GenericOpcodes.td:1516
    G_UNMERGE_VALUES                      = 80, // GenericOpcodes.td:1529
    G_INSERT                              = 81, // GenericOpcodes.td:1538
    G_MERGE_VALUES                        = 82, // GenericOpcodes.td:1548
    G_BUILD_VECTOR                        = 83, // GenericOpcodes.td:1568
    G_BUILD_VECTOR_TRUNC                  = 84, // GenericOpcodes.td:1578
    G_CONCAT_VECTORS                      = 85, // GenericOpcodes.td:1585
    G_PTRTOINT                            = 86, // GenericOpcodes.td:155
    G_INTTOPTR                            = 87, // GenericOpcodes.td:149
    G_BITCAST                             = 88, // GenericOpcodes.td:161
    G_FREEZE                              = 89, // GenericOpcodes.td:284
    G_CONSTANT_FOLD_BARRIER               = 90, // GenericOpcodes.td:1943
    G_INTRINSIC_FPTRUNC_ROUND             = 91, // GenericOpcodes.td:1280
    G_INTRINSIC_TRUNC                     = 92, // GenericOpcodes.td:1286
    G_INTRINSIC_ROUND                     = 93, // GenericOpcodes.td:1292
    G_INTRINSIC_LRINT                     = 94, // GenericOpcodes.td:1298
    G_INTRINSIC_LLRINT                    = 95, // GenericOpcodes.td:1304
    G_INTRINSIC_ROUNDEVEN                 = 96, // GenericOpcodes.td:1310
    G_READCYCLECOUNTER                    = 97, // GenericOpcodes.td:1316
    G_READSTEADYCOUNTER                   = 98, // GenericOpcodes.td:1322
    G_LOAD                                = 99, // GenericOpcodes.td:1349
    G_SEXTLOAD                            = 100, // GenericOpcodes.td:1358
    G_ZEXTLOAD                            = 101, // GenericOpcodes.td:1366
    G_FPEXTLOAD                           = 102, // GenericOpcodes.td:1375
    G_INDEXED_LOAD                        = 103, // GenericOpcodes.td:1385
    G_INDEXED_SEXTLOAD                    = 104, // GenericOpcodes.td:1394
    G_INDEXED_ZEXTLOAD                    = 105, // GenericOpcodes.td:1402
    G_STORE                               = 106, // GenericOpcodes.td:1410
    G_FPTRUNCSTORE                        = 107, // GenericOpcodes.td:1420
    G_INDEXED_STORE                       = 108, // GenericOpcodes.td:1428
    G_ATOMIC_CMPXCHG_WITH_SUCCESS         = 109, // GenericOpcodes.td:1439
    G_ATOMIC_CMPXCHG                      = 110, // GenericOpcodes.td:1450
    G_ATOMICRMW_XCHG                      = 111, // GenericOpcodes.td:1470
    G_ATOMICRMW_ADD                       = 112, // GenericOpcodes.td:1471
    G_ATOMICRMW_SUB                       = 113, // GenericOpcodes.td:1472
    G_ATOMICRMW_AND                       = 114, // GenericOpcodes.td:1473
    G_ATOMICRMW_NAND                      = 115, // GenericOpcodes.td:1474
    G_ATOMICRMW_OR                        = 116, // GenericOpcodes.td:1475
    G_ATOMICRMW_XOR                       = 117, // GenericOpcodes.td:1476
    G_ATOMICRMW_MAX                       = 118, // GenericOpcodes.td:1477
    G_ATOMICRMW_MIN                       = 119, // GenericOpcodes.td:1478
    G_ATOMICRMW_UMAX                      = 120, // GenericOpcodes.td:1479
    G_ATOMICRMW_UMIN                      = 121, // GenericOpcodes.td:1480
    G_ATOMICRMW_FADD                      = 122, // GenericOpcodes.td:1481
    G_ATOMICRMW_FSUB                      = 123, // GenericOpcodes.td:1482
    G_ATOMICRMW_FMAX                      = 124, // GenericOpcodes.td:1483
    G_ATOMICRMW_FMIN                      = 125, // GenericOpcodes.td:1484
    G_ATOMICRMW_FMAXIMUM                  = 126, // GenericOpcodes.td:1485
    G_ATOMICRMW_FMINIMUM                  = 127, // GenericOpcodes.td:1486
    G_ATOMICRMW_FMAXIMUMNUM               = 128, // GenericOpcodes.td:1487
    G_ATOMICRMW_FMINIMUMNUM               = 129, // GenericOpcodes.td:1488
    G_ATOMICRMW_UINC_WRAP                 = 130, // GenericOpcodes.td:1489
    G_ATOMICRMW_UDEC_WRAP                 = 131, // GenericOpcodes.td:1490
    G_ATOMICRMW_USUB_COND                 = 132, // GenericOpcodes.td:1491
    G_ATOMICRMW_USUB_SAT                  = 133, // GenericOpcodes.td:1492
    G_FENCE                               = 134, // GenericOpcodes.td:1494
    G_PREFETCH                            = 135, // GenericOpcodes.td:1501
    G_BRCOND                              = 136, // GenericOpcodes.td:1641
    G_BRINDIRECT                          = 137, // GenericOpcodes.td:1650
    G_INVOKE_REGION_START                 = 138, // GenericOpcodes.td:1673
    G_INTRINSIC                           = 139, // GenericOpcodes.td:1593
    G_INTRINSIC_W_SIDE_EFFECTS            = 140, // GenericOpcodes.td:1600
    G_INTRINSIC_CONVERGENT                = 141, // GenericOpcodes.td:1609
    G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS = 142, // GenericOpcodes.td:1617
    G_ANYEXT                              = 143, // GenericOpcodes.td:44
    G_TRUNC                               = 144, // GenericOpcodes.td:83
    G_TRUNC_SSAT_S                        = 145, // GenericOpcodes.td:91
    G_TRUNC_SSAT_U                        = 146, // GenericOpcodes.td:98
    G_TRUNC_USAT_U                        = 147, // GenericOpcodes.td:105
    G_CONSTANT                            = 148, // GenericOpcodes.td:169
    G_FCONSTANT                           = 149, // GenericOpcodes.td:177
    G_VASTART                             = 150, // GenericOpcodes.td:184
    G_VAARG                               = 151, // GenericOpcodes.td:191
    G_SEXT                                = 152, // GenericOpcodes.td:52
    G_SEXT_INREG                          = 153, // GenericOpcodes.td:66
    G_ZEXT                                = 154, // GenericOpcodes.td:74
    G_SHL                                 = 155, // GenericOpcodes.td:404
    G_LSHR                                = 156, // GenericOpcodes.td:411
    G_ASHR                                = 157, // GenericOpcodes.td:418
    G_FSHL                                = 158, // GenericOpcodes.td:470
    G_FSHR                                = 159, // GenericOpcodes.td:478
    G_ROTR                                = 160, // GenericOpcodes.td:485
    G_ROTL                                = 161, // GenericOpcodes.td:492
    G_ICMP                                = 162, // GenericOpcodes.td:499
    G_FCMP                                = 163, // GenericOpcodes.td:506
    G_SCMP                                = 164, // GenericOpcodes.td:513
    G_UCMP                                = 165, // GenericOpcodes.td:520
    G_SELECT                              = 166, // GenericOpcodes.td:527
    G_UADDO                               = 167, // GenericOpcodes.td:601
    G_UADDE                               = 168, // GenericOpcodes.td:609
    G_USUBO                               = 169, // GenericOpcodes.td:631
    G_USUBE                               = 170, // GenericOpcodes.td:637
    G_SADDO                               = 171, // GenericOpcodes.td:616
    G_SADDE                               = 172, // GenericOpcodes.td:624
    G_SSUBO                               = 173, // GenericOpcodes.td:644
    G_SSUBE                               = 174, // GenericOpcodes.td:651
    G_UMULO                               = 175, // GenericOpcodes.td:658
    G_SMULO                               = 176, // GenericOpcodes.td:666
    G_UMULH                               = 177, // GenericOpcodes.td:675
    G_SMULH                               = 178, // GenericOpcodes.td:684
    G_UADDSAT                             = 179, // GenericOpcodes.td:696
    G_SADDSAT                             = 180, // GenericOpcodes.td:704
    G_USUBSAT                             = 181, // GenericOpcodes.td:712
    G_SSUBSAT                             = 182, // GenericOpcodes.td:720
    G_USHLSAT                             = 183, // GenericOpcodes.td:728
    G_SSHLSAT                             = 184, // GenericOpcodes.td:736
    G_SMULFIX                             = 185, // GenericOpcodes.td:748
    G_UMULFIX                             = 186, // GenericOpcodes.td:755
    G_SMULFIXSAT                          = 187, // GenericOpcodes.td:765
    G_UMULFIXSAT                          = 188, // GenericOpcodes.td:772
    G_SDIVFIX                             = 189, // GenericOpcodes.td:783
    G_UDIVFIX                             = 190, // GenericOpcodes.td:790
    G_SDIVFIXSAT                          = 191, // GenericOpcodes.td:800
    G_UDIVFIXSAT                          = 192, // GenericOpcodes.td:807
    G_FADD                                = 193, // GenericOpcodes.td:980
    G_FSUB                                = 194, // GenericOpcodes.td:988
    G_FMUL                                = 195, // GenericOpcodes.td:996
    G_FMA                                 = 196, // GenericOpcodes.td:1005
    G_FMAD                                = 197, // GenericOpcodes.td:1014
    G_FDIV                                = 198, // GenericOpcodes.td:1022
    G_FREM                                = 199, // GenericOpcodes.td:1029
    G_FMODF                               = 200, // GenericOpcodes.td:1036
    G_FPOW                                = 201, // GenericOpcodes.td:1043
    G_FPOWI                               = 202, // GenericOpcodes.td:1050
    G_FEXP                                = 203, // GenericOpcodes.td:1057
    G_FEXP2                               = 204, // GenericOpcodes.td:1064
    G_FEXP10                              = 205, // GenericOpcodes.td:1071
    G_FLOG                                = 206, // GenericOpcodes.td:1078
    G_FLOG2                               = 207, // GenericOpcodes.td:1085
    G_FLOG10                              = 208, // GenericOpcodes.td:1092
    G_FLDEXP                              = 209, // GenericOpcodes.td:1099
    G_FFREXP                              = 210, // GenericOpcodes.td:1106
    G_FNEG                                = 211, // GenericOpcodes.td:818
    G_FPEXT                               = 212, // GenericOpcodes.td:824
    G_FPTRUNC                             = 213, // GenericOpcodes.td:830
    G_FPTOSI                              = 214, // GenericOpcodes.td:836
    G_FPTOUI                              = 215, // GenericOpcodes.td:842
    G_SITOFP                              = 216, // GenericOpcodes.td:848
    G_UITOFP                              = 217, // GenericOpcodes.td:854
    G_FPTOSI_SAT                          = 218, // GenericOpcodes.td:860
    G_FPTOUI_SAT                          = 219, // GenericOpcodes.td:866
    G_FABS                                = 220, // GenericOpcodes.td:872
    G_FCOPYSIGN                           = 221, // GenericOpcodes.td:878
    G_IS_FPCLASS                          = 222, // GenericOpcodes.td:891
    G_FCANONICALIZE                       = 223, // GenericOpcodes.td:884
    G_FMINNUM                             = 224, // GenericOpcodes.td:904
    G_FMAXNUM                             = 225, // GenericOpcodes.td:911
    G_FMINNUM_IEEE                        = 226, // GenericOpcodes.td:929
    G_FMAXNUM_IEEE                        = 227, // GenericOpcodes.td:936
    G_FMINIMUM                            = 228, // GenericOpcodes.td:946
    G_FMAXIMUM                            = 229, // GenericOpcodes.td:953
    G_FMINIMUMNUM                         = 230, // GenericOpcodes.td:961
    G_FMAXIMUMNUM                         = 231, // GenericOpcodes.td:968
    G_GET_FPENV                           = 232, // GenericOpcodes.td:1236
    G_SET_FPENV                           = 233, // GenericOpcodes.td:1243
    G_RESET_FPENV                         = 234, // GenericOpcodes.td:1250
    G_GET_FPMODE                          = 235, // GenericOpcodes.td:1257
    G_SET_FPMODE                          = 236, // GenericOpcodes.td:1264
    G_RESET_FPMODE                        = 237, // GenericOpcodes.td:1271
    G_GET_ROUNDING                        = 238, // GenericOpcodes.td:1328
    G_SET_ROUNDING                        = 239, // GenericOpcodes.td:1334
    G_PTR_ADD                             = 240, // GenericOpcodes.td:534
    G_PTRMASK                             = 241, // GenericOpcodes.td:542
    G_SMIN                                = 242, // GenericOpcodes.td:549
    G_SMAX                                = 243, // GenericOpcodes.td:557
    G_UMIN                                = 244, // GenericOpcodes.td:565
    G_UMAX                                = 245, // GenericOpcodes.td:573
    G_ABS                                 = 246, // GenericOpcodes.td:581
    G_LROUND                              = 247, // GenericOpcodes.td:291
    G_LLROUND                             = 248, // GenericOpcodes.td:297
    G_BR                                  = 249, // GenericOpcodes.td:1631
    G_BRJT                                = 250, // GenericOpcodes.td:1661
    G_VSCALE                              = 251, // GenericOpcodes.td:1559
    G_INSERT_SUBVECTOR                    = 252, // GenericOpcodes.td:1705
    G_EXTRACT_SUBVECTOR                   = 253, // GenericOpcodes.td:1713
    G_INSERT_VECTOR_ELT                   = 254, // GenericOpcodes.td:1721
    G_EXTRACT_VECTOR_ELT                  = 255, // GenericOpcodes.td:1729
    G_SHUFFLE_VECTOR                      = 256, // GenericOpcodes.td:1740
    G_SPLAT_VECTOR                        = 257, // GenericOpcodes.td:1748
    G_STEP_VECTOR                         = 258, // GenericOpcodes.td:1756
    G_VECTOR_COMPRESS                     = 259, // GenericOpcodes.td:1763
    G_CTTZ                                = 260, // GenericOpcodes.td:211
    G_CTTZ_ZERO_POISON                    = 261, // GenericOpcodes.td:217
    G_CTLZ                                = 262, // GenericOpcodes.td:199
    G_CTLZ_ZERO_POISON                    = 263, // GenericOpcodes.td:205
    G_CTLS                                = 264, // GenericOpcodes.td:223
    G_CTPOP                               = 265, // GenericOpcodes.td:229
    G_BSWAP                               = 266, // GenericOpcodes.td:235
    G_BITREVERSE                          = 267, // GenericOpcodes.td:242
    G_CLMUL                               = 268, // GenericOpcodes.td:588
    G_FCEIL                               = 269, // GenericOpcodes.td:1113
    G_FCOS                                = 270, // GenericOpcodes.td:1120
    G_FSIN                                = 271, // GenericOpcodes.td:1127
    G_FSINCOS                             = 272, // GenericOpcodes.td:1134
    G_FTAN                                = 273, // GenericOpcodes.td:1141
    G_FACOS                               = 274, // GenericOpcodes.td:1148
    G_FASIN                               = 275, // GenericOpcodes.td:1155
    G_FATAN                               = 276, // GenericOpcodes.td:1162
    G_FATAN2                              = 277, // GenericOpcodes.td:1169
    G_FCOSH                               = 278, // GenericOpcodes.td:1176
    G_FSINH                               = 279, // GenericOpcodes.td:1183
    G_FTANH                               = 280, // GenericOpcodes.td:1190
    G_FSQRT                               = 281, // GenericOpcodes.td:1200
    G_FFLOOR                              = 282, // GenericOpcodes.td:1207
    G_FRINT                               = 283, // GenericOpcodes.td:1214
    G_FNEARBYINT                          = 284, // GenericOpcodes.td:1221
    G_ADDRSPACE_CAST                      = 285, // GenericOpcodes.td:248
    G_BLOCK_ADDR                          = 286, // GenericOpcodes.td:254
    G_JUMP_TABLE                          = 287, // GenericOpcodes.td:260
    G_DYN_STACKALLOC                      = 288, // GenericOpcodes.td:266
    G_STACKSAVE                           = 289, // GenericOpcodes.td:272
    G_STACKRESTORE                        = 290, // GenericOpcodes.td:278
    G_STRICT_FADD                         = 291, // GenericOpcodes.td:1813
    G_STRICT_FSUB                         = 292, // GenericOpcodes.td:1814
    G_STRICT_FMUL                         = 293, // GenericOpcodes.td:1815
    G_STRICT_FDIV                         = 294, // GenericOpcodes.td:1816
    G_STRICT_FREM                         = 295, // GenericOpcodes.td:1817
    G_STRICT_FMA                          = 296, // GenericOpcodes.td:1818
    G_STRICT_FSQRT                        = 297, // GenericOpcodes.td:1819
    G_STRICT_FLDEXP                       = 298, // GenericOpcodes.td:1820
    G_STRICT_FCMP                         = 299, // GenericOpcodes.td:1821
    G_STRICT_FCMPS                        = 300, // GenericOpcodes.td:1822
    G_READ_REGISTER                       = 301, // GenericOpcodes.td:1680
    G_WRITE_REGISTER                      = 302, // GenericOpcodes.td:1690
    G_MEMCPY                              = 303, // GenericOpcodes.td:1828
    G_MEMCPY_INLINE                       = 304, // GenericOpcodes.td:1836
    G_MEMMOVE                             = 305, // GenericOpcodes.td:1844
    G_MEMSET                              = 306, // GenericOpcodes.td:1852
    G_BZERO                               = 307, // GenericOpcodes.td:1859
    G_MEMSET_INLINE                       = 308, // GenericOpcodes.td:1866
    G_TRAP                                = 309, // GenericOpcodes.td:1876
    G_DEBUGTRAP                           = 310, // GenericOpcodes.td:1883
    G_UBSANTRAP                           = 311, // GenericOpcodes.td:1889
    G_VECREDUCE_SEQ_FADD                  = 312, // GenericOpcodes.td:1779
    G_VECREDUCE_SEQ_FMUL                  = 313, // GenericOpcodes.td:1785
    G_VECREDUCE_FADD                      = 314, // GenericOpcodes.td:1791
    G_VECREDUCE_FMUL                      = 315, // GenericOpcodes.td:1792
    G_VECREDUCE_FMAX                      = 316, // GenericOpcodes.td:1794
    G_VECREDUCE_FMIN                      = 317, // GenericOpcodes.td:1795
    G_VECREDUCE_FMAXIMUM                  = 318, // GenericOpcodes.td:1796
    G_VECREDUCE_FMINIMUM                  = 319, // GenericOpcodes.td:1797
    G_VECREDUCE_ADD                       = 320, // GenericOpcodes.td:1799
    G_VECREDUCE_MUL                       = 321, // GenericOpcodes.td:1800
    G_VECREDUCE_AND                       = 322, // GenericOpcodes.td:1801
    G_VECREDUCE_OR                        = 323, // GenericOpcodes.td:1802
    G_VECREDUCE_XOR                       = 324, // GenericOpcodes.td:1803
    G_VECREDUCE_SMAX                      = 325, // GenericOpcodes.td:1804
    G_VECREDUCE_SMIN                      = 326, // GenericOpcodes.td:1805
    G_VECREDUCE_UMAX                      = 327, // GenericOpcodes.td:1806
    G_VECREDUCE_UMIN                      = 328, // GenericOpcodes.td:1807
    G_SBFX                                = 329, // GenericOpcodes.td:1901
    G_UBFX                                = 330, // GenericOpcodes.td:1909
    BRANCH                                = 331, // R600Instructions.td:1594
    BRANCH_COND_f32                       = 332, // R600Instructions.td:1567
    BRANCH_COND_i32                       = 333, // R600Instructions.td:1563
    BREAK                                 = 334, // R600Instructions.td:1608
    BREAKC_f32                            = 335, // R600Instructions.td:1584
    BREAKC_i32                            = 336, // R600Instructions.td:1582
    BREAK_LOGICALNZ_f32                   = 337, // R600Instructions.td:1577
    BREAK_LOGICALNZ_i32                   = 338, // R600Instructions.td:1575
    BREAK_LOGICALZ_f32                    = 339, // R600Instructions.td:1577
    BREAK_LOGICALZ_i32                    = 340, // R600Instructions.td:1575
    CONST_COPY                            = 341, // R600Instructions.td:1439
    CONTINUE                              = 342, // R600Instructions.td:1610
    CONTINUEC_f32                         = 343, // R600Instructions.td:1584
    CONTINUEC_i32                         = 344, // R600Instructions.td:1582
    CONTINUE_LOGICALNZ_f32                = 345, // R600Instructions.td:1577
    CONTINUE_LOGICALNZ_i32                = 346, // R600Instructions.td:1575
    CONTINUE_LOGICALZ_f32                 = 347, // R600Instructions.td:1577
    CONTINUE_LOGICALZ_i32                 = 348, // R600Instructions.td:1575
    CUBE_eg_pseudo                        = 349, // R600Instructions.td:1074
    CUBE_r600_pseudo                      = 350, // R600Instructions.td:1074
    DEFAULT                               = 351, // R600Instructions.td:1612
    DOT_4                                 = 352, // R600Instructions.td:1061
    DUMMY_CHAIN                           = 353, // R600Instructions.td:792
    ELSE                                  = 354, // R600Instructions.td:1614
    END                                   = 355, // R600Instructions.td:1620
    ENDFUNC                               = 356, // R600Instructions.td:1622
    ENDIF                                 = 357, // R600Instructions.td:1624
    ENDLOOP                               = 358, // R600Instructions.td:1628
    ENDMAIN                               = 359, // R600Instructions.td:1618
    ENDSWITCH                             = 360, // R600Instructions.td:1616
    FABS_R600                             = 361, // R600Instructions.td:1204
    FNEG_R600                             = 362, // R600Instructions.td:1205
    FUNC                                  = 363, // R600Instructions.td:1630
    IFC_f32                               = 364, // R600Instructions.td:1584
    IFC_i32                               = 365, // R600Instructions.td:1582
    IF_LOGICALNZ_f32                      = 366, // R600Instructions.td:1577
    IF_LOGICALNZ_i32                      = 367, // R600Instructions.td:1575
    IF_LOGICALZ_f32                       = 368, // R600Instructions.td:1577
    IF_LOGICALZ_i32                       = 369, // R600Instructions.td:1575
    IF_PREDICATE_SET                      = 370, // R600Instructions.td:1604
    JUMP                                  = 371, // R600Instructions.td:1385
    JUMP_COND                             = 372, // R600Instructions.td:1378
    MASK_WRITE                            = 373, // R600Instructions.td:1402
    MOV_IMM_F32                           = 374, // R600Instructions.td:827
    MOV_IMM_GLOBAL_ADDR                   = 375, // R600Instructions.td:820
    MOV_IMM_I32                           = 376, // R600Instructions.td:814
    PRED_X                                = 377, // R600Instructions.td:1370
    R600_EXTRACT_ELT_V2                   = 378, // R600Instructions.td:1677
    R600_EXTRACT_ELT_V4                   = 379, // R600Instructions.td:1678
    R600_INSERT_ELT_V2                    = 380, // R600Instructions.td:1680
    R600_INSERT_ELT_V4                    = 381, // R600Instructions.td:1681
    R600_RegisterLoad                     = 382, // R600Instructions.td:698
    R600_RegisterStore                    = 383, // R600Instructions.td:707
    RETDYN                                = 384, // R600Instructions.td:1632
    RETURN                                = 385, // R600Instructions.td:88
    TXD                                   = 386, // R600Instructions.td:1413
    TXD_SHADOW                            = 387, // R600Instructions.td:1422
    WHILELOOP                             = 388, // R600Instructions.td:1626
    ADD                                   = 389, // R600Instructions.td:721
    ADDC_UINT                             = 390, // EvergreenInstructions.td:523
    ADD_INT                               = 391, // R600Instructions.td:848
    ALU_CLAUSE                            = 392, // R600Instructions.td:646
    AND_INT                               = 393, // R600Instructions.td:844
    ASHR_eg                               = 394, // EvergreenInstructions.td:508
    ASHR_r600                             = 395, // R600Instructions.td:1253
    BCNT_INT                              = 396, // EvergreenInstructions.td:528
    BFE_INT_eg                            = 397, // EvergreenInstructions.td:370
    BFE_UINT_eg                           = 398, // EvergreenInstructions.td:365
    BFI_INT_eg                            = 399, // EvergreenInstructions.td:411
    BFM_INT_eg                            = 400, // EvergreenInstructions.td:492
    BIT_ALIGN_INT_eg                      = 401, // EvergreenInstructions.td:500
    CEIL                                  = 402, // R600Instructions.td:781
    CF_ALU                                = 403, // R600Instructions.td:631
    CF_ALU_BREAK                          = 404, // R600Instructions.td:635
    CF_ALU_CONTINUE                       = 405, // R600Instructions.td:634
    CF_ALU_ELSE_AFTER                     = 406, // R600Instructions.td:636
    CF_ALU_POP_AFTER                      = 407, // R600Instructions.td:633
    CF_ALU_PUSH_BEFORE                    = 408, // R600Instructions.td:632
    CF_CALL_FS_EG                         = 409, // EvergreenInstructions.td:850
    CF_CALL_FS_R600                       = 410, // R600Instructions.td:1325
    CF_CONTINUE_EG                        = 411, // EvergreenInstructions.td:833
    CF_CONTINUE_R600                      = 412, // R600Instructions.td:1307
    CF_ELSE_EG                            = 413, // EvergreenInstructions.td:846
    CF_ELSE_R600                          = 414, // R600Instructions.td:1321
    CF_END_CM                             = 415, // CaymanInstructions.td:66
    CF_END_EG                             = 416, // EvergreenInstructions.td:859
    CF_END_R600                           = 417, // R600Instructions.td:1334
    CF_JUMP_EG                            = 418, // EvergreenInstructions.td:838
    CF_JUMP_R600                          = 419, // R600Instructions.td:1312
    CF_PUSH_EG                            = 420, // EvergreenInstructions.td:842
    CF_PUSH_ELSE_R600                     = 421, // R600Instructions.td:1316
    CF_TC_EG                              = 422, // EvergreenInstructions.td:811
    CF_TC_R600                            = 423, // R600Instructions.td:1285
    CF_VC_EG                              = 424, // EvergreenInstructions.td:815
    CF_VC_R600                            = 425, // R600Instructions.td:1289
    CNDE_INT                              = 426, // R600Instructions.td:890
    CNDE_eg                               = 427, // EvergreenInstructions.td:511
    CNDE_r600                             = 428, // R600Instructions.td:1235
    CNDGE_INT                             = 429, // R600Instructions.td:895
    CNDGE_eg                              = 430, // EvergreenInstructions.td:513
    CNDGE_r600                            = 431, // R600Instructions.td:1237
    CNDGT_INT                             = 432, // R600Instructions.td:900
    CNDGT_eg                              = 433, // EvergreenInstructions.td:512
    CNDGT_r600                            = 434, // R600Instructions.td:1236
    COS_cm                                = 435, // CaymanInstructions.td:48
    COS_eg                                = 436, // EvergreenInstructions.td:132
    COS_r600                              = 437, // R600Instructions.td:1252
    COS_r700                              = 438, // R700Instructions.td:19
    CUBE_eg_real                          = 439, // R600Instructions.td:1085
    CUBE_r600_real                        = 440, // R600Instructions.td:1085
    DOT4_eg                               = 441, // EvergreenInstructions.td:519
    DOT4_r600                             = 442, // R600Instructions.td:1238
    EG_ExportBuf                          = 443, // EvergreenInstructions.td:801
    EG_ExportSwz                          = 444, // EvergreenInstructions.td:791
    END_LOOP_EG                           = 445, // EvergreenInstructions.td:824
    END_LOOP_R600                         = 446, // R600Instructions.td:1298
    EXP_IEEE_cm                           = 447, // CaymanInstructions.td:43
    EXP_IEEE_eg                           = 448, // EvergreenInstructions.td:125
    EXP_IEEE_r600                         = 449, // R600Instructions.td:1240
    FETCH_CLAUSE                          = 450, // R600Instructions.td:638
    FFBH_UINT                             = 451, // EvergreenInstructions.td:529
    FFBL_INT                              = 452, // EvergreenInstructions.td:530
    FLOOR                                 = 453, // R600Instructions.td:783
    FLT16_TO_FLT32                        = 454, // EvergreenInstructions.td:527
    FLT32_TO_FLT16                        = 455, // EvergreenInstructions.td:526
    FLT_TO_INT_eg                         = 456, // EvergreenInstructions.td:536
    FLT_TO_INT_r600                       = 457, // R600Instructions.td:1247
    FLT_TO_UINT_eg                        = 458, // EvergreenInstructions.td:543
    FLT_TO_UINT_r600                      = 459, // R600Instructions.td:1249
    FMA_eg                                = 460, // EvergreenInstructions.td:507
    FRACT                                 = 461, // R600Instructions.td:779
    GROUP_BARRIER                         = 462, // EvergreenInstructions.td:549
    INTERP_LOAD_P0                        = 463, // R600Instructions.td:445
    INTERP_PAIR_XY                        = 464, // R600Instructions.td:367
    INTERP_PAIR_ZW                        = 465, // R600Instructions.td:373
    INTERP_VEC_LOAD                       = 466, // R600Instructions.td:430
    INTERP_XY                             = 467, // R600Instructions.td:437
    INTERP_ZW                             = 468, // R600Instructions.td:441
    INT_TO_FLT_eg                         = 469, // EvergreenInstructions.td:541
    INT_TO_FLT_r600                       = 470, // R600Instructions.td:1248
    KILLGT                                = 471, // R600Instructions.td:840
    LDS_ADD                               = 472, // EvergreenInstructions.td:687
    LDS_ADD_RET                           = 473, // EvergreenInstructions.td:707
    LDS_AND                               = 474, // EvergreenInstructions.td:689
    LDS_AND_RET                           = 475, // EvergreenInstructions.td:713
    LDS_BYTE_READ_RET                     = 476, // EvergreenInstructions.td:743
    LDS_BYTE_WRITE                        = 477, // EvergreenInstructions.td:701
    LDS_CMPST                             = 478, // EvergreenInstructions.td:693
    LDS_CMPST_RET                         = 479, // EvergreenInstructions.td:737
    LDS_MAX_INT                           = 480, // EvergreenInstructions.td:695
    LDS_MAX_INT_RET                       = 481, // EvergreenInstructions.td:725
    LDS_MAX_UINT                          = 482, // EvergreenInstructions.td:697
    LDS_MAX_UINT_RET                      = 483, // EvergreenInstructions.td:731
    LDS_MIN_INT                           = 484, // EvergreenInstructions.td:694
    LDS_MIN_INT_RET                       = 485, // EvergreenInstructions.td:722
    LDS_MIN_UINT                          = 486, // EvergreenInstructions.td:696
    LDS_MIN_UINT_RET                      = 487, // EvergreenInstructions.td:728
    LDS_OR                                = 488, // EvergreenInstructions.td:690
    LDS_OR_RET                            = 489, // EvergreenInstructions.td:716
    LDS_READ_RET                          = 490, // EvergreenInstructions.td:740
    LDS_SHORT_READ_RET                    = 491, // EvergreenInstructions.td:749
    LDS_SHORT_WRITE                       = 492, // EvergreenInstructions.td:704
    LDS_SUB                               = 493, // EvergreenInstructions.td:688
    LDS_SUB_RET                           = 494, // EvergreenInstructions.td:710
    LDS_UBYTE_READ_RET                    = 495, // EvergreenInstructions.td:746
    LDS_USHORT_READ_RET                   = 496, // EvergreenInstructions.td:752
    LDS_WRITE                             = 497, // EvergreenInstructions.td:698
    LDS_WRXCHG                            = 498, // EvergreenInstructions.td:692
    LDS_WRXCHG_RET                        = 499, // EvergreenInstructions.td:734
    LDS_XOR                               = 500, // EvergreenInstructions.td:691
    LDS_XOR_RET                           = 501, // EvergreenInstructions.td:719
    LITERALS                              = 502, // R600Instructions.td:654
    LOG_CLAMPED_eg                        = 503, // EvergreenInstructions.td:515
    LOG_CLAMPED_r600                      = 504, // R600Instructions.td:1241
    LOG_IEEE_cm                           = 505, // CaymanInstructions.td:44
    LOG_IEEE_eg                           = 506, // EvergreenInstructions.td:126
    LOG_IEEE_r600                         = 507, // R600Instructions.td:1242
    LOOP_BREAK_EG                         = 508, // EvergreenInstructions.td:828
    LOOP_BREAK_R600                       = 509, // R600Instructions.td:1302
    LSHL_eg                               = 510, // EvergreenInstructions.td:510
    LSHL_r600                             = 511, // R600Instructions.td:1255
    LSHR_eg                               = 512, // EvergreenInstructions.td:509
    LSHR_r600                             = 513, // R600Instructions.td:1254
    MAX                                   = 514, // R600Instructions.td:726
    MAX_DX10                              = 515, // R600Instructions.td:731
    MAX_INT                               = 516, // R600Instructions.td:850
    MAX_UINT                              = 517, // R600Instructions.td:852
    MIN                                   = 518, // R600Instructions.td:727
    MIN_DX10                              = 519, // R600Instructions.td:732
    MIN_INT                               = 520, // R600Instructions.td:851
    MIN_UINT                              = 521, // R600Instructions.td:853
    MOV                                   = 522, // R600Instructions.td:785
    MOVA_INT_eg                           = 523, // EvergreenInstructions.td:533
    MUL                                   = 524, // R600Instructions.td:723
    MULADD_IEEE_eg                        = 525, // EvergreenInstructions.td:506
    MULADD_IEEE_r600                      = 526, // R600Instructions.td:1234
    MULADD_INT24_cm                       = 527, // CaymanInstructions.td:22
    MULADD_UINT24_eg                      = 528, // EvergreenInstructions.td:494
    MULADD_eg                             = 529, // EvergreenInstructions.td:505
    MULADD_r600                           = 530, // R600Instructions.td:1233
    MULHI_INT_cm                          = 531, // CaymanInstructions.td:36
    MULHI_INT_cm24                        = 532, // CaymanInstructions.td:39
    MULHI_INT_eg                          = 533, // EvergreenInstructions.td:118
    MULHI_INT_r600                        = 534, // R600Instructions.td:1257
    MULHI_UINT24_eg                       = 535, // EvergreenInstructions.td:121
    MULHI_UINT_cm                         = 536, // CaymanInstructions.td:38
    MULHI_UINT_cm24                       = 537, // CaymanInstructions.td:40
    MULHI_UINT_eg                         = 538, // EvergreenInstructions.td:120
    MULHI_UINT_r600                       = 539, // R600Instructions.td:1259
    MULLO_INT_cm                          = 540, // CaymanInstructions.td:35
    MULLO_INT_eg                          = 541, // EvergreenInstructions.td:117
    MULLO_INT_r600                        = 542, // R600Instructions.td:1256
    MULLO_UINT_cm                         = 543, // CaymanInstructions.td:37
    MULLO_UINT_eg                         = 544, // EvergreenInstructions.td:119
    MULLO_UINT_r600                       = 545, // R600Instructions.td:1258
    MUL_IEEE                              = 546, // R600Instructions.td:724
    MUL_INT24_cm                          = 547, // CaymanInstructions.td:25
    MUL_LIT_eg                            = 548, // EvergreenInstructions.td:514
    MUL_LIT_r600                          = 549, // R600Instructions.td:1232
    MUL_UINT24_eg                         = 550, // EvergreenInstructions.td:516
    NOT_INT                               = 551, // R600Instructions.td:847
    OR_INT                                = 552, // R600Instructions.td:845
    PAD                                   = 553, // R600Instructions.td:666
    POP_EG                                = 554, // EvergreenInstructions.td:855
    POP_R600                              = 555, // R600Instructions.td:1330
    PRED_SETE                             = 556, // R600Instructions.td:833
    PRED_SETE_INT                         = 557, // R600Instructions.td:885
    PRED_SETGE                            = 558, // R600Instructions.td:835
    PRED_SETGE_INT                        = 559, // R600Instructions.td:887
    PRED_SETGT                            = 560, // R600Instructions.td:834
    PRED_SETGT_INT                        = 561, // R600Instructions.td:886
    PRED_SETNE                            = 562, // R600Instructions.td:836
    PRED_SETNE_INT                        = 563, // R600Instructions.td:888
    R600_ExportBuf                        = 564, // R600Instructions.td:1276
    R600_ExportSwz                        = 565, // R600Instructions.td:1267
    RAT_ATOMIC_ADD_NORET                  = 566, // EvergreenInstructions.td:82
    RAT_ATOMIC_ADD_RTN                    = 567, // EvergreenInstructions.td:78
    RAT_ATOMIC_AND_NORET                  = 568, // EvergreenInstructions.td:82
    RAT_ATOMIC_AND_RTN                    = 569, // EvergreenInstructions.td:78
    RAT_ATOMIC_CMPXCHG_INT_NORET          = 570, // EvergreenInstructions.td:82
    RAT_ATOMIC_CMPXCHG_INT_RTN            = 571, // EvergreenInstructions.td:78
    RAT_ATOMIC_DEC_UINT_NORET             = 572, // EvergreenInstructions.td:82
    RAT_ATOMIC_DEC_UINT_RTN               = 573, // EvergreenInstructions.td:78
    RAT_ATOMIC_INC_UINT_NORET             = 574, // EvergreenInstructions.td:82
    RAT_ATOMIC_INC_UINT_RTN               = 575, // EvergreenInstructions.td:78
    RAT_ATOMIC_MAX_INT_NORET              = 576, // EvergreenInstructions.td:82
    RAT_ATOMIC_MAX_INT_RTN                = 577, // EvergreenInstructions.td:78
    RAT_ATOMIC_MAX_UINT_NORET             = 578, // EvergreenInstructions.td:82
    RAT_ATOMIC_MAX_UINT_RTN               = 579, // EvergreenInstructions.td:78
    RAT_ATOMIC_MIN_INT_NORET              = 580, // EvergreenInstructions.td:82
    RAT_ATOMIC_MIN_INT_RTN                = 581, // EvergreenInstructions.td:78
    RAT_ATOMIC_MIN_UINT_NORET             = 582, // EvergreenInstructions.td:82
    RAT_ATOMIC_MIN_UINT_RTN               = 583, // EvergreenInstructions.td:78
    RAT_ATOMIC_OR_NORET                   = 584, // EvergreenInstructions.td:82
    RAT_ATOMIC_OR_RTN                     = 585, // EvergreenInstructions.td:78
    RAT_ATOMIC_RSUB_NORET                 = 586, // EvergreenInstructions.td:82
    RAT_ATOMIC_RSUB_RTN                   = 587, // EvergreenInstructions.td:78
    RAT_ATOMIC_SUB_NORET                  = 588, // EvergreenInstructions.td:82
    RAT_ATOMIC_SUB_RTN                    = 589, // EvergreenInstructions.td:78
    RAT_ATOMIC_XCHG_INT_NORET             = 590, // EvergreenInstructions.td:82
    RAT_ATOMIC_XCHG_INT_RTN               = 591, // EvergreenInstructions.td:78
    RAT_ATOMIC_XOR_NORET                  = 592, // EvergreenInstructions.td:82
    RAT_ATOMIC_XOR_RTN                    = 593, // EvergreenInstructions.td:78
    RAT_MSKOR                             = 594, // EvergreenInstructions.td:67
    RAT_STORE_DWORD128                    = 595, // CaymanInstructions.td:84
    RAT_STORE_DWORD32                     = 596, // CaymanInstructions.td:82
    RAT_STORE_DWORD64                     = 597, // CaymanInstructions.td:83
    RAT_STORE_TYPED_cm                    = 598, // CaymanInstructions.td:86
    RAT_STORE_TYPED_eg                    = 599, // EvergreenInstructions.td:164
    RAT_WRITE_CACHELESS_128_eg            = 600, // EvergreenInstructions.td:158
    RAT_WRITE_CACHELESS_32_eg             = 601, // EvergreenInstructions.td:144
    RAT_WRITE_CACHELESS_64_eg             = 602, // EvergreenInstructions.td:151
    RECIPSQRT_CLAMPED_cm                  = 603, // CaymanInstructions.td:42
    RECIPSQRT_CLAMPED_eg                  = 604, // EvergreenInstructions.td:124
    RECIPSQRT_CLAMPED_r600                = 605, // R600Instructions.td:1245
    RECIPSQRT_IEEE_cm                     = 606, // CaymanInstructions.td:46
    RECIPSQRT_IEEE_eg                     = 607, // EvergreenInstructions.td:128
    RECIPSQRT_IEEE_r600                   = 608, // R600Instructions.td:1246
    RECIP_CLAMPED_cm                      = 609, // CaymanInstructions.td:45
    RECIP_CLAMPED_eg                      = 610, // EvergreenInstructions.td:127
    RECIP_CLAMPED_r600                    = 611, // R600Instructions.td:1243
    RECIP_IEEE_cm                         = 612, // CaymanInstructions.td:33
    RECIP_IEEE_eg                         = 613, // EvergreenInstructions.td:114
    RECIP_IEEE_r600                       = 614, // R600Instructions.td:1244
    RECIP_UINT_eg                         = 615, // EvergreenInstructions.td:123
    RECIP_UINT_r600                       = 616, // R600Instructions.td:1260
    RNDNE                                 = 617, // R600Instructions.td:782
    SETE                                  = 618, // R600Instructions.td:737
    SETE_DX10                             = 619, // R600Instructions.td:757
    SETE_INT                              = 620, // R600Instructions.td:855
    SETGE_DX10                            = 621, // R600Instructions.td:767
    SETGE_INT                             = 622, // R600Instructions.td:865
    SETGE_UINT                            = 623, // R600Instructions.td:880
    SETGT_DX10                            = 624, // R600Instructions.td:762
    SETGT_INT                             = 625, // R600Instructions.td:860
    SETGT_UINT                            = 626, // R600Instructions.td:875
    SETNE_DX10                            = 627, // R600Instructions.td:773
    SETNE_INT                             = 628, // R600Instructions.td:870
    SGE                                   = 629, // R600Instructions.td:747
    SGT                                   = 630, // R600Instructions.td:742
    SIN_cm                                = 631, // CaymanInstructions.td:47
    SIN_eg                                = 632, // EvergreenInstructions.td:131
    SIN_r600                              = 633, // R600Instructions.td:1251
    SIN_r700                              = 634, // R700Instructions.td:18
    SNE                                   = 635, // R600Instructions.td:752
    SUBB_UINT                             = 636, // EvergreenInstructions.td:524
    SUB_INT                               = 637, // R600Instructions.td:849
    TEX_GET_GRADIENTS_H                   = 638, // R600Instructions.td:959
    TEX_GET_GRADIENTS_V                   = 639, // R600Instructions.td:960
    TEX_GET_TEXTURE_RESINFO               = 640, // R600Instructions.td:958
    TEX_LD                                = 641, // R600Instructions.td:954
    TEX_LDPTR                             = 642, // R600Instructions.td:955
    TEX_SAMPLE                            = 643, // R600Instructions.td:948
    TEX_SAMPLE_C                          = 644, // R600Instructions.td:949
    TEX_SAMPLE_C_G                        = 645, // R600Instructions.td:964
    TEX_SAMPLE_C_L                        = 646, // R600Instructions.td:951
    TEX_SAMPLE_C_LB                       = 647, // R600Instructions.td:953
    TEX_SAMPLE_G                          = 648, // R600Instructions.td:963
    TEX_SAMPLE_L                          = 649, // R600Instructions.td:950
    TEX_SAMPLE_LB                         = 650, // R600Instructions.td:952
    TEX_SET_GRADIENTS_H                   = 651, // R600Instructions.td:961
    TEX_SET_GRADIENTS_V                   = 652, // R600Instructions.td:962
    TEX_VTX_CONSTBUF                      = 653, // R600Instructions.td:1451
    TEX_VTX_TEXBUF                        = 654, // R600Instructions.td:1505
    TRUNC                                 = 655, // R600Instructions.td:780
    UINT_TO_FLT_eg                        = 656, // EvergreenInstructions.td:547
    UINT_TO_FLT_r600                      = 657, // R600Instructions.td:1250
    VTX_READ_128_cm                       = 658, // CaymanInstructions.td:162
    VTX_READ_128_eg                       = 659, // EvergreenInstructions.td:240
    VTX_READ_16_cm                        = 660, // CaymanInstructions.td:120
    VTX_READ_16_eg                        = 661, // EvergreenInstructions.td:195
    VTX_READ_32_cm                        = 662, // CaymanInstructions.td:131
    VTX_READ_32_eg                        = 663, // EvergreenInstructions.td:207
    VTX_READ_64_cm                        = 664, // CaymanInstructions.td:151
    VTX_READ_64_eg                        = 665, // EvergreenInstructions.td:228
    VTX_READ_8_cm                         = 666, // CaymanInstructions.td:109
    VTX_READ_8_eg                         = 667, // EvergreenInstructions.td:183
    WHILE_LOOP_EG                         = 668, // EvergreenInstructions.td:819
    WHILE_LOOP_R600                       = 669, // R600Instructions.td:1293
    XOR_INT                               = 670, // R600Instructions.td:846
    INSTRUCTION_LIST_END = 671
  };

} // namespace llvm_ks::R600

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::R600::Sched {

  enum {
    NoInstrModel	= 0,
    NullALU	= 1,
    VecALU	= 2,
    AnyALU	= 3,
    TransALU	= 4,
    XALU	= 5,
    SCHED_LIST_END = 6
  };

} // namespace llvm_ks::R600::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct R600InstrTable {
  MCInstrDesc Insts[671];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[1];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[461];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof R600InstrTable::ImplicitOps + sizeof R600InstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned R600OpInfoBase = (sizeof R600InstrTable::ImplicitOps + sizeof R600InstrTable::Padding) / sizeof(MCOperandInfo);

extern const R600InstrTable R600Descs = {
  {
    { 670,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // XOR_INT
    { 669,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WHILE_LOOP_R600
    { 668,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WHILE_LOOP_EG
    { 667,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 449,	0,	0|(1ULL<<MCID::MayLoad), 0x1000ULL },  // VTX_READ_8_eg
    { 666,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 449,	0,	0|(1ULL<<MCID::MayLoad), 0x1000ULL },  // VTX_READ_8_cm
    { 665,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 457,	0,	0|(1ULL<<MCID::MayLoad), 0x1000ULL },  // VTX_READ_64_eg
    { 664,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 457,	0,	0|(1ULL<<MCID::MayLoad), 0x1000ULL },  // VTX_READ_64_cm
    { 663,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 453,	0,	0|(1ULL<<MCID::MayLoad), 0x1000ULL },  // VTX_READ_32_eg
    { 662,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 453,	0,	0|(1ULL<<MCID::MayLoad), 0x1000ULL },  // VTX_READ_32_cm
    { 661,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 449,	0,	0|(1ULL<<MCID::MayLoad), 0x1000ULL },  // VTX_READ_16_eg
    { 660,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 449,	0,	0|(1ULL<<MCID::MayLoad), 0x1000ULL },  // VTX_READ_16_cm
    { 659,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 445,	0,	0|(1ULL<<MCID::MayLoad), 0x1000ULL },  // VTX_READ_128_eg
    { 658,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 445,	0,	0|(1ULL<<MCID::MayLoad), 0x1000ULL },  // VTX_READ_128_cm
    { 657,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // UINT_TO_FLT_r600
    { 656,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // UINT_TO_FLT_eg
    { 655,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // TRUNC
    { 654,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 445,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1000ULL },  // TEX_VTX_TEXBUF
    { 653,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 445,	0,	0, 0x1000ULL },  // TEX_VTX_CONSTBUF
    { 652,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_SET_GRADIENTS_V
    { 651,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_SET_GRADIENTS_H
    { 650,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_SAMPLE_LB
    { 649,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_SAMPLE_L
    { 648,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_SAMPLE_G
    { 647,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_SAMPLE_C_LB
    { 646,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_SAMPLE_C_L
    { 645,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_SAMPLE_C_G
    { 644,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_SAMPLE_C
    { 643,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_SAMPLE
    { 642,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_LDPTR
    { 641,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_LD
    { 640,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_GET_TEXTURE_RESINFO
    { 639,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_GET_GRADIENTS_V
    { 638,	19,	1,	0,	1,	0,	0,	R600OpInfoBase + 426,	0,	0, 0x2000ULL },  // TEX_GET_GRADIENTS_H
    { 637,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SUB_INT
    { 636,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SUBB_UINT
    { 635,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SNE
    { 634,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4610ULL },  // SIN_r700
    { 633,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4610ULL },  // SIN_r600
    { 632,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4610ULL },  // SIN_eg
    { 631,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4650ULL },  // SIN_cm
    { 630,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SGT
    { 629,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SGE
    { 628,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETNE_INT
    { 627,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETNE_DX10
    { 626,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETGT_UINT
    { 625,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETGT_INT
    { 624,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETGT_DX10
    { 623,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETGE_UINT
    { 622,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETGE_INT
    { 621,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETGE_DX10
    { 620,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETE_INT
    { 619,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETE_DX10
    { 618,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // SETE
    { 617,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RNDNE
    { 616,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RECIP_UINT_r600
    { 615,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RECIP_UINT_eg
    { 614,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RECIP_IEEE_r600
    { 613,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RECIP_IEEE_eg
    { 612,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4640ULL },  // RECIP_IEEE_cm
    { 611,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RECIP_CLAMPED_r600
    { 610,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RECIP_CLAMPED_eg
    { 609,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4640ULL },  // RECIP_CLAMPED_cm
    { 608,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RECIPSQRT_IEEE_r600
    { 607,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RECIPSQRT_IEEE_eg
    { 606,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4640ULL },  // RECIPSQRT_IEEE_cm
    { 605,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RECIPSQRT_CLAMPED_r600
    { 604,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // RECIPSQRT_CLAMPED_eg
    { 603,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4640ULL },  // RECIPSQRT_CLAMPED_cm
    { 602,	3,	0,	0,	1,	0,	0,	R600OpInfoBase + 423,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x20000ULL },  // RAT_WRITE_CACHELESS_64_eg
    { 601,	3,	0,	0,	1,	0,	0,	R600OpInfoBase + 420,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x20000ULL },  // RAT_WRITE_CACHELESS_32_eg
    { 600,	3,	0,	0,	1,	0,	0,	R600OpInfoBase + 417,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x20000ULL },  // RAT_WRITE_CACHELESS_128_eg
    { 599,	4,	0,	0,	1,	0,	0,	R600OpInfoBase + 413,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_STORE_TYPED_eg
    { 598,	4,	0,	0,	1,	0,	0,	R600OpInfoBase + 413,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_STORE_TYPED_cm
    { 597,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 411,	0,	0|(1ULL<<MCID::MayStore), 0x20000ULL },  // RAT_STORE_DWORD64
    { 596,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 409,	0,	0|(1ULL<<MCID::MayStore), 0x20000ULL },  // RAT_STORE_DWORD32
    { 595,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 407,	0,	0|(1ULL<<MCID::MayStore), 0x20000ULL },  // RAT_STORE_DWORD128
    { 594,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 407,	0,	0|(1ULL<<MCID::MayStore), 0x20000ULL },  // RAT_MSKOR
    { 593,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_XOR_RTN
    { 592,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_XOR_NORET
    { 591,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_XCHG_INT_RTN
    { 590,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_XCHG_INT_NORET
    { 589,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_SUB_RTN
    { 588,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_SUB_NORET
    { 587,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_RSUB_RTN
    { 586,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_RSUB_NORET
    { 585,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_OR_RTN
    { 584,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_OR_NORET
    { 583,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_MIN_UINT_RTN
    { 582,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_MIN_UINT_NORET
    { 581,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_MIN_INT_RTN
    { 580,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_MIN_INT_NORET
    { 579,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_MAX_UINT_RTN
    { 578,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_MAX_UINT_NORET
    { 577,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_MAX_INT_RTN
    { 576,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_MAX_INT_NORET
    { 575,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_INC_UINT_RTN
    { 574,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_INC_UINT_NORET
    { 573,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_DEC_UINT_RTN
    { 572,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_DEC_UINT_NORET
    { 571,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_CMPXCHG_INT_RTN
    { 570,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_CMPXCHG_INT_NORET
    { 569,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_AND_RTN
    { 568,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_AND_NORET
    { 567,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_ADD_RTN
    { 566,	3,	1,	0,	1,	0,	0,	R600OpInfoBase + 404,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // RAT_ATOMIC_ADD_NORET
    { 565,	9,	0,	0,	1,	0,	0,	R600OpInfoBase + 332,	0,	0|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // R600_ExportSwz
    { 564,	7,	0,	0,	1,	0,	0,	R600OpInfoBase + 325,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // R600_ExportBuf
    { 563,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // PRED_SETNE_INT
    { 562,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // PRED_SETNE
    { 561,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // PRED_SETGT_INT
    { 560,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // PRED_SETGT
    { 559,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // PRED_SETGE_INT
    { 558,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // PRED_SETGE
    { 557,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // PRED_SETE_INT
    { 556,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // PRED_SETE
    { 555,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // POP_R600
    { 554,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // POP_EG
    { 553,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PAD
    { 552,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // OR_INT
    { 551,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // NOT_INT
    { 550,	21,	1,	0,	2,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MUL_UINT24_eg
    { 549,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // MUL_LIT_r600
    { 548,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // MUL_LIT_eg
    { 547,	21,	1,	0,	2,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MUL_INT24_cm
    { 546,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MUL_IEEE
    { 545,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MULLO_UINT_r600
    { 544,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MULLO_UINT_eg
    { 543,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a40ULL },  // MULLO_UINT_cm
    { 542,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MULLO_INT_r600
    { 541,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MULLO_INT_eg
    { 540,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a40ULL },  // MULLO_INT_cm
    { 539,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MULHI_UINT_r600
    { 538,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MULHI_UINT_eg
    { 537,	21,	1,	0,	2,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a40ULL },  // MULHI_UINT_cm24
    { 536,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a40ULL },  // MULHI_UINT_cm
    { 535,	21,	1,	0,	2,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MULHI_UINT24_eg
    { 534,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MULHI_INT_r600
    { 533,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MULHI_INT_eg
    { 532,	21,	1,	0,	2,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a40ULL },  // MULHI_INT_cm24
    { 531,	21,	1,	0,	4,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a40ULL },  // MULHI_INT_cm
    { 530,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // MULADD_r600
    { 529,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // MULADD_eg
    { 528,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // MULADD_UINT24_eg
    { 527,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // MULADD_INT24_cm
    { 526,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // MULADD_IEEE_r600
    { 525,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // MULADD_IEEE_eg
    { 524,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MUL
    { 523,	14,	1,	0,	2,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x4600ULL },  // MOVA_INT_eg
    { 522,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // MOV
    { 521,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MIN_UINT
    { 520,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MIN_INT
    { 519,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MIN_DX10
    { 518,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MIN
    { 517,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MAX_UINT
    { 516,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MAX_INT
    { 515,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MAX_DX10
    { 514,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // MAX
    { 513,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // LSHR_r600
    { 512,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // LSHR_eg
    { 511,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // LSHL_r600
    { 510,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // LSHL_eg
    { 509,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LOOP_BREAK_R600
    { 508,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LOOP_BREAK_EG
    { 507,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // LOG_IEEE_r600
    { 506,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // LOG_IEEE_eg
    { 505,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4640ULL },  // LOG_IEEE_cm
    { 504,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // LOG_CLAMPED_r600
    { 503,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // LOG_CLAMPED_eg
    { 502,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 9,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LITERALS
    { 501,	10,	1,	0,	5,	0,	0,	R600OpInfoBase + 362,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x14200ULL },  // LDS_XOR_RET
    { 500,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x14200ULL },  // LDS_XOR
    { 499,	10,	1,	0,	5,	0,	0,	R600OpInfoBase + 362,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x14200ULL },  // LDS_WRXCHG_RET
    { 498,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x14200ULL },  // LDS_WRXCHG
    { 497,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x14200ULL },  // LDS_WRITE
    { 496,	7,	1,	0,	5,	0,	0,	R600OpInfoBase + 372,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0xc200ULL },  // LDS_USHORT_READ_RET
    { 495,	7,	1,	0,	5,	0,	0,	R600OpInfoBase + 372,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0xc200ULL },  // LDS_UBYTE_READ_RET
    { 494,	10,	1,	0,	5,	0,	0,	R600OpInfoBase + 362,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x14200ULL },  // LDS_SUB_RET
    { 493,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x14200ULL },  // LDS_SUB
    { 492,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x14200ULL },  // LDS_SHORT_WRITE
    { 491,	7,	1,	0,	5,	0,	0,	R600OpInfoBase + 372,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0xc200ULL },  // LDS_SHORT_READ_RET
    { 490,	7,	1,	0,	5,	0,	0,	R600OpInfoBase + 372,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0xc200ULL },  // LDS_READ_RET
    { 489,	10,	1,	0,	5,	0,	0,	R600OpInfoBase + 362,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x14200ULL },  // LDS_OR_RET
    { 488,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x14200ULL },  // LDS_OR
    { 487,	10,	1,	0,	5,	0,	0,	R600OpInfoBase + 362,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x14200ULL },  // LDS_MIN_UINT_RET
    { 486,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x14200ULL },  // LDS_MIN_UINT
    { 485,	10,	1,	0,	5,	0,	0,	R600OpInfoBase + 362,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x14200ULL },  // LDS_MIN_INT_RET
    { 484,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x14200ULL },  // LDS_MIN_INT
    { 483,	10,	1,	0,	5,	0,	0,	R600OpInfoBase + 362,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x14200ULL },  // LDS_MAX_UINT_RET
    { 482,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x14200ULL },  // LDS_MAX_UINT
    { 481,	10,	1,	0,	5,	0,	0,	R600OpInfoBase + 362,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x14200ULL },  // LDS_MAX_INT_RET
    { 480,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x14200ULL },  // LDS_MAX_INT
    { 479,	13,	1,	0,	5,	0,	0,	R600OpInfoBase + 391,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x44200ULL },  // LDS_CMPST_RET
    { 478,	12,	0,	0,	5,	0,	0,	R600OpInfoBase + 379,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x44200ULL },  // LDS_CMPST
    { 477,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable), 0x14200ULL },  // LDS_BYTE_WRITE
    { 476,	7,	1,	0,	5,	0,	0,	R600OpInfoBase + 372,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0xc200ULL },  // LDS_BYTE_READ_RET
    { 475,	10,	1,	0,	5,	0,	0,	R600OpInfoBase + 362,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x14200ULL },  // LDS_AND_RET
    { 474,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x14200ULL },  // LDS_AND
    { 473,	10,	1,	0,	5,	0,	0,	R600OpInfoBase + 362,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UsesCustomInserter), 0x14200ULL },  // LDS_ADD_RET
    { 472,	9,	0,	0,	5,	0,	0,	R600OpInfoBase + 353,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x14200ULL },  // LDS_ADD
    { 471,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x4a00ULL },  // KILLGT
    { 470,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // INT_TO_FLT_r600
    { 469,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // INT_TO_FLT_eg
    { 468,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // INTERP_ZW
    { 467,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // INTERP_XY
    { 466,	2,	1,	0,	1,	0,	0,	R600OpInfoBase + 351,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INTERP_VEC_LOAD
    { 465,	5,	2,	0,	1,	0,	0,	R600OpInfoBase + 346,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INTERP_PAIR_ZW
    { 464,	5,	2,	0,	1,	0,	0,	R600OpInfoBase + 341,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INTERP_PAIR_XY
    { 463,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // INTERP_LOAD_P0
    { 462,	0,	0,	0,	3,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x4000ULL },  // GROUP_BARRIER
    { 461,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // FRACT
    { 460,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // FMA_eg
    { 459,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // FLT_TO_UINT_r600
    { 458,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // FLT_TO_UINT_eg
    { 457,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // FLT_TO_INT_r600
    { 456,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // FLT_TO_INT_eg
    { 455,	14,	1,	0,	2,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // FLT32_TO_FLT16
    { 454,	14,	1,	0,	2,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // FLT16_TO_FLT32
    { 453,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // FLOOR
    { 452,	14,	1,	0,	2,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // FFBL_INT
    { 451,	14,	1,	0,	2,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // FFBH_UINT
    { 450,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FETCH_CLAUSE
    { 449,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // EXP_IEEE_r600
    { 448,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // EXP_IEEE_eg
    { 447,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4640ULL },  // EXP_IEEE_cm
    { 446,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // END_LOOP_R600
    { 445,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // END_LOOP_EG
    { 444,	9,	0,	0,	1,	0,	0,	R600OpInfoBase + 332,	0,	0|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // EG_ExportSwz
    { 443,	7,	0,	0,	1,	0,	0,	R600OpInfoBase + 325,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x20000ULL },  // EG_ExportBuf
    { 442,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // DOT4_r600
    { 441,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // DOT4_eg
    { 440,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // CUBE_r600_real
    { 439,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // CUBE_eg_real
    { 438,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4610ULL },  // COS_r700
    { 437,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4610ULL },  // COS_r600
    { 436,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4610ULL },  // COS_eg
    { 435,	14,	1,	0,	4,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4650ULL },  // COS_cm
    { 434,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // CNDGT_r600
    { 433,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // CNDGT_eg
    { 432,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // CNDGT_INT
    { 431,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // CNDGE_r600
    { 430,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // CNDGE_eg
    { 429,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // CNDGE_INT
    { 428,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // CNDE_r600
    { 427,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // CNDE_eg
    { 426,	19,	1,	0,	3,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // CNDE_INT
    { 425,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_VC_R600
    { 424,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_VC_EG
    { 423,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_TC_R600
    { 422,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_TC_EG
    { 421,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_PUSH_ELSE_R600
    { 420,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_PUSH_EG
    { 419,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_JUMP_R600
    { 418,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_JUMP_EG
    { 417,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_END_R600
    { 416,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_END_EG
    { 415,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_END_CM
    { 414,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_ELSE_R600
    { 413,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_ELSE_EG
    { 412,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_CONTINUE_R600
    { 411,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_CONTINUE_EG
    { 410,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_CALL_FS_R600
    { 409,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_CALL_FS_EG
    { 408,	9,	0,	0,	1,	0,	0,	R600OpInfoBase + 316,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_ALU_PUSH_BEFORE
    { 407,	9,	0,	0,	1,	0,	0,	R600OpInfoBase + 316,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_ALU_POP_AFTER
    { 406,	9,	0,	0,	1,	0,	0,	R600OpInfoBase + 316,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_ALU_ELSE_AFTER
    { 405,	9,	0,	0,	1,	0,	0,	R600OpInfoBase + 316,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_ALU_CONTINUE
    { 404,	9,	0,	0,	1,	0,	0,	R600OpInfoBase + 316,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_ALU_BREAK
    { 403,	9,	0,	0,	1,	0,	0,	R600OpInfoBase + 316,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CF_ALU
    { 402,	14,	1,	0,	3,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // CEIL
    { 401,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // BIT_ALIGN_INT_eg
    { 400,	21,	1,	0,	2,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // BFM_INT_eg
    { 399,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // BFI_INT_eg
    { 398,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // BFE_UINT_eg
    { 397,	19,	1,	0,	2,	0,	0,	R600OpInfoBase + 297,	0,	0|(1ULL<<MCID::Predicable), 0x4220ULL },  // BFE_INT_eg
    { 396,	14,	1,	0,	2,	0,	0,	R600OpInfoBase + 283,	0,	0|(1ULL<<MCID::Predicable), 0x4600ULL },  // BCNT_INT
    { 395,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // ASHR_r600
    { 394,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // ASHR_eg
    { 393,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // AND_INT
    { 392,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ALU_CLAUSE
    { 391,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // ADD_INT
    { 390,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // ADDC_UINT
    { 389,	21,	1,	0,	3,	0,	0,	R600OpInfoBase + 262,	0,	0|(1ULL<<MCID::Predicable), 0x4a00ULL },  // ADD
    { 388,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // WHILELOOP
    { 387,	7,	1,	0,	1,	0,	0,	R600OpInfoBase + 255,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2000ULL },  // TXD_SHADOW
    { 386,	7,	1,	0,	1,	0,	0,	R600OpInfoBase + 255,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x2000ULL },  // TXD
    { 385,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic), 0x0ULL },  // RETURN
    { 384,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // RETDYN
    { 383,	4,	0,	0,	1,	0,	0,	R600OpInfoBase + 251,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x4000000000000000ULL },  // R600_RegisterStore
    { 382,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 251,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x8000000000000000ULL },  // R600_RegisterLoad
    { 381,	4,	1,	0,	3,	0,	0,	R600OpInfoBase + 247,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // R600_INSERT_ELT_V4
    { 380,	4,	1,	0,	3,	0,	0,	R600OpInfoBase + 243,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // R600_INSERT_ELT_V2
    { 379,	3,	1,	0,	3,	0,	0,	R600OpInfoBase + 240,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // R600_EXTRACT_ELT_V4
    { 378,	3,	1,	0,	3,	0,	0,	R600OpInfoBase + 237,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // R600_EXTRACT_ELT_V2
    { 377,	4,	1,	0,	1,	0,	0,	R600OpInfoBase + 233,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x180ULL },  // PRED_X
    { 376,	2,	1,	0,	1,	0,	0,	R600OpInfoBase + 156,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MOV_IMM_I32
    { 375,	2,	1,	0,	1,	0,	0,	R600OpInfoBase + 156,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MOV_IMM_GLOBAL_ADDR
    { 374,	2,	1,	0,	1,	0,	0,	R600OpInfoBase + 156,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MOV_IMM_F32
    { 373,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MASK_WRITE
    { 372,	2,	0,	0,	3,	0,	0,	R600OpInfoBase + 231,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JUMP_COND
    { 371,	1,	0,	0,	3,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JUMP
    { 370,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // IF_PREDICATE_SET
    { 369,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // IF_LOGICALZ_i32
    { 368,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // IF_LOGICALZ_f32
    { 367,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // IF_LOGICALNZ_i32
    { 366,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // IF_LOGICALNZ_f32
    { 365,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 153,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // IFC_i32
    { 364,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 153,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // IFC_f32
    { 363,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // FUNC
    { 362,	2,	1,	0,	1,	0,	0,	R600OpInfoBase + 153,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // FNEG_R600
    { 361,	2,	1,	0,	1,	0,	0,	R600OpInfoBase + 153,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // FABS_R600
    { 360,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // ENDSWITCH
    { 359,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // ENDMAIN
    { 358,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // ENDLOOP
    { 357,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // ENDIF
    { 356,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // ENDFUNC
    { 355,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // END
    { 354,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // ELSE
    { 353,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // DUMMY_CHAIN
    { 352,	71,	1,	0,	3,	0,	0,	R600OpInfoBase + 160,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Predicable), 0x0ULL },  // DOT_4
    { 351,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // DEFAULT
    { 350,	2,	1,	0,	2,	0,	0,	R600OpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // CUBE_r600_pseudo
    { 349,	2,	1,	0,	2,	0,	0,	R600OpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // CUBE_eg_pseudo
    { 348,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // CONTINUE_LOGICALZ_i32
    { 347,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // CONTINUE_LOGICALZ_f32
    { 346,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // CONTINUE_LOGICALNZ_i32
    { 345,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // CONTINUE_LOGICALNZ_f32
    { 344,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 153,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // CONTINUEC_i32
    { 343,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 153,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // CONTINUEC_f32
    { 342,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // CONTINUE
    { 341,	2,	1,	0,	1,	0,	0,	R600OpInfoBase + 156,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // CONST_COPY
    { 340,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // BREAK_LOGICALZ_i32
    { 339,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // BREAK_LOGICALZ_f32
    { 338,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // BREAK_LOGICALNZ_i32
    { 337,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // BREAK_LOGICALNZ_f32
    { 336,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 153,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // BREAKC_i32
    { 335,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 153,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // BREAKC_f32
    { 334,	0,	0,	0,	1,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // BREAK
    { 333,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // BRANCH_COND_i32
    { 332,	2,	0,	0,	1,	0,	0,	R600OpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // BRANCH_COND_f32
    { 331,	1,	0,	0,	1,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // BRANCH
    { 330,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	R600OpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	R600OpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	R600OpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	R600OpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	R600OpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	R600OpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	R600OpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	R600OpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	R600OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	R600OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	R600OpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	R600OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	R600OpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	R600OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	R600OpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	R600OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	R600OpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	R600OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	R600OpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	R600OpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	R600OpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	R600OpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	R600OpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	R600OpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	R600OpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	R600OpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	R600OpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	R600OpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_13863
    { 41,	2,	0,	0,	0,	0,	0,	R600OpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_13862
    { 40,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	R600OpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_13861
    { 31,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	R600OpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	R600OpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	R600OpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	0,	0,	0,	R600OpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	0,	0,	0,	R600OpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	0,	0,	0,	R600OpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	R600OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	R600OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // PHI
  }, {
    /* 0 */
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
    /* 28 */ { R600::R600_AddrRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { R600::R600_AddrRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { R600::R600_AddrRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_AddrRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
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
    /* 151 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 153 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 155 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 156 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 158 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 160 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_TReg32_YRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_TReg32_YRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_TReg32_ZRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_TReg32_ZRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_TReg32_WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_TReg32_WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 231 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Predicate_BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 233 */ { R600::R600_Predicate_BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 237 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg64VerticalRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 240 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg128VerticalRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 243 */ { R600::R600_Reg64VerticalRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg64VerticalRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 247 */ { R600::R600_Reg128VerticalRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg128VerticalRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 251 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 255 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 262 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 283 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 297 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 316 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 325 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 332 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 341 */ { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_YRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { R600::R600_TReg32_YRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 346 */ { R600::R600_TReg32_ZRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_WRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { R600::R600_TReg32_YRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 351 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 353 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 362 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 372 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 379 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 391 */ { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_Reg32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { R600::R600_PredicateRegClassID, 0|(1<<MCOI::Predicate), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 404 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 407 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 409 */ { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 411 */ { R600::R600_Reg64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 413 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 417 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 420 */ { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 423 */ { R600::R600_Reg64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 426 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 445 */ { R600::R600_Reg128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 449 */ { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 453 */ { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_UNKNOWN, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 457 */ { R600::R600_Reg64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { R600::R600_TReg32_XRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
  }
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char R600InstrNameData[] = {
  /* 0 */ "CF_TC_R600\000"
  /* 11 */ "CF_VC_R600\000"
  /* 22 */ "CF_END_R600\000"
  /* 34 */ "CF_ELSE_R600\000"
  /* 47 */ "CF_PUSH_ELSE_R600\000"
  /* 65 */ "CF_CONTINUE_R600\000"
  /* 82 */ "FNEG_R600\000"
  /* 92 */ "LOOP_BREAK_R600\000"
  /* 108 */ "CF_JUMP_R600\000"
  /* 121 */ "END_LOOP_R600\000"
  /* 135 */ "WHILE_LOOP_R600\000"
  /* 151 */ "POP_R600\000"
  /* 160 */ "FABS_R600\000"
  /* 170 */ "CF_CALL_FS_R600\000"
  /* 186 */ "DOT4_r600\000"
  /* 196 */ "MULADD_r600\000"
  /* 208 */ "LOG_CLAMPED_r600\000"
  /* 225 */ "RECIP_CLAMPED_r600\000"
  /* 244 */ "RECIPSQRT_CLAMPED_r600\000"
  /* 267 */ "CNDE_r600\000"
  /* 277 */ "MULADD_IEEE_r600\000"
  /* 294 */ "LOG_IEEE_r600\000"
  /* 308 */ "RECIP_IEEE_r600\000"
  /* 324 */ "EXP_IEEE_r600\000"
  /* 338 */ "RECIPSQRT_IEEE_r600\000"
  /* 358 */ "CNDGE_r600\000"
  /* 369 */ "LSHL_r600\000"
  /* 379 */ "SIN_r600\000"
  /* 388 */ "ASHR_r600\000"
  /* 398 */ "LSHR_r600\000"
  /* 408 */ "COS_r600\000"
  /* 417 */ "CNDGT_r600\000"
  /* 428 */ "MUL_LIT_r600\000"
  /* 441 */ "UINT_TO_FLT_r600\000"
  /* 458 */ "MULHI_UINT_r600\000"
  /* 474 */ "MULLO_UINT_r600\000"
  /* 490 */ "FLT_TO_UINT_r600\000"
  /* 507 */ "RECIP_UINT_r600\000"
  /* 523 */ "MULHI_INT_r600\000"
  /* 538 */ "MULLO_INT_r600\000"
  /* 553 */ "FLT_TO_INT_r600\000"
  /* 569 */ "SIN_r700\000"
  /* 578 */ "COS_r700\000"
  /* 587 */ "G_FLOG10\000"
  /* 596 */ "G_FEXP10\000"
  /* 605 */ "SETGE_DX10\000"
  /* 616 */ "SETNE_DX10\000"
  /* 627 */ "SETE_DX10\000"
  /* 637 */ "MIN_DX10\000"
  /* 646 */ "SETGT_DX10\000"
  /* 657 */ "MAX_DX10\000"
  /* 666 */ "INTERP_LOAD_P0\000"
  /* 681 */ "RAT_STORE_DWORD32\000"
  /* 699 */ "MOV_IMM_F32\000"
  /* 711 */ "MOV_IMM_I32\000"
  /* 723 */ "FLT16_TO_FLT32\000"
  /* 738 */ "CONTINUEC_f32\000"
  /* 752 */ "IFC_f32\000"
  /* 760 */ "BREAKC_f32\000"
  /* 771 */ "BRANCH_COND_f32\000"
  /* 787 */ "CONTINUE_LOGICALZ_f32\000"
  /* 809 */ "IF_LOGICALZ_f32\000"
  /* 825 */ "BREAK_LOGICALZ_f32\000"
  /* 844 */ "CONTINUE_LOGICALNZ_f32\000"
  /* 867 */ "IF_LOGICALNZ_f32\000"
  /* 884 */ "BREAK_LOGICALNZ_f32\000"
  /* 904 */ "CONTINUEC_i32\000"
  /* 918 */ "IFC_i32\000"
  /* 926 */ "BREAKC_i32\000"
  /* 937 */ "BRANCH_COND_i32\000"
  /* 953 */ "CONTINUE_LOGICALZ_i32\000"
  /* 975 */ "IF_LOGICALZ_i32\000"
  /* 991 */ "BREAK_LOGICALZ_i32\000"
  /* 1010 */ "CONTINUE_LOGICALNZ_i32\000"
  /* 1033 */ "IF_LOGICALNZ_i32\000"
  /* 1050 */ "BREAK_LOGICALNZ_i32\000"
  /* 1070 */ "G_FLOG2\000"
  /* 1078 */ "G_FATAN2\000"
  /* 1087 */ "G_FEXP2\000"
  /* 1095 */ "R600_EXTRACT_ELT_V2\000"
  /* 1115 */ "R600_INSERT_ELT_V2\000"
  /* 1134 */ "MULHI_UINT_cm24\000"
  /* 1150 */ "MULHI_INT_cm24\000"
  /* 1165 */ "RAT_STORE_DWORD64\000"
  /* 1183 */ "R600_EXTRACT_ELT_V4\000"
  /* 1203 */ "R600_INSERT_ELT_V4\000"
  /* 1222 */ "DOT_4\000"
  /* 1228 */ "FLT32_TO_FLT16\000"
  /* 1243 */ "RAT_STORE_DWORD128\000"
  /* 1262 */ "G_FMA\000"
  /* 1268 */ "G_STRICT_FMA\000"
  /* 1281 */ "TEX_SAMPLE_C_LB\000"
  /* 1297 */ "TEX_SAMPLE_LB\000"
  /* 1311 */ "G_FSUB\000"
  /* 1318 */ "G_STRICT_FSUB\000"
  /* 1332 */ "G_ATOMICRMW_FSUB\000"
  /* 1349 */ "G_SUB\000"
  /* 1355 */ "LDS_SUB\000"
  /* 1363 */ "G_ATOMICRMW_SUB\000"
  /* 1379 */ "G_INTRINSIC\000"
  /* 1391 */ "ENDFUNC\000"
  /* 1399 */ "G_FPTRUNC\000"
  /* 1409 */ "G_INTRINSIC_TRUNC\000"
  /* 1427 */ "G_TRUNC\000"
  /* 1435 */ "G_BUILD_VECTOR_TRUNC\000"
  /* 1456 */ "G_DYN_STACKALLOC\000"
  /* 1473 */ "TEX_SAMPLE_C\000"
  /* 1486 */ "G_FMAD\000"
  /* 1493 */ "G_FPEXTLOAD\000"
  /* 1505 */ "G_INDEXED_SEXTLOAD\000"
  /* 1524 */ "G_SEXTLOAD\000"
  /* 1535 */ "G_INDEXED_ZEXTLOAD\000"
  /* 1554 */ "G_ZEXTLOAD\000"
  /* 1565 */ "INTERP_VEC_LOAD\000"
  /* 1581 */ "G_INDEXED_LOAD\000"
  /* 1596 */ "G_LOAD\000"
  /* 1603 */ "PAD\000"
  /* 1607 */ "G_VECREDUCE_FADD\000"
  /* 1624 */ "G_FADD\000"
  /* 1631 */ "G_VECREDUCE_SEQ_FADD\000"
  /* 1652 */ "G_STRICT_FADD\000"
  /* 1666 */ "G_ATOMICRMW_FADD\000"
  /* 1683 */ "G_VECREDUCE_ADD\000"
  /* 1699 */ "G_ADD\000"
  /* 1705 */ "G_PTR_ADD\000"
  /* 1715 */ "LDS_ADD\000"
  /* 1723 */ "G_ATOMICRMW_ADD\000"
  /* 1739 */ "TEX_LD\000"
  /* 1746 */ "G_ATOMICRMW_NAND\000"
  /* 1763 */ "G_VECREDUCE_AND\000"
  /* 1779 */ "G_AND\000"
  /* 1785 */ "LDS_AND\000"
  /* 1793 */ "G_ATOMICRMW_AND\000"
  /* 1809 */ "LIFETIME_END\000"
  /* 1822 */ "G_BRCOND\000"
  /* 1831 */ "G_ATOMICRMW_USUB_COND\000"
  /* 1853 */ "JUMP_COND\000"
  /* 1863 */ "G_LLROUND\000"
  /* 1873 */ "G_LROUND\000"
  /* 1882 */ "G_INTRINSIC_ROUND\000"
  /* 1900 */ "G_INTRINSIC_FPTRUNC_ROUND\000"
  /* 1926 */ "LOAD_STACK_GUARD\000"
  /* 1943 */ "TXD\000"
  /* 1947 */ "PSEUDO_PROBE\000"
  /* 1960 */ "G_SSUBE\000"
  /* 1968 */ "G_USUBE\000"
  /* 1976 */ "G_FENCE\000"
  /* 1984 */ "ARITH_FENCE\000"
  /* 1996 */ "REG_SEQUENCE\000"
  /* 2009 */ "G_SADDE\000"
  /* 2017 */ "G_UADDE\000"
  /* 2025 */ "G_GET_FPMODE\000"
  /* 2038 */ "G_RESET_FPMODE\000"
  /* 2053 */ "G_SET_FPMODE\000"
  /* 2066 */ "MUL_IEEE\000"
  /* 2075 */ "G_FMINNUM_IEEE\000"
  /* 2090 */ "G_FMAXNUM_IEEE\000"
  /* 2105 */ "SGE\000"
  /* 2109 */ "PRED_SETGE\000"
  /* 2120 */ "G_VSCALE\000"
  /* 2129 */ "G_JUMP_TABLE\000"
  /* 2142 */ "BUNDLE\000"
  /* 2149 */ "TEX_SAMPLE\000"
  /* 2160 */ "RNDNE\000"
  /* 2166 */ "G_MEMSET_INLINE\000"
  /* 2182 */ "G_MEMCPY_INLINE\000"
  /* 2198 */ "RELOC_NONE\000"
  /* 2209 */ "SNE\000"
  /* 2213 */ "PRED_SETNE\000"
  /* 2224 */ "LOCAL_ESCAPE\000"
  /* 2237 */ "CF_ALU_PUSH_BEFORE\000"
  /* 2256 */ "G_FPTRUNCSTORE\000"
  /* 2271 */ "G_STACKRESTORE\000"
  /* 2286 */ "G_INDEXED_STORE\000"
  /* 2302 */ "G_STORE\000"
  /* 2310 */ "ELSE\000"
  /* 2315 */ "G_BITREVERSE\000"
  /* 2328 */ "FETCH_CLAUSE\000"
  /* 2341 */ "ALU_CLAUSE\000"
  /* 2352 */ "FAKE_USE\000"
  /* 2361 */ "PRED_SETE\000"
  /* 2371 */ "LDS_BYTE_WRITE\000"
  /* 2386 */ "MASK_WRITE\000"
  /* 2397 */ "LDS_WRITE\000"
  /* 2407 */ "LDS_SHORT_WRITE\000"
  /* 2423 */ "DBG_VALUE\000"
  /* 2433 */ "G_GLOBAL_VALUE\000"
  /* 2448 */ "G_PTRAUTH_GLOBAL_VALUE\000"
  /* 2471 */ "CONVERGENCECTRL_GLUE\000"
  /* 2492 */ "CF_ALU_CONTINUE\000"
  /* 2508 */ "G_STACKSAVE\000"
  /* 2520 */ "G_MEMMOVE\000"
  /* 2530 */ "G_FREEZE\000"
  /* 2539 */ "G_FCANONICALIZE\000"
  /* 2555 */ "G_FMODF\000"
  /* 2563 */ "INIT_UNDEF\000"
  /* 2574 */ "G_IMPLICIT_DEF\000"
  /* 2589 */ "DBG_INSTR_REF\000"
  /* 2603 */ "ENDIF\000"
  /* 2609 */ "TEX_VTX_CONSTBUF\000"
  /* 2626 */ "TEX_VTX_TEXBUF\000"
  /* 2641 */ "G_FNEG\000"
  /* 2648 */ "EXTRACT_SUBREG\000"
  /* 2663 */ "INSERT_SUBREG\000"
  /* 2677 */ "G_SEXT_INREG\000"
  /* 2690 */ "SUBREG_TO_REG\000"
  /* 2704 */ "CF_TC_EG\000"
  /* 2713 */ "CF_VC_EG\000"
  /* 2722 */ "CF_END_EG\000"
  /* 2732 */ "CF_ELSE_EG\000"
  /* 2743 */ "CF_CONTINUE_EG\000"
  /* 2758 */ "CF_PUSH_EG\000"
  /* 2769 */ "LOOP_BREAK_EG\000"
  /* 2783 */ "CF_JUMP_EG\000"
  /* 2794 */ "END_LOOP_EG\000"
  /* 2806 */ "WHILE_LOOP_EG\000"
  /* 2820 */ "POP_EG\000"
  /* 2827 */ "CF_CALL_FS_EG\000"
  /* 2841 */ "G_ATOMIC_CMPXCHG\000"
  /* 2858 */ "LDS_WRXCHG\000"
  /* 2869 */ "G_ATOMICRMW_XCHG\000"
  /* 2886 */ "G_GET_ROUNDING\000"
  /* 2901 */ "G_SET_ROUNDING\000"
  /* 2916 */ "G_FLOG\000"
  /* 2923 */ "G_VAARG\000"
  /* 2931 */ "PREALLOCATED_ARG\000"
  /* 2948 */ "TEX_SAMPLE_C_G\000"
  /* 2963 */ "TEX_SAMPLE_G\000"
  /* 2976 */ "BRANCH\000"
  /* 2983 */ "G_PREFETCH\000"
  /* 2994 */ "ENDSWITCH\000"
  /* 3004 */ "G_SMULH\000"
  /* 3012 */ "G_UMULH\000"
  /* 3020 */ "G_FTANH\000"
  /* 3028 */ "G_FSINH\000"
  /* 3036 */ "G_FCOSH\000"
  /* 3044 */ "TEX_GET_GRADIENTS_H\000"
  /* 3064 */ "TEX_SET_GRADIENTS_H\000"
  /* 3084 */ "DBG_PHI\000"
  /* 3092 */ "G_FPTOSI\000"
  /* 3101 */ "G_FPTOUI\000"
  /* 3110 */ "G_FPOWI\000"
  /* 3118 */ "CF_ALU_BREAK\000"
  /* 3131 */ "COPY_LANEMASK\000"
  /* 3145 */ "G_PTRMASK\000"
  /* 3155 */ "GC_LABEL\000"
  /* 3164 */ "DBG_LABEL\000"
  /* 3174 */ "EH_LABEL\000"
  /* 3183 */ "ANNOTATION_LABEL\000"
  /* 3200 */ "ICALL_BRANCH_FUNNEL\000"
  /* 3220 */ "G_FSHL\000"
  /* 3227 */ "G_SHL\000"
  /* 3233 */ "G_FCEIL\000"
  /* 3241 */ "G_SAVGCEIL\000"
  /* 3252 */ "G_UAVGCEIL\000"
  /* 3263 */ "PATCHABLE_TAIL_CALL\000"
  /* 3283 */ "PATCHABLE_TYPED_EVENT_CALL\000"
  /* 3310 */ "PATCHABLE_EVENT_CALL\000"
  /* 3331 */ "FENTRY_CALL\000"
  /* 3343 */ "KILL\000"
  /* 3348 */ "G_CONSTANT_POOL\000"
  /* 3364 */ "G_ROTL\000"
  /* 3371 */ "G_VECREDUCE_FMUL\000"
  /* 3388 */ "G_FMUL\000"
  /* 3395 */ "G_VECREDUCE_SEQ_FMUL\000"
  /* 3416 */ "G_STRICT_FMUL\000"
  /* 3430 */ "G_CLMUL\000"
  /* 3438 */ "G_VECREDUCE_MUL\000"
  /* 3454 */ "G_MUL\000"
  /* 3460 */ "TEX_SAMPLE_C_L\000"
  /* 3475 */ "TEX_SAMPLE_L\000"
  /* 3488 */ "CF_END_CM\000"
  /* 3498 */ "G_FREM\000"
  /* 3505 */ "G_STRICT_FREM\000"
  /* 3519 */ "G_SREM\000"
  /* 3526 */ "G_UREM\000"
  /* 3533 */ "G_SDIVREM\000"
  /* 3543 */ "G_UDIVREM\000"
  /* 3553 */ "INLINEASM\000"
  /* 3563 */ "G_VECREDUCE_FMINIMUM\000"
  /* 3584 */ "G_FMINIMUM\000"
  /* 3595 */ "G_ATOMICRMW_FMINIMUM\000"
  /* 3616 */ "G_VECREDUCE_FMAXIMUM\000"
  /* 3637 */ "G_FMAXIMUM\000"
  /* 3648 */ "G_ATOMICRMW_FMAXIMUM\000"
  /* 3669 */ "G_FMINIMUMNUM\000"
  /* 3683 */ "G_ATOMICRMW_FMINIMUMNUM\000"
  /* 3707 */ "G_FMAXIMUMNUM\000"
  /* 3721 */ "G_ATOMICRMW_FMAXIMUMNUM\000"
  /* 3745 */ "G_FMINNUM\000"
  /* 3755 */ "G_FMAXNUM\000"
  /* 3765 */ "G_FATAN\000"
  /* 3773 */ "G_FTAN\000"
  /* 3780 */ "G_INTRINSIC_ROUNDEVEN\000"
  /* 3802 */ "G_ASSERT_ALIGN\000"
  /* 3817 */ "G_FCOPYSIGN\000"
  /* 3829 */ "DUMMY_CHAIN\000"
  /* 3841 */ "ENDMAIN\000"
  /* 3849 */ "G_VECREDUCE_FMIN\000"
  /* 3866 */ "G_ATOMICRMW_FMIN\000"
  /* 3883 */ "G_VECREDUCE_SMIN\000"
  /* 3900 */ "G_SMIN\000"
  /* 3907 */ "G_VECREDUCE_UMIN\000"
  /* 3924 */ "G_UMIN\000"
  /* 3931 */ "G_ATOMICRMW_UMIN\000"
  /* 3948 */ "G_ATOMICRMW_MIN\000"
  /* 3964 */ "G_FASIN\000"
  /* 3972 */ "G_FSIN\000"
  /* 3979 */ "CFI_INSTRUCTION\000"
  /* 3995 */ "G_CTLZ_ZERO_POISON\000"
  /* 4014 */ "G_CTTZ_ZERO_POISON\000"
  /* 4033 */ "RETURN\000"
  /* 4040 */ "RAT_ATOMIC_RSUB_RTN\000"
  /* 4060 */ "RAT_ATOMIC_SUB_RTN\000"
  /* 4079 */ "RAT_ATOMIC_ADD_RTN\000"
  /* 4098 */ "RAT_ATOMIC_AND_RTN\000"
  /* 4117 */ "RAT_ATOMIC_XOR_RTN\000"
  /* 4136 */ "RAT_ATOMIC_OR_RTN\000"
  /* 4154 */ "RAT_ATOMIC_DEC_UINT_RTN\000"
  /* 4178 */ "RAT_ATOMIC_INC_UINT_RTN\000"
  /* 4202 */ "RAT_ATOMIC_MIN_UINT_RTN\000"
  /* 4226 */ "RAT_ATOMIC_MAX_UINT_RTN\000"
  /* 4250 */ "RAT_ATOMIC_CMPXCHG_INT_RTN\000"
  /* 4277 */ "RAT_ATOMIC_XCHG_INT_RTN\000"
  /* 4301 */ "RAT_ATOMIC_MIN_INT_RTN\000"
  /* 4324 */ "RAT_ATOMIC_MAX_INT_RTN\000"
  /* 4347 */ "RETDYN\000"
  /* 4354 */ "G_SSUBO\000"
  /* 4362 */ "G_USUBO\000"
  /* 4370 */ "G_SADDO\000"
  /* 4378 */ "G_UADDO\000"
  /* 4386 */ "TEX_GET_TEXTURE_RESINFO\000"
  /* 4410 */ "JUMP_TABLE_DEBUG_INFO\000"
  /* 4432 */ "G_SMULO\000"
  /* 4440 */ "G_UMULO\000"
  /* 4448 */ "G_BZERO\000"
  /* 4456 */ "STACKMAP\000"
  /* 4465 */ "G_DEBUGTRAP\000"
  /* 4477 */ "G_UBSANTRAP\000"
  /* 4489 */ "G_TRAP\000"
  /* 4496 */ "G_ATOMICRMW_UDEC_WRAP\000"
  /* 4518 */ "G_ATOMICRMW_UINC_WRAP\000"
  /* 4540 */ "G_BSWAP\000"
  /* 4548 */ "G_SITOFP\000"
  /* 4557 */ "G_UITOFP\000"
  /* 4566 */ "G_FCMP\000"
  /* 4573 */ "G_STRICT_FCMP\000"
  /* 4587 */ "G_ICMP\000"
  /* 4594 */ "G_SCMP\000"
  /* 4601 */ "G_UCMP\000"
  /* 4608 */ "JUMP\000"
  /* 4613 */ "ENDLOOP\000"
  /* 4621 */ "WHILELOOP\000"
  /* 4631 */ "CONVERGENCECTRL_LOOP\000"
  /* 4652 */ "G_CTPOP\000"
  /* 4660 */ "PATCHABLE_OP\000"
  /* 4673 */ "FAULTING_OP\000"
  /* 4685 */ "PREALLOCATED_SETUP\000"
  /* 4704 */ "G_FLDEXP\000"
  /* 4713 */ "G_STRICT_FLDEXP\000"
  /* 4729 */ "G_FEXP\000"
  /* 4736 */ "G_FFREXP\000"
  /* 4745 */ "G_BR\000"
  /* 4750 */ "INLINEASM_BR\000"
  /* 4763 */ "G_BLOCK_ADDR\000"
  /* 4776 */ "MOV_IMM_GLOBAL_ADDR\000"
  /* 4796 */ "MEMBARRIER\000"
  /* 4807 */ "G_CONSTANT_FOLD_BARRIER\000"
  /* 4831 */ "GROUP_BARRIER\000"
  /* 4845 */ "CF_ALU_ELSE_AFTER\000"
  /* 4863 */ "CF_ALU_POP_AFTER\000"
  /* 4880 */ "PATCHABLE_FUNCTION_ENTER\000"
  /* 4905 */ "G_READCYCLECOUNTER\000"
  /* 4924 */ "G_READSTEADYCOUNTER\000"
  /* 4944 */ "G_READ_REGISTER\000"
  /* 4960 */ "G_WRITE_REGISTER\000"
  /* 4977 */ "G_ASHR\000"
  /* 4984 */ "G_FSHR\000"
  /* 4991 */ "G_LSHR\000"
  /* 4998 */ "CONVERGENCECTRL_ANCHOR\000"
  /* 5021 */ "RAT_MSKOR\000"
  /* 5031 */ "G_FFLOOR\000"
  /* 5040 */ "G_SAVGFLOOR\000"
  /* 5052 */ "G_UAVGFLOOR\000"
  /* 5064 */ "G_EXTRACT_SUBVECTOR\000"
  /* 5084 */ "G_INSERT_SUBVECTOR\000"
  /* 5103 */ "G_BUILD_VECTOR\000"
  /* 5118 */ "G_SHUFFLE_VECTOR\000"
  /* 5135 */ "G_STEP_VECTOR\000"
  /* 5149 */ "G_SPLAT_VECTOR\000"
  /* 5164 */ "G_VECREDUCE_XOR\000"
  /* 5180 */ "G_XOR\000"
  /* 5186 */ "LDS_XOR\000"
  /* 5194 */ "G_ATOMICRMW_XOR\000"
  /* 5210 */ "G_VECREDUCE_OR\000"
  /* 5225 */ "G_OR\000"
  /* 5230 */ "LDS_OR\000"
  /* 5237 */ "G_ATOMICRMW_OR\000"
  /* 5252 */ "G_ROTR\000"
  /* 5259 */ "TEX_LDPTR\000"
  /* 5269 */ "G_INTTOPTR\000"
  /* 5280 */ "G_FABS\000"
  /* 5287 */ "G_ABS\000"
  /* 5293 */ "G_ABDS\000"
  /* 5300 */ "G_UNMERGE_VALUES\000"
  /* 5317 */ "G_MERGE_VALUES\000"
  /* 5332 */ "LITERALS\000"
  /* 5341 */ "G_CTLS\000"
  /* 5348 */ "G_FACOS\000"
  /* 5356 */ "G_FCOS\000"
  /* 5363 */ "G_FSINCOS\000"
  /* 5373 */ "G_STRICT_FCMPS\000"
  /* 5388 */ "G_CONCAT_VECTORS\000"
  /* 5405 */ "COPY_TO_REGCLASS\000"
  /* 5422 */ "G_IS_FPCLASS\000"
  /* 5435 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\000"
  /* 5465 */ "G_VECTOR_COMPRESS\000"
  /* 5483 */ "G_INTRINSIC_W_SIDE_EFFECTS\000"
  /* 5510 */ "G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS\000"
  /* 5548 */ "G_TRUNC_SSAT_S\000"
  /* 5563 */ "G_SSUBSAT\000"
  /* 5573 */ "G_USUBSAT\000"
  /* 5583 */ "G_SADDSAT\000"
  /* 5593 */ "G_UADDSAT\000"
  /* 5603 */ "G_SSHLSAT\000"
  /* 5613 */ "G_USHLSAT\000"
  /* 5623 */ "G_SMULFIXSAT\000"
  /* 5636 */ "G_UMULFIXSAT\000"
  /* 5649 */ "G_SDIVFIXSAT\000"
  /* 5662 */ "G_UDIVFIXSAT\000"
  /* 5675 */ "G_ATOMICRMW_USUB_SAT\000"
  /* 5696 */ "G_FPTOSI_SAT\000"
  /* 5709 */ "G_FPTOUI_SAT\000"
  /* 5722 */ "FRACT\000"
  /* 5728 */ "G_EXTRACT\000"
  /* 5738 */ "G_SELECT\000"
  /* 5747 */ "G_BRINDIRECT\000"
  /* 5760 */ "RAT_ATOMIC_RSUB_NORET\000"
  /* 5782 */ "RAT_ATOMIC_SUB_NORET\000"
  /* 5803 */ "RAT_ATOMIC_ADD_NORET\000"
  /* 5824 */ "RAT_ATOMIC_AND_NORET\000"
  /* 5845 */ "RAT_ATOMIC_XOR_NORET\000"
  /* 5866 */ "RAT_ATOMIC_OR_NORET\000"
  /* 5886 */ "RAT_ATOMIC_DEC_UINT_NORET\000"
  /* 5912 */ "RAT_ATOMIC_INC_UINT_NORET\000"
  /* 5938 */ "RAT_ATOMIC_MIN_UINT_NORET\000"
  /* 5964 */ "RAT_ATOMIC_MAX_UINT_NORET\000"
  /* 5990 */ "RAT_ATOMIC_CMPXCHG_INT_NORET\000"
  /* 6019 */ "RAT_ATOMIC_XCHG_INT_NORET\000"
  /* 6045 */ "RAT_ATOMIC_MIN_INT_NORET\000"
  /* 6070 */ "RAT_ATOMIC_MAX_INT_NORET\000"
  /* 6095 */ "LDS_SUB_RET\000"
  /* 6107 */ "LDS_UBYTE_READ_RET\000"
  /* 6126 */ "LDS_BYTE_READ_RET\000"
  /* 6144 */ "LDS_READ_RET\000"
  /* 6157 */ "LDS_USHORT_READ_RET\000"
  /* 6177 */ "LDS_SHORT_READ_RET\000"
  /* 6196 */ "LDS_ADD_RET\000"
  /* 6208 */ "LDS_AND_RET\000"
  /* 6220 */ "PATCHABLE_RET\000"
  /* 6234 */ "LDS_WRXCHG_RET\000"
  /* 6249 */ "LDS_XOR_RET\000"
  /* 6261 */ "LDS_OR_RET\000"
  /* 6272 */ "LDS_MIN_UINT_RET\000"
  /* 6289 */ "LDS_MAX_UINT_RET\000"
  /* 6306 */ "LDS_MIN_INT_RET\000"
  /* 6322 */ "LDS_MAX_INT_RET\000"
  /* 6338 */ "LDS_CMPST_RET\000"
  /* 6352 */ "G_MEMSET\000"
  /* 6361 */ "IF_PREDICATE_SET\000"
  /* 6378 */ "KILLGT\000"
  /* 6385 */ "SGT\000"
  /* 6389 */ "PRED_SETGT\000"
  /* 6400 */ "PATCHABLE_FUNCTION_EXIT\000"
  /* 6424 */ "G_BRJT\000"
  /* 6431 */ "G_EXTRACT_VECTOR_ELT\000"
  /* 6452 */ "G_INSERT_VECTOR_ELT\000"
  /* 6472 */ "DEFAULT\000"
  /* 6480 */ "G_FCONSTANT\000"
  /* 6492 */ "G_CONSTANT\000"
  /* 6503 */ "G_INTRINSIC_CONVERGENT\000"
  /* 6526 */ "STATEPOINT\000"
  /* 6537 */ "PATCHPOINT\000"
  /* 6548 */ "G_PTRTOINT\000"
  /* 6559 */ "G_FRINT\000"
  /* 6567 */ "G_INTRINSIC_LLRINT\000"
  /* 6586 */ "G_INTRINSIC_LRINT\000"
  /* 6604 */ "SUBB_UINT\000"
  /* 6614 */ "ADDC_UINT\000"
  /* 6624 */ "SETGE_UINT\000"
  /* 6635 */ "FFBH_UINT\000"
  /* 6645 */ "LDS_MIN_UINT\000"
  /* 6658 */ "SETGT_UINT\000"
  /* 6669 */ "LDS_MAX_UINT\000"
  /* 6682 */ "G_FNEARBYINT\000"
  /* 6695 */ "SUB_INT\000"
  /* 6703 */ "ADD_INT\000"
  /* 6711 */ "AND_INT\000"
  /* 6719 */ "CNDE_INT\000"
  /* 6728 */ "CNDGE_INT\000"
  /* 6738 */ "PRED_SETGE_INT\000"
  /* 6753 */ "PRED_SETNE_INT\000"
  /* 6768 */ "PRED_SETE_INT\000"
  /* 6782 */ "FFBL_INT\000"
  /* 6791 */ "LDS_MIN_INT\000"
  /* 6803 */ "XOR_INT\000"
  /* 6811 */ "CNDGT_INT\000"
  /* 6821 */ "PRED_SETGT_INT\000"
  /* 6836 */ "BCNT_INT\000"
  /* 6845 */ "NOT_INT\000"
  /* 6853 */ "LDS_MAX_INT\000"
  /* 6865 */ "G_VASTART\000"
  /* 6875 */ "LIFETIME_START\000"
  /* 6890 */ "G_INVOKE_REGION_START\000"
  /* 6912 */ "G_INSERT\000"
  /* 6921 */ "G_FSQRT\000"
  /* 6929 */ "G_STRICT_FSQRT\000"
  /* 6944 */ "G_BITCAST\000"
  /* 6954 */ "G_ADDRSPACE_CAST\000"
  /* 6971 */ "DBG_VALUE_LIST\000"
  /* 6986 */ "LDS_CMPST\000"
  /* 6996 */ "G_FPEXT\000"
  /* 7004 */ "G_SEXT\000"
  /* 7011 */ "G_ASSERT_SEXT\000"
  /* 7025 */ "G_ANYEXT\000"
  /* 7034 */ "G_ZEXT\000"
  /* 7041 */ "G_ASSERT_ZEXT\000"
  /* 7055 */ "G_ABDU\000"
  /* 7062 */ "CF_ALU\000"
  /* 7069 */ "G_TRUNC_SSAT_U\000"
  /* 7084 */ "G_TRUNC_USAT_U\000"
  /* 7099 */ "G_FDIV\000"
  /* 7106 */ "G_STRICT_FDIV\000"
  /* 7120 */ "G_SDIV\000"
  /* 7127 */ "G_UDIV\000"
  /* 7134 */ "G_GET_FPENV\000"
  /* 7146 */ "G_RESET_FPENV\000"
  /* 7160 */ "G_SET_FPENV\000"
  /* 7172 */ "MOV\000"
  /* 7176 */ "TEX_GET_GRADIENTS_V\000"
  /* 7196 */ "TEX_SET_GRADIENTS_V\000"
  /* 7216 */ "TXD_SHADOW\000"
  /* 7227 */ "G_FPOW\000"
  /* 7234 */ "INTERP_ZW\000"
  /* 7244 */ "INTERP_PAIR_ZW\000"
  /* 7259 */ "G_VECREDUCE_FMAX\000"
  /* 7276 */ "G_ATOMICRMW_FMAX\000"
  /* 7293 */ "G_VECREDUCE_SMAX\000"
  /* 7310 */ "G_SMAX\000"
  /* 7317 */ "G_VECREDUCE_UMAX\000"
  /* 7334 */ "G_UMAX\000"
  /* 7341 */ "G_ATOMICRMW_UMAX\000"
  /* 7358 */ "G_ATOMICRMW_MAX\000"
  /* 7374 */ "G_FRAME_INDEX\000"
  /* 7388 */ "G_SBFX\000"
  /* 7395 */ "G_UBFX\000"
  /* 7402 */ "G_SMULFIX\000"
  /* 7412 */ "G_UMULFIX\000"
  /* 7422 */ "G_SDIVFIX\000"
  /* 7432 */ "G_UDIVFIX\000"
  /* 7442 */ "PRED_X\000"
  /* 7449 */ "G_MEMCPY\000"
  /* 7458 */ "CONST_COPY\000"
  /* 7469 */ "CONVERGENCECTRL_ENTRY\000"
  /* 7491 */ "INTERP_XY\000"
  /* 7501 */ "INTERP_PAIR_XY\000"
  /* 7516 */ "G_CTLZ\000"
  /* 7523 */ "G_CTTZ\000"
  /* 7530 */ "R600_RegisterLoad\000"
  /* 7548 */ "R600_RegisterStore\000"
  /* 7567 */ "R600_ExportBuf\000"
  /* 7582 */ "EG_ExportBuf\000"
  /* 7595 */ "VTX_READ_32_eg\000"
  /* 7610 */ "RAT_WRITE_CACHELESS_32_eg\000"
  /* 7636 */ "MULADD_UINT24_eg\000"
  /* 7653 */ "MULHI_UINT24_eg\000"
  /* 7669 */ "MUL_UINT24_eg\000"
  /* 7683 */ "VTX_READ_64_eg\000"
  /* 7698 */ "RAT_WRITE_CACHELESS_64_eg\000"
  /* 7724 */ "DOT4_eg\000"
  /* 7732 */ "VTX_READ_16_eg\000"
  /* 7747 */ "VTX_READ_128_eg\000"
  /* 7763 */ "RAT_WRITE_CACHELESS_128_eg\000"
  /* 7790 */ "VTX_READ_8_eg\000"
  /* 7804 */ "FMA_eg\000"
  /* 7811 */ "MULADD_eg\000"
  /* 7821 */ "LOG_CLAMPED_eg\000"
  /* 7836 */ "RECIP_CLAMPED_eg\000"
  /* 7853 */ "RECIPSQRT_CLAMPED_eg\000"
  /* 7874 */ "RAT_STORE_TYPED_eg\000"
  /* 7893 */ "CNDE_eg\000"
  /* 7901 */ "MULADD_IEEE_eg\000"
  /* 7916 */ "LOG_IEEE_eg\000"
  /* 7928 */ "RECIP_IEEE_eg\000"
  /* 7942 */ "EXP_IEEE_eg\000"
  /* 7954 */ "RECIPSQRT_IEEE_eg\000"
  /* 7972 */ "CNDGE_eg\000"
  /* 7981 */ "LSHL_eg\000"
  /* 7989 */ "SIN_eg\000"
  /* 7996 */ "ASHR_eg\000"
  /* 8004 */ "LSHR_eg\000"
  /* 8012 */ "COS_eg\000"
  /* 8019 */ "CNDGT_eg\000"
  /* 8028 */ "MUL_LIT_eg\000"
  /* 8039 */ "UINT_TO_FLT_eg\000"
  /* 8054 */ "BFE_UINT_eg\000"
  /* 8066 */ "MULHI_UINT_eg\000"
  /* 8080 */ "MULLO_UINT_eg\000"
  /* 8094 */ "FLT_TO_UINT_eg\000"
  /* 8109 */ "RECIP_UINT_eg\000"
  /* 8123 */ "MOVA_INT_eg\000"
  /* 8135 */ "BFE_INT_eg\000"
  /* 8146 */ "BFI_INT_eg\000"
  /* 8157 */ "MULHI_INT_eg\000"
  /* 8170 */ "BFM_INT_eg\000"
  /* 8181 */ "BIT_ALIGN_INT_eg\000"
  /* 8198 */ "MULLO_INT_eg\000"
  /* 8211 */ "FLT_TO_INT_eg\000"
  /* 8225 */ "CUBE_r600_real\000"
  /* 8240 */ "CUBE_eg_real\000"
  /* 8253 */ "VTX_READ_32_cm\000"
  /* 8268 */ "MULADD_INT24_cm\000"
  /* 8284 */ "MUL_INT24_cm\000"
  /* 8297 */ "VTX_READ_64_cm\000"
  /* 8312 */ "VTX_READ_16_cm\000"
  /* 8327 */ "VTX_READ_128_cm\000"
  /* 8343 */ "VTX_READ_8_cm\000"
  /* 8357 */ "RECIP_CLAMPED_cm\000"
  /* 8374 */ "RECIPSQRT_CLAMPED_cm\000"
  /* 8395 */ "RAT_STORE_TYPED_cm\000"
  /* 8414 */ "LOG_IEEE_cm\000"
  /* 8426 */ "RECIP_IEEE_cm\000"
  /* 8440 */ "EXP_IEEE_cm\000"
  /* 8452 */ "RECIPSQRT_IEEE_cm\000"
  /* 8470 */ "SIN_cm\000"
  /* 8477 */ "COS_cm\000"
  /* 8484 */ "MULHI_UINT_cm\000"
  /* 8498 */ "MULLO_UINT_cm\000"
  /* 8512 */ "MULHI_INT_cm\000"
  /* 8525 */ "MULLO_INT_cm\000"
  /* 8538 */ "CUBE_r600_pseudo\000"
  /* 8555 */ "CUBE_eg_pseudo\000"
  /* 8570 */ "R600_ExportSwz\000"
  /* 8585 */ "EG_ExportSwz\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned R600InstrNameIndices[] = {
    3088U, 3553U, 4750U, 3979U, 3174U, 3155U, 3183U, 3343U, 
    2648U, 2663U, 2576U, 2563U, 2690U, 5405U, 2423U, 6971U, 
    2589U, 3084U, 3164U, 1996U, 7464U, 3131U, 2142U, 6875U, 
    1809U, 1947U, 1984U, 4456U, 3331U, 6537U, 1926U, 4685U, 
    2931U, 6526U, 2224U, 4673U, 4660U, 4880U, 6220U, 6400U, 
    3263U, 3310U, 3283U, 3200U, 2352U, 4796U, 4410U, 2198U, 
    7469U, 4998U, 4631U, 2471U, 7011U, 7041U, 3802U, 1699U, 
    1349U, 3454U, 7120U, 7127U, 3519U, 3526U, 3533U, 3543U, 
    1779U, 5225U, 5180U, 5293U, 7055U, 5052U, 3252U, 5040U, 
    3241U, 2574U, 3086U, 7374U, 2433U, 2448U, 3348U, 5728U, 
    5300U, 6912U, 5317U, 5103U, 1435U, 5388U, 6548U, 5269U, 
    6944U, 2530U, 4807U, 1900U, 1409U, 1882U, 6586U, 6567U, 
    3780U, 4905U, 4924U, 1596U, 1524U, 1554U, 1493U, 1581U, 
    1505U, 1535U, 2302U, 2256U, 2286U, 5435U, 2841U, 2869U, 
    1723U, 1363U, 1793U, 1746U, 5237U, 5194U, 7358U, 3948U, 
    7341U, 3931U, 1666U, 1332U, 7276U, 3866U, 3648U, 3595U, 
    3721U, 3683U, 4518U, 4496U, 1831U, 5675U, 1976U, 2983U, 
    1822U, 5747U, 6890U, 1379U, 5483U, 6503U, 5510U, 7025U, 
    1427U, 5548U, 7069U, 7084U, 6492U, 6480U, 6865U, 2923U, 
    7004U, 2677U, 7034U, 3227U, 4991U, 4977U, 3220U, 4984U, 
    5252U, 3364U, 4587U, 4566U, 4594U, 4601U, 5738U, 4378U, 
    2017U, 4362U, 1968U, 4370U, 2009U, 4354U, 1960U, 4440U, 
    4432U, 3012U, 3004U, 5593U, 5583U, 5573U, 5563U, 5613U, 
    5603U, 7402U, 7412U, 5623U, 5636U, 7422U, 7432U, 5649U, 
    5662U, 1624U, 1311U, 3388U, 1262U, 1486U, 7099U, 3498U, 
    2555U, 7227U, 3110U, 4729U, 1087U, 596U, 2916U, 1070U, 
    587U, 4704U, 4736U, 2641U, 6996U, 1399U, 3092U, 3101U, 
    4548U, 4557U, 5696U, 5709U, 5280U, 3817U, 5422U, 2539U, 
    3745U, 3755U, 2075U, 2090U, 3584U, 3637U, 3669U, 3707U, 
    7134U, 7160U, 7146U, 2025U, 2053U, 2038U, 2886U, 2901U, 
    1705U, 3145U, 3900U, 7310U, 3924U, 7334U, 5287U, 1873U, 
    1863U, 4745U, 6424U, 2120U, 5084U, 5064U, 6452U, 6431U, 
    5118U, 5149U, 5135U, 5465U, 7523U, 4014U, 7516U, 3995U, 
    5341U, 4652U, 4540U, 2315U, 3430U, 3233U, 5356U, 3972U, 
    5363U, 3773U, 5348U, 3964U, 3765U, 1078U, 3036U, 3028U, 
    3020U, 6921U, 5031U, 6559U, 6682U, 6954U, 4763U, 2129U, 
    1456U, 2508U, 2271U, 1652U, 1318U, 3416U, 7106U, 3505U, 
    1268U, 6929U, 4713U, 4573U, 5373U, 4944U, 4960U, 7449U, 
    2182U, 2520U, 6352U, 4448U, 2166U, 4489U, 4465U, 4477U, 
    1631U, 3395U, 1607U, 3371U, 7259U, 3849U, 3616U, 3563U, 
    1683U, 3438U, 1763U, 5210U, 5164U, 7293U, 3883U, 7317U, 
    3907U, 7388U, 7395U, 2976U, 771U, 937U, 3125U, 760U, 
    926U, 884U, 1050U, 825U, 991U, 7458U, 2499U, 738U, 
    904U, 844U, 1010U, 787U, 953U, 8555U, 8538U, 6472U, 
    1222U, 3829U, 2310U, 1818U, 1391U, 2603U, 4613U, 3841U, 
    2994U, 160U, 82U, 1394U, 752U, 918U, 867U, 1033U, 
    809U, 975U, 6361U, 4608U, 1853U, 2386U, 699U, 4776U, 
    711U, 7442U, 1095U, 1183U, 1115U, 1203U, 7530U, 7548U, 
    4347U, 4033U, 1943U, 7216U, 4621U, 1620U, 6614U, 6703U, 
    2341U, 6711U, 7996U, 388U, 6836U, 8135U, 8054U, 8146U, 
    8170U, 8181U, 3236U, 7062U, 3118U, 2492U, 4845U, 4863U, 
    2237U, 2827U, 170U, 2743U, 65U, 2732U, 34U, 3488U, 
    2722U, 22U, 2783U, 108U, 2758U, 47U, 2704U, 0U, 
    2713U, 11U, 6719U, 7893U, 267U, 6728U, 7972U, 358U, 
    6811U, 8019U, 417U, 8477U, 8012U, 408U, 578U, 8240U, 
    8225U, 7724U, 186U, 7582U, 8585U, 2794U, 121U, 8440U, 
    7942U, 324U, 2328U, 6635U, 6782U, 5034U, 723U, 1228U, 
    8211U, 553U, 8094U, 490U, 7804U, 5722U, 4831U, 666U, 
    7501U, 7244U, 1565U, 7491U, 7234U, 8040U, 442U, 6378U, 
    1715U, 6196U, 1785U, 6208U, 6126U, 2371U, 6986U, 6338U, 
    6853U, 6322U, 6669U, 6289U, 6791U, 6306U, 6645U, 6272U, 
    5230U, 6261U, 6144U, 6177U, 2407U, 1355U, 6095U, 6107U, 
    6157U, 2397U, 2858U, 6234U, 5186U, 6249U, 5332U, 7821U, 
    208U, 8414U, 7916U, 294U, 2769U, 92U, 7981U, 369U, 
    8004U, 398U, 7272U, 657U, 6857U, 6673U, 3862U, 637U, 
    6795U, 6649U, 7172U, 8123U, 3384U, 7901U, 277U, 8268U, 
    7636U, 7811U, 196U, 8512U, 1150U, 8157U, 523U, 7653U, 
    8484U, 1134U, 8066U, 458U, 8525U, 8198U, 538U, 8498U, 
    8080U, 474U, 2066U, 8284U, 8028U, 428U, 7669U, 6845U, 
    6804U, 1603U, 2820U, 151U, 2361U, 6768U, 2109U, 6738U, 
    6389U, 6821U, 2213U, 6753U, 7567U, 8570U, 5803U, 4079U, 
    5824U, 4098U, 5990U, 4250U, 5886U, 4154U, 5912U, 4178U, 
    6070U, 4324U, 5964U, 4226U, 6045U, 4301U, 5938U, 4202U, 
    5866U, 4136U, 5760U, 4040U, 5782U, 4060U, 6019U, 4277U, 
    5845U, 4117U, 5021U, 1243U, 681U, 1165U, 8395U, 7874U, 
    7763U, 7610U, 7698U, 8374U, 7853U, 244U, 8452U, 7954U, 
    338U, 8357U, 7836U, 225U, 8426U, 7928U, 308U, 8109U, 
    507U, 2160U, 2366U, 627U, 6773U, 605U, 6743U, 6624U, 
    646U, 6826U, 6658U, 616U, 6758U, 2105U, 6385U, 8470U, 
    7989U, 379U, 569U, 2209U, 6604U, 6695U, 3044U, 7176U, 
    4386U, 1739U, 5259U, 2149U, 1473U, 2948U, 3460U, 1281U, 
    2963U, 3475U, 1297U, 3064U, 7196U, 2609U, 2626U, 1403U, 
    8039U, 441U, 8327U, 7747U, 8312U, 7732U, 8253U, 7595U, 
    8297U, 7683U, 8343U, 7790U, 2806U, 135U, 6803U, 
};

static inline void InitR600MCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(R600Descs.Insts, R600InstrNameIndices, R600InstrNameData, nullptr, nullptr, 671, nullptr, 0);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct R600GenInstrInfo : public TargetInstrInfo {
  explicit R600GenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~R600GenInstrInfo() override = default;
};

} // namespace llvm_ks

namespace llvm_ks::R600 {

constexpr unsigned SUBOP_FRAMEri_ptr = 0;
constexpr unsigned SUBOP_FRAMEri_index = 1;
constexpr unsigned SUBOP_MEMrr_ptr = 0;
constexpr unsigned SUBOP_MEMrr_index = 1;
constexpr unsigned SUBOP_MEMxi_ptr = 0;
constexpr unsigned SUBOP_MEMxi_index = 1;

} // namespace llvm_ks::R600

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

extern const R600InstrTable R600Descs;
extern const unsigned R600InstrNameIndices[];
extern const char R600InstrNameData[];
R600GenInstrInfo::R600GenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(R600Descs.Insts, R600InstrNameIndices, R600InstrNameData, nullptr, nullptr, 671);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_OPERAND_ENUM
#undef GET_INSTRINFO_OPERAND_ENUM

namespace llvm_ks::R600 {

enum class OpName : uint8_t {
  dst = 0,
  src0 = 1,
  update_exec_mask_X = 2,
  update_pred_X = 3,
  write_X = 4,
  omod_X = 5,
  dst_rel_X = 6,
  clamp_X = 7,
  src0_X = 8,
  src0_neg_X = 9,
  src0_rel_X = 10,
  src0_abs_X = 11,
  src0_sel_X = 12,
  src1_X = 13,
  src1_neg_X = 14,
  src1_rel_X = 15,
  src1_abs_X = 16,
  src1_sel_X = 17,
  pred_sel_X = 18,
  update_exec_mask_Y = 19,
  update_pred_Y = 20,
  write_Y = 21,
  omod_Y = 22,
  dst_rel_Y = 23,
  clamp_Y = 24,
  src0_Y = 25,
  src0_neg_Y = 26,
  src0_rel_Y = 27,
  src0_abs_Y = 28,
  src0_sel_Y = 29,
  src1_Y = 30,
  src1_neg_Y = 31,
  src1_rel_Y = 32,
  src1_abs_Y = 33,
  src1_sel_Y = 34,
  pred_sel_Y = 35,
  update_exec_mask_Z = 36,
  update_pred_Z = 37,
  write_Z = 38,
  omod_Z = 39,
  dst_rel_Z = 40,
  clamp_Z = 41,
  src0_Z = 42,
  src0_neg_Z = 43,
  src0_rel_Z = 44,
  src0_abs_Z = 45,
  src0_sel_Z = 46,
  src1_Z = 47,
  src1_neg_Z = 48,
  src1_rel_Z = 49,
  src1_abs_Z = 50,
  src1_sel_Z = 51,
  pred_sel_Z = 52,
  update_exec_mask_W = 53,
  update_pred_W = 54,
  write_W = 55,
  omod_W = 56,
  dst_rel_W = 57,
  clamp_W = 58,
  src0_W = 59,
  src0_neg_W = 60,
  src0_rel_W = 61,
  src0_abs_W = 62,
  src0_sel_W = 63,
  src1_W = 64,
  src1_neg_W = 65,
  src1_rel_W = 66,
  src1_abs_W = 67,
  src1_sel_W = 68,
  pred_sel_W = 69,
  literal0 = 70,
  literal1 = 71,
  addr = 72,
  chan = 73,
  val = 74,
  update_exec_mask = 75,
  update_pred = 76,
  write = 77,
  omod = 78,
  dst_rel = 79,
  clamp = 80,
  src0_neg = 81,
  src0_rel = 82,
  src0_abs = 83,
  src0_sel = 84,
  src1 = 85,
  src1_neg = 86,
  src1_rel = 87,
  src1_abs = 88,
  src1_sel = 89,
  last = 90,
  pred_sel = 91,
  literal = 92,
  bank_swizzle = 93,
  src2 = 94,
  src2_neg = 95,
  src2_rel = 96,
  src2_sel = 97,
  ADDR = 98,
  KCACHE_BANK0 = 99,
  KCACHE_BANK1 = 100,
  KCACHE_MODE0 = 101,
  KCACHE_MODE1 = 102,
  KCACHE_ADDR0 = 103,
  KCACHE_ADDR1 = 104,
  COUNT = 105,
  Enabled = 106,
  NUM_OPERAND_NAMES = 107,
}; // enum class OpName

LLVM_READONLY int16_t getNamedOperandIdx(uint32_t Opcode, OpName Name);
LLVM_READONLY OpName getOperandIdxName(uint32_t Opcode, int16_t Idx);

} // namespace llvm_ks::R600

#endif // GET_INSTRINFO_OPERAND_ENUM

#ifdef GET_INSTRINFO_NAMED_OPS
#undef GET_INSTRINFO_NAMED_OPS

namespace llvm_ks::R600 {

LLVM_READONLY static uint8_t getInstructionIndexForOpLookup(uint32_t Opcode) {
  static constexpr uint8_t InstructionIndex[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 4,
    0, 0, 0, 0, 0, 5, 5, 5, 0, 5, 5, 5, 6, 7, 7, 7,
    5, 7, 6, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 0, 0, 0, 0, 6,
    6, 6, 0, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 6, 0, 6,
    0, 0, 0, 5, 5, 6, 6, 5, 9, 10, 9, 10, 11, 9, 12, 13,
    9, 10, 9, 10, 9, 10, 9, 10, 9, 10, 11, 11, 9, 9, 10, 11,
    11, 9, 9, 10, 9, 10, 0, 6, 6, 6, 6, 6, 0, 0, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 5, 7, 7, 7,
    7, 7, 7, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 7, 7, 5, 6, 5, 0, 0, 0, 5, 5, 5, 5,
    5, 5, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 5, 5, 5, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6,
    6, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
  };
  return InstructionIndex[Opcode];
}
LLVM_READONLY int16_t getNamedOperandIdx(uint32_t Opcode, OpName Name) {
  assert(Name != OpName::NUM_OPERAND_NAMES);
  static constexpr int8_t OperandMap[][107] = {
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 3, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 2, 3, 4, 6, 7, 8, 9, -1, -1, -1, -1, -1, 10, 11, 12, 13, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 2, 4, 5, -1, 6, 7, 8, 9, -1, 10, 15, 16, 17, 18, 11, 12, 13, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, },
    {-1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, -1, 2, 3, -1, 4, -1, 5, 6, 7, -1, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2, -1, 3, 4, -1, 5, -1, 6, 7, 8, -1, 9, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2, -1, 3, -1, -1, -1, -1, -1, 4, 5, -1, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {-1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, -1, 2, 3, -1, 4, -1, 5, 9, 10, -1, 11, 6, -1, 7, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2, -1, 3, 4, -1, 5, -1, 6, 10, 11, -1, 12, 7, -1, 8, 9, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
  };
  unsigned InstrIdx = getInstructionIndexForOpLookup(Opcode);
  return OperandMap[InstrIdx][(unsigned)Name];
}
LLVM_READONLY OpName getOperandIdxName(uint32_t Opcode, int16_t Idx) {
  assert(Idx >= 0 && Idx < 71);
  static constexpr OpName OperandMap[][71] = {
    {OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::src0, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::update_exec_mask_X, OpName::update_pred_X, OpName::write_X, OpName::omod_X, OpName::dst_rel_X, OpName::clamp_X, OpName::src0_X, OpName::src0_neg_X, OpName::src0_rel_X, OpName::src0_abs_X, OpName::src0_sel_X, OpName::src1_X, OpName::src1_neg_X, OpName::src1_rel_X, OpName::src1_abs_X, OpName::src1_sel_X, OpName::pred_sel_X, OpName::update_exec_mask_Y, OpName::update_pred_Y, OpName::write_Y, OpName::omod_Y, OpName::dst_rel_Y, OpName::clamp_Y, OpName::src0_Y, OpName::src0_neg_Y, OpName::src0_rel_Y, OpName::src0_abs_Y, OpName::src0_sel_Y, OpName::src1_Y, OpName::src1_neg_Y, OpName::src1_rel_Y, OpName::src1_abs_Y, OpName::src1_sel_Y, OpName::pred_sel_Y, OpName::update_exec_mask_Z, OpName::update_pred_Z, OpName::write_Z, OpName::omod_Z, OpName::dst_rel_Z, OpName::clamp_Z, OpName::src0_Z, OpName::src0_neg_Z, OpName::src0_rel_Z, OpName::src0_abs_Z, OpName::src0_sel_Z, OpName::src1_Z, OpName::src1_neg_Z, OpName::src1_rel_Z, OpName::src1_abs_Z, OpName::src1_sel_Z, OpName::pred_sel_Z, OpName::update_exec_mask_W, OpName::update_pred_W, OpName::write_W, OpName::omod_W, OpName::dst_rel_W, OpName::clamp_W, OpName::src0_W, OpName::src0_neg_W, OpName::src0_rel_W, OpName::src0_abs_W, OpName::src0_sel_W, OpName::src1_W, OpName::src1_neg_W, OpName::src1_rel_W, OpName::src1_abs_W, OpName::src1_sel_W, OpName::pred_sel_W, OpName::literal0, OpName::literal1, },
    {OpName::dst, OpName::addr, OpName::NUM_OPERAND_NAMES, OpName::chan, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::val, OpName::addr, OpName::NUM_OPERAND_NAMES, OpName::chan, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::update_exec_mask, OpName::update_pred, OpName::write, OpName::omod, OpName::dst_rel, OpName::clamp, OpName::src0, OpName::src0_neg, OpName::src0_rel, OpName::src0_abs, OpName::src0_sel, OpName::src1, OpName::src1_neg, OpName::src1_rel, OpName::src1_abs, OpName::src1_sel, OpName::last, OpName::pred_sel, OpName::literal, OpName::bank_swizzle, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::write, OpName::omod, OpName::dst_rel, OpName::clamp, OpName::src0, OpName::src0_neg, OpName::src0_rel, OpName::src0_abs, OpName::src0_sel, OpName::last, OpName::pred_sel, OpName::literal, OpName::bank_swizzle, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::dst_rel, OpName::clamp, OpName::src0, OpName::src0_neg, OpName::src0_rel, OpName::src0_sel, OpName::src1, OpName::src1_neg, OpName::src1_rel, OpName::src1_sel, OpName::src2, OpName::src2_neg, OpName::src2_rel, OpName::src2_sel, OpName::last, OpName::pred_sel, OpName::literal, OpName::bank_swizzle, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::ADDR, OpName::KCACHE_BANK0, OpName::KCACHE_BANK1, OpName::KCACHE_MODE0, OpName::KCACHE_MODE1, OpName::KCACHE_ADDR0, OpName::KCACHE_ADDR1, OpName::COUNT, OpName::Enabled, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::src0, OpName::src0_rel, OpName::src0_sel, OpName::src1, OpName::src1_rel, OpName::src1_sel, OpName::last, OpName::pred_sel, OpName::bank_swizzle, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::src0, OpName::src0_rel, OpName::src0_sel, OpName::src1, OpName::src1_rel, OpName::src1_sel, OpName::last, OpName::pred_sel, OpName::bank_swizzle, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::src0, OpName::src0_rel, OpName::src0_sel, OpName::last, OpName::pred_sel, OpName::bank_swizzle, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::src0, OpName::src0_rel, OpName::src0_sel, OpName::src1, OpName::src1_rel, OpName::src1_sel, OpName::src2, OpName::src2_rel, OpName::src2_sel, OpName::last, OpName::pred_sel, OpName::bank_swizzle, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::src0, OpName::src0_rel, OpName::src0_sel, OpName::src1, OpName::src1_rel, OpName::src1_sel, OpName::src2, OpName::src2_rel, OpName::src2_sel, OpName::last, OpName::pred_sel, OpName::bank_swizzle, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
  };
  unsigned InstrIdx = getInstructionIndexForOpLookup(Opcode);
  return OperandMap[InstrIdx][(unsigned)Idx];
}

} // namespace llvm_ks::R600

#endif // GET_INSTRINFO_NAMED_OPS

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace R600_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace R600_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::R600_MC {


} // namespace llvm_ks::R600_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::R600_MC {

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
};

inline FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) {
  FeatureBitset Features;
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
    CEFBS_None, // BRANCH
    CEFBS_None, // BRANCH_COND_f32
    CEFBS_None, // BRANCH_COND_i32
    CEFBS_None, // BREAK
    CEFBS_None, // BREAKC_f32
    CEFBS_None, // BREAKC_i32
    CEFBS_None, // BREAK_LOGICALNZ_f32
    CEFBS_None, // BREAK_LOGICALNZ_i32
    CEFBS_None, // BREAK_LOGICALZ_f32
    CEFBS_None, // BREAK_LOGICALZ_i32
    CEFBS_None, // CONST_COPY
    CEFBS_None, // CONTINUE
    CEFBS_None, // CONTINUEC_f32
    CEFBS_None, // CONTINUEC_i32
    CEFBS_None, // CONTINUE_LOGICALNZ_f32
    CEFBS_None, // CONTINUE_LOGICALNZ_i32
    CEFBS_None, // CONTINUE_LOGICALZ_f32
    CEFBS_None, // CONTINUE_LOGICALZ_i32
    CEFBS_None, // CUBE_eg_pseudo
    CEFBS_None, // CUBE_r600_pseudo
    CEFBS_None, // DEFAULT
    CEFBS_None, // DOT_4
    CEFBS_None, // DUMMY_CHAIN
    CEFBS_None, // ELSE
    CEFBS_None, // END
    CEFBS_None, // ENDFUNC
    CEFBS_None, // ENDIF
    CEFBS_None, // ENDLOOP
    CEFBS_None, // ENDMAIN
    CEFBS_None, // ENDSWITCH
    CEFBS_None, // FABS_R600
    CEFBS_None, // FNEG_R600
    CEFBS_None, // FUNC
    CEFBS_None, // IFC_f32
    CEFBS_None, // IFC_i32
    CEFBS_None, // IF_LOGICALNZ_f32
    CEFBS_None, // IF_LOGICALNZ_i32
    CEFBS_None, // IF_LOGICALZ_f32
    CEFBS_None, // IF_LOGICALZ_i32
    CEFBS_None, // IF_PREDICATE_SET
    CEFBS_None, // JUMP
    CEFBS_None, // JUMP_COND
    CEFBS_None, // MASK_WRITE
    CEFBS_None, // MOV_IMM_F32
    CEFBS_None, // MOV_IMM_GLOBAL_ADDR
    CEFBS_None, // MOV_IMM_I32
    CEFBS_None, // PRED_X
    CEFBS_None, // R600_EXTRACT_ELT_V2
    CEFBS_None, // R600_EXTRACT_ELT_V4
    CEFBS_None, // R600_INSERT_ELT_V2
    CEFBS_None, // R600_INSERT_ELT_V4
    CEFBS_None, // R600_RegisterLoad
    CEFBS_None, // R600_RegisterStore
    CEFBS_None, // RETDYN
    CEFBS_None, // RETURN
    CEFBS_None, // TXD
    CEFBS_None, // TXD_SHADOW
    CEFBS_None, // WHILELOOP
    CEFBS_None, // ADD
    CEFBS_None, // ADDC_UINT
    CEFBS_None, // ADD_INT
    CEFBS_None, // ALU_CLAUSE
    CEFBS_None, // AND_INT
    CEFBS_None, // ASHR_eg
    CEFBS_None, // ASHR_r600
    CEFBS_None, // BCNT_INT
    CEFBS_None, // BFE_INT_eg
    CEFBS_None, // BFE_UINT_eg
    CEFBS_None, // BFI_INT_eg
    CEFBS_None, // BFM_INT_eg
    CEFBS_None, // BIT_ALIGN_INT_eg
    CEFBS_None, // CEIL
    CEFBS_None, // CF_ALU
    CEFBS_None, // CF_ALU_BREAK
    CEFBS_None, // CF_ALU_CONTINUE
    CEFBS_None, // CF_ALU_ELSE_AFTER
    CEFBS_None, // CF_ALU_POP_AFTER
    CEFBS_None, // CF_ALU_PUSH_BEFORE
    CEFBS_None, // CF_CALL_FS_EG
    CEFBS_None, // CF_CALL_FS_R600
    CEFBS_None, // CF_CONTINUE_EG
    CEFBS_None, // CF_CONTINUE_R600
    CEFBS_None, // CF_ELSE_EG
    CEFBS_None, // CF_ELSE_R600
    CEFBS_None, // CF_END_CM
    CEFBS_None, // CF_END_EG
    CEFBS_None, // CF_END_R600
    CEFBS_None, // CF_JUMP_EG
    CEFBS_None, // CF_JUMP_R600
    CEFBS_None, // CF_PUSH_EG
    CEFBS_None, // CF_PUSH_ELSE_R600
    CEFBS_None, // CF_TC_EG
    CEFBS_None, // CF_TC_R600
    CEFBS_None, // CF_VC_EG
    CEFBS_None, // CF_VC_R600
    CEFBS_None, // CNDE_INT
    CEFBS_None, // CNDE_eg
    CEFBS_None, // CNDE_r600
    CEFBS_None, // CNDGE_INT
    CEFBS_None, // CNDGE_eg
    CEFBS_None, // CNDGE_r600
    CEFBS_None, // CNDGT_INT
    CEFBS_None, // CNDGT_eg
    CEFBS_None, // CNDGT_r600
    CEFBS_None, // COS_cm
    CEFBS_None, // COS_eg
    CEFBS_None, // COS_r600
    CEFBS_None, // COS_r700
    CEFBS_None, // CUBE_eg_real
    CEFBS_None, // CUBE_r600_real
    CEFBS_None, // DOT4_eg
    CEFBS_None, // DOT4_r600
    CEFBS_None, // EG_ExportBuf
    CEFBS_None, // EG_ExportSwz
    CEFBS_None, // END_LOOP_EG
    CEFBS_None, // END_LOOP_R600
    CEFBS_None, // EXP_IEEE_cm
    CEFBS_None, // EXP_IEEE_eg
    CEFBS_None, // EXP_IEEE_r600
    CEFBS_None, // FETCH_CLAUSE
    CEFBS_None, // FFBH_UINT
    CEFBS_None, // FFBL_INT
    CEFBS_None, // FLOOR
    CEFBS_None, // FLT16_TO_FLT32
    CEFBS_None, // FLT32_TO_FLT16
    CEFBS_None, // FLT_TO_INT_eg
    CEFBS_None, // FLT_TO_INT_r600
    CEFBS_None, // FLT_TO_UINT_eg
    CEFBS_None, // FLT_TO_UINT_r600
    CEFBS_None, // FMA_eg
    CEFBS_None, // FRACT
    CEFBS_None, // GROUP_BARRIER
    CEFBS_None, // INTERP_LOAD_P0
    CEFBS_None, // INTERP_PAIR_XY
    CEFBS_None, // INTERP_PAIR_ZW
    CEFBS_None, // INTERP_VEC_LOAD
    CEFBS_None, // INTERP_XY
    CEFBS_None, // INTERP_ZW
    CEFBS_None, // INT_TO_FLT_eg
    CEFBS_None, // INT_TO_FLT_r600
    CEFBS_None, // KILLGT
    CEFBS_None, // LDS_ADD
    CEFBS_None, // LDS_ADD_RET
    CEFBS_None, // LDS_AND
    CEFBS_None, // LDS_AND_RET
    CEFBS_None, // LDS_BYTE_READ_RET
    CEFBS_None, // LDS_BYTE_WRITE
    CEFBS_None, // LDS_CMPST
    CEFBS_None, // LDS_CMPST_RET
    CEFBS_None, // LDS_MAX_INT
    CEFBS_None, // LDS_MAX_INT_RET
    CEFBS_None, // LDS_MAX_UINT
    CEFBS_None, // LDS_MAX_UINT_RET
    CEFBS_None, // LDS_MIN_INT
    CEFBS_None, // LDS_MIN_INT_RET
    CEFBS_None, // LDS_MIN_UINT
    CEFBS_None, // LDS_MIN_UINT_RET
    CEFBS_None, // LDS_OR
    CEFBS_None, // LDS_OR_RET
    CEFBS_None, // LDS_READ_RET
    CEFBS_None, // LDS_SHORT_READ_RET
    CEFBS_None, // LDS_SHORT_WRITE
    CEFBS_None, // LDS_SUB
    CEFBS_None, // LDS_SUB_RET
    CEFBS_None, // LDS_UBYTE_READ_RET
    CEFBS_None, // LDS_USHORT_READ_RET
    CEFBS_None, // LDS_WRITE
    CEFBS_None, // LDS_WRXCHG
    CEFBS_None, // LDS_WRXCHG_RET
    CEFBS_None, // LDS_XOR
    CEFBS_None, // LDS_XOR_RET
    CEFBS_None, // LITERALS
    CEFBS_None, // LOG_CLAMPED_eg
    CEFBS_None, // LOG_CLAMPED_r600
    CEFBS_None, // LOG_IEEE_cm
    CEFBS_None, // LOG_IEEE_eg
    CEFBS_None, // LOG_IEEE_r600
    CEFBS_None, // LOOP_BREAK_EG
    CEFBS_None, // LOOP_BREAK_R600
    CEFBS_None, // LSHL_eg
    CEFBS_None, // LSHL_r600
    CEFBS_None, // LSHR_eg
    CEFBS_None, // LSHR_r600
    CEFBS_None, // MAX
    CEFBS_None, // MAX_DX10
    CEFBS_None, // MAX_INT
    CEFBS_None, // MAX_UINT
    CEFBS_None, // MIN
    CEFBS_None, // MIN_DX10
    CEFBS_None, // MIN_INT
    CEFBS_None, // MIN_UINT
    CEFBS_None, // MOV
    CEFBS_None, // MOVA_INT_eg
    CEFBS_None, // MUL
    CEFBS_None, // MULADD_IEEE_eg
    CEFBS_None, // MULADD_IEEE_r600
    CEFBS_None, // MULADD_INT24_cm
    CEFBS_None, // MULADD_UINT24_eg
    CEFBS_None, // MULADD_eg
    CEFBS_None, // MULADD_r600
    CEFBS_None, // MULHI_INT_cm
    CEFBS_None, // MULHI_INT_cm24
    CEFBS_None, // MULHI_INT_eg
    CEFBS_None, // MULHI_INT_r600
    CEFBS_None, // MULHI_UINT24_eg
    CEFBS_None, // MULHI_UINT_cm
    CEFBS_None, // MULHI_UINT_cm24
    CEFBS_None, // MULHI_UINT_eg
    CEFBS_None, // MULHI_UINT_r600
    CEFBS_None, // MULLO_INT_cm
    CEFBS_None, // MULLO_INT_eg
    CEFBS_None, // MULLO_INT_r600
    CEFBS_None, // MULLO_UINT_cm
    CEFBS_None, // MULLO_UINT_eg
    CEFBS_None, // MULLO_UINT_r600
    CEFBS_None, // MUL_IEEE
    CEFBS_None, // MUL_INT24_cm
    CEFBS_None, // MUL_LIT_eg
    CEFBS_None, // MUL_LIT_r600
    CEFBS_None, // MUL_UINT24_eg
    CEFBS_None, // NOT_INT
    CEFBS_None, // OR_INT
    CEFBS_None, // PAD
    CEFBS_None, // POP_EG
    CEFBS_None, // POP_R600
    CEFBS_None, // PRED_SETE
    CEFBS_None, // PRED_SETE_INT
    CEFBS_None, // PRED_SETGE
    CEFBS_None, // PRED_SETGE_INT
    CEFBS_None, // PRED_SETGT
    CEFBS_None, // PRED_SETGT_INT
    CEFBS_None, // PRED_SETNE
    CEFBS_None, // PRED_SETNE_INT
    CEFBS_None, // R600_ExportBuf
    CEFBS_None, // R600_ExportSwz
    CEFBS_None, // RAT_ATOMIC_ADD_NORET
    CEFBS_None, // RAT_ATOMIC_ADD_RTN
    CEFBS_None, // RAT_ATOMIC_AND_NORET
    CEFBS_None, // RAT_ATOMIC_AND_RTN
    CEFBS_None, // RAT_ATOMIC_CMPXCHG_INT_NORET
    CEFBS_None, // RAT_ATOMIC_CMPXCHG_INT_RTN
    CEFBS_None, // RAT_ATOMIC_DEC_UINT_NORET
    CEFBS_None, // RAT_ATOMIC_DEC_UINT_RTN
    CEFBS_None, // RAT_ATOMIC_INC_UINT_NORET
    CEFBS_None, // RAT_ATOMIC_INC_UINT_RTN
    CEFBS_None, // RAT_ATOMIC_MAX_INT_NORET
    CEFBS_None, // RAT_ATOMIC_MAX_INT_RTN
    CEFBS_None, // RAT_ATOMIC_MAX_UINT_NORET
    CEFBS_None, // RAT_ATOMIC_MAX_UINT_RTN
    CEFBS_None, // RAT_ATOMIC_MIN_INT_NORET
    CEFBS_None, // RAT_ATOMIC_MIN_INT_RTN
    CEFBS_None, // RAT_ATOMIC_MIN_UINT_NORET
    CEFBS_None, // RAT_ATOMIC_MIN_UINT_RTN
    CEFBS_None, // RAT_ATOMIC_OR_NORET
    CEFBS_None, // RAT_ATOMIC_OR_RTN
    CEFBS_None, // RAT_ATOMIC_RSUB_NORET
    CEFBS_None, // RAT_ATOMIC_RSUB_RTN
    CEFBS_None, // RAT_ATOMIC_SUB_NORET
    CEFBS_None, // RAT_ATOMIC_SUB_RTN
    CEFBS_None, // RAT_ATOMIC_XCHG_INT_NORET
    CEFBS_None, // RAT_ATOMIC_XCHG_INT_RTN
    CEFBS_None, // RAT_ATOMIC_XOR_NORET
    CEFBS_None, // RAT_ATOMIC_XOR_RTN
    CEFBS_None, // RAT_MSKOR
    CEFBS_None, // RAT_STORE_DWORD128
    CEFBS_None, // RAT_STORE_DWORD32
    CEFBS_None, // RAT_STORE_DWORD64
    CEFBS_None, // RAT_STORE_TYPED_cm
    CEFBS_None, // RAT_STORE_TYPED_eg
    CEFBS_None, // RAT_WRITE_CACHELESS_128_eg
    CEFBS_None, // RAT_WRITE_CACHELESS_32_eg
    CEFBS_None, // RAT_WRITE_CACHELESS_64_eg
    CEFBS_None, // RECIPSQRT_CLAMPED_cm
    CEFBS_None, // RECIPSQRT_CLAMPED_eg
    CEFBS_None, // RECIPSQRT_CLAMPED_r600
    CEFBS_None, // RECIPSQRT_IEEE_cm
    CEFBS_None, // RECIPSQRT_IEEE_eg
    CEFBS_None, // RECIPSQRT_IEEE_r600
    CEFBS_None, // RECIP_CLAMPED_cm
    CEFBS_None, // RECIP_CLAMPED_eg
    CEFBS_None, // RECIP_CLAMPED_r600
    CEFBS_None, // RECIP_IEEE_cm
    CEFBS_None, // RECIP_IEEE_eg
    CEFBS_None, // RECIP_IEEE_r600
    CEFBS_None, // RECIP_UINT_eg
    CEFBS_None, // RECIP_UINT_r600
    CEFBS_None, // RNDNE
    CEFBS_None, // SETE
    CEFBS_None, // SETE_DX10
    CEFBS_None, // SETE_INT
    CEFBS_None, // SETGE_DX10
    CEFBS_None, // SETGE_INT
    CEFBS_None, // SETGE_UINT
    CEFBS_None, // SETGT_DX10
    CEFBS_None, // SETGT_INT
    CEFBS_None, // SETGT_UINT
    CEFBS_None, // SETNE_DX10
    CEFBS_None, // SETNE_INT
    CEFBS_None, // SGE
    CEFBS_None, // SGT
    CEFBS_None, // SIN_cm
    CEFBS_None, // SIN_eg
    CEFBS_None, // SIN_r600
    CEFBS_None, // SIN_r700
    CEFBS_None, // SNE
    CEFBS_None, // SUBB_UINT
    CEFBS_None, // SUB_INT
    CEFBS_None, // TEX_GET_GRADIENTS_H
    CEFBS_None, // TEX_GET_GRADIENTS_V
    CEFBS_None, // TEX_GET_TEXTURE_RESINFO
    CEFBS_None, // TEX_LD
    CEFBS_None, // TEX_LDPTR
    CEFBS_None, // TEX_SAMPLE
    CEFBS_None, // TEX_SAMPLE_C
    CEFBS_None, // TEX_SAMPLE_C_G
    CEFBS_None, // TEX_SAMPLE_C_L
    CEFBS_None, // TEX_SAMPLE_C_LB
    CEFBS_None, // TEX_SAMPLE_G
    CEFBS_None, // TEX_SAMPLE_L
    CEFBS_None, // TEX_SAMPLE_LB
    CEFBS_None, // TEX_SET_GRADIENTS_H
    CEFBS_None, // TEX_SET_GRADIENTS_V
    CEFBS_None, // TEX_VTX_CONSTBUF
    CEFBS_None, // TEX_VTX_TEXBUF
    CEFBS_None, // TRUNC
    CEFBS_None, // UINT_TO_FLT_eg
    CEFBS_None, // UINT_TO_FLT_r600
    CEFBS_None, // VTX_READ_128_cm
    CEFBS_None, // VTX_READ_128_eg
    CEFBS_None, // VTX_READ_16_cm
    CEFBS_None, // VTX_READ_16_eg
    CEFBS_None, // VTX_READ_32_cm
    CEFBS_None, // VTX_READ_32_eg
    CEFBS_None, // VTX_READ_64_cm
    CEFBS_None, // VTX_READ_64_eg
    CEFBS_None, // VTX_READ_8_cm
    CEFBS_None, // VTX_READ_8_eg
    CEFBS_None, // WHILE_LOOP_EG
    CEFBS_None, // WHILE_LOOP_R600
    CEFBS_None, // XOR_INT
  };

  assert(Opcode < 671);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::R600_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::R600_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::R600_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::R600_MC {

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
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
    Msg << "Attempting to emit " << &R600InstrNameData[R600InstrNameIndices[Opcode]]
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::R600_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

#ifdef GET_INSTRMAP_INFO
#undef GET_INSTRMAP_INFO

namespace llvm_ks::R600 {

enum usesCustomInserter {
  usesCustomInserter_0
};

// getLDSNoRetOp
LLVM_READONLY
int32_t getLDSNoRetOp(uint32_t Opcode) {
  using namespace R600;
  static constexpr uint32_t Table[][2] = {
    { LDS_ADD_RET, LDS_ADD },
    { LDS_AND_RET, LDS_AND },
    { LDS_MAX_INT_RET, LDS_MAX_INT },
    { LDS_MAX_UINT_RET, LDS_MAX_UINT },
    { LDS_MIN_INT_RET, LDS_MIN_INT },
    { LDS_MIN_UINT_RET, LDS_MIN_UINT },
    { LDS_OR_RET, LDS_OR },
    { LDS_SUB_RET, LDS_SUB },
    { LDS_WRXCHG_RET, LDS_WRXCHG },
    { LDS_XOR_RET, LDS_XOR },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 10;
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


} // namespace llvm_ks::R600

#endif // GET_INSTRMAP_INFO

