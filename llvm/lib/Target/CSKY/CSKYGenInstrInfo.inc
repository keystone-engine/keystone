/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::CSKY {

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
    ADJCALLSTACKDOWN                      = 331, // CSKYInstrInfo.td:511
    ADJCALLSTACKUP                        = 332, // CSKYInstrInfo.td:513
    BGENI                                 = 333, // CSKYInstrInfo.td:807
    CMPLEI16                              = 334, // CSKYInstrInfo16Instr.td:168
    CMPLEI32                              = 335, // CSKYInstrInfo.td:760
    CONSTPOOL_ENTRY                       = 336, // CSKYInstrInfo.td:1581
    FSELD                                 = 337, // CSKYInstrInfoF1.td:440
    FSELS                                 = 338, // CSKYInstrInfoF1.td:436
    ISEL16                                = 339, // CSKYInstrInfo16Instr.td:431
    ISEL32                                = 340, // CSKYInstrInfo.td:814
    JBF16                                 = 341, // CSKYInstrInfo16Instr.td:451
    JBF32                                 = 342, // CSKYInstrInfo.td:1543
    JBF_E                                 = 343, // CSKYInstrInfo.td:1559
    JBR16                                 = 344, // CSKYInstrInfo16Instr.td:447
    JBR32                                 = 345, // CSKYInstrInfo.td:1526
    JBSR32                                = 346, // CSKYInstrInfo.td:1524
    JBT16                                 = 347, // CSKYInstrInfo16Instr.td:449
    JBT32                                 = 348, // CSKYInstrInfo.td:1535
    JBT_E                                 = 349, // CSKYInstrInfo.td:1551
    LDQ32                                 = 350, // CSKYInstrInfo.td:703
    LOAD_PAIR                             = 351, // CSKYInstrInfo.td:749
    NEG16                                 = 352, // CSKYInstrInfo16Instr.td:124
    NEG32                                 = 353, // CSKYInstrInfo.td:571
    PseudoJMPI32                          = 354, // CSKYInstrInfo.td:1574
    PseudoJSRI32                          = 355, // CSKYInstrInfo.td:1571
    PseudoLRW16                           = 356, // CSKYInstrInfo16Instr.td:455
    PseudoLRW32                           = 357, // CSKYInstrInfo.td:1568
    PseudoTLSLA32                         = 358, // CSKYInstrInfo.td:1577
    RESTORE_CARRY                         = 359, // CSKYInstrInfo.td:739
    ROTRI32                               = 360, // CSKYInstrInfo.td:545
    RSUBI16                               = 361, // CSKYInstrInfo16Instr.td:127
    RSUBI32                               = 362, // CSKYInstrInfo.td:574
    SPILL_CARRY                           = 363, // CSKYInstrInfo.td:732
    STORE_PAIR                            = 364, // CSKYInstrInfo.td:744
    STQ32                                 = 365, // CSKYInstrInfo.td:705
    ABS32                                 = 366, // CSKYInstrInfo.td:961
    ADDC16                                = 367, // CSKYInstrInfo16Instr.td:65
    ADDC32                                = 368, // CSKYInstrInfo.td:616
    ADDI16                                = 369, // CSKYInstrInfo16Instr.td:95
    ADDI16SPSP                            = 370, // CSKYInstrInfo16Instr.td:110
    ADDI16XZ                              = 371, // CSKYInstrInfo16Instr.td:120
    ADDI16ZSP                             = 372, // CSKYInstrInfo16Instr.td:104
    ADDI32                                = 373, // CSKYInstrInfo.td:525
    ADDU16                                = 374, // CSKYInstrInfo16Instr.td:60
    ADDU16XZ                              = 375, // CSKYInstrInfo16Instr.td:70
    ADDU32                                = 376, // CSKYInstrInfo.td:549
    AND16                                 = 377, // CSKYInstrInfo16Instr.td:71
    AND32                                 = 378, // CSKYInstrInfo.td:556
    ANDI32                                = 379, // CSKYInstrInfo.td:530
    ANDN16                                = 380, // CSKYInstrInfo16Instr.td:80
    ANDN32                                = 381, // CSKYInstrInfo.td:558
    ANDNI32                               = 382, // CSKYInstrInfo.td:531
    ASR16                                 = 383, // CSKYInstrInfo16Instr.td:83
    ASR32                                 = 384, // CSKYInstrInfo.td:583
    ASRC32                                = 385, // CSKYInstrInfo.td:597
    ASRI16                                = 386, // CSKYInstrInfo16Instr.td:116
    ASRI32                                = 387, // CSKYInstrInfo.td:538
    BCLRI16                               = 388, // CSKYInstrInfo16Instr.td:320
    BCLRI32                               = 389, // CSKYInstrInfo.td:975
    BEZ32                                 = 390, // CSKYInstrInfo.td:845
    BF16                                  = 391, // CSKYInstrInfo16Instr.td:217
    BF32                                  = 392, // CSKYInstrInfo.td:838
    BGENR32                               = 393, // CSKYInstrInfo.td:962
    BHSZ32                                = 394, // CSKYInstrInfo.td:850
    BHZ32                                 = 395, // CSKYInstrInfo.td:847
    BKPT                                  = 396, // CSKYInstrInfo16Instr.td:361
    BLSZ32                                = 397, // CSKYInstrInfo.td:848
    BLZ32                                 = 398, // CSKYInstrInfo.td:849
    BMASKI32                              = 399, // CSKYInstrInfo.td:588
    BNEZ32                                = 400, // CSKYInstrInfo.td:846
    BNEZAD32                              = 401, // CSKYInstrInfo.td:866
    BPOPH                                 = 402, // CSKYInstrInfo16Instr.td:371
    BPOPW                                 = 403, // CSKYInstrInfo16Instr.td:372
    BPUSHH                                = 404, // CSKYInstrInfo16Instr.td:366
    BPUSHW                                = 405, // CSKYInstrInfo16Instr.td:367
    BR16                                  = 406, // CSKYInstrInfo16Instr.td:214
    BR32                                  = 407, // CSKYInstrInfo.td:830
    BRAR                                  = 408, // CSKYInstrInfo.td:944
    BRARS                                 = 409, // CSKYInstrInfo.td:945
    BRARW                                 = 410, // CSKYInstrInfo.td:940
    BRARWS                                = 411, // CSKYInstrInfo.td:941
    BREV32                                = 412, // CSKYInstrInfo.td:960
    BRWARW                                = 413, // CSKYInstrInfo.td:938
    BRWARWS                               = 414, // CSKYInstrInfo.td:939
    BRWAW                                 = 415, // CSKYInstrInfo.td:942
    BRWAWS                                = 416, // CSKYInstrInfo.td:943
    BSETI16                               = 417, // CSKYInstrInfo16Instr.td:322
    BSETI32                               = 418, // CSKYInstrInfo.td:977
    BSR32                                 = 419, // CSKYInstrInfo.td:879
    BSR32_BR                              = 420, // CSKYInstrInfo.td:881
    BT16                                  = 421, // CSKYInstrInfo16Instr.td:216
    BT32                                  = 422, // CSKYInstrInfo.td:833
    BTSTI16                               = 423, // CSKYInstrInfo16Instr.td:327
    BTSTI32                               = 424, // CSKYInstrInfo.td:974
    BWAW                                  = 425, // CSKYInstrInfo.td:946
    BWAWS                                 = 426, // CSKYInstrInfo.td:947
    CLRC16                                = 427, // CSKYInstrInfo16Instr.td:309
    CLRC32                                = 428, // CSKYInstrInfo.td:778
    CLRF32                                = 429, // CSKYInstrInfo.td:820
    CLRT32                                = 430, // CSKYInstrInfo.td:821
    CMPHS16                               = 431, // CSKYInstrInfo16Instr.td:160
    CMPHS32                               = 432, // CSKYInstrInfo.td:765
    CMPHSI16                              = 433, // CSKYInstrInfo16Instr.td:166
    CMPHSI32                              = 434, // CSKYInstrInfo.td:758
    CMPLT16                               = 435, // CSKYInstrInfo16Instr.td:161
    CMPLT32                               = 436, // CSKYInstrInfo.td:766
    CMPLTI16                              = 437, // CSKYInstrInfo16Instr.td:167
    CMPLTI32                              = 438, // CSKYInstrInfo.td:759
    CMPNE16                               = 439, // CSKYInstrInfo16Instr.td:163
    CMPNE32                               = 440, // CSKYInstrInfo.td:764
    CMPNEI16                              = 441, // CSKYInstrInfo16Instr.td:170
    CMPNEI32                              = 442, // CSKYInstrInfo.td:757
    CPOP32                                = 443, // CSKYInstrInfo.td:1062
    CPRC32                                = 444, // CSKYInstrInfo.td:1063
    CPRCR32                               = 445, // CSKYInstrInfo.td:1067
    CPRGR32                               = 446, // CSKYInstrInfo.td:1068
    CPWCR32                               = 447, // CSKYInstrInfo.td:1069
    CPWGR32                               = 448, // CSKYInstrInfo.td:1070
    DCACHE_CALL32                         = 449, // CSKYInstrInfo.td:1074
    DCACHE_CIALL32                        = 450, // CSKYInstrInfo.td:1075
    DCACHE_CISW32                         = 451, // CSKYInstrInfo.td:1082
    DCACHE_CIVA32                         = 452, // CSKYInstrInfo.td:1081
    DCACHE_CSW32                          = 453, // CSKYInstrInfo.td:1080
    DCACHE_CVA32                          = 454, // CSKYInstrInfo.td:1078
    DCACHE_CVAL32                         = 455, // CSKYInstrInfo.td:1079
    DCACHE_IALL32                         = 456, // CSKYInstrInfo.td:1073
    DCACHE_ISW32                          = 457, // CSKYInstrInfo.td:1077
    DCACHE_IVA32                          = 458, // CSKYInstrInfo.td:1076
    DECF32                                = 459, // CSKYInstrInfo.td:629
    DECGT32                               = 460, // CSKYInstrInfo.td:639
    DECLT32                               = 461, // CSKYInstrInfo.td:643
    DECNE32                               = 462, // CSKYInstrInfo.td:647
    DECT32                                = 463, // CSKYInstrInfo.td:630
    DIVS32                                = 464, // CSKYInstrInfo.td:634
    DIVU32                                = 465, // CSKYInstrInfo.td:636
    DOZE32                                = 466, // CSKYInstrInfo.td:1057
    FABSM                                 = 467, // CSKYInstrInfoF1.td:106
    FABS_D                                = 468, // CSKYInstrFormatsF1.td:90
    FABS_S                                = 469, // CSKYInstrFormatsF1.td:88
    FADDM                                 = 470, // CSKYInstrInfoF1.td:108
    FADD_D                                = 471, // CSKYInstrFormatsF1.td:119
    FADD_S                                = 472, // CSKYInstrFormatsF1.td:117
    FCMPHS_D                              = 473, // CSKYInstrFormatsF1.td:138
    FCMPHS_S                              = 474, // CSKYInstrFormatsF1.td:136
    FCMPLT_D                              = 475, // CSKYInstrFormatsF1.td:138
    FCMPLT_S                              = 476, // CSKYInstrFormatsF1.td:136
    FCMPNE_D                              = 477, // CSKYInstrFormatsF1.td:138
    FCMPNE_S                              = 478, // CSKYInstrFormatsF1.td:136
    FCMPUO_D                              = 479, // CSKYInstrFormatsF1.td:138
    FCMPUO_S                              = 480, // CSKYInstrFormatsF1.td:136
    FCMPZHS_D                             = 481, // CSKYInstrFormatsF1.td:145
    FCMPZHS_S                             = 482, // CSKYInstrFormatsF1.td:143
    FCMPZLS_D                             = 483, // CSKYInstrFormatsF1.td:145
    FCMPZLS_S                             = 484, // CSKYInstrFormatsF1.td:143
    FCMPZNE_D                             = 485, // CSKYInstrFormatsF1.td:145
    FCMPZNE_S                             = 486, // CSKYInstrFormatsF1.td:143
    FCMPZUO_D                             = 487, // CSKYInstrFormatsF1.td:145
    FCMPZUO_S                             = 488, // CSKYInstrFormatsF1.td:143
    FDIV_D                                = 489, // CSKYInstrFormatsF1.td:119
    FDIV_S                                = 490, // CSKYInstrFormatsF1.td:117
    FDTOS                                 = 491, // CSKYInstrInfoF1.td:198
    FF0                                   = 492, // CSKYInstrInfo.td:968
    FF1                                   = 493, // CSKYInstrInfo.td:969
    FLDM                                  = 494, // CSKYInstrInfoF1.td:271
    FLDMM                                 = 495, // CSKYInstrInfoF1.td:268
    FLDM_D                                = 496, // CSKYInstrFormatsF1.td:277
    FLDM_S                                = 497, // CSKYInstrFormatsF1.td:273
    FLDRM                                 = 498, // CSKYInstrInfoF1.td:266
    FLDR_D                                = 499, // CSKYInstrFormatsF1.td:247
    FLDR_S                                = 500, // CSKYInstrFormatsF1.td:245
    FLD_D                                 = 501, // CSKYInstrFormatsF1.td:241
    FLD_S                                 = 502, // CSKYInstrFormatsF1.td:239
    FMACM                                 = 503, // CSKYInstrInfoF1.td:112
    FMAC_D                                = 504, // CSKYInstrFormatsF1.td:132
    FMAC_S                                = 505, // CSKYInstrFormatsF1.td:130
    FMFVRH_D                              = 506, // CSKYInstrInfoF1.td:165
    FMFVRL                                = 507, // CSKYInstrInfoF1.td:156
    FMFVRL_D                              = 508, // CSKYInstrInfoF1.td:163
    FMOVM                                 = 509, // CSKYInstrInfoF1.td:117
    FMOV_D                                = 510, // CSKYInstrFormatsF1.td:84
    FMOV_S                                = 511, // CSKYInstrFormatsF1.td:82
    FMSCM                                 = 512, // CSKYInstrInfoF1.td:113
    FMSC_D                                = 513, // CSKYInstrFormatsF1.td:132
    FMSC_S                                = 514, // CSKYInstrFormatsF1.td:130
    FMTVRH_D                              = 515, // CSKYInstrInfoF1.td:171
    FMTVRL                                = 516, // CSKYInstrInfoF1.td:158
    FMTVRL_D                              = 517, // CSKYInstrInfoF1.td:168
    FMULM                                 = 518, // CSKYInstrInfoF1.td:110
    FMUL_D                                = 519, // CSKYInstrFormatsF1.td:119
    FMUL_S                                = 520, // CSKYInstrFormatsF1.td:117
    FNEGM                                 = 521, // CSKYInstrInfoF1.td:107
    FNEG_D                                = 522, // CSKYInstrFormatsF1.td:90
    FNEG_S                                = 523, // CSKYInstrFormatsF1.td:88
    FNMACM                                = 524, // CSKYInstrInfoF1.td:114
    FNMAC_D                               = 525, // CSKYInstrFormatsF1.td:132
    FNMAC_S                               = 526, // CSKYInstrFormatsF1.td:130
    FNMSCM                                = 527, // CSKYInstrInfoF1.td:115
    FNMSC_D                               = 528, // CSKYInstrFormatsF1.td:132
    FNMSC_S                               = 529, // CSKYInstrFormatsF1.td:130
    FNMULM                                = 530, // CSKYInstrInfoF1.td:111
    FNMUL_D                               = 531, // CSKYInstrFormatsF1.td:119
    FNMUL_S                               = 532, // CSKYInstrFormatsF1.td:117
    FRECIP_D                              = 533, // CSKYInstrFormatsF1.td:84
    FRECIP_S                              = 534, // CSKYInstrFormatsF1.td:82
    FSITOD                                = 535, // CSKYInstrInfoF1.td:187
    FSITOS                                = 536, // CSKYInstrInfoF1.td:177
    FSQRT_D                               = 537, // CSKYInstrFormatsF1.td:90
    FSQRT_S                               = 538, // CSKYInstrFormatsF1.td:88
    FSTM                                  = 539, // CSKYInstrInfoF1.td:287
    FSTMM                                 = 540, // CSKYInstrInfoF1.td:284
    FSTM_D                                = 541, // CSKYInstrFormatsF1.td:267
    FSTM_S                                = 542, // CSKYInstrFormatsF1.td:263
    FSTOD                                 = 543, // CSKYInstrInfoF1.td:199
    FSTRM                                 = 544, // CSKYInstrInfoF1.td:282
    FSTR_D                                = 545, // CSKYInstrFormatsF1.td:259
    FSTR_S                                = 546, // CSKYInstrFormatsF1.td:257
    FST_D                                 = 547, // CSKYInstrFormatsF1.td:253
    FST_S                                 = 548, // CSKYInstrFormatsF1.td:251
    FSUBM                                 = 549, // CSKYInstrInfoF1.td:109
    FSUB_D                                = 550, // CSKYInstrFormatsF1.td:119
    FSUB_S                                = 551, // CSKYInstrFormatsF1.td:117
    FUITOD                                = 552, // CSKYInstrInfoF1.td:192
    FUITOS                                = 553, // CSKYInstrInfoF1.td:182
    GRS32                                 = 554, // CSKYInstrInfo.td:902
    ICACHE_IALL32                         = 555, // CSKYInstrInfo.td:1084
    ICACHE_IALLS32                        = 556, // CSKYInstrInfo.td:1085
    ICACHE_IVA32                          = 557, // CSKYInstrInfo.td:1086
    IDLY32                                = 558, // CSKYInstrInfo.td:1054
    INCF32                                = 559, // CSKYInstrInfo.td:627
    INCT32                                = 560, // CSKYInstrInfo.td:628
    INS32                                 = 561, // CSKYInstrInfo.td:662
    IPOP16                                = 562, // CSKYInstrInfo16Instr.td:393
    IPUSH16                               = 563, // CSKYInstrInfo16Instr.td:384
    IXD32                                 = 564, // CSKYInstrInfo.td:612
    IXH32                                 = 565, // CSKYInstrInfo.td:607
    IXW32                                 = 566, // CSKYInstrInfo.td:609
    JMP16                                 = 567, // CSKYInstrInfo16Instr.td:220
    JMP32                                 = 568, // CSKYInstrInfo.td:853
    JMPI32                                = 569, // CSKYInstrInfo.td:854
    JMPIX16                               = 570, // CSKYInstrInfo16Instr.td:242
    JSR16                                 = 571, // CSKYInstrInfo16Instr.td:228
    JSR32                                 = 572, // CSKYInstrInfo.td:859
    JSRI32                                = 573, // CSKYInstrInfo.td:862
    L2CACHE_CALL                          = 574, // CSKYInstrInfo.td:1098
    L2CACHE_CIALL                         = 575, // CSKYInstrInfo.td:1099
    L2CACHE_IALL                          = 576, // CSKYInstrInfo.td:1097
    LD16B                                 = 577, // CSKYInstrInfo16Instr.td:134
    LD16H                                 = 578, // CSKYInstrInfo16Instr.td:136
    LD16W                                 = 579, // CSKYInstrInfo16Instr.td:138
    LD16WSP                               = 580, // CSKYInstrInfo16Instr.td:147
    LD32B                                 = 581, // CSKYInstrInfo.td:686
    LD32BS                                = 582, // CSKYInstrInfo.td:694
    LD32D                                 = 583, // CSKYInstrInfo.td:691
    LD32H                                 = 584, // CSKYInstrInfo.td:687
    LD32HS                                = 585, // CSKYInstrInfo.td:695
    LD32W                                 = 586, // CSKYInstrInfo.td:688
    LDEX32W                               = 587, // CSKYInstrInfo.td:949
    LDM32                                 = 588, // CSKYInstrInfo.td:697
    LDR32B                                = 589, // CSKYInstrInfo.td:719
    LDR32BS                               = 590, // CSKYInstrInfo.td:720
    LDR32H                                = 591, // CSKYInstrInfo.td:721
    LDR32HS                               = 592, // CSKYInstrInfo.td:722
    LDR32W                                = 593, // CSKYInstrInfo.td:723
    LRS32B                                = 594, // CSKYInstrInfo.td:906
    LRS32H                                = 595, // CSKYInstrInfo.td:908
    LRS32W                                = 596, // CSKYInstrInfo.td:910
    LRW16                                 = 597, // CSKYInstrInfo16Instr.td:259
    LRW16_Gen                             = 598, // CSKYInstrInfo16Instr.td:273
    LRW32                                 = 599, // CSKYInstrInfo.td:928
    LRW32_Gen                             = 600, // CSKYInstrInfo.td:930
    LSL16                                 = 601, // CSKYInstrInfo16Instr.td:81
    LSL32                                 = 602, // CSKYInstrInfo.td:579
    LSLC32                                = 603, // CSKYInstrInfo.td:589
    LSLI16                                = 604, // CSKYInstrInfo16Instr.td:114
    LSLI32                                = 605, // CSKYInstrInfo.td:532
    LSR16                                 = 606, // CSKYInstrInfo16Instr.td:82
    LSR32                                 = 607, // CSKYInstrInfo.td:581
    LSRC32                                = 608, // CSKYInstrInfo.td:593
    LSRI16                                = 609, // CSKYInstrInfo16Instr.td:115
    LSRI32                                = 610, // CSKYInstrInfo.td:535
    MFFCR                                 = 611, // CSKYInstrInfo.td:985
    MOV16                                 = 612, // CSKYInstrInfo16Instr.td:184
    MOV32                                 = 613, // CSKYInstrInfo.td:811
    MOVF32                                = 614, // CSKYInstrInfo.td:803
    MOVI16                                = 615, // CSKYInstrInfo16Instr.td:177
    MOVI32                                = 616, // CSKYInstrInfo.td:805
    MOVIH32                               = 617, // CSKYInstrInfo.td:808
    MOVT32                                = 618, // CSKYInstrInfo.td:802
    MTFCR                                 = 619, // CSKYInstrInfo.td:998
    MULATS32                              = 620, // CSKYInstrInfo.td:672
    MULATU32                              = 621, // CSKYInstrInfo.td:674
    MULSH16                               = 622, // CSKYInstrInfo16Instr.td:86
    MULSH32                               = 623, // CSKYInstrInfo.td:679
    MULT16                                = 624, // CSKYInstrInfo16Instr.td:77
    MULT32                                = 625, // CSKYInstrInfo.td:554
    MULTS32                               = 626, // CSKYInstrInfo.td:666
    MULTU32                               = 627, // CSKYInstrInfo.td:668
    MVC32                                 = 628, // CSKYInstrInfo.td:809
    MVCV16                                = 629, // CSKYInstrInfo16Instr.td:196
    MVCV32                                = 630, // CSKYInstrInfo.td:819
    NIE                                   = 631, // CSKYInstrInfo16Instr.td:375
    NIR                                   = 632, // CSKYInstrInfo16Instr.td:380
    NOR16                                 = 633, // CSKYInstrInfo16Instr.td:74
    NOR32                                 = 634, // CSKYInstrInfo.td:564
    NOT16                                 = 635, // CSKYInstrInfo16Instr.td:76
    NOT32                                 = 636, // CSKYInstrInfo.td:567
    OR16                                  = 637, // CSKYInstrInfo16Instr.td:72
    OR32                                  = 638, // CSKYInstrInfo.td:560
    ORI32                                 = 639, // CSKYInstrInfo.td:527
    PLDR32                                = 640, // CSKYInstrInfo.td:1102
    PLDW32                                = 641, // CSKYInstrInfo.td:1103
    POP16                                 = 642, // CSKYInstrInfo16Instr.td:414
    POP32                                 = 643, // CSKYInstrInfo.td:923
    PUSH16                                = 644, // CSKYInstrInfo16Instr.td:402
    PUSH32                                = 645, // CSKYInstrInfo.td:920
    REVB16                                = 646, // CSKYInstrInfo16Instr.td:294
    REVB32                                = 647, // CSKYInstrInfo.td:963
    REVH16                                = 648, // CSKYInstrInfo16Instr.td:295
    REVH32                                = 649, // CSKYInstrInfo.td:964
    RFI32                                 = 650, // CSKYInstrInfo.td:1050
    ROTL16                                = 651, // CSKYInstrInfo16Instr.td:84
    ROTL32                                = 652, // CSKYInstrInfo.td:585
    ROTLI32                               = 653, // CSKYInstrInfo.td:541
    RTS16                                 = 654, // CSKYInstrInfo16Instr.td:233
    SCE32                                 = 655, // CSKYInstrInfo.td:1051
    SE32                                  = 656, // CSKYInstrInfo.td:1059
    SETC16                                = 657, // CSKYInstrInfo16Instr.td:298
    SETC32                                = 658, // CSKYInstrInfo.td:768
    SEXT32                                = 659, // CSKYInstrInfo.td:652
    SEXTB16                               = 660, // CSKYInstrInfo16Instr.td:90
    SEXTB32                               = 661, // CSKYInstrInfo.td:654
    SEXTH16                               = 662, // CSKYInstrInfo16Instr.td:91
    SEXTH32                               = 663, // CSKYInstrInfo.td:655
    SRS32B                                = 664, // CSKYInstrInfo.td:912
    SRS32H                                = 665, // CSKYInstrInfo.td:914
    SRS32W                                = 666, // CSKYInstrInfo.td:916
    ST16B                                 = 667, // CSKYInstrInfo16Instr.td:140
    ST16H                                 = 668, // CSKYInstrInfo16Instr.td:142
    ST16W                                 = 669, // CSKYInstrInfo16Instr.td:144
    ST16WSP                               = 670, // CSKYInstrInfo16Instr.td:151
    ST32B                                 = 671, // CSKYInstrInfo.td:711
    ST32D                                 = 672, // CSKYInstrInfo.td:716
    ST32H                                 = 673, // CSKYInstrInfo.td:712
    ST32W                                 = 674, // CSKYInstrInfo.td:713
    STEX32W                               = 675, // CSKYInstrInfo.td:951
    STM32                                 = 676, // CSKYInstrInfo.td:699
    STOP32                                = 677, // CSKYInstrInfo.td:1055
    STR32B                                = 678, // CSKYInstrInfo.td:724
    STR32H                                = 679, // CSKYInstrInfo.td:725
    STR32W                                = 680, // CSKYInstrInfo.td:726
    SUBC16                                = 681, // CSKYInstrInfo16Instr.td:66
    SUBC32                                = 682, // CSKYInstrInfo.td:621
    SUBI16                                = 683, // CSKYInstrInfo16Instr.td:97
    SUBI16SPSP                            = 684, // CSKYInstrInfo16Instr.td:111
    SUBI16XZ                              = 685, // CSKYInstrInfo16Instr.td:121
    SUBI32                                = 686, // CSKYInstrInfo.td:526
    SUBU16                                = 687, // CSKYInstrInfo16Instr.td:62
    SUBU16XZ                              = 688, // CSKYInstrInfo16Instr.td:79
    SUBU32                                = 689, // CSKYInstrInfo.td:551
    SYNC0_32                              = 690, // CSKYInstrInfo.td:1013
    SYNC32                                = 691, // CSKYInstrInfo.td:1011
    SYNC_32_I                             = 692, // CSKYInstrInfo.td:1022
    SYNC_32_IS                            = 693, // CSKYInstrInfo.td:1040
    SYNC_32_S                             = 694, // CSKYInstrInfo.td:1031
    TLBI_ALL32                            = 695, // CSKYInstrInfo.td:1094
    TLBI_ALLS32                           = 696, // CSKYInstrInfo.td:1095
    TLBI_ASID32                           = 697, // CSKYInstrInfo.td:1090
    TLBI_ASIDS32                          = 698, // CSKYInstrInfo.td:1091
    TLBI_VA32                             = 699, // CSKYInstrInfo.td:1092
    TLBI_VAA32                            = 700, // CSKYInstrInfo.td:1088
    TLBI_VAAS32                           = 701, // CSKYInstrInfo.td:1089
    TLBI_VAS32                            = 702, // CSKYInstrInfo.td:1093
    TRAP32                                = 703, // CSKYInstrInfo.td:1105
    TST16                                 = 704, // CSKYInstrInfo16Instr.td:332
    TST32                                 = 705, // CSKYInstrInfo.td:789
    TSTNBZ16                              = 706, // CSKYInstrInfo16Instr.td:345
    TSTNBZ32                              = 707, // CSKYInstrInfo.td:790
    WAIT32                                = 708, // CSKYInstrInfo.td:1056
    WE32                                  = 709, // CSKYInstrInfo.td:1058
    WSC32                                 = 710, // CSKYInstrInfo.td:1060
    XOR16                                 = 711, // CSKYInstrInfo16Instr.td:73
    XOR32                                 = 712, // CSKYInstrInfo.td:562
    XORI32                                = 713, // CSKYInstrInfo.td:529
    XSR32                                 = 714, // CSKYInstrInfo.td:601
    XTRB0                                 = 715, // CSKYInstrInfo.td:970
    XTRB1                                 = 716, // CSKYInstrInfo.td:971
    XTRB2                                 = 717, // CSKYInstrInfo.td:972
    XTRB3                                 = 718, // CSKYInstrInfo.td:973
    ZEXT32                                = 719, // CSKYInstrInfo.td:659
    ZEXTB16                               = 720, // CSKYInstrInfo16Instr.td:88
    ZEXTB32                               = 721, // CSKYInstrInfo.td:656
    ZEXTH16                               = 722, // CSKYInstrInfo16Instr.td:89
    ZEXTH32                               = 723, // CSKYInstrInfo.td:657
    f2FABS_D                              = 724, // CSKYInstrFormatsF2.td:81
    f2FABS_S                              = 725, // CSKYInstrFormatsF2.td:79
    f2FADD_D                              = 726, // CSKYInstrFormatsF2.td:39
    f2FADD_S                              = 727, // CSKYInstrFormatsF2.td:35
    f2FCMPHSZ_D                           = 728, // CSKYInstrFormatsF2.td:115
    f2FCMPHSZ_S                           = 729, // CSKYInstrFormatsF2.td:113
    f2FCMPHS_D                            = 730, // CSKYInstrFormatsF2.td:101
    f2FCMPHS_S                            = 731, // CSKYInstrFormatsF2.td:99
    f2FCMPHZ_D                            = 732, // CSKYInstrFormatsF2.td:115
    f2FCMPHZ_S                            = 733, // CSKYInstrFormatsF2.td:113
    f2FCMPLSZ_D                           = 734, // CSKYInstrFormatsF2.td:115
    f2FCMPLSZ_S                           = 735, // CSKYInstrFormatsF2.td:113
    f2FCMPLTZ_D                           = 736, // CSKYInstrFormatsF2.td:115
    f2FCMPLTZ_S                           = 737, // CSKYInstrFormatsF2.td:113
    f2FCMPLT_D                            = 738, // CSKYInstrFormatsF2.td:101
    f2FCMPLT_S                            = 739, // CSKYInstrFormatsF2.td:99
    f2FCMPNEZ_D                           = 740, // CSKYInstrFormatsF2.td:115
    f2FCMPNEZ_S                           = 741, // CSKYInstrFormatsF2.td:113
    f2FCMPNE_D                            = 742, // CSKYInstrFormatsF2.td:101
    f2FCMPNE_S                            = 743, // CSKYInstrFormatsF2.td:99
    f2FCMPUOZ_D                           = 744, // CSKYInstrFormatsF2.td:115
    f2FCMPUOZ_S                           = 745, // CSKYInstrFormatsF2.td:113
    f2FCMPUO_D                            = 746, // CSKYInstrFormatsF2.td:101
    f2FCMPUO_S                            = 747, // CSKYInstrFormatsF2.td:99
    f2FDIV_D                              = 748, // CSKYInstrFormatsF2.td:39
    f2FDIV_S                              = 749, // CSKYInstrFormatsF2.td:35
    f2FDTOS                               = 750, // CSKYInstrInfoF2.td:278
    f2FF32TOFI32_RN                       = 751, // CSKYInstrFormatsF2.td:72
    f2FF32TOFI32_RNI                      = 752, // CSKYInstrFormatsF2.td:75
    f2FF32TOFI32_RPI                      = 753, // CSKYInstrFormatsF2.td:74
    f2FF32TOFI32_RZ                       = 754, // CSKYInstrFormatsF2.td:73
    f2FF32TOSI32_RN                       = 755, // CSKYInstrFormatsF2.td:72
    f2FF32TOSI32_RNI                      = 756, // CSKYInstrFormatsF2.td:75
    f2FF32TOSI32_RPI                      = 757, // CSKYInstrFormatsF2.td:74
    f2FF32TOSI32_RZ                       = 758, // CSKYInstrFormatsF2.td:73
    f2FF32TOUI32_RN                       = 759, // CSKYInstrFormatsF2.td:72
    f2FF32TOUI32_RNI                      = 760, // CSKYInstrFormatsF2.td:75
    f2FF32TOUI32_RPI                      = 761, // CSKYInstrFormatsF2.td:74
    f2FF32TOUI32_RZ                       = 762, // CSKYInstrFormatsF2.td:73
    f2FF64TOFI32_RN                       = 763, // CSKYInstrFormatsF2.td:72
    f2FF64TOFI32_RNI                      = 764, // CSKYInstrFormatsF2.td:75
    f2FF64TOFI32_RPI                      = 765, // CSKYInstrFormatsF2.td:74
    f2FF64TOFI32_RZ                       = 766, // CSKYInstrFormatsF2.td:73
    f2FF64TOSI32_RN                       = 767, // CSKYInstrFormatsF2.td:72
    f2FF64TOSI32_RNI                      = 768, // CSKYInstrFormatsF2.td:75
    f2FF64TOSI32_RPI                      = 769, // CSKYInstrFormatsF2.td:74
    f2FF64TOSI32_RZ                       = 770, // CSKYInstrFormatsF2.td:73
    f2FF64TOUI32_RN                       = 771, // CSKYInstrFormatsF2.td:72
    f2FF64TOUI32_RNI                      = 772, // CSKYInstrFormatsF2.td:75
    f2FF64TOUI32_RPI                      = 773, // CSKYInstrFormatsF2.td:74
    f2FF64TOUI32_RZ                       = 774, // CSKYInstrFormatsF2.td:73
    f2FFMULA_D                            = 775, // CSKYInstrFormatsF2.td:50
    f2FFMULA_S                            = 776, // CSKYInstrFormatsF2.td:46
    f2FFMULS_D                            = 777, // CSKYInstrFormatsF2.td:50
    f2FFMULS_S                            = 778, // CSKYInstrFormatsF2.td:46
    f2FFNMULA_D                           = 779, // CSKYInstrFormatsF2.td:50
    f2FFNMULA_S                           = 780, // CSKYInstrFormatsF2.td:46
    f2FFNMULS_D                           = 781, // CSKYInstrFormatsF2.td:50
    f2FFNMULS_S                           = 782, // CSKYInstrFormatsF2.td:46
    f2FFTOS32_D                           = 783, // CSKYInstrInfoF2.td:231
    f2FFTOS32_S                           = 784, // CSKYInstrInfoF2.td:222
    f2FFTOU32_D                           = 785, // CSKYInstrInfoF2.td:232
    f2FFTOU32_S                           = 786, // CSKYInstrInfoF2.td:223
    f2FFTOXS32_D                          = 787, // CSKYInstrInfoF2.td:236
    f2FFTOXS32_S                          = 788, // CSKYInstrInfoF2.td:227
    f2FFTOXU32_D                          = 789, // CSKYInstrInfoF2.td:235
    f2FFTOXU32_S                          = 790, // CSKYInstrInfoF2.td:226
    f2FINS                                = 791, // CSKYInstrInfoF2.td:287
    f2FLDMU_D                             = 792, // CSKYInstrInfoF2.td:88
    f2FLDMU_S                             = 793, // CSKYInstrInfoF2.td:86
    f2FLDM_D                              = 794, // CSKYInstrInfoF2.td:84
    f2FLDM_S                              = 795, // CSKYInstrInfoF2.td:82
    f2FLDR_D                              = 796, // CSKYInstrInfoF2.td:95
    f2FLDR_S                              = 797, // CSKYInstrInfoF2.td:93
    f2FLD_D                               = 798, // CSKYInstrInfoF2.td:63
    f2FLD_S                               = 799, // CSKYInstrInfoF2.td:61
    f2FLRW_D                              = 800, // CSKYInstrInfoF2.td:107
    f2FLRW_S                              = 801, // CSKYInstrInfoF2.td:106
    f2FMAXNM_D                            = 802, // CSKYInstrFormatsF2.td:39
    f2FMAXNM_S                            = 803, // CSKYInstrFormatsF2.td:35
    f2FMFVRH_D                            = 804, // CSKYInstrInfoF2.td:138
    f2FMFVRL                              = 805, // CSKYInstrInfoF2.td:124
    f2FMFVRL_2                            = 806, // CSKYInstrInfoF2.td:128
    f2FMFVRL_D                            = 807, // CSKYInstrInfoF2.td:135
    f2FMFVR_D                             = 808, // CSKYInstrInfoF2.td:142
    f2FMINNM_D                            = 809, // CSKYInstrFormatsF2.td:39
    f2FMINNM_S                            = 810, // CSKYInstrFormatsF2.td:35
    f2FMOVX                               = 811, // CSKYInstrInfoF2.td:55
    f2FMOV_D                              = 812, // CSKYInstrFormatsF2.td:87
    f2FMOV_S                              = 813, // CSKYInstrFormatsF2.td:85
    f2FMTVRH_D                            = 814, // CSKYInstrInfoF2.td:162
    f2FMTVRL                              = 815, // CSKYInstrInfoF2.td:148
    f2FMTVRL_2                            = 816, // CSKYInstrInfoF2.td:152
    f2FMTVRL_D                            = 817, // CSKYInstrInfoF2.td:158
    f2FMTVR_D                             = 818, // CSKYInstrInfoF2.td:165
    f2FMULA_D                             = 819, // CSKYInstrFormatsF2.td:50
    f2FMULA_S                             = 820, // CSKYInstrFormatsF2.td:46
    f2FMULS_D                             = 821, // CSKYInstrFormatsF2.td:50
    f2FMULS_S                             = 822, // CSKYInstrFormatsF2.td:46
    f2FMUL_D                              = 823, // CSKYInstrFormatsF2.td:39
    f2FMUL_S                              = 824, // CSKYInstrFormatsF2.td:35
    f2FNEG_D                              = 825, // CSKYInstrFormatsF2.td:81
    f2FNEG_S                              = 826, // CSKYInstrFormatsF2.td:79
    f2FNMULA_D                            = 827, // CSKYInstrFormatsF2.td:50
    f2FNMULA_S                            = 828, // CSKYInstrFormatsF2.td:46
    f2FNMULS_D                            = 829, // CSKYInstrFormatsF2.td:50
    f2FNMULS_S                            = 830, // CSKYInstrFormatsF2.td:46
    f2FNMUL_D                             = 831, // CSKYInstrFormatsF2.td:39
    f2FNMUL_S                             = 832, // CSKYInstrFormatsF2.td:35
    f2FS32TOF_D                           = 833, // CSKYInstrInfoF2.td:233
    f2FS32TOF_S                           = 834, // CSKYInstrInfoF2.td:224
    f2FSEL_D                              = 835, // CSKYInstrFormatsF2.td:195
    f2FSEL_S                              = 836, // CSKYInstrFormatsF2.td:193
    f2FSQRT_D                             = 837, // CSKYInstrFormatsF2.td:81
    f2FSQRT_S                             = 838, // CSKYInstrFormatsF2.td:79
    f2FSTMU_D                             = 839, // CSKYInstrInfoF2.td:78
    f2FSTMU_S                             = 840, // CSKYInstrInfoF2.td:76
    f2FSTM_D                              = 841, // CSKYInstrInfoF2.td:74
    f2FSTM_S                              = 842, // CSKYInstrInfoF2.td:72
    f2FSTOD                               = 843, // CSKYInstrInfoF2.td:280
    f2FSTR_D                              = 844, // CSKYInstrInfoF2.td:100
    f2FSTR_S                              = 845, // CSKYInstrInfoF2.td:98
    f2FST_D                               = 846, // CSKYInstrInfoF2.td:68
    f2FST_S                               = 847, // CSKYInstrInfoF2.td:66
    f2FSUB_D                              = 848, // CSKYInstrFormatsF2.td:39
    f2FSUB_S                              = 849, // CSKYInstrFormatsF2.td:35
    f2FU32TOF_D                           = 850, // CSKYInstrInfoF2.td:234
    f2FU32TOF_S                           = 851, // CSKYInstrInfoF2.td:225
    f2FXTOFS32_D                          = 852, // CSKYInstrInfoF2.td:238
    f2FXTOFS32_S                          = 853, // CSKYInstrInfoF2.td:229
    f2FXTOFU32_D                          = 854, // CSKYInstrInfoF2.td:237
    f2FXTOFU32_S                          = 855, // CSKYInstrInfoF2.td:228
    f2RECIP_D                             = 856, // CSKYInstrFormatsF2.td:87
    f2RECIP_S                             = 857, // CSKYInstrFormatsF2.td:85
    rnFDTOSI                              = 858, // CSKYInstrInfoF1.td:216
    rnFDTOUI                              = 859, // CSKYInstrInfoF1.td:217
    rnFSTOSI                              = 860, // CSKYInstrInfoF1.td:206
    rnFSTOUI                              = 861, // CSKYInstrInfoF1.td:207
    rniFDTOSI                             = 862, // CSKYInstrInfoF1.td:218
    rniFDTOUI                             = 863, // CSKYInstrInfoF1.td:219
    rniFSTOSI                             = 864, // CSKYInstrInfoF1.td:208
    rniFSTOUI                             = 865, // CSKYInstrInfoF1.td:209
    rpiFDTOSI                             = 866, // CSKYInstrInfoF1.td:212
    rpiFDTOUI                             = 867, // CSKYInstrInfoF1.td:213
    rpiFSTOSI                             = 868, // CSKYInstrInfoF1.td:202
    rpiFSTOUI                             = 869, // CSKYInstrInfoF1.td:203
    rzFDTOSI                              = 870, // CSKYInstrInfoF1.td:214
    rzFDTOUI                              = 871, // CSKYInstrInfoF1.td:215
    rzFSTOSI                              = 872, // CSKYInstrInfoF1.td:204
    rzFSTOUI                              = 873, // CSKYInstrInfoF1.td:205
    INSTRUCTION_LIST_END = 874
  };

} // namespace llvm_ks::CSKY

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::CSKY::Sched {

  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };

} // namespace llvm_ks::CSKY::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct CSKYInstrTable {
  MCInstrDesc Insts[874];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[24];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[470];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof CSKYInstrTable::ImplicitOps + sizeof CSKYInstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned CSKYOpInfoBase = (sizeof CSKYInstrTable::ImplicitOps + sizeof CSKYInstrTable::Padding) / sizeof(MCOperandInfo);

extern const CSKYInstrTable CSKYDescs = {
  {
    { 873,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rzFSTOUI
    { 872,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rzFSTOSI
    { 871,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rzFDTOUI
    { 870,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rzFDTOSI
    { 869,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rpiFSTOUI
    { 868,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rpiFSTOSI
    { 867,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rpiFDTOUI
    { 866,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rpiFDTOSI
    { 865,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rniFSTOUI
    { 864,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rniFSTOSI
    { 863,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rniFDTOUI
    { 862,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rniFDTOSI
    { 861,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rnFSTOUI
    { 860,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rnFSTOSI
    { 859,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rnFDTOUI
    { 858,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // rnFDTOSI
    { 857,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2RECIP_S
    { 856,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 386,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2RECIP_D
    { 855,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FXTOFU32_S
    { 854,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FXTOFU32_D
    { 853,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FXTOFS32_S
    { 852,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FXTOFS32_D
    { 851,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FU32TOF_S
    { 850,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 460,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FU32TOF_D
    { 849,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 393,	0,	0, 0x0ULL },  // f2FSUB_S
    { 848,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 390,	0,	0, 0x0ULL },  // f2FSUB_D
    { 847,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 433,	0,	0|(1ULL<<MCID::MayStore), 0x7ULL },  // f2FST_S
    { 846,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 430,	0,	0|(1ULL<<MCID::MayStore), 0x7ULL },  // f2FST_D
    { 845,	4,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 426,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // f2FSTR_S
    { 844,	4,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 422,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // f2FSTR_D
    { 843,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 460,	0,	0, 0x0ULL },  // f2FSTOD
    { 842,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 419,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic), 0x7ULL },  // f2FSTM_S
    { 841,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 416,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic), 0x7ULL },  // f2FSTM_D
    { 840,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 419,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic), 0x7ULL },  // f2FSTMU_S
    { 839,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 416,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic), 0x7ULL },  // f2FSTMU_D
    { 838,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0, 0x0ULL },  // f2FSQRT_S
    { 837,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 386,	0,	0, 0x0ULL },  // f2FSQRT_D
    { 836,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 466,	0,	0, 0x0ULL },  // f2FSEL_S
    { 835,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 462,	0,	0, 0x0ULL },  // f2FSEL_D
    { 834,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FS32TOF_S
    { 833,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 460,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FS32TOF_D
    { 832,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 393,	0,	0, 0x0ULL },  // f2FNMUL_S
    { 831,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 390,	0,	0, 0x0ULL },  // f2FNMUL_D
    { 830,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 412,	0,	0, 0x0ULL },  // f2FNMULS_S
    { 829,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 408,	0,	0, 0x0ULL },  // f2FNMULS_D
    { 828,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 412,	0,	0, 0x0ULL },  // f2FNMULA_S
    { 827,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 408,	0,	0, 0x0ULL },  // f2FNMULA_D
    { 826,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0, 0x0ULL },  // f2FNEG_S
    { 825,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 386,	0,	0, 0x0ULL },  // f2FNEG_D
    { 824,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 393,	0,	0, 0x0ULL },  // f2FMUL_S
    { 823,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 390,	0,	0, 0x0ULL },  // f2FMUL_D
    { 822,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 412,	0,	0, 0x0ULL },  // f2FMULS_S
    { 821,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 408,	0,	0, 0x0ULL },  // f2FMULS_D
    { 820,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 412,	0,	0, 0x0ULL },  // f2FMULA_S
    { 819,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 408,	0,	0, 0x0ULL },  // f2FMULA_D
    { 818,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 457,	0,	0, 0x0ULL },  // f2FMTVR_D
    { 817,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 455,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FMTVRL_D
    { 816,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 452,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FMTVRL_2
    { 815,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 450,	0,	0|(1ULL<<MCID::Bitcast), 0x0ULL },  // f2FMTVRL
    { 814,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 447,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FMTVRH_D
    { 813,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FMOV_S
    { 812,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 386,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FMOV_D
    { 811,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FMOVX
    { 810,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 393,	0,	0, 0x0ULL },  // f2FMINNM_S
    { 809,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 390,	0,	0, 0x0ULL },  // f2FMINNM_D
    { 808,	3,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 444,	0,	0, 0x0ULL },  // f2FMFVR_D
    { 807,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 440,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FMFVRL_D
    { 806,	3,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 444,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FMFVRL_2
    { 805,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 442,	0,	0|(1ULL<<MCID::Bitcast), 0x0ULL },  // f2FMFVRL
    { 804,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 440,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FMFVRH_D
    { 803,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 393,	0,	0, 0x0ULL },  // f2FMAXNM_S
    { 802,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 390,	0,	0, 0x0ULL },  // f2FMAXNM_D
    { 801,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 438,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // f2FLRW_S
    { 800,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 436,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // f2FLRW_D
    { 799,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 433,	0,	0|(1ULL<<MCID::MayLoad), 0x7ULL },  // f2FLD_S
    { 798,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 430,	0,	0|(1ULL<<MCID::MayLoad), 0x7ULL },  // f2FLD_D
    { 797,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 426,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // f2FLDR_S
    { 796,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 422,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // f2FLDR_D
    { 795,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 419,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Variadic), 0x7ULL },  // f2FLDM_S
    { 794,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 416,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Variadic), 0x7ULL },  // f2FLDM_D
    { 793,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 419,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Variadic), 0x7ULL },  // f2FLDMU_S
    { 792,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 416,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Variadic), 0x7ULL },  // f2FLDMU_D
    { 791,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FINS
    { 790,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FFTOXU32_S
    { 789,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FFTOXU32_D
    { 788,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FFTOXS32_S
    { 787,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FFTOXS32_D
    { 786,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FFTOU32_S
    { 785,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FFTOU32_D
    { 784,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FFTOS32_S
    { 783,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FFTOS32_D
    { 782,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 412,	0,	0, 0x0ULL },  // f2FFNMULS_S
    { 781,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 408,	0,	0, 0x0ULL },  // f2FFNMULS_D
    { 780,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 412,	0,	0, 0x0ULL },  // f2FFNMULA_S
    { 779,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 408,	0,	0, 0x0ULL },  // f2FFNMULA_D
    { 778,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 412,	0,	0, 0x0ULL },  // f2FFMULS_S
    { 777,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 408,	0,	0, 0x0ULL },  // f2FFMULS_D
    { 776,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 412,	0,	0, 0x0ULL },  // f2FFMULA_S
    { 775,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 408,	0,	0, 0x0ULL },  // f2FFMULA_D
    { 774,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOUI32_RZ
    { 773,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOUI32_RPI
    { 772,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOUI32_RNI
    { 771,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOUI32_RN
    { 770,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOSI32_RZ
    { 769,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOSI32_RPI
    { 768,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOSI32_RNI
    { 767,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOSI32_RN
    { 766,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOFI32_RZ
    { 765,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOFI32_RPI
    { 764,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOFI32_RNI
    { 763,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF64TOFI32_RN
    { 762,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOUI32_RZ
    { 761,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOUI32_RPI
    { 760,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOUI32_RNI
    { 759,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOUI32_RN
    { 758,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOSI32_RZ
    { 757,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOSI32_RPI
    { 756,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOSI32_RNI
    { 755,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOSI32_RN
    { 754,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOFI32_RZ
    { 753,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOFI32_RPI
    { 752,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOFI32_RNI
    { 751,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FF32TOFI32_RN
    { 750,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 406,	0,	0, 0x0ULL },  // f2FDTOS
    { 749,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 393,	0,	0, 0x0ULL },  // f2FDIV_S
    { 748,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 390,	0,	0, 0x0ULL },  // f2FDIV_D
    { 747,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 403,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPUO_S
    { 746,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 400,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPUO_D
    { 745,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 398,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPUOZ_S
    { 744,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 396,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPUOZ_D
    { 743,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 403,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPNE_S
    { 742,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 400,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPNE_D
    { 741,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 398,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPNEZ_S
    { 740,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 396,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPNEZ_D
    { 739,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 403,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPLT_S
    { 738,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 400,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPLT_D
    { 737,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 398,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPLTZ_S
    { 736,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 396,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPLTZ_D
    { 735,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 398,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPLSZ_S
    { 734,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 396,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPLSZ_D
    { 733,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 398,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPHZ_S
    { 732,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 396,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPHZ_D
    { 731,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 403,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPHS_S
    { 730,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 400,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPHS_D
    { 729,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 398,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPHSZ_S
    { 728,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 396,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // f2FCMPHSZ_D
    { 727,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 393,	0,	0, 0x0ULL },  // f2FADD_S
    { 726,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 390,	0,	0, 0x0ULL },  // f2FADD_D
    { 725,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 388,	0,	0, 0x0ULL },  // f2FABS_S
    { 724,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 386,	0,	0, 0x0ULL },  // f2FABS_D
    { 723,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0, 0x0ULL },  // ZEXTH32
    { 722,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 350,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ZEXTH16
    { 721,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0, 0x0ULL },  // ZEXTB32
    { 720,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 350,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ZEXTB16
    { 719,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 369,	0,	0, 0x0ULL },  // ZEXT32
    { 718,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XTRB3
    { 717,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XTRB2
    { 716,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XTRB1
    { 715,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XTRB0
    { 714,	5,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 381,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSR32
    { 713,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // XORI32
    { 712,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // XOR32
    { 711,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // XOR16
    { 710,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WSC32
    { 709,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WE32
    { 708,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WAIT32
    { 707,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 379,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TSTNBZ32
    { 706,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 377,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TSTNBZ16
    { 705,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 246,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TST32
    { 704,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 243,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TST16
    { 703,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TRAP32
    { 702,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBI_VAS32
    { 701,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBI_VAAS32
    { 700,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBI_VAA32
    { 699,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBI_VA32
    { 698,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBI_ASIDS32
    { 697,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBI_ASID32
    { 696,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBI_ALLS32
    { 695,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBI_ALL32
    { 694,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SYNC_32_S
    { 693,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SYNC_32_IS
    { 692,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SYNC_32_I
    { 691,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SYNC32
    { 690,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SYNC0_32
    { 689,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // SUBU32
    { 688,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0, 0x0ULL },  // SUBU16XZ
    { 687,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 222,	0,	0, 0x0ULL },  // SUBU16
    { 686,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // SUBI32
    { 685,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0, 0x0ULL },  // SUBI16XZ
    { 684,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 216,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBI16SPSP
    { 683,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 213,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // SUBI16
    { 682,	5,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 208,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBC32
    { 681,	5,	2,	2,	0,	0,	0,	CSKYOpInfoBase + 203,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBC16
    { 680,	4,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 340,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STR32W
    { 679,	4,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 340,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STR32H
    { 678,	4,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 340,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STR32B
    { 677,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STOP32
    { 676,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 179,	0,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STM32
    { 675,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 373,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL },  // STEX32W
    { 674,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::MayStore), 0x3ULL },  // ST32W
    { 673,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::MayStore), 0x2ULL },  // ST32H
    { 672,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 182,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL },  // ST32D
    { 671,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::MayStore), 0x1ULL },  // ST32B
    { 670,	3,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 219,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL },  // ST16WSP
    { 669,	3,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::MayStore), 0x6ULL },  // ST16W
    { 668,	3,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::MayStore), 0x5ULL },  // ST16H
    { 667,	3,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL },  // ST16B
    { 666,	2,	0,	4,	0,	1,	0,	CSKYOpInfoBase + 34,	20,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SRS32W
    { 665,	2,	0,	4,	0,	1,	0,	CSKYOpInfoBase + 34,	20,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SRS32H
    { 664,	2,	0,	4,	0,	1,	0,	CSKYOpInfoBase + 34,	20,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SRS32B
    { 663,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0, 0x0ULL },  // SEXTH32
    { 662,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 350,	0,	0, 0x0ULL },  // SEXTH16
    { 661,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0, 0x0ULL },  // SEXTB32
    { 660,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 350,	0,	0, 0x0ULL },  // SEXTB16
    { 659,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 369,	0,	0, 0x0ULL },  // SEXT32
    { 658,	1,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 239,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SETC32
    { 657,	1,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 239,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SETC16
    { 656,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SE32
    { 655,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SCE32
    { 654,	0,	0,	2,	0,	1,	0,	CSKYOpInfoBase + 1,	2,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // RTS16
    { 653,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ROTLI32
    { 652,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // ROTL32
    { 651,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0, 0x0ULL },  // ROTL16
    { 650,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RFI32
    { 649,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // REVH32
    { 648,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 350,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // REVH16
    { 647,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0, 0x0ULL },  // REVB32
    { 646,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 350,	0,	0, 0x0ULL },  // REVB16
    { 645,	1,	0,	4,	0,	1,	1,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PUSH32
    { 644,	1,	0,	2,	0,	1,	1,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PUSH16
    { 643,	1,	0,	4,	0,	2,	1,	CSKYOpInfoBase + 0,	21,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // POP32
    { 642,	1,	0,	2,	0,	1,	1,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // POP16
    { 641,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 34,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL },  // PLDW32
    { 640,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 34,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL },  // PLDR32
    { 639,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ORI32
    { 638,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // OR32
    { 637,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // OR16
    { 636,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0, 0x0ULL },  // NOT32
    { 635,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 367,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // NOT16
    { 634,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // NOR32
    { 633,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // NOR16
    { 632,	0,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // NIR
    { 631,	0,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0, 0x0ULL },  // NIE
    { 630,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 363,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MVCV32
    { 629,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 365,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MVCV16
    { 628,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 363,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MVC32
    { 627,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 360,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MULTU32
    { 626,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 360,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MULTS32
    { 625,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MULT32
    { 624,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MULT16
    { 623,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MULSH32
    { 622,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MULSH16
    { 621,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 356,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MULATU32
    { 620,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 356,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MULATS32
    { 619,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MTFCR
    { 618,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 352,	0,	0|(1ULL<<MCID::Select), 0x0ULL },  // MOVT32
    { 617,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 34,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // MOVIH32
    { 616,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 34,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // MOVI32
    { 615,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 338,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // MOVI16
    { 614,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 352,	0,	0|(1ULL<<MCID::Select)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MOVF32
    { 613,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MOV32
    { 612,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 350,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MOV16
    { 611,	1,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MFFCR
    { 610,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LSRI32
    { 609,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LSRI16
    { 608,	4,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 231,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LSRC32
    { 607,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // LSR32
    { 606,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0, 0x0ULL },  // LSR16
    { 605,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LSLI32
    { 604,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LSLI16
    { 603,	4,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 231,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LSLC32
    { 602,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // LSL32
    { 601,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0, 0x0ULL },  // LSL16
    { 600,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 347,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LRW32_Gen
    { 599,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 191,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LRW32
    { 598,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 344,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LRW16_Gen
    { 597,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 189,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LRW16
    { 596,	2,	1,	4,	0,	1,	0,	CSKYOpInfoBase + 34,	20,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LRS32W
    { 595,	2,	1,	4,	0,	1,	0,	CSKYOpInfoBase + 34,	20,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LRS32H
    { 594,	2,	1,	4,	0,	1,	0,	CSKYOpInfoBase + 34,	20,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LRS32B
    { 593,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 340,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDR32W
    { 592,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 340,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDR32HS
    { 591,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 340,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDR32H
    { 590,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 340,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDR32BS
    { 589,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 340,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDR32B
    { 588,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 179,	0,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDM32
    { 587,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL },  // LDEX32W
    { 586,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL },  // LD32W
    { 585,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::MayLoad), 0x2ULL },  // LD32HS
    { 584,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::MayLoad), 0x2ULL },  // LD32H
    { 583,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 182,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL },  // LD32D
    { 582,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL },  // LD32BS
    { 581,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL },  // LD32B
    { 580,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 219,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x6ULL },  // LD16WSP
    { 579,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::MayLoad), 0x6ULL },  // LD16W
    { 578,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::MayLoad), 0x5ULL },  // LD16H
    { 577,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL },  // LD16B
    { 576,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // L2CACHE_IALL
    { 575,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // L2CACHE_CIALL
    { 574,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // L2CACHE_CALL
    { 573,	1,	0,	4,	0,	0,	1,	CSKYOpInfoBase + 178,	2,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad), 0x0ULL },  // JSRI32
    { 572,	1,	0,	4,	0,	0,	1,	CSKYOpInfoBase + 28,	2,	0|(1ULL<<MCID::Call), 0x0ULL },  // JSR32
    { 571,	1,	0,	2,	0,	0,	1,	CSKYOpInfoBase + 337,	2,	0|(1ULL<<MCID::Call), 0x0ULL },  // JSR16
    { 570,	2,	0,	2,	0,	1,	0,	CSKYOpInfoBase + 338,	19,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JMPIX16
    { 569,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 178,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // JMPI32
    { 568,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // JMP32
    { 567,	1,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 337,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // JMP16
    { 566,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // IXW32
    { 565,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // IXH32
    { 564,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // IXD32
    { 563,	0,	0,	2,	0,	7,	1,	CSKYOpInfoBase + 1,	11,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IPUSH16
    { 562,	0,	0,	2,	0,	1,	7,	CSKYOpInfoBase + 1,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IPOP16
    { 561,	5,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 332,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INS32
    { 560,	5,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 255,	0,	0, 0x0ULL },  // INCT32
    { 559,	5,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 255,	0,	0, 0x0ULL },  // INCF32
    { 558,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IDLY32
    { 557,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICACHE_IVA32
    { 556,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICACHE_IALLS32
    { 555,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICACHE_IALL32
    { 554,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 191,	0,	0, 0x0ULL },  // GRS32
    { 553,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FUITOS
    { 552,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FUITOD
    { 551,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 272,	0,	0, 0x0ULL },  // FSUB_S
    { 550,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 269,	0,	0, 0x0ULL },  // FSUB_D
    { 549,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 266,	0,	0, 0x0ULL },  // FSUBM
    { 548,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 304,	0,	0|(1ULL<<MCID::MayStore), 0x7ULL },  // FST_S
    { 547,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 287,	0,	0|(1ULL<<MCID::MayStore), 0x7ULL },  // FST_D
    { 546,	4,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 300,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FSTR_S
    { 545,	4,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 296,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FSTR_D
    { 544,	4,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 296,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FSTRM
    { 543,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 330,	0,	0, 0x0ULL },  // FSTOD
    { 542,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 293,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic), 0x7ULL },  // FSTM_S
    { 541,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 290,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic), 0x7ULL },  // FSTM_D
    { 540,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 290,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic), 0x7ULL },  // FSTMM
    { 539,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 287,	0,	0|(1ULL<<MCID::MayStore), 0x7ULL },  // FSTM
    { 538,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0, 0x0ULL },  // FSQRT_S
    { 537,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0, 0x0ULL },  // FSQRT_D
    { 536,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSITOS
    { 535,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSITOD
    { 534,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FRECIP_S
    { 533,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FRECIP_D
    { 532,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 272,	0,	0, 0x0ULL },  // FNMUL_S
    { 531,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 269,	0,	0, 0x0ULL },  // FNMUL_D
    { 530,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 266,	0,	0, 0x0ULL },  // FNMULM
    { 529,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 315,	0,	0, 0x0ULL },  // FNMSC_S
    { 528,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 311,	0,	0, 0x0ULL },  // FNMSC_D
    { 527,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 307,	0,	0, 0x0ULL },  // FNMSCM
    { 526,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 315,	0,	0, 0x0ULL },  // FNMAC_S
    { 525,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 311,	0,	0, 0x0ULL },  // FNMAC_D
    { 524,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 307,	0,	0, 0x0ULL },  // FNMACM
    { 523,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0, 0x0ULL },  // FNEG_S
    { 522,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0, 0x0ULL },  // FNEG_D
    { 521,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 260,	0,	0, 0x0ULL },  // FNEGM
    { 520,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 272,	0,	0, 0x0ULL },  // FMUL_S
    { 519,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 269,	0,	0, 0x0ULL },  // FMUL_D
    { 518,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 266,	0,	0, 0x0ULL },  // FMULM
    { 517,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 328,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMTVRL_D
    { 516,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 326,	0,	0|(1ULL<<MCID::Bitcast), 0x0ULL },  // FMTVRL
    { 515,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 323,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMTVRH_D
    { 514,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 315,	0,	0, 0x0ULL },  // FMSC_S
    { 513,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 311,	0,	0, 0x0ULL },  // FMSC_D
    { 512,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 307,	0,	0, 0x0ULL },  // FMSCM
    { 511,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMOV_S
    { 510,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMOV_D
    { 509,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 260,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMOVM
    { 508,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 319,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMFVRL_D
    { 507,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 321,	0,	0|(1ULL<<MCID::Bitcast), 0x0ULL },  // FMFVRL
    { 506,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 319,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMFVRH_D
    { 505,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 315,	0,	0, 0x0ULL },  // FMAC_S
    { 504,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 311,	0,	0, 0x0ULL },  // FMAC_D
    { 503,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 307,	0,	0, 0x0ULL },  // FMACM
    { 502,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 304,	0,	0|(1ULL<<MCID::MayLoad), 0x7ULL },  // FLD_S
    { 501,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 287,	0,	0|(1ULL<<MCID::MayLoad), 0x7ULL },  // FLD_D
    { 500,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 300,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLDR_S
    { 499,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 296,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLDR_D
    { 498,	4,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 296,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLDRM
    { 497,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 293,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Variadic), 0x7ULL },  // FLDM_S
    { 496,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 290,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Variadic), 0x7ULL },  // FLDM_D
    { 495,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 290,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Variadic), 0x7ULL },  // FLDMM
    { 494,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 287,	0,	0|(1ULL<<MCID::MayLoad), 0x7ULL },  // FLDM
    { 493,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0, 0x0ULL },  // FF1
    { 492,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FF0
    { 491,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 285,	0,	0, 0x0ULL },  // FDTOS
    { 490,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 272,	0,	0, 0x0ULL },  // FDIV_S
    { 489,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 269,	0,	0, 0x0ULL },  // FDIV_D
    { 488,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 283,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPZUO_S
    { 487,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 281,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPZUO_D
    { 486,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 283,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPZNE_S
    { 485,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 281,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPZNE_D
    { 484,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 283,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPZLS_S
    { 483,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 281,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPZLS_D
    { 482,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 283,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPZHS_S
    { 481,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 281,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPZHS_D
    { 480,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 278,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPUO_S
    { 479,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPUO_D
    { 478,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 278,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPNE_S
    { 477,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPNE_D
    { 476,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 278,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPLT_S
    { 475,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPLT_D
    { 474,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 278,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPHS_S
    { 473,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPHS_D
    { 472,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 272,	0,	0, 0x0ULL },  // FADD_S
    { 471,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 269,	0,	0, 0x0ULL },  // FADD_D
    { 470,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 266,	0,	0, 0x0ULL },  // FADDM
    { 469,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 264,	0,	0, 0x0ULL },  // FABS_S
    { 468,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 262,	0,	0, 0x0ULL },  // FABS_D
    { 467,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 260,	0,	0, 0x0ULL },  // FABSM
    { 466,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DOZE32
    { 465,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // DIVU32
    { 464,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // DIVS32
    { 463,	5,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 255,	0,	0, 0x0ULL },  // DECT32
    { 462,	4,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 231,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DECNE32
    { 461,	4,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 231,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DECLT32
    { 460,	4,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 231,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DECGT32
    { 459,	5,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 255,	0,	0, 0x0ULL },  // DECF32
    { 458,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCACHE_IVA32
    { 457,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCACHE_ISW32
    { 456,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCACHE_IALL32
    { 455,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCACHE_CVAL32
    { 454,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCACHE_CVA32
    { 453,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCACHE_CSW32
    { 452,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCACHE_CIVA32
    { 451,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCACHE_CISW32
    { 450,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCACHE_CIALL32
    { 449,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DCACHE_CALL32
    { 448,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 252,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CPWGR32
    { 447,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 252,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CPWCR32
    { 446,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 252,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CPRGR32
    { 445,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 252,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CPRCR32
    { 444,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 249,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CPRC32
    { 443,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 9,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CPOP32
    { 442,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 154,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CMPNEI32
    { 441,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 151,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMPNEI16
    { 440,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 246,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CMPNE32
    { 439,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 243,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMPNE16
    { 438,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 154,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CMPLTI32
    { 437,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 151,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMPLTI16
    { 436,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 246,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CMPLT32
    { 435,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 243,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMPLT16
    { 434,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 154,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CMPHSI32
    { 433,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 151,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMPHSI16
    { 432,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 246,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CMPHS32
    { 431,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 243,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMPHS16
    { 430,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 240,	0,	0, 0x0ULL },  // CLRT32
    { 429,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 240,	0,	0, 0x0ULL },  // CLRF32
    { 428,	1,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 239,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRC32
    { 427,	1,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 239,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRC16
    { 426,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BWAWS
    { 425,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BWAW
    { 424,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 154,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // BTSTI32
    { 423,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 151,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BTSTI16
    { 422,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 176,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BT32
    { 421,	2,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 176,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BT16
    { 420,	1,	0,	4,	0,	0,	1,	CSKYOpInfoBase + 178,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BSR32_BR
    { 419,	1,	0,	4,	0,	0,	1,	CSKYOpInfoBase + 178,	2,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BSR32
    { 418,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0, 0x0ULL },  // BSETI32
    { 417,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 213,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BSETI16
    { 416,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRWAWS
    { 415,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRWAW
    { 414,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRWARWS
    { 413,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRWARW
    { 412,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0, 0x0ULL },  // BREV32
    { 411,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRARWS
    { 410,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRARW
    { 409,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRARS
    { 408,	0,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BRAR
    { 407,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 178,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0x0ULL },  // BR32
    { 406,	1,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 178,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Predicable)|(1ULL<<MCID::Terminator), 0x0ULL },  // BR16
    { 405,	1,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPUSHW
    { 404,	1,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPUSHH
    { 403,	1,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPOPW
    { 402,	1,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPOPH
    { 401,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 235,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BNEZAD32
    { 400,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 191,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BNEZ32
    { 399,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 34,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BMASKI32
    { 398,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 191,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BLZ32
    { 397,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 191,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BLSZ32
    { 396,	0,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BKPT
    { 395,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 191,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BHZ32
    { 394,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 191,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BHSZ32
    { 393,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BGENR32
    { 392,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 176,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BF32
    { 391,	2,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 176,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BF16
    { 390,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 191,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BEZ32
    { 389,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0, 0x0ULL },  // BCLRI32
    { 388,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 213,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BCLRI16
    { 387,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ASRI32
    { 386,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ASRI16
    { 385,	4,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 231,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ASRC32
    { 384,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // ASR32
    { 383,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0, 0x0ULL },  // ASR16
    { 382,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ANDNI32
    { 381,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0, 0x0ULL },  // ANDN32
    { 380,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0, 0x0ULL },  // ANDN16
    { 379,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ANDI32
    { 378,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // AND32
    { 377,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // AND16
    { 376,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 228,	0,	0|(1ULL<<MCID::Add)|(1ULL<<MCID::Commutable), 0x0ULL },  // ADDU32
    { 375,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 225,	0,	0|(1ULL<<MCID::Add)|(1ULL<<MCID::Commutable), 0x0ULL },  // ADDU16XZ
    { 374,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 222,	0,	0|(1ULL<<MCID::Add)|(1ULL<<MCID::Commutable), 0x0ULL },  // ADDU16
    { 373,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Add)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ADDI32
    { 372,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 219,	0,	0|(1ULL<<MCID::Add)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDI16ZSP
    { 371,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::Add), 0x0ULL },  // ADDI16XZ
    { 370,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 216,	0,	0|(1ULL<<MCID::Add)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDI16SPSP
    { 369,	3,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 213,	0,	0|(1ULL<<MCID::Add)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ADDI16
    { 368,	5,	2,	4,	0,	0,	0,	CSKYOpInfoBase + 208,	0,	0|(1ULL<<MCID::Add)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDC32
    { 367,	5,	2,	2,	0,	0,	0,	CSKYOpInfoBase + 203,	0,	0|(1ULL<<MCID::Add)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDC16
    { 366,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ABS32
    { 365,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 179,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STQ32
    { 364,	3,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 182,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STORE_PAIR
    { 363,	3,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 154,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPILL_CARRY
    { 362,	3,	1,	8,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RSUBI32
    { 361,	3,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 200,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RSUBI16
    { 360,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 197,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ROTRI32
    { 359,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 154,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RESTORE_CARRY
    { 358,	4,	2,	8,	0,	0,	0,	CSKYOpInfoBase + 193,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PseudoTLSLA32
    { 357,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 191,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PseudoLRW32
    { 356,	2,	1,	2,	0,	0,	0,	CSKYOpInfoBase + 189,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PseudoLRW16
    { 355,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PseudoJSRI32
    { 354,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PseudoJMPI32
    { 353,	2,	1,	8,	0,	0,	0,	CSKYOpInfoBase + 187,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // NEG32
    { 352,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 185,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // NEG16
    { 351,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 182,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LOAD_PAIR
    { 350,	3,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 179,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDQ32
    { 349,	2,	0,	6,	0,	0,	0,	CSKYOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JBT_E
    { 348,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JBT32
    { 347,	2,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JBT16
    { 346,	1,	0,	4,	0,	0,	1,	CSKYOpInfoBase + 178,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JBSR32
    { 345,	1,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JBR32
    { 344,	1,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JBR16
    { 343,	2,	0,	6,	0,	0,	0,	CSKYOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JBF_E
    { 342,	2,	0,	4,	0,	0,	0,	CSKYOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JBF32
    { 341,	2,	0,	2,	0,	0,	0,	CSKYOpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JBF16
    { 340,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 172,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ISEL32
    { 339,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 168,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ISEL16
    { 338,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 164,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // FSELS
    { 337,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 160,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // FSELD
    { 336,	3,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 157,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // CONSTPOOL_ENTRY
    { 335,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 154,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMPLEI32
    { 334,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMPLEI16
    { 333,	2,	1,	4,	0,	0,	0,	CSKYOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BGENI
    { 332,	2,	0,	0,	0,	1,	1,	CSKYOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // ADJCALLSTACKUP
    { 331,	2,	0,	0,	0,	1,	1,	CSKYOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // ADJCALLSTACKDOWN
    { 330,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	CSKYOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_15062
    { 41,	2,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_15061
    { 40,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_15060
    { 31,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	CSKYOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	CSKYOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // PHI
  }, {
    /* 0 */
    /* 0 */ CSKY::R14, CSKY::R14,
    /* 2 */ CSKY::R15,
    /* 3 */ CSKY::R14, CSKY::R14, CSKY::R0, CSKY::R1, CSKY::R2, CSKY::R3, CSKY::R12, CSKY::R13,
    /* 11 */ CSKY::R14, CSKY::R0, CSKY::R1, CSKY::R2, CSKY::R3, CSKY::R12, CSKY::R13, CSKY::R14,
    /* 19 */ CSKY::R30,
    /* 20 */ CSKY::R28,
    /* 21 */ CSKY::R14, CSKY::R15, CSKY::R14,
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
    /* 28 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
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
    /* 151 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 154 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 157 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 160 */ { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 164 */ { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 168 */ { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 172 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 176 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 178 */ { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 179 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 182 */ { CSKY::GPRPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 185 */ { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 187 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 189 */ { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 191 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 193 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 197 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 200 */ { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 203 */ { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 208 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 213 */ { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 216 */ { CSKY::GPRSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 219 */ { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 222 */ { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 225 */ { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 228 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 231 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 235 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 238 */ { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 239 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 240 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 243 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 246 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 249 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 252 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 255 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 260 */ { CSKY::sFPR64_VRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64_VRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 262 */ { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 264 */ { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 266 */ { CSKY::sFPR64_VRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64_VRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64_VRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 269 */ { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 272 */ { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 275 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 278 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 281 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 283 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 285 */ { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 287 */ { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 290 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 293 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 296 */ { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 300 */ { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 304 */ { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 307 */ { CSKY::sFPR64_VRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64_VRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::sFPR64_VRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64_VRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 311 */ { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 315 */ { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 319 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 321 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 323 */ { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 326 */ { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 328 */ { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 330 */ { CSKY::sFPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sFPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 332 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 337 */ { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 338 */ { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 340 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 344 */ { CSKY::mGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 347 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 350 */ { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 352 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 356 */ { CSKY::GPRPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRPairRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 360 */ { CSKY::GPRPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 363 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 365 */ { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 367 */ { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 369 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 373 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 377 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::sGPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 379 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 381 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 386 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 388 */ { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 390 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 393 */ { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 396 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 398 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 400 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 403 */ { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 406 */ { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 408 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 412 */ { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 416 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 419 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 422 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 426 */ { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 430 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 433 */ { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 436 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 438 */ { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 440 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 442 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 444 */ { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 447 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 450 */ { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 452 */ { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 455 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 457 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 460 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 462 */ { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 466 */ { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::CARRYRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { CSKY::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
  }
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char CSKYInstrNameData[] = {
  /* 0 */ "G_FLOG10\000"
  /* 9 */ "G_FEXP10\000"
  /* 18 */ "XTRB0\000"
  /* 24 */ "FF0\000"
  /* 28 */ "XTRB1\000"
  /* 34 */ "FF1\000"
  /* 38 */ "TLBI_VAA32\000"
  /* 49 */ "PseudoTLSLA32\000"
  /* 63 */ "DCACHE_CVA32\000"
  /* 76 */ "DCACHE_CIVA32\000"
  /* 90 */ "DCACHE_IVA32\000"
  /* 103 */ "ICACHE_IVA32\000"
  /* 116 */ "TLBI_VA32\000"
  /* 126 */ "SEXTB32\000"
  /* 134 */ "ZEXTB32\000"
  /* 142 */ "REVB32\000"
  /* 149 */ "SUBC32\000"
  /* 156 */ "ADDC32\000"
  /* 163 */ "LSLC32\000"
  /* 170 */ "SYNC32\000"
  /* 177 */ "CLRC32\000"
  /* 184 */ "CPRC32\000"
  /* 191 */ "ASRC32\000"
  /* 198 */ "LSRC32\000"
  /* 205 */ "WSC32\000"
  /* 211 */ "SETC32\000"
  /* 218 */ "MVC32\000"
  /* 224 */ "BNEZAD32\000"
  /* 233 */ "TLBI_ASID32\000"
  /* 245 */ "AND32\000"
  /* 251 */ "IXD32\000"
  /* 257 */ "SCE32\000"
  /* 263 */ "DECNE32\000"
  /* 271 */ "CMPNE32\000"
  /* 279 */ "SE32\000"
  /* 284 */ "WE32\000"
  /* 289 */ "DOZE32\000"
  /* 296 */ "JBF32\000"
  /* 302 */ "DECF32\000"
  /* 309 */ "INCF32\000"
  /* 316 */ "CLRF32\000"
  /* 323 */ "MOVF32\000"
  /* 330 */ "NEG32\000"
  /* 336 */ "MOVIH32\000"
  /* 344 */ "MULSH32\000"
  /* 352 */ "PUSH32\000"
  /* 359 */ "SEXTH32\000"
  /* 367 */ "ZEXTH32\000"
  /* 375 */ "REVH32\000"
  /* 382 */ "IXH32\000"
  /* 388 */ "RSUBI32\000"
  /* 396 */ "ADDI32\000"
  /* 403 */ "ANDI32\000"
  /* 410 */ "CMPLEI32\000"
  /* 419 */ "CMPNEI32\000"
  /* 428 */ "RFI32\000"
  /* 434 */ "BMASKI32\000"
  /* 443 */ "LSLI32\000"
  /* 450 */ "ROTLI32\000"
  /* 458 */ "ANDNI32\000"
  /* 466 */ "PseudoJMPI32\000"
  /* 479 */ "BCLRI32\000"
  /* 487 */ "XORI32\000"
  /* 494 */ "ASRI32\000"
  /* 501 */ "PseudoJSRI32\000"
  /* 514 */ "LSRI32\000"
  /* 521 */ "ROTRI32\000"
  /* 529 */ "CMPHSI32\000"
  /* 538 */ "BSETI32\000"
  /* 546 */ "CMPLTI32\000"
  /* 555 */ "BTSTI32\000"
  /* 563 */ "MOVI32\000"
  /* 570 */ "DCACHE_CVAL32\000"
  /* 584 */ "ISEL32\000"
  /* 591 */ "DCACHE_CALL32\000"
  /* 605 */ "DCACHE_CIALL32\000"
  /* 620 */ "DCACHE_IALL32\000"
  /* 634 */ "ICACHE_IALL32\000"
  /* 648 */ "TLBI_ALL32\000"
  /* 659 */ "LSL32\000"
  /* 665 */ "ROTL32\000"
  /* 672 */ "LDM32\000"
  /* 678 */ "STM32\000"
  /* 684 */ "ANDN32\000"
  /* 691 */ "TRAP32\000"
  /* 698 */ "JMP32\000"
  /* 704 */ "CPOP32\000"
  /* 711 */ "STOP32\000"
  /* 718 */ "LDQ32\000"
  /* 724 */ "STQ32\000"
  /* 730 */ "JBR32\000"
  /* 736 */ "CPRCR32\000"
  /* 744 */ "CPWCR32\000"
  /* 752 */ "PLDR32\000"
  /* 759 */ "CPRGR32\000"
  /* 767 */ "CPWGR32\000"
  /* 775 */ "BGENR32\000"
  /* 783 */ "NOR32\000"
  /* 789 */ "XOR32\000"
  /* 795 */ "ASR32\000"
  /* 801 */ "JBSR32\000"
  /* 808 */ "JSR32\000"
  /* 814 */ "LSR32\000"
  /* 820 */ "XSR32\000"
  /* 826 */ "TLBI_VAAS32\000"
  /* 838 */ "TLBI_VAS32\000"
  /* 849 */ "ABS32\000"
  /* 855 */ "TLBI_ASIDS32\000"
  /* 868 */ "CMPHS32\000"
  /* 876 */ "ICACHE_IALLS32\000"
  /* 891 */ "TLBI_ALLS32\000"
  /* 903 */ "INS32\000"
  /* 909 */ "GRS32\000"
  /* 915 */ "MULATS32\000"
  /* 924 */ "MULTS32\000"
  /* 932 */ "DIVS32\000"
  /* 939 */ "JBT32\000"
  /* 945 */ "DECT32\000"
  /* 952 */ "INCT32\000"
  /* 959 */ "DECGT32\000"
  /* 967 */ "WAIT32\000"
  /* 974 */ "DECLT32\000"
  /* 982 */ "CMPLT32\000"
  /* 990 */ "MULT32\000"
  /* 997 */ "NOT32\000"
  /* 1003 */ "CLRT32\000"
  /* 1010 */ "TST32\000"
  /* 1016 */ "MOVT32\000"
  /* 1023 */ "SEXT32\000"
  /* 1030 */ "ZEXT32\000"
  /* 1037 */ "SUBU32\000"
  /* 1044 */ "ADDU32\000"
  /* 1051 */ "MULATU32\000"
  /* 1060 */ "MULTU32\000"
  /* 1068 */ "DIVU32\000"
  /* 1075 */ "MVCV32\000"
  /* 1082 */ "BREV32\000"
  /* 1089 */ "MOV32\000"
  /* 1095 */ "PLDW32\000"
  /* 1102 */ "PseudoLRW32\000"
  /* 1114 */ "DCACHE_CSW32\000"
  /* 1127 */ "DCACHE_CISW32\000"
  /* 1141 */ "DCACHE_ISW32\000"
  /* 1154 */ "IXW32\000"
  /* 1160 */ "IDLY32\000"
  /* 1167 */ "TSTNBZ32\000"
  /* 1176 */ "BEZ32\000"
  /* 1182 */ "BNEZ32\000"
  /* 1189 */ "BHZ32\000"
  /* 1195 */ "BLZ32\000"
  /* 1201 */ "BHSZ32\000"
  /* 1208 */ "BLSZ32\000"
  /* 1215 */ "SYNC0_32\000"
  /* 1224 */ "XTRB2\000"
  /* 1230 */ "G_FLOG2\000"
  /* 1238 */ "G_FATAN2\000"
  /* 1247 */ "G_FEXP2\000"
  /* 1255 */ "f2FMFVRL_2\000"
  /* 1266 */ "f2FMTVRL_2\000"
  /* 1277 */ "XTRB3\000"
  /* 1283 */ "SEXTB16\000"
  /* 1291 */ "ZEXTB16\000"
  /* 1299 */ "REVB16\000"
  /* 1306 */ "SUBC16\000"
  /* 1313 */ "ADDC16\000"
  /* 1320 */ "CLRC16\000"
  /* 1327 */ "SETC16\000"
  /* 1334 */ "AND16\000"
  /* 1340 */ "CMPNE16\000"
  /* 1348 */ "JBF16\000"
  /* 1354 */ "NEG16\000"
  /* 1360 */ "MULSH16\000"
  /* 1368 */ "IPUSH16\000"
  /* 1376 */ "SEXTH16\000"
  /* 1384 */ "ZEXTH16\000"
  /* 1392 */ "REVH16\000"
  /* 1399 */ "RSUBI16\000"
  /* 1407 */ "ADDI16\000"
  /* 1414 */ "CMPLEI16\000"
  /* 1423 */ "CMPNEI16\000"
  /* 1432 */ "LSLI16\000"
  /* 1439 */ "BCLRI16\000"
  /* 1447 */ "ASRI16\000"
  /* 1454 */ "LSRI16\000"
  /* 1461 */ "CMPHSI16\000"
  /* 1470 */ "BSETI16\000"
  /* 1478 */ "CMPLTI16\000"
  /* 1487 */ "BTSTI16\000"
  /* 1495 */ "MOVI16\000"
  /* 1502 */ "ISEL16\000"
  /* 1509 */ "LSL16\000"
  /* 1515 */ "ROTL16\000"
  /* 1522 */ "ANDN16\000"
  /* 1529 */ "JMP16\000"
  /* 1535 */ "IPOP16\000"
  /* 1542 */ "JBR16\000"
  /* 1548 */ "NOR16\000"
  /* 1554 */ "XOR16\000"
  /* 1560 */ "ASR16\000"
  /* 1566 */ "JSR16\000"
  /* 1572 */ "LSR16\000"
  /* 1578 */ "CMPHS16\000"
  /* 1586 */ "RTS16\000"
  /* 1592 */ "JBT16\000"
  /* 1598 */ "CMPLT16\000"
  /* 1606 */ "MULT16\000"
  /* 1613 */ "NOT16\000"
  /* 1619 */ "TST16\000"
  /* 1625 */ "SUBU16\000"
  /* 1632 */ "ADDU16\000"
  /* 1639 */ "MVCV16\000"
  /* 1646 */ "MOV16\000"
  /* 1652 */ "PseudoLRW16\000"
  /* 1664 */ "JMPIX16\000"
  /* 1672 */ "TSTNBZ16\000"
  /* 1681 */ "G_FMA\000"
  /* 1687 */ "G_STRICT_FMA\000"
  /* 1700 */ "LD32B\000"
  /* 1706 */ "LDR32B\000"
  /* 1713 */ "STR32B\000"
  /* 1720 */ "LRS32B\000"
  /* 1727 */ "SRS32B\000"
  /* 1734 */ "ST32B\000"
  /* 1740 */ "LD16B\000"
  /* 1746 */ "ST16B\000"
  /* 1752 */ "G_FSUB\000"
  /* 1759 */ "G_STRICT_FSUB\000"
  /* 1773 */ "G_ATOMICRMW_FSUB\000"
  /* 1790 */ "G_SUB\000"
  /* 1796 */ "G_ATOMICRMW_SUB\000"
  /* 1812 */ "G_INTRINSIC\000"
  /* 1824 */ "G_FPTRUNC\000"
  /* 1834 */ "G_INTRINSIC_TRUNC\000"
  /* 1852 */ "G_TRUNC\000"
  /* 1860 */ "G_BUILD_VECTOR_TRUNC\000"
  /* 1881 */ "G_DYN_STACKALLOC\000"
  /* 1898 */ "LD32D\000"
  /* 1904 */ "ST32D\000"
  /* 1910 */ "G_FMAD\000"
  /* 1917 */ "G_FPEXTLOAD\000"
  /* 1929 */ "G_INDEXED_SEXTLOAD\000"
  /* 1948 */ "G_SEXTLOAD\000"
  /* 1959 */ "G_INDEXED_ZEXTLOAD\000"
  /* 1978 */ "G_ZEXTLOAD\000"
  /* 1989 */ "G_INDEXED_LOAD\000"
  /* 2004 */ "G_LOAD\000"
  /* 2011 */ "G_VECREDUCE_FADD\000"
  /* 2028 */ "G_FADD\000"
  /* 2035 */ "G_VECREDUCE_SEQ_FADD\000"
  /* 2056 */ "G_STRICT_FADD\000"
  /* 2070 */ "G_ATOMICRMW_FADD\000"
  /* 2087 */ "G_VECREDUCE_ADD\000"
  /* 2103 */ "G_ADD\000"
  /* 2109 */ "G_PTR_ADD\000"
  /* 2119 */ "G_ATOMICRMW_ADD\000"
  /* 2135 */ "FSELD\000"
  /* 2141 */ "G_ATOMICRMW_NAND\000"
  /* 2158 */ "G_VECREDUCE_AND\000"
  /* 2174 */ "G_AND\000"
  /* 2180 */ "G_ATOMICRMW_AND\000"
  /* 2196 */ "LIFETIME_END\000"
  /* 2209 */ "G_BRCOND\000"
  /* 2218 */ "G_ATOMICRMW_USUB_COND\000"
  /* 2240 */ "G_LLROUND\000"
  /* 2250 */ "G_LROUND\000"
  /* 2259 */ "G_INTRINSIC_ROUND\000"
  /* 2277 */ "G_INTRINSIC_FPTRUNC_ROUND\000"
  /* 2303 */ "FSITOD\000"
  /* 2310 */ "FUITOD\000"
  /* 2317 */ "f2FSTOD\000"
  /* 2325 */ "LOAD_STACK_GUARD\000"
  /* 2342 */ "f2FXTOFS32_D\000"
  /* 2355 */ "f2FFTOS32_D\000"
  /* 2367 */ "f2FFTOXS32_D\000"
  /* 2380 */ "f2FXTOFU32_D\000"
  /* 2393 */ "f2FFTOU32_D\000"
  /* 2405 */ "f2FFTOXU32_D\000"
  /* 2418 */ "f2FMULA_D\000"
  /* 2428 */ "f2FFMULA_D\000"
  /* 2439 */ "f2FNMULA_D\000"
  /* 2450 */ "f2FFNMULA_D\000"
  /* 2462 */ "f2FSUB_D\000"
  /* 2471 */ "FMAC_D\000"
  /* 2478 */ "FNMAC_D\000"
  /* 2486 */ "FMSC_D\000"
  /* 2493 */ "FNMSC_D\000"
  /* 2501 */ "f2FADD_D\000"
  /* 2510 */ "f2FLD_D\000"
  /* 2518 */ "f2FCMPNE_D\000"
  /* 2529 */ "FCMPZNE_D\000"
  /* 2539 */ "f2FS32TOF_D\000"
  /* 2551 */ "f2FU32TOF_D\000"
  /* 2563 */ "f2FNEG_D\000"
  /* 2572 */ "f2FMFVRH_D\000"
  /* 2583 */ "f2FMTVRH_D\000"
  /* 2594 */ "f2FSEL_D\000"
  /* 2603 */ "f2FMFVRL_D\000"
  /* 2614 */ "f2FMTVRL_D\000"
  /* 2625 */ "f2FMUL_D\000"
  /* 2634 */ "f2FNMUL_D\000"
  /* 2644 */ "f2FLDM_D\000"
  /* 2653 */ "f2FMINNM_D\000"
  /* 2664 */ "f2FMAXNM_D\000"
  /* 2675 */ "f2FSTM_D\000"
  /* 2684 */ "f2FCMPUO_D\000"
  /* 2695 */ "FCMPZUO_D\000"
  /* 2705 */ "f2RECIP_D\000"
  /* 2715 */ "FRECIP_D\000"
  /* 2724 */ "f2FLDR_D\000"
  /* 2733 */ "f2FSTR_D\000"
  /* 2742 */ "f2FMFVR_D\000"
  /* 2752 */ "f2FMTVR_D\000"
  /* 2762 */ "f2FABS_D\000"
  /* 2771 */ "f2FCMPHS_D\000"
  /* 2782 */ "FCMPZHS_D\000"
  /* 2792 */ "f2FMULS_D\000"
  /* 2802 */ "f2FFMULS_D\000"
  /* 2813 */ "f2FNMULS_D\000"
  /* 2824 */ "f2FFNMULS_D\000"
  /* 2836 */ "FCMPZLS_D\000"
  /* 2846 */ "f2FCMPLT_D\000"
  /* 2857 */ "f2FSQRT_D\000"
  /* 2867 */ "f2FST_D\000"
  /* 2875 */ "f2FLDMU_D\000"
  /* 2885 */ "f2FSTMU_D\000"
  /* 2895 */ "f2FDIV_D\000"
  /* 2904 */ "f2FMOV_D\000"
  /* 2913 */ "f2FLRW_D\000"
  /* 2922 */ "f2FCMPNEZ_D\000"
  /* 2934 */ "f2FCMPHZ_D\000"
  /* 2945 */ "f2FCMPUOZ_D\000"
  /* 2957 */ "f2FCMPHSZ_D\000"
  /* 2969 */ "f2FCMPLSZ_D\000"
  /* 2981 */ "f2FCMPLTZ_D\000"
  /* 2993 */ "PSEUDO_PROBE\000"
  /* 3006 */ "G_SSUBE\000"
  /* 3014 */ "G_USUBE\000"
  /* 3022 */ "G_FENCE\000"
  /* 3030 */ "ARITH_FENCE\000"
  /* 3042 */ "REG_SEQUENCE\000"
  /* 3055 */ "G_SADDE\000"
  /* 3063 */ "G_UADDE\000"
  /* 3071 */ "G_GET_FPMODE\000"
  /* 3084 */ "G_RESET_FPMODE\000"
  /* 3099 */ "G_SET_FPMODE\000"
  /* 3112 */ "G_FMINNUM_IEEE\000"
  /* 3127 */ "G_FMAXNUM_IEEE\000"
  /* 3142 */ "NIE\000"
  /* 3146 */ "G_VSCALE\000"
  /* 3155 */ "G_JUMP_TABLE\000"
  /* 3168 */ "BUNDLE\000"
  /* 3175 */ "G_MEMSET_INLINE\000"
  /* 3191 */ "G_MEMCPY_INLINE\000"
  /* 3207 */ "RELOC_NONE\000"
  /* 3218 */ "LOCAL_ESCAPE\000"
  /* 3231 */ "G_FPTRUNCSTORE\000"
  /* 3246 */ "G_STACKRESTORE\000"
  /* 3261 */ "G_INDEXED_STORE\000"
  /* 3277 */ "G_STORE\000"
  /* 3285 */ "G_BITREVERSE\000"
  /* 3298 */ "FAKE_USE\000"
  /* 3307 */ "DBG_VALUE\000"
  /* 3317 */ "G_GLOBAL_VALUE\000"
  /* 3332 */ "G_PTRAUTH_GLOBAL_VALUE\000"
  /* 3355 */ "CONVERGENCECTRL_GLUE\000"
  /* 3376 */ "G_STACKSAVE\000"
  /* 3388 */ "G_MEMMOVE\000"
  /* 3398 */ "G_FREEZE\000"
  /* 3407 */ "G_FCANONICALIZE\000"
  /* 3423 */ "JBF_E\000"
  /* 3429 */ "JBT_E\000"
  /* 3435 */ "G_FMODF\000"
  /* 3443 */ "INIT_UNDEF\000"
  /* 3454 */ "G_IMPLICIT_DEF\000"
  /* 3469 */ "DBG_INSTR_REF\000"
  /* 3483 */ "G_FNEG\000"
  /* 3490 */ "EXTRACT_SUBREG\000"
  /* 3505 */ "INSERT_SUBREG\000"
  /* 3519 */ "G_SEXT_INREG\000"
  /* 3532 */ "SUBREG_TO_REG\000"
  /* 3546 */ "G_ATOMIC_CMPXCHG\000"
  /* 3563 */ "G_ATOMICRMW_XCHG\000"
  /* 3580 */ "G_GET_ROUNDING\000"
  /* 3595 */ "G_SET_ROUNDING\000"
  /* 3610 */ "G_FLOG\000"
  /* 3617 */ "G_VAARG\000"
  /* 3625 */ "PREALLOCATED_ARG\000"
  /* 3642 */ "LD32H\000"
  /* 3648 */ "LDR32H\000"
  /* 3655 */ "STR32H\000"
  /* 3662 */ "LRS32H\000"
  /* 3669 */ "SRS32H\000"
  /* 3676 */ "ST32H\000"
  /* 3682 */ "LD16H\000"
  /* 3688 */ "ST16H\000"
  /* 3694 */ "G_PREFETCH\000"
  /* 3705 */ "BPUSHH\000"
  /* 3712 */ "G_SMULH\000"
  /* 3720 */ "G_UMULH\000"
  /* 3728 */ "G_FTANH\000"
  /* 3736 */ "G_FSINH\000"
  /* 3744 */ "BPOPH\000"
  /* 3750 */ "G_FCOSH\000"
  /* 3758 */ "DBG_PHI\000"
  /* 3766 */ "BGENI\000"
  /* 3772 */ "f2FF32TOFI32_RNI\000"
  /* 3789 */ "f2FF64TOFI32_RNI\000"
  /* 3806 */ "f2FF32TOSI32_RNI\000"
  /* 3823 */ "f2FF64TOSI32_RNI\000"
  /* 3840 */ "f2FF32TOUI32_RNI\000"
  /* 3857 */ "f2FF64TOUI32_RNI\000"
  /* 3874 */ "f2FF32TOFI32_RPI\000"
  /* 3891 */ "f2FF64TOFI32_RPI\000"
  /* 3908 */ "f2FF32TOSI32_RPI\000"
  /* 3925 */ "f2FF64TOSI32_RPI\000"
  /* 3942 */ "f2FF32TOUI32_RPI\000"
  /* 3959 */ "f2FF64TOUI32_RPI\000"
  /* 3976 */ "rniFDTOSI\000"
  /* 3986 */ "rpiFDTOSI\000"
  /* 3996 */ "rnFDTOSI\000"
  /* 4005 */ "rzFDTOSI\000"
  /* 4014 */ "G_FPTOSI\000"
  /* 4023 */ "rniFSTOSI\000"
  /* 4033 */ "rpiFSTOSI\000"
  /* 4043 */ "rnFSTOSI\000"
  /* 4052 */ "rzFSTOSI\000"
  /* 4061 */ "rniFDTOUI\000"
  /* 4071 */ "rpiFDTOUI\000"
  /* 4081 */ "rnFDTOUI\000"
  /* 4090 */ "rzFDTOUI\000"
  /* 4099 */ "G_FPTOUI\000"
  /* 4108 */ "rniFSTOUI\000"
  /* 4118 */ "rpiFSTOUI\000"
  /* 4128 */ "rnFSTOUI\000"
  /* 4137 */ "rzFSTOUI\000"
  /* 4146 */ "G_FPOWI\000"
  /* 4154 */ "SYNC_32_I\000"
  /* 4164 */ "COPY_LANEMASK\000"
  /* 4178 */ "G_PTRMASK\000"
  /* 4188 */ "GC_LABEL\000"
  /* 4197 */ "DBG_LABEL\000"
  /* 4207 */ "EH_LABEL\000"
  /* 4216 */ "ANNOTATION_LABEL\000"
  /* 4233 */ "ICALL_BRANCH_FUNNEL\000"
  /* 4253 */ "G_FSHL\000"
  /* 4260 */ "G_SHL\000"
  /* 4266 */ "G_FCEIL\000"
  /* 4274 */ "G_SAVGCEIL\000"
  /* 4285 */ "G_UAVGCEIL\000"
  /* 4296 */ "L2CACHE_CALL\000"
  /* 4309 */ "PATCHABLE_TAIL_CALL\000"
  /* 4329 */ "PATCHABLE_TYPED_EVENT_CALL\000"
  /* 4356 */ "PATCHABLE_EVENT_CALL\000"
  /* 4377 */ "FENTRY_CALL\000"
  /* 4389 */ "L2CACHE_CIALL\000"
  /* 4403 */ "L2CACHE_IALL\000"
  /* 4416 */ "KILL\000"
  /* 4421 */ "G_CONSTANT_POOL\000"
  /* 4437 */ "f2FMFVRL\000"
  /* 4446 */ "f2FMTVRL\000"
  /* 4455 */ "G_ROTL\000"
  /* 4462 */ "G_VECREDUCE_FMUL\000"
  /* 4479 */ "G_FMUL\000"
  /* 4486 */ "G_VECREDUCE_SEQ_FMUL\000"
  /* 4507 */ "G_STRICT_FMUL\000"
  /* 4521 */ "G_CLMUL\000"
  /* 4529 */ "G_VECREDUCE_MUL\000"
  /* 4545 */ "G_MUL\000"
  /* 4551 */ "FSUBM\000"
  /* 4557 */ "FMACM\000"
  /* 4563 */ "FNMACM\000"
  /* 4570 */ "FMSCM\000"
  /* 4576 */ "FNMSCM\000"
  /* 4583 */ "FADDM\000"
  /* 4589 */ "FLDM\000"
  /* 4594 */ "G_FREM\000"
  /* 4601 */ "G_STRICT_FREM\000"
  /* 4615 */ "G_SREM\000"
  /* 4622 */ "G_UREM\000"
  /* 4629 */ "G_SDIVREM\000"
  /* 4639 */ "G_UDIVREM\000"
  /* 4649 */ "FNEGM\000"
  /* 4655 */ "FMULM\000"
  /* 4661 */ "FNMULM\000"
  /* 4668 */ "FLDMM\000"
  /* 4674 */ "FSTMM\000"
  /* 4680 */ "FLDRM\000"
  /* 4686 */ "FSTRM\000"
  /* 4692 */ "INLINEASM\000"
  /* 4702 */ "FABSM\000"
  /* 4708 */ "FSTM\000"
  /* 4713 */ "G_VECREDUCE_FMINIMUM\000"
  /* 4734 */ "G_FMINIMUM\000"
  /* 4745 */ "G_ATOMICRMW_FMINIMUM\000"
  /* 4766 */ "G_VECREDUCE_FMAXIMUM\000"
  /* 4787 */ "G_FMAXIMUM\000"
  /* 4798 */ "G_ATOMICRMW_FMAXIMUM\000"
  /* 4819 */ "G_FMINIMUMNUM\000"
  /* 4833 */ "G_ATOMICRMW_FMINIMUMNUM\000"
  /* 4857 */ "G_FMAXIMUMNUM\000"
  /* 4871 */ "G_ATOMICRMW_FMAXIMUMNUM\000"
  /* 4895 */ "G_FMINNUM\000"
  /* 4905 */ "G_FMAXNUM\000"
  /* 4915 */ "FMOVM\000"
  /* 4921 */ "G_FATAN\000"
  /* 4929 */ "G_FTAN\000"
  /* 4936 */ "G_INTRINSIC_ROUNDEVEN\000"
  /* 4958 */ "G_ASSERT_ALIGN\000"
  /* 4973 */ "G_FCOPYSIGN\000"
  /* 4985 */ "G_VECREDUCE_FMIN\000"
  /* 5002 */ "G_ATOMICRMW_FMIN\000"
  /* 5019 */ "G_VECREDUCE_SMIN\000"
  /* 5036 */ "G_SMIN\000"
  /* 5043 */ "G_VECREDUCE_UMIN\000"
  /* 5060 */ "G_UMIN\000"
  /* 5067 */ "G_ATOMICRMW_UMIN\000"
  /* 5084 */ "G_ATOMICRMW_MIN\000"
  /* 5100 */ "G_FASIN\000"
  /* 5108 */ "G_FSIN\000"
  /* 5115 */ "CFI_INSTRUCTION\000"
  /* 5131 */ "G_CTLZ_ZERO_POISON\000"
  /* 5150 */ "G_CTTZ_ZERO_POISON\000"
  /* 5169 */ "f2FF32TOFI32_RN\000"
  /* 5185 */ "f2FF64TOFI32_RN\000"
  /* 5201 */ "f2FF32TOSI32_RN\000"
  /* 5217 */ "f2FF64TOSI32_RN\000"
  /* 5233 */ "f2FF32TOUI32_RN\000"
  /* 5249 */ "f2FF64TOUI32_RN\000"
  /* 5265 */ "ADJCALLSTACKDOWN\000"
  /* 5282 */ "G_SSUBO\000"
  /* 5290 */ "G_USUBO\000"
  /* 5298 */ "G_SADDO\000"
  /* 5306 */ "G_UADDO\000"
  /* 5314 */ "JUMP_TABLE_DEBUG_INFO\000"
  /* 5336 */ "G_SMULO\000"
  /* 5344 */ "G_UMULO\000"
  /* 5352 */ "G_BZERO\000"
  /* 5360 */ "STACKMAP\000"
  /* 5369 */ "G_DEBUGTRAP\000"
  /* 5381 */ "G_UBSANTRAP\000"
  /* 5393 */ "G_TRAP\000"
  /* 5400 */ "G_ATOMICRMW_UDEC_WRAP\000"
  /* 5422 */ "G_ATOMICRMW_UINC_WRAP\000"
  /* 5444 */ "G_BSWAP\000"
  /* 5452 */ "G_SITOFP\000"
  /* 5461 */ "G_UITOFP\000"
  /* 5470 */ "G_FCMP\000"
  /* 5477 */ "G_STRICT_FCMP\000"
  /* 5491 */ "G_ICMP\000"
  /* 5498 */ "G_SCMP\000"
  /* 5505 */ "G_UCMP\000"
  /* 5512 */ "CONVERGENCECTRL_LOOP\000"
  /* 5533 */ "G_CTPOP\000"
  /* 5541 */ "PATCHABLE_OP\000"
  /* 5554 */ "FAULTING_OP\000"
  /* 5566 */ "SUBI16SPSP\000"
  /* 5577 */ "ADDI16SPSP\000"
  /* 5588 */ "LD16WSP\000"
  /* 5596 */ "ST16WSP\000"
  /* 5604 */ "ADDI16ZSP\000"
  /* 5614 */ "ADJCALLSTACKUP\000"
  /* 5629 */ "PREALLOCATED_SETUP\000"
  /* 5648 */ "G_FLDEXP\000"
  /* 5657 */ "G_STRICT_FLDEXP\000"
  /* 5673 */ "G_FEXP\000"
  /* 5680 */ "G_FFREXP\000"
  /* 5689 */ "BRAR\000"
  /* 5694 */ "BSR32_BR\000"
  /* 5703 */ "G_BR\000"
  /* 5708 */ "INLINEASM_BR\000"
  /* 5721 */ "MFFCR\000"
  /* 5727 */ "MTFCR\000"
  /* 5733 */ "G_BLOCK_ADDR\000"
  /* 5746 */ "MEMBARRIER\000"
  /* 5757 */ "G_CONSTANT_FOLD_BARRIER\000"
  /* 5781 */ "PATCHABLE_FUNCTION_ENTER\000"
  /* 5806 */ "G_READCYCLECOUNTER\000"
  /* 5825 */ "G_READSTEADYCOUNTER\000"
  /* 5845 */ "G_READ_REGISTER\000"
  /* 5861 */ "G_WRITE_REGISTER\000"
  /* 5878 */ "G_ASHR\000"
  /* 5885 */ "G_FSHR\000"
  /* 5892 */ "G_LSHR\000"
  /* 5899 */ "LOAD_PAIR\000"
  /* 5909 */ "STORE_PAIR\000"
  /* 5920 */ "NIR\000"
  /* 5924 */ "CONVERGENCECTRL_ANCHOR\000"
  /* 5947 */ "G_FFLOOR\000"
  /* 5956 */ "G_SAVGFLOOR\000"
  /* 5968 */ "G_UAVGFLOOR\000"
  /* 5980 */ "G_EXTRACT_SUBVECTOR\000"
  /* 6000 */ "G_INSERT_SUBVECTOR\000"
  /* 6019 */ "G_BUILD_VECTOR\000"
  /* 6034 */ "G_SHUFFLE_VECTOR\000"
  /* 6051 */ "G_STEP_VECTOR\000"
  /* 6065 */ "G_SPLAT_VECTOR\000"
  /* 6080 */ "G_VECREDUCE_XOR\000"
  /* 6096 */ "G_XOR\000"
  /* 6102 */ "G_ATOMICRMW_XOR\000"
  /* 6118 */ "G_VECREDUCE_OR\000"
  /* 6133 */ "G_OR\000"
  /* 6138 */ "G_ATOMICRMW_OR\000"
  /* 6153 */ "G_ROTR\000"
  /* 6160 */ "G_INTTOPTR\000"
  /* 6171 */ "LD32BS\000"
  /* 6178 */ "LDR32BS\000"
  /* 6186 */ "G_FABS\000"
  /* 6193 */ "G_ABS\000"
  /* 6199 */ "G_ABDS\000"
  /* 6206 */ "G_UNMERGE_VALUES\000"
  /* 6223 */ "G_MERGE_VALUES\000"
  /* 6238 */ "LD32HS\000"
  /* 6245 */ "LDR32HS\000"
  /* 6253 */ "SYNC_32_IS\000"
  /* 6264 */ "FSELS\000"
  /* 6270 */ "G_CTLS\000"
  /* 6277 */ "f2FINS\000"
  /* 6284 */ "G_FACOS\000"
  /* 6292 */ "G_FCOS\000"
  /* 6299 */ "G_FSINCOS\000"
  /* 6309 */ "f2FDTOS\000"
  /* 6317 */ "FSITOS\000"
  /* 6324 */ "FUITOS\000"
  /* 6331 */ "G_STRICT_FCMPS\000"
  /* 6346 */ "BRARS\000"
  /* 6352 */ "G_CONCAT_VECTORS\000"
  /* 6369 */ "COPY_TO_REGCLASS\000"
  /* 6386 */ "G_IS_FPCLASS\000"
  /* 6399 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\000"
  /* 6429 */ "G_VECTOR_COMPRESS\000"
  /* 6447 */ "G_INTRINSIC_W_SIDE_EFFECTS\000"
  /* 6474 */ "G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS\000"
  /* 6512 */ "BWAWS\000"
  /* 6518 */ "BRWAWS\000"
  /* 6525 */ "BRARWS\000"
  /* 6532 */ "BRWARWS\000"
  /* 6540 */ "f2FXTOFS32_S\000"
  /* 6553 */ "f2FFTOS32_S\000"
  /* 6565 */ "f2FFTOXS32_S\000"
  /* 6578 */ "f2FXTOFU32_S\000"
  /* 6591 */ "f2FFTOU32_S\000"
  /* 6603 */ "f2FFTOXU32_S\000"
  /* 6616 */ "SYNC_32_S\000"
  /* 6626 */ "f2FMULA_S\000"
  /* 6636 */ "f2FFMULA_S\000"
  /* 6647 */ "f2FNMULA_S\000"
  /* 6658 */ "f2FFNMULA_S\000"
  /* 6670 */ "f2FSUB_S\000"
  /* 6679 */ "FMAC_S\000"
  /* 6686 */ "FNMAC_S\000"
  /* 6694 */ "FMSC_S\000"
  /* 6701 */ "FNMSC_S\000"
  /* 6709 */ "f2FADD_S\000"
  /* 6718 */ "f2FLD_S\000"
  /* 6726 */ "f2FCMPNE_S\000"
  /* 6737 */ "FCMPZNE_S\000"
  /* 6747 */ "f2FS32TOF_S\000"
  /* 6759 */ "f2FU32TOF_S\000"
  /* 6771 */ "f2FNEG_S\000"
  /* 6780 */ "f2FSEL_S\000"
  /* 6789 */ "f2FMUL_S\000"
  /* 6798 */ "f2FNMUL_S\000"
  /* 6808 */ "f2FLDM_S\000"
  /* 6817 */ "f2FMINNM_S\000"
  /* 6828 */ "f2FMAXNM_S\000"
  /* 6839 */ "f2FSTM_S\000"
  /* 6848 */ "f2FCMPUO_S\000"
  /* 6859 */ "FCMPZUO_S\000"
  /* 6869 */ "f2RECIP_S\000"
  /* 6879 */ "FRECIP_S\000"
  /* 6888 */ "f2FLDR_S\000"
  /* 6897 */ "f2FSTR_S\000"
  /* 6906 */ "f2FABS_S\000"
  /* 6915 */ "f2FCMPHS_S\000"
  /* 6926 */ "FCMPZHS_S\000"
  /* 6936 */ "f2FMULS_S\000"
  /* 6946 */ "f2FFMULS_S\000"
  /* 6957 */ "f2FNMULS_S\000"
  /* 6968 */ "f2FFNMULS_S\000"
  /* 6980 */ "FCMPZLS_S\000"
  /* 6990 */ "G_TRUNC_SSAT_S\000"
  /* 7005 */ "f2FCMPLT_S\000"
  /* 7016 */ "f2FSQRT_S\000"
  /* 7026 */ "f2FST_S\000"
  /* 7034 */ "f2FLDMU_S\000"
  /* 7044 */ "f2FSTMU_S\000"
  /* 7054 */ "f2FDIV_S\000"
  /* 7063 */ "f2FMOV_S\000"
  /* 7072 */ "f2FLRW_S\000"
  /* 7081 */ "f2FCMPNEZ_S\000"
  /* 7093 */ "f2FCMPHZ_S\000"
  /* 7104 */ "f2FCMPUOZ_S\000"
  /* 7116 */ "f2FCMPHSZ_S\000"
  /* 7128 */ "f2FCMPLSZ_S\000"
  /* 7140 */ "f2FCMPLTZ_S\000"
  /* 7152 */ "G_SSUBSAT\000"
  /* 7162 */ "G_USUBSAT\000"
  /* 7172 */ "G_SADDSAT\000"
  /* 7182 */ "G_UADDSAT\000"
  /* 7192 */ "G_SSHLSAT\000"
  /* 7202 */ "G_USHLSAT\000"
  /* 7212 */ "G_SMULFIXSAT\000"
  /* 7225 */ "G_UMULFIXSAT\000"
  /* 7238 */ "G_SDIVFIXSAT\000"
  /* 7251 */ "G_UDIVFIXSAT\000"
  /* 7264 */ "G_ATOMICRMW_USUB_SAT\000"
  /* 7285 */ "G_FPTOSI_SAT\000"
  /* 7298 */ "G_FPTOUI_SAT\000"
  /* 7311 */ "G_EXTRACT\000"
  /* 7321 */ "G_SELECT\000"
  /* 7330 */ "G_BRINDIRECT\000"
  /* 7343 */ "PATCHABLE_RET\000"
  /* 7357 */ "G_MEMSET\000"
  /* 7366 */ "PATCHABLE_FUNCTION_EXIT\000"
  /* 7390 */ "G_BRJT\000"
  /* 7397 */ "G_EXTRACT_VECTOR_ELT\000"
  /* 7418 */ "G_INSERT_VECTOR_ELT\000"
  /* 7438 */ "G_FCONSTANT\000"
  /* 7450 */ "G_CONSTANT\000"
  /* 7461 */ "G_INTRINSIC_CONVERGENT\000"
  /* 7484 */ "STATEPOINT\000"
  /* 7495 */ "PATCHPOINT\000"
  /* 7506 */ "G_PTRTOINT\000"
  /* 7517 */ "G_FRINT\000"
  /* 7525 */ "G_INTRINSIC_LLRINT\000"
  /* 7544 */ "G_INTRINSIC_LRINT\000"
  /* 7562 */ "G_FNEARBYINT\000"
  /* 7575 */ "BKPT\000"
  /* 7580 */ "G_VASTART\000"
  /* 7590 */ "LIFETIME_START\000"
  /* 7605 */ "G_INVOKE_REGION_START\000"
  /* 7627 */ "G_INSERT\000"
  /* 7636 */ "G_FSQRT\000"
  /* 7644 */ "G_STRICT_FSQRT\000"
  /* 7659 */ "G_BITCAST\000"
  /* 7669 */ "G_ADDRSPACE_CAST\000"
  /* 7686 */ "DBG_VALUE_LIST\000"
  /* 7701 */ "G_FPEXT\000"
  /* 7709 */ "G_SEXT\000"
  /* 7716 */ "G_ASSERT_SEXT\000"
  /* 7730 */ "G_ANYEXT\000"
  /* 7739 */ "G_ZEXT\000"
  /* 7746 */ "G_ASSERT_ZEXT\000"
  /* 7760 */ "G_ABDU\000"
  /* 7767 */ "G_TRUNC_SSAT_U\000"
  /* 7782 */ "G_TRUNC_USAT_U\000"
  /* 7797 */ "G_FDIV\000"
  /* 7804 */ "G_STRICT_FDIV\000"
  /* 7818 */ "G_SDIV\000"
  /* 7825 */ "G_UDIV\000"
  /* 7832 */ "G_GET_FPENV\000"
  /* 7844 */ "G_RESET_FPENV\000"
  /* 7858 */ "G_SET_FPENV\000"
  /* 7870 */ "LD32W\000"
  /* 7876 */ "LDR32W\000"
  /* 7883 */ "STR32W\000"
  /* 7890 */ "LRS32W\000"
  /* 7897 */ "SRS32W\000"
  /* 7904 */ "ST32W\000"
  /* 7910 */ "LDEX32W\000"
  /* 7918 */ "STEX32W\000"
  /* 7926 */ "LD16W\000"
  /* 7932 */ "ST16W\000"
  /* 7938 */ "BWAW\000"
  /* 7943 */ "BRWAW\000"
  /* 7949 */ "BPUSHW\000"
  /* 7956 */ "G_FPOW\000"
  /* 7963 */ "BPOPW\000"
  /* 7969 */ "BRARW\000"
  /* 7975 */ "BRWARW\000"
  /* 7982 */ "G_VECREDUCE_FMAX\000"
  /* 7999 */ "G_ATOMICRMW_FMAX\000"
  /* 8016 */ "G_VECREDUCE_SMAX\000"
  /* 8033 */ "G_SMAX\000"
  /* 8040 */ "G_VECREDUCE_UMAX\000"
  /* 8057 */ "G_UMAX\000"
  /* 8064 */ "G_ATOMICRMW_UMAX\000"
  /* 8081 */ "G_ATOMICRMW_MAX\000"
  /* 8097 */ "G_FRAME_INDEX\000"
  /* 8111 */ "G_SBFX\000"
  /* 8118 */ "G_UBFX\000"
  /* 8125 */ "G_SMULFIX\000"
  /* 8135 */ "G_UMULFIX\000"
  /* 8145 */ "G_SDIVFIX\000"
  /* 8155 */ "G_UDIVFIX\000"
  /* 8165 */ "f2FMOVX\000"
  /* 8173 */ "G_MEMCPY\000"
  /* 8182 */ "COPY\000"
  /* 8187 */ "RESTORE_CARRY\000"
  /* 8201 */ "SPILL_CARRY\000"
  /* 8213 */ "CONSTPOOL_ENTRY\000"
  /* 8229 */ "CONVERGENCECTRL_ENTRY\000"
  /* 8251 */ "G_CTLZ\000"
  /* 8258 */ "f2FF32TOFI32_RZ\000"
  /* 8274 */ "f2FF64TOFI32_RZ\000"
  /* 8290 */ "f2FF32TOSI32_RZ\000"
  /* 8306 */ "f2FF64TOSI32_RZ\000"
  /* 8322 */ "f2FF32TOUI32_RZ\000"
  /* 8338 */ "f2FF64TOUI32_RZ\000"
  /* 8354 */ "G_CTTZ\000"
  /* 8361 */ "SUBI16XZ\000"
  /* 8370 */ "ADDI16XZ\000"
  /* 8379 */ "SUBU16XZ\000"
  /* 8388 */ "ADDU16XZ\000"
  /* 8397 */ "LRW32_Gen\000"
  /* 8407 */ "LRW16_Gen\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned CSKYInstrNameIndices[] = {
    3762U, 4692U, 5708U, 5115U, 4207U, 4188U, 4216U, 4416U, 
    3490U, 3505U, 3456U, 3443U, 3532U, 6369U, 3307U, 7686U, 
    3469U, 3758U, 4197U, 3042U, 8182U, 4164U, 3168U, 7590U, 
    2196U, 2993U, 3030U, 5360U, 4377U, 7495U, 2325U, 5629U, 
    3625U, 7484U, 3218U, 5554U, 5541U, 5781U, 7343U, 7366U, 
    4309U, 4356U, 4329U, 4233U, 3298U, 5746U, 5314U, 3207U, 
    8229U, 5924U, 5512U, 3355U, 7716U, 7746U, 4958U, 2103U, 
    1790U, 4545U, 7818U, 7825U, 4615U, 4622U, 4629U, 4639U, 
    2174U, 6133U, 6096U, 6199U, 7760U, 5968U, 4285U, 5956U, 
    4274U, 3454U, 3760U, 8097U, 3317U, 3332U, 4421U, 7311U, 
    6206U, 7627U, 6223U, 6019U, 1860U, 6352U, 7506U, 6160U, 
    7659U, 3398U, 5757U, 2277U, 1834U, 2259U, 7544U, 7525U, 
    4936U, 5806U, 5825U, 2004U, 1948U, 1978U, 1917U, 1989U, 
    1929U, 1959U, 3277U, 3231U, 3261U, 6399U, 3546U, 3563U, 
    2119U, 1796U, 2180U, 2141U, 6138U, 6102U, 8081U, 5084U, 
    8064U, 5067U, 2070U, 1773U, 7999U, 5002U, 4798U, 4745U, 
    4871U, 4833U, 5422U, 5400U, 2218U, 7264U, 3022U, 3694U, 
    2209U, 7330U, 7605U, 1812U, 6447U, 7461U, 6474U, 7730U, 
    1852U, 6990U, 7767U, 7782U, 7450U, 7438U, 7580U, 3617U, 
    7709U, 3519U, 7739U, 4260U, 5892U, 5878U, 4253U, 5885U, 
    6153U, 4455U, 5491U, 5470U, 5498U, 5505U, 7321U, 5306U, 
    3063U, 5290U, 3014U, 5298U, 3055U, 5282U, 3006U, 5344U, 
    5336U, 3720U, 3712U, 7182U, 7172U, 7162U, 7152U, 7202U, 
    7192U, 8125U, 8135U, 7212U, 7225U, 8145U, 8155U, 7238U, 
    7251U, 2028U, 1752U, 4479U, 1681U, 1910U, 7797U, 4594U, 
    3435U, 7956U, 4146U, 5673U, 1247U, 9U, 3610U, 1230U, 
    0U, 5648U, 5680U, 3483U, 7701U, 1824U, 4014U, 4099U, 
    5452U, 5461U, 7285U, 7298U, 6186U, 4973U, 6386U, 3407U, 
    4895U, 4905U, 3112U, 3127U, 4734U, 4787U, 4819U, 4857U, 
    7832U, 7858U, 7844U, 3071U, 3099U, 3084U, 3580U, 3595U, 
    2109U, 4178U, 5036U, 8033U, 5060U, 8057U, 6193U, 2250U, 
    2240U, 5703U, 7390U, 3146U, 6000U, 5980U, 7418U, 7397U, 
    6034U, 6065U, 6051U, 6429U, 8354U, 5150U, 8251U, 5131U, 
    6270U, 5533U, 5444U, 3285U, 4521U, 4266U, 6292U, 5108U, 
    6299U, 4929U, 6284U, 5100U, 4921U, 1238U, 3750U, 3736U, 
    3728U, 7636U, 5947U, 7517U, 7562U, 7669U, 5733U, 3155U, 
    1881U, 3376U, 3246U, 2056U, 1759U, 4507U, 7804U, 4601U, 
    1687U, 7644U, 5657U, 5477U, 6331U, 5845U, 5861U, 8173U, 
    3191U, 3388U, 7357U, 5352U, 3175U, 5393U, 5369U, 5381U, 
    2035U, 4486U, 2011U, 4462U, 7982U, 4985U, 4766U, 4713U, 
    2087U, 4529U, 2158U, 6118U, 6080U, 8016U, 5019U, 8040U, 
    5043U, 8111U, 8118U, 5265U, 5614U, 3766U, 1414U, 410U, 
    8213U, 2135U, 6264U, 1502U, 584U, 1348U, 296U, 3423U, 
    1542U, 730U, 801U, 1592U, 939U, 3429U, 718U, 5899U, 
    1354U, 330U, 466U, 501U, 1652U, 1102U, 49U, 8187U, 
    521U, 1399U, 388U, 8201U, 5909U, 724U, 849U, 1313U, 
    156U, 1407U, 5577U, 8370U, 5604U, 396U, 1632U, 8388U, 
    1044U, 1334U, 245U, 403U, 1522U, 684U, 458U, 1560U, 
    795U, 191U, 1447U, 494U, 1439U, 479U, 1176U, 1349U, 
    297U, 775U, 1201U, 1189U, 7575U, 1208U, 1195U, 434U, 
    1182U, 224U, 3744U, 7963U, 3705U, 7949U, 1543U, 731U, 
    5689U, 6346U, 7969U, 6525U, 1082U, 7975U, 6532U, 7943U, 
    6518U, 1470U, 538U, 802U, 5694U, 1593U, 940U, 1487U, 
    555U, 7938U, 6512U, 1320U, 177U, 316U, 1003U, 1578U, 
    868U, 1461U, 529U, 1598U, 982U, 1478U, 546U, 1340U, 
    271U, 1423U, 419U, 704U, 184U, 736U, 759U, 744U, 
    767U, 591U, 605U, 1127U, 76U, 1114U, 63U, 570U, 
    620U, 1141U, 90U, 302U, 959U, 974U, 263U, 945U, 
    932U, 1068U, 289U, 4702U, 2764U, 6908U, 4583U, 2503U, 
    6711U, 2773U, 6917U, 2848U, 7007U, 2520U, 6728U, 2686U, 
    6850U, 2782U, 6926U, 2836U, 6980U, 2529U, 6737U, 2695U, 
    6859U, 2897U, 7056U, 6311U, 24U, 34U, 4589U, 4668U, 
    2646U, 6810U, 4680U, 2726U, 6890U, 2512U, 6720U, 4557U, 
    2471U, 6679U, 2574U, 4439U, 2605U, 4915U, 2906U, 7065U, 
    4570U, 2486U, 6694U, 2585U, 4448U, 2616U, 4655U, 2627U, 
    6791U, 4649U, 2565U, 6773U, 4563U, 2478U, 6686U, 4576U, 
    2493U, 6701U, 4661U, 2636U, 6800U, 2715U, 6879U, 2303U, 
    6317U, 2859U, 7018U, 4708U, 4674U, 2677U, 6841U, 2319U, 
    4686U, 2735U, 6899U, 2869U, 7028U, 4551U, 2464U, 6672U, 
    2310U, 6324U, 909U, 634U, 876U, 103U, 1160U, 309U, 
    952U, 903U, 1535U, 1368U, 251U, 382U, 1154U, 1529U, 
    698U, 472U, 1664U, 1566U, 808U, 507U, 4296U, 4389U, 
    4403U, 1740U, 3682U, 7926U, 5588U, 1700U, 6171U, 1898U, 
    3642U, 6238U, 7870U, 7910U, 672U, 1706U, 6178U, 3648U, 
    6245U, 7876U, 1720U, 3662U, 7890U, 1658U, 8407U, 1108U, 
    8397U, 1509U, 659U, 163U, 1432U, 443U, 1572U, 814U, 
    198U, 1454U, 514U, 5721U, 1646U, 1089U, 323U, 1495U, 
    563U, 336U, 1016U, 5727U, 915U, 1051U, 1360U, 344U, 
    1606U, 990U, 924U, 1060U, 218U, 1639U, 1075U, 3142U, 
    5920U, 1548U, 783U, 1613U, 997U, 1549U, 784U, 488U, 
    752U, 1095U, 1536U, 705U, 1369U, 352U, 1299U, 142U, 
    1392U, 375U, 428U, 1515U, 665U, 450U, 1586U, 257U, 
    279U, 1327U, 211U, 1023U, 1283U, 126U, 1376U, 359U, 
    1727U, 3669U, 7897U, 1746U, 3688U, 7932U, 5596U, 1734U, 
    1904U, 3676U, 7904U, 7918U, 678U, 711U, 1713U, 3655U, 
    7883U, 1306U, 149U, 1400U, 5566U, 8361U, 389U, 1625U, 
    8379U, 1037U, 1215U, 170U, 4154U, 6253U, 6616U, 648U, 
    891U, 233U, 855U, 116U, 38U, 826U, 838U, 691U, 
    1619U, 1010U, 1672U, 1167U, 967U, 284U, 205U, 1554U, 
    789U, 487U, 820U, 18U, 28U, 1224U, 1277U, 1030U, 
    1291U, 134U, 1384U, 367U, 2762U, 6906U, 2501U, 6709U, 
    2957U, 7116U, 2771U, 6915U, 2934U, 7093U, 2969U, 7128U, 
    2981U, 7140U, 2846U, 7005U, 2922U, 7081U, 2518U, 6726U, 
    2945U, 7104U, 2684U, 6848U, 2895U, 7054U, 6309U, 5169U, 
    3772U, 3874U, 8258U, 5201U, 3806U, 3908U, 8290U, 5233U, 
    3840U, 3942U, 8322U, 5185U, 3789U, 3891U, 8274U, 5217U, 
    3823U, 3925U, 8306U, 5249U, 3857U, 3959U, 8338U, 2428U, 
    6636U, 2802U, 6946U, 2450U, 6658U, 2824U, 6968U, 2355U, 
    6553U, 2393U, 6591U, 2367U, 6565U, 2405U, 6603U, 6277U, 
    2875U, 7034U, 2644U, 6808U, 2724U, 6888U, 2510U, 6718U, 
    2913U, 7072U, 2664U, 6828U, 2572U, 4437U, 1255U, 2603U, 
    2742U, 2653U, 6817U, 8165U, 2904U, 7063U, 2583U, 4446U, 
    1266U, 2614U, 2752U, 2418U, 6626U, 2792U, 6936U, 2625U, 
    6789U, 2563U, 6771U, 2439U, 6647U, 2813U, 6957U, 2634U, 
    6798U, 2539U, 6747U, 2594U, 6780U, 2857U, 7016U, 2885U, 
    7044U, 2675U, 6839U, 2317U, 2733U, 6897U, 2867U, 7026U, 
    2462U, 6670U, 2551U, 6759U, 2342U, 6540U, 2380U, 6578U, 
    2705U, 6869U, 3996U, 4081U, 4043U, 4128U, 3976U, 4061U, 
    4023U, 4108U, 3986U, 4071U, 4033U, 4118U, 4005U, 4090U, 
    4052U, 4137U, 
};

static inline void InitCSKYMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(CSKYDescs.Insts, CSKYInstrNameIndices, CSKYInstrNameData, nullptr, nullptr, 874, nullptr, 0);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct CSKYGenInstrInfo : public TargetInstrInfo {
  explicit CSKYGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~CSKYGenInstrInfo() override = default;
};

} // namespace llvm_ks

namespace llvm_ks::CSKY {


} // namespace llvm_ks::CSKY

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

extern const CSKYInstrTable CSKYDescs;
extern const unsigned CSKYInstrNameIndices[];
extern const char CSKYInstrNameData[];
CSKYGenInstrInfo::CSKYGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(CSKYDescs.Insts, CSKYInstrNameIndices, CSKYInstrNameData, nullptr, nullptr, 874);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace CSKY_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace CSKY_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::CSKY_MC {


} // namespace llvm_ks::CSKY_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::CSKY_MC {

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_HasFPUv2_SFBit = 11,
  Feature_HasFPUv2_DFBit = 10,
  Feature_HasFdivduBit = 16,
  Feature_HasFPUv3_HIBit = 14,
  Feature_HasFPUv3_HFBit = 13,
  Feature_HasFPUv3_SFBit = 15,
  Feature_HasFPUv3_DFBit = 12,
  Feature_iHasFLOATE1Bit = 44,
  Feature_iHasFLOAT1E2Bit = 40,
  Feature_iHasFLOAT1E3Bit = 41,
  Feature_iHasFLOAT3E4Bit = 42,
  Feature_iHasFLOAT7E60Bit = 43,
  Feature_HasHWDivBit = 17,
  Feature_HasSTMBit = 22,
  Feature_HasPushPopBit = 21,
  Feature_HasDSPBit = 5,
  Feature_iHasDSP1E2Bit = 36,
  Feature_iHasDSPE60Bit = 37,
  Feature_HasDSPV2Bit = 6,
  Feature_HasDSP_SilanBit = 7,
  Feature_HasBTST16Bit = 3,
  Feature_HasExtendLrwBit = 9,
  Feature_HasTrustBit = 23,
  Feature_HasJAVABit = 19,
  Feature_HasCacheBit = 4,
  Feature_HasNVICBit = 20,
  Feature_HasDoloopBit = 8,
  Feature_HasHighRegistersBit = 18,
  Feature_SmartModeBit = 27,
  Feature_HasVDSPV2Bit = 25,
  Feature_iHasVDSP2E3Bit = 47,
  Feature_iHasVDSP2E60FBit = 48,
  Feature_ReadTPHardBit = 26,
  Feature_EnableInterruptAttributeBit = 1,
  Feature_DumpConstPoolBit = 0,
  Feature_EnableStackSizeBit = 2,
  Feature_UseCCRTBit = 28,
  Feature_HasVDSPV1_128Bit = 24,
  Feature_iHasE1Bit = 38,
  Feature_iHasE2Bit = 39,
  Feature_iHas2E3Bit = 29,
  Feature_iHasMPBit = 45,
  Feature_iHas3E3r1Bit = 30,
  Feature_iHas3r1E3r2Bit = 32,
  Feature_iHas3r2E3r3Bit = 33,
  Feature_iHas3E7Bit = 31,
  Feature_iHasMP1E2Bit = 46,
  Feature_iHas7E10Bit = 34,
  Feature_iHas10E60Bit = 35,
  Feature_isCK801Bit = 49,
};

inline FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) {
  FeatureBitset Features;
  if (FB[CSKY::FeatureFPUV2_SF])
    Features.set(Feature_HasFPUv2_SFBit);
  if (FB[CSKY::FeatureFPUV2_DF])
    Features.set(Feature_HasFPUv2_DFBit);
  if (FB[CSKY::FeatureFdivdu])
    Features.set(Feature_HasFdivduBit);
  if (FB[CSKY::FeatureFPUV3_HI])
    Features.set(Feature_HasFPUv3_HIBit);
  if (FB[CSKY::FeatureFPUV3_HF])
    Features.set(Feature_HasFPUv3_HFBit);
  if (FB[CSKY::FeatureFPUV3_SF])
    Features.set(Feature_HasFPUv3_SFBit);
  if (FB[CSKY::FeatureFPUV3_DF])
    Features.set(Feature_HasFPUv3_DFBit);
  if (FB[CSKY::HasFLOATE1])
    Features.set(Feature_iHasFLOATE1Bit);
  if (FB[CSKY::HasFLOAT1E2])
    Features.set(Feature_iHasFLOAT1E2Bit);
  if (FB[CSKY::HasFLOAT1E3])
    Features.set(Feature_iHasFLOAT1E3Bit);
  if (FB[CSKY::HasFLOAT3E4])
    Features.set(Feature_iHasFLOAT3E4Bit);
  if (FB[CSKY::HasFLOAT7E60])
    Features.set(Feature_iHasFLOAT7E60Bit);
  if (FB[CSKY::FeatureHWDiv])
    Features.set(Feature_HasHWDivBit);
  if (FB[CSKY::FeatureSTM])
    Features.set(Feature_HasSTMBit);
  if (FB[CSKY::FeaturePushPop])
    Features.set(Feature_HasPushPopBit);
  if (FB[CSKY::FeatureDSP])
    Features.set(Feature_HasDSPBit);
  if (FB[CSKY::HasDSP1E2])
    Features.set(Feature_iHasDSP1E2Bit);
  if (FB[CSKY::HasDSPE60])
    Features.set(Feature_iHasDSPE60Bit);
  if (FB[CSKY::FeatureDSPV2])
    Features.set(Feature_HasDSPV2Bit);
  if (FB[CSKY::FeatureDSP_Silan])
    Features.set(Feature_HasDSP_SilanBit);
  if (FB[CSKY::FeatureBTST16])
    Features.set(Feature_HasBTST16Bit);
  if (FB[CSKY::FeatureExtendLrw])
    Features.set(Feature_HasExtendLrwBit);
  if (FB[CSKY::FeatureTrust])
    Features.set(Feature_HasTrustBit);
  if (FB[CSKY::FeatureJAVA])
    Features.set(Feature_HasJAVABit);
  if (FB[CSKY::FeatureCache])
    Features.set(Feature_HasCacheBit);
  if (FB[CSKY::FeatureNVIC])
    Features.set(Feature_HasNVICBit);
  if (FB[CSKY::FeatureDoloop])
    Features.set(Feature_HasDoloopBit);
  if (FB[CSKY::FeatureHighreg])
    Features.set(Feature_HasHighRegistersBit);
  if (FB[CSKY::FeatureSmart])
    Features.set(Feature_SmartModeBit);
  if (FB[CSKY::FeatureVDSPV2])
    Features.set(Feature_HasVDSPV2Bit);
  if (FB[CSKY::HasVDSP2E3])
    Features.set(Feature_iHasVDSP2E3Bit);
  if (FB[CSKY::HasVDSP2E60F])
    Features.set(Feature_iHasVDSP2E60FBit);
  if (FB[CSKY::FeatureHardTP])
    Features.set(Feature_ReadTPHardBit);
  if (FB[CSKY::FeatureIstack])
    Features.set(Feature_EnableInterruptAttributeBit);
  if (FB[CSKY::FeatureConstPool])
    Features.set(Feature_DumpConstPoolBit);
  if (FB[CSKY::FeatureStackSize])
    Features.set(Feature_EnableStackSizeBit);
  if (FB[CSKY::FeatureCCRT])
    Features.set(Feature_UseCCRTBit);
  if (FB[CSKY::FeatureVDSPV1_128])
    Features.set(Feature_HasVDSPV1_128Bit);
  if (FB[CSKY::HasE1])
    Features.set(Feature_iHasE1Bit);
  if (FB[CSKY::HasE2])
    Features.set(Feature_iHasE2Bit);
  if (FB[CSKY::Has2E3])
    Features.set(Feature_iHas2E3Bit);
  if (FB[CSKY::HasMP])
    Features.set(Feature_iHasMPBit);
  if (FB[CSKY::Has3E3r1])
    Features.set(Feature_iHas3E3r1Bit);
  if (FB[CSKY::Has3r1E3r2])
    Features.set(Feature_iHas3r1E3r2Bit);
  if (FB[CSKY::Has3r2E3r3])
    Features.set(Feature_iHas3r2E3r3Bit);
  if (FB[CSKY::Has3E7])
    Features.set(Feature_iHas3E7Bit);
  if (FB[CSKY::HasMP1E2])
    Features.set(Feature_iHasMP1E2Bit);
  if (FB[CSKY::Has7E10])
    Features.set(Feature_iHas7E10Bit);
  if (FB[CSKY::Has10E60])
    Features.set(Feature_iHas10E60Bit);
  if (FB[CSKY::ProcCK801])
    Features.set(Feature_isCK801Bit);
  return Features;
}

inline FeatureBitset computeRequiredFeatures(unsigned Opcode) {
  enum : uint8_t {
    CEFBS_None,
    CEFBS_HasBTST16,
    CEFBS_HasExtendLrw,
    CEFBS_HasFPUv2_DF,
    CEFBS_HasFPUv2_SF,
    CEFBS_HasFPUv3_DF,
    CEFBS_HasFPUv3_SF,
    CEFBS_HasJAVA,
    CEFBS_iHas2E3,
    CEFBS_iHas3E3r1,
    CEFBS_iHas3r2E3r3,
    CEFBS_iHasE1,
    CEFBS_iHasE2,
    CEFBS_iHasMP1E2,
    CEFBS_iHas2E3_iHas10E60,
  };

  static constexpr FeatureBitset FeatureBitsets[] = {
    {}, // CEFBS_None
    {Feature_HasBTST16Bit, },
    {Feature_HasExtendLrwBit, },
    {Feature_HasFPUv2_DFBit, },
    {Feature_HasFPUv2_SFBit, },
    {Feature_HasFPUv3_DFBit, },
    {Feature_HasFPUv3_SFBit, },
    {Feature_HasJAVABit, },
    {Feature_iHas2E3Bit, },
    {Feature_iHas3E3r1Bit, },
    {Feature_iHas3r2E3r3Bit, },
    {Feature_iHasE1Bit, },
    {Feature_iHasE2Bit, },
    {Feature_iHasMP1E2Bit, },
    {Feature_iHas2E3Bit, Feature_iHas10E60Bit, },
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
    CEFBS_None, // ADJCALLSTACKDOWN
    CEFBS_None, // ADJCALLSTACKUP
    CEFBS_iHasE2, // BGENI
    CEFBS_None, // CMPLEI16
    CEFBS_iHasE2, // CMPLEI32
    CEFBS_None, // CONSTPOOL_ENTRY
    CEFBS_HasFPUv2_DF, // FSELD
    CEFBS_HasFPUv2_SF, // FSELS
    CEFBS_None, // ISEL16
    CEFBS_iHasE2, // ISEL32
    CEFBS_None, // JBF16
    CEFBS_None, // JBF32
    CEFBS_None, // JBF_E
    CEFBS_None, // JBR16
    CEFBS_None, // JBR32
    CEFBS_None, // JBSR32
    CEFBS_None, // JBT16
    CEFBS_None, // JBT32
    CEFBS_None, // JBT_E
    CEFBS_iHasE2, // LDQ32
    CEFBS_None, // LOAD_PAIR
    CEFBS_None, // NEG16
    CEFBS_iHasE2, // NEG32
    CEFBS_None, // PseudoJMPI32
    CEFBS_None, // PseudoJSRI32
    CEFBS_None, // PseudoLRW16
    CEFBS_None, // PseudoLRW32
    CEFBS_None, // PseudoTLSLA32
    CEFBS_None, // RESTORE_CARRY
    CEFBS_iHasE2, // ROTRI32
    CEFBS_None, // RSUBI16
    CEFBS_iHasE2, // RSUBI32
    CEFBS_None, // SPILL_CARRY
    CEFBS_None, // STORE_PAIR
    CEFBS_iHasE2, // STQ32
    CEFBS_iHas2E3, // ABS32
    CEFBS_None, // ADDC16
    CEFBS_iHasE2, // ADDC32
    CEFBS_None, // ADDI16
    CEFBS_None, // ADDI16SPSP
    CEFBS_None, // ADDI16XZ
    CEFBS_None, // ADDI16ZSP
    CEFBS_iHasE2, // ADDI32
    CEFBS_None, // ADDU16
    CEFBS_None, // ADDU16XZ
    CEFBS_iHasE2, // ADDU32
    CEFBS_None, // AND16
    CEFBS_iHasE2, // AND32
    CEFBS_iHasE2, // ANDI32
    CEFBS_None, // ANDN16
    CEFBS_iHasE2, // ANDN32
    CEFBS_iHasE2, // ANDNI32
    CEFBS_None, // ASR16
    CEFBS_iHasE2, // ASR32
    CEFBS_iHasE2, // ASRC32
    CEFBS_None, // ASRI16
    CEFBS_iHasE2, // ASRI32
    CEFBS_None, // BCLRI16
    CEFBS_iHasE2, // BCLRI32
    CEFBS_iHas2E3, // BEZ32
    CEFBS_None, // BF16
    CEFBS_iHasE2, // BF32
    CEFBS_iHas2E3, // BGENR32
    CEFBS_iHas2E3, // BHSZ32
    CEFBS_iHas2E3, // BHZ32
    CEFBS_None, // BKPT
    CEFBS_iHas2E3, // BLSZ32
    CEFBS_iHas2E3, // BLZ32
    CEFBS_iHasE2, // BMASKI32
    CEFBS_iHas2E3, // BNEZ32
    CEFBS_iHas2E3_iHas10E60, // BNEZAD32
    CEFBS_HasJAVA, // BPOPH
    CEFBS_HasJAVA, // BPOPW
    CEFBS_HasJAVA, // BPUSHH
    CEFBS_HasJAVA, // BPUSHW
    CEFBS_None, // BR16
    CEFBS_None, // BR32
    CEFBS_iHasMP1E2, // BRAR
    CEFBS_iHasMP1E2, // BRARS
    CEFBS_iHasMP1E2, // BRARW
    CEFBS_iHasMP1E2, // BRARWS
    CEFBS_iHas2E3, // BREV32
    CEFBS_iHasMP1E2, // BRWARW
    CEFBS_iHasMP1E2, // BRWARWS
    CEFBS_iHasMP1E2, // BRWAW
    CEFBS_iHasMP1E2, // BRWAWS
    CEFBS_None, // BSETI16
    CEFBS_iHasE2, // BSETI32
    CEFBS_None, // BSR32
    CEFBS_None, // BSR32_BR
    CEFBS_None, // BT16
    CEFBS_iHasE2, // BT32
    CEFBS_HasBTST16, // BTSTI16
    CEFBS_iHasE2, // BTSTI32
    CEFBS_iHasMP1E2, // BWAW
    CEFBS_iHasMP1E2, // BWAWS
    CEFBS_None, // CLRC16
    CEFBS_iHas2E3, // CLRC32
    CEFBS_iHas2E3, // CLRF32
    CEFBS_iHas2E3, // CLRT32
    CEFBS_None, // CMPHS16
    CEFBS_iHas2E3, // CMPHS32
    CEFBS_None, // CMPHSI16
    CEFBS_iHasE2, // CMPHSI32
    CEFBS_None, // CMPLT16
    CEFBS_iHas2E3, // CMPLT32
    CEFBS_None, // CMPLTI16
    CEFBS_iHasE2, // CMPLTI32
    CEFBS_None, // CMPNE16
    CEFBS_iHas2E3, // CMPNE32
    CEFBS_None, // CMPNEI16
    CEFBS_iHasE2, // CMPNEI32
    CEFBS_None, // CPOP32
    CEFBS_None, // CPRC32
    CEFBS_None, // CPRCR32
    CEFBS_None, // CPRGR32
    CEFBS_None, // CPWCR32
    CEFBS_None, // CPWGR32
    CEFBS_iHas3r2E3r3, // DCACHE_CALL32
    CEFBS_iHas3r2E3r3, // DCACHE_CIALL32
    CEFBS_iHas3r2E3r3, // DCACHE_CISW32
    CEFBS_iHas3r2E3r3, // DCACHE_CIVA32
    CEFBS_iHas3r2E3r3, // DCACHE_CSW32
    CEFBS_iHas3r2E3r3, // DCACHE_CVA32
    CEFBS_iHas3r2E3r3, // DCACHE_CVAL32
    CEFBS_iHas3r2E3r3, // DCACHE_IALL32
    CEFBS_iHas3r2E3r3, // DCACHE_ISW32
    CEFBS_iHas3r2E3r3, // DCACHE_IVA32
    CEFBS_iHasE2, // DECF32
    CEFBS_iHas2E3, // DECGT32
    CEFBS_iHas2E3, // DECLT32
    CEFBS_iHas2E3, // DECNE32
    CEFBS_iHasE2, // DECT32
    CEFBS_iHas2E3, // DIVS32
    CEFBS_iHas2E3, // DIVU32
    CEFBS_None, // DOZE32
    CEFBS_HasFPUv2_SF, // FABSM
    CEFBS_HasFPUv2_DF, // FABS_D
    CEFBS_HasFPUv2_SF, // FABS_S
    CEFBS_HasFPUv2_SF, // FADDM
    CEFBS_HasFPUv2_DF, // FADD_D
    CEFBS_HasFPUv2_SF, // FADD_S
    CEFBS_HasFPUv2_DF, // FCMPHS_D
    CEFBS_HasFPUv2_SF, // FCMPHS_S
    CEFBS_HasFPUv2_DF, // FCMPLT_D
    CEFBS_HasFPUv2_SF, // FCMPLT_S
    CEFBS_HasFPUv2_DF, // FCMPNE_D
    CEFBS_HasFPUv2_SF, // FCMPNE_S
    CEFBS_HasFPUv2_DF, // FCMPUO_D
    CEFBS_HasFPUv2_SF, // FCMPUO_S
    CEFBS_HasFPUv2_DF, // FCMPZHS_D
    CEFBS_HasFPUv2_SF, // FCMPZHS_S
    CEFBS_HasFPUv2_DF, // FCMPZLS_D
    CEFBS_HasFPUv2_SF, // FCMPZLS_S
    CEFBS_HasFPUv2_DF, // FCMPZNE_D
    CEFBS_HasFPUv2_SF, // FCMPZNE_S
    CEFBS_HasFPUv2_DF, // FCMPZUO_D
    CEFBS_HasFPUv2_SF, // FCMPZUO_S
    CEFBS_HasFPUv2_DF, // FDIV_D
    CEFBS_HasFPUv2_SF, // FDIV_S
    CEFBS_HasFPUv2_DF, // FDTOS
    CEFBS_iHasE2, // FF0
    CEFBS_iHasE2, // FF1
    CEFBS_HasFPUv2_DF, // FLDM
    CEFBS_HasFPUv2_DF, // FLDMM
    CEFBS_HasFPUv2_DF, // FLDM_D
    CEFBS_None, // FLDM_S
    CEFBS_HasFPUv2_DF, // FLDRM
    CEFBS_HasFPUv2_DF, // FLDR_D
    CEFBS_None, // FLDR_S
    CEFBS_HasFPUv2_DF, // FLD_D
    CEFBS_None, // FLD_S
    CEFBS_HasFPUv2_SF, // FMACM
    CEFBS_HasFPUv2_DF, // FMAC_D
    CEFBS_HasFPUv2_SF, // FMAC_S
    CEFBS_HasFPUv2_DF, // FMFVRH_D
    CEFBS_HasFPUv2_SF, // FMFVRL
    CEFBS_HasFPUv2_DF, // FMFVRL_D
    CEFBS_HasFPUv2_SF, // FMOVM
    CEFBS_HasFPUv2_DF, // FMOV_D
    CEFBS_HasFPUv2_SF, // FMOV_S
    CEFBS_HasFPUv2_SF, // FMSCM
    CEFBS_HasFPUv2_DF, // FMSC_D
    CEFBS_HasFPUv2_SF, // FMSC_S
    CEFBS_HasFPUv2_DF, // FMTVRH_D
    CEFBS_HasFPUv2_SF, // FMTVRL
    CEFBS_HasFPUv2_DF, // FMTVRL_D
    CEFBS_HasFPUv2_SF, // FMULM
    CEFBS_HasFPUv2_DF, // FMUL_D
    CEFBS_HasFPUv2_SF, // FMUL_S
    CEFBS_HasFPUv2_SF, // FNEGM
    CEFBS_HasFPUv2_DF, // FNEG_D
    CEFBS_HasFPUv2_SF, // FNEG_S
    CEFBS_HasFPUv2_SF, // FNMACM
    CEFBS_HasFPUv2_DF, // FNMAC_D
    CEFBS_HasFPUv2_SF, // FNMAC_S
    CEFBS_HasFPUv2_SF, // FNMSCM
    CEFBS_HasFPUv2_DF, // FNMSC_D
    CEFBS_HasFPUv2_SF, // FNMSC_S
    CEFBS_HasFPUv2_SF, // FNMULM
    CEFBS_HasFPUv2_DF, // FNMUL_D
    CEFBS_HasFPUv2_SF, // FNMUL_S
    CEFBS_HasFPUv2_DF, // FRECIP_D
    CEFBS_HasFPUv2_SF, // FRECIP_S
    CEFBS_HasFPUv2_SF, // FSITOD
    CEFBS_HasFPUv2_SF, // FSITOS
    CEFBS_HasFPUv2_DF, // FSQRT_D
    CEFBS_HasFPUv2_SF, // FSQRT_S
    CEFBS_HasFPUv2_DF, // FSTM
    CEFBS_HasFPUv2_DF, // FSTMM
    CEFBS_HasFPUv2_DF, // FSTM_D
    CEFBS_None, // FSTM_S
    CEFBS_HasFPUv2_DF, // FSTOD
    CEFBS_HasFPUv2_DF, // FSTRM
    CEFBS_HasFPUv2_DF, // FSTR_D
    CEFBS_None, // FSTR_S
    CEFBS_HasFPUv2_DF, // FST_D
    CEFBS_None, // FST_S
    CEFBS_HasFPUv2_SF, // FSUBM
    CEFBS_HasFPUv2_DF, // FSUB_D
    CEFBS_HasFPUv2_SF, // FSUB_S
    CEFBS_HasFPUv2_SF, // FUITOD
    CEFBS_HasFPUv2_SF, // FUITOS
    CEFBS_iHas2E3, // GRS32
    CEFBS_iHas3r2E3r3, // ICACHE_IALL32
    CEFBS_iHas3r2E3r3, // ICACHE_IALLS32
    CEFBS_iHas3r2E3r3, // ICACHE_IVA32
    CEFBS_HasExtendLrw, // IDLY32
    CEFBS_iHasE2, // INCF32
    CEFBS_iHasE2, // INCT32
    CEFBS_iHas2E3, // INS32
    CEFBS_iHasE1, // IPOP16
    CEFBS_iHasE1, // IPUSH16
    CEFBS_iHas2E3, // IXD32
    CEFBS_iHasE2, // IXH32
    CEFBS_iHasE2, // IXW32
    CEFBS_None, // JMP16
    CEFBS_iHas2E3, // JMP32
    CEFBS_iHas2E3, // JMPI32
    CEFBS_HasJAVA, // JMPIX16
    CEFBS_None, // JSR16
    CEFBS_iHas2E3, // JSR32
    CEFBS_iHas2E3, // JSRI32
    CEFBS_iHas3r2E3r3, // L2CACHE_CALL
    CEFBS_iHas3r2E3r3, // L2CACHE_CIALL
    CEFBS_iHas3r2E3r3, // L2CACHE_IALL
    CEFBS_None, // LD16B
    CEFBS_None, // LD16H
    CEFBS_None, // LD16W
    CEFBS_None, // LD16WSP
    CEFBS_None, // LD32B
    CEFBS_iHasE2, // LD32BS
    CEFBS_None, // LD32D
    CEFBS_None, // LD32H
    CEFBS_iHasE2, // LD32HS
    CEFBS_None, // LD32W
    CEFBS_iHasMP1E2, // LDEX32W
    CEFBS_iHasE2, // LDM32
    CEFBS_iHas2E3, // LDR32B
    CEFBS_iHas2E3, // LDR32BS
    CEFBS_iHas2E3, // LDR32H
    CEFBS_iHas2E3, // LDR32HS
    CEFBS_iHas2E3, // LDR32W
    CEFBS_iHas2E3, // LRS32B
    CEFBS_iHas2E3, // LRS32H
    CEFBS_iHas2E3, // LRS32W
    CEFBS_None, // LRW16
    CEFBS_None, // LRW16_Gen
    CEFBS_None, // LRW32
    CEFBS_None, // LRW32_Gen
    CEFBS_None, // LSL16
    CEFBS_iHasE2, // LSL32
    CEFBS_iHasE2, // LSLC32
    CEFBS_None, // LSLI16
    CEFBS_iHasE2, // LSLI32
    CEFBS_None, // LSR16
    CEFBS_iHasE2, // LSR32
    CEFBS_iHasE2, // LSRC32
    CEFBS_None, // LSRI16
    CEFBS_iHasE2, // LSRI32
    CEFBS_None, // MFFCR
    CEFBS_None, // MOV16
    CEFBS_iHasE2, // MOV32
    CEFBS_iHasE2, // MOVF32
    CEFBS_None, // MOVI16
    CEFBS_iHasE2, // MOVI32
    CEFBS_iHasE2, // MOVIH32
    CEFBS_iHasE2, // MOVT32
    CEFBS_None, // MTFCR
    CEFBS_iHas3E3r1, // MULATS32
    CEFBS_iHas3E3r1, // MULATU32
    CEFBS_None, // MULSH16
    CEFBS_None, // MULSH32
    CEFBS_None, // MULT16
    CEFBS_iHasE2, // MULT32
    CEFBS_iHas3E3r1, // MULTS32
    CEFBS_iHas3E3r1, // MULTU32
    CEFBS_iHasE2, // MVC32
    CEFBS_None, // MVCV16
    CEFBS_iHas2E3, // MVCV32
    CEFBS_None, // NIE
    CEFBS_None, // NIR
    CEFBS_None, // NOR16
    CEFBS_iHasE2, // NOR32
    CEFBS_None, // NOT16
    CEFBS_iHasE2, // NOT32
    CEFBS_None, // OR16
    CEFBS_iHasE2, // OR32
    CEFBS_iHasE2, // ORI32
    CEFBS_None, // PLDR32
    CEFBS_None, // PLDW32
    CEFBS_iHasE1, // POP16
    CEFBS_iHas2E3, // POP32
    CEFBS_iHasE1, // PUSH16
    CEFBS_iHas2E3, // PUSH32
    CEFBS_None, // REVB16
    CEFBS_iHas2E3, // REVB32
    CEFBS_None, // REVH16
    CEFBS_iHas2E3, // REVH32
    CEFBS_iHas2E3, // RFI32
    CEFBS_None, // ROTL16
    CEFBS_iHasE2, // ROTL32
    CEFBS_iHasE2, // ROTLI32
    CEFBS_None, // RTS16
    CEFBS_iHas2E3, // SCE32
    CEFBS_None, // SE32
    CEFBS_None, // SETC16
    CEFBS_iHas2E3, // SETC32
    CEFBS_iHas2E3, // SEXT32
    CEFBS_None, // SEXTB16
    CEFBS_iHas2E3, // SEXTB32
    CEFBS_None, // SEXTH16
    CEFBS_iHas2E3, // SEXTH32
    CEFBS_iHas2E3, // SRS32B
    CEFBS_iHas2E3, // SRS32H
    CEFBS_iHas2E3, // SRS32W
    CEFBS_None, // ST16B
    CEFBS_None, // ST16H
    CEFBS_None, // ST16W
    CEFBS_None, // ST16WSP
    CEFBS_None, // ST32B
    CEFBS_None, // ST32D
    CEFBS_None, // ST32H
    CEFBS_None, // ST32W
    CEFBS_iHasMP1E2, // STEX32W
    CEFBS_iHasE2, // STM32
    CEFBS_None, // STOP32
    CEFBS_iHas2E3, // STR32B
    CEFBS_iHas2E3, // STR32H
    CEFBS_iHas2E3, // STR32W
    CEFBS_None, // SUBC16
    CEFBS_iHasE2, // SUBC32
    CEFBS_None, // SUBI16
    CEFBS_None, // SUBI16SPSP
    CEFBS_None, // SUBI16XZ
    CEFBS_iHasE2, // SUBI32
    CEFBS_None, // SUBU16
    CEFBS_None, // SUBU16XZ
    CEFBS_iHasE2, // SUBU32
    CEFBS_None, // SYNC0_32
    CEFBS_None, // SYNC32
    CEFBS_None, // SYNC_32_I
    CEFBS_None, // SYNC_32_IS
    CEFBS_None, // SYNC_32_S
    CEFBS_iHas3r2E3r3, // TLBI_ALL32
    CEFBS_iHas3r2E3r3, // TLBI_ALLS32
    CEFBS_iHas3r2E3r3, // TLBI_ASID32
    CEFBS_iHas3r2E3r3, // TLBI_ASIDS32
    CEFBS_iHas3r2E3r3, // TLBI_VA32
    CEFBS_iHas3r2E3r3, // TLBI_VAA32
    CEFBS_iHas3r2E3r3, // TLBI_VAAS32
    CEFBS_iHas3r2E3r3, // TLBI_VAS32
    CEFBS_None, // TRAP32
    CEFBS_None, // TST16
    CEFBS_iHas2E3, // TST32
    CEFBS_None, // TSTNBZ16
    CEFBS_iHas2E3, // TSTNBZ32
    CEFBS_None, // WAIT32
    CEFBS_None, // WE32
    CEFBS_None, // WSC32
    CEFBS_None, // XOR16
    CEFBS_iHasE2, // XOR32
    CEFBS_iHasE2, // XORI32
    CEFBS_iHasE2, // XSR32
    CEFBS_iHasE2, // XTRB0
    CEFBS_iHasE2, // XTRB1
    CEFBS_iHasE2, // XTRB2
    CEFBS_iHasE2, // XTRB3
    CEFBS_iHas2E3, // ZEXT32
    CEFBS_None, // ZEXTB16
    CEFBS_iHas2E3, // ZEXTB32
    CEFBS_None, // ZEXTH16
    CEFBS_iHas2E3, // ZEXTH32
    CEFBS_HasFPUv3_DF, // f2FABS_D
    CEFBS_HasFPUv3_SF, // f2FABS_S
    CEFBS_HasFPUv3_DF, // f2FADD_D
    CEFBS_HasFPUv3_SF, // f2FADD_S
    CEFBS_HasFPUv3_DF, // f2FCMPHSZ_D
    CEFBS_HasFPUv3_SF, // f2FCMPHSZ_S
    CEFBS_HasFPUv3_DF, // f2FCMPHS_D
    CEFBS_HasFPUv3_SF, // f2FCMPHS_S
    CEFBS_HasFPUv3_DF, // f2FCMPHZ_D
    CEFBS_HasFPUv3_SF, // f2FCMPHZ_S
    CEFBS_HasFPUv3_DF, // f2FCMPLSZ_D
    CEFBS_HasFPUv3_SF, // f2FCMPLSZ_S
    CEFBS_HasFPUv3_DF, // f2FCMPLTZ_D
    CEFBS_HasFPUv3_SF, // f2FCMPLTZ_S
    CEFBS_HasFPUv3_DF, // f2FCMPLT_D
    CEFBS_HasFPUv3_SF, // f2FCMPLT_S
    CEFBS_HasFPUv3_DF, // f2FCMPNEZ_D
    CEFBS_HasFPUv3_SF, // f2FCMPNEZ_S
    CEFBS_HasFPUv3_DF, // f2FCMPNE_D
    CEFBS_HasFPUv3_SF, // f2FCMPNE_S
    CEFBS_HasFPUv3_DF, // f2FCMPUOZ_D
    CEFBS_HasFPUv3_SF, // f2FCMPUOZ_S
    CEFBS_HasFPUv3_DF, // f2FCMPUO_D
    CEFBS_HasFPUv3_SF, // f2FCMPUO_S
    CEFBS_HasFPUv3_DF, // f2FDIV_D
    CEFBS_HasFPUv3_SF, // f2FDIV_S
    CEFBS_HasFPUv3_DF, // f2FDTOS
    CEFBS_HasFPUv3_SF, // f2FF32TOFI32_RN
    CEFBS_HasFPUv3_SF, // f2FF32TOFI32_RNI
    CEFBS_HasFPUv3_SF, // f2FF32TOFI32_RPI
    CEFBS_HasFPUv3_SF, // f2FF32TOFI32_RZ
    CEFBS_HasFPUv3_SF, // f2FF32TOSI32_RN
    CEFBS_HasFPUv3_SF, // f2FF32TOSI32_RNI
    CEFBS_HasFPUv3_SF, // f2FF32TOSI32_RPI
    CEFBS_HasFPUv3_SF, // f2FF32TOSI32_RZ
    CEFBS_HasFPUv3_SF, // f2FF32TOUI32_RN
    CEFBS_HasFPUv3_SF, // f2FF32TOUI32_RNI
    CEFBS_HasFPUv3_SF, // f2FF32TOUI32_RPI
    CEFBS_HasFPUv3_SF, // f2FF32TOUI32_RZ
    CEFBS_HasFPUv3_DF, // f2FF64TOFI32_RN
    CEFBS_HasFPUv3_DF, // f2FF64TOFI32_RNI
    CEFBS_HasFPUv3_DF, // f2FF64TOFI32_RPI
    CEFBS_HasFPUv3_DF, // f2FF64TOFI32_RZ
    CEFBS_HasFPUv3_DF, // f2FF64TOSI32_RN
    CEFBS_HasFPUv3_DF, // f2FF64TOSI32_RNI
    CEFBS_HasFPUv3_DF, // f2FF64TOSI32_RPI
    CEFBS_HasFPUv3_DF, // f2FF64TOSI32_RZ
    CEFBS_HasFPUv3_DF, // f2FF64TOUI32_RN
    CEFBS_HasFPUv3_DF, // f2FF64TOUI32_RNI
    CEFBS_HasFPUv3_DF, // f2FF64TOUI32_RPI
    CEFBS_HasFPUv3_DF, // f2FF64TOUI32_RZ
    CEFBS_HasFPUv3_DF, // f2FFMULA_D
    CEFBS_HasFPUv3_SF, // f2FFMULA_S
    CEFBS_HasFPUv3_DF, // f2FFMULS_D
    CEFBS_HasFPUv3_SF, // f2FFMULS_S
    CEFBS_HasFPUv3_DF, // f2FFNMULA_D
    CEFBS_HasFPUv3_SF, // f2FFNMULA_S
    CEFBS_HasFPUv3_DF, // f2FFNMULS_D
    CEFBS_HasFPUv3_SF, // f2FFNMULS_S
    CEFBS_HasFPUv3_DF, // f2FFTOS32_D
    CEFBS_HasFPUv3_SF, // f2FFTOS32_S
    CEFBS_HasFPUv3_DF, // f2FFTOU32_D
    CEFBS_HasFPUv3_SF, // f2FFTOU32_S
    CEFBS_HasFPUv3_DF, // f2FFTOXS32_D
    CEFBS_HasFPUv3_SF, // f2FFTOXS32_S
    CEFBS_HasFPUv3_DF, // f2FFTOXU32_D
    CEFBS_HasFPUv3_SF, // f2FFTOXU32_S
    CEFBS_HasFPUv3_SF, // f2FINS
    CEFBS_HasFPUv3_DF, // f2FLDMU_D
    CEFBS_HasFPUv3_SF, // f2FLDMU_S
    CEFBS_HasFPUv3_DF, // f2FLDM_D
    CEFBS_HasFPUv3_SF, // f2FLDM_S
    CEFBS_HasFPUv3_DF, // f2FLDR_D
    CEFBS_HasFPUv3_SF, // f2FLDR_S
    CEFBS_HasFPUv3_DF, // f2FLD_D
    CEFBS_HasFPUv3_SF, // f2FLD_S
    CEFBS_HasFPUv3_SF, // f2FLRW_D
    CEFBS_HasFPUv3_SF, // f2FLRW_S
    CEFBS_HasFPUv3_DF, // f2FMAXNM_D
    CEFBS_HasFPUv3_SF, // f2FMAXNM_S
    CEFBS_HasFPUv3_DF, // f2FMFVRH_D
    CEFBS_HasFPUv3_SF, // f2FMFVRL
    CEFBS_HasFPUv3_SF, // f2FMFVRL_2
    CEFBS_HasFPUv3_DF, // f2FMFVRL_D
    CEFBS_HasFPUv3_DF, // f2FMFVR_D
    CEFBS_HasFPUv3_DF, // f2FMINNM_D
    CEFBS_HasFPUv3_SF, // f2FMINNM_S
    CEFBS_HasFPUv3_SF, // f2FMOVX
    CEFBS_HasFPUv3_DF, // f2FMOV_D
    CEFBS_HasFPUv3_SF, // f2FMOV_S
    CEFBS_HasFPUv3_DF, // f2FMTVRH_D
    CEFBS_HasFPUv3_SF, // f2FMTVRL
    CEFBS_HasFPUv3_SF, // f2FMTVRL_2
    CEFBS_HasFPUv3_DF, // f2FMTVRL_D
    CEFBS_HasFPUv3_DF, // f2FMTVR_D
    CEFBS_HasFPUv3_DF, // f2FMULA_D
    CEFBS_HasFPUv3_SF, // f2FMULA_S
    CEFBS_HasFPUv3_DF, // f2FMULS_D
    CEFBS_HasFPUv3_SF, // f2FMULS_S
    CEFBS_HasFPUv3_DF, // f2FMUL_D
    CEFBS_HasFPUv3_SF, // f2FMUL_S
    CEFBS_HasFPUv3_DF, // f2FNEG_D
    CEFBS_HasFPUv3_SF, // f2FNEG_S
    CEFBS_HasFPUv3_DF, // f2FNMULA_D
    CEFBS_HasFPUv3_SF, // f2FNMULA_S
    CEFBS_HasFPUv3_DF, // f2FNMULS_D
    CEFBS_HasFPUv3_SF, // f2FNMULS_S
    CEFBS_HasFPUv3_DF, // f2FNMUL_D
    CEFBS_HasFPUv3_SF, // f2FNMUL_S
    CEFBS_HasFPUv3_DF, // f2FS32TOF_D
    CEFBS_HasFPUv3_SF, // f2FS32TOF_S
    CEFBS_HasFPUv3_DF, // f2FSEL_D
    CEFBS_HasFPUv3_SF, // f2FSEL_S
    CEFBS_HasFPUv3_DF, // f2FSQRT_D
    CEFBS_HasFPUv3_SF, // f2FSQRT_S
    CEFBS_HasFPUv3_DF, // f2FSTMU_D
    CEFBS_HasFPUv3_SF, // f2FSTMU_S
    CEFBS_HasFPUv3_DF, // f2FSTM_D
    CEFBS_HasFPUv3_SF, // f2FSTM_S
    CEFBS_HasFPUv3_DF, // f2FSTOD
    CEFBS_HasFPUv3_DF, // f2FSTR_D
    CEFBS_HasFPUv3_SF, // f2FSTR_S
    CEFBS_HasFPUv3_DF, // f2FST_D
    CEFBS_HasFPUv3_SF, // f2FST_S
    CEFBS_HasFPUv3_DF, // f2FSUB_D
    CEFBS_HasFPUv3_SF, // f2FSUB_S
    CEFBS_HasFPUv3_DF, // f2FU32TOF_D
    CEFBS_HasFPUv3_SF, // f2FU32TOF_S
    CEFBS_HasFPUv3_DF, // f2FXTOFS32_D
    CEFBS_HasFPUv3_SF, // f2FXTOFS32_S
    CEFBS_HasFPUv3_DF, // f2FXTOFU32_D
    CEFBS_HasFPUv3_SF, // f2FXTOFU32_S
    CEFBS_HasFPUv3_DF, // f2RECIP_D
    CEFBS_HasFPUv3_SF, // f2RECIP_S
    CEFBS_HasFPUv2_DF, // rnFDTOSI
    CEFBS_HasFPUv2_DF, // rnFDTOUI
    CEFBS_HasFPUv2_SF, // rnFSTOSI
    CEFBS_HasFPUv2_SF, // rnFSTOUI
    CEFBS_HasFPUv2_DF, // rniFDTOSI
    CEFBS_HasFPUv2_DF, // rniFDTOUI
    CEFBS_HasFPUv2_SF, // rniFSTOSI
    CEFBS_HasFPUv2_SF, // rniFSTOUI
    CEFBS_HasFPUv2_DF, // rpiFDTOSI
    CEFBS_HasFPUv2_DF, // rpiFDTOUI
    CEFBS_HasFPUv2_SF, // rpiFSTOSI
    CEFBS_HasFPUv2_SF, // rpiFSTOUI
    CEFBS_HasFPUv2_DF, // rzFDTOSI
    CEFBS_HasFPUv2_DF, // rzFDTOUI
    CEFBS_HasFPUv2_SF, // rzFSTOSI
    CEFBS_HasFPUv2_SF, // rzFSTOUI
  };

  assert(Opcode < 874);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::CSKY_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::CSKY_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::CSKY_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::CSKY_MC {

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_DumpConstPool",
  "Feature_EnableInterruptAttribute",
  "Feature_EnableStackSize",
  "Feature_HasBTST16",
  "Feature_HasCache",
  "Feature_HasDSP",
  "Feature_HasDSPV2",
  "Feature_HasDSP_Silan",
  "Feature_HasDoloop",
  "Feature_HasExtendLrw",
  "Feature_HasFPUv2_DF",
  "Feature_HasFPUv2_SF",
  "Feature_HasFPUv3_DF",
  "Feature_HasFPUv3_HF",
  "Feature_HasFPUv3_HI",
  "Feature_HasFPUv3_SF",
  "Feature_HasFdivdu",
  "Feature_HasHWDiv",
  "Feature_HasHighRegisters",
  "Feature_HasJAVA",
  "Feature_HasNVIC",
  "Feature_HasPushPop",
  "Feature_HasSTM",
  "Feature_HasTrust",
  "Feature_HasVDSPV1_128",
  "Feature_HasVDSPV2",
  "Feature_ReadTPHard",
  "Feature_SmartMode",
  "Feature_UseCCRT",
  "Feature_iHas2E3",
  "Feature_iHas3E3r1",
  "Feature_iHas3E7",
  "Feature_iHas3r1E3r2",
  "Feature_iHas3r2E3r3",
  "Feature_iHas7E10",
  "Feature_iHas10E60",
  "Feature_iHasDSP1E2",
  "Feature_iHasDSPE60",
  "Feature_iHasE1",
  "Feature_iHasE2",
  "Feature_iHasFLOAT1E2",
  "Feature_iHasFLOAT1E3",
  "Feature_iHasFLOAT3E4",
  "Feature_iHasFLOAT7E60",
  "Feature_iHasFLOATE1",
  "Feature_iHasMP",
  "Feature_iHasMP1E2",
  "Feature_iHasVDSP2E3",
  "Feature_iHasVDSP2E60F",
  "Feature_isCK801",
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
    Msg << "Attempting to emit " << &CSKYInstrNameData[CSKYInstrNameIndices[Opcode]]
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::CSKY_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

