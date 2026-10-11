/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::SystemZ {

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
    ADA_ENTRY                             = 331, // SystemZInstrInfo.td:299
    ADA_ENTRY_VALUE                       = 332, // SystemZInstrInfo.td:305
    ADB_MemFoldPseudo                     = 333, // SystemZInstrFormats.td:5535
    ADJCALLSTACKDOWN                      = 334, // SystemZInstrInfo.td:26
    ADJCALLSTACKUP                        = 335, // SystemZInstrInfo.td:28
    ADJDYNALLOC                           = 336, // SystemZInstrInfo.td:39
    AEB_MemFoldPseudo                     = 337, // SystemZInstrFormats.td:5535
    AEXT128                               = 338, // SystemZInstrInfo.td:845
    AFIMux                                = 339, // SystemZInstrInfo.td:1089
    AG_MemFoldPseudo                      = 340, // SystemZInstrFormats.td:5507
    AHIMux                                = 341, // SystemZInstrFormats.td:5184
    AHIMuxK                               = 342, // SystemZInstrFormats.td:5181
    ALG_MemFoldPseudo                     = 343, // SystemZInstrFormats.td:5507
    AL_MemFoldPseudo                      = 344, // SystemZInstrFormats.td:5525
    ATOMIC_CMP_SWAPW                      = 345, // SystemZInstrInfo.td:1860
    ATOMIC_LOADW_AFI                      = 346, // SystemZInstrInfo.td:1838
    ATOMIC_LOADW_AR                       = 347, // SystemZInstrInfo.td:1837
    ATOMIC_LOADW_MAX                      = 348, // SystemZInstrInfo.td:1856
    ATOMIC_LOADW_MIN                      = 349, // SystemZInstrInfo.td:1855
    ATOMIC_LOADW_NILH                     = 350, // SystemZInstrInfo.td:1843
    ATOMIC_LOADW_NILHi                    = 351, // SystemZInstrInfo.td:1852
    ATOMIC_LOADW_NR                       = 352, // SystemZInstrInfo.td:1842
    ATOMIC_LOADW_NRi                      = 353, // SystemZInstrInfo.td:1851
    ATOMIC_LOADW_OILH                     = 354, // SystemZInstrInfo.td:1846
    ATOMIC_LOADW_OR                       = 355, // SystemZInstrInfo.td:1845
    ATOMIC_LOADW_SR                       = 356, // SystemZInstrInfo.td:1840
    ATOMIC_LOADW_UMAX                     = 357, // SystemZInstrInfo.td:1858
    ATOMIC_LOADW_UMIN                     = 358, // SystemZInstrInfo.td:1857
    ATOMIC_LOADW_XILF                     = 359, // SystemZInstrInfo.td:1849
    ATOMIC_LOADW_XR                       = 360, // SystemZInstrInfo.td:1848
    ATOMIC_SWAPW                          = 361, // SystemZInstrInfo.td:1835
    A_MemFoldPseudo                       = 362, // SystemZInstrFormats.td:5525
    CFIMux                                = 363, // SystemZInstrInfo.td:1673
    CGIBCall                              = 364, // SystemZInstrInfo.td:354
    CGIBReturn                            = 365, // SystemZInstrInfo.td:386
    CGRBCall                              = 366, // SystemZInstrInfo.td:352
    CGRBReturn                            = 367, // SystemZInstrInfo.td:384
    CHIMux                                = 368, // SystemZInstrInfo.td:1666
    CIBCall                               = 369, // SystemZInstrInfo.td:353
    CIBReturn                             = 370, // SystemZInstrInfo.td:385
    CLCImm                                = 371, // SystemZInstrFormats.td:5590
    CLCReg                                = 372, // SystemZInstrFormats.td:5594
    CLFIMux                               = 373, // SystemZInstrInfo.td:1718
    CLGIBCall                             = 374, // SystemZInstrInfo.td:358
    CLGIBReturn                           = 375, // SystemZInstrInfo.td:390
    CLGRBCall                             = 376, // SystemZInstrInfo.td:356
    CLGRBReturn                           = 377, // SystemZInstrInfo.td:388
    CLIBCall                              = 378, // SystemZInstrInfo.td:357
    CLIBReturn                            = 379, // SystemZInstrInfo.td:389
    CLMux                                 = 380, // SystemZInstrInfo.td:1726
    CLRBCall                              = 381, // SystemZInstrInfo.td:355
    CLRBReturn                            = 382, // SystemZInstrInfo.td:387
    CLSTLoop                              = 383, // SystemZInstrFormats.td:5611
    CMP_STACKGUARD                        = 384, // SystemZInstrInfo.td:565
    CMP_STACKGUARD_DAG                    = 385, // SystemZInstrInfo.td:557
    CMux                                  = 386, // SystemZInstrInfo.td:1682
    CRBCall                               = 387, // SystemZInstrInfo.td:351
    CRBReturn                             = 388, // SystemZInstrInfo.td:383
    CallBASR                              = 389, // SystemZInstrInfo.td:318
    CallBASR_STACKEXT                     = 390, // SystemZInstrInfo.td:295
    CallBASR_XPLINK64                     = 391, // SystemZInstrInfo.td:290
    CallBCR                               = 392, // SystemZInstrInfo.td:345
    CallBR                                = 393, // SystemZInstrInfo.td:337
    CallBRASL                             = 394, // SystemZInstrInfo.td:316
    CallBRASL_XPLINK64                    = 395, // SystemZInstrInfo.td:288
    CallBRCL                              = 396, // SystemZInstrInfo.td:343
    CallJG                                = 397, // SystemZInstrInfo.td:335
    CondReturn                            = 398, // SystemZInstrInfo.td:378
    CondReturn_XPLINK                     = 399, // SystemZInstrInfo.td:368
    CondStore16                           = 400, // SystemZInstrFormats.td:5379
    CondStore16Inv                        = 401, // SystemZInstrFormats.td:5384
    CondStore16Mux                        = 402, // SystemZInstrFormats.td:5379
    CondStore16MuxInv                     = 403, // SystemZInstrFormats.td:5384
    CondStore32                           = 404, // SystemZInstrFormats.td:5379
    CondStore32Inv                        = 405, // SystemZInstrFormats.td:5384
    CondStore32Mux                        = 406, // SystemZInstrFormats.td:5379
    CondStore32MuxInv                     = 407, // SystemZInstrFormats.td:5384
    CondStore64                           = 408, // SystemZInstrFormats.td:5379
    CondStore64Inv                        = 409, // SystemZInstrFormats.td:5384
    CondStore8                            = 410, // SystemZInstrFormats.td:5379
    CondStore8Inv                         = 411, // SystemZInstrFormats.td:5384
    CondStore8Mux                         = 412, // SystemZInstrFormats.td:5379
    CondStore8MuxInv                      = 413, // SystemZInstrFormats.td:5384
    CondStoreF32                          = 414, // SystemZInstrFormats.td:5379
    CondStoreF32Inv                       = 415, // SystemZInstrFormats.td:5384
    CondStoreF64                          = 416, // SystemZInstrFormats.td:5379
    CondStoreF64Inv                       = 417, // SystemZInstrFormats.td:5384
    CondTrap                              = 418, // SystemZInstrInfo.td:230
    DDB_MemFoldPseudo                     = 419, // SystemZInstrFormats.td:5535
    DEB_MemFoldPseudo                     = 420, // SystemZInstrFormats.td:5535
    EH_SjLj_LongJmp                       = 421, // SystemZInstrInfo.td:1971
    EH_SjLj_SetJmp                        = 422, // SystemZInstrInfo.td:1968
    EH_SjLj_Setup                         = 423, // SystemZInstrInfo.td:1976
    EXRL_Pseudo                           = 424, // SystemZInstrInfo.td:2265
    FENCE                                 = 425, // SystemZInstrInfo.td:17
    GOT                                   = 426, // SystemZInstrInfo.td:936
    IIFMux                                = 427, // SystemZInstrInfo.td:1049
    IIHF64                                = 428, // SystemZInstrInfo.td:1056
    IIHH64                                = 429, // SystemZInstrInfo.td:1042
    IIHL64                                = 430, // SystemZInstrInfo.td:1041
    IIHMux                                = 431, // SystemZInstrInfo.td:1033
    IILF64                                = 432, // SystemZInstrInfo.td:1055
    IILH64                                = 433, // SystemZInstrInfo.td:1040
    IILL64                                = 434, // SystemZInstrInfo.td:1039
    IILMux                                = 435, // SystemZInstrInfo.td:1031
    L128                                  = 436, // SystemZInstrInfo.td:484
    LBMux                                 = 437, // SystemZInstrInfo.td:734
    LEFR                                  = 438, // SystemZInstrVector.td:2262
    LEFR_16                               = 439, // SystemZInstrVector.td:2267
    LFER                                  = 440, // SystemZInstrVector.td:2263
    LFER_16                               = 441, // SystemZInstrVector.td:2268
    LHIMux                                = 442, // SystemZInstrInfo.td:451
    LHMux                                 = 443, // SystemZInstrInfo.td:742
    LLCMux                                = 444, // SystemZInstrInfo.td:787
    LLCRMux                               = 445, // SystemZInstrInfo.td:766
    LLHMux                                = 446, // SystemZInstrInfo.td:795
    LLHRMux                               = 447, // SystemZInstrInfo.td:770
    LMux                                  = 448, // SystemZInstrInfo.td:474
    LOAD_GLOBAL_STACKGUARD_ADDR           = 449, // SystemZInstrInfo.td:538
    LOAD_TLS_BLOCK_ADDR                   = 450, // SystemZInstrInfo.td:535
    LOCG_MemFoldPseudo                    = 451, // SystemZInstrFormats.td:5554
    LOCHIMux                              = 452, // SystemZInstrInfo.td:637
    LOCMux                                = 453, // SystemZInstrFormats.td:5561
    LOCMux_MemFoldPseudo                  = 454, // SystemZInstrFormats.td:5562
    LOCRMux                               = 455, // SystemZInstrInfo.td:647
    LTDBRCompare_Pseudo                   = 456, // SystemZInstrFP.td:75
    LTEBRCompare_Pseudo                   = 457, // SystemZInstrFP.td:74
    LTXBRCompare_Pseudo                   = 458, // SystemZInstrFP.td:76
    LX                                    = 459, // SystemZInstrFP.td:174
    MADB_MemFoldPseudo                    = 460, // SystemZInstrFormats.td:5546
    MAEB_MemFoldPseudo                    = 461, // SystemZInstrFormats.td:5546
    MDB_MemFoldPseudo                     = 462, // SystemZInstrFormats.td:5535
    MEEB_MemFoldPseudo                    = 463, // SystemZInstrFormats.td:5535
    MOV_STACKGUARD                        = 464, // SystemZInstrInfo.td:551
    MOV_STACKGUARD_DAG                    = 465, // SystemZInstrInfo.td:544
    MSC_MemFoldPseudo                     = 466, // SystemZInstrFormats.td:5507
    MSDB_MemFoldPseudo                    = 467, // SystemZInstrFormats.td:5546
    MSEB_MemFoldPseudo                    = 468, // SystemZInstrFormats.td:5546
    MSGC_MemFoldPseudo                    = 469, // SystemZInstrFormats.td:5507
    MVCImm                                = 470, // SystemZInstrFormats.td:5574
    MVCReg                                = 471, // SystemZInstrFormats.td:5578
    MVSTLoop                              = 472, // SystemZInstrFormats.td:5611
    MemsetImmImm                          = 473, // SystemZInstrInfo.td:591
    MemsetImmReg                          = 474, // SystemZInstrInfo.td:592
    MemsetRegImm                          = 475, // SystemZInstrInfo.td:593
    MemsetRegReg                          = 476, // SystemZInstrInfo.td:594
    NCImm                                 = 477, // SystemZInstrFormats.td:5574
    NCReg                                 = 478, // SystemZInstrFormats.td:5578
    NG_MemFoldPseudo                      = 479, // SystemZInstrFormats.td:5507
    NIFMux                                = 480, // SystemZInstrInfo.td:1304
    NIHF64                                = 481, // SystemZInstrInfo.td:1310
    NIHH64                                = 482, // SystemZInstrInfo.td:1297
    NIHL64                                = 483, // SystemZInstrInfo.td:1296
    NIHMux                                = 484, // SystemZInstrInfo.td:1288
    NILF64                                = 485, // SystemZInstrInfo.td:1309
    NILH64                                = 486, // SystemZInstrInfo.td:1295
    NILL64                                = 487, // SystemZInstrInfo.td:1294
    NILMux                                = 488, // SystemZInstrInfo.td:1286
    N_MemFoldPseudo                       = 489, // SystemZInstrFormats.td:5525
    OCImm                                 = 490, // SystemZInstrFormats.td:5574
    OCReg                                 = 491, // SystemZInstrFormats.td:5578
    OG_MemFoldPseudo                      = 492, // SystemZInstrFormats.td:5507
    OIFMux                                = 493, // SystemZInstrInfo.td:1362
    OIHF64                                = 494, // SystemZInstrInfo.td:1368
    OIHH64                                = 495, // SystemZInstrInfo.td:1355
    OIHL64                                = 496, // SystemZInstrInfo.td:1354
    OIHMux                                = 497, // SystemZInstrInfo.td:1346
    OILF64                                = 498, // SystemZInstrInfo.td:1367
    OILH64                                = 499, // SystemZInstrInfo.td:1353
    OILL64                                = 500, // SystemZInstrInfo.td:1352
    OILMux                                = 501, // SystemZInstrInfo.td:1344
    O_MemFoldPseudo                       = 502, // SystemZInstrFormats.td:5525
    PAIR128                               = 503, // SystemZInstrInfo.td:445
    PROBED_ALLOCA                         = 504, // SystemZInstrInfo.td:44
    PROBED_STACKALLOC                     = 505, // SystemZInstrInfo.td:50
    RISBHH                                = 506, // SystemZInstrFormats.td:5476
    RISBHHOpt                             = 507, // SystemZInstrFormats.td:5479
    RISBHL                                = 508, // SystemZInstrFormats.td:5476
    RISBHLOpt                             = 509, // SystemZInstrFormats.td:5479
    RISBLH                                = 510, // SystemZInstrFormats.td:5476
    RISBLHOpt                             = 511, // SystemZInstrFormats.td:5479
    RISBLL                                = 512, // SystemZInstrFormats.td:5476
    RISBLLOpt                             = 513, // SystemZInstrFormats.td:5479
    RISBMux                               = 514, // SystemZInstrInfo.td:1627
    Return                                = 515, // SystemZInstrInfo.td:374
    Return_XPLINK                         = 516, // SystemZInstrInfo.td:364
    SCmp128Hi                             = 517, // SystemZInstrVector.td:2138
    SDB_MemFoldPseudo                     = 518, // SystemZInstrFormats.td:5535
    SEB_MemFoldPseudo                     = 519, // SystemZInstrFormats.td:5535
    SELRMux                               = 520, // SystemZInstrInfo.td:614
    SG_MemFoldPseudo                      = 521, // SystemZInstrFormats.td:5507
    SLG_MemFoldPseudo                     = 522, // SystemZInstrFormats.td:5507
    SL_MemFoldPseudo                      = 523, // SystemZInstrFormats.td:5525
    SRSTLoop                              = 524, // SystemZInstrFormats.td:5611
    ST128                                 = 525, // SystemZInstrInfo.td:528
    STCMux                                = 526, // SystemZInstrInfo.td:857
    STHMux                                = 527, // SystemZInstrInfo.td:865
    STMux                                 = 528, // SystemZInstrInfo.td:518
    STOCMux                               = 529, // SystemZInstrInfo.td:658
    STX                                   = 530, // SystemZInstrFP.td:193
    S_MemFoldPseudo                       = 531, // SystemZInstrFormats.td:5525
    Select128                             = 532, // SystemZInstrVector.td:2148
    Select32                              = 533, // SystemZInstrInfo.td:397
    Select64                              = 534, // SystemZInstrInfo.td:399
    SelectF128                            = 535, // SystemZInstrFP.td:24
    SelectF32                             = 536, // SystemZInstrFP.td:21
    SelectF64                             = 537, // SystemZInstrFP.td:22
    SelectVR128                           = 538, // SystemZInstrFP.td:26
    SelectVR32                            = 539, // SystemZInstrFP.td:18
    SelectVR64                            = 540, // SystemZInstrFP.td:19
    Serialize                             = 541, // SystemZInstrInfo.td:1820
    TBEGIN_nofloat                        = 542, // SystemZInstrInfo.td:2150
    TLS_GDCALL                            = 543, // SystemZInstrInfo.td:325
    TLS_LDCALL                            = 544, // SystemZInstrInfo.td:327
    TMHH64                                = 545, // SystemZInstrInfo.td:1781
    TMHL64                                = 546, // SystemZInstrInfo.td:1780
    TMHMux                                = 547, // SystemZInstrInfo.td:1771
    TMLH64                                = 548, // SystemZInstrInfo.td:1779
    TMLL64                                = 549, // SystemZInstrInfo.td:1778
    TMLMux                                = 550, // SystemZInstrInfo.td:1769
    Trap                                  = 551, // SystemZInstrInfo.td:226
    UCmp128Hi                             = 552, // SystemZInstrVector.td:2141
    VL16                                  = 553, // SystemZInstrVector.td:175
    VL32                                  = 554, // SystemZInstrVector.td:176
    VL64                                  = 555, // SystemZInstrVector.td:177
    VLR16                                 = 556, // SystemZInstrVector.td:17
    VLR32                                 = 557, // SystemZInstrVector.td:18
    VLR64                                 = 558, // SystemZInstrVector.td:19
    VLVGP32                               = 559, // SystemZInstrVector.td:42
    VST16                                 = 560, // SystemZInstrVector.td:276
    VST32                                 = 561, // SystemZInstrVector.td:277
    VST64                                 = 562, // SystemZInstrVector.td:278
    XCImm                                 = 563, // SystemZInstrFormats.td:5574
    XCReg                                 = 564, // SystemZInstrFormats.td:5578
    XG_MemFoldPseudo                      = 565, // SystemZInstrFormats.td:5507
    XIFMux                                = 566, // SystemZInstrInfo.td:1402
    XIHF64                                = 567, // SystemZInstrInfo.td:1408
    XILF64                                = 568, // SystemZInstrInfo.td:1407
    XPLINK_STACKALLOC                     = 569, // SystemZInstrInfo.td:54
    X_MemFoldPseudo                       = 570, // SystemZInstrFormats.td:5525
    ZEXT128                               = 571, // SystemZInstrInfo.td:833
    A                                     = 572, // SystemZInstrFormats.td:5515
    AD                                    = 573, // SystemZInstrHFP.td:138
    ADB                                   = 574, // SystemZInstrFormats.td:5531
    ADBR                                  = 575, // SystemZInstrFP.td:477
    ADR                                   = 576, // SystemZInstrHFP.td:134
    ADTR                                  = 577, // SystemZInstrDFP.td:147
    ADTRA                                 = 578, // SystemZInstrDFP.td:151
    AE                                    = 579, // SystemZInstrHFP.td:137
    AEB                                   = 580, // SystemZInstrFormats.td:5531
    AEBR                                  = 581, // SystemZInstrFP.td:476
    AER                                   = 582, // SystemZInstrHFP.td:133
    AFI                                   = 583, // SystemZInstrInfo.td:1091
    AG                                    = 584, // SystemZInstrFormats.td:5502
    AGF                                   = 585, // SystemZInstrInfo.td:1101
    AGFI                                  = 586, // SystemZInstrInfo.td:1094
    AGFR                                  = 587, // SystemZInstrInfo.td:1075
    AGH                                   = 588, // SystemZInstrInfo.td:1099
    AGHI                                  = 589, // SystemZInstrFormats.td:3672
    AGHIK                                 = 590, // SystemZInstrFormats.td:3669
    AGR                                   = 591, // SystemZInstrFormats.td:3524
    AGRK                                  = 592, // SystemZInstrFormats.td:3521
    AGSI                                  = 593, // SystemZInstrInfo.td:1106
    AH                                    = 594, // SystemZInstrFormats.td:3817
    AHHHR                                 = 595, // SystemZInstrInfo.td:1078
    AHHLR                                 = 596, // SystemZInstrInfo.td:1080
    AHI                                   = 597, // SystemZInstrFormats.td:3672
    AHIK                                  = 598, // SystemZInstrFormats.td:3669
    AHY                                   = 599, // SystemZInstrFormats.td:3820
    AIH                                   = 600, // SystemZInstrInfo.td:1092
    AL                                    = 601, // SystemZInstrFormats.td:5515
    ALC                                   = 602, // SystemZInstrInfo.td:1157
    ALCG                                  = 603, // SystemZInstrInfo.td:1158
    ALCGR                                 = 604, // SystemZInstrInfo.td:1154
    ALCR                                  = 605, // SystemZInstrInfo.td:1153
    ALFI                                  = 606, // SystemZInstrInfo.td:1132
    ALG                                   = 607, // SystemZInstrFormats.td:5502
    ALGF                                  = 608, // SystemZInstrInfo.td:1141
    ALGFI                                 = 609, // SystemZInstrInfo.td:1133
    ALGFR                                 = 610, // SystemZInstrInfo.td:1117
    ALGHSIK                               = 611, // SystemZInstrInfo.td:1128
    ALGR                                  = 612, // SystemZInstrFormats.td:3524
    ALGRK                                 = 613, // SystemZInstrFormats.td:3521
    ALGSI                                 = 614, // SystemZInstrInfo.td:1146
    ALHHHR                                = 615, // SystemZInstrInfo.td:1120
    ALHHLR                                = 616, // SystemZInstrInfo.td:1122
    ALHSIK                                = 617, // SystemZInstrInfo.td:1126
    ALR                                   = 618, // SystemZInstrFormats.td:3512
    ALRK                                  = 619, // SystemZInstrFormats.td:3509
    ALSI                                  = 620, // SystemZInstrInfo.td:1145
    ALSIH                                 = 621, // SystemZInstrInfo.td:1136
    ALSIHN                                = 622, // SystemZInstrInfo.td:1162
    ALY                                   = 623, // SystemZInstrFormats.td:5522
    AP                                    = 624, // SystemZInstrInfo.td:2062
    AR                                    = 625, // SystemZInstrFormats.td:3512
    ARK                                   = 626, // SystemZInstrFormats.td:3509
    ASI                                   = 627, // SystemZInstrInfo.td:1105
    AU                                    = 628, // SystemZInstrHFP.td:147
    AUR                                   = 629, // SystemZInstrHFP.td:144
    AW                                    = 630, // SystemZInstrHFP.td:148
    AWR                                   = 631, // SystemZInstrHFP.td:145
    AXBR                                  = 632, // SystemZInstrFP.td:478
    AXR                                   = 633, // SystemZInstrHFP.td:135
    AXTR                                  = 634, // SystemZInstrDFP.td:148
    AXTRA                                 = 635, // SystemZInstrDFP.td:152
    AY                                    = 636, // SystemZInstrFormats.td:5522
    B                                     = 637, // SystemZInstrInfo.td:111
    BAKR                                  = 638, // SystemZInstrSystem.td:299
    BAL                                   = 639, // SystemZInstrInfo.td:2118
    BALR                                  = 640, // SystemZInstrInfo.td:2119
    BAS                                   = 641, // SystemZInstrInfo.td:278
    BASR                                  = 642, // SystemZInstrInfo.td:279
    BASSM                                 = 643, // SystemZInstrInfo.td:2139
    BAsmE                                 = 644, // SystemZInstrInfo.td:97
    BAsmH                                 = 645, // SystemZInstrInfo.td:97
    BAsmHE                                = 646, // SystemZInstrInfo.td:97
    BAsmL                                 = 647, // SystemZInstrInfo.td:97
    BAsmLE                                = 648, // SystemZInstrInfo.td:97
    BAsmLH                                = 649, // SystemZInstrInfo.td:97
    BAsmM                                 = 650, // SystemZInstrInfo.td:97
    BAsmNE                                = 651, // SystemZInstrInfo.td:97
    BAsmNH                                = 652, // SystemZInstrInfo.td:97
    BAsmNHE                               = 653, // SystemZInstrInfo.td:97
    BAsmNL                                = 654, // SystemZInstrInfo.td:97
    BAsmNLE                               = 655, // SystemZInstrInfo.td:97
    BAsmNLH                               = 656, // SystemZInstrInfo.td:97
    BAsmNM                                = 657, // SystemZInstrInfo.td:97
    BAsmNO                                = 658, // SystemZInstrInfo.td:97
    BAsmNP                                = 659, // SystemZInstrInfo.td:97
    BAsmNZ                                = 660, // SystemZInstrInfo.td:97
    BAsmO                                 = 661, // SystemZInstrInfo.td:97
    BAsmP                                 = 662, // SystemZInstrInfo.td:97
    BAsmZ                                 = 663, // SystemZInstrInfo.td:97
    BC                                    = 664, // SystemZInstrInfo.td:72
    BCAsm                                 = 665, // SystemZInstrInfo.td:84
    BCR                                   = 666, // SystemZInstrInfo.td:73
    BCRAsm                                = 667, // SystemZInstrInfo.td:85
    BCT                                   = 668, // SystemZInstrInfo.td:201
    BCTG                                  = 669, // SystemZInstrInfo.td:203
    BCTGR                                 = 670, // SystemZInstrInfo.td:204
    BCTR                                  = 671, // SystemZInstrInfo.td:202
    BDEPG                                 = 672, // SystemZInstrInfo.td:2213
    BEXTG                                 = 673, // SystemZInstrInfo.td:2214
    BI                                    = 674, // SystemZInstrInfo.td:113
    BIAsmE                                = 675, // SystemZInstrInfo.td:99
    BIAsmH                                = 676, // SystemZInstrInfo.td:99
    BIAsmHE                               = 677, // SystemZInstrInfo.td:99
    BIAsmL                                = 678, // SystemZInstrInfo.td:99
    BIAsmLE                               = 679, // SystemZInstrInfo.td:99
    BIAsmLH                               = 680, // SystemZInstrInfo.td:99
    BIAsmM                                = 681, // SystemZInstrInfo.td:99
    BIAsmNE                               = 682, // SystemZInstrInfo.td:99
    BIAsmNH                               = 683, // SystemZInstrInfo.td:99
    BIAsmNHE                              = 684, // SystemZInstrInfo.td:99
    BIAsmNL                               = 685, // SystemZInstrInfo.td:99
    BIAsmNLE                              = 686, // SystemZInstrInfo.td:99
    BIAsmNLH                              = 687, // SystemZInstrInfo.td:99
    BIAsmNM                               = 688, // SystemZInstrInfo.td:99
    BIAsmNO                               = 689, // SystemZInstrInfo.td:99
    BIAsmNP                               = 690, // SystemZInstrInfo.td:99
    BIAsmNZ                               = 691, // SystemZInstrInfo.td:99
    BIAsmO                                = 692, // SystemZInstrInfo.td:99
    BIAsmP                                = 693, // SystemZInstrInfo.td:99
    BIAsmZ                                = 694, // SystemZInstrInfo.td:99
    BIC                                   = 695, // SystemZInstrInfo.td:74
    BICAsm                                = 696, // SystemZInstrInfo.td:86
    BPP                                   = 697, // SystemZInstrInfo.td:1806
    BPRP                                  = 698, // SystemZInstrInfo.td:1807
    BR                                    = 699, // SystemZInstrInfo.td:112
    BRAS                                  = 700, // SystemZInstrInfo.td:276
    BRASL                                 = 701, // SystemZInstrInfo.td:277
    BRAsmE                                = 702, // SystemZInstrInfo.td:98
    BRAsmH                                = 703, // SystemZInstrInfo.td:98
    BRAsmHE                               = 704, // SystemZInstrInfo.td:98
    BRAsmL                                = 705, // SystemZInstrInfo.td:98
    BRAsmLE                               = 706, // SystemZInstrInfo.td:98
    BRAsmLH                               = 707, // SystemZInstrInfo.td:98
    BRAsmM                                = 708, // SystemZInstrInfo.td:98
    BRAsmNE                               = 709, // SystemZInstrInfo.td:98
    BRAsmNH                               = 710, // SystemZInstrInfo.td:98
    BRAsmNHE                              = 711, // SystemZInstrInfo.td:98
    BRAsmNL                               = 712, // SystemZInstrInfo.td:98
    BRAsmNLE                              = 713, // SystemZInstrInfo.td:98
    BRAsmNLH                              = 714, // SystemZInstrInfo.td:98
    BRAsmNM                               = 715, // SystemZInstrInfo.td:98
    BRAsmNO                               = 716, // SystemZInstrInfo.td:98
    BRAsmNP                               = 717, // SystemZInstrInfo.td:98
    BRAsmNZ                               = 718, // SystemZInstrInfo.td:98
    BRAsmO                                = 719, // SystemZInstrInfo.td:98
    BRAsmP                                = 720, // SystemZInstrInfo.td:98
    BRAsmZ                                = 721, // SystemZInstrInfo.td:98
    BRC                                   = 722, // SystemZInstrInfo.td:67
    BRCAsm                                = 723, // SystemZInstrInfo.td:81
    BRCL                                  = 724, // SystemZInstrInfo.td:70
    BRCLAsm                               = 725, // SystemZInstrInfo.td:82
    BRCT                                  = 726, // SystemZInstrInfo.td:194
    BRCTG                                 = 727, // SystemZInstrInfo.td:195
    BRCTH                                 = 728, // SystemZInstrInfo.td:198
    BRXH                                  = 729, // SystemZInstrInfo.td:209
    BRXHG                                 = 730, // SystemZInstrInfo.td:211
    BRXLE                                 = 731, // SystemZInstrInfo.td:210
    BRXLG                                 = 732, // SystemZInstrInfo.td:212
    BSA                                   = 733, // SystemZInstrSystem.td:287
    BSG                                   = 734, // SystemZInstrSystem.td:283
    BSM                                   = 735, // SystemZInstrInfo.td:2135
    BXH                                   = 736, // SystemZInstrInfo.td:214
    BXHG                                  = 737, // SystemZInstrInfo.td:216
    BXLE                                  = 738, // SystemZInstrInfo.td:215
    BXLEG                                 = 739, // SystemZInstrInfo.td:217
    C                                     = 740, // SystemZInstrFormats.td:4289
    CAL                                   = 741, // SystemZInstrInfo.td:1911
    CALG                                  = 742, // SystemZInstrInfo.td:1913
    CALGF                                 = 743, // SystemZInstrInfo.td:1912
    CD                                    = 744, // SystemZInstrHFP.td:247
    CDB                                   = 745, // SystemZInstrFP.td:590
    CDBR                                  = 746, // SystemZInstrFP.td:586
    CDFBR                                 = 747, // SystemZInstrFP.td:252
    CDFBRA                                = 748, // SystemZInstrFP.td:264
    CDFR                                  = 749, // SystemZInstrHFP.td:51
    CDFTR                                 = 750, // SystemZInstrDFP.td:52
    CDGBR                                 = 751, // SystemZInstrFP.td:256
    CDGBRA                                = 752, // SystemZInstrFP.td:268
    CDGR                                  = 753, // SystemZInstrHFP.td:55
    CDGTR                                 = 754, // SystemZInstrDFP.td:47
    CDGTRA                                = 755, // SystemZInstrDFP.td:50
    CDLFBR                                = 756, // SystemZInstrFP.td:276
    CDLFTR                                = 757, // SystemZInstrDFP.td:61
    CDLGBR                                = 758, // SystemZInstrFP.td:280
    CDLGTR                                = 759, // SystemZInstrDFP.td:59
    CDPT                                  = 760, // SystemZInstrDFP.td:109
    CDR                                   = 761, // SystemZInstrHFP.td:243
    CDS                                   = 762, // SystemZInstrFormats.td:5069
    CDSG                                  = 763, // SystemZInstrInfo.td:1888
    CDSTR                                 = 764, // SystemZInstrDFP.td:88
    CDSY                                  = 765, // SystemZInstrFormats.td:5071
    CDTR                                  = 766, // SystemZInstrDFP.td:217
    CDUTR                                 = 767, // SystemZInstrDFP.td:90
    CDZT                                  = 768, // SystemZInstrDFP.td:101
    CE                                    = 769, // SystemZInstrHFP.td:246
    CEB                                   = 770, // SystemZInstrFP.td:589
    CEBR                                  = 771, // SystemZInstrFP.td:585
    CEDTR                                 = 772, // SystemZInstrDFP.td:229
    CEFBR                                 = 773, // SystemZInstrFP.td:251
    CEFBRA                                = 774, // SystemZInstrFP.td:263
    CEFR                                  = 775, // SystemZInstrHFP.td:50
    CEGBR                                 = 776, // SystemZInstrFP.td:255
    CEGBRA                                = 777, // SystemZInstrFP.td:267
    CEGR                                  = 778, // SystemZInstrHFP.td:54
    CELFBR                                = 779, // SystemZInstrFP.td:275
    CELGBR                                = 780, // SystemZInstrFP.td:279
    CER                                   = 781, // SystemZInstrHFP.td:242
    CEXTR                                 = 782, // SystemZInstrDFP.td:230
    CFC                                   = 783, // SystemZInstrInfo.td:2229
    CFDBR                                 = 784, // SystemZInstrFP.td:297
    CFDBRA                                = 785, // SystemZInstrFP.td:319
    CFDR                                  = 786, // SystemZInstrHFP.td:62
    CFDTR                                 = 787, // SystemZInstrDFP.td:72
    CFEBR                                 = 788, // SystemZInstrFP.td:296
    CFEBRA                                = 789, // SystemZInstrFP.td:318
    CFER                                  = 790, // SystemZInstrHFP.td:61
    CFI                                   = 791, // SystemZInstrInfo.td:1675
    CFXBR                                 = 792, // SystemZInstrFP.td:298
    CFXBRA                                = 793, // SystemZInstrFP.td:320
    CFXR                                  = 794, // SystemZInstrHFP.td:63
    CFXTR                                 = 795, // SystemZInstrDFP.td:73
    CG                                    = 796, // SystemZInstrInfo.td:1689
    CGDBR                                 = 797, // SystemZInstrFP.td:301
    CGDBRA                                = 798, // SystemZInstrFP.td:323
    CGDR                                  = 799, // SystemZInstrHFP.td:66
    CGDTR                                 = 800, // SystemZInstrDFP.td:67
    CGDTRA                                = 801, // SystemZInstrDFP.td:70
    CGEBR                                 = 802, // SystemZInstrFP.td:300
    CGEBRA                                = 803, // SystemZInstrFP.td:322
    CGER                                  = 804, // SystemZInstrHFP.td:65
    CGF                                   = 805, // SystemZInstrInfo.td:1688
    CGFI                                  = 806, // SystemZInstrInfo.td:1678
    CGFR                                  = 807, // SystemZInstrInfo.td:1655
    CGFRL                                 = 808, // SystemZInstrInfo.td:1693
    CGH                                   = 809, // SystemZInstrInfo.td:1687
    CGHI                                  = 810, // SystemZInstrInfo.td:1669
    CGHRL                                 = 811, // SystemZInstrInfo.td:1692
    CGHSI                                 = 812, // SystemZInstrInfo.td:1699
    CGIB                                  = 813, // SystemZInstrFormats.td:2613
    CGIBAsm                               = 814, // SystemZInstrFormats.td:2614
    CGIBAsmE                              = 815, // SystemZInstrInfo.td:178
    CGIBAsmH                              = 816, // SystemZInstrInfo.td:178
    CGIBAsmHE                             = 817, // SystemZInstrInfo.td:178
    CGIBAsmL                              = 818, // SystemZInstrInfo.td:178
    CGIBAsmLE                             = 819, // SystemZInstrInfo.td:178
    CGIBAsmLH                             = 820, // SystemZInstrInfo.td:178
    CGIBAsmNE                             = 821, // SystemZInstrInfo.td:178
    CGIBAsmNH                             = 822, // SystemZInstrInfo.td:178
    CGIBAsmNHE                            = 823, // SystemZInstrInfo.td:178
    CGIBAsmNL                             = 824, // SystemZInstrInfo.td:178
    CGIBAsmNLE                            = 825, // SystemZInstrInfo.td:178
    CGIBAsmNLH                            = 826, // SystemZInstrInfo.td:178
    CGIJ                                  = 827, // SystemZInstrFormats.td:2529
    CGIJAsm                               = 828, // SystemZInstrFormats.td:2530
    CGIJAsmE                              = 829, // SystemZInstrInfo.td:164
    CGIJAsmH                              = 830, // SystemZInstrInfo.td:164
    CGIJAsmHE                             = 831, // SystemZInstrInfo.td:164
    CGIJAsmL                              = 832, // SystemZInstrInfo.td:164
    CGIJAsmLE                             = 833, // SystemZInstrInfo.td:164
    CGIJAsmLH                             = 834, // SystemZInstrInfo.td:164
    CGIJAsmNE                             = 835, // SystemZInstrInfo.td:164
    CGIJAsmNH                             = 836, // SystemZInstrInfo.td:164
    CGIJAsmNHE                            = 837, // SystemZInstrInfo.td:164
    CGIJAsmNL                             = 838, // SystemZInstrInfo.td:164
    CGIJAsmNLE                            = 839, // SystemZInstrInfo.td:164
    CGIJAsmNLH                            = 840, // SystemZInstrInfo.td:164
    CGIT                                  = 841, // SystemZInstrFormats.td:2473
    CGITAsm                               = 842, // SystemZInstrFormats.td:2474
    CGITAsmE                              = 843, // SystemZInstrInfo.td:256
    CGITAsmH                              = 844, // SystemZInstrInfo.td:256
    CGITAsmHE                             = 845, // SystemZInstrInfo.td:256
    CGITAsmL                              = 846, // SystemZInstrInfo.td:256
    CGITAsmLE                             = 847, // SystemZInstrInfo.td:256
    CGITAsmLH                             = 848, // SystemZInstrInfo.td:256
    CGITAsmNE                             = 849, // SystemZInstrInfo.td:256
    CGITAsmNH                             = 850, // SystemZInstrInfo.td:256
    CGITAsmNHE                            = 851, // SystemZInstrInfo.td:256
    CGITAsmNL                             = 852, // SystemZInstrInfo.td:256
    CGITAsmNLE                            = 853, // SystemZInstrInfo.td:256
    CGITAsmNLH                            = 854, // SystemZInstrInfo.td:256
    CGR                                   = 855, // SystemZInstrInfo.td:1656
    CGRB                                  = 856, // SystemZInstrFormats.td:2584
    CGRBAsm                               = 857, // SystemZInstrFormats.td:2585
    CGRBAsmE                              = 858, // SystemZInstrInfo.td:175
    CGRBAsmH                              = 859, // SystemZInstrInfo.td:175
    CGRBAsmHE                             = 860, // SystemZInstrInfo.td:175
    CGRBAsmL                              = 861, // SystemZInstrInfo.td:175
    CGRBAsmLE                             = 862, // SystemZInstrInfo.td:175
    CGRBAsmLH                             = 863, // SystemZInstrInfo.td:175
    CGRBAsmNE                             = 864, // SystemZInstrInfo.td:175
    CGRBAsmNH                             = 865, // SystemZInstrInfo.td:175
    CGRBAsmNHE                            = 866, // SystemZInstrInfo.td:175
    CGRBAsmNL                             = 867, // SystemZInstrInfo.td:175
    CGRBAsmNLE                            = 868, // SystemZInstrInfo.td:175
    CGRBAsmNLH                            = 869, // SystemZInstrInfo.td:175
    CGRJ                                  = 870, // SystemZInstrFormats.td:2501
    CGRJAsm                               = 871, // SystemZInstrFormats.td:2502
    CGRJAsmE                              = 872, // SystemZInstrInfo.td:161
    CGRJAsmH                              = 873, // SystemZInstrInfo.td:161
    CGRJAsmHE                             = 874, // SystemZInstrInfo.td:161
    CGRJAsmL                              = 875, // SystemZInstrInfo.td:161
    CGRJAsmLE                             = 876, // SystemZInstrInfo.td:161
    CGRJAsmLH                             = 877, // SystemZInstrInfo.td:161
    CGRJAsmNE                             = 878, // SystemZInstrInfo.td:161
    CGRJAsmNH                             = 879, // SystemZInstrInfo.td:161
    CGRJAsmNHE                            = 880, // SystemZInstrInfo.td:161
    CGRJAsmNL                             = 881, // SystemZInstrInfo.td:161
    CGRJAsmNLE                            = 882, // SystemZInstrInfo.td:161
    CGRJAsmNLH                            = 883, // SystemZInstrInfo.td:161
    CGRL                                  = 884, // SystemZInstrInfo.td:1694
    CGRT                                  = 885, // SystemZInstrFormats.td:2546
    CGRTAsm                               = 886, // SystemZInstrFormats.td:2547
    CGRTAsmE                              = 887, // SystemZInstrInfo.td:251
    CGRTAsmH                              = 888, // SystemZInstrInfo.td:251
    CGRTAsmHE                             = 889, // SystemZInstrInfo.td:251
    CGRTAsmL                              = 890, // SystemZInstrInfo.td:251
    CGRTAsmLE                             = 891, // SystemZInstrInfo.td:251
    CGRTAsmLH                             = 892, // SystemZInstrInfo.td:251
    CGRTAsmNE                             = 893, // SystemZInstrInfo.td:251
    CGRTAsmNH                             = 894, // SystemZInstrInfo.td:251
    CGRTAsmNHE                            = 895, // SystemZInstrInfo.td:251
    CGRTAsmNL                             = 896, // SystemZInstrInfo.td:251
    CGRTAsmNLE                            = 897, // SystemZInstrInfo.td:251
    CGRTAsmNLH                            = 898, // SystemZInstrInfo.td:251
    CGXBR                                 = 899, // SystemZInstrFP.td:302
    CGXBRA                                = 900, // SystemZInstrFP.td:324
    CGXR                                  = 901, // SystemZInstrHFP.td:67
    CGXTR                                 = 902, // SystemZInstrDFP.td:68
    CGXTRA                                = 903, // SystemZInstrDFP.td:71
    CH                                    = 904, // SystemZInstrFormats.td:4289
    CHF                                   = 905, // SystemZInstrInfo.td:1685
    CHHR                                  = 906, // SystemZInstrInfo.td:1659
    CHHSI                                 = 907, // SystemZInstrInfo.td:1697
    CHI                                   = 908, // SystemZInstrInfo.td:1668
    CHLR                                  = 909, // SystemZInstrInfo.td:1661
    CHRL                                  = 910, // SystemZInstrInfo.td:1690
    CHSI                                  = 911, // SystemZInstrInfo.td:1698
    CHY                                   = 912, // SystemZInstrFormats.td:4292
    CIB                                   = 913, // SystemZInstrFormats.td:2613
    CIBAsm                                = 914, // SystemZInstrFormats.td:2614
    CIBAsmE                               = 915, // SystemZInstrInfo.td:176
    CIBAsmH                               = 916, // SystemZInstrInfo.td:176
    CIBAsmHE                              = 917, // SystemZInstrInfo.td:176
    CIBAsmL                               = 918, // SystemZInstrInfo.td:176
    CIBAsmLE                              = 919, // SystemZInstrInfo.td:176
    CIBAsmLH                              = 920, // SystemZInstrInfo.td:176
    CIBAsmNE                              = 921, // SystemZInstrInfo.td:176
    CIBAsmNH                              = 922, // SystemZInstrInfo.td:176
    CIBAsmNHE                             = 923, // SystemZInstrInfo.td:176
    CIBAsmNL                              = 924, // SystemZInstrInfo.td:176
    CIBAsmNLE                             = 925, // SystemZInstrInfo.td:176
    CIBAsmNLH                             = 926, // SystemZInstrInfo.td:176
    CIH                                   = 927, // SystemZInstrInfo.td:1676
    CIJ                                   = 928, // SystemZInstrFormats.td:2529
    CIJAsm                                = 929, // SystemZInstrFormats.td:2530
    CIJAsmE                               = 930, // SystemZInstrInfo.td:162
    CIJAsmH                               = 931, // SystemZInstrInfo.td:162
    CIJAsmHE                              = 932, // SystemZInstrInfo.td:162
    CIJAsmL                               = 933, // SystemZInstrInfo.td:162
    CIJAsmLE                              = 934, // SystemZInstrInfo.td:162
    CIJAsmLH                              = 935, // SystemZInstrInfo.td:162
    CIJAsmNE                              = 936, // SystemZInstrInfo.td:162
    CIJAsmNH                              = 937, // SystemZInstrInfo.td:162
    CIJAsmNHE                             = 938, // SystemZInstrInfo.td:162
    CIJAsmNL                              = 939, // SystemZInstrInfo.td:162
    CIJAsmNLE                             = 940, // SystemZInstrInfo.td:162
    CIJAsmNLH                             = 941, // SystemZInstrInfo.td:162
    CIT                                   = 942, // SystemZInstrFormats.td:2473
    CITAsm                                = 943, // SystemZInstrFormats.td:2474
    CITAsmE                               = 944, // SystemZInstrInfo.td:254
    CITAsmH                               = 945, // SystemZInstrInfo.td:254
    CITAsmHE                              = 946, // SystemZInstrInfo.td:254
    CITAsmL                               = 947, // SystemZInstrInfo.td:254
    CITAsmLE                              = 948, // SystemZInstrInfo.td:254
    CITAsmLH                              = 949, // SystemZInstrInfo.td:254
    CITAsmNE                              = 950, // SystemZInstrInfo.td:254
    CITAsmNH                              = 951, // SystemZInstrInfo.td:254
    CITAsmNHE                             = 952, // SystemZInstrInfo.td:254
    CITAsmNL                              = 953, // SystemZInstrInfo.td:254
    CITAsmNLE                             = 954, // SystemZInstrInfo.td:254
    CITAsmNLH                             = 955, // SystemZInstrInfo.td:254
    CKSM                                  = 956, // SystemZInstrInfo.td:2238
    CL                                    = 957, // SystemZInstrFormats.td:4289
    CLC                                   = 958, // SystemZInstrFormats.td:5588
    CLCL                                  = 959, // SystemZInstrInfo.td:1757
    CLCLE                                 = 960, // SystemZInstrInfo.td:1758
    CLCLU                                 = 961, // SystemZInstrInfo.td:1759
    CLFDBR                                = 962, // SystemZInstrFP.td:331
    CLFDTR                                = 963, // SystemZInstrDFP.td:82
    CLFEBR                                = 964, // SystemZInstrFP.td:330
    CLFHSI                                = 965, // SystemZInstrInfo.td:1749
    CLFI                                  = 966, // SystemZInstrInfo.td:1720
    CLFIT                                 = 967, // SystemZInstrFormats.td:2473
    CLFITAsm                              = 968, // SystemZInstrFormats.td:2474
    CLFITAsmE                             = 969, // SystemZInstrInfo.td:258
    CLFITAsmH                             = 970, // SystemZInstrInfo.td:258
    CLFITAsmHE                            = 971, // SystemZInstrInfo.td:258
    CLFITAsmL                             = 972, // SystemZInstrInfo.td:258
    CLFITAsmLE                            = 973, // SystemZInstrInfo.td:258
    CLFITAsmLH                            = 974, // SystemZInstrInfo.td:258
    CLFITAsmNE                            = 975, // SystemZInstrInfo.td:258
    CLFITAsmNH                            = 976, // SystemZInstrInfo.td:258
    CLFITAsmNHE                           = 977, // SystemZInstrInfo.td:258
    CLFITAsmNL                            = 978, // SystemZInstrInfo.td:258
    CLFITAsmNLE                           = 979, // SystemZInstrInfo.td:258
    CLFITAsmNLH                           = 980, // SystemZInstrInfo.td:258
    CLFXBR                                = 981, // SystemZInstrFP.td:332
    CLFXTR                                = 982, // SystemZInstrDFP.td:83
    CLG                                   = 983, // SystemZInstrInfo.td:1732
    CLGDBR                                = 984, // SystemZInstrFP.td:335
    CLGDTR                                = 985, // SystemZInstrDFP.td:80
    CLGEBR                                = 986, // SystemZInstrFP.td:334
    CLGF                                  = 987, // SystemZInstrInfo.td:1731
    CLGFI                                 = 988, // SystemZInstrInfo.td:1723
    CLGFR                                 = 989, // SystemZInstrInfo.td:1707
    CLGFRL                                = 990, // SystemZInstrInfo.td:1739
    CLGHRL                                = 991, // SystemZInstrInfo.td:1737
    CLGHSI                                = 992, // SystemZInstrInfo.td:1750
    CLGIB                                 = 993, // SystemZInstrFormats.td:2613
    CLGIBAsm                              = 994, // SystemZInstrFormats.td:2614
    CLGIBAsmE                             = 995, // SystemZInstrInfo.td:184
    CLGIBAsmH                             = 996, // SystemZInstrInfo.td:184
    CLGIBAsmHE                            = 997, // SystemZInstrInfo.td:184
    CLGIBAsmL                             = 998, // SystemZInstrInfo.td:184
    CLGIBAsmLE                            = 999, // SystemZInstrInfo.td:184
    CLGIBAsmLH                            = 1000, // SystemZInstrInfo.td:184
    CLGIBAsmNE                            = 1001, // SystemZInstrInfo.td:184
    CLGIBAsmNH                            = 1002, // SystemZInstrInfo.td:184
    CLGIBAsmNHE                           = 1003, // SystemZInstrInfo.td:184
    CLGIBAsmNL                            = 1004, // SystemZInstrInfo.td:184
    CLGIBAsmNLE                           = 1005, // SystemZInstrInfo.td:184
    CLGIBAsmNLH                           = 1006, // SystemZInstrInfo.td:184
    CLGIJ                                 = 1007, // SystemZInstrFormats.td:2529
    CLGIJAsm                              = 1008, // SystemZInstrFormats.td:2530
    CLGIJAsmE                             = 1009, // SystemZInstrInfo.td:170
    CLGIJAsmH                             = 1010, // SystemZInstrInfo.td:170
    CLGIJAsmHE                            = 1011, // SystemZInstrInfo.td:170
    CLGIJAsmL                             = 1012, // SystemZInstrInfo.td:170
    CLGIJAsmLE                            = 1013, // SystemZInstrInfo.td:170
    CLGIJAsmLH                            = 1014, // SystemZInstrInfo.td:170
    CLGIJAsmNE                            = 1015, // SystemZInstrInfo.td:170
    CLGIJAsmNH                            = 1016, // SystemZInstrInfo.td:170
    CLGIJAsmNHE                           = 1017, // SystemZInstrInfo.td:170
    CLGIJAsmNL                            = 1018, // SystemZInstrInfo.td:170
    CLGIJAsmNLE                           = 1019, // SystemZInstrInfo.td:170
    CLGIJAsmNLH                           = 1020, // SystemZInstrInfo.td:170
    CLGIT                                 = 1021, // SystemZInstrFormats.td:2473
    CLGITAsm                              = 1022, // SystemZInstrFormats.td:2474
    CLGITAsmE                             = 1023, // SystemZInstrInfo.td:260
    CLGITAsmH                             = 1024, // SystemZInstrInfo.td:260
    CLGITAsmHE                            = 1025, // SystemZInstrInfo.td:260
    CLGITAsmL                             = 1026, // SystemZInstrInfo.td:260
    CLGITAsmLE                            = 1027, // SystemZInstrInfo.td:260
    CLGITAsmLH                            = 1028, // SystemZInstrInfo.td:260
    CLGITAsmNE                            = 1029, // SystemZInstrInfo.td:260
    CLGITAsmNH                            = 1030, // SystemZInstrInfo.td:260
    CLGITAsmNHE                           = 1031, // SystemZInstrInfo.td:260
    CLGITAsmNL                            = 1032, // SystemZInstrInfo.td:260
    CLGITAsmNLE                           = 1033, // SystemZInstrInfo.td:260
    CLGITAsmNLH                           = 1034, // SystemZInstrInfo.td:260
    CLGR                                  = 1035, // SystemZInstrInfo.td:1708
    CLGRB                                 = 1036, // SystemZInstrFormats.td:2584
    CLGRBAsm                              = 1037, // SystemZInstrFormats.td:2585
    CLGRBAsmE                             = 1038, // SystemZInstrInfo.td:181
    CLGRBAsmH                             = 1039, // SystemZInstrInfo.td:181
    CLGRBAsmHE                            = 1040, // SystemZInstrInfo.td:181
    CLGRBAsmL                             = 1041, // SystemZInstrInfo.td:181
    CLGRBAsmLE                            = 1042, // SystemZInstrInfo.td:181
    CLGRBAsmLH                            = 1043, // SystemZInstrInfo.td:181
    CLGRBAsmNE                            = 1044, // SystemZInstrInfo.td:181
    CLGRBAsmNH                            = 1045, // SystemZInstrInfo.td:181
    CLGRBAsmNHE                           = 1046, // SystemZInstrInfo.td:181
    CLGRBAsmNL                            = 1047, // SystemZInstrInfo.td:181
    CLGRBAsmNLE                           = 1048, // SystemZInstrInfo.td:181
    CLGRBAsmNLH                           = 1049, // SystemZInstrInfo.td:181
    CLGRJ                                 = 1050, // SystemZInstrFormats.td:2501
    CLGRJAsm                              = 1051, // SystemZInstrFormats.td:2502
    CLGRJAsmE                             = 1052, // SystemZInstrInfo.td:167
    CLGRJAsmH                             = 1053, // SystemZInstrInfo.td:167
    CLGRJAsmHE                            = 1054, // SystemZInstrInfo.td:167
    CLGRJAsmL                             = 1055, // SystemZInstrInfo.td:167
    CLGRJAsmLE                            = 1056, // SystemZInstrInfo.td:167
    CLGRJAsmLH                            = 1057, // SystemZInstrInfo.td:167
    CLGRJAsmNE                            = 1058, // SystemZInstrInfo.td:167
    CLGRJAsmNH                            = 1059, // SystemZInstrInfo.td:167
    CLGRJAsmNHE                           = 1060, // SystemZInstrInfo.td:167
    CLGRJAsmNL                            = 1061, // SystemZInstrInfo.td:167
    CLGRJAsmNLE                           = 1062, // SystemZInstrInfo.td:167
    CLGRJAsmNLH                           = 1063, // SystemZInstrInfo.td:167
    CLGRL                                 = 1064, // SystemZInstrInfo.td:1741
    CLGRT                                 = 1065, // SystemZInstrFormats.td:2546
    CLGRTAsm                              = 1066, // SystemZInstrFormats.td:2547
    CLGRTAsmE                             = 1067, // SystemZInstrInfo.td:253
    CLGRTAsmH                             = 1068, // SystemZInstrInfo.td:253
    CLGRTAsmHE                            = 1069, // SystemZInstrInfo.td:253
    CLGRTAsmL                             = 1070, // SystemZInstrInfo.td:253
    CLGRTAsmLE                            = 1071, // SystemZInstrInfo.td:253
    CLGRTAsmLH                            = 1072, // SystemZInstrInfo.td:253
    CLGRTAsmNE                            = 1073, // SystemZInstrInfo.td:253
    CLGRTAsmNH                            = 1074, // SystemZInstrInfo.td:253
    CLGRTAsmNHE                           = 1075, // SystemZInstrInfo.td:253
    CLGRTAsmNL                            = 1076, // SystemZInstrInfo.td:253
    CLGRTAsmNLE                           = 1077, // SystemZInstrInfo.td:253
    CLGRTAsmNLH                           = 1078, // SystemZInstrInfo.td:253
    CLGT                                  = 1079, // SystemZInstrFormats.td:2632
    CLGTAsm                               = 1080, // SystemZInstrFormats.td:2633
    CLGTAsmE                              = 1081, // SystemZInstrInfo.td:264
    CLGTAsmH                              = 1082, // SystemZInstrInfo.td:264
    CLGTAsmHE                             = 1083, // SystemZInstrInfo.td:264
    CLGTAsmL                              = 1084, // SystemZInstrInfo.td:264
    CLGTAsmLE                             = 1085, // SystemZInstrInfo.td:264
    CLGTAsmLH                             = 1086, // SystemZInstrInfo.td:264
    CLGTAsmNE                             = 1087, // SystemZInstrInfo.td:264
    CLGTAsmNH                             = 1088, // SystemZInstrInfo.td:264
    CLGTAsmNHE                            = 1089, // SystemZInstrInfo.td:264
    CLGTAsmNL                             = 1090, // SystemZInstrInfo.td:264
    CLGTAsmNLE                            = 1091, // SystemZInstrInfo.td:264
    CLGTAsmNLH                            = 1092, // SystemZInstrInfo.td:264
    CLGXBR                                = 1093, // SystemZInstrFP.td:336
    CLGXTR                                = 1094, // SystemZInstrDFP.td:81
    CLHF                                  = 1095, // SystemZInstrInfo.td:1729
    CLHHR                                 = 1096, // SystemZInstrInfo.td:1711
    CLHHSI                                = 1097, // SystemZInstrInfo.td:1748
    CLHLR                                 = 1098, // SystemZInstrInfo.td:1713
    CLHRL                                 = 1099, // SystemZInstrInfo.td:1733
    CLI                                   = 1100, // SystemZInstrFormats.td:4366
    CLIB                                  = 1101, // SystemZInstrFormats.td:2613
    CLIBAsm                               = 1102, // SystemZInstrFormats.td:2614
    CLIBAsmE                              = 1103, // SystemZInstrInfo.td:182
    CLIBAsmH                              = 1104, // SystemZInstrInfo.td:182
    CLIBAsmHE                             = 1105, // SystemZInstrInfo.td:182
    CLIBAsmL                              = 1106, // SystemZInstrInfo.td:182
    CLIBAsmLE                             = 1107, // SystemZInstrInfo.td:182
    CLIBAsmLH                             = 1108, // SystemZInstrInfo.td:182
    CLIBAsmNE                             = 1109, // SystemZInstrInfo.td:182
    CLIBAsmNH                             = 1110, // SystemZInstrInfo.td:182
    CLIBAsmNHE                            = 1111, // SystemZInstrInfo.td:182
    CLIBAsmNL                             = 1112, // SystemZInstrInfo.td:182
    CLIBAsmNLE                            = 1113, // SystemZInstrInfo.td:182
    CLIBAsmNLH                            = 1114, // SystemZInstrInfo.td:182
    CLIH                                  = 1115, // SystemZInstrInfo.td:1721
    CLIJ                                  = 1116, // SystemZInstrFormats.td:2529
    CLIJAsm                               = 1117, // SystemZInstrFormats.td:2530
    CLIJAsmE                              = 1118, // SystemZInstrInfo.td:168
    CLIJAsmH                              = 1119, // SystemZInstrInfo.td:168
    CLIJAsmHE                             = 1120, // SystemZInstrInfo.td:168
    CLIJAsmL                              = 1121, // SystemZInstrInfo.td:168
    CLIJAsmLE                             = 1122, // SystemZInstrInfo.td:168
    CLIJAsmLH                             = 1123, // SystemZInstrInfo.td:168
    CLIJAsmNE                             = 1124, // SystemZInstrInfo.td:168
    CLIJAsmNH                             = 1125, // SystemZInstrInfo.td:168
    CLIJAsmNHE                            = 1126, // SystemZInstrInfo.td:168
    CLIJAsmNL                             = 1127, // SystemZInstrInfo.td:168
    CLIJAsmNLE                            = 1128, // SystemZInstrInfo.td:168
    CLIJAsmNLH                            = 1129, // SystemZInstrInfo.td:168
    CLIY                                  = 1130, // SystemZInstrFormats.td:4368
    CLM                                   = 1131, // SystemZInstrFormats.td:4317
    CLMH                                  = 1132, // SystemZInstrInfo.td:1792
    CLMY                                  = 1133, // SystemZInstrFormats.td:4319
    CLR                                   = 1134, // SystemZInstrInfo.td:1706
    CLRB                                  = 1135, // SystemZInstrFormats.td:2584
    CLRBAsm                               = 1136, // SystemZInstrFormats.td:2585
    CLRBAsmE                              = 1137, // SystemZInstrInfo.td:180
    CLRBAsmH                              = 1138, // SystemZInstrInfo.td:180
    CLRBAsmHE                             = 1139, // SystemZInstrInfo.td:180
    CLRBAsmL                              = 1140, // SystemZInstrInfo.td:180
    CLRBAsmLE                             = 1141, // SystemZInstrInfo.td:180
    CLRBAsmLH                             = 1142, // SystemZInstrInfo.td:180
    CLRBAsmNE                             = 1143, // SystemZInstrInfo.td:180
    CLRBAsmNH                             = 1144, // SystemZInstrInfo.td:180
    CLRBAsmNHE                            = 1145, // SystemZInstrInfo.td:180
    CLRBAsmNL                             = 1146, // SystemZInstrInfo.td:180
    CLRBAsmNLE                            = 1147, // SystemZInstrInfo.td:180
    CLRBAsmNLH                            = 1148, // SystemZInstrInfo.td:180
    CLRJ                                  = 1149, // SystemZInstrFormats.td:2501
    CLRJAsm                               = 1150, // SystemZInstrFormats.td:2502
    CLRJAsmE                              = 1151, // SystemZInstrInfo.td:166
    CLRJAsmH                              = 1152, // SystemZInstrInfo.td:166
    CLRJAsmHE                             = 1153, // SystemZInstrInfo.td:166
    CLRJAsmL                              = 1154, // SystemZInstrInfo.td:166
    CLRJAsmLE                             = 1155, // SystemZInstrInfo.td:166
    CLRJAsmLH                             = 1156, // SystemZInstrInfo.td:166
    CLRJAsmNE                             = 1157, // SystemZInstrInfo.td:166
    CLRJAsmNH                             = 1158, // SystemZInstrInfo.td:166
    CLRJAsmNHE                            = 1159, // SystemZInstrInfo.td:166
    CLRJAsmNL                             = 1160, // SystemZInstrInfo.td:166
    CLRJAsmNLE                            = 1161, // SystemZInstrInfo.td:166
    CLRJAsmNLH                            = 1162, // SystemZInstrInfo.td:166
    CLRL                                  = 1163, // SystemZInstrInfo.td:1735
    CLRT                                  = 1164, // SystemZInstrFormats.td:2546
    CLRTAsm                               = 1165, // SystemZInstrFormats.td:2547
    CLRTAsmE                              = 1166, // SystemZInstrInfo.td:252
    CLRTAsmH                              = 1167, // SystemZInstrInfo.td:252
    CLRTAsmHE                             = 1168, // SystemZInstrInfo.td:252
    CLRTAsmL                              = 1169, // SystemZInstrInfo.td:252
    CLRTAsmLE                             = 1170, // SystemZInstrInfo.td:252
    CLRTAsmLH                             = 1171, // SystemZInstrInfo.td:252
    CLRTAsmNE                             = 1172, // SystemZInstrInfo.td:252
    CLRTAsmNH                             = 1173, // SystemZInstrInfo.td:252
    CLRTAsmNHE                            = 1174, // SystemZInstrInfo.td:252
    CLRTAsmNL                             = 1175, // SystemZInstrInfo.td:252
    CLRTAsmNLE                            = 1176, // SystemZInstrInfo.td:252
    CLRTAsmNLH                            = 1177, // SystemZInstrInfo.td:252
    CLST                                  = 1178, // SystemZInstrFormats.td:5609
    CLT                                   = 1179, // SystemZInstrFormats.td:2632
    CLTAsm                                = 1180, // SystemZInstrFormats.td:2633
    CLTAsmE                               = 1181, // SystemZInstrInfo.td:263
    CLTAsmH                               = 1182, // SystemZInstrInfo.td:263
    CLTAsmHE                              = 1183, // SystemZInstrInfo.td:263
    CLTAsmL                               = 1184, // SystemZInstrInfo.td:263
    CLTAsmLE                              = 1185, // SystemZInstrInfo.td:263
    CLTAsmLH                              = 1186, // SystemZInstrInfo.td:263
    CLTAsmNE                              = 1187, // SystemZInstrInfo.td:263
    CLTAsmNH                              = 1188, // SystemZInstrInfo.td:263
    CLTAsmNHE                             = 1189, // SystemZInstrInfo.td:263
    CLTAsmNL                              = 1190, // SystemZInstrInfo.td:263
    CLTAsmNLE                             = 1191, // SystemZInstrInfo.td:263
    CLTAsmNLH                             = 1192, // SystemZInstrInfo.td:263
    CLY                                   = 1193, // SystemZInstrFormats.td:4292
    CLZG                                  = 1194, // SystemZInstrInfo.td:2189
    CMPSC                                 = 1195, // SystemZInstrInfo.td:2242
    CP                                    = 1196, // SystemZInstrInfo.td:2076
    CPDT                                  = 1197, // SystemZInstrDFP.td:111
    CPSDRdd                               = 1198, // SystemZInstrFP.td:123
    CPSDRdh                               = 1199, // SystemZInstrFP.td:120
    CPSDRds                               = 1200, // SystemZInstrFP.td:121
    CPSDRhd                               = 1201, // SystemZInstrFP.td:91
    CPSDRhh                               = 1202, // SystemZInstrFP.td:89
    CPSDRhs                               = 1203, // SystemZInstrFP.td:90
    CPSDRsd                               = 1204, // SystemZInstrFP.td:107
    CPSDRsh                               = 1205, // SystemZInstrFP.td:105
    CPSDRss                               = 1206, // SystemZInstrFP.td:106
    CPXT                                  = 1207, // SystemZInstrDFP.td:112
    CPYA                                  = 1208, // SystemZInstrInfo.td:2093
    CR                                    = 1209, // SystemZInstrInfo.td:1654
    CRB                                   = 1210, // SystemZInstrFormats.td:2584
    CRBAsm                                = 1211, // SystemZInstrFormats.td:2585
    CRBAsmE                               = 1212, // SystemZInstrInfo.td:174
    CRBAsmH                               = 1213, // SystemZInstrInfo.td:174
    CRBAsmHE                              = 1214, // SystemZInstrInfo.td:174
    CRBAsmL                               = 1215, // SystemZInstrInfo.td:174
    CRBAsmLE                              = 1216, // SystemZInstrInfo.td:174
    CRBAsmLH                              = 1217, // SystemZInstrInfo.td:174
    CRBAsmNE                              = 1218, // SystemZInstrInfo.td:174
    CRBAsmNH                              = 1219, // SystemZInstrInfo.td:174
    CRBAsmNHE                             = 1220, // SystemZInstrInfo.td:174
    CRBAsmNL                              = 1221, // SystemZInstrInfo.td:174
    CRBAsmNLE                             = 1222, // SystemZInstrInfo.td:174
    CRBAsmNLH                             = 1223, // SystemZInstrInfo.td:174
    CRDTE                                 = 1224, // SystemZInstrFormats.td:5014
    CRDTEOpt                              = 1225, // SystemZInstrFormats.td:5015
    CRJ                                   = 1226, // SystemZInstrFormats.td:2501
    CRJAsm                                = 1227, // SystemZInstrFormats.td:2502
    CRJAsmE                               = 1228, // SystemZInstrInfo.td:160
    CRJAsmH                               = 1229, // SystemZInstrInfo.td:160
    CRJAsmHE                              = 1230, // SystemZInstrInfo.td:160
    CRJAsmL                               = 1231, // SystemZInstrInfo.td:160
    CRJAsmLE                              = 1232, // SystemZInstrInfo.td:160
    CRJAsmLH                              = 1233, // SystemZInstrInfo.td:160
    CRJAsmNE                              = 1234, // SystemZInstrInfo.td:160
    CRJAsmNH                              = 1235, // SystemZInstrInfo.td:160
    CRJAsmNHE                             = 1236, // SystemZInstrInfo.td:160
    CRJAsmNL                              = 1237, // SystemZInstrInfo.td:160
    CRJAsmNLE                             = 1238, // SystemZInstrInfo.td:160
    CRJAsmNLH                             = 1239, // SystemZInstrInfo.td:160
    CRL                                   = 1240, // SystemZInstrInfo.td:1691
    CRT                                   = 1241, // SystemZInstrFormats.td:2546
    CRTAsm                                = 1242, // SystemZInstrFormats.td:2547
    CRTAsmE                               = 1243, // SystemZInstrInfo.td:250
    CRTAsmH                               = 1244, // SystemZInstrInfo.td:250
    CRTAsmHE                              = 1245, // SystemZInstrInfo.td:250
    CRTAsmL                               = 1246, // SystemZInstrInfo.td:250
    CRTAsmLE                              = 1247, // SystemZInstrInfo.td:250
    CRTAsmLH                              = 1248, // SystemZInstrInfo.td:250
    CRTAsmNE                              = 1249, // SystemZInstrInfo.td:250
    CRTAsmNH                              = 1250, // SystemZInstrInfo.td:250
    CRTAsmNHE                             = 1251, // SystemZInstrInfo.td:250
    CRTAsmNL                              = 1252, // SystemZInstrInfo.td:250
    CRTAsmNLE                             = 1253, // SystemZInstrInfo.td:250
    CRTAsmNLH                             = 1254, // SystemZInstrInfo.td:250
    CS                                    = 1255, // SystemZInstrFormats.td:5069
    CSCH                                  = 1256, // SystemZInstrSystem.td:494
    CSDTR                                 = 1257, // SystemZInstrDFP.td:94
    CSG                                   = 1258, // SystemZInstrInfo.td:1882
    CSP                                   = 1259, // SystemZInstrSystem.td:190
    CSPG                                  = 1260, // SystemZInstrSystem.td:191
    CSST                                  = 1261, // SystemZInstrInfo.td:1893
    CSXTR                                 = 1262, // SystemZInstrDFP.td:95
    CSY                                   = 1263, // SystemZInstrFormats.td:5071
    CTZG                                  = 1264, // SystemZInstrInfo.td:2190
    CU12                                  = 1265, // SystemZInstrFormats.td:4516
    CU12Opt                               = 1266, // SystemZInstrFormats.td:4517
    CU14                                  = 1267, // SystemZInstrFormats.td:4516
    CU14Opt                               = 1268, // SystemZInstrFormats.td:4517
    CU21                                  = 1269, // SystemZInstrFormats.td:4516
    CU21Opt                               = 1270, // SystemZInstrFormats.td:4517
    CU24                                  = 1271, // SystemZInstrFormats.td:4516
    CU24Opt                               = 1272, // SystemZInstrFormats.td:4517
    CU41                                  = 1273, // SystemZInstrInfo.td:1954
    CU42                                  = 1274, // SystemZInstrInfo.td:1955
    CUDTR                                 = 1275, // SystemZInstrDFP.td:96
    CUSE                                  = 1276, // SystemZInstrInfo.td:2225
    CUTFU                                 = 1277, // SystemZInstrFormats.td:4516
    CUTFUOpt                              = 1278, // SystemZInstrFormats.td:4517
    CUUTF                                 = 1279, // SystemZInstrFormats.td:4516
    CUUTFOpt                              = 1280, // SystemZInstrFormats.td:4517
    CUXTR                                 = 1281, // SystemZInstrDFP.td:97
    CVB                                   = 1282, // SystemZInstrFormats.td:3817
    CVBG                                  = 1283, // SystemZInstrInfo.td:2040
    CVBY                                  = 1284, // SystemZInstrFormats.td:3820
    CVD                                   = 1285, // SystemZInstrFormats.td:2795
    CVDG                                  = 1286, // SystemZInstrInfo.td:2043
    CVDY                                  = 1287, // SystemZInstrFormats.td:2797
    CXBR                                  = 1288, // SystemZInstrFP.td:587
    CXFBR                                 = 1289, // SystemZInstrFP.td:253
    CXFBRA                                = 1290, // SystemZInstrFP.td:265
    CXFR                                  = 1291, // SystemZInstrHFP.td:52
    CXFTR                                 = 1292, // SystemZInstrDFP.td:53
    CXGBR                                 = 1293, // SystemZInstrFP.td:257
    CXGBRA                                = 1294, // SystemZInstrFP.td:269
    CXGR                                  = 1295, // SystemZInstrHFP.td:56
    CXGTR                                 = 1296, // SystemZInstrDFP.td:48
    CXGTRA                                = 1297, // SystemZInstrDFP.td:51
    CXLFBR                                = 1298, // SystemZInstrFP.td:277
    CXLFTR                                = 1299, // SystemZInstrDFP.td:62
    CXLGBR                                = 1300, // SystemZInstrFP.td:281
    CXLGTR                                = 1301, // SystemZInstrDFP.td:60
    CXPT                                  = 1302, // SystemZInstrDFP.td:110
    CXR                                   = 1303, // SystemZInstrHFP.td:244
    CXSTR                                 = 1304, // SystemZInstrDFP.td:89
    CXTR                                  = 1305, // SystemZInstrDFP.td:218
    CXUTR                                 = 1306, // SystemZInstrDFP.td:91
    CXZT                                  = 1307, // SystemZInstrDFP.td:102
    CY                                    = 1308, // SystemZInstrFormats.td:4292
    CZDT                                  = 1309, // SystemZInstrDFP.td:103
    CZXT                                  = 1310, // SystemZInstrDFP.td:104
    D                                     = 1311, // SystemZInstrInfo.td:1548
    DD                                    = 1312, // SystemZInstrHFP.td:234
    DDB                                   = 1313, // SystemZInstrFormats.td:5531
    DDBR                                  = 1314, // SystemZInstrFP.td:567
    DDR                                   = 1315, // SystemZInstrHFP.td:231
    DDTR                                  = 1316, // SystemZInstrDFP.td:180
    DDTRA                                 = 1317, // SystemZInstrDFP.td:183
    DE                                    = 1318, // SystemZInstrHFP.td:233
    DEB                                   = 1319, // SystemZInstrFormats.td:5531
    DEBR                                  = 1320, // SystemZInstrFP.td:566
    DER                                   = 1321, // SystemZInstrHFP.td:230
    DFLTCC                                = 1322, // SystemZInstrInfo.td:2252
    DIAG                                  = 1323, // SystemZInstrSystem.td:414
    DIDBR                                 = 1324, // SystemZInstrFP.td:577
    DIEBR                                 = 1325, // SystemZInstrFP.td:576
    DL                                    = 1326, // SystemZInstrInfo.td:1551
    DLG                                   = 1327, // SystemZInstrInfo.td:1552
    DLGR                                  = 1328, // SystemZInstrInfo.td:1545
    DLR                                   = 1329, // SystemZInstrInfo.td:1544
    DP                                    = 1330, // SystemZInstrInfo.td:2068
    DR                                    = 1331, // SystemZInstrInfo.td:1541
    DSG                                   = 1332, // SystemZInstrInfo.td:1550
    DSGF                                  = 1333, // SystemZInstrInfo.td:1549
    DSGFR                                 = 1334, // SystemZInstrInfo.td:1542
    DSGR                                  = 1335, // SystemZInstrInfo.td:1543
    DXBR                                  = 1336, // SystemZInstrFP.td:568
    DXR                                   = 1337, // SystemZInstrHFP.td:232
    DXTR                                  = 1338, // SystemZInstrDFP.td:181
    DXTRA                                 = 1339, // SystemZInstrDFP.td:184
    EAR                                   = 1340, // SystemZInstrInfo.td:2087
    ECAG                                  = 1341, // SystemZInstrSystem.td:380
    ECCTR                                 = 1342, // SystemZInstrSystem.td:454
    ECPGA                                 = 1343, // SystemZInstrSystem.td:450
    ECTG                                  = 1344, // SystemZInstrSystem.td:384
    ED                                    = 1345, // SystemZInstrInfo.td:2070
    EDMK                                  = 1346, // SystemZInstrInfo.td:2071
    EEDTR                                 = 1347, // SystemZInstrDFP.td:132
    EEXTR                                 = 1348, // SystemZInstrDFP.td:133
    EFPC                                  = 1349, // SystemZInstrFP.td:615
    EPAIR                                 = 1350, // SystemZInstrSystem.td:77
    EPAR                                  = 1351, // SystemZInstrSystem.td:76
    EPCTR                                 = 1352, // SystemZInstrSystem.td:458
    EPSW                                  = 1353, // SystemZInstrSystem.td:22
    EREG                                  = 1354, // SystemZInstrSystem.td:303
    EREGG                                 = 1355, // SystemZInstrSystem.td:304
    ESAIR                                 = 1356, // SystemZInstrSystem.td:83
    ESAR                                  = 1357, // SystemZInstrSystem.td:82
    ESDTR                                 = 1358, // SystemZInstrDFP.td:136
    ESEA                                  = 1359, // SystemZInstrSystem.td:94
    ESTA                                  = 1360, // SystemZInstrSystem.td:309
    ESXTR                                 = 1361, // SystemZInstrDFP.td:137
    ETND                                  = 1362, // SystemZInstrInfo.td:2168
    EX                                    = 1363, // SystemZInstrInfo.td:2262
    EXRL                                  = 1364, // SystemZInstrInfo.td:2263
    FIDBR                                 = 1365, // SystemZInstrFP.td:414
    FIDBRA                                = 1366, // SystemZInstrFP.td:429
    FIDR                                  = 1367, // SystemZInstrHFP.td:122
    FIDTR                                 = 1368, // SystemZInstrDFP.td:127
    FIEBR                                 = 1369, // SystemZInstrFP.td:413
    FIEBRA                                = 1370, // SystemZInstrFP.td:428
    FIER                                  = 1371, // SystemZInstrHFP.td:121
    FIXBR                                 = 1372, // SystemZInstrFP.td:415
    FIXBRA                                = 1373, // SystemZInstrFP.td:430
    FIXR                                  = 1374, // SystemZInstrHFP.td:123
    FIXTR                                 = 1375, // SystemZInstrDFP.td:128
    FLOGR                                 = 1376, // SystemZInstrInfo.td:2198
    HDR                                   = 1377, // SystemZInstrHFP.td:110
    HER                                   = 1378, // SystemZInstrHFP.td:109
    HSCH                                  = 1379, // SystemZInstrSystem.td:498
    IAC                                   = 1380, // SystemZInstrSystem.td:52
    IC                                    = 1381, // SystemZInstrFormats.td:3817
    IC32                                  = 1382, // SystemZInstrFormats.td:3817
    IC32Y                                 = 1383, // SystemZInstrFormats.td:3820
    ICM                                   = 1384, // SystemZInstrFormats.td:4584
    ICMH                                  = 1385, // SystemZInstrInfo.td:1023
    ICMY                                  = 1386, // SystemZInstrFormats.td:4586
    ICY                                   = 1387, // SystemZInstrFormats.td:3820
    IDTE                                  = 1388, // SystemZInstrFormats.td:5014
    IDTEOpt                               = 1389, // SystemZInstrFormats.td:5015
    IEDTR                                 = 1390, // SystemZInstrDFP.td:207
    IEXTR                                 = 1391, // SystemZInstrDFP.td:208
    IIHF                                  = 1392, // SystemZInstrInfo.td:1052
    IIHH                                  = 1393, // SystemZInstrInfo.td:1038
    IIHL                                  = 1394, // SystemZInstrInfo.td:1037
    IILF                                  = 1395, // SystemZInstrInfo.td:1051
    IILH                                  = 1396, // SystemZInstrInfo.td:1036
    IILL                                  = 1397, // SystemZInstrInfo.td:1035
    IPK                                   = 1398, // SystemZInstrSystem.td:34
    IPM                                   = 1399, // SystemZInstrInfo.td:2110
    IPTE                                  = 1400, // SystemZInstrFormats.td:4999
    IPTEOpt                               = 1401, // SystemZInstrFormats.td:5000
    IPTEOptOpt                            = 1402, // SystemZInstrFormats.td:5001
    IRBM                                  = 1403, // SystemZInstrSystem.td:148
    ISKE                                  = 1404, // SystemZInstrSystem.td:128
    IVSK                                  = 1405, // SystemZInstrSystem.td:132
    InsnE                                 = 1406, // SystemZInstrInfo.td:2275
    InsnRI                                = 1407, // SystemZInstrInfo.td:2276
    InsnRIE                               = 1408, // SystemZInstrInfo.td:2279
    InsnRIL                               = 1409, // SystemZInstrInfo.td:2282
    InsnRILU                              = 1410, // SystemZInstrInfo.td:2285
    InsnRIS                               = 1411, // SystemZInstrInfo.td:2288
    InsnRR                                = 1412, // SystemZInstrInfo.td:2293
    InsnRRE                               = 1413, // SystemZInstrInfo.td:2296
    InsnRRF                               = 1414, // SystemZInstrInfo.td:2299
    InsnRRS                               = 1415, // SystemZInstrInfo.td:2303
    InsnRS                                = 1416, // SystemZInstrInfo.td:2308
    InsnRSE                               = 1417, // SystemZInstrInfo.td:2312
    InsnRSI                               = 1418, // SystemZInstrInfo.td:2316
    InsnRSY                               = 1419, // SystemZInstrInfo.td:2320
    InsnRX                                = 1420, // SystemZInstrInfo.td:2324
    InsnRXE                               = 1421, // SystemZInstrInfo.td:2327
    InsnRXF                               = 1422, // SystemZInstrInfo.td:2330
    InsnRXY                               = 1423, // SystemZInstrInfo.td:2334
    InsnS                                 = 1424, // SystemZInstrInfo.td:2337
    InsnSI                                = 1425, // SystemZInstrInfo.td:2340
    InsnSIL                               = 1426, // SystemZInstrInfo.td:2348
    InsnSIY                               = 1427, // SystemZInstrInfo.td:2344
    InsnSS                                = 1428, // SystemZInstrInfo.td:2352
    InsnSSE                               = 1429, // SystemZInstrInfo.td:2356
    InsnSSF                               = 1430, // SystemZInstrInfo.td:2360
    InsnVRI                               = 1431, // SystemZInstrInfo.td:2364
    InsnVRR                               = 1432, // SystemZInstrInfo.td:2368
    InsnVRS                               = 1433, // SystemZInstrInfo.td:2373
    InsnVRV                               = 1434, // SystemZInstrInfo.td:2377
    InsnVRX                               = 1435, // SystemZInstrInfo.td:2381
    InsnVSI                               = 1436, // SystemZInstrInfo.td:2385
    J                                     = 1437, // SystemZInstrInfo.td:108
    JAsmE                                 = 1438, // SystemZInstrInfo.td:94
    JAsmH                                 = 1439, // SystemZInstrInfo.td:94
    JAsmHE                                = 1440, // SystemZInstrInfo.td:94
    JAsmL                                 = 1441, // SystemZInstrInfo.td:94
    JAsmLE                                = 1442, // SystemZInstrInfo.td:94
    JAsmLH                                = 1443, // SystemZInstrInfo.td:94
    JAsmM                                 = 1444, // SystemZInstrInfo.td:94
    JAsmNE                                = 1445, // SystemZInstrInfo.td:94
    JAsmNH                                = 1446, // SystemZInstrInfo.td:94
    JAsmNHE                               = 1447, // SystemZInstrInfo.td:94
    JAsmNL                                = 1448, // SystemZInstrInfo.td:94
    JAsmNLE                               = 1449, // SystemZInstrInfo.td:94
    JAsmNLH                               = 1450, // SystemZInstrInfo.td:94
    JAsmNM                                = 1451, // SystemZInstrInfo.td:94
    JAsmNO                                = 1452, // SystemZInstrInfo.td:94
    JAsmNP                                = 1453, // SystemZInstrInfo.td:94
    JAsmNZ                                = 1454, // SystemZInstrInfo.td:94
    JAsmO                                 = 1455, // SystemZInstrInfo.td:94
    JAsmP                                 = 1456, // SystemZInstrInfo.td:94
    JAsmZ                                 = 1457, // SystemZInstrInfo.td:94
    JG                                    = 1458, // SystemZInstrInfo.td:109
    JGAsmE                                = 1459, // SystemZInstrInfo.td:95
    JGAsmH                                = 1460, // SystemZInstrInfo.td:95
    JGAsmHE                               = 1461, // SystemZInstrInfo.td:95
    JGAsmL                                = 1462, // SystemZInstrInfo.td:95
    JGAsmLE                               = 1463, // SystemZInstrInfo.td:95
    JGAsmLH                               = 1464, // SystemZInstrInfo.td:95
    JGAsmM                                = 1465, // SystemZInstrInfo.td:95
    JGAsmNE                               = 1466, // SystemZInstrInfo.td:95
    JGAsmNH                               = 1467, // SystemZInstrInfo.td:95
    JGAsmNHE                              = 1468, // SystemZInstrInfo.td:95
    JGAsmNL                               = 1469, // SystemZInstrInfo.td:95
    JGAsmNLE                              = 1470, // SystemZInstrInfo.td:95
    JGAsmNLH                              = 1471, // SystemZInstrInfo.td:95
    JGAsmNM                               = 1472, // SystemZInstrInfo.td:95
    JGAsmNO                               = 1473, // SystemZInstrInfo.td:95
    JGAsmNP                               = 1474, // SystemZInstrInfo.td:95
    JGAsmNZ                               = 1475, // SystemZInstrInfo.td:95
    JGAsmO                                = 1476, // SystemZInstrInfo.td:95
    JGAsmP                                = 1477, // SystemZInstrInfo.td:95
    JGAsmZ                                = 1478, // SystemZInstrInfo.td:95
    JGNOP                                 = 1479, // SystemZInstrInfo.td:123
    JNOP                                  = 1480, // SystemZInstrInfo.td:122
    KDB                                   = 1481, // SystemZInstrFP.td:597
    KDBR                                  = 1482, // SystemZInstrFP.td:593
    KDSA                                  = 1483, // SystemZInstrInfo.td:2010
    KDTR                                  = 1484, // SystemZInstrDFP.td:223
    KEB                                   = 1485, // SystemZInstrFP.td:596
    KEBR                                  = 1486, // SystemZInstrFP.td:592
    KIMD                                  = 1487, // SystemZInstrInfo.td:1988
    KIMDOpt                               = 1488, // SystemZInstrInfo.td:2013
    KLMD                                  = 1489, // SystemZInstrInfo.td:1989
    KLMDOpt                               = 1490, // SystemZInstrInfo.td:2014
    KM                                    = 1491, // SystemZInstrInfo.td:1985
    KMA                                   = 1492, // SystemZInstrInfo.td:2006
    KMAC                                  = 1493, // SystemZInstrInfo.td:1990
    KMC                                   = 1494, // SystemZInstrInfo.td:1986
    KMCTR                                 = 1495, // SystemZInstrInfo.td:1995
    KMF                                   = 1496, // SystemZInstrInfo.td:1993
    KMO                                   = 1497, // SystemZInstrInfo.td:1994
    KXBR                                  = 1498, // SystemZInstrFP.td:594
    KXTR                                  = 1499, // SystemZInstrDFP.td:224
    L                                     = 1500, // SystemZInstrFormats.td:3240
    LA                                    = 1501, // SystemZInstrFormats.td:3049
    LAA                                   = 1502, // SystemZInstrInfo.td:1823
    LAAG                                  = 1503, // SystemZInstrInfo.td:1824
    LAAL                                  = 1504, // SystemZInstrInfo.td:1825
    LAALG                                 = 1505, // SystemZInstrInfo.td:1826
    LAE                                   = 1506, // SystemZInstrFormats.td:3049
    LAEY                                  = 1507, // SystemZInstrFormats.td:3051
    LAM                                   = 1508, // SystemZInstrFormats.td:2729
    LAMY                                  = 1509, // SystemZInstrFormats.td:2731
    LAN                                   = 1510, // SystemZInstrInfo.td:1827
    LANG                                  = 1511, // SystemZInstrInfo.td:1828
    LAO                                   = 1512, // SystemZInstrInfo.td:1829
    LAOG                                  = 1513, // SystemZInstrInfo.td:1830
    LARL                                  = 1514, // SystemZInstrInfo.td:931
    LASP                                  = 1515, // SystemZInstrSystem.td:257
    LAT                                   = 1516, // SystemZInstrInfo.td:510
    LAX                                   = 1517, // SystemZInstrInfo.td:1831
    LAXG                                  = 1518, // SystemZInstrInfo.td:1832
    LAY                                   = 1519, // SystemZInstrFormats.td:3051
    LB                                    = 1520, // SystemZInstrInfo.td:736
    LBEAR                                 = 1521, // SystemZInstrSystem.td:115
    LBH                                   = 1522, // SystemZInstrInfo.td:737
    LBR                                   = 1523, // SystemZInstrInfo.td:715
    LCBB                                  = 1524, // SystemZInstrVector.td:144
    LCCTL                                 = 1525, // SystemZInstrSystem.td:462
    LCDBR                                 = 1526, // SystemZInstrFP.td:364
    LCDFR                                 = 1527, // SystemZInstrFP.td:368
    LCDFR_16                              = 1528, // SystemZInstrFP.td:370
    LCDFR_32                              = 1529, // SystemZInstrFP.td:371
    LCDR                                  = 1530, // SystemZInstrHFP.td:90
    LCEBR                                 = 1531, // SystemZInstrFP.td:363
    LCER                                  = 1532, // SystemZInstrHFP.td:89
    LCGFR                                 = 1533, // SystemZInstrInfo.td:1002
    LCGR                                  = 1534, // SystemZInstrInfo.td:999
    LCR                                   = 1535, // SystemZInstrInfo.td:998
    LCTL                                  = 1536, // SystemZInstrSystem.td:66
    LCTLG                                 = 1537, // SystemZInstrSystem.td:67
    LCXBR                                 = 1538, // SystemZInstrFP.td:365
    LCXR                                  = 1539, // SystemZInstrHFP.td:91
    LD                                    = 1540, // SystemZInstrFormats.td:3240
    LDE                                   = 1541, // SystemZInstrHFP.td:45
    LDE32                                 = 1542, // SystemZInstrFP.td:169
    LDEB                                  = 1543, // SystemZInstrFP.td:238
    LDEBR                                 = 1544, // SystemZInstrFP.td:227
    LDER                                  = 1545, // SystemZInstrHFP.td:41
    LDETR                                 = 1546, // SystemZInstrDFP.td:41
    LDGR                                  = 1547, // SystemZInstrFP.td:85
    LDR                                   = 1548, // SystemZInstrFP.td:49
    LDR16                                 = 1549, // SystemZInstrFP.td:54
    LDR32                                 = 1550, // SystemZInstrFP.td:55
    LDXBR                                 = 1551, // SystemZInstrFP.td:208
    LDXBRA                                = 1552, // SystemZInstrFP.td:214
    LDXR                                  = 1553, // SystemZInstrHFP.td:34
    LDXTR                                 = 1554, // SystemZInstrDFP.td:36
    LDY                                   = 1555, // SystemZInstrFormats.td:3242
    LE                                    = 1556, // SystemZInstrFormats.td:3240
    LE16                                  = 1557, // SystemZInstrFormats.td:3240
    LE16Y                                 = 1558, // SystemZInstrFormats.td:3242
    LEDBR                                 = 1559, // SystemZInstrFP.td:206
    LEDBRA                                = 1560, // SystemZInstrFP.td:210
    LEDR                                  = 1561, // SystemZInstrHFP.td:32
    LEDTR                                 = 1562, // SystemZInstrDFP.td:35
    LER                                   = 1563, // SystemZInstrFP.td:48
    LER16                                 = 1564, // SystemZInstrFP.td:53
    LEXBR                                 = 1565, // SystemZInstrFP.td:207
    LEXBRA                                = 1566, // SystemZInstrFP.td:212
    LEXR                                  = 1567, // SystemZInstrHFP.td:33
    LEY                                   = 1568, // SystemZInstrFormats.td:3242
    LFAS                                  = 1569, // SystemZInstrFP.td:627
    LFH                                   = 1570, // SystemZInstrInfo.td:477
    LFHAT                                 = 1571, // SystemZInstrInfo.td:511
    LFPC                                  = 1572, // SystemZInstrFP.td:621
    LG                                    = 1573, // SystemZInstrInfo.td:479
    LGAT                                  = 1574, // SystemZInstrInfo.td:512
    LGB                                   = 1575, // SystemZInstrInfo.td:750
    LGBR                                  = 1576, // SystemZInstrInfo.td:719
    LGDR                                  = 1577, // SystemZInstrFP.td:84
    LGF                                   = 1578, // SystemZInstrInfo.td:752
    LGFI                                  = 1579, // SystemZInstrInfo.td:463
    LGFR                                  = 1580, // SystemZInstrInfo.td:721
    LGFRL                                 = 1581, // SystemZInstrInfo.td:754
    LGG                                   = 1582, // SystemZInstrInfo.td:2026
    LGH                                   = 1583, // SystemZInstrInfo.td:751
    LGHI                                  = 1584, // SystemZInstrInfo.td:454
    LGHR                                  = 1585, // SystemZInstrInfo.td:720
    LGHRL                                 = 1586, // SystemZInstrInfo.td:753
    LGR                                   = 1587, // SystemZInstrInfo.td:436
    LGRL                                  = 1588, // SystemZInstrInfo.td:495
    LGSC                                  = 1589, // SystemZInstrInfo.td:2030
    LH                                    = 1590, // SystemZInstrFormats.td:3240
    LHH                                   = 1591, // SystemZInstrInfo.td:745
    LHI                                   = 1592, // SystemZInstrInfo.td:453
    LHR                                   = 1593, // SystemZInstrInfo.td:716
    LHRL                                  = 1594, // SystemZInstrInfo.td:747
    LHY                                   = 1595, // SystemZInstrFormats.td:3242
    LLC                                   = 1596, // SystemZInstrInfo.td:789
    LLCH                                  = 1597, // SystemZInstrInfo.td:790
    LLCR                                  = 1598, // SystemZInstrInfo.td:768
    LLGC                                  = 1599, // SystemZInstrInfo.td:803
    LLGCR                                 = 1600, // SystemZInstrInfo.td:775
    LLGF                                  = 1601, // SystemZInstrInfo.td:805
    LLGFAT                                = 1602, // SystemZInstrInfo.td:827
    LLGFR                                 = 1603, // SystemZInstrInfo.td:777
    LLGFRL                                = 1604, // SystemZInstrInfo.td:807
    LLGFSG                                = 1605, // SystemZInstrInfo.td:2027
    LLGH                                  = 1606, // SystemZInstrInfo.td:804
    LLGHR                                 = 1607, // SystemZInstrInfo.td:776
    LLGHRL                                = 1608, // SystemZInstrInfo.td:806
    LLGT                                  = 1609, // SystemZInstrInfo.td:812
    LLGTAT                                = 1610, // SystemZInstrInfo.td:828
    LLGTR                                 = 1611, // SystemZInstrInfo.td:811
    LLH                                   = 1612, // SystemZInstrInfo.td:797
    LLHH                                  = 1613, // SystemZInstrInfo.td:798
    LLHR                                  = 1614, // SystemZInstrInfo.td:772
    LLHRL                                 = 1615, // SystemZInstrInfo.td:800
    LLIHF                                 = 1616, // SystemZInstrInfo.td:465
    LLIHH                                 = 1617, // SystemZInstrInfo.td:460
    LLIHL                                 = 1618, // SystemZInstrInfo.td:459
    LLILF                                 = 1619, // SystemZInstrInfo.td:464
    LLILH                                 = 1620, // SystemZInstrInfo.td:458
    LLILL                                 = 1621, // SystemZInstrInfo.td:457
    LLXAB                                 = 1622, // SystemZInstrFormats.td:3064
    LLXAF                                 = 1623, // SystemZInstrFormats.td:3064
    LLXAG                                 = 1624, // SystemZInstrFormats.td:3064
    LLXAH                                 = 1625, // SystemZInstrFormats.td:3064
    LLXAQ                                 = 1626, // SystemZInstrFormats.td:3064
    LLZRGF                                = 1627, // SystemZInstrInfo.td:820
    LM                                    = 1628, // SystemZInstrFormats.td:2729
    LMD                                   = 1629, // SystemZInstrInfo.td:891
    LMG                                   = 1630, // SystemZInstrInfo.td:889
    LMH                                   = 1631, // SystemZInstrInfo.td:890
    LMY                                   = 1632, // SystemZInstrFormats.td:2731
    LNDBR                                 = 1633, // SystemZInstrFP.td:390
    LNDFR                                 = 1634, // SystemZInstrFP.td:394
    LNDFR_16                              = 1635, // SystemZInstrFP.td:396
    LNDFR_32                              = 1636, // SystemZInstrFP.td:397
    LNDR                                  = 1637, // SystemZInstrHFP.td:104
    LNEBR                                 = 1638, // SystemZInstrFP.td:389
    LNER                                  = 1639, // SystemZInstrHFP.td:103
    LNGFR                                 = 1640, // SystemZInstrInfo.td:992
    LNGR                                  = 1641, // SystemZInstrInfo.td:989
    LNR                                   = 1642, // SystemZInstrInfo.td:988
    LNXBR                                 = 1643, // SystemZInstrFP.td:391
    LNXR                                  = 1644, // SystemZInstrHFP.td:105
    LOC                                   = 1645, // SystemZInstrFormats.td:3195
    LOCAsm                                = 1646, // SystemZInstrFormats.td:3196
    LOCAsmE                               = 1647, // SystemZInstrInfo.td:697
    LOCAsmH                               = 1648, // SystemZInstrInfo.td:697
    LOCAsmHE                              = 1649, // SystemZInstrInfo.td:697
    LOCAsmL                               = 1650, // SystemZInstrInfo.td:697
    LOCAsmLE                              = 1651, // SystemZInstrInfo.td:697
    LOCAsmLH                              = 1652, // SystemZInstrInfo.td:697
    LOCAsmM                               = 1653, // SystemZInstrInfo.td:697
    LOCAsmNE                              = 1654, // SystemZInstrInfo.td:697
    LOCAsmNH                              = 1655, // SystemZInstrInfo.td:697
    LOCAsmNHE                             = 1656, // SystemZInstrInfo.td:697
    LOCAsmNL                              = 1657, // SystemZInstrInfo.td:697
    LOCAsmNLE                             = 1658, // SystemZInstrInfo.td:697
    LOCAsmNLH                             = 1659, // SystemZInstrInfo.td:697
    LOCAsmNM                              = 1660, // SystemZInstrInfo.td:697
    LOCAsmNO                              = 1661, // SystemZInstrInfo.td:697
    LOCAsmNP                              = 1662, // SystemZInstrInfo.td:697
    LOCAsmNZ                              = 1663, // SystemZInstrInfo.td:697
    LOCAsmO                               = 1664, // SystemZInstrInfo.td:697
    LOCAsmP                               = 1665, // SystemZInstrInfo.td:697
    LOCAsmZ                               = 1666, // SystemZInstrInfo.td:697
    LOCFH                                 = 1667, // SystemZInstrFormats.td:3195
    LOCFHAsm                              = 1668, // SystemZInstrFormats.td:3196
    LOCFHAsmE                             = 1669, // SystemZInstrInfo.td:671
    LOCFHAsmH                             = 1670, // SystemZInstrInfo.td:671
    LOCFHAsmHE                            = 1671, // SystemZInstrInfo.td:671
    LOCFHAsmL                             = 1672, // SystemZInstrInfo.td:671
    LOCFHAsmLE                            = 1673, // SystemZInstrInfo.td:671
    LOCFHAsmLH                            = 1674, // SystemZInstrInfo.td:671
    LOCFHAsmM                             = 1675, // SystemZInstrInfo.td:671
    LOCFHAsmNE                            = 1676, // SystemZInstrInfo.td:671
    LOCFHAsmNH                            = 1677, // SystemZInstrInfo.td:671
    LOCFHAsmNHE                           = 1678, // SystemZInstrInfo.td:671
    LOCFHAsmNL                            = 1679, // SystemZInstrInfo.td:671
    LOCFHAsmNLE                           = 1680, // SystemZInstrInfo.td:671
    LOCFHAsmNLH                           = 1681, // SystemZInstrInfo.td:671
    LOCFHAsmNM                            = 1682, // SystemZInstrInfo.td:671
    LOCFHAsmNO                            = 1683, // SystemZInstrInfo.td:671
    LOCFHAsmNP                            = 1684, // SystemZInstrInfo.td:671
    LOCFHAsmNZ                            = 1685, // SystemZInstrInfo.td:671
    LOCFHAsmO                             = 1686, // SystemZInstrInfo.td:671
    LOCFHAsmP                             = 1687, // SystemZInstrInfo.td:671
    LOCFHAsmZ                             = 1688, // SystemZInstrInfo.td:671
    LOCFHR                                = 1689, // SystemZInstrFormats.td:3606
    LOCFHRAsm                             = 1690, // SystemZInstrFormats.td:3607
    LOCFHRAsmE                            = 1691, // SystemZInstrInfo.td:670
    LOCFHRAsmH                            = 1692, // SystemZInstrInfo.td:670
    LOCFHRAsmHE                           = 1693, // SystemZInstrInfo.td:670
    LOCFHRAsmL                            = 1694, // SystemZInstrInfo.td:670
    LOCFHRAsmLE                           = 1695, // SystemZInstrInfo.td:670
    LOCFHRAsmLH                           = 1696, // SystemZInstrInfo.td:670
    LOCFHRAsmM                            = 1697, // SystemZInstrInfo.td:670
    LOCFHRAsmNE                           = 1698, // SystemZInstrInfo.td:670
    LOCFHRAsmNH                           = 1699, // SystemZInstrInfo.td:670
    LOCFHRAsmNHE                          = 1700, // SystemZInstrInfo.td:670
    LOCFHRAsmNL                           = 1701, // SystemZInstrInfo.td:670
    LOCFHRAsmNLE                          = 1702, // SystemZInstrInfo.td:670
    LOCFHRAsmNLH                          = 1703, // SystemZInstrInfo.td:670
    LOCFHRAsmNM                           = 1704, // SystemZInstrInfo.td:670
    LOCFHRAsmNO                           = 1705, // SystemZInstrInfo.td:670
    LOCFHRAsmNP                           = 1706, // SystemZInstrInfo.td:670
    LOCFHRAsmNZ                           = 1707, // SystemZInstrInfo.td:670
    LOCFHRAsmO                            = 1708, // SystemZInstrInfo.td:670
    LOCFHRAsmP                            = 1709, // SystemZInstrInfo.td:670
    LOCFHRAsmZ                            = 1710, // SystemZInstrInfo.td:670
    LOCG                                  = 1711, // SystemZInstrFormats.td:3195
    LOCGAsm                               = 1712, // SystemZInstrFormats.td:3196
    LOCGAsmE                              = 1713, // SystemZInstrInfo.td:698
    LOCGAsmH                              = 1714, // SystemZInstrInfo.td:698
    LOCGAsmHE                             = 1715, // SystemZInstrInfo.td:698
    LOCGAsmL                              = 1716, // SystemZInstrInfo.td:698
    LOCGAsmLE                             = 1717, // SystemZInstrInfo.td:698
    LOCGAsmLH                             = 1718, // SystemZInstrInfo.td:698
    LOCGAsmM                              = 1719, // SystemZInstrInfo.td:698
    LOCGAsmNE                             = 1720, // SystemZInstrInfo.td:698
    LOCGAsmNH                             = 1721, // SystemZInstrInfo.td:698
    LOCGAsmNHE                            = 1722, // SystemZInstrInfo.td:698
    LOCGAsmNL                             = 1723, // SystemZInstrInfo.td:698
    LOCGAsmNLE                            = 1724, // SystemZInstrInfo.td:698
    LOCGAsmNLH                            = 1725, // SystemZInstrInfo.td:698
    LOCGAsmNM                             = 1726, // SystemZInstrInfo.td:698
    LOCGAsmNO                             = 1727, // SystemZInstrInfo.td:698
    LOCGAsmNP                             = 1728, // SystemZInstrInfo.td:698
    LOCGAsmNZ                             = 1729, // SystemZInstrInfo.td:698
    LOCGAsmO                              = 1730, // SystemZInstrInfo.td:698
    LOCGAsmP                              = 1731, // SystemZInstrInfo.td:698
    LOCGAsmZ                              = 1732, // SystemZInstrInfo.td:698
    LOCGHI                                = 1733, // SystemZInstrFormats.td:3711
    LOCGHIAsm                             = 1734, // SystemZInstrFormats.td:3712
    LOCGHIAsmE                            = 1735, // SystemZInstrInfo.td:666
    LOCGHIAsmH                            = 1736, // SystemZInstrInfo.td:666
    LOCGHIAsmHE                           = 1737, // SystemZInstrInfo.td:666
    LOCGHIAsmL                            = 1738, // SystemZInstrInfo.td:666
    LOCGHIAsmLE                           = 1739, // SystemZInstrInfo.td:666
    LOCGHIAsmLH                           = 1740, // SystemZInstrInfo.td:666
    LOCGHIAsmM                            = 1741, // SystemZInstrInfo.td:666
    LOCGHIAsmNE                           = 1742, // SystemZInstrInfo.td:666
    LOCGHIAsmNH                           = 1743, // SystemZInstrInfo.td:666
    LOCGHIAsmNHE                          = 1744, // SystemZInstrInfo.td:666
    LOCGHIAsmNL                           = 1745, // SystemZInstrInfo.td:666
    LOCGHIAsmNLE                          = 1746, // SystemZInstrInfo.td:666
    LOCGHIAsmNLH                          = 1747, // SystemZInstrInfo.td:666
    LOCGHIAsmNM                           = 1748, // SystemZInstrInfo.td:666
    LOCGHIAsmNO                           = 1749, // SystemZInstrInfo.td:666
    LOCGHIAsmNP                           = 1750, // SystemZInstrInfo.td:666
    LOCGHIAsmNZ                           = 1751, // SystemZInstrInfo.td:666
    LOCGHIAsmO                            = 1752, // SystemZInstrInfo.td:666
    LOCGHIAsmP                            = 1753, // SystemZInstrInfo.td:666
    LOCGHIAsmZ                            = 1754, // SystemZInstrInfo.td:666
    LOCGR                                 = 1755, // SystemZInstrFormats.td:3606
    LOCGRAsm                              = 1756, // SystemZInstrFormats.td:3607
    LOCGRAsmE                             = 1757, // SystemZInstrInfo.td:696
    LOCGRAsmH                             = 1758, // SystemZInstrInfo.td:696
    LOCGRAsmHE                            = 1759, // SystemZInstrInfo.td:696
    LOCGRAsmL                             = 1760, // SystemZInstrInfo.td:696
    LOCGRAsmLE                            = 1761, // SystemZInstrInfo.td:696
    LOCGRAsmLH                            = 1762, // SystemZInstrInfo.td:696
    LOCGRAsmM                             = 1763, // SystemZInstrInfo.td:696
    LOCGRAsmNE                            = 1764, // SystemZInstrInfo.td:696
    LOCGRAsmNH                            = 1765, // SystemZInstrInfo.td:696
    LOCGRAsmNHE                           = 1766, // SystemZInstrInfo.td:696
    LOCGRAsmNL                            = 1767, // SystemZInstrInfo.td:696
    LOCGRAsmNLE                           = 1768, // SystemZInstrInfo.td:696
    LOCGRAsmNLH                           = 1769, // SystemZInstrInfo.td:696
    LOCGRAsmNM                            = 1770, // SystemZInstrInfo.td:696
    LOCGRAsmNO                            = 1771, // SystemZInstrInfo.td:696
    LOCGRAsmNP                            = 1772, // SystemZInstrInfo.td:696
    LOCGRAsmNZ                            = 1773, // SystemZInstrInfo.td:696
    LOCGRAsmO                             = 1774, // SystemZInstrInfo.td:696
    LOCGRAsmP                             = 1775, // SystemZInstrInfo.td:696
    LOCGRAsmZ                             = 1776, // SystemZInstrInfo.td:696
    LOCHHI                                = 1777, // SystemZInstrFormats.td:3711
    LOCHHIAsm                             = 1778, // SystemZInstrFormats.td:3712
    LOCHHIAsmE                            = 1779, // SystemZInstrInfo.td:668
    LOCHHIAsmH                            = 1780, // SystemZInstrInfo.td:668
    LOCHHIAsmHE                           = 1781, // SystemZInstrInfo.td:668
    LOCHHIAsmL                            = 1782, // SystemZInstrInfo.td:668
    LOCHHIAsmLE                           = 1783, // SystemZInstrInfo.td:668
    LOCHHIAsmLH                           = 1784, // SystemZInstrInfo.td:668
    LOCHHIAsmM                            = 1785, // SystemZInstrInfo.td:668
    LOCHHIAsmNE                           = 1786, // SystemZInstrInfo.td:668
    LOCHHIAsmNH                           = 1787, // SystemZInstrInfo.td:668
    LOCHHIAsmNHE                          = 1788, // SystemZInstrInfo.td:668
    LOCHHIAsmNL                           = 1789, // SystemZInstrInfo.td:668
    LOCHHIAsmNLE                          = 1790, // SystemZInstrInfo.td:668
    LOCHHIAsmNLH                          = 1791, // SystemZInstrInfo.td:668
    LOCHHIAsmNM                           = 1792, // SystemZInstrInfo.td:668
    LOCHHIAsmNO                           = 1793, // SystemZInstrInfo.td:668
    LOCHHIAsmNP                           = 1794, // SystemZInstrInfo.td:668
    LOCHHIAsmNZ                           = 1795, // SystemZInstrInfo.td:668
    LOCHHIAsmO                            = 1796, // SystemZInstrInfo.td:668
    LOCHHIAsmP                            = 1797, // SystemZInstrInfo.td:668
    LOCHHIAsmZ                            = 1798, // SystemZInstrInfo.td:668
    LOCHI                                 = 1799, // SystemZInstrFormats.td:3711
    LOCHIAsm                              = 1800, // SystemZInstrFormats.td:3712
    LOCHIAsmE                             = 1801, // SystemZInstrInfo.td:664
    LOCHIAsmH                             = 1802, // SystemZInstrInfo.td:664
    LOCHIAsmHE                            = 1803, // SystemZInstrInfo.td:664
    LOCHIAsmL                             = 1804, // SystemZInstrInfo.td:664
    LOCHIAsmLE                            = 1805, // SystemZInstrInfo.td:664
    LOCHIAsmLH                            = 1806, // SystemZInstrInfo.td:664
    LOCHIAsmM                             = 1807, // SystemZInstrInfo.td:664
    LOCHIAsmNE                            = 1808, // SystemZInstrInfo.td:664
    LOCHIAsmNH                            = 1809, // SystemZInstrInfo.td:664
    LOCHIAsmNHE                           = 1810, // SystemZInstrInfo.td:664
    LOCHIAsmNL                            = 1811, // SystemZInstrInfo.td:664
    LOCHIAsmNLE                           = 1812, // SystemZInstrInfo.td:664
    LOCHIAsmNLH                           = 1813, // SystemZInstrInfo.td:664
    LOCHIAsmNM                            = 1814, // SystemZInstrInfo.td:664
    LOCHIAsmNO                            = 1815, // SystemZInstrInfo.td:664
    LOCHIAsmNP                            = 1816, // SystemZInstrInfo.td:664
    LOCHIAsmNZ                            = 1817, // SystemZInstrInfo.td:664
    LOCHIAsmO                             = 1818, // SystemZInstrInfo.td:664
    LOCHIAsmP                             = 1819, // SystemZInstrInfo.td:664
    LOCHIAsmZ                             = 1820, // SystemZInstrInfo.td:664
    LOCR                                  = 1821, // SystemZInstrFormats.td:3606
    LOCRAsm                               = 1822, // SystemZInstrFormats.td:3607
    LOCRAsmE                              = 1823, // SystemZInstrInfo.td:695
    LOCRAsmH                              = 1824, // SystemZInstrInfo.td:695
    LOCRAsmHE                             = 1825, // SystemZInstrInfo.td:695
    LOCRAsmL                              = 1826, // SystemZInstrInfo.td:695
    LOCRAsmLE                             = 1827, // SystemZInstrInfo.td:695
    LOCRAsmLH                             = 1828, // SystemZInstrInfo.td:695
    LOCRAsmM                              = 1829, // SystemZInstrInfo.td:695
    LOCRAsmNE                             = 1830, // SystemZInstrInfo.td:695
    LOCRAsmNH                             = 1831, // SystemZInstrInfo.td:695
    LOCRAsmNHE                            = 1832, // SystemZInstrInfo.td:695
    LOCRAsmNL                             = 1833, // SystemZInstrInfo.td:695
    LOCRAsmNLE                            = 1834, // SystemZInstrInfo.td:695
    LOCRAsmNLH                            = 1835, // SystemZInstrInfo.td:695
    LOCRAsmNM                             = 1836, // SystemZInstrInfo.td:695
    LOCRAsmNO                             = 1837, // SystemZInstrInfo.td:695
    LOCRAsmNP                             = 1838, // SystemZInstrInfo.td:695
    LOCRAsmNZ                             = 1839, // SystemZInstrInfo.td:695
    LOCRAsmO                              = 1840, // SystemZInstrInfo.td:695
    LOCRAsmP                              = 1841, // SystemZInstrInfo.td:695
    LOCRAsmZ                              = 1842, // SystemZInstrInfo.td:695
    LPCTL                                 = 1843, // SystemZInstrSystem.td:466
    LPD                                   = 1844, // SystemZInstrInfo.td:1905
    LPDBR                                 = 1845, // SystemZInstrFP.td:377
    LPDFR                                 = 1846, // SystemZInstrFP.td:381
    LPDFR_16                              = 1847, // SystemZInstrFP.td:383
    LPDFR_32                              = 1848, // SystemZInstrFP.td:384
    LPDG                                  = 1849, // SystemZInstrInfo.td:1906
    LPDR                                  = 1850, // SystemZInstrHFP.td:97
    LPEBR                                 = 1851, // SystemZInstrFP.td:376
    LPER                                  = 1852, // SystemZInstrHFP.td:96
    LPGFR                                 = 1853, // SystemZInstrInfo.td:982
    LPGR                                  = 1854, // SystemZInstrInfo.td:979
    LPP                                   = 1855, // SystemZInstrSystem.td:446
    LPQ                                   = 1856, // SystemZInstrInfo.td:1900
    LPR                                   = 1857, // SystemZInstrInfo.td:978
    LPSW                                  = 1858, // SystemZInstrSystem.td:26
    LPSWE                                 = 1859, // SystemZInstrSystem.td:27
    LPSWEY                                = 1860, // SystemZInstrSystem.td:30
    LPTEA                                 = 1861, // SystemZInstrSystem.td:196
    LPXBR                                 = 1862, // SystemZInstrFP.td:378
    LPXR                                  = 1863, // SystemZInstrHFP.td:98
    LR                                    = 1864, // SystemZInstrInfo.td:435
    LRA                                   = 1865, // SystemZInstrFormats.td:3049
    LRAG                                  = 1866, // SystemZInstrSystem.td:201
    LRAY                                  = 1867, // SystemZInstrFormats.td:3051
    LRDR                                  = 1868, // SystemZInstrHFP.td:37
    LRER                                  = 1869, // SystemZInstrHFP.td:36
    LRL                                   = 1870, // SystemZInstrInfo.td:494
    LRV                                   = 1871, // SystemZInstrInfo.td:908
    LRVG                                  = 1872, // SystemZInstrInfo.td:909
    LRVGR                                 = 1873, // SystemZInstrInfo.td:904
    LRVH                                  = 1874, // SystemZInstrInfo.td:907
    LRVR                                  = 1875, // SystemZInstrInfo.td:903
    LSCTL                                 = 1876, // SystemZInstrSystem.td:470
    LT                                    = 1877, // SystemZInstrInfo.td:489
    LTDBR                                 = 1878, // SystemZInstrFP.td:66
    LTDR                                  = 1879, // SystemZInstrHFP.td:23
    LTDTR                                 = 1880, // SystemZInstrDFP.td:23
    LTEBR                                 = 1881, // SystemZInstrFP.td:65
    LTER                                  = 1882, // SystemZInstrHFP.td:22
    LTG                                   = 1883, // SystemZInstrInfo.td:490
    LTGF                                  = 1884, // SystemZInstrInfo.td:757
    LTGFR                                 = 1885, // SystemZInstrInfo.td:724
    LTGR                                  = 1886, // SystemZInstrInfo.td:441
    LTR                                   = 1887, // SystemZInstrInfo.td:440
    LTXBR                                 = 1888, // SystemZInstrFP.td:67
    LTXR                                  = 1889, // SystemZInstrHFP.td:24
    LTXTR                                 = 1890, // SystemZInstrDFP.td:24
    LURA                                  = 1891, // SystemZInstrSystem.td:209
    LURAG                                 = 1892, // SystemZInstrSystem.td:210
    LXAB                                  = 1893, // SystemZInstrFormats.td:3064
    LXAF                                  = 1894, // SystemZInstrFormats.td:3064
    LXAG                                  = 1895, // SystemZInstrFormats.td:3064
    LXAH                                  = 1896, // SystemZInstrFormats.td:3064
    LXAQ                                  = 1897, // SystemZInstrFormats.td:3064
    LXD                                   = 1898, // SystemZInstrHFP.td:47
    LXDB                                  = 1899, // SystemZInstrFP.td:240
    LXDBR                                 = 1900, // SystemZInstrFP.td:229
    LXDR                                  = 1901, // SystemZInstrHFP.td:43
    LXDTR                                 = 1902, // SystemZInstrDFP.td:42
    LXE                                   = 1903, // SystemZInstrHFP.td:46
    LXEB                                  = 1904, // SystemZInstrFP.td:239
    LXEBR                                 = 1905, // SystemZInstrFP.td:228
    LXER                                  = 1906, // SystemZInstrHFP.td:42
    LXR                                   = 1907, // SystemZInstrFP.td:50
    LY                                    = 1908, // SystemZInstrFormats.td:3242
    LZDR                                  = 1909, // SystemZInstrFP.td:42
    LZER                                  = 1910, // SystemZInstrFP.td:41
    LZER_16                               = 1911, // SystemZInstrFP.td:40
    LZRF                                  = 1912, // SystemZInstrInfo.td:500
    LZRG                                  = 1913, // SystemZInstrInfo.td:501
    LZXR                                  = 1914, // SystemZInstrFP.td:43
    M                                     = 1915, // SystemZInstrInfo.td:1523
    MAD                                   = 1916, // SystemZInstrHFP.td:195
    MADB                                  = 1917, // SystemZInstrFormats.td:5542
    MADBR                                 = 1918, // SystemZInstrFP.td:549
    MADR                                  = 1919, // SystemZInstrHFP.td:193
    MAE                                   = 1920, // SystemZInstrHFP.td:194
    MAEB                                  = 1921, // SystemZInstrFormats.td:5542
    MAEBR                                 = 1922, // SystemZInstrFP.td:548
    MAER                                  = 1923, // SystemZInstrHFP.td:192
    MAY                                   = 1924, // SystemZInstrHFP.td:226
    MAYH                                  = 1925, // SystemZInstrHFP.td:214
    MAYHR                                 = 1926, // SystemZInstrHFP.td:212
    MAYL                                  = 1927, // SystemZInstrHFP.td:215
    MAYLR                                 = 1928, // SystemZInstrHFP.td:213
    MAYR                                  = 1929, // SystemZInstrHFP.td:227
    MC                                    = 1930, // SystemZInstrSystem.td:410
    MD                                    = 1931, // SystemZInstrHFP.td:177
    MDB                                   = 1932, // SystemZInstrFormats.td:5531
    MDBR                                  = 1933, // SystemZInstrFP.td:503
    MDE                                   = 1934, // SystemZInstrHFP.td:181
    MDEB                                  = 1935, // SystemZInstrFP.td:522
    MDEBR                                 = 1936, // SystemZInstrFP.td:514
    MDER                                  = 1937, // SystemZInstrHFP.td:180
    MDR                                   = 1938, // SystemZInstrHFP.td:173
    MDTR                                  = 1939, // SystemZInstrDFP.td:169
    MDTRA                                 = 1940, // SystemZInstrDFP.td:173
    ME                                    = 1941, // SystemZInstrHFP.td:184
    MEE                                   = 1942, // SystemZInstrHFP.td:176
    MEEB                                  = 1943, // SystemZInstrFormats.td:5531
    MEEBR                                 = 1944, // SystemZInstrFP.td:502
    MEER                                  = 1945, // SystemZInstrHFP.td:172
    MER                                   = 1946, // SystemZInstrHFP.td:183
    MFY                                   = 1947, // SystemZInstrInfo.td:1524
    MG                                    = 1948, // SystemZInstrInfo.td:1525
    MGH                                   = 1949, // SystemZInstrInfo.td:1499
    MGHI                                  = 1950, // SystemZInstrInfo.td:1490
    MGRK                                  = 1951, // SystemZInstrInfo.td:1512
    MH                                    = 1952, // SystemZInstrFormats.td:3817
    MHI                                   = 1953, // SystemZInstrInfo.td:1489
    MHY                                   = 1954, // SystemZInstrFormats.td:3820
    ML                                    = 1955, // SystemZInstrInfo.td:1527
    MLG                                   = 1956, // SystemZInstrInfo.td:1528
    MLGR                                  = 1957, // SystemZInstrInfo.td:1515
    MLR                                   = 1958, // SystemZInstrInfo.td:1514
    MP                                    = 1959, // SystemZInstrInfo.td:2067
    MR                                    = 1960, // SystemZInstrInfo.td:1511
    MS                                    = 1961, // SystemZInstrFormats.td:3817
    MSC                                   = 1962, // SystemZInstrFormats.td:5502
    MSCH                                  = 1963, // SystemZInstrSystem.td:502
    MSD                                   = 1964, // SystemZInstrHFP.td:201
    MSDB                                  = 1965, // SystemZInstrFormats.td:5542
    MSDBR                                 = 1966, // SystemZInstrFP.td:558
    MSDR                                  = 1967, // SystemZInstrHFP.td:199
    MSE                                   = 1968, // SystemZInstrHFP.td:200
    MSEB                                  = 1969, // SystemZInstrFormats.td:5542
    MSEBR                                 = 1970, // SystemZInstrFP.td:557
    MSER                                  = 1971, // SystemZInstrHFP.td:198
    MSFI                                  = 1972, // SystemZInstrInfo.td:1493
    MSG                                   = 1973, // SystemZInstrInfo.td:1502
    MSGC                                  = 1974, // SystemZInstrFormats.td:5502
    MSGF                                  = 1975, // SystemZInstrInfo.td:1501
    MSGFI                                 = 1976, // SystemZInstrInfo.td:1494
    MSGFR                                 = 1977, // SystemZInstrInfo.td:1485
    MSGR                                  = 1978, // SystemZInstrInfo.td:1483
    MSGRKC                                = 1979, // SystemZInstrInfo.td:1477
    MSR                                   = 1980, // SystemZInstrInfo.td:1482
    MSRKC                                 = 1981, // SystemZInstrInfo.td:1476
    MSTA                                  = 1982, // SystemZInstrSystem.td:313
    MSY                                   = 1983, // SystemZInstrFormats.td:3820
    MVC                                   = 1984, // SystemZInstrFormats.td:5572
    MVCDK                                 = 1985, // SystemZInstrSystem.td:240
    MVCIN                                 = 1986, // SystemZInstrInfo.td:918
    MVCK                                  = 1987, // SystemZInstrSystem.td:229
    MVCL                                  = 1988, // SystemZInstrInfo.td:585
    MVCLE                                 = 1989, // SystemZInstrInfo.td:586
    MVCLU                                 = 1990, // SystemZInstrInfo.td:587
    MVCOS                                 = 1991, // SystemZInstrSystem.td:245
    MVCP                                  = 1992, // SystemZInstrSystem.td:233
    MVCRL                                 = 1993, // SystemZInstrInfo.td:599
    MVCS                                  = 1994, // SystemZInstrSystem.td:234
    MVCSK                                 = 1995, // SystemZInstrSystem.td:239
    MVGHI                                 = 1996, // SystemZInstrInfo.td:579
    MVHHI                                 = 1997, // SystemZInstrInfo.td:577
    MVHI                                  = 1998, // SystemZInstrInfo.td:578
    MVI                                   = 1999, // SystemZInstrFormats.td:2935
    MVIY                                  = 2000, // SystemZInstrFormats.td:2937
    MVN                                   = 2001, // SystemZInstrInfo.td:2046
    MVO                                   = 2002, // SystemZInstrInfo.td:2048
    MVPG                                  = 2003, // SystemZInstrSystem.td:249
    MVST                                  = 2004, // SystemZInstrFormats.td:5609
    MVZ                                   = 2005, // SystemZInstrInfo.td:2047
    MXBR                                  = 2006, // SystemZInstrFP.td:504
    MXD                                   = 2007, // SystemZInstrHFP.td:189
    MXDB                                  = 2008, // SystemZInstrFP.td:539
    MXDBR                                 = 2009, // SystemZInstrFP.td:530
    MXDR                                  = 2010, // SystemZInstrHFP.td:188
    MXR                                   = 2011, // SystemZInstrHFP.td:174
    MXTR                                  = 2012, // SystemZInstrDFP.td:170
    MXTRA                                 = 2013, // SystemZInstrDFP.td:174
    MY                                    = 2014, // SystemZInstrHFP.td:207
    MYH                                   = 2015, // SystemZInstrHFP.td:208
    MYHR                                  = 2016, // SystemZInstrHFP.td:205
    MYL                                   = 2017, // SystemZInstrHFP.td:209
    MYLR                                  = 2018, // SystemZInstrHFP.td:206
    MYR                                   = 2019, // SystemZInstrHFP.td:204
    N                                     = 2020, // SystemZInstrFormats.td:5515
    NC                                    = 2021, // SystemZInstrFormats.td:5572
    NCGRK                                 = 2022, // SystemZInstrInfo.td:1435
    NCRK                                  = 2023, // SystemZInstrInfo.td:1434
    NG                                    = 2024, // SystemZInstrFormats.td:5502
    NGR                                   = 2025, // SystemZInstrFormats.td:3524
    NGRK                                  = 2026, // SystemZInstrFormats.td:3521
    NI                                    = 2027, // SystemZInstrFormats.td:3848
    NIAI                                  = 2028, // SystemZInstrInfo.td:1810
    NIHF                                  = 2029, // SystemZInstrInfo.td:1307
    NIHH                                  = 2030, // SystemZInstrInfo.td:1293
    NIHL                                  = 2031, // SystemZInstrInfo.td:1292
    NILF                                  = 2032, // SystemZInstrInfo.td:1306
    NILH                                  = 2033, // SystemZInstrInfo.td:1291
    NILL                                  = 2034, // SystemZInstrInfo.td:1290
    NIY                                   = 2035, // SystemZInstrFormats.td:3850
    NNGRK                                 = 2036, // SystemZInstrInfo.td:1447
    NNPA                                  = 2037, // SystemZInstrInfo.td:2258
    NNRK                                  = 2038, // SystemZInstrInfo.td:1446
    NOGRK                                 = 2039, // SystemZInstrInfo.td:1453
    NOP                                   = 2040, // SystemZInstrFormats.td:2404
    NOPOpt                                = 2041, // SystemZInstrFormats.td:2409
    NOPR                                  = 2042, // SystemZInstrFormats.td:2371
    NOPROpt                               = 2043, // SystemZInstrFormats.td:2375
    NORK                                  = 2044, // SystemZInstrInfo.td:1452
    NOTGR                                 = 2045, // SystemZInstrInfo.td:1456
    NOTR                                  = 2046, // SystemZInstrInfo.td:1455
    NR                                    = 2047, // SystemZInstrFormats.td:3512
    NRK                                   = 2048, // SystemZInstrFormats.td:3509
    NTSTG                                 = 2049, // SystemZInstrInfo.td:2165
    NXGRK                                 = 2050, // SystemZInstrInfo.td:1463
    NXRK                                  = 2051, // SystemZInstrInfo.td:1462
    NY                                    = 2052, // SystemZInstrFormats.td:5522
    O                                     = 2053, // SystemZInstrFormats.td:5515
    OC                                    = 2054, // SystemZInstrFormats.td:5572
    OCGRK                                 = 2055, // SystemZInstrInfo.td:1441
    OCRK                                  = 2056, // SystemZInstrInfo.td:1440
    OG                                    = 2057, // SystemZInstrFormats.td:5502
    OGR                                   = 2058, // SystemZInstrFormats.td:3524
    OGRK                                  = 2059, // SystemZInstrFormats.td:3521
    OI                                    = 2060, // SystemZInstrFormats.td:3848
    OIHF                                  = 2061, // SystemZInstrInfo.td:1365
    OIHH                                  = 2062, // SystemZInstrInfo.td:1351
    OIHL                                  = 2063, // SystemZInstrInfo.td:1350
    OILF                                  = 2064, // SystemZInstrInfo.td:1364
    OILH                                  = 2065, // SystemZInstrInfo.td:1349
    OILL                                  = 2066, // SystemZInstrInfo.td:1348
    OIY                                   = 2067, // SystemZInstrFormats.td:3850
    OR                                    = 2068, // SystemZInstrFormats.td:3512
    ORK                                   = 2069, // SystemZInstrFormats.td:3509
    OY                                    = 2070, // SystemZInstrFormats.td:5522
    PACK                                  = 2071, // SystemZInstrInfo.td:2050
    PALB                                  = 2072, // SystemZInstrSystem.td:261
    PC                                    = 2073, // SystemZInstrSystem.td:265
    PCC                                   = 2074, // SystemZInstrInfo.td:1997
    PCKMO                                 = 2075, // SystemZInstrSystem.td:393
    PFCR                                  = 2076, // SystemZInstrInfo.td:1919
    PFD                                   = 2077, // SystemZInstrInfo.td:1800
    PFDRL                                 = 2078, // SystemZInstrInfo.td:1801
    PFMF                                  = 2079, // SystemZInstrSystem.td:152
    PFPO                                  = 2080, // SystemZInstrDFP.td:117
    PGIN                                  = 2081, // SystemZInstrSystem.td:160
    PGOUT                                 = 2082, // SystemZInstrSystem.td:161
    PKA                                   = 2083, // SystemZInstrInfo.td:2051
    PKU                                   = 2084, // SystemZInstrInfo.td:2052
    PLO                                   = 2085, // SystemZInstrInfo.td:1897
    POPCNT                                = 2086, // SystemZInstrInfo.td:2209
    POPCNTOpt                             = 2087, // SystemZInstrInfo.td:2205
    PPA                                   = 2088, // SystemZInstrInfo.td:2177
    PPNO                                  = 2089, // SystemZInstrInfo.td:2001
    PR                                    = 2090, // SystemZInstrSystem.td:269
    PRNO                                  = 2091, // SystemZInstrInfo.td:2003
    PT                                    = 2092, // SystemZInstrSystem.td:273
    PTF                                   = 2093, // SystemZInstrSystem.td:388
    PTFF                                  = 2094, // SystemZInstrSystem.td:321
    PTI                                   = 2095, // SystemZInstrSystem.td:274
    PTLB                                  = 2096, // SystemZInstrSystem.td:186
    QADTR                                 = 2097, // SystemZInstrDFP.td:190
    QAXTR                                 = 2098, // SystemZInstrDFP.td:191
    QCTRI                                 = 2099, // SystemZInstrSystem.td:478
    QPACI                                 = 2100, // SystemZInstrSystem.td:398
    QSI                                   = 2101, // SystemZInstrSystem.td:474
    RCHP                                  = 2102, // SystemZInstrSystem.td:526
    RDP                                   = 2103, // SystemZInstrFormats.td:5014
    RDPOpt                                = 2104, // SystemZInstrFormats.td:5015
    RISBG                                 = 2105, // SystemZInstrFormats.td:5078
    RISBG32                               = 2106, // SystemZInstrFormats.td:5078
    RISBG32Opt                            = 2107, // SystemZInstrFormats.td:5083
    RISBGN                                = 2108, // SystemZInstrFormats.td:5078
    RISBGNOpt                             = 2109, // SystemZInstrFormats.td:5083
    RISBGNZ                               = 2110, // SystemZInstrFormats.td:5078
    RISBGNZOpt                            = 2111, // SystemZInstrFormats.td:5083
    RISBGOpt                              = 2112, // SystemZInstrFormats.td:5083
    RISBGZ                                = 2113, // SystemZInstrFormats.td:5078
    RISBGZOpt                             = 2114, // SystemZInstrFormats.td:5083
    RISBHG                                = 2115, // SystemZInstrFormats.td:5078
    RISBHGOpt                             = 2116, // SystemZInstrFormats.td:5083
    RISBLG                                = 2117, // SystemZInstrFormats.td:5078
    RISBLGOpt                             = 2118, // SystemZInstrFormats.td:5083
    RLL                                   = 2119, // SystemZInstrInfo.td:1603
    RLLG                                  = 2120, // SystemZInstrInfo.td:1604
    RNSBG                                 = 2121, // SystemZInstrFormats.td:5078
    RNSBGOpt                              = 2122, // SystemZInstrFormats.td:5083
    ROSBG                                 = 2123, // SystemZInstrFormats.td:5078
    ROSBGOpt                              = 2124, // SystemZInstrFormats.td:5083
    RP                                    = 2125, // SystemZInstrSystem.td:279
    RRBE                                  = 2126, // SystemZInstrSystem.td:140
    RRBM                                  = 2127, // SystemZInstrSystem.td:144
    RRDTR                                 = 2128, // SystemZInstrDFP.td:196
    RRXTR                                 = 2129, // SystemZInstrDFP.td:197
    RSCH                                  = 2130, // SystemZInstrSystem.td:506
    RXSBG                                 = 2131, // SystemZInstrFormats.td:5078
    RXSBGOpt                              = 2132, // SystemZInstrFormats.td:5083
    S                                     = 2133, // SystemZInstrFormats.td:5515
    SAC                                   = 2134, // SystemZInstrSystem.td:56
    SACF                                  = 2135, // SystemZInstrSystem.td:57
    SAL                                   = 2136, // SystemZInstrSystem.td:550
    SAM24                                 = 2137, // SystemZInstrInfo.td:2128
    SAM31                                 = 2138, // SystemZInstrInfo.td:2129
    SAM64                                 = 2139, // SystemZInstrInfo.td:2130
    SAR                                   = 2140, // SystemZInstrInfo.td:2090
    SCCTR                                 = 2141, // SystemZInstrSystem.td:482
    SCHM                                  = 2142, // SystemZInstrSystem.td:530
    SCK                                   = 2143, // SystemZInstrSystem.td:325
    SCKC                                  = 2144, // SystemZInstrSystem.td:333
    SCKPF                                 = 2145, // SystemZInstrSystem.td:329
    SD                                    = 2146, // SystemZInstrHFP.td:158
    SDB                                   = 2147, // SystemZInstrFormats.td:5531
    SDBR                                  = 2148, // SystemZInstrFP.td:490
    SDR                                   = 2149, // SystemZInstrHFP.td:154
    SDTR                                  = 2150, // SystemZInstrDFP.td:158
    SDTRA                                 = 2151, // SystemZInstrDFP.td:161
    SE                                    = 2152, // SystemZInstrHFP.td:157
    SEB                                   = 2153, // SystemZInstrFormats.td:5531
    SEBR                                  = 2154, // SystemZInstrFP.td:489
    SELFHR                                = 2155, // SystemZInstrFormats.td:3646
    SELFHRAsm                             = 2156, // SystemZInstrFormats.td:3647
    SELFHRAsmE                            = 2157, // SystemZInstrInfo.td:625
    SELFHRAsmH                            = 2158, // SystemZInstrInfo.td:625
    SELFHRAsmHE                           = 2159, // SystemZInstrInfo.td:625
    SELFHRAsmL                            = 2160, // SystemZInstrInfo.td:625
    SELFHRAsmLE                           = 2161, // SystemZInstrInfo.td:625
    SELFHRAsmLH                           = 2162, // SystemZInstrInfo.td:625
    SELFHRAsmM                            = 2163, // SystemZInstrInfo.td:625
    SELFHRAsmNE                           = 2164, // SystemZInstrInfo.td:625
    SELFHRAsmNH                           = 2165, // SystemZInstrInfo.td:625
    SELFHRAsmNHE                          = 2166, // SystemZInstrInfo.td:625
    SELFHRAsmNL                           = 2167, // SystemZInstrInfo.td:625
    SELFHRAsmNLE                          = 2168, // SystemZInstrInfo.td:625
    SELFHRAsmNLH                          = 2169, // SystemZInstrInfo.td:625
    SELFHRAsmNM                           = 2170, // SystemZInstrInfo.td:625
    SELFHRAsmNO                           = 2171, // SystemZInstrInfo.td:625
    SELFHRAsmNP                           = 2172, // SystemZInstrInfo.td:625
    SELFHRAsmNZ                           = 2173, // SystemZInstrInfo.td:625
    SELFHRAsmO                            = 2174, // SystemZInstrInfo.td:625
    SELFHRAsmP                            = 2175, // SystemZInstrInfo.td:625
    SELFHRAsmZ                            = 2176, // SystemZInstrInfo.td:625
    SELGR                                 = 2177, // SystemZInstrFormats.td:3646
    SELGRAsm                              = 2178, // SystemZInstrFormats.td:3647
    SELGRAsmE                             = 2179, // SystemZInstrInfo.td:627
    SELGRAsmH                             = 2180, // SystemZInstrInfo.td:627
    SELGRAsmHE                            = 2181, // SystemZInstrInfo.td:627
    SELGRAsmL                             = 2182, // SystemZInstrInfo.td:627
    SELGRAsmLE                            = 2183, // SystemZInstrInfo.td:627
    SELGRAsmLH                            = 2184, // SystemZInstrInfo.td:627
    SELGRAsmM                             = 2185, // SystemZInstrInfo.td:627
    SELGRAsmNE                            = 2186, // SystemZInstrInfo.td:627
    SELGRAsmNH                            = 2187, // SystemZInstrInfo.td:627
    SELGRAsmNHE                           = 2188, // SystemZInstrInfo.td:627
    SELGRAsmNL                            = 2189, // SystemZInstrInfo.td:627
    SELGRAsmNLE                           = 2190, // SystemZInstrInfo.td:627
    SELGRAsmNLH                           = 2191, // SystemZInstrInfo.td:627
    SELGRAsmNM                            = 2192, // SystemZInstrInfo.td:627
    SELGRAsmNO                            = 2193, // SystemZInstrInfo.td:627
    SELGRAsmNP                            = 2194, // SystemZInstrInfo.td:627
    SELGRAsmNZ                            = 2195, // SystemZInstrInfo.td:627
    SELGRAsmO                             = 2196, // SystemZInstrInfo.td:627
    SELGRAsmP                             = 2197, // SystemZInstrInfo.td:627
    SELGRAsmZ                             = 2198, // SystemZInstrInfo.td:627
    SELR                                  = 2199, // SystemZInstrFormats.td:3646
    SELRAsm                               = 2200, // SystemZInstrFormats.td:3647
    SELRAsmE                              = 2201, // SystemZInstrInfo.td:623
    SELRAsmH                              = 2202, // SystemZInstrInfo.td:623
    SELRAsmHE                             = 2203, // SystemZInstrInfo.td:623
    SELRAsmL                              = 2204, // SystemZInstrInfo.td:623
    SELRAsmLE                             = 2205, // SystemZInstrInfo.td:623
    SELRAsmLH                             = 2206, // SystemZInstrInfo.td:623
    SELRAsmM                              = 2207, // SystemZInstrInfo.td:623
    SELRAsmNE                             = 2208, // SystemZInstrInfo.td:623
    SELRAsmNH                             = 2209, // SystemZInstrInfo.td:623
    SELRAsmNHE                            = 2210, // SystemZInstrInfo.td:623
    SELRAsmNL                             = 2211, // SystemZInstrInfo.td:623
    SELRAsmNLE                            = 2212, // SystemZInstrInfo.td:623
    SELRAsmNLH                            = 2213, // SystemZInstrInfo.td:623
    SELRAsmNM                             = 2214, // SystemZInstrInfo.td:623
    SELRAsmNO                             = 2215, // SystemZInstrInfo.td:623
    SELRAsmNP                             = 2216, // SystemZInstrInfo.td:623
    SELRAsmNZ                             = 2217, // SystemZInstrInfo.td:623
    SELRAsmO                              = 2218, // SystemZInstrInfo.td:623
    SELRAsmP                              = 2219, // SystemZInstrInfo.td:623
    SELRAsmZ                              = 2220, // SystemZInstrInfo.td:623
    SER                                   = 2221, // SystemZInstrHFP.td:153
    SFASR                                 = 2222, // SystemZInstrFP.td:626
    SFPC                                  = 2223, // SystemZInstrFP.td:620
    SG                                    = 2224, // SystemZInstrFormats.td:5502
    SGF                                   = 2225, // SystemZInstrInfo.td:1189
    SGFR                                  = 2226, // SystemZInstrInfo.td:1175
    SGH                                   = 2227, // SystemZInstrInfo.td:1187
    SGR                                   = 2228, // SystemZInstrFormats.td:3524
    SGRK                                  = 2229, // SystemZInstrFormats.td:3521
    SH                                    = 2230, // SystemZInstrFormats.td:3817
    SHHHR                                 = 2231, // SystemZInstrInfo.td:1179
    SHHLR                                 = 2232, // SystemZInstrInfo.td:1181
    SHY                                   = 2233, // SystemZInstrFormats.td:3820
    SIE                                   = 2234, // SystemZInstrSystem.td:438
    SIGA                                  = 2235, // SystemZInstrSystem.td:434
    SIGP                                  = 2236, // SystemZInstrSystem.td:430
    SL                                    = 2237, // SystemZInstrFormats.td:5515
    SLA                                   = 2238, // SystemZInstrFormats.td:3746
    SLAG                                  = 2239, // SystemZInstrInfo.td:1586
    SLAK                                  = 2240, // SystemZInstrFormats.td:3743
    SLB                                   = 2241, // SystemZInstrInfo.td:1265
    SLBG                                  = 2242, // SystemZInstrInfo.td:1266
    SLBGR                                 = 2243, // SystemZInstrInfo.td:1262
    SLBR                                  = 2244, // SystemZInstrInfo.td:1261
    SLDA                                  = 2245, // SystemZInstrInfo.td:1587
    SLDL                                  = 2246, // SystemZInstrInfo.td:1581
    SLDT                                  = 2247, // SystemZInstrDFP.td:201
    SLFI                                  = 2248, // SystemZInstrInfo.td:1234
    SLG                                   = 2249, // SystemZInstrFormats.td:5502
    SLGF                                  = 2250, // SystemZInstrInfo.td:1239
    SLGFI                                 = 2251, // SystemZInstrInfo.td:1235
    SLGFR                                 = 2252, // SystemZInstrInfo.td:1224
    SLGR                                  = 2253, // SystemZInstrFormats.td:3524
    SLGRK                                 = 2254, // SystemZInstrFormats.td:3521
    SLHHHR                                = 2255, // SystemZInstrInfo.td:1228
    SLHHLR                                = 2256, // SystemZInstrInfo.td:1230
    SLL                                   = 2257, // SystemZInstrFormats.td:3746
    SLLG                                  = 2258, // SystemZInstrInfo.td:1580
    SLLK                                  = 2259, // SystemZInstrFormats.td:3743
    SLR                                   = 2260, // SystemZInstrFormats.td:3512
    SLRK                                  = 2261, // SystemZInstrFormats.td:3509
    SLXT                                  = 2262, // SystemZInstrDFP.td:202
    SLY                                   = 2263, // SystemZInstrFormats.td:5522
    SORTL                                 = 2264, // SystemZInstrInfo.td:2247
    SP                                    = 2265, // SystemZInstrInfo.td:2063
    SPCTR                                 = 2266, // SystemZInstrSystem.td:486
    SPKA                                  = 2267, // SystemZInstrSystem.td:38
    SPM                                   = 2268, // SystemZInstrInfo.td:2114
    SPT                                   = 2269, // SystemZInstrSystem.td:337
    SPX                                   = 2270, // SystemZInstrSystem.td:102
    SQD                                   = 2271, // SystemZInstrHFP.td:118
    SQDB                                  = 2272, // SystemZInstrFP.td:407
    SQDBR                                 = 2273, // SystemZInstrFP.td:403
    SQDR                                  = 2274, // SystemZInstrHFP.td:114
    SQE                                   = 2275, // SystemZInstrHFP.td:117
    SQEB                                  = 2276, // SystemZInstrFP.td:406
    SQEBR                                 = 2277, // SystemZInstrFP.td:402
    SQER                                  = 2278, // SystemZInstrHFP.td:113
    SQXBR                                 = 2279, // SystemZInstrFP.td:404
    SQXR                                  = 2280, // SystemZInstrHFP.td:115
    SR                                    = 2281, // SystemZInstrFormats.td:3512
    SRA                                   = 2282, // SystemZInstrFormats.td:3746
    SRAG                                  = 2283, // SystemZInstrInfo.td:1598
    SRAK                                  = 2284, // SystemZInstrFormats.td:3743
    SRDA                                  = 2285, // SystemZInstrInfo.td:1599
    SRDL                                  = 2286, // SystemZInstrInfo.td:1593
    SRDT                                  = 2287, // SystemZInstrDFP.td:203
    SRK                                   = 2288, // SystemZInstrFormats.td:3509
    SRL                                   = 2289, // SystemZInstrFormats.td:3746
    SRLG                                  = 2290, // SystemZInstrInfo.td:1592
    SRLK                                  = 2291, // SystemZInstrFormats.td:3743
    SRNM                                  = 2292, // SystemZInstrFP.td:633
    SRNMB                                 = 2293, // SystemZInstrFP.td:631
    SRNMT                                 = 2294, // SystemZInstrFP.td:634
    SRP                                   = 2295, // SystemZInstrInfo.td:2065
    SRST                                  = 2296, // SystemZInstrFormats.td:5609
    SRSTU                                 = 2297, // SystemZInstrInfo.td:2221
    SRXT                                  = 2298, // SystemZInstrDFP.td:204
    SSAIR                                 = 2299, // SystemZInstrSystem.td:89
    SSAR                                  = 2300, // SystemZInstrSystem.td:88
    SSCH                                  = 2301, // SystemZInstrSystem.td:510
    SSKE                                  = 2302, // SystemZInstrFormats.td:4500
    SSKEOpt                               = 2303, // SystemZInstrFormats.td:4501
    SSM                                   = 2304, // SystemZInstrSystem.td:42
    ST                                    = 2305, // SystemZInstrFormats.td:2795
    STAM                                  = 2306, // SystemZInstrFormats.td:2882
    STAMY                                 = 2307, // SystemZInstrFormats.td:2884
    STAP                                  = 2308, // SystemZInstrSystem.td:360
    STBEAR                                = 2309, // SystemZInstrSystem.td:119
    STC                                   = 2310, // SystemZInstrFormats.td:2795
    STCH                                  = 2311, // SystemZInstrInfo.td:860
    STCK                                  = 2312, // SystemZInstrSystem.td:341
    STCKC                                 = 2313, // SystemZInstrSystem.td:348
    STCKE                                 = 2314, // SystemZInstrSystem.td:343
    STCKF                                 = 2315, // SystemZInstrSystem.td:342
    STCM                                  = 2316, // SystemZInstrFormats.td:4144
    STCMH                                 = 2317, // SystemZInstrInfo.td:881
    STCMY                                 = 2318, // SystemZInstrFormats.td:4146
    STCPS                                 = 2319, // SystemZInstrSystem.td:534
    STCRW                                 = 2320, // SystemZInstrSystem.td:538
    STCTG                                 = 2321, // SystemZInstrSystem.td:71
    STCTL                                 = 2322, // SystemZInstrSystem.td:70
    STCY                                  = 2323, // SystemZInstrFormats.td:2797
    STD                                   = 2324, // SystemZInstrFormats.td:2795
    STDY                                  = 2325, // SystemZInstrFormats.td:2797
    STE                                   = 2326, // SystemZInstrFormats.td:2795
    STE16                                 = 2327, // SystemZInstrFormats.td:2795
    STE16Y                                = 2328, // SystemZInstrFormats.td:2797
    STEY                                  = 2329, // SystemZInstrFormats.td:2797
    STFH                                  = 2330, // SystemZInstrInfo.td:521
    STFL                                  = 2331, // SystemZInstrSystem.td:372
    STFLE                                 = 2332, // SystemZInstrSystem.td:376
    STFPC                                 = 2333, // SystemZInstrFP.td:616
    STG                                   = 2334, // SystemZInstrInfo.td:523
    STGRL                                 = 2335, // SystemZInstrInfo.td:571
    STGSC                                 = 2336, // SystemZInstrInfo.td:2032
    STH                                   = 2337, // SystemZInstrFormats.td:2795
    STHH                                  = 2338, // SystemZInstrInfo.td:868
    STHRL                                 = 2339, // SystemZInstrInfo.td:870
    STHY                                  = 2340, // SystemZInstrFormats.td:2797
    STIDP                                 = 2341, // SystemZInstrSystem.td:364
    STM                                   = 2342, // SystemZInstrFormats.td:2882
    STMG                                  = 2343, // SystemZInstrInfo.td:895
    STMH                                  = 2344, // SystemZInstrInfo.td:896
    STMY                                  = 2345, // SystemZInstrFormats.td:2884
    STNSM                                 = 2346, // SystemZInstrSystem.td:46
    STOC                                  = 2347, // SystemZInstrFormats.td:2987
    STOCAsm                               = 2348, // SystemZInstrFormats.td:2988
    STOCAsmE                              = 2349, // SystemZInstrInfo.td:699
    STOCAsmH                              = 2350, // SystemZInstrInfo.td:699
    STOCAsmHE                             = 2351, // SystemZInstrInfo.td:699
    STOCAsmL                              = 2352, // SystemZInstrInfo.td:699
    STOCAsmLE                             = 2353, // SystemZInstrInfo.td:699
    STOCAsmLH                             = 2354, // SystemZInstrInfo.td:699
    STOCAsmM                              = 2355, // SystemZInstrInfo.td:699
    STOCAsmNE                             = 2356, // SystemZInstrInfo.td:699
    STOCAsmNH                             = 2357, // SystemZInstrInfo.td:699
    STOCAsmNHE                            = 2358, // SystemZInstrInfo.td:699
    STOCAsmNL                             = 2359, // SystemZInstrInfo.td:699
    STOCAsmNLE                            = 2360, // SystemZInstrInfo.td:699
    STOCAsmNLH                            = 2361, // SystemZInstrInfo.td:699
    STOCAsmNM                             = 2362, // SystemZInstrInfo.td:699
    STOCAsmNO                             = 2363, // SystemZInstrInfo.td:699
    STOCAsmNP                             = 2364, // SystemZInstrInfo.td:699
    STOCAsmNZ                             = 2365, // SystemZInstrInfo.td:699
    STOCAsmO                              = 2366, // SystemZInstrInfo.td:699
    STOCAsmP                              = 2367, // SystemZInstrInfo.td:699
    STOCAsmZ                              = 2368, // SystemZInstrInfo.td:699
    STOCFH                                = 2369, // SystemZInstrFormats.td:2987
    STOCFHAsm                             = 2370, // SystemZInstrFormats.td:2988
    STOCFHAsmE                            = 2371, // SystemZInstrInfo.td:672
    STOCFHAsmH                            = 2372, // SystemZInstrInfo.td:672
    STOCFHAsmHE                           = 2373, // SystemZInstrInfo.td:672
    STOCFHAsmL                            = 2374, // SystemZInstrInfo.td:672
    STOCFHAsmLE                           = 2375, // SystemZInstrInfo.td:672
    STOCFHAsmLH                           = 2376, // SystemZInstrInfo.td:672
    STOCFHAsmM                            = 2377, // SystemZInstrInfo.td:672
    STOCFHAsmNE                           = 2378, // SystemZInstrInfo.td:672
    STOCFHAsmNH                           = 2379, // SystemZInstrInfo.td:672
    STOCFHAsmNHE                          = 2380, // SystemZInstrInfo.td:672
    STOCFHAsmNL                           = 2381, // SystemZInstrInfo.td:672
    STOCFHAsmNLE                          = 2382, // SystemZInstrInfo.td:672
    STOCFHAsmNLH                          = 2383, // SystemZInstrInfo.td:672
    STOCFHAsmNM                           = 2384, // SystemZInstrInfo.td:672
    STOCFHAsmNO                           = 2385, // SystemZInstrInfo.td:672
    STOCFHAsmNP                           = 2386, // SystemZInstrInfo.td:672
    STOCFHAsmNZ                           = 2387, // SystemZInstrInfo.td:672
    STOCFHAsmO                            = 2388, // SystemZInstrInfo.td:672
    STOCFHAsmP                            = 2389, // SystemZInstrInfo.td:672
    STOCFHAsmZ                            = 2390, // SystemZInstrInfo.td:672
    STOCG                                 = 2391, // SystemZInstrFormats.td:2987
    STOCGAsm                              = 2392, // SystemZInstrFormats.td:2988
    STOCGAsmE                             = 2393, // SystemZInstrInfo.td:700
    STOCGAsmH                             = 2394, // SystemZInstrInfo.td:700
    STOCGAsmHE                            = 2395, // SystemZInstrInfo.td:700
    STOCGAsmL                             = 2396, // SystemZInstrInfo.td:700
    STOCGAsmLE                            = 2397, // SystemZInstrInfo.td:700
    STOCGAsmLH                            = 2398, // SystemZInstrInfo.td:700
    STOCGAsmM                             = 2399, // SystemZInstrInfo.td:700
    STOCGAsmNE                            = 2400, // SystemZInstrInfo.td:700
    STOCGAsmNH                            = 2401, // SystemZInstrInfo.td:700
    STOCGAsmNHE                           = 2402, // SystemZInstrInfo.td:700
    STOCGAsmNL                            = 2403, // SystemZInstrInfo.td:700
    STOCGAsmNLE                           = 2404, // SystemZInstrInfo.td:700
    STOCGAsmNLH                           = 2405, // SystemZInstrInfo.td:700
    STOCGAsmNM                            = 2406, // SystemZInstrInfo.td:700
    STOCGAsmNO                            = 2407, // SystemZInstrInfo.td:700
    STOCGAsmNP                            = 2408, // SystemZInstrInfo.td:700
    STOCGAsmNZ                            = 2409, // SystemZInstrInfo.td:700
    STOCGAsmO                             = 2410, // SystemZInstrInfo.td:700
    STOCGAsmP                             = 2411, // SystemZInstrInfo.td:700
    STOCGAsmZ                             = 2412, // SystemZInstrInfo.td:700
    STOSM                                 = 2413, // SystemZInstrSystem.td:47
    STPQ                                  = 2414, // SystemZInstrInfo.td:1901
    STPT                                  = 2415, // SystemZInstrSystem.td:352
    STPX                                  = 2416, // SystemZInstrSystem.td:106
    STRAG                                 = 2417, // SystemZInstrSystem.td:205
    STRL                                  = 2418, // SystemZInstrInfo.td:570
    STRV                                  = 2419, // SystemZInstrInfo.td:913
    STRVG                                 = 2420, // SystemZInstrInfo.td:914
    STRVH                                 = 2421, // SystemZInstrInfo.td:912
    STSCH                                 = 2422, // SystemZInstrSystem.td:514
    STSI                                  = 2423, // SystemZInstrSystem.td:368
    STURA                                 = 2424, // SystemZInstrSystem.td:215
    STURG                                 = 2425, // SystemZInstrSystem.td:216
    STY                                   = 2426, // SystemZInstrFormats.td:2797
    SU                                    = 2427, // SystemZInstrHFP.td:166
    SUR                                   = 2428, // SystemZInstrHFP.td:163
    SVC                                   = 2429, // SystemZInstrSystem.td:406
    SW                                    = 2430, // SystemZInstrHFP.td:167
    SWR                                   = 2431, // SystemZInstrHFP.td:164
    SXBR                                  = 2432, // SystemZInstrFP.td:491
    SXR                                   = 2433, // SystemZInstrHFP.td:155
    SXTR                                  = 2434, // SystemZInstrDFP.td:159
    SXTRA                                 = 2435, // SystemZInstrDFP.td:162
    SY                                    = 2436, // SystemZInstrFormats.td:5522
    TABORT                                = 2437, // SystemZInstrInfo.td:2162
    TAM                                   = 2438, // SystemZInstrInfo.td:2124
    TAR                                   = 2439, // SystemZInstrSystem.td:291
    TB                                    = 2440, // SystemZInstrSystem.td:156
    TBDR                                  = 2441, // SystemZInstrHFP.td:79
    TBEDR                                 = 2442, // SystemZInstrHFP.td:78
    TBEGIN                                = 2443, // SystemZInstrInfo.td:2148
    TBEGINC                               = 2444, // SystemZInstrInfo.td:2151
    TCDB                                  = 2445, // SystemZInstrFP.td:603
    TCEB                                  = 2446, // SystemZInstrFP.td:602
    TCXB                                  = 2447, // SystemZInstrFP.td:604
    TDCDT                                 = 2448, // SystemZInstrDFP.td:236
    TDCET                                 = 2449, // SystemZInstrDFP.td:235
    TDCXT                                 = 2450, // SystemZInstrDFP.td:237
    TDGDT                                 = 2451, // SystemZInstrDFP.td:243
    TDGET                                 = 2452, // SystemZInstrDFP.td:242
    TDGXT                                 = 2453, // SystemZInstrDFP.td:244
    TEND                                  = 2454, // SystemZInstrInfo.td:2157
    THDER                                 = 2455, // SystemZInstrHFP.td:72
    THDR                                  = 2456, // SystemZInstrHFP.td:73
    TM                                    = 2457, // SystemZInstrFormats.td:4366
    TMHH                                  = 2458, // SystemZInstrInfo.td:1776
    TMHL                                  = 2459, // SystemZInstrInfo.td:1775
    TMLH                                  = 2460, // SystemZInstrInfo.td:1774
    TMLL                                  = 2461, // SystemZInstrInfo.td:1773
    TMY                                   = 2462, // SystemZInstrFormats.td:4368
    TP                                    = 2463, // SystemZInstrInfo.td:2077
    TPEI                                  = 2464, // SystemZInstrSystem.td:546
    TPI                                   = 2465, // SystemZInstrSystem.td:542
    TPROT                                 = 2466, // SystemZInstrSystem.td:221
    TR                                    = 2467, // SystemZInstrInfo.td:1927
    TRACE                                 = 2468, // SystemZInstrSystem.td:418
    TRACG                                 = 2469, // SystemZInstrSystem.td:419
    TRAP2                                 = 2470, // SystemZInstrSystem.td:424
    TRAP4                                 = 2471, // SystemZInstrSystem.td:425
    TRE                                   = 2472, // SystemZInstrInfo.td:1935
    TROO                                  = 2473, // SystemZInstrFormats.td:4516
    TROOOpt                               = 2474, // SystemZInstrFormats.td:4517
    TROT                                  = 2475, // SystemZInstrFormats.td:4516
    TROTOpt                               = 2476, // SystemZInstrFormats.td:4517
    TRT                                   = 2477, // SystemZInstrInfo.td:1930
    TRTE                                  = 2478, // SystemZInstrFormats.td:3551
    TRTEOpt                               = 2479, // SystemZInstrFormats.td:3552
    TRTO                                  = 2480, // SystemZInstrFormats.td:4516
    TRTOOpt                               = 2481, // SystemZInstrFormats.td:4517
    TRTR                                  = 2482, // SystemZInstrInfo.td:1931
    TRTRE                                 = 2483, // SystemZInstrFormats.td:3551
    TRTREOpt                              = 2484, // SystemZInstrFormats.td:3552
    TRTT                                  = 2485, // SystemZInstrFormats.td:4516
    TRTTOpt                               = 2486, // SystemZInstrFormats.td:4517
    TS                                    = 2487, // SystemZInstrInfo.td:1877
    TSCH                                  = 2488, // SystemZInstrSystem.td:518
    UNPK                                  = 2489, // SystemZInstrInfo.td:2053
    UNPKA                                 = 2490, // SystemZInstrInfo.td:2055
    UNPKU                                 = 2491, // SystemZInstrInfo.td:2056
    UPT                                   = 2492, // SystemZInstrInfo.td:2234
    VA                                    = 2493, // SystemZInstrVector.td:577
    VAB                                   = 2494, // SystemZInstrVector.td:578
    VAC                                   = 2495, // SystemZInstrVector.td:595
    VACC                                  = 2496, // SystemZInstrVector.td:587
    VACCB                                 = 2497, // SystemZInstrVector.td:588
    VACCC                                 = 2498, // SystemZInstrVector.td:599
    VACCCQ                                = 2499, // SystemZInstrVector.td:600
    VACCF                                 = 2500, // SystemZInstrVector.td:590
    VACCG                                 = 2501, // SystemZInstrVector.td:591
    VACCH                                 = 2502, // SystemZInstrVector.td:589
    VACCQ                                 = 2503, // SystemZInstrVector.td:592
    VACQ                                  = 2504, // SystemZInstrVector.td:596
    VAF                                   = 2505, // SystemZInstrVector.td:580
    VAG                                   = 2506, // SystemZInstrVector.td:581
    VAH                                   = 2507, // SystemZInstrVector.td:579
    VAP                                   = 2508, // SystemZInstrVector.td:2472
    VAQ                                   = 2509, // SystemZInstrVector.td:582
    VAVG                                  = 2510, // SystemZInstrVector.td:612
    VAVGB                                 = 2511, // SystemZInstrVector.td:613
    VAVGF                                 = 2512, // SystemZInstrVector.td:615
    VAVGG                                 = 2513, // SystemZInstrVector.td:616
    VAVGH                                 = 2514, // SystemZInstrVector.td:614
    VAVGL                                 = 2515, // SystemZInstrVector.td:621
    VAVGLB                                = 2516, // SystemZInstrVector.td:622
    VAVGLF                                = 2517, // SystemZInstrVector.td:624
    VAVGLG                                = 2518, // SystemZInstrVector.td:625
    VAVGLH                                = 2519, // SystemZInstrVector.td:623
    VAVGLQ                                = 2520, // SystemZInstrVector.td:627
    VAVGQ                                 = 2521, // SystemZInstrVector.td:618
    VBLEND                                = 2522, // SystemZInstrVector.td:429
    VBLENDB                               = 2523, // SystemZInstrVector.td:430
    VBLENDF                               = 2524, // SystemZInstrVector.td:432
    VBLENDG                               = 2525, // SystemZInstrVector.td:433
    VBLENDH                               = 2526, // SystemZInstrVector.td:431
    VBLENDQ                               = 2527, // SystemZInstrVector.td:434
    VBPERM                                = 2528, // SystemZInstrVector.td:409
    VCDG                                  = 2529, // SystemZInstrVector.td:1479
    VCDGB                                 = 2530, // SystemZInstrVector.td:1480
    VCDLG                                 = 2531, // SystemZInstrVector.td:1496
    VCDLGB                                = 2532, // SystemZInstrVector.td:1497
    VCEFB                                 = 2533, // SystemZInstrVector.td:1488
    VCELFB                                = 2534, // SystemZInstrVector.td:1505
    VCEQ                                  = 2535, // SystemZInstrVector.td:1400
    VCEQB                                 = 2536, // SystemZInstrFormats.td:3951
    VCEQBS                                = 2537, // SystemZInstrFormats.td:3954
    VCEQF                                 = 2538, // SystemZInstrFormats.td:3951
    VCEQFS                                = 2539, // SystemZInstrFormats.td:3954
    VCEQG                                 = 2540, // SystemZInstrFormats.td:3951
    VCEQGS                                = 2541, // SystemZInstrFormats.td:3954
    VCEQH                                 = 2542, // SystemZInstrFormats.td:3951
    VCEQHS                                = 2543, // SystemZInstrFormats.td:3954
    VCEQQ                                 = 2544, // SystemZInstrFormats.td:3951
    VCEQQS                                = 2545, // SystemZInstrFormats.td:3954
    VCFEB                                 = 2546, // SystemZInstrVector.td:1523
    VCFN                                  = 2547, // SystemZInstrVector.td:2427
    VCFPL                                 = 2548, // SystemZInstrVector.td:1504
    VCFPS                                 = 2549, // SystemZInstrVector.td:1487
    VCGD                                  = 2550, // SystemZInstrVector.td:1513
    VCGDB                                 = 2551, // SystemZInstrVector.td:1514
    VCH                                   = 2552, // SystemZInstrVector.td:1414
    VCHB                                  = 2553, // SystemZInstrFormats.td:3951
    VCHBS                                 = 2554, // SystemZInstrFormats.td:3954
    VCHF                                  = 2555, // SystemZInstrFormats.td:3951
    VCHFS                                 = 2556, // SystemZInstrFormats.td:3954
    VCHG                                  = 2557, // SystemZInstrFormats.td:3951
    VCHGS                                 = 2558, // SystemZInstrFormats.td:3954
    VCHH                                  = 2559, // SystemZInstrFormats.td:3951
    VCHHS                                 = 2560, // SystemZInstrFormats.td:3954
    VCHL                                  = 2561, // SystemZInstrVector.td:1428
    VCHLB                                 = 2562, // SystemZInstrFormats.td:3951
    VCHLBS                                = 2563, // SystemZInstrFormats.td:3954
    VCHLF                                 = 2564, // SystemZInstrFormats.td:3951
    VCHLFS                                = 2565, // SystemZInstrFormats.td:3954
    VCHLG                                 = 2566, // SystemZInstrFormats.td:3951
    VCHLGS                                = 2567, // SystemZInstrFormats.td:3954
    VCHLH                                 = 2568, // SystemZInstrFormats.td:3951
    VCHLHS                                = 2569, // SystemZInstrFormats.td:3954
    VCHLQ                                 = 2570, // SystemZInstrFormats.td:3951
    VCHLQS                                = 2571, // SystemZInstrFormats.td:3954
    VCHQ                                  = 2572, // SystemZInstrFormats.td:3951
    VCHQS                                 = 2573, // SystemZInstrFormats.td:3954
    VCKSM                                 = 2574, // SystemZInstrVector.td:631
    VCLFEB                                = 2575, // SystemZInstrVector.td:1542
    VCLFNH                                = 2576, // SystemZInstrVector.td:2437
    VCLFNL                                = 2577, // SystemZInstrVector.td:2432
    VCLFP                                 = 2578, // SystemZInstrVector.td:1541
    VCLGD                                 = 2579, // SystemZInstrVector.td:1532
    VCLGDB                                = 2580, // SystemZInstrVector.td:1533
    VCLZ                                  = 2581, // SystemZInstrVector.td:634
    VCLZB                                 = 2582, // SystemZInstrVector.td:635
    VCLZDP                                = 2583, // SystemZInstrVector.td:2501
    VCLZF                                 = 2584, // SystemZInstrVector.td:637
    VCLZG                                 = 2585, // SystemZInstrVector.td:638
    VCLZH                                 = 2586, // SystemZInstrVector.td:636
    VCLZQ                                 = 2587, // SystemZInstrVector.td:640
    VCNF                                  = 2588, // SystemZInstrVector.td:2442
    VCP                                   = 2589, // SystemZInstrVector.td:2486
    VCRNF                                 = 2590, // SystemZInstrVector.td:2447
    VCSFP                                 = 2591, // SystemZInstrVector.td:1522
    VCSPH                                 = 2592, // SystemZInstrVector.td:2498
    VCTZ                                  = 2593, // SystemZInstrVector.td:643
    VCTZB                                 = 2594, // SystemZInstrVector.td:644
    VCTZF                                 = 2595, // SystemZInstrVector.td:646
    VCTZG                                 = 2596, // SystemZInstrVector.td:647
    VCTZH                                 = 2597, // SystemZInstrVector.td:645
    VCTZQ                                 = 2598, // SystemZInstrVector.td:649
    VCVB                                  = 2599, // SystemZInstrVector.td:2467
    VCVBG                                 = 2600, // SystemZInstrVector.td:2468
    VCVBGOpt                              = 2601, // SystemZInstrVector.td:2465
    VCVBOpt                               = 2602, // SystemZInstrVector.td:2464
    VCVBQ                                 = 2603, // SystemZInstrVector.td:2514
    VCVD                                  = 2604, // SystemZInstrVector.td:2469
    VCVDG                                 = 2605, // SystemZInstrVector.td:2470
    VCVDQ                                 = 2606, // SystemZInstrVector.td:2516
    VD                                    = 2607, // SystemZInstrVector.td:654
    VDF                                   = 2608, // SystemZInstrVector.td:655
    VDG                                   = 2609, // SystemZInstrVector.td:656
    VDL                                   = 2610, // SystemZInstrVector.td:667
    VDLF                                  = 2611, // SystemZInstrVector.td:668
    VDLG                                  = 2612, // SystemZInstrVector.td:669
    VDLQ                                  = 2613, // SystemZInstrVector.td:670
    VDP                                   = 2614, // SystemZInstrVector.td:2478
    VDQ                                   = 2615, // SystemZInstrVector.td:657
    VEC                                   = 2616, // SystemZInstrVector.td:1379
    VECB                                  = 2617, // SystemZInstrVector.td:1380
    VECF                                  = 2618, // SystemZInstrVector.td:1382
    VECG                                  = 2619, // SystemZInstrVector.td:1383
    VECH                                  = 2620, // SystemZInstrVector.td:1381
    VECL                                  = 2621, // SystemZInstrVector.td:1390
    VECLB                                 = 2622, // SystemZInstrVector.td:1391
    VECLF                                 = 2623, // SystemZInstrVector.td:1393
    VECLG                                 = 2624, // SystemZInstrVector.td:1394
    VECLH                                 = 2625, // SystemZInstrVector.td:1392
    VECLQ                                 = 2626, // SystemZInstrVector.td:1396
    VECQ                                  = 2627, // SystemZInstrVector.td:1385
    VERIM                                 = 2628, // SystemZInstrVector.td:965
    VERIMB                                = 2629, // SystemZInstrVector.td:966
    VERIMF                                = 2630, // SystemZInstrVector.td:968
    VERIMG                                = 2631, // SystemZInstrVector.td:969
    VERIMH                                = 2632, // SystemZInstrVector.td:967
    VERLL                                 = 2633, // SystemZInstrVector.td:958
    VERLLB                                = 2634, // SystemZInstrVector.td:959
    VERLLF                                = 2635, // SystemZInstrVector.td:961
    VERLLG                                = 2636, // SystemZInstrVector.td:962
    VERLLH                                = 2637, // SystemZInstrVector.td:960
    VERLLV                                = 2638, // SystemZInstrVector.td:951
    VERLLVB                               = 2639, // SystemZInstrVector.td:952
    VERLLVF                               = 2640, // SystemZInstrVector.td:954
    VERLLVG                               = 2641, // SystemZInstrVector.td:955
    VERLLVH                               = 2642, // SystemZInstrVector.td:953
    VESL                                  = 2643, // SystemZInstrVector.td:979
    VESLB                                 = 2644, // SystemZInstrVector.td:980
    VESLF                                 = 2645, // SystemZInstrVector.td:982
    VESLG                                 = 2646, // SystemZInstrVector.td:983
    VESLH                                 = 2647, // SystemZInstrVector.td:981
    VESLV                                 = 2648, // SystemZInstrVector.td:972
    VESLVB                                = 2649, // SystemZInstrVector.td:973
    VESLVF                                = 2650, // SystemZInstrVector.td:975
    VESLVG                                = 2651, // SystemZInstrVector.td:976
    VESLVH                                = 2652, // SystemZInstrVector.td:974
    VESRA                                 = 2653, // SystemZInstrVector.td:993
    VESRAB                                = 2654, // SystemZInstrVector.td:994
    VESRAF                                = 2655, // SystemZInstrVector.td:996
    VESRAG                                = 2656, // SystemZInstrVector.td:997
    VESRAH                                = 2657, // SystemZInstrVector.td:995
    VESRAV                                = 2658, // SystemZInstrVector.td:986
    VESRAVB                               = 2659, // SystemZInstrVector.td:987
    VESRAVF                               = 2660, // SystemZInstrVector.td:989
    VESRAVG                               = 2661, // SystemZInstrVector.td:990
    VESRAVH                               = 2662, // SystemZInstrVector.td:988
    VESRL                                 = 2663, // SystemZInstrVector.td:1007
    VESRLB                                = 2664, // SystemZInstrVector.td:1008
    VESRLF                                = 2665, // SystemZInstrVector.td:1010
    VESRLG                                = 2666, // SystemZInstrVector.td:1011
    VESRLH                                = 2667, // SystemZInstrVector.td:1009
    VESRLV                                = 2668, // SystemZInstrVector.td:1000
    VESRLVB                               = 2669, // SystemZInstrVector.td:1001
    VESRLVF                               = 2670, // SystemZInstrVector.td:1003
    VESRLVG                               = 2671, // SystemZInstrVector.td:1004
    VESRLVH                               = 2672, // SystemZInstrVector.td:1002
    VEVAL                                 = 2673, // SystemZInstrVector.td:679
    VFA                                   = 2674, // SystemZInstrVector.td:1465
    VFADB                                 = 2675, // SystemZInstrVector.td:1466
    VFAE                                  = 2676, // SystemZInstrFormats.td:4716
    VFAEB                                 = 2677, // SystemZInstrFormats.td:4701
    VFAEBS                                = 2678, // SystemZInstrFormats.td:4707
    VFAEF                                 = 2679, // SystemZInstrFormats.td:4701
    VFAEFS                                = 2680, // SystemZInstrFormats.td:4707
    VFAEH                                 = 2681, // SystemZInstrFormats.td:4701
    VFAEHS                                = 2682, // SystemZInstrFormats.td:4707
    VFAEZB                                = 2683, // SystemZInstrFormats.td:4701
    VFAEZBS                               = 2684, // SystemZInstrFormats.td:4707
    VFAEZF                                = 2685, // SystemZInstrFormats.td:4701
    VFAEZFS                               = 2686, // SystemZInstrFormats.td:4707
    VFAEZH                                = 2687, // SystemZInstrFormats.td:4701
    VFAEZHS                               = 2688, // SystemZInstrFormats.td:4707
    VFASB                                 = 2689, // SystemZInstrVector.td:1470
    VFCE                                  = 2690, // SystemZInstrVector.td:1849
    VFCEDB                                = 2691, // SystemZInstrFormats.td:4033
    VFCEDBS                               = 2692, // SystemZInstrFormats.td:4036
    VFCESB                                = 2693, // SystemZInstrFormats.td:4033
    VFCESBS                               = 2694, // SystemZInstrFormats.td:4036
    VFCH                                  = 2695, // SystemZInstrVector.td:1881
    VFCHDB                                = 2696, // SystemZInstrFormats.td:4033
    VFCHDBS                               = 2697, // SystemZInstrFormats.td:4036
    VFCHE                                 = 2698, // SystemZInstrVector.td:1913
    VFCHEDB                               = 2699, // SystemZInstrFormats.td:4033
    VFCHEDBS                              = 2700, // SystemZInstrFormats.td:4036
    VFCHESB                               = 2701, // SystemZInstrFormats.td:4033
    VFCHESBS                              = 2702, // SystemZInstrFormats.td:4036
    VFCHSB                                = 2703, // SystemZInstrFormats.td:4033
    VFCHSBS                               = 2704, // SystemZInstrFormats.td:4036
    VFD                                   = 2705, // SystemZInstrVector.td:1551
    VFDDB                                 = 2706, // SystemZInstrVector.td:1552
    VFDSB                                 = 2707, // SystemZInstrVector.td:1556
    VFEE                                  = 2708, // SystemZInstrFormats.td:3988
    VFEEB                                 = 2709, // SystemZInstrFormats.td:3974
    VFEEBS                                = 2710, // SystemZInstrFormats.td:3983
    VFEEF                                 = 2711, // SystemZInstrFormats.td:3974
    VFEEFS                                = 2712, // SystemZInstrFormats.td:3983
    VFEEH                                 = 2713, // SystemZInstrFormats.td:3974
    VFEEHS                                = 2714, // SystemZInstrFormats.td:3983
    VFEEZB                                = 2715, // SystemZInstrFormats.td:3951
    VFEEZBS                               = 2716, // SystemZInstrFormats.td:3954
    VFEEZF                                = 2717, // SystemZInstrFormats.td:3951
    VFEEZFS                               = 2718, // SystemZInstrFormats.td:3954
    VFEEZH                                = 2719, // SystemZInstrFormats.td:3951
    VFEEZHS                               = 2720, // SystemZInstrFormats.td:3954
    VFENE                                 = 2721, // SystemZInstrFormats.td:3988
    VFENEB                                = 2722, // SystemZInstrFormats.td:3974
    VFENEBS                               = 2723, // SystemZInstrFormats.td:3983
    VFENEF                                = 2724, // SystemZInstrFormats.td:3974
    VFENEFS                               = 2725, // SystemZInstrFormats.td:3983
    VFENEH                                = 2726, // SystemZInstrFormats.td:3974
    VFENEHS                               = 2727, // SystemZInstrFormats.td:3983
    VFENEZB                               = 2728, // SystemZInstrFormats.td:3951
    VFENEZBS                              = 2729, // SystemZInstrFormats.td:3954
    VFENEZF                               = 2730, // SystemZInstrFormats.td:3951
    VFENEZFS                              = 2731, // SystemZInstrFormats.td:3954
    VFENEZH                               = 2732, // SystemZInstrFormats.td:3951
    VFENEZHS                              = 2733, // SystemZInstrFormats.td:3954
    VFI                                   = 2734, // SystemZInstrVector.td:1565
    VFIDB                                 = 2735, // SystemZInstrVector.td:1566
    VFISB                                 = 2736, // SystemZInstrVector.td:1573
    VFKEDB                                = 2737, // SystemZInstrFormats.td:4033
    VFKEDBS                               = 2738, // SystemZInstrFormats.td:4036
    VFKESB                                = 2739, // SystemZInstrFormats.td:4033
    VFKESBS                               = 2740, // SystemZInstrFormats.td:4036
    VFKHDB                                = 2741, // SystemZInstrFormats.td:4033
    VFKHDBS                               = 2742, // SystemZInstrFormats.td:4036
    VFKHEDB                               = 2743, // SystemZInstrFormats.td:4033
    VFKHEDBS                              = 2744, // SystemZInstrFormats.td:4036
    VFKHESB                               = 2745, // SystemZInstrFormats.td:4033
    VFKHESBS                              = 2746, // SystemZInstrFormats.td:4036
    VFKHSB                                = 2747, // SystemZInstrFormats.td:4033
    VFKHSBS                               = 2748, // SystemZInstrFormats.td:4036
    VFLCDB                                = 2749, // SystemZInstrVector.td:1755
    VFLCSB                                = 2750, // SystemZInstrVector.td:1758
    VFLL                                  = 2751, // SystemZInstrVector.td:1592
    VFLLS                                 = 2752, // SystemZInstrVector.td:1593
    VFLNDB                                = 2753, // SystemZInstrVector.td:1764
    VFLNSB                                = 2754, // SystemZInstrVector.td:1767
    VFLPDB                                = 2755, // SystemZInstrVector.td:1773
    VFLPSB                                = 2756, // SystemZInstrVector.td:1776
    VFLR                                  = 2757, // SystemZInstrVector.td:1613
    VFLRD                                 = 2758, // SystemZInstrVector.td:1614
    VFM                                   = 2759, // SystemZInstrVector.td:1682
    VFMA                                  = 2760, // SystemZInstrVector.td:1696
    VFMADB                                = 2761, // SystemZInstrVector.td:1697
    VFMASB                                = 2762, // SystemZInstrVector.td:1701
    VFMAX                                 = 2763, // SystemZInstrVector.td:1633
    VFMAXDB                               = 2764, // SystemZInstrVector.td:1634
    VFMAXSB                               = 2765, // SystemZInstrVector.td:1638
    VFMDB                                 = 2766, // SystemZInstrVector.td:1683
    VFMIN                                 = 2767, // SystemZInstrVector.td:1661
    VFMINDB                               = 2768, // SystemZInstrVector.td:1662
    VFMINSB                               = 2769, // SystemZInstrVector.td:1666
    VFMS                                  = 2770, // SystemZInstrVector.td:1710
    VFMSB                                 = 2771, // SystemZInstrVector.td:1687
    VFMSDB                                = 2772, // SystemZInstrVector.td:1711
    VFMSSB                                = 2773, // SystemZInstrVector.td:1715
    VFNMA                                 = 2774, // SystemZInstrVector.td:1725
    VFNMADB                               = 2775, // SystemZInstrVector.td:1726
    VFNMASB                               = 2776, // SystemZInstrVector.td:1728
    VFNMS                                 = 2777, // SystemZInstrVector.td:1736
    VFNMSDB                               = 2778, // SystemZInstrVector.td:1737
    VFNMSSB                               = 2779, // SystemZInstrVector.td:1739
    VFPSO                                 = 2780, // SystemZInstrVector.td:1745
    VFPSODB                               = 2781, // SystemZInstrVector.td:1746
    VFPSOSB                               = 2782, // SystemZInstrVector.td:1749
    VFS                                   = 2783, // SystemZInstrVector.td:1797
    VFSDB                                 = 2784, // SystemZInstrVector.td:1798
    VFSQ                                  = 2785, // SystemZInstrVector.td:1783
    VFSQDB                                = 2786, // SystemZInstrVector.td:1784
    VFSQSB                                = 2787, // SystemZInstrVector.td:1788
    VFSSB                                 = 2788, // SystemZInstrVector.td:1802
    VFTCI                                 = 2789, // SystemZInstrVector.td:1811
    VFTCIDB                               = 2790, // SystemZInstrVector.td:1812
    VFTCISB                               = 2791, // SystemZInstrVector.td:1815
    VGBM                                  = 2792, // SystemZInstrVector.td:91
    VGEF                                  = 2793, // SystemZInstrVector.td:207
    VGEG                                  = 2794, // SystemZInstrVector.td:208
    VGEM                                  = 2795, // SystemZInstrVector.td:478
    VGEMB                                 = 2796, // SystemZInstrVector.td:479
    VGEMF                                 = 2797, // SystemZInstrVector.td:481
    VGEMG                                 = 2798, // SystemZInstrVector.td:482
    VGEMH                                 = 2799, // SystemZInstrVector.td:480
    VGEMQ                                 = 2800, // SystemZInstrVector.td:483
    VGFM                                  = 2801, // SystemZInstrVector.td:691
    VGFMA                                 = 2802, // SystemZInstrVector.td:698
    VGFMAB                                = 2803, // SystemZInstrVector.td:699
    VGFMAF                                = 2804, // SystemZInstrVector.td:701
    VGFMAG                                = 2805, // SystemZInstrVector.td:702
    VGFMAH                                = 2806, // SystemZInstrVector.td:700
    VGFMB                                 = 2807, // SystemZInstrVector.td:692
    VGFMF                                 = 2808, // SystemZInstrVector.td:694
    VGFMG                                 = 2809, // SystemZInstrVector.td:695
    VGFMH                                 = 2810, // SystemZInstrVector.td:693
    VGM                                   = 2811, // SystemZInstrVector.td:94
    VGMB                                  = 2812, // SystemZInstrVector.td:95
    VGMF                                  = 2813, // SystemZInstrVector.td:97
    VGMG                                  = 2814, // SystemZInstrVector.td:98
    VGMH                                  = 2815, // SystemZInstrVector.td:96
    VISTR                                 = 2816, // SystemZInstrFormats.td:3310
    VISTRB                                = 2817, // SystemZInstrFormats.td:3296
    VISTRBS                               = 2818, // SystemZInstrFormats.td:3304
    VISTRF                                = 2819, // SystemZInstrFormats.td:3296
    VISTRFS                               = 2820, // SystemZInstrFormats.td:3304
    VISTRH                                = 2821, // SystemZInstrFormats.td:3296
    VISTRHS                               = 2822, // SystemZInstrFormats.td:3304
    VL                                    = 2823, // SystemZInstrFormats.td:3341
    VLAlign                               = 2824, // SystemZInstrFormats.td:3337
    VLBB                                  = 2825, // SystemZInstrVector.td:140
    VLBR                                  = 2826, // SystemZInstrVector.td:303
    VLBRF                                 = 2827, // SystemZInstrVector.td:305
    VLBRG                                 = 2828, // SystemZInstrVector.td:306
    VLBRH                                 = 2829, // SystemZInstrVector.td:304
    VLBRQ                                 = 2830, // SystemZInstrVector.td:307
    VLBRREP                               = 2831, // SystemZInstrVector.td:340
    VLBRREPF                              = 2832, // SystemZInstrVector.td:342
    VLBRREPG                              = 2833, // SystemZInstrVector.td:343
    VLBRREPH                              = 2834, // SystemZInstrVector.td:341
    VLC                                   = 2835, // SystemZInstrVector.td:705
    VLCB                                  = 2836, // SystemZInstrVector.td:706
    VLCF                                  = 2837, // SystemZInstrVector.td:708
    VLCG                                  = 2838, // SystemZInstrVector.td:709
    VLCH                                  = 2839, // SystemZInstrVector.td:707
    VLCQ                                  = 2840, // SystemZInstrVector.td:711
    VLDE                                  = 2841, // SystemZInstrVector.td:1584
    VLDEB                                 = 2842, // SystemZInstrVector.td:1585
    VLEB                                  = 2843, // SystemZInstrVector.td:197
    VLEBRF                                = 2844, // SystemZInstrVector.td:325
    VLEBRG                                = 2845, // SystemZInstrVector.td:326
    VLEBRH                                = 2846, // SystemZInstrVector.td:324
    VLED                                  = 2847, // SystemZInstrVector.td:1604
    VLEDB                                 = 2848, // SystemZInstrVector.td:1605
    VLEF                                  = 2849, // SystemZInstrVector.td:199
    VLEG                                  = 2850, // SystemZInstrVector.td:200
    VLEH                                  = 2851, // SystemZInstrVector.td:198
    VLEIB                                 = 2852, // SystemZInstrVector.td:117
    VLEIF                                 = 2853, // SystemZInstrVector.td:121
    VLEIG                                 = 2854, // SystemZInstrVector.td:123
    VLEIH                                 = 2855, // SystemZInstrVector.td:119
    VLER                                  = 2856, // SystemZInstrVector.td:310
    VLERF                                 = 2857, // SystemZInstrVector.td:312
    VLERG                                 = 2858, // SystemZInstrVector.td:313
    VLERH                                 = 2859, // SystemZInstrVector.td:311
    VLGV                                  = 2860, // SystemZInstrVector.td:23
    VLGVB                                 = 2861, // SystemZInstrVector.td:24
    VLGVF                                 = 2862, // SystemZInstrVector.td:26
    VLGVG                                 = 2863, // SystemZInstrVector.td:27
    VLGVH                                 = 2864, // SystemZInstrVector.td:25
    VLIP                                  = 2865, // SystemZInstrVector.td:2457
    VLL                                   = 2866, // SystemZInstrVector.td:151
    VLLEBRZ                               = 2867, // SystemZInstrVector.td:329
    VLLEBRZE                              = 2868, // SystemZInstrVector.td:333
    VLLEBRZF                              = 2869, // SystemZInstrVector.td:331
    VLLEBRZG                              = 2870, // SystemZInstrVector.td:332
    VLLEBRZH                              = 2871, // SystemZInstrVector.td:330
    VLLEZ                                 = 2872, // SystemZInstrVector.td:181
    VLLEZB                                = 2873, // SystemZInstrVector.td:182
    VLLEZF                                = 2874, // SystemZInstrVector.td:184
    VLLEZG                                = 2875, // SystemZInstrVector.td:185
    VLLEZH                                = 2876, // SystemZInstrVector.td:183
    VLLEZLF                               = 2877, // SystemZInstrVector.td:191
    VLM                                   = 2878, // SystemZInstrFormats.td:2748
    VLMAlign                              = 2879, // SystemZInstrFormats.td:2744
    VLP                                   = 2880, // SystemZInstrVector.td:714
    VLPB                                  = 2881, // SystemZInstrVector.td:715
    VLPF                                  = 2882, // SystemZInstrVector.td:717
    VLPG                                  = 2883, // SystemZInstrVector.td:718
    VLPH                                  = 2884, // SystemZInstrVector.td:716
    VLPQ                                  = 2885, // SystemZInstrVector.td:720
    VLR                                   = 2886, // SystemZInstrVector.td:16
    VLREP                                 = 2887, // SystemZInstrVector.td:157
    VLREPB                                = 2888, // SystemZInstrVector.td:158
    VLREPF                                = 2889, // SystemZInstrVector.td:160
    VLREPG                                = 2890, // SystemZInstrVector.td:161
    VLREPH                                = 2891, // SystemZInstrVector.td:159
    VLRL                                  = 2892, // SystemZInstrVector.td:216
    VLRLR                                 = 2893, // SystemZInstrVector.td:217
    VLVG                                  = 2894, // SystemZInstrVector.td:30
    VLVGB                                 = 2895, // SystemZInstrVector.td:31
    VLVGF                                 = 2896, // SystemZInstrVector.td:35
    VLVGG                                 = 2897, // SystemZInstrVector.td:37
    VLVGH                                 = 2898, // SystemZInstrVector.td:33
    VLVGP                                 = 2899, // SystemZInstrVector.td:41
    VMAE                                  = 2900, // SystemZInstrVector.td:794
    VMAEB                                 = 2901, // SystemZInstrVector.td:795
    VMAEF                                 = 2902, // SystemZInstrVector.td:797
    VMAEG                                 = 2903, // SystemZInstrVector.td:799
    VMAEH                                 = 2904, // SystemZInstrVector.td:796
    VMAH                                  = 2905, // SystemZInstrVector.td:774
    VMAHB                                 = 2906, // SystemZInstrVector.td:775
    VMAHF                                 = 2907, // SystemZInstrVector.td:777
    VMAHG                                 = 2908, // SystemZInstrVector.td:779
    VMAHH                                 = 2909, // SystemZInstrVector.td:776
    VMAHQ                                 = 2910, // SystemZInstrVector.td:780
    VMAL                                  = 2911, // SystemZInstrVector.td:764
    VMALB                                 = 2912, // SystemZInstrVector.td:765
    VMALE                                 = 2913, // SystemZInstrVector.td:802
    VMALEB                                = 2914, // SystemZInstrVector.td:803
    VMALEF                                = 2915, // SystemZInstrVector.td:805
    VMALEG                                = 2916, // SystemZInstrVector.td:807
    VMALEH                                = 2917, // SystemZInstrVector.td:804
    VMALF                                 = 2918, // SystemZInstrVector.td:767
    VMALG                                 = 2919, // SystemZInstrVector.td:769
    VMALH                                 = 2920, // SystemZInstrVector.td:784
    VMALHB                                = 2921, // SystemZInstrVector.td:785
    VMALHF                                = 2922, // SystemZInstrVector.td:787
    VMALHG                                = 2923, // SystemZInstrVector.td:789
    VMALHH                                = 2924, // SystemZInstrVector.td:786
    VMALHQ                                = 2925, // SystemZInstrVector.td:790
    VMALHW                                = 2926, // SystemZInstrVector.td:766
    VMALO                                 = 2927, // SystemZInstrVector.td:818
    VMALOB                                = 2928, // SystemZInstrVector.td:819
    VMALOF                                = 2929, // SystemZInstrVector.td:821
    VMALOG                                = 2930, // SystemZInstrVector.td:823
    VMALOH                                = 2931, // SystemZInstrVector.td:820
    VMALQ                                 = 2932, // SystemZInstrVector.td:770
    VMAO                                  = 2933, // SystemZInstrVector.td:810
    VMAOB                                 = 2934, // SystemZInstrVector.td:811
    VMAOF                                 = 2935, // SystemZInstrVector.td:813
    VMAOG                                 = 2936, // SystemZInstrVector.td:815
    VMAOH                                 = 2937, // SystemZInstrVector.td:812
    VME                                   = 2938, // SystemZInstrVector.td:858
    VMEB                                  = 2939, // SystemZInstrVector.td:859
    VMEF                                  = 2940, // SystemZInstrVector.td:861
    VMEG                                  = 2941, // SystemZInstrVector.td:863
    VMEH                                  = 2942, // SystemZInstrVector.td:860
    VMH                                   = 2943, // SystemZInstrVector.td:828
    VMHB                                  = 2944, // SystemZInstrVector.td:829
    VMHF                                  = 2945, // SystemZInstrVector.td:831
    VMHG                                  = 2946, // SystemZInstrVector.td:833
    VMHH                                  = 2947, // SystemZInstrVector.td:830
    VMHQ                                  = 2948, // SystemZInstrVector.td:834
    VML                                   = 2949, // SystemZInstrVector.td:848
    VMLB                                  = 2950, // SystemZInstrVector.td:849
    VMLE                                  = 2951, // SystemZInstrVector.td:866
    VMLEB                                 = 2952, // SystemZInstrVector.td:867
    VMLEF                                 = 2953, // SystemZInstrVector.td:869
    VMLEG                                 = 2954, // SystemZInstrVector.td:871
    VMLEH                                 = 2955, // SystemZInstrVector.td:868
    VMLF                                  = 2956, // SystemZInstrVector.td:851
    VMLG                                  = 2957, // SystemZInstrVector.td:853
    VMLH                                  = 2958, // SystemZInstrVector.td:838
    VMLHB                                 = 2959, // SystemZInstrVector.td:839
    VMLHF                                 = 2960, // SystemZInstrVector.td:841
    VMLHG                                 = 2961, // SystemZInstrVector.td:843
    VMLHH                                 = 2962, // SystemZInstrVector.td:840
    VMLHQ                                 = 2963, // SystemZInstrVector.td:844
    VMLHW                                 = 2964, // SystemZInstrVector.td:850
    VMLO                                  = 2965, // SystemZInstrVector.td:882
    VMLOB                                 = 2966, // SystemZInstrVector.td:883
    VMLOF                                 = 2967, // SystemZInstrVector.td:885
    VMLOG                                 = 2968, // SystemZInstrVector.td:887
    VMLOH                                 = 2969, // SystemZInstrVector.td:884
    VMLQ                                  = 2970, // SystemZInstrVector.td:854
    VMN                                   = 2971, // SystemZInstrVector.td:744
    VMNB                                  = 2972, // SystemZInstrVector.td:745
    VMNF                                  = 2973, // SystemZInstrVector.td:747
    VMNG                                  = 2974, // SystemZInstrVector.td:748
    VMNH                                  = 2975, // SystemZInstrVector.td:746
    VMNL                                  = 2976, // SystemZInstrVector.td:753
    VMNLB                                 = 2977, // SystemZInstrVector.td:754
    VMNLF                                 = 2978, // SystemZInstrVector.td:756
    VMNLG                                 = 2979, // SystemZInstrVector.td:757
    VMNLH                                 = 2980, // SystemZInstrVector.td:755
    VMNLQ                                 = 2981, // SystemZInstrVector.td:759
    VMNQ                                  = 2982, // SystemZInstrVector.td:750
    VMO                                   = 2983, // SystemZInstrVector.td:874
    VMOB                                  = 2984, // SystemZInstrVector.td:875
    VMOF                                  = 2985, // SystemZInstrVector.td:877
    VMOG                                  = 2986, // SystemZInstrVector.td:879
    VMOH                                  = 2987, // SystemZInstrVector.td:876
    VMP                                   = 2988, // SystemZInstrVector.td:2475
    VMRH                                  = 2989, // SystemZInstrVector.td:382
    VMRHB                                 = 2990, // SystemZInstrVector.td:383
    VMRHF                                 = 2991, // SystemZInstrVector.td:385
    VMRHG                                 = 2992, // SystemZInstrVector.td:386
    VMRHH                                 = 2993, // SystemZInstrVector.td:384
    VMRL                                  = 2994, // SystemZInstrVector.td:392
    VMRLB                                 = 2995, // SystemZInstrVector.td:393
    VMRLF                                 = 2996, // SystemZInstrVector.td:395
    VMRLG                                 = 2997, // SystemZInstrVector.td:396
    VMRLH                                 = 2998, // SystemZInstrVector.td:394
    VMSL                                  = 2999, // SystemZInstrVector.td:892
    VMSLG                                 = 3000, // SystemZInstrVector.td:893
    VMSP                                  = 3001, // SystemZInstrVector.td:2476
    VMX                                   = 3002, // SystemZInstrVector.td:724
    VMXB                                  = 3003, // SystemZInstrVector.td:725
    VMXF                                  = 3004, // SystemZInstrVector.td:727
    VMXG                                  = 3005, // SystemZInstrVector.td:728
    VMXH                                  = 3006, // SystemZInstrVector.td:726
    VMXL                                  = 3007, // SystemZInstrVector.td:733
    VMXLB                                 = 3008, // SystemZInstrVector.td:734
    VMXLF                                 = 3009, // SystemZInstrVector.td:736
    VMXLG                                 = 3010, // SystemZInstrVector.td:737
    VMXLH                                 = 3011, // SystemZInstrVector.td:735
    VMXLQ                                 = 3012, // SystemZInstrVector.td:739
    VMXQ                                  = 3013, // SystemZInstrVector.td:730
    VN                                    = 3014, // SystemZInstrVector.td:605
    VNC                                   = 3015, // SystemZInstrVector.td:608
    VNN                                   = 3016, // SystemZInstrVector.td:899
    VNO                                   = 3017, // SystemZInstrVector.td:903
    VNX                                   = 3018, // SystemZInstrVector.td:684
    VO                                    = 3019, // SystemZInstrVector.td:908
    VOC                                   = 3020, // SystemZInstrVector.td:912
    VONE                                  = 3021, // SystemZInstrVector.td:90
    VPDI                                  = 3022, // SystemZInstrVector.td:405
    VPERM                                 = 3023, // SystemZInstrVector.td:402
    VPK                                   = 3024, // SystemZInstrVector.td:444
    VPKF                                  = 3025, // SystemZInstrVector.td:446
    VPKG                                  = 3026, // SystemZInstrVector.td:447
    VPKH                                  = 3027, // SystemZInstrVector.td:445
    VPKLS                                 = 3028, // SystemZInstrVector.td:459
    VPKLSF                                = 3029, // SystemZInstrFormats.td:3951
    VPKLSFS                               = 3030, // SystemZInstrFormats.td:3954
    VPKLSG                                = 3031, // SystemZInstrFormats.td:3951
    VPKLSGS                               = 3032, // SystemZInstrFormats.td:3954
    VPKLSH                                = 3033, // SystemZInstrFormats.td:3951
    VPKLSHS                               = 3034, // SystemZInstrFormats.td:3954
    VPKS                                  = 3035, // SystemZInstrVector.td:450
    VPKSF                                 = 3036, // SystemZInstrFormats.td:3951
    VPKSFS                                = 3037, // SystemZInstrFormats.td:3954
    VPKSG                                 = 3038, // SystemZInstrFormats.td:3951
    VPKSGS                                = 3039, // SystemZInstrFormats.td:3954
    VPKSH                                 = 3040, // SystemZInstrFormats.td:3951
    VPKSHS                                = 3041, // SystemZInstrFormats.td:3954
    VPKZ                                  = 3042, // SystemZInstrVector.td:2459
    VPKZR                                 = 3043, // SystemZInstrVector.td:2507
    VPOPCT                                = 3044, // SystemZInstrVector.td:915
    VPOPCTB                               = 3045, // SystemZInstrVector.td:918
    VPOPCTF                               = 3046, // SystemZInstrVector.td:920
    VPOPCTG                               = 3047, // SystemZInstrVector.td:921
    VPOPCTH                               = 3048, // SystemZInstrVector.td:919
    VPSOP                                 = 3049, // SystemZInstrVector.td:2483
    VR                                    = 3050, // SystemZInstrVector.td:927
    VREP                                  = 3051, // SystemZInstrVector.td:412
    VREPB                                 = 3052, // SystemZInstrVector.td:413
    VREPF                                 = 3053, // SystemZInstrVector.td:415
    VREPG                                 = 3054, // SystemZInstrVector.td:416
    VREPH                                 = 3055, // SystemZInstrVector.td:414
    VREPI                                 = 3056, // SystemZInstrVector.td:101
    VREPIB                                = 3057, // SystemZInstrVector.td:102
    VREPIF                                = 3058, // SystemZInstrVector.td:104
    VREPIG                                = 3059, // SystemZInstrVector.td:105
    VREPIH                                = 3060, // SystemZInstrVector.td:103
    VRF                                   = 3061, // SystemZInstrVector.td:928
    VRG                                   = 3062, // SystemZInstrVector.td:929
    VRL                                   = 3063, // SystemZInstrVector.td:940
    VRLF                                  = 3064, // SystemZInstrVector.td:941
    VRLG                                  = 3065, // SystemZInstrVector.td:942
    VRLQ                                  = 3066, // SystemZInstrVector.td:943
    VRP                                   = 3067, // SystemZInstrVector.td:2479
    VRQ                                   = 3068, // SystemZInstrVector.td:930
    VS                                    = 3069, // SystemZInstrVector.td:1051
    VSB                                   = 3070, // SystemZInstrVector.td:1052
    VSBCBI                                = 3071, // SystemZInstrVector.td:1071
    VSBCBIQ                               = 3072, // SystemZInstrVector.td:1072
    VSBI                                  = 3073, // SystemZInstrVector.td:1067
    VSBIQ                                 = 3074, // SystemZInstrVector.td:1068
    VSCBI                                 = 3075, // SystemZInstrVector.td:1059
    VSCBIB                                = 3076, // SystemZInstrVector.td:1060
    VSCBIF                                = 3077, // SystemZInstrVector.td:1062
    VSCBIG                                = 3078, // SystemZInstrVector.td:1063
    VSCBIH                                = 3079, // SystemZInstrVector.td:1061
    VSCBIQ                                = 3080, // SystemZInstrVector.td:1064
    VSCEF                                 = 3081, // SystemZInstrVector.td:282
    VSCEG                                 = 3082, // SystemZInstrVector.td:283
    VSCHDP                                = 3083, // SystemZInstrVector.td:2493
    VSCHP                                 = 3084, // SystemZInstrVector.td:2491
    VSCHSP                                = 3085, // SystemZInstrVector.td:2492
    VSCHXP                                = 3086, // SystemZInstrVector.td:2494
    VSCSHP                                = 3087, // SystemZInstrVector.td:2496
    VSDP                                  = 3088, // SystemZInstrVector.td:2480
    VSEG                                  = 3089, // SystemZInstrVector.td:468
    VSEGB                                 = 3090, // SystemZInstrVector.td:469
    VSEGF                                 = 3091, // SystemZInstrVector.td:471
    VSEGH                                 = 3092, // SystemZInstrVector.td:470
    VSEL                                  = 3093, // SystemZInstrVector.td:425
    VSF                                   = 3094, // SystemZInstrVector.td:1054
    VSG                                   = 3095, // SystemZInstrVector.td:1055
    VSH                                   = 3096, // SystemZInstrVector.td:1053
    VSL                                   = 3097, // SystemZInstrVector.td:1014
    VSLB                                  = 3098, // SystemZInstrVector.td:1017
    VSLD                                  = 3099, // SystemZInstrVector.td:1026
    VSLDB                                 = 3100, // SystemZInstrVector.td:1020
    VSP                                   = 3101, // SystemZInstrVector.td:2473
    VSQ                                   = 3102, // SystemZInstrVector.td:1056
    VSRA                                  = 3103, // SystemZInstrVector.td:1032
    VSRAB                                 = 3104, // SystemZInstrVector.td:1035
    VSRD                                  = 3105, // SystemZInstrVector.td:1045
    VSRL                                  = 3106, // SystemZInstrVector.td:1038
    VSRLB                                 = 3107, // SystemZInstrVector.td:1041
    VSRP                                  = 3108, // SystemZInstrVector.td:2482
    VSRPR                                 = 3109, // SystemZInstrVector.td:2504
    VST                                   = 3110, // SystemZInstrFormats.td:2827
    VSTAlign                              = 3111, // SystemZInstrFormats.td:2822
    VSTBR                                 = 3112, // SystemZInstrVector.td:346
    VSTBRF                                = 3113, // SystemZInstrVector.td:348
    VSTBRG                                = 3114, // SystemZInstrVector.td:349
    VSTBRH                                = 3115, // SystemZInstrVector.td:347
    VSTBRQ                                = 3116, // SystemZInstrVector.td:350
    VSTEB                                 = 3117, // SystemZInstrVector.td:257
    VSTEBRF                               = 3118, // SystemZInstrVector.td:368
    VSTEBRG                               = 3119, // SystemZInstrVector.td:369
    VSTEBRH                               = 3120, // SystemZInstrVector.td:367
    VSTEF                                 = 3121, // SystemZInstrVector.td:259
    VSTEG                                 = 3122, // SystemZInstrVector.td:260
    VSTEH                                 = 3123, // SystemZInstrVector.td:258
    VSTER                                 = 3124, // SystemZInstrVector.td:353
    VSTERF                                = 3125, // SystemZInstrVector.td:355
    VSTERG                                = 3126, // SystemZInstrVector.td:356
    VSTERH                                = 3127, // SystemZInstrVector.td:354
    VSTL                                  = 3128, // SystemZInstrVector.td:251
    VSTM                                  = 3129, // SystemZInstrFormats.td:2895
    VSTMAlign                             = 3130, // SystemZInstrFormats.td:2890
    VSTRC                                 = 3131, // SystemZInstrFormats.td:4983
    VSTRCB                                = 3132, // SystemZInstrFormats.td:4966
    VSTRCBS                               = 3133, // SystemZInstrFormats.td:4973
    VSTRCF                                = 3134, // SystemZInstrFormats.td:4966
    VSTRCFS                               = 3135, // SystemZInstrFormats.td:4973
    VSTRCH                                = 3136, // SystemZInstrFormats.td:4966
    VSTRCHS                               = 3137, // SystemZInstrFormats.td:4973
    VSTRCZB                               = 3138, // SystemZInstrFormats.td:4966
    VSTRCZBS                              = 3139, // SystemZInstrFormats.td:4973
    VSTRCZF                               = 3140, // SystemZInstrFormats.td:4966
    VSTRCZFS                              = 3141, // SystemZInstrFormats.td:4973
    VSTRCZH                               = 3142, // SystemZInstrFormats.td:4966
    VSTRCZHS                              = 3143, // SystemZInstrFormats.td:4973
    VSTRL                                 = 3144, // SystemZInstrVector.td:291
    VSTRLR                                = 3145, // SystemZInstrVector.td:292
    VSTRS                                 = 3146, // SystemZInstrFormats.td:4813
    VSTRSB                                = 3147, // SystemZInstrFormats.td:4800
    VSTRSF                                = 3148, // SystemZInstrFormats.td:4800
    VSTRSH                                = 3149, // SystemZInstrFormats.td:4800
    VSTRSZB                               = 3150, // SystemZInstrVector.td:2412
    VSTRSZF                               = 3151, // SystemZInstrVector.td:2416
    VSTRSZH                               = 3152, // SystemZInstrVector.td:2414
    VSUM                                  = 3153, // SystemZInstrVector.td:1085
    VSUMB                                 = 3154, // SystemZInstrVector.td:1086
    VSUMG                                 = 3155, // SystemZInstrVector.td:1075
    VSUMGF                                = 3156, // SystemZInstrVector.td:1077
    VSUMGH                                = 3157, // SystemZInstrVector.td:1076
    VSUMH                                 = 3158, // SystemZInstrVector.td:1087
    VSUMQ                                 = 3159, // SystemZInstrVector.td:1080
    VSUMQF                                = 3160, // SystemZInstrVector.td:1081
    VSUMQG                                = 3161, // SystemZInstrVector.td:1082
    VTM                                   = 3162, // SystemZInstrVector.td:1443
    VTP                                   = 3163, // SystemZInstrVector.td:2485
    VTPOpt                                = 3164, // SystemZInstrVector.td:2519
    VTZ                                   = 3165, // SystemZInstrVector.td:2520
    VUPH                                  = 3166, // SystemZInstrVector.td:487
    VUPHB                                 = 3167, // SystemZInstrVector.td:488
    VUPHF                                 = 3168, // SystemZInstrVector.td:490
    VUPHG                                 = 3169, // SystemZInstrVector.td:492
    VUPHH                                 = 3170, // SystemZInstrVector.td:489
    VUPKZ                                 = 3171, // SystemZInstrVector.td:2460
    VUPKZH                                = 3172, // SystemZInstrVector.td:2508
    VUPKZL                                = 3173, // SystemZInstrVector.td:2509
    VUPL                                  = 3174, // SystemZInstrVector.td:503
    VUPLB                                 = 3175, // SystemZInstrVector.td:504
    VUPLF                                 = 3176, // SystemZInstrVector.td:506
    VUPLG                                 = 3177, // SystemZInstrVector.td:508
    VUPLH                                 = 3178, // SystemZInstrVector.td:495
    VUPLHB                                = 3179, // SystemZInstrVector.td:496
    VUPLHF                                = 3180, // SystemZInstrVector.td:498
    VUPLHG                                = 3181, // SystemZInstrVector.td:500
    VUPLHH                                = 3182, // SystemZInstrVector.td:497
    VUPLHW                                = 3183, // SystemZInstrVector.td:505
    VUPLL                                 = 3184, // SystemZInstrVector.td:511
    VUPLLB                                = 3185, // SystemZInstrVector.td:512
    VUPLLF                                = 3186, // SystemZInstrVector.td:514
    VUPLLG                                = 3187, // SystemZInstrVector.td:516
    VUPLLH                                = 3188, // SystemZInstrVector.td:513
    VX                                    = 3189, // SystemZInstrVector.td:687
    VZERO                                 = 3190, // SystemZInstrVector.td:89
    WCDGB                                 = 3191, // SystemZInstrVector.td:1481
    WCDLGB                                = 3192, // SystemZInstrVector.td:1498
    WCEFB                                 = 3193, // SystemZInstrVector.td:1489
    WCELFB                                = 3194, // SystemZInstrVector.td:1506
    WCFEB                                 = 3195, // SystemZInstrVector.td:1524
    WCGDB                                 = 3196, // SystemZInstrVector.td:1515
    WCLFEB                                = 3197, // SystemZInstrVector.td:1543
    WCLGDB                                = 3198, // SystemZInstrVector.td:1534
    WFADB                                 = 3199, // SystemZInstrVector.td:1467
    WFASB                                 = 3200, // SystemZInstrVector.td:1471
    WFAXB                                 = 3201, // SystemZInstrVector.td:1473
    WFC                                   = 3202, // SystemZInstrVector.td:1829
    WFCDB                                 = 3203, // SystemZInstrVector.td:1830
    WFCEDB                                = 3204, // SystemZInstrFormats.td:4033
    WFCEDBS                               = 3205, // SystemZInstrFormats.td:4036
    WFCESB                                = 3206, // SystemZInstrFormats.td:4033
    WFCESBS                               = 3207, // SystemZInstrFormats.td:4036
    WFCEXB                                = 3208, // SystemZInstrFormats.td:4033
    WFCEXBS                               = 3209, // SystemZInstrFormats.td:4036
    WFCHDB                                = 3210, // SystemZInstrFormats.td:4033
    WFCHDBS                               = 3211, // SystemZInstrFormats.td:4036
    WFCHEDB                               = 3212, // SystemZInstrFormats.td:4033
    WFCHEDBS                              = 3213, // SystemZInstrFormats.td:4036
    WFCHESB                               = 3214, // SystemZInstrFormats.td:4033
    WFCHESBS                              = 3215, // SystemZInstrFormats.td:4036
    WFCHEXB                               = 3216, // SystemZInstrFormats.td:4033
    WFCHEXBS                              = 3217, // SystemZInstrFormats.td:4036
    WFCHSB                                = 3218, // SystemZInstrFormats.td:4033
    WFCHSBS                               = 3219, // SystemZInstrFormats.td:4036
    WFCHXB                                = 3220, // SystemZInstrFormats.td:4033
    WFCHXBS                               = 3221, // SystemZInstrFormats.td:4036
    WFCSB                                 = 3222, // SystemZInstrVector.td:1832
    WFCXB                                 = 3223, // SystemZInstrVector.td:1833
    WFDDB                                 = 3224, // SystemZInstrVector.td:1553
    WFDSB                                 = 3225, // SystemZInstrVector.td:1557
    WFDXB                                 = 3226, // SystemZInstrVector.td:1559
    WFIDB                                 = 3227, // SystemZInstrVector.td:1567
    WFISB                                 = 3228, // SystemZInstrVector.td:1574
    WFIXB                                 = 3229, // SystemZInstrVector.td:1575
    WFK                                   = 3230, // SystemZInstrVector.td:1839
    WFKDB                                 = 3231, // SystemZInstrVector.td:1840
    WFKEDB                                = 3232, // SystemZInstrFormats.td:4033
    WFKEDBS                               = 3233, // SystemZInstrFormats.td:4036
    WFKESB                                = 3234, // SystemZInstrFormats.td:4033
    WFKESBS                               = 3235, // SystemZInstrFormats.td:4036
    WFKEXB                                = 3236, // SystemZInstrFormats.td:4033
    WFKEXBS                               = 3237, // SystemZInstrFormats.td:4036
    WFKHDB                                = 3238, // SystemZInstrFormats.td:4033
    WFKHDBS                               = 3239, // SystemZInstrFormats.td:4036
    WFKHEDB                               = 3240, // SystemZInstrFormats.td:4033
    WFKHEDBS                              = 3241, // SystemZInstrFormats.td:4036
    WFKHESB                               = 3242, // SystemZInstrFormats.td:4033
    WFKHESBS                              = 3243, // SystemZInstrFormats.td:4036
    WFKHEXB                               = 3244, // SystemZInstrFormats.td:4033
    WFKHEXBS                              = 3245, // SystemZInstrFormats.td:4036
    WFKHSB                                = 3246, // SystemZInstrFormats.td:4033
    WFKHSBS                               = 3247, // SystemZInstrFormats.td:4036
    WFKHXB                                = 3248, // SystemZInstrFormats.td:4033
    WFKHXBS                               = 3249, // SystemZInstrFormats.td:4036
    WFKSB                                 = 3250, // SystemZInstrVector.td:1842
    WFKXB                                 = 3251, // SystemZInstrVector.td:1843
    WFLCDB                                = 3252, // SystemZInstrVector.td:1756
    WFLCSB                                = 3253, // SystemZInstrVector.td:1759
    WFLCXB                                = 3254, // SystemZInstrVector.td:1760
    WFLLD                                 = 3255, // SystemZInstrVector.td:1596
    WFLLS                                 = 3256, // SystemZInstrVector.td:1594
    WFLNDB                                = 3257, // SystemZInstrVector.td:1765
    WFLNSB                                = 3258, // SystemZInstrVector.td:1768
    WFLNXB                                = 3259, // SystemZInstrVector.td:1769
    WFLPDB                                = 3260, // SystemZInstrVector.td:1774
    WFLPSB                                = 3261, // SystemZInstrVector.td:1777
    WFLPXB                                = 3262, // SystemZInstrVector.td:1778
    WFLRD                                 = 3263, // SystemZInstrVector.td:1615
    WFLRX                                 = 3264, // SystemZInstrVector.td:1617
    WFMADB                                = 3265, // SystemZInstrVector.td:1698
    WFMASB                                = 3266, // SystemZInstrVector.td:1702
    WFMAXB                                = 3267, // SystemZInstrVector.td:1704
    WFMAXDB                               = 3268, // SystemZInstrVector.td:1636
    WFMAXSB                               = 3269, // SystemZInstrVector.td:1640
    WFMAXXB                               = 3270, // SystemZInstrVector.td:1642
    WFMDB                                 = 3271, // SystemZInstrVector.td:1684
    WFMINDB                               = 3272, // SystemZInstrVector.td:1664
    WFMINSB                               = 3273, // SystemZInstrVector.td:1668
    WFMINXB                               = 3274, // SystemZInstrVector.td:1670
    WFMSB                                 = 3275, // SystemZInstrVector.td:1688
    WFMSDB                                = 3276, // SystemZInstrVector.td:1712
    WFMSSB                                = 3277, // SystemZInstrVector.td:1716
    WFMSXB                                = 3278, // SystemZInstrVector.td:1718
    WFMXB                                 = 3279, // SystemZInstrVector.td:1690
    WFNMADB                               = 3280, // SystemZInstrVector.td:1727
    WFNMASB                               = 3281, // SystemZInstrVector.td:1729
    WFNMAXB                               = 3282, // SystemZInstrVector.td:1730
    WFNMSDB                               = 3283, // SystemZInstrVector.td:1738
    WFNMSSB                               = 3284, // SystemZInstrVector.td:1740
    WFNMSXB                               = 3285, // SystemZInstrVector.td:1741
    WFPSODB                               = 3286, // SystemZInstrVector.td:1747
    WFPSOSB                               = 3287, // SystemZInstrVector.td:1750
    WFPSOXB                               = 3288, // SystemZInstrVector.td:1751
    WFSDB                                 = 3289, // SystemZInstrVector.td:1799
    WFSQDB                                = 3290, // SystemZInstrVector.td:1785
    WFSQSB                                = 3291, // SystemZInstrVector.td:1789
    WFSQXB                                = 3292, // SystemZInstrVector.td:1791
    WFSSB                                 = 3293, // SystemZInstrVector.td:1803
    WFSXB                                 = 3294, // SystemZInstrVector.td:1805
    WFTCIDB                               = 3295, // SystemZInstrVector.td:1813
    WFTCISB                               = 3296, // SystemZInstrVector.td:1816
    WFTCIXB                               = 3297, // SystemZInstrVector.td:1817
    WLDEB                                 = 3298, // SystemZInstrVector.td:1586
    WLEDB                                 = 3299, // SystemZInstrVector.td:1606
    X                                     = 3300, // SystemZInstrFormats.td:5515
    XC                                    = 3301, // SystemZInstrFormats.td:5572
    XG                                    = 3302, // SystemZInstrFormats.td:5502
    XGR                                   = 3303, // SystemZInstrFormats.td:3524
    XGRK                                  = 3304, // SystemZInstrFormats.td:3521
    XI                                    = 3305, // SystemZInstrFormats.td:3848
    XIHF                                  = 3306, // SystemZInstrInfo.td:1405
    XILF                                  = 3307, // SystemZInstrInfo.td:1404
    XIY                                   = 3308, // SystemZInstrFormats.td:3850
    XR                                    = 3309, // SystemZInstrFormats.td:3512
    XRK                                   = 3310, // SystemZInstrFormats.td:3509
    XSCH                                  = 3311, // SystemZInstrSystem.td:522
    XY                                    = 3312, // SystemZInstrFormats.td:5522
    ZAP                                   = 3313, // SystemZInstrInfo.td:2064
    INSTRUCTION_LIST_END = 3314
  };

} // namespace llvm_ks::SystemZ

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::SystemZ::Sched {

  enum {
    NoInstrModel	= 0,
    ADJDYNALLOC	= 1,
    CallBRCL_BRC_BRCAsm_BRCL_BRCLAsm	= 2,
    CallJG_J_JAsmE_JAsmH_JAsmHE_JAsmL_JAsmLE_JAsmLH_JAsmM_JAsmNE_JAsmNH_JAsmNHE_JAsmNL_JAsmNLE_JAsmNLH_JAsmNM_JAsmNO_JAsmNP_JAsmNZ_JAsmO_JAsmP_JAsmZ_JG_JGAsmE_JGAsmH_JGAsmHE_JGAsmL_JGAsmLE_JGAsmLH_JGAsmM_JGAsmNE_JGAsmNH_JGAsmNHE_JGAsmNL_JGAsmNLE_JGAsmNLH_JGAsmNM_JGAsmNO_JGAsmNP_JGAsmNZ_JGAsmO_JGAsmP_JGAsmZ	= 3,
    CallBCR_BC_BCAsm_BCR_BCRAsm	= 4,
    CallBR_B_BAsmE_BAsmH_BAsmHE_BAsmL_BAsmLE_BAsmLH_BAsmM_BAsmNE_BAsmNH_BAsmNHE_BAsmNL_BAsmNLE_BAsmNLH_BAsmNM_BAsmNO_BAsmNP_BAsmNZ_BAsmO_BAsmP_BAsmZ_BR_BRAsmE_BRAsmH_BRAsmHE_BRAsmL_BRAsmLE_BRAsmLH_BRAsmM_BRAsmNE_BRAsmNH_BRAsmNHE_BRAsmNL_BRAsmNLE_BRAsmNLH_BRAsmNM_BRAsmNO_BRAsmNP_BRAsmNZ_BRAsmO_BRAsmP_BRAsmZ	= 5,
    BI_BIAsmE_BIAsmH_BIAsmHE_BIAsmL_BIAsmLE_BIAsmLH_BIAsmM_BIAsmNE_BIAsmNH_BIAsmNHE_BIAsmNL_BIAsmNLE_BIAsmNLH_BIAsmNM_BIAsmNO_BIAsmNP_BIAsmNZ_BIAsmO_BIAsmP_BIAsmZ_BIC_BICAsm	= 6,
    BRCT_BRCTG	= 7,
    BRCTH	= 8,
    BCT_BCTG_BCTGR_BCTR	= 9,
    BRXH_BRXHG_BRXLE_BRXLG_BXH_BXHG_BXLE_BXLEG	= 10,
    CGIJ_CGIJAsm_CGIJAsmE_CGIJAsmH_CGIJAsmHE_CGIJAsmL_CGIJAsmLE_CGIJAsmLH_CGIJAsmNE_CGIJAsmNH_CGIJAsmNHE_CGIJAsmNL_CGIJAsmNLE_CGIJAsmNLH_CGRJ_CGRJAsm_CGRJAsmE_CGRJAsmH_CGRJAsmHE_CGRJAsmL_CGRJAsmLE_CGRJAsmLH_CGRJAsmNE_CGRJAsmNH_CGRJAsmNHE_CGRJAsmNL_CGRJAsmNLE_CGRJAsmNLH_CIJ_CIJAsm_CIJAsmE_CIJAsmH_CIJAsmHE_CIJAsmL_CIJAsmLE_CIJAsmLH_CIJAsmNE_CIJAsmNH_CIJAsmNHE_CIJAsmNL_CIJAsmNLE_CIJAsmNLH_CLGIJ_CLGIJAsm_CLGIJAsmE_CLGIJAsmH_CLGIJAsmHE_CLGIJAsmL_CLGIJAsmLE_CLGIJAsmLH_CLGIJAsmNE_CLGIJAsmNH_CLGIJAsmNHE_CLGIJAsmNL_CLGIJAsmNLE_CLGIJAsmNLH_CLGRJ_CLGRJAsm_CLGRJAsmE_CLGRJAsmH_CLGRJAsmHE_CLGRJAsmL_CLGRJAsmLE_CLGRJAsmLH_CLGRJAsmNE_CLGRJAsmNH_CLGRJAsmNHE_CLGRJAsmNL_CLGRJAsmNLE_CLGRJAsmNLH_CLIJ_CLIJAsm_CLIJAsmE_CLIJAsmH_CLIJAsmHE_CLIJAsmL_CLIJAsmLE_CLIJAsmLH_CLIJAsmNE_CLIJAsmNH_CLIJAsmNHE_CLIJAsmNL_CLIJAsmNLE_CLIJAsmNLH_CLRJ_CLRJAsm_CLRJAsmE_CLRJAsmH_CLRJAsmHE_CLRJAsmL_CLRJAsmLE_CLRJAsmLH_CLRJAsmNE_CLRJAsmNH_CLRJAsmNHE_CLRJAsmNL_CLRJAsmNLE_CLRJAsmNLH_CRJ_CRJAsm_CRJAsmE_CRJAsmH_CRJAsmHE_CRJAsmL_CRJAsmLE_CRJAsmLH_CRJAsmNE_CRJAsmNH_CRJAsmNHE_CRJAsmNL_CRJAsmNLE_CRJAsmNLH	= 11,
    CGIBCall_CGIBReturn_CGRBCall_CGRBReturn_CIBCall_CIBReturn_CLGIBCall_CLGIBReturn_CLGRBCall_CLGRBReturn_CLIBCall_CLIBReturn_CLRBCall_CLRBReturn_CRBCall_CRBReturn_CGIB_CGIBAsm_CGIBAsmE_CGIBAsmH_CGIBAsmHE_CGIBAsmL_CGIBAsmLE_CGIBAsmLH_CGIBAsmNE_CGIBAsmNH_CGIBAsmNHE_CGIBAsmNL_CGIBAsmNLE_CGIBAsmNLH_CGRB_CGRBAsm_CGRBAsmE_CGRBAsmH_CGRBAsmHE_CGRBAsmL_CGRBAsmLE_CGRBAsmLH_CGRBAsmNE_CGRBAsmNH_CGRBAsmNHE_CGRBAsmNL_CGRBAsmNLE_CGRBAsmNLH_CIB_CIBAsm_CIBAsmE_CIBAsmH_CIBAsmHE_CIBAsmL_CIBAsmLE_CIBAsmLH_CIBAsmNE_CIBAsmNH_CIBAsmNHE_CIBAsmNL_CIBAsmNLE_CIBAsmNLH_CLGIB_CLGIBAsm_CLGIBAsmE_CLGIBAsmH_CLGIBAsmHE_CLGIBAsmL_CLGIBAsmLE_CLGIBAsmLH_CLGIBAsmNE_CLGIBAsmNH_CLGIBAsmNHE_CLGIBAsmNL_CLGIBAsmNLE_CLGIBAsmNLH_CLGRB_CLGRBAsm_CLGRBAsmE_CLGRBAsmH_CLGRBAsmHE_CLGRBAsmL_CLGRBAsmLE_CLGRBAsmLH_CLGRBAsmNE_CLGRBAsmNH_CLGRBAsmNHE_CLGRBAsmNL_CLGRBAsmNLE_CLGRBAsmNLH_CLIB_CLIBAsm_CLIBAsmE_CLIBAsmH_CLIBAsmHE_CLIBAsmL_CLIBAsmLE_CLIBAsmLH_CLIBAsmNE_CLIBAsmNH_CLIBAsmNHE_CLIBAsmNL_CLIBAsmNLE_CLIBAsmNLH_CLRB_CLRBAsm_CLRBAsmE_CLRBAsmH_CLRBAsmHE_CLRBAsmL_CLRBAsmLE_CLRBAsmLH_CLRBAsmNE_CLRBAsmNH_CLRBAsmNHE_CLRBAsmNL_CLRBAsmNLE_CLRBAsmNLH_CRB_CRBAsm_CRBAsmE_CRBAsmH_CRBAsmHE_CRBAsmL_CRBAsmLE_CRBAsmLH_CRBAsmNE_CRBAsmNH_CRBAsmNHE_CRBAsmNL_CRBAsmNLE_CRBAsmNLH	= 12,
    CondTrap_Trap	= 13,
    CGIT_CGITAsm_CGITAsmE_CGITAsmH_CGITAsmHE_CGITAsmL_CGITAsmLE_CGITAsmLH_CGITAsmNE_CGITAsmNH_CGITAsmNHE_CGITAsmNL_CGITAsmNLE_CGITAsmNLH_CGRT_CGRTAsm_CGRTAsmE_CGRTAsmH_CGRTAsmHE_CGRTAsmL_CGRTAsmLE_CGRTAsmLH_CGRTAsmNE_CGRTAsmNH_CGRTAsmNHE_CGRTAsmNL_CGRTAsmNLE_CGRTAsmNLH_CIT_CITAsm_CITAsmE_CITAsmH_CITAsmHE_CITAsmL_CITAsmLE_CITAsmLH_CITAsmNE_CITAsmNH_CITAsmNHE_CITAsmNL_CITAsmNLE_CITAsmNLH_CRT_CRTAsm_CRTAsmE_CRTAsmH_CRTAsmHE_CRTAsmL_CRTAsmLE_CRTAsmLH_CRTAsmNE_CRTAsmNH_CRTAsmNHE_CRTAsmNL_CRTAsmNLE_CRTAsmNLH	= 14,
    CLGRT_CLGRTAsm_CLGRTAsmE_CLGRTAsmH_CLGRTAsmHE_CLGRTAsmL_CLGRTAsmLE_CLGRTAsmLH_CLGRTAsmNE_CLGRTAsmNH_CLGRTAsmNHE_CLGRTAsmNL_CLGRTAsmNLE_CLGRTAsmNLH_CLRT_CLRTAsm_CLRTAsmE_CLRTAsmH_CLRTAsmHE_CLRTAsmL_CLRTAsmLE_CLRTAsmLH_CLRTAsmNE_CLRTAsmNH_CLRTAsmNHE_CLRTAsmNL_CLRTAsmNLE_CLRTAsmNLH	= 15,
    CLFIT_CLFITAsm_CLFITAsmE_CLFITAsmH_CLFITAsmHE_CLFITAsmL_CLFITAsmLE_CLFITAsmLH_CLFITAsmNE_CLFITAsmNH_CLFITAsmNHE_CLFITAsmNL_CLFITAsmNLE_CLFITAsmNLH_CLGIT_CLGITAsm_CLGITAsmE_CLGITAsmH_CLGITAsmHE_CLGITAsmL_CLGITAsmLE_CLGITAsmLH_CLGITAsmNE_CLGITAsmNH_CLGITAsmNHE_CLGITAsmNL_CLGITAsmNLE_CLGITAsmNLH	= 16,
    CLGT_CLGTAsm_CLGTAsmE_CLGTAsmH_CLGTAsmHE_CLGTAsmL_CLGTAsmLE_CLGTAsmLH_CLGTAsmNE_CLGTAsmNH_CLGTAsmNHE_CLGTAsmNL_CLGTAsmNLE_CLGTAsmNLH_CLT_CLTAsm_CLTAsmE_CLTAsmH_CLTAsmHE_CLTAsmL_CLTAsmLE_CLTAsmLH_CLTAsmNE_CLTAsmNH_CLTAsmNHE_CLTAsmNL_CLTAsmNLE_CLTAsmNLH	= 17,
    BRAS	= 18,
    CallBRASL_CallBRASL_XPLINK64_BRASL	= 19,
    CallBASR_CallBASR_STACKEXT_CallBASR_XPLINK64_BAS_BASR	= 20,
    TLS_GDCALL_TLS_LDCALL	= 21,
    Return_Return_XPLINK	= 22,
    CondReturn_CondReturn_XPLINK	= 23,
    MVGHI_MVHHI_MVHI	= 24,
    MVI_MVIY	= 25,
    MVC	= 26,
    MVCL_MVCLE_MVCLU	= 27,
    MVCRL	= 28,
    COPY_TO_REGCLASS_COPY	= 29,
    EXTRACT_SUBREG	= 30,
    INSERT_SUBREG	= 31,
    REG_SEQUENCE	= 32,
    LMux_L_LFH_LRL_LY	= 33,
    LCBB	= 34,
    LG_LGRL	= 35,
    L128	= 36,
    LLIHF_LLIHH_LLIHL	= 37,
    LLILF_LLILH_LLILL	= 38,
    LGFI_LGHI	= 39,
    LHIMux_LHI	= 40,
    LR	= 41,
    LZRF_LZRG	= 42,
    LAT_LFHAT_LGAT	= 43,
    LT_LTG	= 44,
    LTGR_LTR	= 45,
    STG_STGRL	= 46,
    ST128	= 47,
    STMux_ST_STFH_STRL_STY	= 48,
    MVST	= 49,
    LOCRMux	= 50,
    LOCFHR_LOCFHRAsm_LOCFHRAsmE_LOCFHRAsmH_LOCFHRAsmHE_LOCFHRAsmL_LOCFHRAsmLE_LOCFHRAsmLH_LOCFHRAsmM_LOCFHRAsmNE_LOCFHRAsmNH_LOCFHRAsmNHE_LOCFHRAsmNL_LOCFHRAsmNLE_LOCFHRAsmNLH_LOCFHRAsmNM_LOCFHRAsmNO_LOCFHRAsmNP_LOCFHRAsmNZ_LOCFHRAsmO_LOCFHRAsmP_LOCFHRAsmZ_LOCGR_LOCGRAsm_LOCGRAsmE_LOCGRAsmH_LOCGRAsmHE_LOCGRAsmL_LOCGRAsmLE_LOCGRAsmLH_LOCGRAsmM_LOCGRAsmNE_LOCGRAsmNH_LOCGRAsmNHE_LOCGRAsmNL_LOCGRAsmNLE_LOCGRAsmNLH_LOCGRAsmNM_LOCGRAsmNO_LOCGRAsmNP_LOCGRAsmNZ_LOCGRAsmO_LOCGRAsmP_LOCGRAsmZ_LOCR_LOCRAsm_LOCRAsmE_LOCRAsmH_LOCRAsmHE_LOCRAsmL_LOCRAsmLE_LOCRAsmLH_LOCRAsmM_LOCRAsmNE_LOCRAsmNH_LOCRAsmNHE_LOCRAsmNL_LOCRAsmNLE_LOCRAsmNLH_LOCRAsmNM_LOCRAsmNO_LOCRAsmNP_LOCRAsmNZ_LOCRAsmO_LOCRAsmP_LOCRAsmZ	= 51,
    LOCHIMux_LOCGHI_LOCGHIAsm_LOCGHIAsmE_LOCGHIAsmH_LOCGHIAsmHE_LOCGHIAsmL_LOCGHIAsmLE_LOCGHIAsmLH_LOCGHIAsmM_LOCGHIAsmNE_LOCGHIAsmNH_LOCGHIAsmNHE_LOCGHIAsmNL_LOCGHIAsmNLE_LOCGHIAsmNLH_LOCGHIAsmNM_LOCGHIAsmNO_LOCGHIAsmNP_LOCGHIAsmNZ_LOCGHIAsmO_LOCGHIAsmP_LOCGHIAsmZ_LOCHHI_LOCHHIAsm_LOCHHIAsmE_LOCHHIAsmH_LOCHHIAsmHE_LOCHHIAsmL_LOCHHIAsmLE_LOCHHIAsmLH_LOCHHIAsmM_LOCHHIAsmNE_LOCHHIAsmNH_LOCHHIAsmNHE_LOCHHIAsmNL_LOCHHIAsmNLE_LOCHHIAsmNLH_LOCHHIAsmNM_LOCHHIAsmNO_LOCHHIAsmNP_LOCHHIAsmNZ_LOCHHIAsmO_LOCHHIAsmP_LOCHHIAsmZ_LOCHI_LOCHIAsm_LOCHIAsmE_LOCHIAsmH_LOCHIAsmHE_LOCHIAsmL_LOCHIAsmLE_LOCHIAsmLH_LOCHIAsmM_LOCHIAsmNE_LOCHIAsmNH_LOCHIAsmNHE_LOCHIAsmNL_LOCHIAsmNLE_LOCHIAsmNLH_LOCHIAsmNM_LOCHIAsmNO_LOCHIAsmNP_LOCHIAsmNZ_LOCHIAsmO_LOCHIAsmP_LOCHIAsmZ	= 52,
    LOCMux_LOC_LOCAsm_LOCAsmE_LOCAsmH_LOCAsmHE_LOCAsmL_LOCAsmLE_LOCAsmLH_LOCAsmM_LOCAsmNE_LOCAsmNH_LOCAsmNHE_LOCAsmNL_LOCAsmNLE_LOCAsmNLH_LOCAsmNM_LOCAsmNO_LOCAsmNP_LOCAsmNZ_LOCAsmO_LOCAsmP_LOCAsmZ_LOCFH_LOCFHAsm_LOCFHAsmE_LOCFHAsmH_LOCFHAsmHE_LOCFHAsmL_LOCFHAsmLE_LOCFHAsmLH_LOCFHAsmM_LOCFHAsmNE_LOCFHAsmNH_LOCFHAsmNHE_LOCFHAsmNL_LOCFHAsmNLE_LOCFHAsmNLH_LOCFHAsmNM_LOCFHAsmNO_LOCFHAsmNP_LOCFHAsmNZ_LOCFHAsmO_LOCFHAsmP_LOCFHAsmZ_LOCG_LOCGAsm_LOCGAsmE_LOCGAsmH_LOCGAsmHE_LOCGAsmL_LOCGAsmLE_LOCGAsmLH_LOCGAsmM_LOCGAsmNE_LOCGAsmNH_LOCGAsmNHE_LOCGAsmNL_LOCGAsmNLE_LOCGAsmNLH_LOCGAsmNM_LOCGAsmNO_LOCGAsmNP_LOCGAsmNZ_LOCGAsmO_LOCGAsmP_LOCGAsmZ	= 53,
    STOCMux_STOC_STOCAsm_STOCAsmE_STOCAsmH_STOCAsmHE_STOCAsmL_STOCAsmLE_STOCAsmLH_STOCAsmM_STOCAsmNE_STOCAsmNH_STOCAsmNHE_STOCAsmNL_STOCAsmNLE_STOCAsmNLH_STOCAsmNM_STOCAsmNO_STOCAsmNP_STOCAsmNZ_STOCAsmO_STOCAsmP_STOCAsmZ_STOCFH_STOCFHAsm_STOCFHAsmE_STOCFHAsmH_STOCFHAsmHE_STOCFHAsmL_STOCFHAsmLE_STOCFHAsmLH_STOCFHAsmM_STOCFHAsmNE_STOCFHAsmNH_STOCFHAsmNHE_STOCFHAsmNL_STOCFHAsmNLE_STOCFHAsmNLH_STOCFHAsmNM_STOCFHAsmNO_STOCFHAsmNP_STOCFHAsmNZ_STOCFHAsmO_STOCFHAsmP_STOCFHAsmZ_STOCG_STOCGAsm_STOCGAsmE_STOCGAsmH_STOCGAsmHE_STOCGAsmL_STOCGAsmLE_STOCGAsmLH_STOCGAsmM_STOCGAsmNE_STOCGAsmNH_STOCGAsmNHE_STOCGAsmNL_STOCGAsmNLE_STOCGAsmNLH_STOCGAsmNM_STOCGAsmNO_STOCGAsmNP_STOCGAsmNZ_STOCGAsmO_STOCGAsmP_STOCGAsmZ	= 54,
    SELRMux	= 55,
    SELFHR_SELFHRAsm_SELFHRAsmE_SELFHRAsmH_SELFHRAsmHE_SELFHRAsmL_SELFHRAsmLE_SELFHRAsmLH_SELFHRAsmM_SELFHRAsmNE_SELFHRAsmNH_SELFHRAsmNHE_SELFHRAsmNL_SELFHRAsmNLE_SELFHRAsmNLH_SELFHRAsmNM_SELFHRAsmNO_SELFHRAsmNP_SELFHRAsmNZ_SELFHRAsmO_SELFHRAsmP_SELFHRAsmZ_SELGR_SELGRAsm_SELGRAsmE_SELGRAsmH_SELGRAsmHE_SELGRAsmL_SELGRAsmLE_SELGRAsmLH_SELGRAsmM_SELGRAsmNE_SELGRAsmNH_SELGRAsmNHE_SELGRAsmNL_SELGRAsmNLE_SELGRAsmNLH_SELGRAsmNM_SELGRAsmNO_SELGRAsmNP_SELGRAsmNZ_SELGRAsmO_SELGRAsmP_SELGRAsmZ_SELR_SELRAsm_SELRAsmE_SELRAsmH_SELRAsmHE_SELRAsmL_SELRAsmLE_SELRAsmLH_SELRAsmM_SELRAsmNE_SELRAsmNH_SELRAsmNHE_SELRAsmNL_SELRAsmNLE_SELRAsmNLH_SELRAsmNM_SELRAsmNO_SELRAsmNP_SELRAsmNZ_SELRAsmO_SELRAsmP_SELRAsmZ	= 56,
    LBR_LGR_LHR	= 57,
    LGBR_LGFR_LGHR	= 58,
    LTGF	= 59,
    LTGFR	= 60,
    LBMux_LB_LBH	= 61,
    LH_LHY	= 62,
    LHMux_LHH_LHRL	= 63,
    LGB_LGF_LGH	= 64,
    LGFRL_LGHRL	= 65,
    LLCRMux_LLCR	= 66,
    LLHRMux_LLHR	= 67,
    LLGCR_LLGFR_LLGHR_LLGTR	= 68,
    LLCMux_LLC	= 69,
    LLHMux_LLH	= 70,
    LLCH_LLHH	= 71,
    LLHRL	= 72,
    LLGC_LLGF_LLGFRL_LLGH_LLGHRL_LLGT	= 73,
    LLZRGF	= 74,
    LLGFAT_LLGTAT	= 75,
    STCMux_STC_STCH_STCY	= 76,
    STHMux_STH_STHH_STHRL_STHY	= 77,
    STCM_STCMH_STCMY	= 78,
    LM_LMG_LMH_LMY	= 79,
    LMD	= 80,
    STM_STMG_STMH_STMY	= 81,
    LRVGR_LRVR	= 82,
    LRV_LRVG_LRVH	= 83,
    STRV_STRVG_STRVH	= 84,
    MVCIN	= 85,
    LA_LARL_LAY	= 86,
    GOT	= 87,
    LLXAB_LLXAF_LLXAG_LLXAH_LLXAQ_LXAB_LXAF_LXAG_LXAH_LXAQ	= 88,
    LPGR_LPR	= 89,
    LNGFR_LPGFR	= 90,
    LNGR_LNR	= 91,
    LCGR_LCR	= 92,
    LCGFR	= 93,
    IC_ICY	= 94,
    IC32_IC32Y	= 95,
    ICM_ICMH_ICMY	= 96,
    IIFMux_IIHMux_IILMux	= 97,
    IIHF64_IIHF	= 98,
    IIHH64_IIHH	= 99,
    IIHL64_IIHL	= 100,
    IILF64_IILF	= 101,
    IILH64_IILH	= 102,
    IILL64_IILL	= 103,
    A_AY	= 104,
    AH_AHY	= 105,
    AIH	= 106,
    AFIMux_AFI	= 107,
    AG	= 108,
    AGFI	= 109,
    AGHI_AGHIK	= 110,
    AGR_AGRK	= 111,
    AHI_AHIK	= 112,
    AHIMux_AHIMuxK	= 113,
    AL_ALY	= 114,
    ALFI_ALHSIK	= 115,
    ALG_ALGF	= 116,
    ALGHSIK	= 117,
    ALGFI_ALGFR	= 118,
    ALGR_ALGRK	= 119,
    ALR_ALRK	= 120,
    AR_ARK	= 121,
    AHHHR_ALHHHR	= 122,
    AHHLR_ALHHLR	= 123,
    ALSIH_ALSIHN	= 124,
    AGSI_ALGSI_ALSI_ASI	= 125,
    ALC_ALCG	= 126,
    ALCGR_ALCR	= 127,
    AGF_AGH	= 128,
    AGFR	= 129,
    S_SG_SY	= 130,
    SH_SHY	= 131,
    SGR_SGRK	= 132,
    SLFI	= 133,
    SL_SLG_SLGF_SLY	= 134,
    SLGFI_SLGFR	= 135,
    SLGR_SLGRK	= 136,
    SLR_SLRK	= 137,
    SR_SRK	= 138,
    SHHHR_SLHHHR	= 139,
    SHHLR_SLHHLR	= 140,
    SLB_SLBG	= 141,
    SLBGR_SLBR	= 142,
    SGF_SGH	= 143,
    SGFR	= 144,
    N_NG_NY	= 145,
    NGR_NGRK	= 146,
    NIFMux_NIHMux_NILMux	= 147,
    NI_NIY	= 148,
    NIHF64_NIHF	= 149,
    NIHH64_NIHH	= 150,
    NIHL64_NIHL	= 151,
    NILF64_NILF	= 152,
    NILH64_NILH	= 153,
    NILL64_NILL	= 154,
    NR_NRK	= 155,
    NC	= 156,
    O_OG_OY	= 157,
    OGR_OGRK	= 158,
    OI_OIY	= 159,
    OIFMux_OIHMux_OILMux	= 160,
    OIHF64_OIHF	= 161,
    OIHH64_OIHH	= 162,
    OIHL64_OIHL	= 163,
    OILF64_OILF	= 164,
    OILH64_OILH	= 165,
    OILL64_OILL	= 166,
    OR_ORK	= 167,
    OC	= 168,
    X_XG_XY	= 169,
    XI_XIY	= 170,
    XIFMux	= 171,
    XGR_XGRK	= 172,
    XIHF64_XIHF	= 173,
    XILF64_XILF	= 174,
    XR_XRK	= 175,
    XC	= 176,
    NCGRK_NCRK	= 177,
    OCGRK_OCRK	= 178,
    NNGRK_NNRK	= 179,
    NOGRK_NORK	= 180,
    NOTGR_NOTR	= 181,
    NXGRK_NXRK	= 182,
    MS_MSGF_MSY	= 183,
    MSFI_MSR	= 184,
    MSG	= 185,
    MSGR	= 186,
    MSGFI_MSGFR	= 187,
    MLG	= 188,
    MLGR	= 189,
    MGHI	= 190,
    MHI	= 191,
    MH_MHY	= 192,
    MLR_MR	= 193,
    M_MFY_ML	= 194,
    MGH	= 195,
    MG	= 196,
    MGRK	= 197,
    MSC	= 198,
    MSGC	= 199,
    MSRKC	= 200,
    MSGRKC	= 201,
    DR	= 202,
    D	= 203,
    DSGFR_DSGR	= 204,
    DSG_DSGF	= 205,
    DLR	= 206,
    DLGR	= 207,
    DL_DLG	= 208,
    SLL_SLLG_SLLK	= 209,
    SRL_SRLG_SRLK	= 210,
    SRA_SRAG_SRAK	= 211,
    SLA_SLAG_SLAK	= 212,
    SLDA_SLDL_SRDA_SRDL	= 213,
    RLL_RLLG	= 214,
    RISBHH_RISBHHOpt_RISBHL_RISBHLOpt_RISBHG_RISBHGOpt	= 215,
    RISBLH_RISBLHOpt_RISBLL_RISBLLOpt_RISBLG_RISBLGOpt	= 216,
    RISBG_RISBG32_RISBG32Opt_RISBGN_RISBGNOpt_RISBGNZ_RISBGNZOpt_RISBGOpt_RISBGZ_RISBGZOpt	= 217,
    RISBMux	= 218,
    RNSBG_RNSBGOpt_ROSBG_ROSBGOpt_RXSBG_RXSBGOpt	= 219,
    CMux_C_CG_CY	= 220,
    CRL	= 221,
    CFIMux_CHIMux_CFI_CHI	= 222,
    CGFI_CGHI	= 223,
    CGHSI_CGRL	= 224,
    CGR_CR	= 225,
    CIH	= 226,
    CHF	= 227,
    CHSI	= 228,
    CLMux_CL_CLY	= 229,
    CLFHSI	= 230,
    CLFIMux_CLFI	= 231,
    CLG	= 232,
    CLGHRL_CLGHSI	= 233,
    CLGF	= 234,
    CLGFRL	= 235,
    CLGFI_CLGFR	= 236,
    CLGR	= 237,
    CLGRL	= 238,
    CLHF	= 239,
    CLHHSI_CLHRL	= 240,
    CLIH	= 241,
    CLI_CLIY	= 242,
    CLR	= 243,
    CLRL	= 244,
    CHHR_CLHHR	= 245,
    CHLR_CLHLR	= 246,
    CH_CHY	= 247,
    CHRL	= 248,
    CGH	= 249,
    CGHRL	= 250,
    CHHSI	= 251,
    CGF	= 252,
    CGFRL	= 253,
    CGFR	= 254,
    CLC	= 255,
    CLCL_CLCLE_CLCLU	= 256,
    CLST	= 257,
    TM_TMY	= 258,
    TMHMux_TMLMux	= 259,
    TMHH64_TMHH	= 260,
    TMHL64_TMHL	= 261,
    TMLH64_TMLH	= 262,
    TMLL64_TMLL	= 263,
    CLM_CLMH_CLMY	= 264,
    PFD_PFDRL	= 265,
    BPP	= 266,
    BPRP	= 267,
    NIAI	= 268,
    Serialize	= 269,
    LAA_LAAG	= 270,
    LAAL_LAALG	= 271,
    LAN_LANG	= 272,
    LAO_LAOG	= 273,
    LAX_LAXG	= 274,
    TS	= 275,
    CS_CSG_CSY	= 276,
    CDS_CDSY	= 277,
    CDSG	= 278,
    CSST	= 279,
    PLO	= 280,
    LPQ	= 281,
    STPQ	= 282,
    LPD_LPDG	= 283,
    CAL_CALG_CALGF	= 284,
    PFCR	= 285,
    TR	= 286,
    TRT	= 287,
    TRTR	= 288,
    TRE	= 289,
    TRTE_TRTEOpt_TRTRE_TRTREOpt	= 290,
    TROO_TROOOpt_TROT_TROTOpt_TRTO_TRTOOpt_TRTT_TRTTOpt	= 291,
    CU12_CU12Opt_CU14_CU14Opt_CU21_CU21Opt_CU24_CU24Opt_CU41_CU42	= 292,
    CUTFU_CUTFUOpt_CUUTF_CUUTFOpt	= 293,
    KM_KMA_KMC_KMCTR_KMF_KMO	= 294,
    KDSA_KIMD_KIMDOpt_KLMD_KLMDOpt_KMAC	= 295,
    PCC_PPNO_PRNO	= 296,
    LGG	= 297,
    LLGFSG	= 298,
    LGSC_STGSC	= 299,
    CVBG	= 300,
    CVB_CVBY	= 301,
    CVDG	= 302,
    CVD_CVDY	= 303,
    MVN_MVO_MVZ	= 304,
    PACK_PKA_PKU	= 305,
    UNPKA_UNPKU	= 306,
    UNPK	= 307,
    AP_SP_ZAP	= 308,
    MP	= 309,
    DP	= 310,
    SRP	= 311,
    CP	= 312,
    TP	= 313,
    ED_EDMK	= 314,
    CPYA_EAR_SAR	= 315,
    LAE_LAEY	= 316,
    LAM_LAMY	= 317,
    STAM_STAMY	= 318,
    IPM	= 319,
    SPM	= 320,
    BAL_BALR	= 321,
    TAM	= 322,
    SAM24_SAM31_SAM64	= 323,
    BSM	= 324,
    BASSM	= 325,
    TBEGIN_TBEGINC	= 326,
    TEND	= 327,
    TABORT	= 328,
    ETND	= 329,
    NTSTG	= 330,
    PPA	= 331,
    CLZG_CTZG	= 332,
    FLOGR	= 333,
    POPCNT_POPCNTOpt	= 334,
    BDEPG_BEXTG	= 335,
    SRST_SRSTU	= 336,
    CUSE	= 337,
    CFC	= 338,
    UPT	= 339,
    CKSM	= 340,
    CMPSC	= 341,
    SORTL	= 342,
    DFLTCC	= 343,
    NNPA	= 344,
    EX_EXRL	= 345,
    InsnE_InsnRI_InsnRIE_InsnRIL_InsnRILU_InsnRIS_InsnRR_InsnRRE_InsnRRF_InsnRRS_InsnRS_InsnRSE_InsnRSI_InsnRSY_InsnRX_InsnRXE_InsnRXF_InsnRXY_InsnS_InsnSI_InsnSIL_InsnSIY_InsnSS_InsnSSE_InsnSSF_InsnVRI_InsnVRR_InsnVRS_InsnVRV_InsnVRX_InsnVSI	= 346,
    LZDR_LZER_LZER_16	= 347,
    LZXR	= 348,
    LER_LER16	= 349,
    LDGR_LDR_LDR16_LDR32	= 350,
    LGDR	= 351,
    LXR	= 352,
    LTDBR_LTEBR	= 353,
    LTXBR	= 354,
    CPSDRdd_CPSDRdh_CPSDRds_CPSDRhd_CPSDRhh_CPSDRhs_CPSDRsd_CPSDRsh_CPSDRss	= 355,
    LE_LE16_LE16Y_LEY	= 356,
    LD_LDE32_LDY	= 357,
    LX	= 358,
    STD_STDY_STE_STE16_STE16Y_STEY	= 359,
    STX	= 360,
    LEDBR_LEDBRA	= 361,
    LDXBR_LDXBRA_LEXBR_LEXBRA	= 362,
    LDEB	= 363,
    LDEBR	= 364,
    LXDB_LXEB	= 365,
    LXDBR_LXEBR	= 366,
    CDFBR_CDFBRA_CDGBR_CDGBRA_CEFBR_CEFBRA_CEGBR_CEGBRA	= 367,
    CXFBR_CXFBRA_CXGBR_CXGBRA	= 368,
    CDLFBR_CDLGBR_CELFBR_CELGBR	= 369,
    CXLFBR_CXLGBR	= 370,
    CFDBR_CFDBRA_CFEBR_CFEBRA_CGDBR_CGDBRA_CGEBR_CGEBRA	= 371,
    CFXBR_CFXBRA_CGXBR_CGXBRA	= 372,
    CLFEBR	= 373,
    CLFDBR	= 374,
    CLGDBR_CLGEBR	= 375,
    CLFXBR_CLGXBR	= 376,
    LCDBR_LCEBR_LNDBR_LNEBR_LPDBR_LPEBR	= 377,
    LCDFR_LCDFR_16_LCDFR_32_LNDFR_LNDFR_16_LNDFR_32_LPDFR_LPDFR_16_LPDFR_32	= 378,
    LCXBR_LNXBR_LPXBR	= 379,
    SQDB_SQEB	= 380,
    SQEBR	= 381,
    SQDBR	= 382,
    SQXBR	= 383,
    FIDBR_FIDBRA_FIEBR_FIEBRA	= 384,
    FIXBR_FIXBRA	= 385,
    ADB_AEB	= 386,
    ADBR_AEBR	= 387,
    AXBR	= 388,
    SDB_SEB	= 389,
    SDBR_SEBR	= 390,
    SXBR	= 391,
    MDB_MDEB_MEEB	= 392,
    MDBR_MDEBR_MEEBR	= 393,
    MXDB	= 394,
    MXDBR	= 395,
    MXBR	= 396,
    MAEB_MSEB	= 397,
    MAEBR_MSEBR	= 398,
    MADB_MSDB	= 399,
    MADBR_MSDBR	= 400,
    DEB	= 401,
    DDB	= 402,
    DEBR	= 403,
    DDBR	= 404,
    DXBR	= 405,
    DIDBR_DIEBR	= 406,
    CDB_CEB_KDB_KEB	= 407,
    CDBR_CEBR_KDBR_KEBR	= 408,
    CXBR_KXBR	= 409,
    TCDB_TCEB	= 410,
    TCXB	= 411,
    EFPC	= 412,
    STFPC	= 413,
    SFPC	= 414,
    LFPC	= 415,
    SFASR	= 416,
    LFAS	= 417,
    SRNM_SRNMB_SRNMT	= 418,
    LTDR_LTER	= 419,
    LTXR	= 420,
    LEDR_LRER	= 421,
    LEXR	= 422,
    LDXR_LRDR	= 423,
    LDE	= 424,
    LDER	= 425,
    LXD_LXE	= 426,
    LXDR_LXER	= 427,
    CDFR_CDGR_CEFR_CEGR	= 428,
    CXFR_CXGR	= 429,
    CFDR_CFER_CGDR_CGER	= 430,
    CFXR_CGXR	= 431,
    THDER_THDR	= 432,
    TBDR_TBEDR	= 433,
    LCDR_LCER_LNDR_LNER_LPDR_LPER	= 434,
    LCXR_LNXR_LPXR	= 435,
    HDR_HER	= 436,
    SQD_SQE	= 437,
    SQER	= 438,
    SQDR	= 439,
    SQXR	= 440,
    FIDR_FIER	= 441,
    FIXR	= 442,
    AD_AE_AU_AW	= 443,
    ADR_AER_AUR_AWR	= 444,
    AXR	= 445,
    SD_SE_SU_SW	= 446,
    SDR_SER_SUR_SWR	= 447,
    SXR	= 448,
    MD_MDE_ME_MEE	= 449,
    MDER_MDR_MEER_MER	= 450,
    MXD	= 451,
    MXDR	= 452,
    MXR	= 453,
    MY	= 454,
    MYH_MYL	= 455,
    MYR	= 456,
    MYHR_MYLR	= 457,
    MAD_MAE_MSD_MSE	= 458,
    MADR_MAER_MSDR_MSER	= 459,
    MAY	= 460,
    MAYH_MAYL	= 461,
    MAYR	= 462,
    MAYHR_MAYLR	= 463,
    DE	= 464,
    DD	= 465,
    DER	= 466,
    DDR	= 467,
    DXR	= 468,
    CD_CE	= 469,
    CDR_CER	= 470,
    CXR	= 471,
    LTDTR	= 472,
    LTXTR	= 473,
    LEDTR	= 474,
    LDXTR	= 475,
    LDETR	= 476,
    LXDTR	= 477,
    CDFTR	= 478,
    CDGTR_CDGTRA	= 479,
    CXFTR	= 480,
    CXGTR_CXGTRA	= 481,
    CDLFTR	= 482,
    CDLGTR	= 483,
    CXLFTR	= 484,
    CXLGTR	= 485,
    CFDTR_CGDTR_CGDTRA	= 486,
    CFXTR_CGXTR_CGXTRA	= 487,
    CLFDTR_CLGDTR	= 488,
    CLFXTR_CLGXTR	= 489,
    CDSTR_CDUTR	= 490,
    CXSTR_CXUTR	= 491,
    CSDTR_CUDTR	= 492,
    CSXTR_CUXTR	= 493,
    CDZT	= 494,
    CXZT	= 495,
    CZDT	= 496,
    CZXT	= 497,
    CDPT	= 498,
    CXPT	= 499,
    CPDT	= 500,
    CPXT	= 501,
    PFPO	= 502,
    FIDTR	= 503,
    FIXTR	= 504,
    EEDTR	= 505,
    EEXTR	= 506,
    ESDTR	= 507,
    ESXTR	= 508,
    ADTR_ADTRA	= 509,
    AXTR_AXTRA	= 510,
    SDTR_SDTRA	= 511,
    SXTR_SXTRA	= 512,
    MDTR_MDTRA	= 513,
    MXTR_MXTRA	= 514,
    DDTR_DDTRA	= 515,
    DXTR_DXTRA	= 516,
    QADTR	= 517,
    QAXTR	= 518,
    RRDTR	= 519,
    RRXTR	= 520,
    SLDT_SRDT	= 521,
    SLXT_SRXT	= 522,
    IEDTR	= 523,
    IEXTR	= 524,
    CDTR_KDTR	= 525,
    CXTR_KXTR	= 526,
    CEDTR	= 527,
    CEXTR	= 528,
    TDCDT_TDCET_TDGDT_TDGET	= 529,
    TDCXT_TDGXT	= 530,
    VLR16_VLR32_VLR64_VLR	= 531,
    VLGV_VLGVB_VLGVF_VLGVG_VLGVH	= 532,
    VLVG_VLVGB_VLVGF_VLVGG_VLVGH	= 533,
    VLVGP32_VLVGP	= 534,
    VZERO	= 535,
    VONE	= 536,
    VGBM	= 537,
    VGM_VGMB_VGMF_VGMG_VGMH	= 538,
    VREPI_VREPIB_VREPIF_VREPIG_VREPIH	= 539,
    VLEIB_VLEIF_VLEIG_VLEIH	= 540,
    VL_VLAlign	= 541,
    VLBB_VLL	= 542,
    VL16_VL32_VL64	= 543,
    VLLEZ_VLLEZB_VLLEZF_VLLEZG_VLLEZH_VLLEZLF	= 544,
    VLREP_VLREPB_VLREPF_VLREPG_VLREPH	= 545,
    VLEB_VLEF_VLEG_VLEH	= 546,
    VGEF_VGEG	= 547,
    VLM_VLMAlign	= 548,
    VLRL_VLRLR	= 549,
    VST16_VST32_VST64_VST_VSTAlign_VSTL	= 550,
    VSTEF_VSTEG	= 551,
    VSTEB_VSTEH	= 552,
    VSTM_VSTMAlign	= 553,
    VSCEF_VSCEG	= 554,
    VSTRL_VSTRLR	= 555,
    VLBR_VLBRF_VLBRG_VLBRH_VLBRQ	= 556,
    VLER_VLERF_VLERG_VLERH	= 557,
    VLEBRF_VLEBRG_VLEBRH	= 558,
    VLLEBRZ_VLLEBRZE_VLLEBRZF_VLLEBRZG_VLLEBRZH	= 559,
    VLBRREP_VLBRREPF_VLBRREPG_VLBRREPH	= 560,
    VSTBR_VSTBRF_VSTBRG_VSTBRH_VSTBRQ	= 561,
    VSTER_VSTERF_VSTERG_VSTERH	= 562,
    VSTEBRH	= 563,
    VSTEBRF_VSTEBRG	= 564,
    VMRH_VMRHB_VMRHF_VMRHG_VMRHH	= 565,
    VMRL_VMRLB_VMRLF_VMRLG_VMRLH	= 566,
    VPERM	= 567,
    VPDI	= 568,
    VBPERM	= 569,
    VREP_VREPB_VREPF_VREPG_VREPH	= 570,
    VSEL	= 571,
    VBLEND_VBLENDB_VBLENDF_VBLENDG_VBLENDH_VBLENDQ	= 572,
    VPK_VPKF_VPKG_VPKH	= 573,
    VPKS_VPKSF_VPKSG_VPKSH	= 574,
    VPKSFS_VPKSGS_VPKSHS	= 575,
    VPKLS_VPKLSF_VPKLSG_VPKLSH	= 576,
    VPKLSFS_VPKLSGS_VPKLSHS	= 577,
    VSEG_VSEGB_VSEGF_VSEGH	= 578,
    VGEM_VGEMB_VGEMF_VGEMG_VGEMH_VGEMQ	= 579,
    VUPH_VUPHB_VUPHF_VUPHG_VUPHH	= 580,
    VUPL_VUPLB_VUPLF_VUPLG	= 581,
    VUPLH_VUPLHB_VUPLHF_VUPLHG_VUPLHH_VUPLHW	= 582,
    VUPLL_VUPLLB_VUPLLF_VUPLLG_VUPLLH	= 583,
    VA_VAB_VAC_VACQ_VAF_VAG_VAH_VAQ	= 584,
    VACC_VACCB_VACCC_VACCCQ_VACCF_VACCG_VACCH_VACCQ	= 585,
    VAVG_VAVGB_VAVGF_VAVGG_VAVGH_VAVGQ	= 586,
    VAVGL_VAVGLB_VAVGLF_VAVGLG_VAVGLH_VAVGLQ	= 587,
    VN_VNC_VNN_VNO_VNX	= 588,
    VO_VOC	= 589,
    VCKSM	= 590,
    VCLZ_VCLZB_VCLZF_VCLZG_VCLZH_VCLZQ	= 591,
    VCTZ_VCTZB_VCTZF_VCTZG_VCTZH_VCTZQ	= 592,
    VD_VDF_VDG_VDL_VDLF_VDLG_VDLQ_VDQ	= 593,
    VEVAL	= 594,
    VX	= 595,
    VGFM	= 596,
    VGFMA_VGFMAB_VGFMAF_VGFMAG_VGFMAH	= 597,
    VGFMB_VGFMF_VGFMG_VGFMH	= 598,
    VLC_VLCB_VLCF_VLCG_VLCH_VLCQ	= 599,
    VLP_VLPB_VLPF_VLPG_VLPH_VLPQ	= 600,
    VMX_VMXB_VMXF_VMXG_VMXH_VMXQ	= 601,
    VMXL_VMXLB_VMXLF_VMXLG_VMXLH_VMXLQ	= 602,
    VMN_VMNB_VMNF_VMNG_VMNH_VMNQ	= 603,
    VMNL_VMNLB_VMNLF_VMNLG_VMNLH_VMNLQ	= 604,
    VMAL_VMALB_VMALF_VMALG_VMALQ	= 605,
    VMALE_VMALEB_VMALEF_VMALEG_VMALEH	= 606,
    VMALH_VMALHB_VMALHF_VMALHG_VMALHH_VMALHQ_VMALHW	= 607,
    VMALO_VMALOB_VMALOF_VMALOG_VMALOH	= 608,
    VMAO_VMAOB_VMAOF_VMAOG_VMAOH	= 609,
    VMAE_VMAEB_VMAEF_VMAEG_VMAEH	= 610,
    VMAH_VMAHB_VMAHF_VMAHG_VMAHH_VMAHQ	= 611,
    VME_VMEB_VMEF_VMEG_VMEH	= 612,
    VMH_VMHB_VMHF_VMHG_VMHH_VMHQ	= 613,
    VML_VMLB_VMLF_VMLG_VMLQ	= 614,
    VMLE_VMLEB_VMLEF_VMLEG_VMLEH	= 615,
    VMLH_VMLHB_VMLHF_VMLHG_VMLHH_VMLHQ_VMLHW	= 616,
    VMLO_VMLOB_VMLOF_VMLOG_VMLOH	= 617,
    VMO_VMOB_VMOF_VMOG_VMOH	= 618,
    VMSL_VMSLG	= 619,
    VPOPCT_VPOPCTB_VPOPCTF_VPOPCTG_VPOPCTH	= 620,
    VR_VRF_VRG_VRL_VRLF_VRLG_VRLQ_VRQ	= 621,
    VERLL_VERLLB_VERLLF_VERLLG_VERLLH	= 622,
    VERLLV_VERLLVB_VERLLVF_VERLLVG_VERLLVH	= 623,
    VERIM_VERIMB_VERIMF_VERIMG_VERIMH	= 624,
    VESL_VESLB_VESLF_VESLG_VESLH	= 625,
    VESLV_VESLVB_VESLVF_VESLVG_VESLVH	= 626,
    VESRA_VESRAB_VESRAF_VESRAG_VESRAH	= 627,
    VESRAV_VESRAVB_VESRAVF_VESRAVG_VESRAVH	= 628,
    VESRL_VESRLB_VESRLF_VESRLG_VESRLH	= 629,
    VESRLV_VESRLVB_VESRLVF_VESRLVG_VESRLVH	= 630,
    VSL_VSLDB	= 631,
    VSLB	= 632,
    VSRA_VSRL	= 633,
    VSRAB_VSRLB	= 634,
    VSLD	= 635,
    VSRD	= 636,
    VSB_VSBCBI_VSBCBIQ_VSBI_VSBIQ	= 637,
    VSCBI_VSCBIB_VSCBIF_VSCBIG_VSCBIH_VSCBIQ	= 638,
    VS_VSF_VSG_VSH_VSQ	= 639,
    VSUM_VSUMB_VSUMH	= 640,
    VSUMG_VSUMGF_VSUMGH	= 641,
    VSUMQ_VSUMQF_VSUMQG	= 642,
    VEC_VECB_VECF_VECG_VECH_VECQ	= 643,
    VECL_VECLB_VECLF_VECLG_VECLH_VECLQ	= 644,
    VCEQ_VCEQB_VCEQF_VCEQG_VCEQH_VCEQQ	= 645,
    VCEQBS_VCEQFS_VCEQGS_VCEQHS_VCEQQS	= 646,
    VCH_VCHB_VCHF_VCHG_VCHH_VCHQ	= 647,
    VCHBS_VCHFS_VCHGS_VCHHS_VCHQS	= 648,
    VCHL_VCHLB_VCHLF_VCHLG_VCHLH_VCHLQ	= 649,
    VCHLBS_VCHLFS_VCHLGS_VCHLHS_VCHLQS	= 650,
    VTM	= 651,
    VCFPL_VCFPS	= 652,
    VCDG_VCDLG	= 653,
    VCDGB_VCDLGB	= 654,
    WCDGB_WCDLGB	= 655,
    VCEFB_VCELFB	= 656,
    WCEFB_WCELFB	= 657,
    VCLFP_VCSFP	= 658,
    VCGD_VCLGD	= 659,
    VCGDB_VCLGDB	= 660,
    WCGDB_WCLGDB	= 661,
    VCFEB_VCLFEB	= 662,
    WCFEB_WCLFEB	= 663,
    VLDE_VLED	= 664,
    VLDEB_VLEDB	= 665,
    WLDEB_WLEDB	= 666,
    VFLL_VFLR	= 667,
    VFLLS_VFLRD	= 668,
    WFLLS_WFLRD	= 669,
    WFLLD	= 670,
    WFLRX	= 671,
    VFI_VFIDB	= 672,
    WFIDB	= 673,
    VFISB	= 674,
    WFISB	= 675,
    WFIXB	= 676,
    VFPSO	= 677,
    VFPSODB_WFPSODB	= 678,
    VFPSOSB_WFPSOSB	= 679,
    WFPSOXB	= 680,
    VFLCDB_VFLNDB_VFLPDB_WFLCDB_WFLNDB_WFLPDB	= 681,
    VFLCSB_VFLNSB_VFLPSB_WFLCSB_WFLNSB_WFLPSB	= 682,
    WFLCXB_WFLNXB_WFLPXB	= 683,
    VFMAX_VFMIN	= 684,
    VFMAXDB_VFMINDB	= 685,
    WFMAXDB_WFMINDB	= 686,
    VFMAXSB_VFMINSB	= 687,
    WFMAXSB_WFMINSB	= 688,
    WFMAXXB_WFMINXB	= 689,
    VFTCI	= 690,
    VFTCIDB_WFTCIDB	= 691,
    VFTCISB_WFTCISB	= 692,
    WFTCIXB	= 693,
    VFA_VFS	= 694,
    VFADB_VFSDB	= 695,
    WFADB_WFSDB	= 696,
    VFASB_VFSSB	= 697,
    WFASB_WFSSB	= 698,
    WFAXB_WFSXB	= 699,
    VFM_VFMDB	= 700,
    WFMDB_WFMSB	= 701,
    VFMSB	= 702,
    WFMXB	= 703,
    VFMA_VFMS_VFNMA_VFNMS	= 704,
    VFMADB_VFMSDB_VFNMADB_VFNMSDB	= 705,
    WFMADB_WFMSDB_WFNMADB_WFNMSDB	= 706,
    VFMASB_VFMSSB_VFNMASB_VFNMSSB	= 707,
    WFMASB_WFMSSB_WFNMASB_WFNMSSB	= 708,
    WFMAXB_WFMSXB_WFNMAXB_WFNMSXB	= 709,
    VFD	= 710,
    VFDDB_WFDDB	= 711,
    WFDSB	= 712,
    VFDSB	= 713,
    WFDXB	= 714,
    VFSQ	= 715,
    VFSQDB_WFSQDB	= 716,
    WFSQSB	= 717,
    VFSQSB	= 718,
    WFSQXB	= 719,
    VFCE_VFCH_VFCHE	= 720,
    VFCEDB_VFCHDB_VFCHEDB_VFKEDB_VFKHDB_VFKHEDB	= 721,
    WFCEDB_WFCHDB_WFCHEDB	= 722,
    WFKEDB_WFKHDB_WFKHEDB	= 723,
    VFCESB_VFCHESB_VFCHSB_VFKESB_VFKHESB_VFKHSB	= 724,
    WFCESB_WFCHESB_WFCHSB	= 725,
    WFKESB_WFKHESB_WFKHSB	= 726,
    WFCEXB_WFCHEXB_WFCHXB	= 727,
    WFKEXB_WFKHEXB_WFKHXB	= 728,
    VFCEDBS_VFCHDBS_VFCHEDBS	= 729,
    VFKEDBS_VFKHDBS_VFKHEDBS	= 730,
    WFCEDBS_WFCHDBS_WFCHEDBS_WFKEDBS_WFKHDBS_WFKHEDBS	= 731,
    VFCESBS_VFCHESBS_VFCHSBS_VFKESBS_VFKHESBS_VFKHSBS	= 732,
    WFCESBS_WFCHESBS_WFCHSBS	= 733,
    WFKESBS_WFKHESBS_WFKHSBS	= 734,
    WFCEXBS_WFCHEXBS_WFCHXBS	= 735,
    WFKEXBS_WFKHEXBS_WFKHXBS	= 736,
    WFC_WFK	= 737,
    WFCDB_WFKDB	= 738,
    WFCSB_WFKSB	= 739,
    WFCXB_WFKXB	= 740,
    LEFR_LEFR_16	= 741,
    LFER_LFER_16	= 742,
    VFAE_VFAEB	= 743,
    VFAEF_VFAEH	= 744,
    VFAEBS_VFAEFS_VFAEHS	= 745,
    VFAEZB_VFAEZF_VFAEZH	= 746,
    VFAEZBS_VFAEZFS_VFAEZHS	= 747,
    VFEE_VFEEB_VFEEF_VFEEH_VFEEZB_VFEEZF_VFEEZH	= 748,
    VFEEBS_VFEEFS_VFEEHS_VFEEZBS_VFEEZFS_VFEEZHS	= 749,
    VFENE_VFENEB_VFENEF_VFENEH_VFENEZB_VFENEZF_VFENEZH	= 750,
    VFENEBS_VFENEFS_VFENEHS_VFENEZBS_VFENEZFS_VFENEZHS	= 751,
    VISTR_VISTRB_VISTRF_VISTRH	= 752,
    VISTRBS_VISTRFS_VISTRHS	= 753,
    VSTRC_VSTRCB_VSTRCF_VSTRCH	= 754,
    VSTRCBS_VSTRCFS_VSTRCHS	= 755,
    VSTRCZB_VSTRCZF_VSTRCZH	= 756,
    VSTRCZBS_VSTRCZFS_VSTRCZHS	= 757,
    VSTRS_VSTRSB_VSTRSF_VSTRSH	= 758,
    VSTRSZB_VSTRSZF_VSTRSZH	= 759,
    VCFN	= 760,
    VCLFNH_VCLFNL	= 761,
    VCNF_VCRNF	= 762,
    VLIP	= 763,
    VPKZ	= 764,
    VUPKZ	= 765,
    VCVB_VCVBG_VCVBGOpt_VCVBOpt_VCVBQ	= 766,
    VCVD_VCVDG_VCVDQ	= 767,
    VAP_VSP	= 768,
    VMP_VMSP	= 769,
    VDP_VRP	= 770,
    VSDP	= 771,
    VSRP_VSRPR	= 772,
    VPSOP	= 773,
    VCP_VTP_VTPOpt_VTZ	= 774,
    VSCHDP_VSCHP_VSCHSP_VSCHXP	= 775,
    VSCSHP	= 776,
    VCSPH	= 777,
    VCLZDP	= 778,
    VPKZR	= 779,
    VUPKZH	= 780,
    VUPKZL	= 781,
    EPSW	= 782,
    LPSW_LPSWE_LPSWEY	= 783,
    IPK	= 784,
    SPKA	= 785,
    SSM	= 786,
    STNSM_STOSM	= 787,
    IAC	= 788,
    SAC_SACF	= 789,
    LCTL_LCTLG	= 790,
    STCTG_STCTL	= 791,
    EPAIR_EPAR_ESAIR_ESAR	= 792,
    SSAIR_SSAR	= 793,
    ESEA	= 794,
    SPX_STPX	= 795,
    LBEAR	= 796,
    STBEAR	= 797,
    ISKE	= 798,
    IVSK	= 799,
    SSKE_SSKEOpt	= 800,
    RRBE_RRBM	= 801,
    IRBM	= 802,
    PFMF	= 803,
    TB	= 804,
    PGIN	= 805,
    PGOUT	= 806,
    IPTE_IPTEOpt_IPTEOptOpt	= 807,
    IDTE_IDTEOpt	= 808,
    RDP_RDPOpt	= 809,
    CRDTE_CRDTEOpt	= 810,
    PTLB	= 811,
    CSP_CSPG	= 812,
    LPTEA	= 813,
    LRA_LRAG_LRAY	= 814,
    STRAG	= 815,
    LURA_LURAG	= 816,
    STURA_STURG	= 817,
    TPROT	= 818,
    MVCK_MVCP_MVCS	= 819,
    MVCDK_MVCSK	= 820,
    MVCOS	= 821,
    MVPG	= 822,
    LASP	= 823,
    PALB	= 824,
    PC	= 825,
    PR	= 826,
    PT_PTI	= 827,
    RP	= 828,
    BSA_BSG	= 829,
    TAR	= 830,
    BAKR	= 831,
    EREG_EREGG	= 832,
    ESTA_MSTA	= 833,
    PTFF	= 834,
    SCK_SCKC_SCKPF	= 835,
    SPT	= 836,
    STCK_STCKF	= 837,
    STCKE	= 838,
    STCKC	= 839,
    STPT	= 840,
    STAP	= 841,
    STIDP	= 842,
    STSI	= 843,
    STFL_STFLE	= 844,
    ECAG	= 845,
    ECTG	= 846,
    PTF	= 847,
    PCKMO	= 848,
    QPACI	= 849,
    SVC	= 850,
    MC	= 851,
    DIAG	= 852,
    TRACE	= 853,
    TRACG	= 854,
    TRAP2_TRAP4	= 855,
    SIGA_SIGP	= 856,
    SIE	= 857,
    LPP	= 858,
    ECPGA	= 859,
    ECCTR_EPCTR	= 860,
    LCCTL	= 861,
    LPCTL_LSCTL	= 862,
    QCTRI_QSI	= 863,
    SCCTR_SPCTR	= 864,
    CSCH_HSCH_RSCH_XSCH	= 865,
    MSCH_SSCH_STSCH_TSCH	= 866,
    RCHP	= 867,
    SCHM	= 868,
    STCPS_STCRW	= 869,
    TPEI_TPI	= 870,
    SAL	= 871,
    NOP_NOPOpt_NOPR_NOPROpt	= 872,
    JGNOP_JNOP	= 873,
    KDSA_KIMD_KLMD_KMAC	= 874,
    VUPH_VUPHB_VUPHF_VUPHH	= 875,
    VUPL_VUPLB_VUPLF	= 876,
    VUPLH_VUPLHB_VUPLHF_VUPLHH_VUPLHW	= 877,
    VUPLL_VUPLLB_VUPLLF_VUPLLH	= 878,
    VAVG_VAVGB_VAVGF_VAVGG_VAVGH	= 879,
    VAVGL_VAVGLB_VAVGLF_VAVGLG_VAVGLH	= 880,
    VCLZ_VCLZB_VCLZF_VCLZG_VCLZH	= 881,
    VCTZ_VCTZB_VCTZF_VCTZG_VCTZH	= 882,
    VLC_VLCB_VLCF_VLCG_VLCH	= 883,
    VLP_VLPB_VLPF_VLPG_VLPH	= 884,
    VMX_VMXB_VMXF_VMXG_VMXH	= 885,
    VMXL_VMXLB_VMXLF_VMXLG_VMXLH	= 886,
    VMN_VMNB_VMNF_VMNG_VMNH	= 887,
    VMNL_VMNLB_VMNLF_VMNLG_VMNLH	= 888,
    VMAL_VMALB_VMALF	= 889,
    VMALE_VMALEB_VMALEF_VMALEH	= 890,
    VMALH_VMALHB_VMALHF_VMALHH_VMALHW	= 891,
    VMALO_VMALOB_VMALOF_VMALOH	= 892,
    VMAO_VMAOB_VMAOF_VMAOH	= 893,
    VMAE_VMAEB_VMAEF_VMAEH	= 894,
    VMAH_VMAHB_VMAHF_VMAHH	= 895,
    VME_VMEB_VMEF_VMEH	= 896,
    VMH_VMHB_VMHF_VMHH	= 897,
    VML_VMLB_VMLF	= 898,
    VMLE_VMLEB_VMLEF_VMLEH	= 899,
    VMLH_VMLHB_VMLHF_VMLHH_VMLHW	= 900,
    VMLO_VMLOB_VMLOF_VMLOH	= 901,
    VMO_VMOB_VMOF_VMOH	= 902,
    VEC_VECB_VECF_VECG_VECH	= 903,
    VECL_VECLB_VECLF_VECLG_VECLH	= 904,
    VCEQ_VCEQB_VCEQF_VCEQG_VCEQH	= 905,
    VCEQBS_VCEQFS_VCEQGS_VCEQHS	= 906,
    VCH_VCHB_VCHF_VCHG_VCHH	= 907,
    VCHBS_VCHFS_VCHGS_VCHHS	= 908,
    VCHL_VCHLB_VCHLF_VCHLG_VCHLH	= 909,
    VCHLBS_VCHLFS_VCHLGS_VCHLHS	= 910,
    VCVB_VCVBG_VCVBGOpt_VCVBOpt	= 911,
    VCVD_VCVDG	= 912,
    VSRP	= 913,
    VCP_VTP	= 914,
    LPSW_LPSWE	= 915,
    KIMD_KLMD_KMAC	= 916,
    POPCNT	= 917,
    VFI	= 918,
    VFM	= 919,
    VCVB_VCVBG	= 920,
    AGF	= 921,
    SGF	= 922,
    KM_KMC_KMCTR_KMF_KMO	= 923,
    PCC_PPNO	= 924,
    VLLEZ_VLLEZB_VLLEZF_VLLEZG_VLLEZH	= 925,
    VN_VNC_VNO	= 926,
    VO	= 927,
    VPOPCT	= 928,
    WFMDB	= 929,
    VFMA_VFMS	= 930,
    VFMADB_VFMSDB	= 931,
    WFMADB_WFMSDB	= 932,
    VFCEDB_VFCHDB_VFCHEDB	= 933,
    WFCEDBS_WFCHDBS_WFCHEDBS	= 934,
    TPI	= 935,
    LOCGR_LOCGRAsm_LOCGRAsmE_LOCGRAsmH_LOCGRAsmHE_LOCGRAsmL_LOCGRAsmLE_LOCGRAsmLH_LOCGRAsmM_LOCGRAsmNE_LOCGRAsmNH_LOCGRAsmNHE_LOCGRAsmNL_LOCGRAsmNLE_LOCGRAsmNLH_LOCGRAsmNM_LOCGRAsmNO_LOCGRAsmNP_LOCGRAsmNZ_LOCGRAsmO_LOCGRAsmP_LOCGRAsmZ_LOCR_LOCRAsm_LOCRAsmE_LOCRAsmH_LOCRAsmHE_LOCRAsmL_LOCRAsmLE_LOCRAsmLH_LOCRAsmM_LOCRAsmNE_LOCRAsmNH_LOCRAsmNHE_LOCRAsmNL_LOCRAsmNLE_LOCRAsmNLH_LOCRAsmNM_LOCRAsmNO_LOCRAsmNP_LOCRAsmNZ_LOCRAsmO_LOCRAsmP_LOCRAsmZ	= 936,
    LOC_LOCAsm_LOCAsmE_LOCAsmH_LOCAsmHE_LOCAsmL_LOCAsmLE_LOCAsmLH_LOCAsmM_LOCAsmNE_LOCAsmNH_LOCAsmNHE_LOCAsmNL_LOCAsmNLE_LOCAsmNLH_LOCAsmNM_LOCAsmNO_LOCAsmNP_LOCAsmNZ_LOCAsmO_LOCAsmP_LOCAsmZ_LOCG_LOCGAsm_LOCGAsmE_LOCGAsmH_LOCGAsmHE_LOCGAsmL_LOCGAsmLE_LOCGAsmLH_LOCGAsmM_LOCGAsmNE_LOCGAsmNH_LOCGAsmNHE_LOCGAsmNL_LOCGAsmNLE_LOCGAsmNLH_LOCGAsmNM_LOCGAsmNO_LOCGAsmNP_LOCGAsmNZ_LOCGAsmO_LOCGAsmP_LOCGAsmZ	= 937,
    STOC_STOCAsm_STOCAsmE_STOCAsmH_STOCAsmHE_STOCAsmL_STOCAsmLE_STOCAsmLH_STOCAsmM_STOCAsmNE_STOCAsmNH_STOCAsmNHE_STOCAsmNL_STOCAsmNLE_STOCAsmNLH_STOCAsmNM_STOCAsmNO_STOCAsmNP_STOCAsmNZ_STOCAsmO_STOCAsmP_STOCAsmZ_STOCG_STOCGAsm_STOCGAsmE_STOCGAsmH_STOCGAsmHE_STOCGAsmL_STOCGAsmLE_STOCGAsmLH_STOCGAsmM_STOCGAsmNE_STOCGAsmNH_STOCGAsmNHE_STOCGAsmNL_STOCGAsmNLE_STOCGAsmNLH_STOCGAsmNM_STOCGAsmNO_STOCGAsmNP_STOCGAsmNZ_STOCGAsmO_STOCGAsmP_STOCGAsmZ	= 938,
    ALSI_ASI	= 939,
    ALGF	= 940,
    PCC	= 941,
    CELFBR_CELGBR	= 942,
    MD_MEE	= 943,
    MDR_MEER	= 944,
    CFDTR	= 945,
    CFXTR	= 946,
    TDCDT_TDGDT	= 947,
    SCK	= 948,
    SCKPF	= 949,
    RISBG_RISBG32_RISBG32Opt_RISBGOpt_RISBGZ_RISBGZOpt	= 950,
    SCHED_LIST_END = 951
  };

} // namespace llvm_ks::SystemZ::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct SystemZInstrTable {
  MCInstrDesc Insts[3314];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[104];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[1744];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof SystemZInstrTable::ImplicitOps + sizeof SystemZInstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned SystemZOpInfoBase = (sizeof SystemZInstrTable::ImplicitOps + sizeof SystemZInstrTable::Padding) / sizeof(MCOperandInfo);

extern const SystemZInstrTable SystemZDescs = {
  {
    { 3313,	6,	0,	6,	308,	0,	1,	SystemZOpInfoBase + 579,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // ZAP
    { 3312,	5,	1,	6,	169,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x2308cULL },  // XY
    { 3311,	0,	0,	4,	865,	1,	1,	SystemZOpInfoBase + 1,	41,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XSCH
    { 3310,	3,	1,	4,	175,	0,	1,	SystemZOpInfoBase + 576,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // XRK
    { 3309,	3,	1,	2,	175,	0,	1,	SystemZOpInfoBase + 573,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // XR
    { 3308,	3,	0,	6,	170,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // XIY
    { 3307,	3,	1,	6,	174,	0,	1,	SystemZOpInfoBase + 550,	0,	0, 0x23000ULL },  // XILF
    { 3306,	3,	1,	6,	173,	0,	1,	SystemZOpInfoBase + 570,	0,	0, 0x23000ULL },  // XIHF
    { 3305,	3,	0,	4,	170,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // XI
    { 3304,	3,	1,	4,	172,	0,	1,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // XGRK
    { 3303,	3,	1,	4,	172,	0,	1,	SystemZOpInfoBase + 561,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // XGR
    { 3302,	5,	1,	6,	169,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x2310cULL },  // XG
    { 3301,	5,	0,	6,	176,	0,	1,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // XC
    { 3300,	5,	1,	4,	169,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x23088ULL },  // X
    { 3299,	4,	1,	6,	666,	1,	0,	SystemZOpInfoBase + 1714,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WLEDB
    { 3298,	2,	1,	6,	666,	1,	0,	SystemZOpInfoBase + 1712,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WLDEB
    { 3297,	3,	1,	6,	693,	0,	1,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // WFTCIXB
    { 3296,	3,	1,	6,	692,	0,	1,	SystemZOpInfoBase + 1741,	0,	0, 0x0ULL },  // WFTCISB
    { 3295,	3,	1,	6,	691,	0,	1,	SystemZOpInfoBase + 1738,	0,	0, 0x0ULL },  // WFTCIDB
    { 3294,	3,	1,	6,	699,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFSXB
    { 3293,	3,	1,	6,	698,	1,	0,	SystemZOpInfoBase + 1707,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFSSB
    { 3292,	2,	1,	6,	719,	1,	0,	SystemZOpInfoBase + 444,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFSQXB
    { 3291,	2,	1,	6,	717,	1,	0,	SystemZOpInfoBase + 515,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFSQSB
    { 3290,	2,	1,	6,	716,	1,	0,	SystemZOpInfoBase + 517,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFSQDB
    { 3289,	3,	1,	6,	696,	1,	0,	SystemZOpInfoBase + 1704,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFSDB
    { 3288,	3,	1,	6,	680,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // WFPSOXB
    { 3287,	3,	1,	6,	679,	0,	0,	SystemZOpInfoBase + 1741,	0,	0, 0x0ULL },  // WFPSOSB
    { 3286,	3,	1,	6,	678,	0,	0,	SystemZOpInfoBase + 1738,	0,	0, 0x0ULL },  // WFPSODB
    { 3285,	4,	1,	6,	709,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFNMSXB
    { 3284,	4,	1,	6,	708,	1,	0,	SystemZOpInfoBase + 1726,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFNMSSB
    { 3283,	4,	1,	6,	706,	1,	0,	SystemZOpInfoBase + 1722,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFNMSDB
    { 3282,	4,	1,	6,	709,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFNMAXB
    { 3281,	4,	1,	6,	708,	1,	0,	SystemZOpInfoBase + 1726,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFNMASB
    { 3280,	4,	1,	6,	706,	1,	0,	SystemZOpInfoBase + 1722,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFNMADB
    { 3279,	3,	1,	6,	703,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMXB
    { 3278,	4,	1,	6,	709,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMSXB
    { 3277,	4,	1,	6,	708,	1,	0,	SystemZOpInfoBase + 1726,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMSSB
    { 3276,	4,	1,	6,	932,	1,	0,	SystemZOpInfoBase + 1722,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMSDB
    { 3275,	3,	1,	6,	701,	1,	0,	SystemZOpInfoBase + 1707,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMSB
    { 3274,	4,	1,	6,	689,	1,	0,	SystemZOpInfoBase + 1529,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMINXB
    { 3273,	4,	1,	6,	688,	1,	0,	SystemZOpInfoBase + 1734,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMINSB
    { 3272,	4,	1,	6,	686,	1,	0,	SystemZOpInfoBase + 1730,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMINDB
    { 3271,	3,	1,	6,	929,	1,	0,	SystemZOpInfoBase + 1704,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMDB
    { 3270,	4,	1,	6,	689,	1,	0,	SystemZOpInfoBase + 1529,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMAXXB
    { 3269,	4,	1,	6,	688,	1,	0,	SystemZOpInfoBase + 1734,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMAXSB
    { 3268,	4,	1,	6,	686,	1,	0,	SystemZOpInfoBase + 1730,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMAXDB
    { 3267,	4,	1,	6,	709,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMAXB
    { 3266,	4,	1,	6,	708,	1,	0,	SystemZOpInfoBase + 1726,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMASB
    { 3265,	4,	1,	6,	932,	1,	0,	SystemZOpInfoBase + 1722,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFMADB
    { 3264,	4,	1,	6,	671,	1,	0,	SystemZOpInfoBase + 1718,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFLRX
    { 3263,	4,	1,	6,	669,	1,	0,	SystemZOpInfoBase + 1714,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFLRD
    { 3262,	2,	1,	6,	683,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // WFLPXB
    { 3261,	2,	1,	6,	682,	0,	0,	SystemZOpInfoBase + 515,	0,	0, 0x0ULL },  // WFLPSB
    { 3260,	2,	1,	6,	681,	0,	0,	SystemZOpInfoBase + 517,	0,	0, 0x0ULL },  // WFLPDB
    { 3259,	2,	1,	6,	683,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // WFLNXB
    { 3258,	2,	1,	6,	682,	0,	0,	SystemZOpInfoBase + 515,	0,	0, 0x0ULL },  // WFLNSB
    { 3257,	2,	1,	6,	681,	0,	0,	SystemZOpInfoBase + 517,	0,	0, 0x0ULL },  // WFLNDB
    { 3256,	2,	1,	6,	669,	1,	0,	SystemZOpInfoBase + 1712,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFLLS
    { 3255,	2,	1,	6,	670,	1,	0,	SystemZOpInfoBase + 1710,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFLLD
    { 3254,	2,	1,	6,	683,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // WFLCXB
    { 3253,	2,	1,	6,	682,	0,	0,	SystemZOpInfoBase + 515,	0,	0, 0x0ULL },  // WFLCSB
    { 3252,	2,	1,	6,	681,	0,	0,	SystemZOpInfoBase + 517,	0,	0, 0x0ULL },  // WFLCDB
    { 3251,	2,	0,	6,	740,	1,	1,	SystemZOpInfoBase + 444,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKXB
    { 3250,	2,	0,	6,	739,	1,	1,	SystemZOpInfoBase + 515,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKSB
    { 3249,	3,	1,	6,	736,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHXBS
    { 3248,	3,	1,	6,	728,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHXB
    { 3247,	3,	1,	6,	734,	1,	1,	SystemZOpInfoBase + 1707,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHSBS
    { 3246,	3,	1,	6,	726,	1,	0,	SystemZOpInfoBase + 1707,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHSB
    { 3245,	3,	1,	6,	736,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHEXBS
    { 3244,	3,	1,	6,	728,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHEXB
    { 3243,	3,	1,	6,	734,	1,	1,	SystemZOpInfoBase + 1707,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHESBS
    { 3242,	3,	1,	6,	726,	1,	0,	SystemZOpInfoBase + 1707,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHESB
    { 3241,	3,	1,	6,	731,	1,	1,	SystemZOpInfoBase + 1704,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHEDBS
    { 3240,	3,	1,	6,	723,	1,	0,	SystemZOpInfoBase + 1704,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHEDB
    { 3239,	3,	1,	6,	731,	1,	1,	SystemZOpInfoBase + 1704,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHDBS
    { 3238,	3,	1,	6,	723,	1,	0,	SystemZOpInfoBase + 1704,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKHDB
    { 3237,	3,	1,	6,	736,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKEXBS
    { 3236,	3,	1,	6,	728,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKEXB
    { 3235,	3,	1,	6,	734,	1,	1,	SystemZOpInfoBase + 1707,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKESBS
    { 3234,	3,	1,	6,	726,	1,	0,	SystemZOpInfoBase + 1707,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKESB
    { 3233,	3,	1,	6,	731,	1,	1,	SystemZOpInfoBase + 1704,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKEDBS
    { 3232,	3,	1,	6,	723,	1,	0,	SystemZOpInfoBase + 1704,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKEDB
    { 3231,	2,	0,	6,	738,	1,	1,	SystemZOpInfoBase + 517,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFKDB
    { 3230,	4,	0,	6,	737,	1,	1,	SystemZOpInfoBase + 1696,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFK
    { 3229,	4,	1,	6,	676,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFIXB
    { 3228,	4,	1,	6,	675,	1,	0,	SystemZOpInfoBase + 1700,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFISB
    { 3227,	4,	1,	6,	673,	1,	0,	SystemZOpInfoBase + 1696,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFIDB
    { 3226,	3,	1,	6,	714,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFDXB
    { 3225,	3,	1,	6,	712,	1,	0,	SystemZOpInfoBase + 1707,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFDSB
    { 3224,	3,	1,	6,	711,	1,	0,	SystemZOpInfoBase + 1704,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFDDB
    { 3223,	2,	0,	6,	740,	1,	1,	SystemZOpInfoBase + 444,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCXB
    { 3222,	2,	0,	6,	739,	1,	1,	SystemZOpInfoBase + 515,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCSB
    { 3221,	3,	1,	6,	735,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHXBS
    { 3220,	3,	1,	6,	727,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHXB
    { 3219,	3,	1,	6,	733,	1,	1,	SystemZOpInfoBase + 1707,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHSBS
    { 3218,	3,	1,	6,	725,	1,	0,	SystemZOpInfoBase + 1707,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHSB
    { 3217,	3,	1,	6,	735,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHEXBS
    { 3216,	3,	1,	6,	727,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHEXB
    { 3215,	3,	1,	6,	733,	1,	1,	SystemZOpInfoBase + 1707,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHESBS
    { 3214,	3,	1,	6,	725,	1,	0,	SystemZOpInfoBase + 1707,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHESB
    { 3213,	3,	1,	6,	934,	1,	1,	SystemZOpInfoBase + 1704,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHEDBS
    { 3212,	3,	1,	6,	722,	1,	0,	SystemZOpInfoBase + 1704,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHEDB
    { 3211,	3,	1,	6,	934,	1,	1,	SystemZOpInfoBase + 1704,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHDBS
    { 3210,	3,	1,	6,	722,	1,	0,	SystemZOpInfoBase + 1704,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCHDB
    { 3209,	3,	1,	6,	735,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCEXBS
    { 3208,	3,	1,	6,	727,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCEXB
    { 3207,	3,	1,	6,	733,	1,	1,	SystemZOpInfoBase + 1707,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCESBS
    { 3206,	3,	1,	6,	725,	1,	0,	SystemZOpInfoBase + 1707,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCESB
    { 3205,	3,	1,	6,	934,	1,	1,	SystemZOpInfoBase + 1704,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCEDBS
    { 3204,	3,	1,	6,	722,	1,	0,	SystemZOpInfoBase + 1704,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCEDB
    { 3203,	2,	0,	6,	738,	1,	1,	SystemZOpInfoBase + 517,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFCDB
    { 3202,	4,	0,	6,	737,	1,	1,	SystemZOpInfoBase + 1696,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WFC
    { 3201,	3,	1,	6,	699,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFAXB
    { 3200,	3,	1,	6,	698,	1,	0,	SystemZOpInfoBase + 1707,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFASB
    { 3199,	3,	1,	6,	696,	1,	0,	SystemZOpInfoBase + 1704,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // WFADB
    { 3198,	4,	1,	6,	661,	1,	0,	SystemZOpInfoBase + 1696,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WCLGDB
    { 3197,	4,	1,	6,	663,	1,	0,	SystemZOpInfoBase + 1700,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WCLFEB
    { 3196,	4,	1,	6,	661,	1,	0,	SystemZOpInfoBase + 1696,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WCGDB
    { 3195,	4,	1,	6,	663,	1,	0,	SystemZOpInfoBase + 1700,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WCFEB
    { 3194,	4,	1,	6,	657,	1,	0,	SystemZOpInfoBase + 1700,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WCELFB
    { 3193,	4,	1,	6,	657,	1,	0,	SystemZOpInfoBase + 1700,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WCEFB
    { 3192,	4,	1,	6,	655,	1,	0,	SystemZOpInfoBase + 1696,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WCDLGB
    { 3191,	4,	1,	6,	655,	1,	0,	SystemZOpInfoBase + 1696,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // WCDGB
    { 3190,	1,	1,	6,	535,	0,	0,	SystemZOpInfoBase + 1690,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VZERO
    { 3189,	3,	1,	6,	595,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VX
    { 3188,	2,	1,	6,	878,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLLH
    { 3187,	2,	1,	6,	583,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLLG
    { 3186,	2,	1,	6,	878,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLLF
    { 3185,	2,	1,	6,	878,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLLB
    { 3184,	3,	1,	6,	878,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VUPLL
    { 3183,	2,	1,	6,	877,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLHW
    { 3182,	2,	1,	6,	877,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLHH
    { 3181,	2,	1,	6,	582,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLHG
    { 3180,	2,	1,	6,	877,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLHF
    { 3179,	2,	1,	6,	877,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLHB
    { 3178,	3,	1,	6,	877,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VUPLH
    { 3177,	2,	1,	6,	581,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLG
    { 3176,	2,	1,	6,	876,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLF
    { 3175,	2,	1,	6,	876,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPLB
    { 3174,	3,	1,	6,	876,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VUPL
    { 3173,	3,	1,	6,	781,	0,	1,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VUPKZL
    { 3172,	3,	1,	6,	780,	0,	1,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VUPKZH
    { 3171,	4,	0,	6,	765,	0,	0,	SystemZOpInfoBase + 1667,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VUPKZ
    { 3170,	2,	1,	6,	875,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPHH
    { 3169,	2,	1,	6,	580,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPHG
    { 3168,	2,	1,	6,	875,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPHF
    { 3167,	2,	1,	6,	875,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VUPHB
    { 3166,	3,	1,	6,	875,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VUPH
    { 3165,	3,	0,	6,	774,	0,	1,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VTZ
    { 3164,	2,	0,	6,	774,	0,	1,	SystemZOpInfoBase + 1611,	0,	0, 0x0ULL },  // VTPOpt
    { 3163,	1,	0,	6,	914,	0,	1,	SystemZOpInfoBase + 1690,	0,	0, 0x0ULL },  // VTP
    { 3162,	2,	0,	6,	651,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VTM
    { 3161,	3,	1,	6,	642,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSUMQG
    { 3160,	3,	1,	6,	642,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSUMQF
    { 3159,	4,	1,	6,	642,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VSUMQ
    { 3158,	3,	1,	6,	640,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSUMH
    { 3157,	3,	1,	6,	641,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSUMGH
    { 3156,	3,	1,	6,	641,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSUMGF
    { 3155,	4,	1,	6,	641,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VSUMG
    { 3154,	3,	1,	6,	640,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSUMB
    { 3153,	4,	1,	6,	640,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VSUM
    { 3152,	4,	1,	6,	759,	0,	1,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VSTRSZH
    { 3151,	4,	1,	6,	759,	0,	1,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VSTRSZF
    { 3150,	4,	1,	6,	759,	0,	1,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VSTRSZB
    { 3149,	5,	1,	6,	758,	0,	1,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRSH
    { 3148,	5,	1,	6,	758,	0,	1,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRSF
    { 3147,	5,	1,	6,	758,	0,	1,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRSB
    { 3146,	6,	1,	6,	758,	0,	1,	SystemZOpInfoBase + 1605,	0,	0, 0x0ULL },  // VSTRS
    { 3145,	4,	0,	6,	555,	0,	0,	SystemZOpInfoBase + 1654,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTRLR
    { 3144,	4,	0,	6,	555,	0,	0,	SystemZOpInfoBase + 1667,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTRL
    { 3143,	5,	1,	6,	757,	0,	1,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCZHS
    { 3142,	5,	1,	6,	756,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCZH
    { 3141,	5,	1,	6,	757,	0,	1,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCZFS
    { 3140,	5,	1,	6,	756,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCZF
    { 3139,	5,	1,	6,	757,	0,	1,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCZBS
    { 3138,	5,	1,	6,	756,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCZB
    { 3137,	5,	1,	6,	755,	0,	1,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCHS
    { 3136,	5,	1,	6,	754,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCH
    { 3135,	5,	1,	6,	755,	0,	1,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCFS
    { 3134,	5,	1,	6,	754,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCF
    { 3133,	5,	1,	6,	755,	0,	1,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCBS
    { 3132,	5,	1,	6,	754,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSTRCB
    { 3131,	6,	1,	6,	754,	0,	1,	SystemZOpInfoBase + 1605,	0,	0, 0x0ULL },  // VSTRC
    { 3130,	5,	0,	6,	553,	0,	0,	SystemZOpInfoBase + 1662,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTMAlign
    { 3129,	4,	0,	6,	553,	0,	0,	SystemZOpInfoBase + 1658,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTM
    { 3128,	4,	0,	6,	550,	0,	0,	SystemZOpInfoBase + 1654,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTL
    { 3127,	4,	0,	6,	562,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayStore), 0x200ULL },  // VSTERH
    { 3126,	4,	0,	6,	562,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayStore), 0x200ULL },  // VSTERG
    { 3125,	4,	0,	6,	562,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayStore), 0x200ULL },  // VSTERF
    { 3124,	5,	0,	6,	562,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTER
    { 3123,	5,	0,	6,	552,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // VSTEH
    { 3122,	5,	0,	6,	551,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayStore), 0x100ULL },  // VSTEG
    { 3121,	5,	0,	6,	551,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayStore), 0x80ULL },  // VSTEF
    { 3120,	5,	0,	6,	563,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayStore), 0x40ULL },  // VSTEBRH
    { 3119,	5,	0,	6,	564,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayStore), 0x100ULL },  // VSTEBRG
    { 3118,	5,	0,	6,	564,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayStore), 0x80ULL },  // VSTEBRF
    { 3117,	5,	0,	6,	552,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayStore), 0x20ULL },  // VSTEB
    { 3116,	4,	0,	6,	561,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayStore), 0x200ULL },  // VSTBRQ
    { 3115,	4,	0,	6,	561,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayStore), 0x200ULL },  // VSTBRH
    { 3114,	4,	0,	6,	561,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayStore), 0x200ULL },  // VSTBRG
    { 3113,	4,	0,	6,	561,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayStore), 0x200ULL },  // VSTBRF
    { 3112,	5,	0,	6,	561,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTBR
    { 3111,	5,	0,	6,	550,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayStore), 0x202ULL },  // VSTAlign
    { 3110,	4,	0,	6,	550,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayStore), 0x202ULL },  // VST
    { 3109,	5,	1,	6,	772,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VSRPR
    { 3108,	5,	1,	6,	913,	0,	1,	SystemZOpInfoBase + 1545,	0,	0, 0x0ULL },  // VSRP
    { 3107,	3,	1,	6,	634,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSRLB
    { 3106,	3,	1,	6,	633,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSRL
    { 3105,	4,	1,	6,	636,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VSRD
    { 3104,	3,	1,	6,	634,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSRAB
    { 3103,	3,	1,	6,	633,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSRA
    { 3102,	3,	1,	6,	639,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSQ
    { 3101,	5,	1,	6,	768,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VSP
    { 3100,	4,	1,	6,	631,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VSLDB
    { 3099,	4,	1,	6,	635,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VSLD
    { 3098,	3,	1,	6,	632,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSLB
    { 3097,	3,	1,	6,	631,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSL
    { 3096,	3,	1,	6,	639,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSH
    { 3095,	3,	1,	6,	639,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSG
    { 3094,	3,	1,	6,	639,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSF
    { 3093,	4,	1,	6,	571,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VSEL
    { 3092,	2,	1,	6,	578,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VSEGH
    { 3091,	2,	1,	6,	578,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VSEGF
    { 3090,	2,	1,	6,	578,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VSEGB
    { 3089,	3,	1,	6,	578,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VSEG
    { 3088,	5,	1,	6,	771,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VSDP
    { 3087,	3,	1,	6,	776,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSCSHP
    { 3086,	4,	1,	6,	775,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VSCHXP
    { 3085,	4,	1,	6,	775,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VSCHSP
    { 3084,	5,	1,	6,	775,	0,	0,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VSCHP
    { 3083,	4,	1,	6,	775,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VSCHDP
    { 3082,	5,	0,	6,	554,	0,	0,	SystemZOpInfoBase + 1691,	0,	0|(1ULL<<MCID::MayStore), 0x100ULL },  // VSCEG
    { 3081,	5,	0,	6,	554,	0,	0,	SystemZOpInfoBase + 1691,	0,	0|(1ULL<<MCID::MayStore), 0x80ULL },  // VSCEF
    { 3080,	3,	1,	6,	638,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSCBIQ
    { 3079,	3,	1,	6,	638,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSCBIH
    { 3078,	3,	1,	6,	638,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSCBIG
    { 3077,	3,	1,	6,	638,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSCBIF
    { 3076,	3,	1,	6,	638,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSCBIB
    { 3075,	4,	1,	6,	638,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VSCBI
    { 3074,	4,	1,	6,	637,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VSBIQ
    { 3073,	5,	1,	6,	637,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSBI
    { 3072,	4,	1,	6,	637,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VSBCBIQ
    { 3071,	5,	1,	6,	637,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VSBCBI
    { 3070,	3,	1,	6,	637,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VSB
    { 3069,	4,	1,	6,	639,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VS
    { 3068,	4,	1,	6,	621,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VRQ
    { 3067,	5,	1,	6,	770,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VRP
    { 3066,	4,	1,	6,	621,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VRLQ
    { 3065,	4,	1,	6,	621,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VRLG
    { 3064,	4,	1,	6,	621,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VRLF
    { 3063,	5,	1,	6,	621,	0,	0,	SystemZOpInfoBase + 456,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VRL
    { 3062,	4,	1,	6,	621,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VRG
    { 3061,	4,	1,	6,	621,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VRF
    { 3060,	2,	1,	6,	539,	0,	0,	SystemZOpInfoBase + 1611,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VREPIH
    { 3059,	2,	1,	6,	539,	0,	0,	SystemZOpInfoBase + 1611,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VREPIG
    { 3058,	2,	1,	6,	539,	0,	0,	SystemZOpInfoBase + 1611,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VREPIF
    { 3057,	2,	1,	6,	539,	0,	0,	SystemZOpInfoBase + 1611,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VREPIB
    { 3056,	3,	1,	6,	539,	0,	0,	SystemZOpInfoBase + 1623,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VREPI
    { 3055,	3,	1,	6,	570,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VREPH
    { 3054,	3,	1,	6,	570,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VREPG
    { 3053,	3,	1,	6,	570,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VREPF
    { 3052,	3,	1,	6,	570,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VREPB
    { 3051,	4,	1,	6,	570,	0,	0,	SystemZOpInfoBase + 1550,	0,	0, 0x0ULL },  // VREP
    { 3050,	5,	1,	6,	621,	0,	0,	SystemZOpInfoBase + 456,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VR
    { 3049,	5,	1,	6,	773,	0,	1,	SystemZOpInfoBase + 1545,	0,	0, 0x0ULL },  // VPSOP
    { 3048,	2,	1,	6,	620,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VPOPCTH
    { 3047,	2,	1,	6,	620,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VPOPCTG
    { 3046,	2,	1,	6,	620,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VPOPCTF
    { 3045,	2,	1,	6,	620,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VPOPCTB
    { 3044,	3,	1,	6,	928,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VPOPCT
    { 3043,	5,	1,	6,	779,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VPKZR
    { 3042,	4,	1,	6,	764,	0,	0,	SystemZOpInfoBase + 1667,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VPKZ
    { 3041,	3,	1,	6,	575,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKSHS
    { 3040,	3,	1,	6,	574,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKSH
    { 3039,	3,	1,	6,	575,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKSGS
    { 3038,	3,	1,	6,	574,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKSG
    { 3037,	3,	1,	6,	575,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKSFS
    { 3036,	3,	1,	6,	574,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKSF
    { 3035,	5,	1,	6,	574,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VPKS
    { 3034,	3,	1,	6,	577,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKLSHS
    { 3033,	3,	1,	6,	576,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKLSH
    { 3032,	3,	1,	6,	577,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKLSGS
    { 3031,	3,	1,	6,	576,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKLSG
    { 3030,	3,	1,	6,	577,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKLSFS
    { 3029,	3,	1,	6,	576,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKLSF
    { 3028,	5,	1,	6,	576,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VPKLS
    { 3027,	3,	1,	6,	573,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKH
    { 3026,	3,	1,	6,	573,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKG
    { 3025,	3,	1,	6,	573,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VPKF
    { 3024,	4,	1,	6,	573,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VPK
    { 3023,	4,	1,	6,	567,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VPERM
    { 3022,	4,	1,	6,	568,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VPDI
    { 3021,	1,	1,	6,	536,	0,	0,	SystemZOpInfoBase + 1690,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VONE
    { 3020,	3,	1,	6,	589,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VOC
    { 3019,	3,	1,	6,	927,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VO
    { 3018,	3,	1,	6,	588,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VNX
    { 3017,	3,	1,	6,	926,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VNO
    { 3016,	3,	1,	6,	588,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VNN
    { 3015,	3,	1,	6,	926,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VNC
    { 3014,	3,	1,	6,	926,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VN
    { 3013,	3,	1,	6,	601,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXQ
    { 3012,	3,	1,	6,	602,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXLQ
    { 3011,	3,	1,	6,	886,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXLH
    { 3010,	3,	1,	6,	886,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXLG
    { 3009,	3,	1,	6,	886,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXLF
    { 3008,	3,	1,	6,	886,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXLB
    { 3007,	4,	1,	6,	886,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXL
    { 3006,	3,	1,	6,	885,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXH
    { 3005,	3,	1,	6,	885,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXG
    { 3004,	3,	1,	6,	885,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXF
    { 3003,	3,	1,	6,	885,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMXB
    { 3002,	4,	1,	6,	885,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMX
    { 3001,	5,	1,	6,	769,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VMSP
    { 3000,	5,	1,	6,	619,	0,	0,	SystemZOpInfoBase + 1536,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMSLG
    { 2999,	6,	1,	6,	619,	0,	0,	SystemZOpInfoBase + 1605,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMSL
    { 2998,	3,	1,	6,	566,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VMRLH
    { 2997,	3,	1,	6,	566,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VMRLG
    { 2996,	3,	1,	6,	566,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VMRLF
    { 2995,	3,	1,	6,	566,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VMRLB
    { 2994,	4,	1,	6,	566,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VMRL
    { 2993,	3,	1,	6,	565,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VMRHH
    { 2992,	3,	1,	6,	565,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VMRHG
    { 2991,	3,	1,	6,	565,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VMRHF
    { 2990,	3,	1,	6,	565,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VMRHB
    { 2989,	4,	1,	6,	565,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VMRH
    { 2988,	5,	1,	6,	769,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VMP
    { 2987,	3,	1,	6,	902,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMOH
    { 2986,	3,	1,	6,	618,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMOG
    { 2985,	3,	1,	6,	902,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMOF
    { 2984,	3,	1,	6,	902,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMOB
    { 2983,	4,	1,	6,	902,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMO
    { 2982,	3,	1,	6,	603,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNQ
    { 2981,	3,	1,	6,	604,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNLQ
    { 2980,	3,	1,	6,	888,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNLH
    { 2979,	3,	1,	6,	888,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNLG
    { 2978,	3,	1,	6,	888,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNLF
    { 2977,	3,	1,	6,	888,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNLB
    { 2976,	4,	1,	6,	888,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNL
    { 2975,	3,	1,	6,	887,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNH
    { 2974,	3,	1,	6,	887,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNG
    { 2973,	3,	1,	6,	887,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNF
    { 2972,	3,	1,	6,	887,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMNB
    { 2971,	4,	1,	6,	887,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMN
    { 2970,	3,	1,	6,	614,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLQ
    { 2969,	3,	1,	6,	901,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLOH
    { 2968,	3,	1,	6,	617,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLOG
    { 2967,	3,	1,	6,	901,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLOF
    { 2966,	3,	1,	6,	901,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLOB
    { 2965,	4,	1,	6,	901,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLO
    { 2964,	3,	1,	6,	900,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLHW
    { 2963,	3,	1,	6,	616,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLHQ
    { 2962,	3,	1,	6,	900,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLHH
    { 2961,	3,	1,	6,	616,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLHG
    { 2960,	3,	1,	6,	900,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLHF
    { 2959,	3,	1,	6,	900,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLHB
    { 2958,	4,	1,	6,	900,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLH
    { 2957,	3,	1,	6,	614,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLG
    { 2956,	3,	1,	6,	898,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLF
    { 2955,	3,	1,	6,	899,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLEH
    { 2954,	3,	1,	6,	615,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLEG
    { 2953,	3,	1,	6,	899,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLEF
    { 2952,	3,	1,	6,	899,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLEB
    { 2951,	4,	1,	6,	899,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLE
    { 2950,	3,	1,	6,	898,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMLB
    { 2949,	4,	1,	6,	898,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VML
    { 2948,	3,	1,	6,	613,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMHQ
    { 2947,	3,	1,	6,	897,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMHH
    { 2946,	3,	1,	6,	613,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMHG
    { 2945,	3,	1,	6,	897,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMHF
    { 2944,	3,	1,	6,	897,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMHB
    { 2943,	4,	1,	6,	897,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMH
    { 2942,	3,	1,	6,	896,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMEH
    { 2941,	3,	1,	6,	612,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMEG
    { 2940,	3,	1,	6,	896,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMEF
    { 2939,	3,	1,	6,	896,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMEB
    { 2938,	4,	1,	6,	896,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VME
    { 2937,	4,	1,	6,	893,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAOH
    { 2936,	4,	1,	6,	609,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAOG
    { 2935,	4,	1,	6,	893,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAOF
    { 2934,	4,	1,	6,	893,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAOB
    { 2933,	5,	1,	6,	893,	0,	0,	SystemZOpInfoBase + 1536,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAO
    { 2932,	4,	1,	6,	605,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALQ
    { 2931,	4,	1,	6,	892,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALOH
    { 2930,	4,	1,	6,	608,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALOG
    { 2929,	4,	1,	6,	892,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALOF
    { 2928,	4,	1,	6,	892,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALOB
    { 2927,	5,	1,	6,	892,	0,	0,	SystemZOpInfoBase + 1536,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALO
    { 2926,	4,	1,	6,	891,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALHW
    { 2925,	4,	1,	6,	607,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALHQ
    { 2924,	4,	1,	6,	891,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALHH
    { 2923,	4,	1,	6,	607,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALHG
    { 2922,	4,	1,	6,	891,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALHF
    { 2921,	4,	1,	6,	891,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALHB
    { 2920,	5,	1,	6,	891,	0,	0,	SystemZOpInfoBase + 1536,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALH
    { 2919,	4,	1,	6,	605,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALG
    { 2918,	4,	1,	6,	889,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALF
    { 2917,	4,	1,	6,	890,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALEH
    { 2916,	4,	1,	6,	606,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALEG
    { 2915,	4,	1,	6,	890,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALEF
    { 2914,	4,	1,	6,	890,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALEB
    { 2913,	5,	1,	6,	890,	0,	0,	SystemZOpInfoBase + 1536,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALE
    { 2912,	4,	1,	6,	889,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMALB
    { 2911,	5,	1,	6,	889,	0,	0,	SystemZOpInfoBase + 1536,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAL
    { 2910,	4,	1,	6,	611,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAHQ
    { 2909,	4,	1,	6,	895,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAHH
    { 2908,	4,	1,	6,	611,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAHG
    { 2907,	4,	1,	6,	895,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAHF
    { 2906,	4,	1,	6,	895,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAHB
    { 2905,	5,	1,	6,	895,	0,	0,	SystemZOpInfoBase + 1536,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAH
    { 2904,	4,	1,	6,	894,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAEH
    { 2903,	4,	1,	6,	610,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAEG
    { 2902,	4,	1,	6,	894,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAEF
    { 2901,	4,	1,	6,	894,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAEB
    { 2900,	5,	1,	6,	894,	0,	0,	SystemZOpInfoBase + 1536,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VMAE
    { 2899,	3,	1,	6,	534,	0,	0,	SystemZOpInfoBase + 1687,	0,	0, 0x0ULL },  // VLVGP
    { 2898,	5,	1,	6,	533,	0,	0,	SystemZOpInfoBase + 1677,	0,	0, 0x0ULL },  // VLVGH
    { 2897,	5,	1,	6,	533,	0,	0,	SystemZOpInfoBase + 1682,	0,	0, 0x0ULL },  // VLVGG
    { 2896,	5,	1,	6,	533,	0,	0,	SystemZOpInfoBase + 1677,	0,	0, 0x0ULL },  // VLVGF
    { 2895,	5,	1,	6,	533,	0,	0,	SystemZOpInfoBase + 1677,	0,	0, 0x0ULL },  // VLVGB
    { 2894,	6,	1,	6,	533,	0,	0,	SystemZOpInfoBase + 1671,	0,	0, 0x0ULL },  // VLVG
    { 2893,	4,	1,	6,	549,	0,	0,	SystemZOpInfoBase + 1654,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLRLR
    { 2892,	4,	1,	6,	549,	0,	0,	SystemZOpInfoBase + 1667,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLRL
    { 2891,	4,	1,	6,	545,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // VLREPH
    { 2890,	4,	1,	6,	545,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x100ULL },  // VLREPG
    { 2889,	4,	1,	6,	545,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL },  // VLREPF
    { 2888,	4,	1,	6,	545,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x20ULL },  // VLREPB
    { 2887,	5,	1,	6,	545,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLREP
    { 2886,	2,	1,	6,	531,	0,	0,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::MoveReg), 0x0ULL },  // VLR
    { 2885,	2,	1,	6,	600,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VLPQ
    { 2884,	2,	1,	6,	884,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VLPH
    { 2883,	2,	1,	6,	884,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VLPG
    { 2882,	2,	1,	6,	884,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VLPF
    { 2881,	2,	1,	6,	884,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VLPB
    { 2880,	3,	1,	6,	884,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VLP
    { 2879,	5,	2,	6,	548,	0,	0,	SystemZOpInfoBase + 1662,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLMAlign
    { 2878,	4,	2,	6,	548,	0,	0,	SystemZOpInfoBase + 1658,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLM
    { 2877,	4,	1,	6,	544,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL },  // VLLEZLF
    { 2876,	4,	1,	6,	925,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // VLLEZH
    { 2875,	4,	1,	6,	925,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x100ULL },  // VLLEZG
    { 2874,	4,	1,	6,	925,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL },  // VLLEZF
    { 2873,	4,	1,	6,	925,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x20ULL },  // VLLEZB
    { 2872,	5,	1,	6,	925,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLLEZ
    { 2871,	4,	1,	6,	559,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // VLLEBRZH
    { 2870,	4,	1,	6,	559,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x100ULL },  // VLLEBRZG
    { 2869,	4,	1,	6,	559,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL },  // VLLEBRZF
    { 2868,	4,	1,	6,	559,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL },  // VLLEBRZE
    { 2867,	5,	1,	6,	559,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLLEBRZ
    { 2866,	4,	1,	6,	542,	0,	0,	SystemZOpInfoBase + 1654,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLL
    { 2865,	3,	1,	6,	763,	0,	0,	SystemZOpInfoBase + 1623,	0,	0, 0x0ULL },  // VLIP
    { 2864,	4,	1,	6,	532,	0,	0,	SystemZOpInfoBase + 1650,	0,	0, 0x0ULL },  // VLGVH
    { 2863,	4,	1,	6,	532,	0,	0,	SystemZOpInfoBase + 1650,	0,	0, 0x0ULL },  // VLGVG
    { 2862,	4,	1,	6,	532,	0,	0,	SystemZOpInfoBase + 1650,	0,	0, 0x0ULL },  // VLGVF
    { 2861,	4,	1,	6,	532,	0,	0,	SystemZOpInfoBase + 1650,	0,	0, 0x0ULL },  // VLGVB
    { 2860,	5,	1,	6,	532,	0,	0,	SystemZOpInfoBase + 1645,	0,	0, 0x0ULL },  // VLGV
    { 2859,	4,	1,	6,	557,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x200ULL },  // VLERH
    { 2858,	4,	1,	6,	557,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x200ULL },  // VLERG
    { 2857,	4,	1,	6,	557,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x200ULL },  // VLERF
    { 2856,	5,	1,	6,	557,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLER
    { 2855,	4,	1,	6,	540,	0,	0,	SystemZOpInfoBase + 1641,	0,	0, 0x0ULL },  // VLEIH
    { 2854,	4,	1,	6,	540,	0,	0,	SystemZOpInfoBase + 1641,	0,	0, 0x0ULL },  // VLEIG
    { 2853,	4,	1,	6,	540,	0,	0,	SystemZOpInfoBase + 1641,	0,	0, 0x0ULL },  // VLEIF
    { 2852,	4,	1,	6,	540,	0,	0,	SystemZOpInfoBase + 1641,	0,	0, 0x0ULL },  // VLEIB
    { 2851,	6,	1,	6,	546,	0,	0,	SystemZOpInfoBase + 1635,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // VLEH
    { 2850,	6,	1,	6,	546,	0,	0,	SystemZOpInfoBase + 1635,	0,	0|(1ULL<<MCID::MayLoad), 0x100ULL },  // VLEG
    { 2849,	6,	1,	6,	546,	0,	0,	SystemZOpInfoBase + 1635,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL },  // VLEF
    { 2848,	4,	1,	6,	665,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VLEDB
    { 2847,	5,	1,	6,	664,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VLED
    { 2846,	6,	1,	6,	558,	0,	0,	SystemZOpInfoBase + 1635,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // VLEBRH
    { 2845,	6,	1,	6,	558,	0,	0,	SystemZOpInfoBase + 1635,	0,	0|(1ULL<<MCID::MayLoad), 0x100ULL },  // VLEBRG
    { 2844,	6,	1,	6,	558,	0,	0,	SystemZOpInfoBase + 1635,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL },  // VLEBRF
    { 2843,	6,	1,	6,	546,	0,	0,	SystemZOpInfoBase + 1635,	0,	0|(1ULL<<MCID::MayLoad), 0x20ULL },  // VLEB
    { 2842,	2,	1,	6,	665,	1,	0,	SystemZOpInfoBase + 444,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VLDEB
    { 2841,	4,	1,	6,	664,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VLDE
    { 2840,	2,	1,	6,	599,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VLCQ
    { 2839,	2,	1,	6,	883,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VLCH
    { 2838,	2,	1,	6,	883,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VLCG
    { 2837,	2,	1,	6,	883,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VLCF
    { 2836,	2,	1,	6,	883,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VLCB
    { 2835,	3,	1,	6,	883,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VLC
    { 2834,	4,	1,	6,	560,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x40ULL },  // VLBRREPH
    { 2833,	4,	1,	6,	560,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x100ULL },  // VLBRREPG
    { 2832,	4,	1,	6,	560,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL },  // VLBRREPF
    { 2831,	5,	1,	6,	560,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLBRREP
    { 2830,	4,	1,	6,	556,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x200ULL },  // VLBRQ
    { 2829,	4,	1,	6,	556,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x200ULL },  // VLBRH
    { 2828,	4,	1,	6,	556,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x200ULL },  // VLBRG
    { 2827,	4,	1,	6,	556,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x200ULL },  // VLBRF
    { 2826,	5,	1,	6,	556,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLBR
    { 2825,	5,	1,	6,	542,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLBB
    { 2824,	5,	1,	6,	541,	0,	0,	SystemZOpInfoBase + 1630,	0,	0|(1ULL<<MCID::MayLoad), 0x201ULL },  // VLAlign
    { 2823,	4,	1,	6,	541,	0,	0,	SystemZOpInfoBase + 1626,	0,	0|(1ULL<<MCID::MayLoad), 0x201ULL },  // VL
    { 2822,	2,	1,	6,	753,	0,	1,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VISTRHS
    { 2821,	3,	1,	6,	752,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VISTRH
    { 2820,	2,	1,	6,	753,	0,	1,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VISTRFS
    { 2819,	3,	1,	6,	752,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VISTRF
    { 2818,	2,	1,	6,	753,	0,	1,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VISTRBS
    { 2817,	3,	1,	6,	752,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VISTRB
    { 2816,	4,	1,	6,	752,	0,	1,	SystemZOpInfoBase + 1550,	0,	0, 0x0ULL },  // VISTR
    { 2815,	3,	1,	6,	538,	0,	0,	SystemZOpInfoBase + 1623,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VGMH
    { 2814,	3,	1,	6,	538,	0,	0,	SystemZOpInfoBase + 1623,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VGMG
    { 2813,	3,	1,	6,	538,	0,	0,	SystemZOpInfoBase + 1623,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VGMF
    { 2812,	3,	1,	6,	538,	0,	0,	SystemZOpInfoBase + 1623,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VGMB
    { 2811,	4,	1,	6,	538,	0,	0,	SystemZOpInfoBase + 1619,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VGM
    { 2810,	3,	1,	6,	598,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VGFMH
    { 2809,	3,	1,	6,	598,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VGFMG
    { 2808,	3,	1,	6,	598,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VGFMF
    { 2807,	3,	1,	6,	598,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VGFMB
    { 2806,	4,	1,	6,	597,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VGFMAH
    { 2805,	4,	1,	6,	597,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VGFMAG
    { 2804,	4,	1,	6,	597,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VGFMAF
    { 2803,	4,	1,	6,	597,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VGFMAB
    { 2802,	5,	1,	6,	597,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VGFMA
    { 2801,	4,	1,	6,	596,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VGFM
    { 2800,	2,	1,	6,	579,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VGEMQ
    { 2799,	2,	1,	6,	579,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VGEMH
    { 2798,	2,	1,	6,	579,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VGEMG
    { 2797,	2,	1,	6,	579,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VGEMF
    { 2796,	2,	1,	6,	579,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VGEMB
    { 2795,	3,	1,	6,	579,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VGEM
    { 2794,	6,	1,	6,	547,	0,	0,	SystemZOpInfoBase + 1613,	0,	0|(1ULL<<MCID::MayLoad), 0x100ULL },  // VGEG
    { 2793,	6,	1,	6,	547,	0,	0,	SystemZOpInfoBase + 1613,	0,	0|(1ULL<<MCID::MayLoad), 0x80ULL },  // VGEF
    { 2792,	2,	1,	6,	537,	0,	0,	SystemZOpInfoBase + 1611,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VGBM
    { 2791,	3,	1,	6,	692,	0,	1,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VFTCISB
    { 2790,	3,	1,	6,	691,	0,	1,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VFTCIDB
    { 2789,	5,	1,	6,	690,	0,	1,	SystemZOpInfoBase + 1545,	0,	0, 0x0ULL },  // VFTCI
    { 2788,	3,	1,	6,	697,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFSSB
    { 2787,	2,	1,	6,	718,	1,	0,	SystemZOpInfoBase + 444,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFSQSB
    { 2786,	2,	1,	6,	716,	1,	0,	SystemZOpInfoBase + 444,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFSQDB
    { 2785,	4,	1,	6,	715,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFSQ
    { 2784,	3,	1,	6,	695,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFSDB
    { 2783,	5,	1,	6,	694,	1,	0,	SystemZOpInfoBase + 456,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFS
    { 2782,	3,	1,	6,	679,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VFPSOSB
    { 2781,	3,	1,	6,	678,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VFPSODB
    { 2780,	5,	1,	6,	677,	0,	0,	SystemZOpInfoBase + 1545,	0,	0, 0x0ULL },  // VFPSO
    { 2779,	4,	1,	6,	707,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFNMSSB
    { 2778,	4,	1,	6,	705,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFNMSDB
    { 2777,	6,	1,	6,	704,	1,	0,	SystemZOpInfoBase + 1605,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFNMS
    { 2776,	4,	1,	6,	707,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFNMASB
    { 2775,	4,	1,	6,	705,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFNMADB
    { 2774,	6,	1,	6,	704,	1,	0,	SystemZOpInfoBase + 1605,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFNMA
    { 2773,	4,	1,	6,	707,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMSSB
    { 2772,	4,	1,	6,	931,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMSDB
    { 2771,	3,	1,	6,	702,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMSB
    { 2770,	6,	1,	6,	930,	1,	0,	SystemZOpInfoBase + 1605,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMS
    { 2769,	4,	1,	6,	687,	1,	0,	SystemZOpInfoBase + 1529,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMINSB
    { 2768,	4,	1,	6,	685,	1,	0,	SystemZOpInfoBase + 1529,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMINDB
    { 2767,	6,	1,	6,	684,	1,	0,	SystemZOpInfoBase + 1599,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMIN
    { 2766,	3,	1,	6,	700,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMDB
    { 2765,	4,	1,	6,	687,	1,	0,	SystemZOpInfoBase + 1529,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMAXSB
    { 2764,	4,	1,	6,	685,	1,	0,	SystemZOpInfoBase + 1529,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMAXDB
    { 2763,	6,	1,	6,	684,	1,	0,	SystemZOpInfoBase + 1599,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMAX
    { 2762,	4,	1,	6,	707,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMASB
    { 2761,	4,	1,	6,	931,	1,	0,	SystemZOpInfoBase + 1541,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMADB
    { 2760,	6,	1,	6,	930,	1,	0,	SystemZOpInfoBase + 1605,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFMA
    { 2759,	5,	1,	6,	919,	1,	0,	SystemZOpInfoBase + 456,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFM
    { 2758,	4,	1,	6,	668,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFLRD
    { 2757,	5,	1,	6,	667,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFLR
    { 2756,	2,	1,	6,	682,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VFLPSB
    { 2755,	2,	1,	6,	681,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VFLPDB
    { 2754,	2,	1,	6,	682,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VFLNSB
    { 2753,	2,	1,	6,	681,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VFLNDB
    { 2752,	2,	1,	6,	668,	1,	0,	SystemZOpInfoBase + 444,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFLLS
    { 2751,	4,	1,	6,	667,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFLL
    { 2750,	2,	1,	6,	682,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VFLCSB
    { 2749,	2,	1,	6,	681,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VFLCDB
    { 2748,	3,	1,	6,	732,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKHSBS
    { 2747,	3,	1,	6,	724,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKHSB
    { 2746,	3,	1,	6,	732,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKHESBS
    { 2745,	3,	1,	6,	724,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKHESB
    { 2744,	3,	1,	6,	730,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKHEDBS
    { 2743,	3,	1,	6,	721,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKHEDB
    { 2742,	3,	1,	6,	730,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKHDBS
    { 2741,	3,	1,	6,	721,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKHDB
    { 2740,	3,	1,	6,	732,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKESBS
    { 2739,	3,	1,	6,	724,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKESB
    { 2738,	3,	1,	6,	730,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKEDBS
    { 2737,	3,	1,	6,	721,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFKEDB
    { 2736,	4,	1,	6,	674,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFISB
    { 2735,	4,	1,	6,	672,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFIDB
    { 2734,	5,	1,	6,	918,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFI
    { 2733,	3,	1,	6,	751,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFENEZHS
    { 2732,	3,	1,	6,	750,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFENEZH
    { 2731,	3,	1,	6,	751,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFENEZFS
    { 2730,	3,	1,	6,	750,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFENEZF
    { 2729,	3,	1,	6,	751,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFENEZBS
    { 2728,	3,	1,	6,	750,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFENEZB
    { 2727,	3,	1,	6,	751,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFENEHS
    { 2726,	4,	1,	6,	750,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFENEH
    { 2725,	3,	1,	6,	751,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFENEFS
    { 2724,	4,	1,	6,	750,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFENEF
    { 2723,	3,	1,	6,	751,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFENEBS
    { 2722,	4,	1,	6,	750,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFENEB
    { 2721,	5,	1,	6,	750,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VFENE
    { 2720,	3,	1,	6,	749,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFEEZHS
    { 2719,	3,	1,	6,	748,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFEEZH
    { 2718,	3,	1,	6,	749,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFEEZFS
    { 2717,	3,	1,	6,	748,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFEEZF
    { 2716,	3,	1,	6,	749,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFEEZBS
    { 2715,	3,	1,	6,	748,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFEEZB
    { 2714,	3,	1,	6,	749,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFEEHS
    { 2713,	4,	1,	6,	748,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFEEH
    { 2712,	3,	1,	6,	749,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFEEFS
    { 2711,	4,	1,	6,	748,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFEEF
    { 2710,	3,	1,	6,	749,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VFEEBS
    { 2709,	4,	1,	6,	748,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFEEB
    { 2708,	5,	1,	6,	748,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VFEE
    { 2707,	3,	1,	6,	713,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFDSB
    { 2706,	3,	1,	6,	711,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFDDB
    { 2705,	5,	1,	6,	710,	1,	0,	SystemZOpInfoBase + 456,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFD
    { 2704,	3,	1,	6,	732,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCHSBS
    { 2703,	3,	1,	6,	724,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCHSB
    { 2702,	3,	1,	6,	732,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCHESBS
    { 2701,	3,	1,	6,	724,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCHESB
    { 2700,	3,	1,	6,	729,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCHEDBS
    { 2699,	3,	1,	6,	933,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCHEDB
    { 2698,	6,	1,	6,	720,	1,	0,	SystemZOpInfoBase + 1599,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCHE
    { 2697,	3,	1,	6,	729,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCHDBS
    { 2696,	3,	1,	6,	933,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCHDB
    { 2695,	6,	1,	6,	720,	1,	0,	SystemZOpInfoBase + 1599,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCH
    { 2694,	3,	1,	6,	732,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCESBS
    { 2693,	3,	1,	6,	724,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCESB
    { 2692,	3,	1,	6,	729,	1,	1,	SystemZOpInfoBase + 1533,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCEDBS
    { 2691,	3,	1,	6,	933,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCEDB
    { 2690,	6,	1,	6,	720,	1,	0,	SystemZOpInfoBase + 1599,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VFCE
    { 2689,	3,	1,	6,	697,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFASB
    { 2688,	4,	1,	6,	747,	0,	1,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEZHS
    { 2687,	4,	1,	6,	746,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEZH
    { 2686,	4,	1,	6,	747,	0,	1,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEZFS
    { 2685,	4,	1,	6,	746,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEZF
    { 2684,	4,	1,	6,	747,	0,	1,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEZBS
    { 2683,	4,	1,	6,	746,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEZB
    { 2682,	4,	1,	6,	745,	0,	1,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEHS
    { 2681,	4,	1,	6,	744,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEH
    { 2680,	4,	1,	6,	745,	0,	1,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEFS
    { 2679,	4,	1,	6,	744,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEF
    { 2678,	4,	1,	6,	745,	0,	1,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEBS
    { 2677,	4,	1,	6,	743,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VFAEB
    { 2676,	5,	1,	6,	743,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VFAE
    { 2675,	3,	1,	6,	695,	1,	0,	SystemZOpInfoBase + 1533,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFADB
    { 2674,	5,	1,	6,	694,	1,	0,	SystemZOpInfoBase + 456,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // VFA
    { 2673,	5,	1,	6,	594,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VEVAL
    { 2672,	3,	1,	6,	630,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESRLVH
    { 2671,	3,	1,	6,	630,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESRLVG
    { 2670,	3,	1,	6,	630,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESRLVF
    { 2669,	3,	1,	6,	630,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESRLVB
    { 2668,	4,	1,	6,	630,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VESRLV
    { 2667,	4,	1,	6,	629,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESRLH
    { 2666,	4,	1,	6,	629,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESRLG
    { 2665,	4,	1,	6,	629,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESRLF
    { 2664,	4,	1,	6,	629,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESRLB
    { 2663,	5,	1,	6,	629,	0,	0,	SystemZOpInfoBase + 1590,	0,	0, 0x0ULL },  // VESRL
    { 2662,	3,	1,	6,	628,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESRAVH
    { 2661,	3,	1,	6,	628,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESRAVG
    { 2660,	3,	1,	6,	628,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESRAVF
    { 2659,	3,	1,	6,	628,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESRAVB
    { 2658,	4,	1,	6,	628,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VESRAV
    { 2657,	4,	1,	6,	627,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESRAH
    { 2656,	4,	1,	6,	627,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESRAG
    { 2655,	4,	1,	6,	627,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESRAF
    { 2654,	4,	1,	6,	627,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESRAB
    { 2653,	5,	1,	6,	627,	0,	0,	SystemZOpInfoBase + 1590,	0,	0, 0x0ULL },  // VESRA
    { 2652,	3,	1,	6,	626,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESLVH
    { 2651,	3,	1,	6,	626,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESLVG
    { 2650,	3,	1,	6,	626,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESLVF
    { 2649,	3,	1,	6,	626,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VESLVB
    { 2648,	4,	1,	6,	626,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VESLV
    { 2647,	4,	1,	6,	625,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESLH
    { 2646,	4,	1,	6,	625,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESLG
    { 2645,	4,	1,	6,	625,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESLF
    { 2644,	4,	1,	6,	625,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VESLB
    { 2643,	5,	1,	6,	625,	0,	0,	SystemZOpInfoBase + 1590,	0,	0, 0x0ULL },  // VESL
    { 2642,	3,	1,	6,	623,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VERLLVH
    { 2641,	3,	1,	6,	623,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VERLLVG
    { 2640,	3,	1,	6,	623,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VERLLVF
    { 2639,	3,	1,	6,	623,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VERLLVB
    { 2638,	4,	1,	6,	623,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VERLLV
    { 2637,	4,	1,	6,	622,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VERLLH
    { 2636,	4,	1,	6,	622,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VERLLG
    { 2635,	4,	1,	6,	622,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VERLLF
    { 2634,	4,	1,	6,	622,	0,	0,	SystemZOpInfoBase + 1595,	0,	0, 0x0ULL },  // VERLLB
    { 2633,	5,	1,	6,	622,	0,	0,	SystemZOpInfoBase + 1590,	0,	0, 0x0ULL },  // VERLL
    { 2632,	5,	1,	6,	624,	0,	0,	SystemZOpInfoBase + 1585,	0,	0, 0x0ULL },  // VERIMH
    { 2631,	5,	1,	6,	624,	0,	0,	SystemZOpInfoBase + 1585,	0,	0, 0x0ULL },  // VERIMG
    { 2630,	5,	1,	6,	624,	0,	0,	SystemZOpInfoBase + 1585,	0,	0, 0x0ULL },  // VERIMF
    { 2629,	5,	1,	6,	624,	0,	0,	SystemZOpInfoBase + 1585,	0,	0, 0x0ULL },  // VERIMB
    { 2628,	6,	1,	6,	624,	0,	0,	SystemZOpInfoBase + 1579,	0,	0, 0x0ULL },  // VERIM
    { 2627,	2,	0,	6,	643,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECQ
    { 2626,	2,	0,	6,	644,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECLQ
    { 2625,	2,	0,	6,	904,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECLH
    { 2624,	2,	0,	6,	904,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECLG
    { 2623,	2,	0,	6,	904,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECLF
    { 2622,	2,	0,	6,	904,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECLB
    { 2621,	3,	0,	6,	904,	0,	1,	SystemZOpInfoBase + 1554,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECL
    { 2620,	2,	0,	6,	903,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECH
    { 2619,	2,	0,	6,	903,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECG
    { 2618,	2,	0,	6,	903,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECF
    { 2617,	2,	0,	6,	903,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VECB
    { 2616,	3,	0,	6,	903,	0,	1,	SystemZOpInfoBase + 1554,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VEC
    { 2615,	4,	1,	6,	593,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VDQ
    { 2614,	5,	1,	6,	770,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VDP
    { 2613,	4,	1,	6,	593,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VDLQ
    { 2612,	4,	1,	6,	593,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VDLG
    { 2611,	4,	1,	6,	593,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VDLF
    { 2610,	5,	1,	6,	593,	0,	0,	SystemZOpInfoBase + 456,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VDL
    { 2609,	4,	1,	6,	593,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VDG
    { 2608,	4,	1,	6,	593,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VDF
    { 2607,	5,	1,	6,	593,	0,	0,	SystemZOpInfoBase + 456,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // VD
    { 2606,	4,	1,	6,	767,	0,	1,	SystemZOpInfoBase + 1550,	0,	0, 0x0ULL },  // VCVDQ
    { 2605,	4,	1,	6,	912,	0,	1,	SystemZOpInfoBase + 1575,	0,	0, 0x0ULL },  // VCVDG
    { 2604,	4,	1,	6,	912,	0,	1,	SystemZOpInfoBase + 1571,	0,	0, 0x0ULL },  // VCVD
    { 2603,	3,	1,	6,	766,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VCVBQ
    { 2602,	4,	1,	6,	911,	0,	1,	SystemZOpInfoBase + 1567,	0,	0, 0x0ULL },  // VCVBOpt
    { 2601,	4,	1,	6,	911,	0,	1,	SystemZOpInfoBase + 1563,	0,	0, 0x0ULL },  // VCVBGOpt
    { 2600,	3,	1,	6,	920,	0,	1,	SystemZOpInfoBase + 1560,	0,	0, 0x0ULL },  // VCVBG
    { 2599,	3,	1,	6,	920,	0,	1,	SystemZOpInfoBase + 1557,	0,	0, 0x0ULL },  // VCVB
    { 2598,	2,	1,	6,	592,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VCTZQ
    { 2597,	2,	1,	6,	882,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VCTZH
    { 2596,	2,	1,	6,	882,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VCTZG
    { 2595,	2,	1,	6,	882,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VCTZF
    { 2594,	2,	1,	6,	882,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VCTZB
    { 2593,	3,	1,	6,	882,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VCTZ
    { 2592,	4,	1,	6,	777,	0,	0,	SystemZOpInfoBase + 1529,	0,	0, 0x0ULL },  // VCSPH
    { 2591,	5,	1,	6,	658,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCSFP
    { 2590,	5,	1,	6,	762,	1,	0,	SystemZOpInfoBase + 456,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCRNF
    { 2589,	3,	0,	6,	914,	0,	1,	SystemZOpInfoBase + 1554,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // VCP
    { 2588,	4,	1,	6,	762,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCNF
    { 2587,	2,	1,	6,	591,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VCLZQ
    { 2586,	2,	1,	6,	881,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VCLZH
    { 2585,	2,	1,	6,	881,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VCLZG
    { 2584,	2,	1,	6,	881,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VCLZF
    { 2583,	3,	1,	6,	778,	0,	1,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VCLZDP
    { 2582,	2,	1,	6,	881,	0,	0,	SystemZOpInfoBase + 444,	0,	0, 0x0ULL },  // VCLZB
    { 2581,	3,	1,	6,	881,	0,	0,	SystemZOpInfoBase + 1554,	0,	0, 0x0ULL },  // VCLZ
    { 2580,	4,	1,	6,	660,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCLGDB
    { 2579,	5,	1,	6,	659,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCLGD
    { 2578,	5,	1,	6,	658,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCLFP
    { 2577,	4,	1,	6,	761,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCLFNL
    { 2576,	4,	1,	6,	761,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCLFNH
    { 2575,	4,	1,	6,	662,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCLFEB
    { 2574,	3,	1,	6,	590,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCKSM
    { 2573,	3,	1,	6,	648,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHQS
    { 2572,	3,	1,	6,	647,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHQ
    { 2571,	3,	1,	6,	650,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHLQS
    { 2570,	3,	1,	6,	649,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHLQ
    { 2569,	3,	1,	6,	910,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHLHS
    { 2568,	3,	1,	6,	909,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHLH
    { 2567,	3,	1,	6,	910,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHLGS
    { 2566,	3,	1,	6,	909,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHLG
    { 2565,	3,	1,	6,	910,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHLFS
    { 2564,	3,	1,	6,	909,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHLF
    { 2563,	3,	1,	6,	910,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHLBS
    { 2562,	3,	1,	6,	909,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHLB
    { 2561,	5,	1,	6,	909,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VCHL
    { 2560,	3,	1,	6,	908,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHHS
    { 2559,	3,	1,	6,	907,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHH
    { 2558,	3,	1,	6,	908,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHGS
    { 2557,	3,	1,	6,	907,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHG
    { 2556,	3,	1,	6,	908,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHFS
    { 2555,	3,	1,	6,	907,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHF
    { 2554,	3,	1,	6,	908,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHBS
    { 2553,	3,	1,	6,	907,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCHB
    { 2552,	5,	1,	6,	907,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VCH
    { 2551,	4,	1,	6,	660,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCGDB
    { 2550,	5,	1,	6,	659,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCGD
    { 2549,	5,	1,	6,	652,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCFPS
    { 2548,	5,	1,	6,	652,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCFPL
    { 2547,	4,	1,	6,	760,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCFN
    { 2546,	4,	1,	6,	662,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCFEB
    { 2545,	3,	1,	6,	646,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCEQQS
    { 2544,	3,	1,	6,	645,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCEQQ
    { 2543,	3,	1,	6,	906,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCEQHS
    { 2542,	3,	1,	6,	905,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCEQH
    { 2541,	3,	1,	6,	906,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCEQGS
    { 2540,	3,	1,	6,	905,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCEQG
    { 2539,	3,	1,	6,	906,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCEQFS
    { 2538,	3,	1,	6,	905,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCEQF
    { 2537,	3,	1,	6,	906,	0,	1,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCEQBS
    { 2536,	3,	1,	6,	905,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VCEQB
    { 2535,	5,	1,	6,	905,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VCEQ
    { 2534,	4,	1,	6,	656,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCELFB
    { 2533,	4,	1,	6,	656,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCEFB
    { 2532,	4,	1,	6,	654,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCDLGB
    { 2531,	5,	1,	6,	653,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCDLG
    { 2530,	4,	1,	6,	654,	1,	0,	SystemZOpInfoBase + 1550,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCDGB
    { 2529,	5,	1,	6,	653,	1,	0,	SystemZOpInfoBase + 1545,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // VCDG
    { 2528,	3,	1,	6,	569,	0,	0,	SystemZOpInfoBase + 1533,	0,	0, 0x0ULL },  // VBPERM
    { 2527,	4,	1,	6,	572,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VBLENDQ
    { 2526,	4,	1,	6,	572,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VBLENDH
    { 2525,	4,	1,	6,	572,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VBLENDG
    { 2524,	4,	1,	6,	572,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VBLENDF
    { 2523,	4,	1,	6,	572,	0,	0,	SystemZOpInfoBase + 1541,	0,	0, 0x0ULL },  // VBLENDB
    { 2522,	5,	1,	6,	572,	0,	0,	SystemZOpInfoBase + 1536,	0,	0, 0x0ULL },  // VBLEND
    { 2521,	3,	1,	6,	586,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGQ
    { 2520,	3,	1,	6,	587,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGLQ
    { 2519,	3,	1,	6,	880,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGLH
    { 2518,	3,	1,	6,	880,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGLG
    { 2517,	3,	1,	6,	880,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGLF
    { 2516,	3,	1,	6,	880,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGLB
    { 2515,	4,	1,	6,	880,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGL
    { 2514,	3,	1,	6,	879,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGH
    { 2513,	3,	1,	6,	879,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGG
    { 2512,	3,	1,	6,	879,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGF
    { 2511,	3,	1,	6,	879,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVGB
    { 2510,	4,	1,	6,	879,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAVG
    { 2509,	3,	1,	6,	584,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAQ
    { 2508,	5,	1,	6,	768,	0,	1,	SystemZOpInfoBase + 456,	0,	0, 0x0ULL },  // VAP
    { 2507,	3,	1,	6,	584,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAH
    { 2506,	3,	1,	6,	584,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAG
    { 2505,	3,	1,	6,	584,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAF
    { 2504,	4,	1,	6,	584,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VACQ
    { 2503,	3,	1,	6,	585,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VACCQ
    { 2502,	3,	1,	6,	585,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VACCH
    { 2501,	3,	1,	6,	585,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VACCG
    { 2500,	3,	1,	6,	585,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VACCF
    { 2499,	4,	1,	6,	585,	0,	0,	SystemZOpInfoBase + 1541,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VACCCQ
    { 2498,	5,	1,	6,	585,	0,	0,	SystemZOpInfoBase + 1536,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VACCC
    { 2497,	3,	1,	6,	585,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VACCB
    { 2496,	4,	1,	6,	585,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VACC
    { 2495,	5,	1,	6,	584,	0,	0,	SystemZOpInfoBase + 1536,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAC
    { 2494,	3,	1,	6,	584,	0,	0,	SystemZOpInfoBase + 1533,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VAB
    { 2493,	4,	1,	6,	584,	0,	0,	SystemZOpInfoBase + 1529,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // VA
    { 2492,	0,	0,	2,	339,	6,	6,	SystemZOpInfoBase + 1,	92,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // UPT
    { 2491,	5,	0,	6,	306,	0,	1,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // UNPKU
    { 2490,	5,	0,	6,	306,	0,	1,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // UNPKA
    { 2489,	6,	0,	6,	307,	0,	0,	SystemZOpInfoBase + 579,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // UNPK
    { 2488,	2,	0,	4,	866,	1,	1,	SystemZOpInfoBase + 260,	41,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TSCH
    { 2487,	2,	0,	4,	275,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x20ULL },  // TS
    { 2486,	4,	2,	4,	291,	2,	1,	SystemZOpInfoBase + 1513,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // TRTTOpt
    { 2485,	5,	2,	4,	291,	2,	1,	SystemZOpInfoBase + 1517,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // TRTT
    { 2484,	3,	2,	4,	290,	1,	1,	SystemZOpInfoBase + 1526,	90,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // TRTREOpt
    { 2483,	4,	2,	4,	290,	1,	1,	SystemZOpInfoBase + 1522,	90,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // TRTRE
    { 2482,	5,	0,	6,	288,	0,	3,	SystemZOpInfoBase + 832,	87,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // TRTR
    { 2481,	4,	2,	4,	291,	2,	1,	SystemZOpInfoBase + 1513,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // TRTOOpt
    { 2480,	5,	2,	4,	291,	2,	1,	SystemZOpInfoBase + 1517,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // TRTO
    { 2479,	3,	2,	4,	290,	1,	1,	SystemZOpInfoBase + 1526,	90,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // TRTEOpt
    { 2478,	4,	2,	4,	290,	1,	1,	SystemZOpInfoBase + 1522,	90,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // TRTE
    { 2477,	5,	0,	6,	287,	0,	3,	SystemZOpInfoBase + 832,	87,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // TRT
    { 2476,	4,	2,	4,	291,	2,	1,	SystemZOpInfoBase + 1513,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // TROTOpt
    { 2475,	5,	2,	4,	291,	2,	1,	SystemZOpInfoBase + 1517,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // TROT
    { 2474,	4,	2,	4,	291,	2,	1,	SystemZOpInfoBase + 1513,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // TROOOpt
    { 2473,	5,	2,	4,	291,	2,	1,	SystemZOpInfoBase + 1517,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // TROO
    { 2472,	4,	2,	4,	289,	1,	0,	SystemZOpInfoBase + 1513,	55,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // TRE
    { 2471,	2,	0,	4,	855,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TRAP4
    { 2470,	0,	0,	2,	855,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TRAP2
    { 2469,	4,	0,	6,	854,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // TRACG
    { 2468,	4,	0,	4,	853,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TRACE
    { 2467,	5,	0,	6,	286,	0,	0,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // TR
    { 2466,	4,	0,	6,	818,	0,	1,	SystemZOpInfoBase + 1179,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TPROT
    { 2465,	2,	0,	4,	935,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TPI
    { 2464,	2,	1,	4,	870,	0,	1,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TPEI
    { 2463,	3,	0,	6,	313,	0,	1,	SystemZOpInfoBase + 1510,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // TP
    { 2462,	3,	0,	6,	258,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x4ULL },  // TMY
    { 2461,	2,	0,	4,	263,	0,	1,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // TMLL
    { 2460,	2,	0,	4,	262,	0,	1,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // TMLH
    { 2459,	2,	0,	4,	261,	0,	1,	SystemZOpInfoBase + 819,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // TMHL
    { 2458,	2,	0,	4,	260,	0,	1,	SystemZOpInfoBase + 819,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // TMHH
    { 2457,	3,	0,	4,	258,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x0ULL },  // TM
    { 2456,	2,	1,	4,	432,	0,	1,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // THDR
    { 2455,	2,	1,	4,	432,	0,	1,	SystemZOpInfoBase + 1194,	0,	0, 0x0ULL },  // THDER
    { 2454,	0,	0,	4,	327,	0,	1,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TEND
    { 2453,	4,	0,	6,	530,	0,	1,	SystemZOpInfoBase + 356,	0,	0, 0x8ULL },  // TDGXT
    { 2452,	4,	0,	6,	529,	0,	1,	SystemZOpInfoBase + 700,	0,	0, 0x8ULL },  // TDGET
    { 2451,	4,	0,	6,	947,	0,	1,	SystemZOpInfoBase + 672,	0,	0, 0x8ULL },  // TDGDT
    { 2450,	4,	0,	6,	530,	0,	1,	SystemZOpInfoBase + 356,	0,	0, 0x8ULL },  // TDCXT
    { 2449,	4,	0,	6,	529,	0,	1,	SystemZOpInfoBase + 700,	0,	0, 0x8ULL },  // TDCET
    { 2448,	4,	0,	6,	947,	0,	1,	SystemZOpInfoBase + 672,	0,	0, 0x8ULL },  // TDCDT
    { 2447,	4,	0,	6,	411,	0,	1,	SystemZOpInfoBase + 356,	0,	0, 0x3008ULL },  // TCXB
    { 2446,	4,	0,	6,	410,	0,	1,	SystemZOpInfoBase + 700,	0,	0, 0x3008ULL },  // TCEB
    { 2445,	4,	0,	6,	410,	0,	1,	SystemZOpInfoBase + 672,	0,	0, 0x3008ULL },  // TCDB
    { 2444,	3,	0,	6,	326,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TBEGINC
    { 2443,	3,	0,	6,	326,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TBEGIN
    { 2442,	3,	1,	4,	433,	0,	1,	SystemZOpInfoBase + 1507,	0,	0, 0x0ULL },  // TBEDR
    { 2441,	3,	1,	4,	433,	0,	1,	SystemZOpInfoBase + 1006,	0,	0, 0x0ULL },  // TBDR
    { 2440,	2,	0,	4,	804,	1,	2,	SystemZOpInfoBase + 598,	70,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TB
    { 2439,	2,	0,	4,	830,	0,	1,	SystemZOpInfoBase + 1446,	0,	0, 0x0ULL },  // TAR
    { 2438,	0,	0,	2,	322,	0,	1,	SystemZOpInfoBase + 1,	0,	0, 0x0ULL },  // TAM
    { 2437,	2,	0,	4,	328,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TABORT
    { 2436,	5,	1,	6,	130,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x223c8cULL },  // SY
    { 2435,	4,	1,	4,	512,	1,	1,	SystemZOpInfoBase + 591,	1,	0, 0x0ULL },  // SXTRA
    { 2434,	3,	1,	4,	512,	1,	1,	SystemZOpInfoBase + 588,	1,	0, 0x0ULL },  // SXTR
    { 2433,	3,	1,	2,	448,	0,	1,	SystemZOpInfoBase + 585,	0,	0, 0x0ULL },  // SXR
    { 2432,	3,	1,	4,	391,	1,	1,	SystemZOpInfoBase + 585,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x3fc00ULL },  // SXBR
    { 2431,	3,	1,	2,	447,	0,	1,	SystemZOpInfoBase + 532,	0,	0, 0x0ULL },  // SWR
    { 2430,	5,	1,	4,	446,	0,	1,	SystemZOpInfoBase + 527,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // SW
    { 2429,	1,	0,	2,	850,	0,	1,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SVC
    { 2428,	3,	1,	2,	447,	0,	1,	SystemZOpInfoBase + 547,	0,	0, 0x0ULL },  // SUR
    { 2427,	5,	1,	4,	446,	0,	1,	SystemZOpInfoBase + 542,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // SU
    { 2426,	4,	0,	6,	48,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayStore), 0x8eULL },  // STY
    { 2425,	2,	0,	4,	817,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STURG
    { 2424,	2,	0,	4,	817,	0,	0,	SystemZOpInfoBase + 991,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STURA
    { 2423,	2,	0,	4,	843,	2,	2,	SystemZOpInfoBase + 260,	83,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STSI
    { 2422,	2,	0,	4,	866,	1,	1,	SystemZOpInfoBase + 260,	41,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STSCH
    { 2421,	4,	0,	6,	84,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayStore), 0x4cULL },  // STRVH
    { 2420,	4,	0,	6,	84,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayStore), 0x10cULL },  // STRVG
    { 2419,	4,	0,	6,	84,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayStore), 0x8cULL },  // STRV
    { 2418,	2,	0,	6,	48,	0,	0,	SystemZOpInfoBase + 808,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STRL
    { 2417,	4,	0,	6,	815,	0,	0,	SystemZOpInfoBase + 1179,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STRAG
    { 2416,	2,	0,	4,	795,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // STPX
    { 2415,	2,	0,	4,	840,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // STPT
    { 2414,	4,	0,	6,	282,	0,	0,	SystemZOpInfoBase + 311,	0,	0|(1ULL<<MCID::MayStore), 0x20cULL },  // STPQ
    { 2413,	3,	0,	4,	787,	0,	0,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STOSM
    { 2412,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmZ
    { 2411,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmP
    { 2410,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmO
    { 2409,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmNZ
    { 2408,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmNP
    { 2407,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmNO
    { 2406,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmNM
    { 2405,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmNLH
    { 2404,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmNLE
    { 2403,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmNL
    { 2402,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmNHE
    { 2401,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmNH
    { 2400,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmNE
    { 2399,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmM
    { 2398,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmLH
    { 2397,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmLE
    { 2396,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmL
    { 2395,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmHE
    { 2394,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmH
    { 2393,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsmE
    { 2392,	4,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 847,	0,	0|(1ULL<<MCID::MayStore), 0x104ULL },  // STOCGAsm
    { 2391,	5,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 1502,	0,	0|(1ULL<<MCID::MayStore), 0x80104ULL },  // STOCG
    { 2390,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmZ
    { 2389,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmP
    { 2388,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmO
    { 2387,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmNZ
    { 2386,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmNP
    { 2385,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmNO
    { 2384,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmNM
    { 2383,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmNLH
    { 2382,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmNLE
    { 2381,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmNL
    { 2380,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmNHE
    { 2379,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmNH
    { 2378,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmNE
    { 2377,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmM
    { 2376,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmLH
    { 2375,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmLE
    { 2374,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmL
    { 2373,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmHE
    { 2372,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmH
    { 2371,	3,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1499,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsmE
    { 2370,	4,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1495,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCFHAsm
    { 2369,	5,	0,	6,	54,	1,	0,	SystemZOpInfoBase + 1490,	0,	0|(1ULL<<MCID::MayStore), 0x80084ULL },  // STOCFH
    { 2368,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmZ
    { 2367,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmP
    { 2366,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmO
    { 2365,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmNZ
    { 2364,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmNP
    { 2363,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmNO
    { 2362,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmNM
    { 2361,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmNLH
    { 2360,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmNLE
    { 2359,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmNL
    { 2358,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmNHE
    { 2357,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmNH
    { 2356,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmNE
    { 2355,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmM
    { 2354,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmLH
    { 2353,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmLE
    { 2352,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmL
    { 2351,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmHE
    { 2350,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmH
    { 2349,	3,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsmE
    { 2348,	4,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 880,	0,	0|(1ULL<<MCID::MayStore), 0x84ULL },  // STOCAsm
    { 2347,	5,	0,	6,	938,	1,	0,	SystemZOpInfoBase + 1485,	0,	0|(1ULL<<MCID::MayStore), 0x80084ULL },  // STOC
    { 2346,	3,	0,	4,	787,	0,	0,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STNSM
    { 2345,	4,	0,	6,	81,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL },  // STMY
    { 2344,	4,	0,	6,	81,	0,	0,	SystemZOpInfoBase + 1223,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL },  // STMH
    { 2343,	4,	0,	6,	81,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL },  // STMG
    { 2342,	4,	0,	4,	81,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STM
    { 2341,	2,	0,	4,	842,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // STIDP
    { 2340,	4,	0,	6,	77,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayStore), 0x4cULL },  // STHY
    { 2339,	2,	0,	6,	77,	0,	0,	SystemZOpInfoBase + 808,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STHRL
    { 2338,	4,	0,	6,	77,	0,	0,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::MayStore), 0x4cULL },  // STHH
    { 2337,	4,	0,	4,	77,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayStore), 0x48ULL },  // STH
    { 2336,	4,	0,	6,	299,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0xcULL },  // STGSC
    { 2335,	2,	0,	6,	46,	0,	0,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STGRL
    { 2334,	4,	0,	6,	46,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayStore), 0x10eULL },  // STG
    { 2333,	2,	0,	4,	413,	1,	0,	SystemZOpInfoBase + 260,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // STFPC
    { 2332,	2,	0,	4,	844,	1,	2,	SystemZOpInfoBase + 260,	70,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STFLE
    { 2331,	2,	0,	4,	844,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // STFL
    { 2330,	4,	0,	6,	48,	0,	0,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::MayStore), 0x8eULL },  // STFH
    { 2329,	4,	0,	6,	359,	0,	0,	SystemZOpInfoBase + 700,	0,	0|(1ULL<<MCID::MayStore), 0x8eULL },  // STEY
    { 2328,	4,	0,	6,	359,	0,	0,	SystemZOpInfoBase + 1201,	0,	0|(1ULL<<MCID::MayStore), 0x8eULL },  // STE16Y
    { 2327,	4,	0,	4,	359,	0,	0,	SystemZOpInfoBase + 1201,	0,	0|(1ULL<<MCID::MayStore), 0x8aULL },  // STE16
    { 2326,	4,	0,	4,	359,	0,	0,	SystemZOpInfoBase + 700,	0,	0|(1ULL<<MCID::MayStore), 0x8aULL },  // STE
    { 2325,	4,	0,	6,	359,	0,	0,	SystemZOpInfoBase + 672,	0,	0|(1ULL<<MCID::MayStore), 0x10eULL },  // STDY
    { 2324,	4,	0,	4,	359,	0,	0,	SystemZOpInfoBase + 672,	0,	0|(1ULL<<MCID::MayStore), 0x10aULL },  // STD
    { 2323,	4,	0,	6,	76,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayStore), 0x2cULL },  // STCY
    { 2322,	4,	0,	4,	791,	0,	0,	SystemZOpInfoBase + 1190,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STCTL
    { 2321,	4,	0,	6,	791,	0,	0,	SystemZOpInfoBase + 1190,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // STCTG
    { 2320,	2,	0,	4,	869,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STCRW
    { 2319,	2,	0,	4,	869,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STCPS
    { 2318,	4,	0,	6,	78,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL },  // STCMY
    { 2317,	4,	0,	6,	78,	0,	0,	SystemZOpInfoBase + 854,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL },  // STCMH
    { 2316,	4,	0,	4,	78,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STCM
    { 2315,	2,	0,	4,	837,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // STCKF
    { 2314,	2,	0,	4,	838,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x200ULL },  // STCKE
    { 2313,	2,	0,	4,	839,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // STCKC
    { 2312,	2,	0,	4,	837,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // STCK
    { 2311,	4,	0,	6,	76,	0,	0,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::MayStore), 0x2cULL },  // STCH
    { 2310,	4,	0,	4,	76,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayStore), 0x28ULL },  // STC
    { 2309,	2,	0,	4,	797,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // STBEAR
    { 2308,	2,	0,	4,	841,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x40ULL },  // STAP
    { 2307,	4,	0,	6,	318,	0,	0,	SystemZOpInfoBase + 1175,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL },  // STAMY
    { 2306,	4,	0,	4,	318,	0,	0,	SystemZOpInfoBase + 1175,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STAM
    { 2305,	4,	0,	4,	48,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayStore), 0x8aULL },  // ST
    { 2304,	2,	0,	4,	786,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x20ULL },  // SSM
    { 2303,	2,	0,	4,	800,	0,	1,	SystemZOpInfoBase + 991,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SSKEOpt
    { 2302,	3,	0,	4,	800,	0,	1,	SystemZOpInfoBase + 1482,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SSKE
    { 2301,	2,	0,	4,	866,	1,	1,	SystemZOpInfoBase + 260,	41,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SSCH
    { 2300,	1,	0,	4,	793,	0,	0,	SystemZOpInfoBase + 995,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SSAR
    { 2299,	1,	0,	4,	793,	0,	0,	SystemZOpInfoBase + 307,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SSAIR
    { 2298,	5,	1,	6,	522,	0,	0,	SystemZOpInfoBase + 1469,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // SRXT
    { 2297,	4,	2,	4,	336,	1,	1,	SystemZOpInfoBase + 876,	35,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // SRSTU
    { 2296,	4,	2,	4,	336,	1,	1,	SystemZOpInfoBase + 876,	35,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // SRST
    { 2295,	6,	0,	6,	311,	0,	1,	SystemZOpInfoBase + 1476,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // SRP
    { 2294,	2,	0,	4,	418,	1,	1,	SystemZOpInfoBase + 1474,	81,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SRNMT
    { 2293,	2,	0,	4,	418,	1,	1,	SystemZOpInfoBase + 1474,	81,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SRNMB
    { 2292,	2,	0,	4,	418,	1,	1,	SystemZOpInfoBase + 1474,	81,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SRNM
    { 2291,	4,	1,	6,	210,	0,	0,	SystemZOpInfoBase + 1432,	0,	0, 0x4ULL },  // SRLK
    { 2290,	4,	1,	6,	210,	0,	0,	SystemZOpInfoBase + 987,	0,	0, 0x4ULL },  // SRLG
    { 2289,	4,	1,	4,	210,	0,	0,	SystemZOpInfoBase + 1461,	0,	0, 0x0ULL },  // SRL
    { 2288,	3,	1,	4,	138,	0,	1,	SystemZOpInfoBase + 576,	0,	0, 0x223c00ULL },  // SRK
    { 2287,	5,	1,	6,	521,	0,	0,	SystemZOpInfoBase + 155,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // SRDT
    { 2286,	4,	1,	4,	213,	0,	0,	SystemZOpInfoBase + 1465,	0,	0, 0x0ULL },  // SRDL
    { 2285,	4,	1,	4,	213,	0,	1,	SystemZOpInfoBase + 1465,	0,	0, 0x3b800ULL },  // SRDA
    { 2284,	4,	1,	6,	211,	0,	1,	SystemZOpInfoBase + 1432,	0,	0, 0x3b804ULL },  // SRAK
    { 2283,	4,	1,	6,	211,	0,	1,	SystemZOpInfoBase + 987,	0,	0, 0x3b804ULL },  // SRAG
    { 2282,	4,	1,	4,	211,	0,	1,	SystemZOpInfoBase + 1461,	0,	0, 0x3b800ULL },  // SRA
    { 2281,	3,	1,	2,	138,	0,	1,	SystemZOpInfoBase + 573,	0,	0, 0x223c00ULL },  // SR
    { 2280,	2,	1,	4,	440,	0,	0,	SystemZOpInfoBase + 718,	0,	0, 0x0ULL },  // SQXR
    { 2279,	2,	1,	4,	383,	1,	0,	SystemZOpInfoBase + 718,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // SQXBR
    { 2278,	2,	1,	4,	438,	0,	0,	SystemZOpInfoBase + 704,	0,	0, 0x0ULL },  // SQER
    { 2277,	2,	1,	4,	381,	1,	0,	SystemZOpInfoBase + 704,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // SQEBR
    { 2276,	4,	1,	6,	380,	1,	0,	SystemZOpInfoBase + 700,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // SQEB
    { 2275,	4,	1,	6,	437,	0,	0,	SystemZOpInfoBase + 700,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // SQE
    { 2274,	2,	1,	4,	439,	0,	0,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // SQDR
    { 2273,	2,	1,	4,	382,	1,	0,	SystemZOpInfoBase + 676,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // SQDBR
    { 2272,	4,	1,	6,	380,	1,	0,	SystemZOpInfoBase + 672,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // SQDB
    { 2271,	4,	1,	6,	437,	0,	0,	SystemZOpInfoBase + 672,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // SQD
    { 2270,	2,	0,	4,	795,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // SPX
    { 2269,	2,	0,	4,	836,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // SPT
    { 2268,	1,	0,	2,	320,	0,	1,	SystemZOpInfoBase + 995,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPM
    { 2267,	2,	0,	4,	785,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPKA
    { 2266,	2,	0,	4,	864,	0,	1,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SPCTR
    { 2265,	6,	0,	6,	308,	0,	1,	SystemZOpInfoBase + 579,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // SP
    { 2264,	4,	2,	4,	342,	2,	1,	SystemZOpInfoBase + 837,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // SORTL
    { 2263,	5,	1,	6,	134,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x101c8cULL },  // SLY
    { 2262,	5,	1,	6,	522,	0,	0,	SystemZOpInfoBase + 1469,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // SLXT
    { 2261,	3,	1,	4,	137,	0,	1,	SystemZOpInfoBase + 576,	0,	0, 0x101c00ULL },  // SLRK
    { 2260,	3,	1,	2,	137,	0,	1,	SystemZOpInfoBase + 573,	0,	0, 0x101c00ULL },  // SLR
    { 2259,	4,	1,	6,	209,	0,	0,	SystemZOpInfoBase + 1432,	0,	0, 0x4ULL },  // SLLK
    { 2258,	4,	1,	6,	209,	0,	0,	SystemZOpInfoBase + 987,	0,	0, 0x4ULL },  // SLLG
    { 2257,	4,	1,	4,	209,	0,	0,	SystemZOpInfoBase + 1461,	0,	0, 0x0ULL },  // SLL
    { 2256,	3,	1,	4,	140,	0,	1,	SystemZOpInfoBase + 567,	0,	0, 0x101c00ULL },  // SLHHLR
    { 2255,	3,	1,	4,	139,	0,	1,	SystemZOpInfoBase + 564,	0,	0, 0x101c00ULL },  // SLHHHR
    { 2254,	3,	1,	4,	136,	0,	1,	SystemZOpInfoBase + 391,	0,	0, 0x101c00ULL },  // SLGRK
    { 2253,	3,	1,	4,	136,	0,	1,	SystemZOpInfoBase + 561,	0,	0, 0x101c00ULL },  // SLGR
    { 2252,	3,	1,	4,	135,	0,	1,	SystemZOpInfoBase + 558,	0,	0, 0x101c00ULL },  // SLGFR
    { 2251,	3,	1,	6,	135,	0,	1,	SystemZOpInfoBase + 308,	0,	0, 0x101c00ULL },  // SLGFI
    { 2250,	5,	1,	6,	134,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x101c8cULL },  // SLGF
    { 2249,	5,	1,	6,	134,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x101d0cULL },  // SLG
    { 2248,	3,	1,	6,	133,	0,	1,	SystemZOpInfoBase + 550,	0,	0, 0x101c00ULL },  // SLFI
    { 2247,	5,	1,	6,	521,	0,	0,	SystemZOpInfoBase + 155,	0,	0|(1ULL<<MCID::MayLoad), 0x8ULL },  // SLDT
    { 2246,	4,	1,	4,	213,	0,	0,	SystemZOpInfoBase + 1465,	0,	0, 0x0ULL },  // SLDL
    { 2245,	4,	1,	4,	213,	0,	1,	SystemZOpInfoBase + 1465,	0,	0, 0x0ULL },  // SLDA
    { 2244,	3,	1,	4,	142,	1,	1,	SystemZOpInfoBase + 573,	26,	0, 0x103c00ULL },  // SLBR
    { 2243,	3,	1,	4,	142,	1,	1,	SystemZOpInfoBase + 561,	26,	0, 0x103c00ULL },  // SLBGR
    { 2242,	5,	1,	6,	141,	1,	1,	SystemZOpInfoBase + 553,	26,	0|(1ULL<<MCID::MayLoad), 0x103d0cULL },  // SLBG
    { 2241,	5,	1,	6,	141,	1,	1,	SystemZOpInfoBase + 522,	26,	0|(1ULL<<MCID::MayLoad), 0x103c8cULL },  // SLB
    { 2240,	4,	1,	6,	212,	0,	1,	SystemZOpInfoBase + 1432,	0,	0, 0x4ULL },  // SLAK
    { 2239,	4,	1,	6,	212,	0,	1,	SystemZOpInfoBase + 987,	0,	0, 0x4ULL },  // SLAG
    { 2238,	4,	1,	4,	212,	0,	1,	SystemZOpInfoBase + 1461,	0,	0, 0x0ULL },  // SLA
    { 2237,	5,	1,	4,	134,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x101c88ULL },  // SL
    { 2236,	4,	0,	4,	856,	0,	1,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SIGP
    { 2235,	2,	0,	4,	856,	4,	1,	SystemZOpInfoBase + 260,	76,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SIGA
    { 2234,	2,	0,	4,	857,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SIE
    { 2233,	5,	1,	6,	131,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x223c4cULL },  // SHY
    { 2232,	3,	1,	4,	140,	0,	1,	SystemZOpInfoBase + 567,	0,	0, 0x223c00ULL },  // SHHLR
    { 2231,	3,	1,	4,	139,	0,	1,	SystemZOpInfoBase + 564,	0,	0, 0x223c00ULL },  // SHHHR
    { 2230,	5,	1,	4,	131,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x223c48ULL },  // SH
    { 2229,	3,	1,	4,	132,	0,	1,	SystemZOpInfoBase + 391,	0,	0, 0x223c00ULL },  // SGRK
    { 2228,	3,	1,	4,	132,	0,	1,	SystemZOpInfoBase + 561,	0,	0, 0x223c00ULL },  // SGR
    { 2227,	5,	1,	6,	143,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x223c4cULL },  // SGH
    { 2226,	3,	1,	4,	144,	0,	1,	SystemZOpInfoBase + 558,	0,	0, 0x223c00ULL },  // SGFR
    { 2225,	5,	1,	6,	922,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x223c8cULL },  // SGF
    { 2224,	5,	1,	6,	130,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x223d0cULL },  // SG
    { 2223,	1,	0,	4,	414,	0,	1,	SystemZOpInfoBase + 995,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SFPC
    { 2222,	1,	0,	4,	416,	0,	1,	SystemZOpInfoBase + 995,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SFASR
    { 2221,	3,	1,	2,	447,	0,	1,	SystemZOpInfoBase + 547,	0,	0, 0x0ULL },  // SER
    { 2220,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmZ
    { 2219,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmP
    { 2218,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmO
    { 2217,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmNZ
    { 2216,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmNP
    { 2215,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmNO
    { 2214,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmNM
    { 2213,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmNLH
    { 2212,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmNLE
    { 2211,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmNL
    { 2210,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmNHE
    { 2209,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmNH
    { 2208,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmNE
    { 2207,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmM
    { 2206,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmLH
    { 2205,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmLE
    { 2204,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmL
    { 2203,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmHE
    { 2202,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmH
    { 2201,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 576,	0,	0, 0x0ULL },  // SELRAsmE
    { 2200,	4,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 1457,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // SELRAsm
    { 2199,	5,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 461,	0,	0|(1ULL<<MCID::Commutable), 0x80000ULL },  // SELR
    { 2198,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmZ
    { 2197,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmP
    { 2196,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmO
    { 2195,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmNZ
    { 2194,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmNP
    { 2193,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmNO
    { 2192,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmNM
    { 2191,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmNLH
    { 2190,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmNLE
    { 2189,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmNL
    { 2188,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmNHE
    { 2187,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmNH
    { 2186,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmNE
    { 2185,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmM
    { 2184,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmLH
    { 2183,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmLE
    { 2182,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmL
    { 2181,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmHE
    { 2180,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmH
    { 2179,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // SELGRAsmE
    { 2178,	4,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 1037,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // SELGRAsm
    { 2177,	5,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 466,	0,	0|(1ULL<<MCID::Commutable), 0x80000ULL },  // SELGR
    { 2176,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmZ
    { 2175,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmP
    { 2174,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmO
    { 2173,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmNZ
    { 2172,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmNP
    { 2171,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmNO
    { 2170,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmNM
    { 2169,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmNLH
    { 2168,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmNLE
    { 2167,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmNL
    { 2166,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmNHE
    { 2165,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmNH
    { 2164,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmNE
    { 2163,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmM
    { 2162,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmLH
    { 2161,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmLE
    { 2160,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmL
    { 2159,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmHE
    { 2158,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmH
    { 2157,	3,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 564,	0,	0, 0x0ULL },  // SELFHRAsmE
    { 2156,	4,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 1453,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // SELFHRAsm
    { 2155,	5,	1,	4,	56,	1,	0,	SystemZOpInfoBase + 1448,	0,	0|(1ULL<<MCID::Commutable), 0x80000ULL },  // SELFHR
    { 2154,	3,	1,	4,	390,	1,	1,	SystemZOpInfoBase + 547,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x3fc00ULL },  // SEBR
    { 2153,	5,	1,	6,	389,	1,	1,	SystemZOpInfoBase + 542,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3fc88ULL },  // SEB
    { 2152,	5,	1,	4,	446,	0,	1,	SystemZOpInfoBase + 542,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // SE
    { 2151,	4,	1,	4,	511,	1,	1,	SystemZOpInfoBase + 538,	1,	0, 0x0ULL },  // SDTRA
    { 2150,	3,	1,	4,	511,	1,	1,	SystemZOpInfoBase + 535,	1,	0, 0x0ULL },  // SDTR
    { 2149,	3,	1,	2,	447,	0,	1,	SystemZOpInfoBase + 532,	0,	0, 0x0ULL },  // SDR
    { 2148,	3,	1,	4,	390,	1,	1,	SystemZOpInfoBase + 532,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x3fc00ULL },  // SDBR
    { 2147,	5,	1,	6,	389,	1,	1,	SystemZOpInfoBase + 527,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3fd08ULL },  // SDB
    { 2146,	5,	1,	4,	446,	0,	1,	SystemZOpInfoBase + 527,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // SD
    { 2145,	0,	0,	2,	949,	1,	0,	SystemZOpInfoBase + 1,	55,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SCKPF
    { 2144,	2,	0,	4,	835,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // SCKC
    { 2143,	2,	0,	4,	948,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // SCK
    { 2142,	0,	0,	4,	868,	2,	0,	SystemZOpInfoBase + 1,	74,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SCHM
    { 2141,	2,	0,	4,	864,	0,	1,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SCCTR
    { 2140,	2,	1,	4,	315,	0,	0,	SystemZOpInfoBase + 1446,	0,	0, 0x0ULL },  // SAR
    { 2139,	0,	0,	2,	323,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SAM64
    { 2138,	0,	0,	2,	323,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SAM31
    { 2137,	0,	0,	2,	323,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SAM24
    { 2136,	0,	0,	4,	871,	1,	0,	SystemZOpInfoBase + 1,	73,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SAL
    { 2135,	2,	0,	4,	789,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SACF
    { 2134,	2,	0,	4,	789,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SAC
    { 2133,	5,	1,	4,	130,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x223c88ULL },  // S
    { 2132,	5,	1,	6,	219,	0,	1,	SystemZOpInfoBase + 1288,	0,	0, 0x0ULL },  // RXSBGOpt
    { 2131,	6,	1,	6,	219,	0,	1,	SystemZOpInfoBase + 1404,	0,	0, 0x0ULL },  // RXSBG
    { 2130,	0,	0,	4,	865,	1,	1,	SystemZOpInfoBase + 1,	41,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RSCH
    { 2129,	5,	2,	4,	520,	1,	0,	SystemZOpInfoBase + 1441,	12,	0, 0x0ULL },  // RRXTR
    { 2128,	5,	2,	4,	519,	1,	0,	SystemZOpInfoBase + 1436,	12,	0, 0x0ULL },  // RRDTR
    { 2127,	2,	1,	4,	801,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RRBM
    { 2126,	2,	0,	4,	801,	0,	1,	SystemZOpInfoBase + 991,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RRBE
    { 2125,	2,	0,	4,	828,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RP
    { 2124,	5,	1,	6,	219,	0,	1,	SystemZOpInfoBase + 1288,	0,	0, 0x0ULL },  // ROSBGOpt
    { 2123,	6,	1,	6,	219,	0,	1,	SystemZOpInfoBase + 1404,	0,	0, 0x0ULL },  // ROSBG
    { 2122,	5,	1,	6,	219,	0,	1,	SystemZOpInfoBase + 1288,	0,	0, 0x0ULL },  // RNSBGOpt
    { 2121,	6,	1,	6,	219,	0,	1,	SystemZOpInfoBase + 1404,	0,	0, 0x0ULL },  // RNSBG
    { 2120,	4,	1,	6,	214,	0,	0,	SystemZOpInfoBase + 987,	0,	0, 0x4ULL },  // RLLG
    { 2119,	4,	1,	6,	214,	0,	0,	SystemZOpInfoBase + 1432,	0,	0, 0x4ULL },  // RLL
    { 2118,	5,	1,	6,	216,	0,	0,	SystemZOpInfoBase + 1427,	0,	0, 0x0ULL },  // RISBLGOpt
    { 2117,	6,	1,	6,	216,	0,	0,	SystemZOpInfoBase + 1421,	0,	0, 0x0ULL },  // RISBLG
    { 2116,	5,	1,	6,	215,	0,	0,	SystemZOpInfoBase + 1416,	0,	0, 0x0ULL },  // RISBHGOpt
    { 2115,	6,	1,	6,	215,	0,	0,	SystemZOpInfoBase + 1410,	0,	0, 0x0ULL },  // RISBHG
    { 2114,	5,	1,	6,	950,	0,	1,	SystemZOpInfoBase + 1288,	0,	0, 0x3b800ULL },  // RISBGZOpt
    { 2113,	6,	1,	6,	950,	0,	1,	SystemZOpInfoBase + 1404,	0,	0, 0x3b800ULL },  // RISBGZ
    { 2112,	5,	1,	6,	950,	0,	1,	SystemZOpInfoBase + 1288,	0,	0, 0x3b800ULL },  // RISBGOpt
    { 2111,	5,	1,	6,	217,	0,	0,	SystemZOpInfoBase + 1288,	0,	0, 0x0ULL },  // RISBGNZOpt
    { 2110,	6,	1,	6,	217,	0,	0,	SystemZOpInfoBase + 1404,	0,	0, 0x0ULL },  // RISBGNZ
    { 2109,	5,	1,	6,	217,	0,	0,	SystemZOpInfoBase + 1288,	0,	0, 0x0ULL },  // RISBGNOpt
    { 2108,	6,	1,	6,	217,	0,	0,	SystemZOpInfoBase + 1404,	0,	0, 0x0ULL },  // RISBGN
    { 2107,	5,	1,	6,	950,	0,	1,	SystemZOpInfoBase + 433,	0,	0, 0x0ULL },  // RISBG32Opt
    { 2106,	6,	1,	6,	950,	0,	1,	SystemZOpInfoBase + 427,	0,	0, 0x0ULL },  // RISBG32
    { 2105,	6,	1,	6,	950,	0,	1,	SystemZOpInfoBase + 1404,	0,	0, 0x3b800ULL },  // RISBG
    { 2104,	3,	0,	4,	809,	0,	0,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDPOpt
    { 2103,	4,	0,	4,	809,	0,	0,	SystemZOpInfoBase + 1037,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDP
    { 2102,	0,	0,	4,	867,	1,	1,	SystemZOpInfoBase + 1,	41,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RCHP
    { 2101,	2,	0,	4,	863,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // QSI
    { 2100,	2,	0,	4,	849,	1,	2,	SystemZOpInfoBase + 260,	70,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // QPACI
    { 2099,	2,	0,	4,	863,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // QCTRI
    { 2098,	5,	2,	4,	518,	1,	0,	SystemZOpInfoBase + 1399,	12,	0, 0x0ULL },  // QAXTR
    { 2097,	5,	2,	4,	517,	1,	0,	SystemZOpInfoBase + 972,	12,	0, 0x0ULL },  // QADTR
    { 2096,	0,	0,	4,	811,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PTLB
    { 2095,	2,	0,	4,	827,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PTI
    { 2094,	0,	0,	2,	834,	2,	1,	SystemZOpInfoBase + 1,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PTFF
    { 2093,	2,	1,	4,	847,	0,	0,	SystemZOpInfoBase + 1397,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PTF
    { 2092,	2,	0,	4,	827,	0,	0,	SystemZOpInfoBase + 991,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PT
    { 2091,	4,	2,	4,	296,	2,	1,	SystemZOpInfoBase + 837,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PRNO
    { 2090,	0,	0,	2,	826,	0,	1,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PR
    { 2089,	4,	2,	4,	924,	2,	1,	SystemZOpInfoBase + 837,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PPNO
    { 2088,	3,	0,	4,	331,	0,	0,	SystemZOpInfoBase + 222,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PPA
    { 2087,	3,	1,	4,	334,	0,	1,	SystemZOpInfoBase + 222,	0,	0, 0x0ULL },  // POPCNTOpt
    { 2086,	2,	1,	4,	917,	0,	1,	SystemZOpInfoBase + 598,	0,	0, 0x0ULL },  // POPCNT
    { 2085,	6,	0,	6,	280,	2,	1,	SystemZOpInfoBase + 1391,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PLO
    { 2084,	5,	0,	6,	305,	0,	0,	SystemZOpInfoBase + 1386,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PKU
    { 2083,	5,	0,	6,	305,	0,	0,	SystemZOpInfoBase + 1386,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PKA
    { 2082,	2,	0,	4,	806,	0,	1,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PGOUT
    { 2081,	2,	0,	4,	805,	0,	1,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PGIN
    { 2080,	0,	0,	2,	502,	3,	3,	SystemZOpInfoBase + 1,	64,	0, 0x0ULL },  // PFPO
    { 2079,	3,	1,	4,	803,	0,	0,	SystemZOpInfoBase + 1383,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PFMF
    { 2078,	2,	0,	6,	265,	0,	0,	SystemZOpInfoBase + 629,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PFDRL
    { 2077,	4,	0,	6,	265,	0,	0,	SystemZOpInfoBase + 607,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0xcULL },  // PFD
    { 2076,	4,	1,	6,	285,	1,	1,	SystemZOpInfoBase + 987,	62,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // PFCR
    { 2075,	0,	0,	4,	848,	2,	0,	SystemZOpInfoBase + 1,	60,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PCKMO
    { 2074,	0,	0,	4,	941,	2,	1,	SystemZOpInfoBase + 1,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PCC
    { 2073,	2,	0,	4,	825,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PC
    { 2072,	0,	0,	4,	824,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PALB
    { 2071,	6,	0,	6,	305,	0,	0,	SystemZOpInfoBase + 579,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PACK
    { 2070,	5,	1,	6,	157,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x2308cULL },  // OY
    { 2069,	3,	1,	4,	167,	0,	1,	SystemZOpInfoBase + 576,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // ORK
    { 2068,	3,	1,	2,	167,	0,	1,	SystemZOpInfoBase + 573,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // OR
    { 2067,	3,	0,	6,	159,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // OIY
    { 2066,	3,	1,	4,	166,	0,	1,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // OILL
    { 2065,	3,	1,	4,	165,	0,	1,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // OILH
    { 2064,	3,	1,	6,	164,	0,	1,	SystemZOpInfoBase + 550,	0,	0, 0x23000ULL },  // OILF
    { 2063,	3,	1,	4,	163,	0,	1,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // OIHL
    { 2062,	3,	1,	4,	162,	0,	1,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // OIHH
    { 2061,	3,	1,	6,	161,	0,	1,	SystemZOpInfoBase + 570,	0,	0, 0x23000ULL },  // OIHF
    { 2060,	3,	0,	4,	159,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // OI
    { 2059,	3,	1,	4,	158,	0,	1,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // OGRK
    { 2058,	3,	1,	4,	158,	0,	1,	SystemZOpInfoBase + 561,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // OGR
    { 2057,	5,	1,	6,	157,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x2310cULL },  // OG
    { 2056,	3,	1,	4,	178,	0,	1,	SystemZOpInfoBase + 576,	0,	0, 0x23000ULL },  // OCRK
    { 2055,	3,	1,	4,	178,	0,	1,	SystemZOpInfoBase + 391,	0,	0, 0x23000ULL },  // OCGRK
    { 2054,	5,	0,	6,	168,	0,	1,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // OC
    { 2053,	5,	1,	4,	157,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x23088ULL },  // O
    { 2052,	5,	1,	6,	145,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x2308cULL },  // NY
    { 2051,	3,	1,	4,	182,	0,	1,	SystemZOpInfoBase + 576,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NXRK
    { 2050,	3,	1,	4,	182,	0,	1,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NXGRK
    { 2049,	4,	0,	6,	330,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x10cULL },  // NTSTG
    { 2048,	3,	1,	4,	155,	0,	1,	SystemZOpInfoBase + 576,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NRK
    { 2047,	3,	1,	2,	155,	0,	1,	SystemZOpInfoBase + 573,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NR
    { 2046,	3,	1,	4,	181,	0,	1,	SystemZOpInfoBase + 576,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NOTR
    { 2045,	3,	1,	4,	181,	0,	1,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NOTGR
    { 2044,	3,	1,	4,	180,	0,	1,	SystemZOpInfoBase + 576,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NORK
    { 2043,	0,	0,	2,	872,	0,	0,	SystemZOpInfoBase + 1,	0,	0, 0x0ULL },  // NOPROpt
    { 2042,	1,	0,	2,	872,	0,	0,	SystemZOpInfoBase + 307,	0,	0, 0x0ULL },  // NOPR
    { 2041,	0,	0,	4,	872,	0,	0,	SystemZOpInfoBase + 1,	0,	0, 0x8ULL },  // NOPOpt
    { 2040,	3,	0,	4,	872,	0,	0,	SystemZOpInfoBase + 595,	0,	0, 0x8ULL },  // NOP
    { 2039,	3,	1,	4,	180,	0,	1,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NOGRK
    { 2038,	3,	1,	4,	179,	0,	1,	SystemZOpInfoBase + 576,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NNRK
    { 2037,	0,	0,	4,	344,	2,	2,	SystemZOpInfoBase + 1,	56,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // NNPA
    { 2036,	3,	1,	4,	179,	0,	1,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NNGRK
    { 2035,	3,	0,	6,	148,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // NIY
    { 2034,	3,	1,	4,	154,	0,	1,	SystemZOpInfoBase + 550,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NILL
    { 2033,	3,	1,	4,	153,	0,	1,	SystemZOpInfoBase + 550,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NILH
    { 2032,	3,	1,	6,	152,	0,	1,	SystemZOpInfoBase + 550,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x23000ULL },  // NILF
    { 2031,	3,	1,	4,	151,	0,	1,	SystemZOpInfoBase + 570,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NIHL
    { 2030,	3,	1,	4,	150,	0,	1,	SystemZOpInfoBase + 570,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NIHH
    { 2029,	3,	1,	6,	149,	0,	1,	SystemZOpInfoBase + 570,	0,	0|(1ULL<<MCID::ConvertibleTo3Addr), 0x23000ULL },  // NIHF
    { 2028,	2,	0,	4,	268,	0,	0,	SystemZOpInfoBase + 20,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // NIAI
    { 2027,	3,	0,	4,	148,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // NI
    { 2026,	3,	1,	4,	146,	0,	1,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NGRK
    { 2025,	3,	1,	4,	146,	0,	1,	SystemZOpInfoBase + 561,	0,	0|(1ULL<<MCID::Commutable), 0x23000ULL },  // NGR
    { 2024,	5,	1,	6,	145,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x2310cULL },  // NG
    { 2023,	3,	1,	4,	177,	0,	1,	SystemZOpInfoBase + 576,	0,	0, 0x23000ULL },  // NCRK
    { 2022,	3,	1,	4,	177,	0,	1,	SystemZOpInfoBase + 391,	0,	0, 0x23000ULL },  // NCGRK
    { 2021,	5,	0,	6,	156,	0,	1,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // NC
    { 2020,	5,	1,	4,	145,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x23088ULL },  // N
    { 2019,	3,	1,	4,	456,	0,	0,	SystemZOpInfoBase + 1380,	0,	0, 0x0ULL },  // MYR
    { 2018,	3,	1,	4,	457,	0,	0,	SystemZOpInfoBase + 535,	0,	0, 0x0ULL },  // MYLR
    { 2017,	5,	1,	6,	455,	0,	0,	SystemZOpInfoBase + 155,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // MYL
    { 2016,	3,	1,	4,	457,	0,	0,	SystemZOpInfoBase + 535,	0,	0, 0x0ULL },  // MYHR
    { 2015,	5,	1,	6,	455,	0,	0,	SystemZOpInfoBase + 155,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // MYH
    { 2014,	5,	1,	6,	454,	0,	0,	SystemZOpInfoBase + 1375,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // MY
    { 2013,	4,	1,	4,	514,	1,	0,	SystemZOpInfoBase + 591,	12,	0, 0x0ULL },  // MXTRA
    { 2012,	3,	1,	4,	514,	1,	0,	SystemZOpInfoBase + 588,	12,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MXTR
    { 2011,	3,	1,	2,	453,	0,	0,	SystemZOpInfoBase + 585,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MXR
    { 2010,	3,	1,	2,	452,	0,	0,	SystemZOpInfoBase + 1372,	0,	0, 0x0ULL },  // MXDR
    { 2009,	3,	1,	4,	395,	1,	0,	SystemZOpInfoBase + 1372,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // MXDBR
    { 2008,	5,	1,	6,	394,	1,	0,	SystemZOpInfoBase + 1367,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // MXDB
    { 2007,	5,	1,	4,	451,	0,	0,	SystemZOpInfoBase + 1367,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // MXD
    { 2006,	3,	1,	4,	396,	1,	0,	SystemZOpInfoBase + 585,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // MXBR
    { 2005,	5,	0,	6,	304,	0,	0,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVZ
    { 2004,	4,	2,	4,	49,	1,	1,	SystemZOpInfoBase + 876,	35,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVST
    { 2003,	2,	0,	4,	822,	1,	1,	SystemZOpInfoBase + 598,	35,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVPG
    { 2002,	6,	0,	6,	304,	0,	0,	SystemZOpInfoBase + 579,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVO
    { 2001,	5,	0,	6,	304,	0,	0,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVN
    { 2000,	3,	0,	6,	25,	0,	0,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL },  // MVIY
    { 1999,	3,	0,	4,	25,	0,	0,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // MVI
    { 1998,	3,	0,	6,	24,	0,	0,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // MVHI
    { 1997,	3,	0,	6,	24,	0,	0,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // MVHHI
    { 1996,	3,	0,	6,	24,	0,	0,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // MVGHI
    { 1995,	4,	0,	6,	820,	2,	0,	SystemZOpInfoBase + 1179,	53,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVCSK
    { 1994,	6,	0,	6,	819,	0,	1,	SystemZOpInfoBase + 1361,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVCS
    { 1993,	4,	0,	6,	28,	1,	0,	SystemZOpInfoBase + 1179,	55,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVCRL
    { 1992,	6,	0,	6,	819,	0,	1,	SystemZOpInfoBase + 1361,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVCP
    { 1991,	5,	0,	6,	821,	1,	0,	SystemZOpInfoBase + 931,	55,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVCOS
    { 1990,	6,	2,	6,	27,	0,	1,	SystemZOpInfoBase + 841,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // MVCLU
    { 1989,	6,	2,	4,	27,	0,	1,	SystemZOpInfoBase + 841,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVCLE
    { 1988,	4,	2,	2,	27,	0,	1,	SystemZOpInfoBase + 837,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVCL
    { 1987,	6,	0,	6,	819,	0,	1,	SystemZOpInfoBase + 1361,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVCK
    { 1986,	5,	0,	6,	85,	0,	0,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVCIN
    { 1985,	4,	0,	6,	820,	2,	0,	SystemZOpInfoBase + 1179,	53,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVCDK
    { 1984,	5,	0,	6,	26,	0,	0,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MVC
    { 1983,	5,	1,	6,	183,	0,	0,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL },  // MSY
    { 1982,	1,	0,	4,	833,	0,	0,	SystemZOpInfoBase + 1360,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MSTA
    { 1981,	3,	1,	4,	200,	0,	1,	SystemZOpInfoBase + 576,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MSRKC
    { 1980,	3,	1,	4,	184,	0,	0,	SystemZOpInfoBase + 573,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MSR
    { 1979,	3,	1,	4,	201,	0,	1,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MSGRKC
    { 1978,	3,	1,	4,	186,	0,	0,	SystemZOpInfoBase + 561,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MSGR
    { 1977,	3,	1,	4,	187,	0,	0,	SystemZOpInfoBase + 558,	0,	0, 0x0ULL },  // MSGFR
    { 1976,	3,	1,	6,	187,	0,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // MSGFI
    { 1975,	5,	1,	6,	183,	0,	0,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL },  // MSGF
    { 1974,	5,	1,	6,	199,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL },  // MSGC
    { 1973,	5,	1,	6,	185,	0,	0,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL },  // MSG
    { 1972,	3,	1,	6,	184,	0,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // MSFI
    { 1971,	4,	1,	4,	459,	0,	0,	SystemZOpInfoBase + 1353,	0,	0, 0x0ULL },  // MSER
    { 1970,	4,	1,	4,	398,	1,	0,	SystemZOpInfoBase + 1353,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // MSEBR
    { 1969,	6,	1,	6,	397,	1,	0,	SystemZOpInfoBase + 1347,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // MSEB
    { 1968,	6,	1,	6,	458,	0,	0,	SystemZOpInfoBase + 1347,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // MSE
    { 1967,	4,	1,	4,	459,	0,	0,	SystemZOpInfoBase + 1343,	0,	0, 0x0ULL },  // MSDR
    { 1966,	4,	1,	4,	400,	1,	0,	SystemZOpInfoBase + 1343,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // MSDBR
    { 1965,	6,	1,	6,	399,	1,	0,	SystemZOpInfoBase + 1337,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // MSDB
    { 1964,	6,	1,	6,	458,	0,	0,	SystemZOpInfoBase + 1337,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // MSD
    { 1963,	2,	0,	4,	866,	1,	1,	SystemZOpInfoBase + 260,	41,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MSCH
    { 1962,	5,	1,	6,	198,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL },  // MSC
    { 1961,	5,	1,	4,	183,	0,	0,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // MS
    { 1960,	3,	1,	2,	193,	0,	0,	SystemZOpInfoBase + 982,	0,	0, 0x0ULL },  // MR
    { 1959,	6,	0,	6,	309,	0,	0,	SystemZOpInfoBase + 579,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // MP
    { 1958,	3,	1,	4,	193,	0,	0,	SystemZOpInfoBase + 982,	0,	0, 0x0ULL },  // MLR
    { 1957,	3,	1,	4,	189,	0,	0,	SystemZOpInfoBase + 928,	0,	0, 0x0ULL },  // MLGR
    { 1956,	5,	1,	6,	188,	0,	0,	SystemZOpInfoBase + 962,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL },  // MLG
    { 1955,	5,	1,	6,	194,	0,	0,	SystemZOpInfoBase + 962,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL },  // ML
    { 1954,	5,	1,	6,	192,	0,	0,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x4cULL },  // MHY
    { 1953,	3,	1,	4,	191,	0,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // MHI
    { 1952,	5,	1,	4,	192,	0,	0,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x48ULL },  // MH
    { 1951,	3,	1,	4,	197,	0,	0,	SystemZOpInfoBase + 388,	0,	0, 0x0ULL },  // MGRK
    { 1950,	3,	1,	4,	190,	0,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // MGHI
    { 1949,	5,	1,	6,	195,	0,	0,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x4cULL },  // MGH
    { 1948,	5,	1,	6,	196,	0,	0,	SystemZOpInfoBase + 962,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL },  // MG
    { 1947,	5,	1,	6,	194,	0,	0,	SystemZOpInfoBase + 962,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL },  // MFY
    { 1946,	3,	1,	2,	450,	0,	0,	SystemZOpInfoBase + 1357,	0,	0, 0x0ULL },  // MER
    { 1945,	3,	1,	4,	944,	0,	0,	SystemZOpInfoBase + 547,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MEER
    { 1944,	3,	1,	4,	393,	1,	0,	SystemZOpInfoBase + 547,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // MEEBR
    { 1943,	5,	1,	6,	392,	1,	0,	SystemZOpInfoBase + 542,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // MEEB
    { 1942,	5,	1,	6,	943,	0,	0,	SystemZOpInfoBase + 542,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // MEE
    { 1941,	5,	1,	4,	449,	0,	0,	SystemZOpInfoBase + 527,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // ME
    { 1940,	4,	1,	4,	513,	1,	0,	SystemZOpInfoBase + 538,	12,	0, 0x0ULL },  // MDTRA
    { 1939,	3,	1,	4,	513,	1,	0,	SystemZOpInfoBase + 535,	12,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MDTR
    { 1938,	3,	1,	2,	944,	0,	0,	SystemZOpInfoBase + 532,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // MDR
    { 1937,	3,	1,	2,	450,	0,	0,	SystemZOpInfoBase + 1357,	0,	0, 0x0ULL },  // MDER
    { 1936,	3,	1,	4,	393,	1,	0,	SystemZOpInfoBase + 1357,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // MDEBR
    { 1935,	5,	1,	6,	392,	1,	0,	SystemZOpInfoBase + 527,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // MDEB
    { 1934,	5,	1,	4,	449,	0,	0,	SystemZOpInfoBase + 527,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // MDE
    { 1933,	3,	1,	4,	393,	1,	0,	SystemZOpInfoBase + 532,	12,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x0ULL },  // MDBR
    { 1932,	5,	1,	6,	392,	1,	0,	SystemZOpInfoBase + 527,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // MDB
    { 1931,	5,	1,	4,	943,	0,	0,	SystemZOpInfoBase + 527,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // MD
    { 1930,	3,	0,	4,	851,	0,	0,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MC
    { 1929,	4,	1,	4,	462,	0,	0,	SystemZOpInfoBase + 1343,	0,	0, 0x0ULL },  // MAYR
    { 1928,	4,	1,	4,	463,	0,	0,	SystemZOpInfoBase + 1343,	0,	0, 0x0ULL },  // MAYLR
    { 1927,	6,	1,	6,	461,	0,	0,	SystemZOpInfoBase + 1337,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // MAYL
    { 1926,	4,	1,	4,	463,	0,	0,	SystemZOpInfoBase + 1343,	0,	0, 0x0ULL },  // MAYHR
    { 1925,	6,	1,	6,	461,	0,	0,	SystemZOpInfoBase + 1337,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // MAYH
    { 1924,	6,	1,	6,	460,	0,	0,	SystemZOpInfoBase + 1337,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // MAY
    { 1923,	4,	1,	4,	459,	0,	0,	SystemZOpInfoBase + 1353,	0,	0, 0x0ULL },  // MAER
    { 1922,	4,	1,	4,	398,	1,	0,	SystemZOpInfoBase + 1353,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // MAEBR
    { 1921,	6,	1,	6,	397,	1,	0,	SystemZOpInfoBase + 1347,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // MAEB
    { 1920,	6,	1,	6,	458,	0,	0,	SystemZOpInfoBase + 1347,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // MAE
    { 1919,	4,	1,	4,	459,	0,	0,	SystemZOpInfoBase + 1343,	0,	0, 0x0ULL },  // MADR
    { 1918,	4,	1,	4,	400,	1,	0,	SystemZOpInfoBase + 1343,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // MADBR
    { 1917,	6,	1,	6,	399,	1,	0,	SystemZOpInfoBase + 1337,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // MADB
    { 1916,	6,	1,	6,	458,	0,	0,	SystemZOpInfoBase + 1337,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // MAD
    { 1915,	5,	1,	4,	194,	0,	0,	SystemZOpInfoBase + 962,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // M
    { 1914,	1,	1,	4,	348,	0,	0,	SystemZOpInfoBase + 355,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LZXR
    { 1913,	4,	1,	6,	42,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL },  // LZRG
    { 1912,	4,	1,	6,	42,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL },  // LZRF
    { 1911,	1,	1,	4,	347,	0,	0,	SystemZOpInfoBase + 1336,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LZER_16
    { 1910,	1,	1,	4,	347,	0,	0,	SystemZOpInfoBase + 354,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LZER
    { 1909,	1,	1,	4,	347,	0,	0,	SystemZOpInfoBase + 353,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LZDR
    { 1908,	4,	1,	6,	33,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x8dULL },  // LY
    { 1907,	2,	1,	4,	352,	0,	0,	SystemZOpInfoBase + 718,	0,	0|(1ULL<<MCID::MoveReg), 0x0ULL },  // LXR
    { 1906,	2,	1,	4,	427,	0,	0,	SystemZOpInfoBase + 1334,	0,	0, 0x0ULL },  // LXER
    { 1905,	2,	1,	4,	366,	1,	0,	SystemZOpInfoBase + 1334,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // LXEBR
    { 1904,	4,	1,	6,	365,	1,	0,	SystemZOpInfoBase + 356,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // LXEB
    { 1903,	4,	1,	6,	426,	0,	0,	SystemZOpInfoBase + 356,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // LXE
    { 1902,	3,	1,	4,	477,	1,	0,	SystemZOpInfoBase + 1331,	12,	0, 0x0ULL },  // LXDTR
    { 1901,	2,	1,	4,	427,	0,	0,	SystemZOpInfoBase + 1329,	0,	0, 0x0ULL },  // LXDR
    { 1900,	2,	1,	4,	366,	1,	0,	SystemZOpInfoBase + 1329,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // LXDBR
    { 1899,	4,	1,	6,	365,	1,	0,	SystemZOpInfoBase + 356,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // LXDB
    { 1898,	4,	1,	6,	426,	0,	0,	SystemZOpInfoBase + 356,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // LXD
    { 1897,	4,	1,	6,	88,	0,	0,	SystemZOpInfoBase + 1213,	0,	0, 0xcULL },  // LXAQ
    { 1896,	4,	1,	6,	88,	0,	0,	SystemZOpInfoBase + 1213,	0,	0, 0xcULL },  // LXAH
    { 1895,	4,	1,	6,	88,	0,	0,	SystemZOpInfoBase + 1213,	0,	0, 0xcULL },  // LXAG
    { 1894,	4,	1,	6,	88,	0,	0,	SystemZOpInfoBase + 1213,	0,	0, 0xcULL },  // LXAF
    { 1893,	4,	1,	6,	88,	0,	0,	SystemZOpInfoBase + 1213,	0,	0, 0xcULL },  // LXAB
    { 1892,	2,	1,	4,	816,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LURAG
    { 1891,	2,	1,	4,	816,	0,	0,	SystemZOpInfoBase + 991,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LURA
    { 1890,	2,	1,	4,	473,	1,	1,	SystemZOpInfoBase + 718,	1,	0, 0x0ULL },  // LTXTR
    { 1889,	2,	1,	4,	420,	0,	1,	SystemZOpInfoBase + 718,	0,	0, 0x0ULL },  // LTXR
    { 1888,	2,	1,	4,	354,	1,	1,	SystemZOpInfoBase + 718,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x3fc00ULL },  // LTXBR
    { 1887,	2,	1,	2,	45,	0,	1,	SystemZOpInfoBase + 858,	0,	0, 0x3b800ULL },  // LTR
    { 1886,	2,	1,	4,	45,	0,	1,	SystemZOpInfoBase + 598,	0,	0, 0x3b800ULL },  // LTGR
    { 1885,	2,	1,	4,	60,	0,	1,	SystemZOpInfoBase + 757,	0,	0, 0x3b800ULL },  // LTGFR
    { 1884,	4,	1,	6,	59,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad), 0x3b88cULL },  // LTGF
    { 1883,	4,	1,	6,	44,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad), 0x3b90cULL },  // LTG
    { 1882,	2,	1,	2,	419,	0,	1,	SystemZOpInfoBase + 704,	0,	0, 0x0ULL },  // LTER
    { 1881,	2,	1,	4,	353,	1,	1,	SystemZOpInfoBase + 704,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x3fc00ULL },  // LTEBR
    { 1880,	2,	1,	4,	472,	1,	1,	SystemZOpInfoBase + 676,	1,	0, 0x0ULL },  // LTDTR
    { 1879,	2,	1,	2,	419,	0,	1,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // LTDR
    { 1878,	2,	1,	4,	353,	1,	1,	SystemZOpInfoBase + 676,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x3fc00ULL },  // LTDBR
    { 1877,	4,	1,	6,	44,	0,	1,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayLoad), 0x3b88cULL },  // LT
    { 1876,	2,	0,	4,	862,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LSCTL
    { 1875,	2,	1,	4,	82,	0,	0,	SystemZOpInfoBase + 858,	0,	0, 0x0ULL },  // LRVR
    { 1874,	4,	1,	6,	83,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayLoad), 0x4cULL },  // LRVH
    { 1873,	2,	1,	4,	82,	0,	0,	SystemZOpInfoBase + 598,	0,	0, 0x0ULL },  // LRVGR
    { 1872,	4,	1,	6,	83,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL },  // LRVG
    { 1871,	4,	1,	6,	83,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL },  // LRV
    { 1870,	2,	1,	6,	33,	0,	0,	SystemZOpInfoBase + 808,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LRL
    { 1869,	2,	1,	2,	421,	0,	0,	SystemZOpInfoBase + 1205,	0,	0, 0x0ULL },  // LRER
    { 1868,	2,	1,	2,	423,	0,	0,	SystemZOpInfoBase + 1199,	0,	0, 0x0ULL },  // LRDR
    { 1867,	4,	1,	6,	814,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xcULL },  // LRAY
    { 1866,	4,	1,	6,	814,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xcULL },  // LRAG
    { 1865,	4,	1,	4,	814,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL },  // LRA
    { 1864,	2,	1,	2,	41,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::MoveReg), 0x0ULL },  // LR
    { 1863,	2,	1,	4,	435,	0,	1,	SystemZOpInfoBase + 718,	0,	0, 0x0ULL },  // LPXR
    { 1862,	2,	1,	4,	379,	0,	1,	SystemZOpInfoBase + 718,	0,	0, 0x3fc00ULL },  // LPXBR
    { 1861,	5,	2,	4,	813,	0,	1,	SystemZOpInfoBase + 1324,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LPTEA
    { 1860,	2,	0,	6,	783,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x204ULL },  // LPSWEY
    { 1859,	2,	0,	4,	915,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x200ULL },  // LPSWE
    { 1858,	2,	0,	4,	915,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // LPSW
    { 1857,	2,	1,	2,	89,	0,	1,	SystemZOpInfoBase + 858,	0,	0, 0x23c00ULL },  // LPR
    { 1856,	4,	1,	6,	281,	0,	0,	SystemZOpInfoBase + 311,	0,	0|(1ULL<<MCID::MayLoad), 0x20cULL },  // LPQ
    { 1855,	2,	0,	4,	858,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // LPP
    { 1854,	2,	1,	4,	89,	0,	1,	SystemZOpInfoBase + 598,	0,	0, 0x23c00ULL },  // LPGR
    { 1853,	2,	1,	4,	90,	0,	1,	SystemZOpInfoBase + 757,	0,	0, 0x3b800ULL },  // LPGFR
    { 1852,	2,	1,	2,	434,	0,	1,	SystemZOpInfoBase + 704,	0,	0, 0x0ULL },  // LPER
    { 1851,	2,	1,	4,	377,	0,	1,	SystemZOpInfoBase + 704,	0,	0, 0x3fc00ULL },  // LPEBR
    { 1850,	2,	1,	2,	434,	0,	1,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // LPDR
    { 1849,	5,	1,	6,	283,	0,	1,	SystemZOpInfoBase + 1319,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LPDG
    { 1848,	2,	1,	4,	378,	0,	0,	SystemZOpInfoBase + 704,	0,	0, 0x0ULL },  // LPDFR_32
    { 1847,	2,	1,	4,	378,	0,	0,	SystemZOpInfoBase + 1188,	0,	0, 0x0ULL },  // LPDFR_16
    { 1846,	2,	1,	4,	378,	0,	0,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // LPDFR
    { 1845,	2,	1,	4,	377,	0,	1,	SystemZOpInfoBase + 676,	0,	0, 0x3fc00ULL },  // LPDBR
    { 1844,	5,	1,	6,	283,	0,	1,	SystemZOpInfoBase + 1319,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LPD
    { 1843,	2,	0,	4,	862,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // LPCTL
    { 1842,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmZ
    { 1841,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmP
    { 1840,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmO
    { 1839,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmNZ
    { 1838,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmNP
    { 1837,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmNO
    { 1836,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmNM
    { 1835,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmNLH
    { 1834,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmNLE
    { 1833,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmNL
    { 1832,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmNHE
    { 1831,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmNH
    { 1830,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmNE
    { 1829,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmM
    { 1828,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmLH
    { 1827,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmLE
    { 1826,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmL
    { 1825,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmHE
    { 1824,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmH
    { 1823,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 573,	0,	0, 0x0ULL },  // LOCRAsmE
    { 1822,	4,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 1315,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // LOCRAsm
    { 1821,	5,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 433,	0,	0|(1ULL<<MCID::Commutable), 0x80000ULL },  // LOCR
    { 1820,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmZ
    { 1819,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmP
    { 1818,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmO
    { 1817,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmNZ
    { 1816,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmNP
    { 1815,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmNO
    { 1814,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmNM
    { 1813,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmNLH
    { 1812,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmNLE
    { 1811,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmNL
    { 1810,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmNHE
    { 1809,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmNH
    { 1808,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmNE
    { 1807,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmM
    { 1806,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmLH
    { 1805,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmLE
    { 1804,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmL
    { 1803,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmHE
    { 1802,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmH
    { 1801,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // LOCHIAsmE
    { 1800,	4,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 1311,	0,	0, 0x0ULL },  // LOCHIAsm
    { 1799,	5,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 1306,	0,	0, 0x80000ULL },  // LOCHI
    { 1798,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmZ
    { 1797,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmP
    { 1796,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmO
    { 1795,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmNZ
    { 1794,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmNP
    { 1793,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmNO
    { 1792,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmNM
    { 1791,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmNLH
    { 1790,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmNLE
    { 1789,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmNL
    { 1788,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmNHE
    { 1787,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmNH
    { 1786,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmNE
    { 1785,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmM
    { 1784,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmLH
    { 1783,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmLE
    { 1782,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmL
    { 1781,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmHE
    { 1780,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmH
    { 1779,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // LOCHHIAsmE
    { 1778,	4,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 1302,	0,	0, 0x0ULL },  // LOCHHIAsm
    { 1777,	5,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 1297,	0,	0, 0x80000ULL },  // LOCHHI
    { 1776,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmZ
    { 1775,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmP
    { 1774,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmO
    { 1773,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmNZ
    { 1772,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmNP
    { 1771,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmNO
    { 1770,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmNM
    { 1769,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmNLH
    { 1768,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmNLE
    { 1767,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmNL
    { 1766,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmNHE
    { 1765,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmNH
    { 1764,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmNE
    { 1763,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmM
    { 1762,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmLH
    { 1761,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmLE
    { 1760,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmL
    { 1759,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmHE
    { 1758,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmH
    { 1757,	3,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 561,	0,	0, 0x0ULL },  // LOCGRAsmE
    { 1756,	4,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 1293,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // LOCGRAsm
    { 1755,	5,	1,	4,	936,	1,	0,	SystemZOpInfoBase + 1288,	0,	0|(1ULL<<MCID::Commutable), 0x80000ULL },  // LOCGR
    { 1754,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmZ
    { 1753,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmP
    { 1752,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmO
    { 1751,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmNZ
    { 1750,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmNP
    { 1749,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmNO
    { 1748,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmNM
    { 1747,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmNLH
    { 1746,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmNLE
    { 1745,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmNL
    { 1744,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmNHE
    { 1743,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmNH
    { 1742,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmNE
    { 1741,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmM
    { 1740,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmLH
    { 1739,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmLE
    { 1738,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmL
    { 1737,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmHE
    { 1736,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmH
    { 1735,	3,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 308,	0,	0, 0x0ULL },  // LOCGHIAsmE
    { 1734,	4,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 1284,	0,	0, 0x0ULL },  // LOCGHIAsm
    { 1733,	5,	1,	6,	52,	1,	0,	SystemZOpInfoBase + 1279,	0,	0, 0x80000ULL },  // LOCGHI
    { 1732,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmZ
    { 1731,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmP
    { 1730,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmO
    { 1729,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmNZ
    { 1728,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmNP
    { 1727,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmNO
    { 1726,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmNM
    { 1725,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmNLH
    { 1724,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmNLE
    { 1723,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmNL
    { 1722,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmNHE
    { 1721,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmNH
    { 1720,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmNE
    { 1719,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmM
    { 1718,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmLH
    { 1717,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmLE
    { 1716,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmL
    { 1715,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmHE
    { 1714,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmH
    { 1713,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1275,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsmE
    { 1712,	5,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1270,	0,	0|(1ULL<<MCID::MayLoad), 0x104ULL },  // LOCGAsm
    { 1711,	6,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1264,	0,	0|(1ULL<<MCID::MayLoad), 0x80104ULL },  // LOCG
    { 1710,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmZ
    { 1709,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmP
    { 1708,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmO
    { 1707,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmNZ
    { 1706,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmNP
    { 1705,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmNO
    { 1704,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmNM
    { 1703,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmNLH
    { 1702,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmNLE
    { 1701,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmNL
    { 1700,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmNHE
    { 1699,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmNH
    { 1698,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmNE
    { 1697,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmM
    { 1696,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmLH
    { 1695,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmLE
    { 1694,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmL
    { 1693,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmHE
    { 1692,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmH
    { 1691,	3,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1261,	0,	0, 0x0ULL },  // LOCFHRAsmE
    { 1690,	4,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 1257,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // LOCFHRAsm
    { 1689,	5,	1,	4,	51,	1,	0,	SystemZOpInfoBase + 400,	0,	0|(1ULL<<MCID::Commutable), 0x80000ULL },  // LOCFHR
    { 1688,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmZ
    { 1687,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmP
    { 1686,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmO
    { 1685,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmNZ
    { 1684,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmNP
    { 1683,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmNO
    { 1682,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmNM
    { 1681,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmNLH
    { 1680,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmNLE
    { 1679,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmNL
    { 1678,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmNHE
    { 1677,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmNH
    { 1676,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmNE
    { 1675,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmM
    { 1674,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmLH
    { 1673,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmLE
    { 1672,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmL
    { 1671,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmHE
    { 1670,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmH
    { 1669,	4,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1253,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsmE
    { 1668,	5,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1248,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCFHAsm
    { 1667,	6,	1,	6,	53,	1,	0,	SystemZOpInfoBase + 1242,	0,	0|(1ULL<<MCID::MayLoad), 0x80084ULL },  // LOCFH
    { 1666,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmZ
    { 1665,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmP
    { 1664,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmO
    { 1663,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmNZ
    { 1662,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmNP
    { 1661,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmNO
    { 1660,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmNM
    { 1659,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmNLH
    { 1658,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmNLE
    { 1657,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmNL
    { 1656,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmNHE
    { 1655,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmNH
    { 1654,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmNE
    { 1653,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmM
    { 1652,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmLH
    { 1651,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmLE
    { 1650,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmL
    { 1649,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmHE
    { 1648,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmH
    { 1647,	4,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1238,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsmE
    { 1646,	5,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1233,	0,	0|(1ULL<<MCID::MayLoad), 0x84ULL },  // LOCAsm
    { 1645,	6,	1,	6,	937,	1,	0,	SystemZOpInfoBase + 1227,	0,	0|(1ULL<<MCID::MayLoad), 0x80084ULL },  // LOC
    { 1644,	2,	1,	4,	435,	0,	1,	SystemZOpInfoBase + 718,	0,	0, 0x0ULL },  // LNXR
    { 1643,	2,	1,	4,	379,	0,	1,	SystemZOpInfoBase + 718,	0,	0, 0x3fc00ULL },  // LNXBR
    { 1642,	2,	1,	2,	91,	0,	1,	SystemZOpInfoBase + 858,	0,	0, 0x23c00ULL },  // LNR
    { 1641,	2,	1,	4,	91,	0,	1,	SystemZOpInfoBase + 598,	0,	0, 0x23c00ULL },  // LNGR
    { 1640,	2,	1,	4,	90,	0,	1,	SystemZOpInfoBase + 757,	0,	0, 0x3b800ULL },  // LNGFR
    { 1639,	2,	1,	2,	434,	0,	1,	SystemZOpInfoBase + 704,	0,	0, 0x0ULL },  // LNER
    { 1638,	2,	1,	4,	377,	0,	1,	SystemZOpInfoBase + 704,	0,	0, 0x3fc00ULL },  // LNEBR
    { 1637,	2,	1,	2,	434,	0,	1,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // LNDR
    { 1636,	2,	1,	4,	378,	0,	0,	SystemZOpInfoBase + 704,	0,	0, 0x0ULL },  // LNDFR_32
    { 1635,	2,	1,	4,	378,	0,	0,	SystemZOpInfoBase + 1188,	0,	0, 0x0ULL },  // LNDFR_16
    { 1634,	2,	1,	4,	378,	0,	0,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // LNDFR
    { 1633,	2,	1,	4,	377,	0,	1,	SystemZOpInfoBase + 676,	0,	0, 0x3fc00ULL },  // LNDBR
    { 1632,	4,	2,	6,	79,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL },  // LMY
    { 1631,	4,	2,	6,	79,	0,	0,	SystemZOpInfoBase + 1223,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL },  // LMH
    { 1630,	4,	2,	6,	79,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL },  // LMG
    { 1629,	6,	2,	6,	80,	0,	0,	SystemZOpInfoBase + 1217,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LMD
    { 1628,	4,	2,	4,	79,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LM
    { 1627,	4,	1,	6,	74,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL },  // LLZRGF
    { 1626,	4,	1,	6,	88,	0,	0,	SystemZOpInfoBase + 1213,	0,	0, 0xcULL },  // LLXAQ
    { 1625,	4,	1,	6,	88,	0,	0,	SystemZOpInfoBase + 1213,	0,	0, 0xcULL },  // LLXAH
    { 1624,	4,	1,	6,	88,	0,	0,	SystemZOpInfoBase + 1213,	0,	0, 0xcULL },  // LLXAG
    { 1623,	4,	1,	6,	88,	0,	0,	SystemZOpInfoBase + 1213,	0,	0, 0xcULL },  // LLXAF
    { 1622,	4,	1,	6,	88,	0,	0,	SystemZOpInfoBase + 1213,	0,	0, 0xcULL },  // LLXAB
    { 1621,	2,	1,	4,	38,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LLILL
    { 1620,	2,	1,	4,	38,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LLILH
    { 1619,	2,	1,	6,	38,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LLILF
    { 1618,	2,	1,	4,	37,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LLIHL
    { 1617,	2,	1,	4,	37,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LLIHH
    { 1616,	2,	1,	6,	37,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LLIHF
    { 1615,	2,	1,	6,	72,	0,	0,	SystemZOpInfoBase + 808,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LLHRL
    { 1614,	2,	1,	4,	67,	0,	0,	SystemZOpInfoBase + 858,	0,	0, 0x0ULL },  // LLHR
    { 1613,	4,	1,	6,	71,	0,	0,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x4cULL },  // LLHH
    { 1612,	4,	1,	6,	70,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x4cULL },  // LLH
    { 1611,	2,	1,	4,	68,	0,	0,	SystemZOpInfoBase + 598,	0,	0, 0x0ULL },  // LLGTR
    { 1610,	4,	1,	6,	75,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x8cULL },  // LLGTAT
    { 1609,	4,	1,	6,	73,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL },  // LLGT
    { 1608,	2,	1,	6,	73,	0,	0,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LLGHRL
    { 1607,	2,	1,	4,	68,	0,	0,	SystemZOpInfoBase + 598,	0,	0, 0x0ULL },  // LLGHR
    { 1606,	4,	1,	6,	73,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x4cULL },  // LLGH
    { 1605,	4,	1,	6,	298,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x8cULL },  // LLGFSG
    { 1604,	2,	1,	6,	73,	0,	0,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LLGFRL
    { 1603,	2,	1,	4,	68,	0,	0,	SystemZOpInfoBase + 757,	0,	0, 0x0ULL },  // LLGFR
    { 1602,	4,	1,	6,	75,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x8cULL },  // LLGFAT
    { 1601,	4,	1,	6,	73,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x8cULL },  // LLGF
    { 1600,	2,	1,	4,	68,	0,	0,	SystemZOpInfoBase + 598,	0,	0, 0x0ULL },  // LLGCR
    { 1599,	4,	1,	6,	73,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x2cULL },  // LLGC
    { 1598,	2,	1,	4,	66,	0,	0,	SystemZOpInfoBase + 858,	0,	0, 0x0ULL },  // LLCR
    { 1597,	4,	1,	6,	71,	0,	0,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x2cULL },  // LLCH
    { 1596,	4,	1,	6,	69,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x2cULL },  // LLC
    { 1595,	4,	1,	6,	62,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x4cULL },  // LHY
    { 1594,	2,	1,	6,	63,	0,	0,	SystemZOpInfoBase + 808,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LHRL
    { 1593,	2,	1,	4,	57,	0,	0,	SystemZOpInfoBase + 858,	0,	0, 0x0ULL },  // LHR
    { 1592,	2,	1,	4,	40,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LHI
    { 1591,	4,	1,	6,	63,	0,	0,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x4cULL },  // LHH
    { 1590,	4,	1,	4,	62,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x48ULL },  // LH
    { 1589,	4,	0,	6,	299,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0xcULL },  // LGSC
    { 1588,	2,	1,	6,	35,	0,	0,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LGRL
    { 1587,	2,	1,	4,	57,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::MoveReg), 0x0ULL },  // LGR
    { 1586,	2,	1,	6,	65,	0,	0,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LGHRL
    { 1585,	2,	1,	4,	58,	0,	0,	SystemZOpInfoBase + 598,	0,	0, 0x0ULL },  // LGHR
    { 1584,	2,	1,	4,	39,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LGHI
    { 1583,	4,	1,	6,	64,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x4cULL },  // LGH
    { 1582,	4,	1,	6,	297,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x10cULL },  // LGG
    { 1581,	2,	1,	6,	65,	0,	0,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LGFRL
    { 1580,	2,	1,	4,	58,	0,	0,	SystemZOpInfoBase + 757,	0,	0, 0x0ULL },  // LGFR
    { 1579,	2,	1,	6,	39,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LGFI
    { 1578,	4,	1,	6,	64,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x8cULL },  // LGF
    { 1577,	2,	1,	4,	351,	0,	0,	SystemZOpInfoBase + 944,	0,	0|(1ULL<<MCID::Bitcast), 0x0ULL },  // LGDR
    { 1576,	2,	1,	4,	58,	0,	0,	SystemZOpInfoBase + 598,	0,	0, 0x0ULL },  // LGBR
    { 1575,	4,	1,	6,	64,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x2cULL },  // LGB
    { 1574,	4,	1,	6,	43,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x10cULL },  // LGAT
    { 1573,	4,	1,	6,	35,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x10dULL },  // LG
    { 1572,	2,	0,	4,	415,	0,	1,	SystemZOpInfoBase + 260,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // LFPC
    { 1571,	4,	1,	6,	43,	0,	0,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x8cULL },  // LFHAT
    { 1570,	4,	1,	6,	33,	0,	0,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x8dULL },  // LFH
    { 1569,	2,	0,	4,	417,	0,	1,	SystemZOpInfoBase + 260,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x80ULL },  // LFAS
    { 1568,	4,	1,	6,	356,	0,	0,	SystemZOpInfoBase + 700,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x8dULL },  // LEY
    { 1567,	2,	1,	4,	422,	0,	0,	SystemZOpInfoBase + 1211,	0,	0, 0x0ULL },  // LEXR
    { 1566,	4,	1,	4,	362,	1,	0,	SystemZOpInfoBase + 1023,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // LEXBRA
    { 1565,	2,	1,	4,	362,	1,	0,	SystemZOpInfoBase + 718,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // LEXBR
    { 1564,	2,	1,	2,	349,	0,	0,	SystemZOpInfoBase + 1188,	0,	0|(1ULL<<MCID::MoveReg), 0x0ULL },  // LER16
    { 1563,	2,	1,	2,	349,	0,	0,	SystemZOpInfoBase + 704,	0,	0|(1ULL<<MCID::MoveReg), 0x0ULL },  // LER
    { 1562,	4,	1,	4,	474,	1,	0,	SystemZOpInfoBase + 1207,	12,	0, 0x0ULL },  // LEDTR
    { 1561,	2,	1,	2,	421,	0,	0,	SystemZOpInfoBase + 1205,	0,	0, 0x0ULL },  // LEDR
    { 1560,	4,	1,	4,	361,	1,	0,	SystemZOpInfoBase + 1207,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // LEDBRA
    { 1559,	2,	1,	4,	361,	1,	0,	SystemZOpInfoBase + 1205,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // LEDBR
    { 1558,	4,	1,	6,	356,	0,	0,	SystemZOpInfoBase + 1201,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x8dULL },  // LE16Y
    { 1557,	4,	1,	4,	356,	0,	0,	SystemZOpInfoBase + 1201,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x89ULL },  // LE16
    { 1556,	4,	1,	4,	356,	0,	0,	SystemZOpInfoBase + 700,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x89ULL },  // LE
    { 1555,	4,	1,	6,	357,	0,	0,	SystemZOpInfoBase + 672,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x10dULL },  // LDY
    { 1554,	4,	1,	4,	475,	1,	0,	SystemZOpInfoBase + 1023,	12,	0, 0x0ULL },  // LDXTR
    { 1553,	2,	1,	2,	423,	0,	0,	SystemZOpInfoBase + 1199,	0,	0, 0x0ULL },  // LDXR
    { 1552,	4,	1,	4,	362,	1,	0,	SystemZOpInfoBase + 1023,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // LDXBRA
    { 1551,	2,	1,	4,	362,	1,	0,	SystemZOpInfoBase + 718,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // LDXBR
    { 1550,	2,	1,	2,	350,	0,	0,	SystemZOpInfoBase + 704,	0,	0|(1ULL<<MCID::MoveReg), 0x0ULL },  // LDR32
    { 1549,	2,	1,	2,	350,	0,	0,	SystemZOpInfoBase + 1188,	0,	0|(1ULL<<MCID::MoveReg), 0x0ULL },  // LDR16
    { 1548,	2,	1,	2,	350,	0,	0,	SystemZOpInfoBase + 676,	0,	0|(1ULL<<MCID::MoveReg), 0x0ULL },  // LDR
    { 1547,	2,	1,	4,	350,	0,	0,	SystemZOpInfoBase + 684,	0,	0|(1ULL<<MCID::Bitcast), 0x0ULL },  // LDGR
    { 1546,	3,	1,	4,	476,	1,	0,	SystemZOpInfoBase + 1196,	12,	0, 0x0ULL },  // LDETR
    { 1545,	2,	1,	4,	425,	0,	0,	SystemZOpInfoBase + 1194,	0,	0, 0x0ULL },  // LDER
    { 1544,	2,	1,	4,	364,	1,	0,	SystemZOpInfoBase + 1194,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // LDEBR
    { 1543,	4,	1,	6,	363,	1,	0,	SystemZOpInfoBase + 672,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // LDEB
    { 1542,	4,	1,	6,	357,	0,	0,	SystemZOpInfoBase + 700,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x89ULL },  // LDE32
    { 1541,	4,	1,	6,	424,	0,	0,	SystemZOpInfoBase + 672,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // LDE
    { 1540,	4,	1,	4,	357,	0,	0,	SystemZOpInfoBase + 672,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x109ULL },  // LD
    { 1539,	2,	1,	4,	435,	0,	1,	SystemZOpInfoBase + 718,	0,	0, 0x0ULL },  // LCXR
    { 1538,	2,	1,	4,	379,	0,	1,	SystemZOpInfoBase + 718,	0,	0, 0x3fc00ULL },  // LCXBR
    { 1537,	4,	2,	6,	790,	0,	0,	SystemZOpInfoBase + 1190,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // LCTLG
    { 1536,	4,	2,	4,	790,	0,	0,	SystemZOpInfoBase + 1190,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LCTL
    { 1535,	2,	1,	2,	92,	0,	1,	SystemZOpInfoBase + 858,	0,	0, 0x23c00ULL },  // LCR
    { 1534,	2,	1,	4,	92,	0,	1,	SystemZOpInfoBase + 598,	0,	0, 0x23c00ULL },  // LCGR
    { 1533,	2,	1,	4,	93,	0,	1,	SystemZOpInfoBase + 757,	0,	0, 0x3b800ULL },  // LCGFR
    { 1532,	2,	1,	2,	434,	0,	1,	SystemZOpInfoBase + 704,	0,	0, 0x0ULL },  // LCER
    { 1531,	2,	1,	4,	377,	0,	1,	SystemZOpInfoBase + 704,	0,	0, 0x3fc00ULL },  // LCEBR
    { 1530,	2,	1,	2,	434,	0,	1,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // LCDR
    { 1529,	2,	1,	4,	378,	0,	0,	SystemZOpInfoBase + 704,	0,	0, 0x0ULL },  // LCDFR_32
    { 1528,	2,	1,	4,	378,	0,	0,	SystemZOpInfoBase + 1188,	0,	0, 0x0ULL },  // LCDFR_16
    { 1527,	2,	1,	4,	378,	0,	0,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // LCDFR
    { 1526,	2,	1,	4,	377,	0,	1,	SystemZOpInfoBase + 676,	0,	0, 0x3fc00ULL },  // LCDBR
    { 1525,	2,	0,	4,	861,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // LCCTL
    { 1524,	5,	1,	6,	34,	0,	1,	SystemZOpInfoBase + 1183,	0,	0, 0x8ULL },  // LCBB
    { 1523,	2,	1,	4,	57,	0,	0,	SystemZOpInfoBase + 858,	0,	0, 0x0ULL },  // LBR
    { 1522,	4,	1,	6,	61,	0,	0,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x2cULL },  // LBH
    { 1521,	2,	0,	4,	796,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x100ULL },  // LBEAR
    { 1520,	4,	1,	6,	61,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x2cULL },  // LB
    { 1519,	4,	1,	6,	86,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0xcULL },  // LAY
    { 1518,	4,	1,	6,	274,	0,	1,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // LAXG
    { 1517,	4,	1,	6,	274,	0,	1,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // LAX
    { 1516,	4,	1,	6,	43,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x8cULL },  // LAT
    { 1515,	4,	0,	6,	823,	0,	1,	SystemZOpInfoBase + 1179,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LASP
    { 1514,	2,	1,	6,	86,	0,	0,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LARL
    { 1513,	4,	1,	6,	273,	0,	1,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // LAOG
    { 1512,	4,	1,	6,	273,	0,	1,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // LAO
    { 1511,	4,	1,	6,	272,	0,	1,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // LANG
    { 1510,	4,	1,	6,	272,	0,	1,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // LAN
    { 1509,	4,	2,	6,	317,	0,	0,	SystemZOpInfoBase + 1175,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL },  // LAMY
    { 1508,	4,	2,	4,	317,	0,	0,	SystemZOpInfoBase + 1175,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LAM
    { 1507,	4,	1,	6,	316,	0,	0,	SystemZOpInfoBase + 160,	0,	0, 0xcULL },  // LAEY
    { 1506,	4,	1,	4,	316,	0,	0,	SystemZOpInfoBase + 160,	0,	0, 0x8ULL },  // LAE
    { 1505,	4,	1,	6,	271,	0,	1,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // LAALG
    { 1504,	4,	1,	6,	271,	0,	1,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // LAAL
    { 1503,	4,	1,	6,	270,	0,	1,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // LAAG
    { 1502,	4,	1,	6,	270,	0,	1,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // LAA
    { 1501,	4,	1,	4,	86,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x8ULL },  // LA
    { 1500,	4,	1,	4,	33,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x89ULL },  // L
    { 1499,	2,	0,	4,	526,	1,	1,	SystemZOpInfoBase + 718,	1,	0|(1ULL<<MCID::Compare), 0x0ULL },  // KXTR
    { 1498,	2,	0,	4,	409,	1,	1,	SystemZOpInfoBase + 718,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x3c00ULL },  // KXBR
    { 1497,	4,	2,	4,	923,	2,	1,	SystemZOpInfoBase + 837,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KMO
    { 1496,	4,	2,	4,	923,	2,	1,	SystemZOpInfoBase + 837,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KMF
    { 1495,	6,	3,	4,	923,	2,	1,	SystemZOpInfoBase + 1169,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KMCTR
    { 1494,	4,	2,	4,	923,	2,	1,	SystemZOpInfoBase + 837,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KMC
    { 1493,	3,	1,	4,	916,	2,	1,	SystemZOpInfoBase + 1161,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KMAC
    { 1492,	6,	3,	4,	294,	2,	1,	SystemZOpInfoBase + 1169,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KMA
    { 1491,	4,	2,	4,	923,	2,	1,	SystemZOpInfoBase + 837,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KM
    { 1490,	5,	2,	4,	295,	2,	1,	SystemZOpInfoBase + 1164,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KLMDOpt
    { 1489,	3,	1,	4,	916,	2,	1,	SystemZOpInfoBase + 1161,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KLMD
    { 1488,	5,	2,	4,	295,	2,	1,	SystemZOpInfoBase + 1164,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KIMDOpt
    { 1487,	3,	1,	4,	916,	2,	1,	SystemZOpInfoBase + 1161,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KIMD
    { 1486,	2,	0,	4,	408,	1,	1,	SystemZOpInfoBase + 704,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x3c00ULL },  // KEBR
    { 1485,	4,	0,	6,	407,	1,	1,	SystemZOpInfoBase + 700,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3c88ULL },  // KEB
    { 1484,	2,	0,	4,	525,	1,	1,	SystemZOpInfoBase + 676,	1,	0|(1ULL<<MCID::Compare), 0x0ULL },  // KDTR
    { 1483,	3,	1,	4,	874,	2,	1,	SystemZOpInfoBase + 1161,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // KDSA
    { 1482,	2,	0,	4,	408,	1,	1,	SystemZOpInfoBase + 676,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x3c00ULL },  // KDBR
    { 1481,	4,	0,	6,	407,	1,	1,	SystemZOpInfoBase + 672,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3d08ULL },  // KDB
    { 1480,	1,	0,	4,	873,	0,	0,	SystemZOpInfoBase + 265,	0,	0, 0x0ULL },  // JNOP
    { 1479,	1,	0,	6,	873,	0,	0,	SystemZOpInfoBase + 265,	0,	0, 0x0ULL },  // JGNOP
    { 1478,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmZ
    { 1477,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmP
    { 1476,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmO
    { 1475,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmNZ
    { 1474,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmNP
    { 1473,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmNO
    { 1472,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmNM
    { 1471,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmNLH
    { 1470,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmNLE
    { 1469,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmNL
    { 1468,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmNHE
    { 1467,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmNH
    { 1466,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmNE
    { 1465,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmM
    { 1464,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmLH
    { 1463,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmLE
    { 1462,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmL
    { 1461,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmHE
    { 1460,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmH
    { 1459,	1,	0,	6,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JGAsmE
    { 1458,	1,	0,	6,	3,	0,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // JG
    { 1457,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmZ
    { 1456,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmP
    { 1455,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmO
    { 1454,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmNZ
    { 1453,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmNP
    { 1452,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmNO
    { 1451,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmNM
    { 1450,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmNLH
    { 1449,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmNLE
    { 1448,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmNL
    { 1447,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmNHE
    { 1446,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmNH
    { 1445,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmNE
    { 1444,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmM
    { 1443,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmLH
    { 1442,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmLE
    { 1441,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmL
    { 1440,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmHE
    { 1439,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmH
    { 1438,	1,	0,	4,	3,	1,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // JAsmE
    { 1437,	1,	0,	4,	3,	0,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // J
    { 1436,	5,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1156,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnVSI
    { 1435,	6,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1150,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnVRX
    { 1434,	6,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1144,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnVRV
    { 1433,	6,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1138,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnVRS
    { 1432,	7,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1131,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnVRR
    { 1431,	6,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1125,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnVRI
    { 1430,	6,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1119,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnSSF
    { 1429,	5,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1114,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnSSE
    { 1428,	7,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1107,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnSS
    { 1427,	4,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1103,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // InsnSIY
    { 1426,	4,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1103,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnSIL
    { 1425,	4,	0,	4,	346,	0,	0,	SystemZOpInfoBase + 1103,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnSI
    { 1424,	3,	0,	4,	346,	0,	0,	SystemZOpInfoBase + 1100,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnS
    { 1423,	5,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1089,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0xcULL },  // InsnRXY
    { 1422,	6,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1094,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL },  // InsnRXF
    { 1421,	5,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1089,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL },  // InsnRXE
    { 1420,	5,	0,	4,	346,	0,	0,	SystemZOpInfoBase + 1089,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL },  // InsnRX
    { 1419,	5,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1084,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // InsnRSY
    { 1418,	4,	0,	4,	346,	0,	0,	SystemZOpInfoBase + 1057,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRSI
    { 1417,	5,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1084,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRSE
    { 1416,	5,	0,	4,	346,	0,	0,	SystemZOpInfoBase + 1084,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRS
    { 1415,	6,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1078,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRRS
    { 1414,	5,	0,	4,	346,	0,	0,	SystemZOpInfoBase + 1073,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRRF
    { 1413,	3,	0,	4,	346,	0,	0,	SystemZOpInfoBase + 1070,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRRE
    { 1412,	3,	0,	2,	346,	0,	0,	SystemZOpInfoBase + 1070,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRR
    { 1411,	6,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1064,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRIS
    { 1410,	3,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1054,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRILU
    { 1409,	3,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1061,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRIL
    { 1408,	4,	0,	6,	346,	0,	0,	SystemZOpInfoBase + 1057,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRIE
    { 1407,	3,	0,	4,	346,	0,	0,	SystemZOpInfoBase + 1054,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnRI
    { 1406,	1,	0,	2,	346,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // InsnE
    { 1405,	3,	1,	4,	799,	0,	0,	SystemZOpInfoBase + 616,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IVSK
    { 1404,	3,	1,	4,	798,	0,	0,	SystemZOpInfoBase + 616,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ISKE
    { 1403,	2,	1,	4,	802,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IRBM
    { 1402,	2,	0,	4,	807,	0,	0,	SystemZOpInfoBase + 757,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IPTEOptOpt
    { 1401,	3,	0,	4,	807,	0,	0,	SystemZOpInfoBase + 1051,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IPTEOpt
    { 1400,	4,	0,	4,	807,	0,	0,	SystemZOpInfoBase + 1047,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IPTE
    { 1399,	1,	1,	4,	319,	1,	0,	SystemZOpInfoBase + 995,	0,	0, 0x0ULL },  // IPM
    { 1398,	0,	0,	4,	784,	1,	1,	SystemZOpInfoBase + 1,	51,	0, 0x0ULL },  // IPK
    { 1397,	3,	1,	4,	103,	0,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // IILL
    { 1396,	3,	1,	4,	102,	0,	0,	SystemZOpInfoBase + 550,	0,	0, 0x0ULL },  // IILH
    { 1395,	2,	1,	6,	101,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // IILF
    { 1394,	3,	1,	4,	100,	0,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // IIHL
    { 1393,	3,	1,	4,	99,	0,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // IIHH
    { 1392,	2,	1,	6,	98,	0,	0,	SystemZOpInfoBase + 819,	0,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // IIHF
    { 1391,	3,	1,	4,	524,	0,	0,	SystemZOpInfoBase + 1044,	0,	0, 0x0ULL },  // IEXTR
    { 1390,	3,	1,	4,	523,	0,	0,	SystemZOpInfoBase + 1041,	0,	0, 0x0ULL },  // IEDTR
    { 1389,	3,	0,	4,	808,	0,	0,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IDTEOpt
    { 1388,	4,	0,	4,	808,	0,	0,	SystemZOpInfoBase + 1037,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IDTE
    { 1387,	5,	1,	6,	94,	0,	0,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x2cULL },  // ICY
    { 1386,	5,	1,	6,	96,	0,	1,	SystemZOpInfoBase + 1027,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL },  // ICMY
    { 1385,	5,	1,	6,	96,	0,	1,	SystemZOpInfoBase + 1032,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL },  // ICMH
    { 1384,	5,	1,	4,	96,	0,	1,	SystemZOpInfoBase + 1027,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // ICM
    { 1383,	5,	1,	6,	95,	0,	0,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x2cULL },  // IC32Y
    { 1382,	5,	1,	4,	95,	0,	0,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x28ULL },  // IC32
    { 1381,	5,	1,	4,	94,	0,	0,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x28ULL },  // IC
    { 1380,	1,	1,	4,	788,	0,	0,	SystemZOpInfoBase + 995,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IAC
    { 1379,	0,	0,	4,	865,	1,	1,	SystemZOpInfoBase + 1,	41,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // HSCH
    { 1378,	2,	1,	2,	436,	0,	0,	SystemZOpInfoBase + 704,	0,	0, 0x0ULL },  // HER
    { 1377,	2,	1,	2,	436,	0,	0,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // HDR
    { 1376,	2,	1,	4,	333,	0,	1,	SystemZOpInfoBase + 169,	0,	0, 0x0ULL },  // FLOGR
    { 1375,	4,	1,	4,	504,	1,	0,	SystemZOpInfoBase + 1023,	12,	0, 0x0ULL },  // FIXTR
    { 1374,	2,	1,	4,	442,	0,	0,	SystemZOpInfoBase + 718,	0,	0, 0x0ULL },  // FIXR
    { 1373,	4,	1,	4,	385,	1,	0,	SystemZOpInfoBase + 1023,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // FIXBRA
    { 1372,	3,	1,	4,	385,	1,	0,	SystemZOpInfoBase + 1020,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // FIXBR
    { 1371,	2,	1,	4,	441,	0,	0,	SystemZOpInfoBase + 704,	0,	0, 0x0ULL },  // FIER
    { 1370,	4,	1,	4,	384,	1,	0,	SystemZOpInfoBase + 1016,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // FIEBRA
    { 1369,	3,	1,	4,	384,	1,	0,	SystemZOpInfoBase + 1013,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // FIEBR
    { 1368,	4,	1,	4,	503,	1,	0,	SystemZOpInfoBase + 1009,	12,	0, 0x0ULL },  // FIDTR
    { 1367,	2,	1,	4,	441,	0,	0,	SystemZOpInfoBase + 676,	0,	0, 0x0ULL },  // FIDR
    { 1366,	4,	1,	4,	384,	1,	0,	SystemZOpInfoBase + 1009,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // FIDBRA
    { 1365,	3,	1,	4,	384,	1,	0,	SystemZOpInfoBase + 1006,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // FIDBR
    { 1364,	2,	0,	6,	345,	0,	0,	SystemZOpInfoBase + 1004,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EXRL
    { 1363,	4,	0,	4,	345,	0,	0,	SystemZOpInfoBase + 1000,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL },  // EX
    { 1362,	1,	1,	4,	329,	0,	0,	SystemZOpInfoBase + 995,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ETND
    { 1361,	2,	1,	4,	508,	0,	0,	SystemZOpInfoBase + 993,	0,	0, 0x0ULL },  // ESXTR
    { 1360,	2,	1,	4,	833,	0,	1,	SystemZOpInfoBase + 998,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ESTA
    { 1359,	2,	1,	4,	794,	0,	0,	SystemZOpInfoBase + 996,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ESEA
    { 1358,	2,	1,	4,	507,	0,	0,	SystemZOpInfoBase + 944,	0,	0, 0x0ULL },  // ESDTR
    { 1357,	1,	1,	4,	792,	0,	0,	SystemZOpInfoBase + 995,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ESAR
    { 1356,	1,	1,	4,	792,	0,	0,	SystemZOpInfoBase + 307,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ESAIR
    { 1355,	2,	0,	4,	832,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EREGG
    { 1354,	2,	0,	4,	832,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EREG
    { 1353,	2,	2,	4,	782,	1,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EPSW
    { 1352,	2,	1,	4,	860,	0,	1,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EPCTR
    { 1351,	1,	1,	4,	792,	0,	0,	SystemZOpInfoBase + 995,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EPAR
    { 1350,	1,	1,	4,	792,	0,	0,	SystemZOpInfoBase + 307,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EPAIR
    { 1349,	1,	1,	4,	412,	1,	0,	SystemZOpInfoBase + 995,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EFPC
    { 1348,	2,	1,	4,	506,	0,	0,	SystemZOpInfoBase + 993,	0,	0, 0x0ULL },  // EEXTR
    { 1347,	2,	1,	4,	505,	0,	0,	SystemZOpInfoBase + 944,	0,	0, 0x0ULL },  // EEDTR
    { 1346,	5,	0,	6,	314,	0,	1,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // EDMK
    { 1345,	5,	0,	6,	314,	0,	1,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // ED
    { 1344,	5,	0,	6,	846,	0,	2,	SystemZOpInfoBase + 931,	49,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ECTG
    { 1343,	2,	1,	4,	859,	0,	1,	SystemZOpInfoBase + 991,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ECPGA
    { 1342,	2,	1,	4,	860,	0,	1,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ECCTR
    { 1341,	4,	1,	6,	845,	0,	0,	SystemZOpInfoBase + 987,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // ECAG
    { 1340,	2,	1,	4,	315,	0,	0,	SystemZOpInfoBase + 985,	0,	0, 0x0ULL },  // EAR
    { 1339,	4,	1,	4,	516,	1,	0,	SystemZOpInfoBase + 591,	12,	0, 0x0ULL },  // DXTRA
    { 1338,	3,	1,	4,	516,	1,	0,	SystemZOpInfoBase + 588,	12,	0, 0x0ULL },  // DXTR
    { 1337,	3,	1,	4,	468,	0,	0,	SystemZOpInfoBase + 585,	0,	0, 0x0ULL },  // DXR
    { 1336,	3,	1,	4,	405,	1,	0,	SystemZOpInfoBase + 585,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DXBR
    { 1335,	3,	1,	4,	204,	0,	0,	SystemZOpInfoBase + 928,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSGR
    { 1334,	3,	1,	4,	204,	0,	0,	SystemZOpInfoBase + 982,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DSGFR
    { 1333,	5,	1,	6,	205,	0,	0,	SystemZOpInfoBase + 962,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x8cULL },  // DSGF
    { 1332,	5,	1,	6,	205,	0,	0,	SystemZOpInfoBase + 962,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x10cULL },  // DSG
    { 1331,	3,	1,	2,	202,	0,	0,	SystemZOpInfoBase + 982,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DR
    { 1330,	6,	0,	6,	310,	0,	0,	SystemZOpInfoBase + 579,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // DP
    { 1329,	3,	1,	4,	206,	0,	0,	SystemZOpInfoBase + 982,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DLR
    { 1328,	3,	1,	4,	207,	0,	0,	SystemZOpInfoBase + 928,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DLGR
    { 1327,	5,	1,	6,	208,	0,	0,	SystemZOpInfoBase + 962,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x10cULL },  // DLG
    { 1326,	5,	1,	6,	208,	0,	0,	SystemZOpInfoBase + 962,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x8cULL },  // DL
    { 1325,	5,	2,	4,	406,	1,	1,	SystemZOpInfoBase + 977,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DIEBR
    { 1324,	5,	2,	4,	406,	1,	1,	SystemZOpInfoBase + 972,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DIDBR
    { 1323,	4,	0,	4,	852,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DIAG
    { 1322,	5,	2,	4,	343,	2,	1,	SystemZOpInfoBase + 967,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // DFLTCC
    { 1321,	3,	1,	2,	466,	0,	0,	SystemZOpInfoBase + 547,	0,	0, 0x0ULL },  // DER
    { 1320,	3,	1,	4,	403,	1,	0,	SystemZOpInfoBase + 547,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DEBR
    { 1319,	5,	1,	6,	401,	1,	0,	SystemZOpInfoBase + 542,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // DEB
    { 1318,	5,	1,	4,	464,	0,	0,	SystemZOpInfoBase + 542,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // DE
    { 1317,	4,	1,	4,	515,	1,	0,	SystemZOpInfoBase + 538,	12,	0, 0x0ULL },  // DDTRA
    { 1316,	3,	1,	4,	515,	1,	0,	SystemZOpInfoBase + 535,	12,	0, 0x0ULL },  // DDTR
    { 1315,	3,	1,	2,	467,	0,	0,	SystemZOpInfoBase + 532,	0,	0, 0x0ULL },  // DDR
    { 1314,	3,	1,	4,	404,	1,	0,	SystemZOpInfoBase + 532,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // DDBR
    { 1313,	5,	1,	6,	402,	1,	0,	SystemZOpInfoBase + 527,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // DDB
    { 1312,	5,	1,	4,	465,	0,	0,	SystemZOpInfoBase + 527,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // DD
    { 1311,	5,	1,	4,	203,	0,	0,	SystemZOpInfoBase + 962,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x88ULL },  // D
    { 1310,	5,	0,	6,	497,	0,	0,	SystemZOpInfoBase + 911,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // CZXT
    { 1309,	5,	0,	6,	496,	0,	0,	SystemZOpInfoBase + 690,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // CZDT
    { 1308,	4,	0,	6,	220,	0,	1,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x388cULL },  // CY
    { 1307,	5,	1,	6,	495,	0,	0,	SystemZOpInfoBase + 911,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CXZT
    { 1306,	2,	1,	4,	491,	0,	0,	SystemZOpInfoBase + 960,	0,	0, 0x0ULL },  // CXUTR
    { 1305,	2,	0,	4,	526,	1,	1,	SystemZOpInfoBase + 718,	1,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CXTR
    { 1304,	2,	1,	4,	491,	0,	0,	SystemZOpInfoBase + 960,	0,	0, 0x0ULL },  // CXSTR
    { 1303,	2,	0,	4,	471,	0,	1,	SystemZOpInfoBase + 718,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CXR
    { 1302,	5,	1,	6,	499,	0,	0,	SystemZOpInfoBase + 911,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CXPT
    { 1301,	4,	1,	4,	485,	1,	0,	SystemZOpInfoBase + 956,	12,	0, 0x0ULL },  // CXLGTR
    { 1300,	4,	1,	4,	370,	1,	0,	SystemZOpInfoBase + 956,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CXLGBR
    { 1299,	4,	1,	4,	484,	1,	0,	SystemZOpInfoBase + 950,	12,	0, 0x0ULL },  // CXLFTR
    { 1298,	4,	1,	4,	370,	1,	0,	SystemZOpInfoBase + 950,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CXLFBR
    { 1297,	4,	1,	4,	481,	1,	0,	SystemZOpInfoBase + 956,	12,	0, 0x0ULL },  // CXGTRA
    { 1296,	2,	1,	4,	481,	1,	0,	SystemZOpInfoBase + 954,	12,	0, 0x0ULL },  // CXGTR
    { 1295,	2,	1,	4,	429,	0,	0,	SystemZOpInfoBase + 954,	0,	0, 0x0ULL },  // CXGR
    { 1294,	4,	1,	4,	368,	1,	0,	SystemZOpInfoBase + 956,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CXGBRA
    { 1293,	2,	1,	4,	368,	1,	0,	SystemZOpInfoBase + 954,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CXGBR
    { 1292,	4,	1,	4,	480,	1,	0,	SystemZOpInfoBase + 950,	12,	0, 0x0ULL },  // CXFTR
    { 1291,	2,	1,	4,	429,	0,	0,	SystemZOpInfoBase + 948,	0,	0, 0x0ULL },  // CXFR
    { 1290,	4,	1,	4,	368,	1,	0,	SystemZOpInfoBase + 950,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CXFBRA
    { 1289,	2,	1,	4,	368,	1,	0,	SystemZOpInfoBase + 948,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CXFBR
    { 1288,	2,	0,	4,	409,	1,	1,	SystemZOpInfoBase + 718,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x3c00ULL },  // CXBR
    { 1287,	4,	0,	6,	303,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayStore), 0x8cULL },  // CVDY
    { 1286,	4,	0,	6,	302,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::MayStore), 0x10cULL },  // CVDG
    { 1285,	4,	0,	4,	303,	0,	0,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::MayStore), 0x88ULL },  // CVD
    { 1284,	5,	1,	6,	301,	0,	0,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x8cULL },  // CVBY
    { 1283,	5,	1,	6,	300,	0,	0,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x10cULL },  // CVBG
    { 1282,	5,	1,	4,	301,	0,	0,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // CVB
    { 1281,	2,	1,	4,	493,	0,	0,	SystemZOpInfoBase + 946,	0,	0, 0x0ULL },  // CUXTR
    { 1280,	4,	2,	4,	293,	0,	1,	SystemZOpInfoBase + 837,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CUUTFOpt
    { 1279,	5,	2,	4,	293,	0,	1,	SystemZOpInfoBase + 939,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CUUTF
    { 1278,	4,	2,	4,	293,	0,	1,	SystemZOpInfoBase + 837,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CUTFUOpt
    { 1277,	5,	2,	4,	293,	0,	1,	SystemZOpInfoBase + 939,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CUTFU
    { 1276,	4,	2,	4,	337,	2,	1,	SystemZOpInfoBase + 837,	46,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CUSE
    { 1275,	2,	1,	4,	492,	0,	0,	SystemZOpInfoBase + 944,	0,	0, 0x0ULL },  // CUDTR
    { 1274,	4,	2,	4,	292,	0,	1,	SystemZOpInfoBase + 837,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CU42
    { 1273,	4,	2,	4,	292,	0,	1,	SystemZOpInfoBase + 837,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CU41
    { 1272,	4,	2,	4,	292,	0,	1,	SystemZOpInfoBase + 837,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CU24Opt
    { 1271,	5,	2,	4,	292,	0,	1,	SystemZOpInfoBase + 939,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CU24
    { 1270,	4,	2,	4,	292,	0,	1,	SystemZOpInfoBase + 837,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CU21Opt
    { 1269,	5,	2,	4,	292,	0,	1,	SystemZOpInfoBase + 939,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CU21
    { 1268,	4,	2,	4,	292,	0,	1,	SystemZOpInfoBase + 837,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CU14Opt
    { 1267,	5,	2,	4,	292,	0,	1,	SystemZOpInfoBase + 939,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CU14
    { 1266,	4,	2,	4,	292,	0,	1,	SystemZOpInfoBase + 837,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CU12Opt
    { 1265,	5,	2,	4,	292,	0,	1,	SystemZOpInfoBase + 939,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CU12
    { 1264,	2,	1,	4,	332,	0,	0,	SystemZOpInfoBase + 598,	0,	0, 0x0ULL },  // CTZG
    { 1263,	5,	1,	6,	276,	0,	1,	SystemZOpInfoBase + 648,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // CSY
    { 1262,	3,	1,	4,	493,	0,	0,	SystemZOpInfoBase + 936,	0,	0, 0x0ULL },  // CSXTR
    { 1261,	5,	0,	6,	279,	2,	1,	SystemZOpInfoBase + 931,	43,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CSST
    { 1260,	3,	1,	4,	812,	0,	1,	SystemZOpInfoBase + 928,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CSPG
    { 1259,	3,	1,	4,	812,	0,	1,	SystemZOpInfoBase + 928,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CSP
    { 1258,	5,	1,	6,	276,	0,	1,	SystemZOpInfoBase + 653,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // CSG
    { 1257,	3,	1,	4,	492,	0,	0,	SystemZOpInfoBase + 925,	0,	0, 0x0ULL },  // CSDTR
    { 1256,	0,	0,	4,	865,	1,	1,	SystemZOpInfoBase + 1,	41,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CSCH
    { 1255,	5,	1,	4,	276,	0,	1,	SystemZOpInfoBase + 648,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CS
    { 1254,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmNLH
    { 1253,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmNLE
    { 1252,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmNL
    { 1251,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmNHE
    { 1250,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmNH
    { 1249,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmNE
    { 1248,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmLH
    { 1247,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmLE
    { 1246,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmL
    { 1245,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmHE
    { 1244,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmH
    { 1243,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsmE
    { 1242,	3,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 250,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRTAsm
    { 1241,	3,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 250,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRT
    { 1240,	2,	0,	6,	221,	0,	1,	SystemZOpInfoBase + 808,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL },  // CRL
    { 1239,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmNLH
    { 1238,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmNLE
    { 1237,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmNL
    { 1236,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmNHE
    { 1235,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmNH
    { 1234,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmNE
    { 1233,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmLH
    { 1232,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmLE
    { 1231,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmL
    { 1230,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmHE
    { 1229,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmH
    { 1228,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsmE
    { 1227,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 869,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJAsm
    { 1226,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 869,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRJ
    { 1225,	3,	0,	4,	810,	0,	1,	SystemZOpInfoBase + 922,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRDTEOpt
    { 1224,	4,	0,	4,	810,	0,	1,	SystemZOpInfoBase + 918,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRDTE
    { 1223,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmNLH
    { 1222,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmNLE
    { 1221,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmNL
    { 1220,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmNHE
    { 1219,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmNH
    { 1218,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmNE
    { 1217,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmLH
    { 1216,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmLE
    { 1215,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmL
    { 1214,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmHE
    { 1213,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmH
    { 1212,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsmE
    { 1211,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 860,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBAsm
    { 1210,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 860,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRB
    { 1209,	2,	0,	2,	225,	0,	1,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL },  // CR
    { 1208,	2,	1,	4,	315,	0,	0,	SystemZOpInfoBase + 916,	0,	0, 0x0ULL },  // CPYA
    { 1207,	5,	0,	6,	501,	0,	0,	SystemZOpInfoBase + 911,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // CPXT
    { 1206,	3,	1,	4,	355,	0,	0,	SystemZOpInfoBase + 908,	0,	0, 0x0ULL },  // CPSDRss
    { 1205,	3,	1,	4,	355,	0,	0,	SystemZOpInfoBase + 905,	0,	0, 0x0ULL },  // CPSDRsh
    { 1204,	3,	1,	4,	355,	0,	0,	SystemZOpInfoBase + 902,	0,	0, 0x0ULL },  // CPSDRsd
    { 1203,	3,	1,	4,	355,	0,	0,	SystemZOpInfoBase + 899,	0,	0, 0x0ULL },  // CPSDRhs
    { 1202,	3,	1,	4,	355,	0,	0,	SystemZOpInfoBase + 896,	0,	0, 0x0ULL },  // CPSDRhh
    { 1201,	3,	1,	4,	355,	0,	0,	SystemZOpInfoBase + 893,	0,	0, 0x0ULL },  // CPSDRhd
    { 1200,	3,	1,	4,	355,	0,	0,	SystemZOpInfoBase + 890,	0,	0, 0x0ULL },  // CPSDRds
    { 1199,	3,	1,	4,	355,	0,	0,	SystemZOpInfoBase + 887,	0,	0, 0x0ULL },  // CPSDRdh
    { 1198,	3,	1,	4,	355,	0,	0,	SystemZOpInfoBase + 535,	0,	0, 0x0ULL },  // CPSDRdd
    { 1197,	5,	0,	6,	500,	0,	0,	SystemZOpInfoBase + 690,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // CPDT
    { 1196,	6,	0,	6,	312,	0,	1,	SystemZOpInfoBase + 579,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x0ULL },  // CP
    { 1195,	4,	2,	4,	341,	2,	2,	SystemZOpInfoBase + 837,	37,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CMPSC
    { 1194,	2,	1,	4,	332,	0,	0,	SystemZOpInfoBase + 598,	0,	0, 0x0ULL },  // CLZG
    { 1193,	4,	0,	6,	229,	0,	1,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x10388cULL },  // CLY
    { 1192,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmNLH
    { 1191,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmNLE
    { 1190,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmNL
    { 1189,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmNHE
    { 1188,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmNH
    { 1187,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmNE
    { 1186,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmLH
    { 1185,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmLE
    { 1184,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmL
    { 1183,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmHE
    { 1182,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmH
    { 1181,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 884,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsmE
    { 1180,	4,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 880,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLTAsm
    { 1179,	4,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 880,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLT
    { 1178,	4,	2,	4,	257,	1,	1,	SystemZOpInfoBase + 876,	35,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CLST
    { 1177,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmNLH
    { 1176,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmNLE
    { 1175,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmNL
    { 1174,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmNHE
    { 1173,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmNH
    { 1172,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmNE
    { 1171,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmLH
    { 1170,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmLE
    { 1169,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmL
    { 1168,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmHE
    { 1167,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmH
    { 1166,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsmE
    { 1165,	3,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 250,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRTAsm
    { 1164,	3,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 250,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLRT
    { 1163,	2,	0,	6,	244,	0,	1,	SystemZOpInfoBase + 808,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL },  // CLRL
    { 1162,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmNLH
    { 1161,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmNLE
    { 1160,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmNL
    { 1159,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmNHE
    { 1158,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmNH
    { 1157,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmNE
    { 1156,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmLH
    { 1155,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmLE
    { 1154,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmL
    { 1153,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmHE
    { 1152,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmH
    { 1151,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 873,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsmE
    { 1150,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 869,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJAsm
    { 1149,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 869,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRJ
    { 1148,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmNLH
    { 1147,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmNLE
    { 1146,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmNL
    { 1145,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmNHE
    { 1144,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmNH
    { 1143,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmNE
    { 1142,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmLH
    { 1141,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmLE
    { 1140,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmL
    { 1139,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmHE
    { 1138,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmH
    { 1137,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 865,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsmE
    { 1136,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 860,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBAsm
    { 1135,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 860,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRB
    { 1134,	2,	0,	2,	243,	0,	1,	SystemZOpInfoBase + 858,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL },  // CLR
    { 1133,	4,	0,	6,	264,	0,	1,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL },  // CLMY
    { 1132,	4,	0,	6,	264,	0,	1,	SystemZOpInfoBase + 854,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL },  // CLMH
    { 1131,	4,	0,	4,	264,	0,	1,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CLM
    { 1130,	3,	0,	6,	242,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103804ULL },  // CLIY
    { 1129,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmNLH
    { 1128,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmNLE
    { 1127,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmNL
    { 1126,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmNHE
    { 1125,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmNH
    { 1124,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmNE
    { 1123,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmLH
    { 1122,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmLE
    { 1121,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmL
    { 1120,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmHE
    { 1119,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmH
    { 1118,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsmE
    { 1117,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 821,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJAsm
    { 1116,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 821,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIJ
    { 1115,	2,	0,	6,	241,	0,	1,	SystemZOpInfoBase + 819,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL },  // CLIH
    { 1114,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmNLH
    { 1113,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmNLE
    { 1112,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmNL
    { 1111,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmNHE
    { 1110,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmNH
    { 1109,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmNE
    { 1108,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmLH
    { 1107,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmLE
    { 1106,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmL
    { 1105,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmHE
    { 1104,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmH
    { 1103,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsmE
    { 1102,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 810,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBAsm
    { 1101,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 810,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIB
    { 1100,	3,	0,	4,	242,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL },  // CLI
    { 1099,	2,	0,	6,	240,	0,	1,	SystemZOpInfoBase + 808,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL },  // CLHRL
    { 1098,	2,	0,	4,	246,	0,	1,	SystemZOpInfoBase + 806,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL },  // CLHLR
    { 1097,	3,	0,	6,	240,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL },  // CLHHSI
    { 1096,	2,	0,	4,	245,	0,	1,	SystemZOpInfoBase + 804,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL },  // CLHHR
    { 1095,	4,	0,	6,	239,	0,	1,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x10388cULL },  // CLHF
    { 1094,	4,	1,	4,	489,	1,	1,	SystemZOpInfoBase + 796,	1,	0, 0x0ULL },  // CLGXTR
    { 1093,	4,	1,	4,	376,	1,	1,	SystemZOpInfoBase + 796,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CLGXBR
    { 1092,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmNLH
    { 1091,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmNLE
    { 1090,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmNL
    { 1089,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmNHE
    { 1088,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmNH
    { 1087,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmNE
    { 1086,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmLH
    { 1085,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmLE
    { 1084,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmL
    { 1083,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmHE
    { 1082,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmH
    { 1081,	3,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 851,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsmE
    { 1080,	4,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 847,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGTAsm
    { 1079,	4,	0,	6,	17,	0,	0,	SystemZOpInfoBase + 847,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x4ULL },  // CLGT
    { 1078,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmNLH
    { 1077,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmNLE
    { 1076,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmNL
    { 1075,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmNHE
    { 1074,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmNH
    { 1073,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmNE
    { 1072,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmLH
    { 1071,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmLE
    { 1070,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmL
    { 1069,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmHE
    { 1068,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmH
    { 1067,	2,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsmE
    { 1066,	3,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 222,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRTAsm
    { 1065,	3,	0,	4,	15,	0,	0,	SystemZOpInfoBase + 222,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGRT
    { 1064,	2,	0,	6,	238,	0,	1,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL },  // CLGRL
    { 1063,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmNLH
    { 1062,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmNLE
    { 1061,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmNL
    { 1060,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmNHE
    { 1059,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmNH
    { 1058,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmNE
    { 1057,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmLH
    { 1056,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmLE
    { 1055,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmL
    { 1054,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmHE
    { 1053,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmH
    { 1052,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsmE
    { 1051,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 786,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJAsm
    { 1050,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 786,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRJ
    { 1049,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmNLH
    { 1048,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmNLE
    { 1047,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmNL
    { 1046,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmNHE
    { 1045,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmNH
    { 1044,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmNE
    { 1043,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmLH
    { 1042,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmLE
    { 1041,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmL
    { 1040,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmHE
    { 1039,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmH
    { 1038,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsmE
    { 1037,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 777,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBAsm
    { 1036,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 777,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRB
    { 1035,	2,	0,	4,	237,	0,	1,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL },  // CLGR
    { 1034,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmNLH
    { 1033,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmNLE
    { 1032,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmNL
    { 1031,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmNHE
    { 1030,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmNH
    { 1029,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmNE
    { 1028,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmLH
    { 1027,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmLE
    { 1026,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmL
    { 1025,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmHE
    { 1024,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmH
    { 1023,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsmE
    { 1022,	3,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 215,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGITAsm
    { 1021,	3,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 215,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLGIT
    { 1020,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmNLH
    { 1019,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmNLE
    { 1018,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmNL
    { 1017,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmNHE
    { 1016,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmNH
    { 1015,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmNE
    { 1014,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmLH
    { 1013,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmLE
    { 1012,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmL
    { 1011,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmHE
    { 1010,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmH
    { 1009,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsmE
    { 1008,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 770,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJAsm
    { 1007,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 770,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIJ
    { 1006,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmNLH
    { 1005,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmNLE
    { 1004,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmNL
    { 1003,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmNHE
    { 1002,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmNH
    { 1001,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmNE
    { 1000,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmLH
    { 999,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmLE
    { 998,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmL
    { 997,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmHE
    { 996,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmH
    { 995,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsmE
    { 994,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 761,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBAsm
    { 993,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 761,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIB
    { 992,	3,	0,	6,	233,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL },  // CLGHSI
    { 991,	2,	0,	6,	233,	0,	1,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL },  // CLGHRL
    { 990,	2,	0,	6,	235,	0,	1,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL },  // CLGFRL
    { 989,	2,	0,	4,	236,	0,	1,	SystemZOpInfoBase + 757,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL },  // CLGFR
    { 988,	2,	0,	6,	236,	0,	1,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL },  // CLGFI
    { 987,	4,	0,	6,	234,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x10388cULL },  // CLGF
    { 986,	4,	1,	4,	375,	1,	1,	SystemZOpInfoBase + 753,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CLGEBR
    { 985,	4,	1,	4,	488,	1,	1,	SystemZOpInfoBase + 746,	1,	0, 0x0ULL },  // CLGDTR
    { 984,	4,	1,	4,	375,	1,	1,	SystemZOpInfoBase + 746,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CLGDBR
    { 983,	4,	0,	6,	232,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x10390cULL },  // CLG
    { 982,	4,	1,	4,	489,	1,	1,	SystemZOpInfoBase + 739,	1,	0, 0x0ULL },  // CLFXTR
    { 981,	4,	1,	4,	376,	1,	1,	SystemZOpInfoBase + 739,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CLFXBR
    { 980,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmNLH
    { 979,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmNLE
    { 978,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmNL
    { 977,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmNHE
    { 976,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmNH
    { 975,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmNE
    { 974,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmLH
    { 973,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmLE
    { 972,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmL
    { 971,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmHE
    { 970,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmH
    { 969,	2,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsmE
    { 968,	3,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 229,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFITAsm
    { 967,	3,	0,	6,	16,	0,	0,	SystemZOpInfoBase + 229,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CLFIT
    { 966,	2,	0,	6,	231,	0,	1,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::Compare), 0x103800ULL },  // CLFI
    { 965,	3,	0,	6,	230,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103800ULL },  // CLFHSI
    { 964,	4,	1,	4,	373,	1,	1,	SystemZOpInfoBase + 730,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CLFEBR
    { 963,	4,	1,	4,	488,	1,	1,	SystemZOpInfoBase + 723,	1,	0, 0x0ULL },  // CLFDTR
    { 962,	4,	1,	4,	374,	1,	1,	SystemZOpInfoBase + 723,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CLFDBR
    { 961,	6,	2,	6,	256,	0,	1,	SystemZOpInfoBase + 841,	0,	0|(1ULL<<MCID::MayLoad), 0x4ULL },  // CLCLU
    { 960,	6,	2,	4,	256,	0,	1,	SystemZOpInfoBase + 841,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CLCLE
    { 959,	4,	2,	2,	256,	0,	1,	SystemZOpInfoBase + 837,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CLCL
    { 958,	5,	0,	6,	255,	0,	1,	SystemZOpInfoBase + 832,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CLC
    { 957,	4,	0,	4,	229,	0,	1,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x103888ULL },  // CL
    { 956,	4,	2,	4,	340,	0,	1,	SystemZOpInfoBase + 828,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CKSM
    { 955,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmNLH
    { 954,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmNLE
    { 953,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmNL
    { 952,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmNHE
    { 951,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmNH
    { 950,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmNE
    { 949,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmLH
    { 948,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmLE
    { 947,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmL
    { 946,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmHE
    { 945,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmH
    { 944,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsmE
    { 943,	3,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 229,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CITAsm
    { 942,	3,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 229,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CIT
    { 941,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmNLH
    { 940,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmNLE
    { 939,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmNL
    { 938,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmNHE
    { 937,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmNH
    { 936,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmNE
    { 935,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmLH
    { 934,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmLE
    { 933,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmL
    { 932,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmHE
    { 931,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmH
    { 930,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 825,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsmE
    { 929,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 821,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJAsm
    { 928,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 821,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIJ
    { 927,	2,	0,	6,	226,	0,	1,	SystemZOpInfoBase + 819,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL },  // CIH
    { 926,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmNLH
    { 925,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmNLE
    { 924,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmNL
    { 923,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmNHE
    { 922,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmNH
    { 921,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmNE
    { 920,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmLH
    { 919,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmLE
    { 918,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmL
    { 917,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmHE
    { 916,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmH
    { 915,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 815,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsmE
    { 914,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 810,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBAsm
    { 913,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 810,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIB
    { 912,	4,	0,	6,	247,	0,	1,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x384cULL },  // CHY
    { 911,	3,	0,	6,	228,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL },  // CHSI
    { 910,	2,	0,	6,	248,	0,	1,	SystemZOpInfoBase + 808,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL },  // CHRL
    { 909,	2,	0,	4,	246,	0,	1,	SystemZOpInfoBase + 806,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL },  // CHLR
    { 908,	2,	0,	4,	222,	0,	1,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL },  // CHI
    { 907,	3,	0,	6,	251,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL },  // CHHSI
    { 906,	2,	0,	4,	245,	0,	1,	SystemZOpInfoBase + 804,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL },  // CHHR
    { 905,	4,	0,	6,	227,	0,	1,	SystemZOpInfoBase + 800,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x388cULL },  // CHF
    { 904,	4,	0,	4,	247,	0,	1,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3848ULL },  // CH
    { 903,	4,	1,	4,	487,	1,	1,	SystemZOpInfoBase + 796,	1,	0, 0x0ULL },  // CGXTRA
    { 902,	3,	1,	4,	487,	1,	1,	SystemZOpInfoBase + 793,	1,	0, 0x0ULL },  // CGXTR
    { 901,	3,	1,	4,	431,	0,	1,	SystemZOpInfoBase + 793,	0,	0, 0x0ULL },  // CGXR
    { 900,	4,	1,	4,	372,	1,	1,	SystemZOpInfoBase + 796,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CGXBRA
    { 899,	3,	1,	4,	372,	1,	1,	SystemZOpInfoBase + 793,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CGXBR
    { 898,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmNLH
    { 897,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmNLE
    { 896,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmNL
    { 895,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmNHE
    { 894,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmNH
    { 893,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmNE
    { 892,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmLH
    { 891,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmLE
    { 890,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmL
    { 889,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmHE
    { 888,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmH
    { 887,	2,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsmE
    { 886,	3,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 222,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRTAsm
    { 885,	3,	0,	4,	14,	0,	0,	SystemZOpInfoBase + 222,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGRT
    { 884,	2,	0,	6,	224,	0,	1,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL },  // CGRL
    { 883,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmNLH
    { 882,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmNLE
    { 881,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmNL
    { 880,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmNHE
    { 879,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmNH
    { 878,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmNE
    { 877,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmLH
    { 876,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmLE
    { 875,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmL
    { 874,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmHE
    { 873,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmH
    { 872,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 790,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsmE
    { 871,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 786,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJAsm
    { 870,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 786,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRJ
    { 869,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmNLH
    { 868,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmNLE
    { 867,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmNL
    { 866,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmNHE
    { 865,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmNH
    { 864,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmNE
    { 863,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmLH
    { 862,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmLE
    { 861,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmL
    { 860,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmHE
    { 859,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmH
    { 858,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 782,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsmE
    { 857,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 777,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBAsm
    { 856,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 777,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRB
    { 855,	2,	0,	4,	225,	0,	1,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL },  // CGR
    { 854,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmNLH
    { 853,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmNLE
    { 852,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmNL
    { 851,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmNHE
    { 850,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmNH
    { 849,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmNE
    { 848,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmLH
    { 847,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmLE
    { 846,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmL
    { 845,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmHE
    { 844,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmH
    { 843,	2,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsmE
    { 842,	3,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 215,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGITAsm
    { 841,	3,	0,	6,	14,	0,	0,	SystemZOpInfoBase + 215,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CGIT
    { 840,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmNLH
    { 839,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmNLE
    { 838,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmNL
    { 837,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmNHE
    { 836,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmNH
    { 835,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmNE
    { 834,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmLH
    { 833,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmLE
    { 832,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmL
    { 831,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmHE
    { 830,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmH
    { 829,	3,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 774,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsmE
    { 828,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 770,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJAsm
    { 827,	4,	0,	6,	11,	0,	1,	SystemZOpInfoBase + 770,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIJ
    { 826,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmNLH
    { 825,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmNLE
    { 824,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmNL
    { 823,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmNHE
    { 822,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmNH
    { 821,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmNE
    { 820,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmLH
    { 819,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmLE
    { 818,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmL
    { 817,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmHE
    { 816,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmH
    { 815,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 766,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsmE
    { 814,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 761,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBAsm
    { 813,	5,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 761,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIB
    { 812,	3,	0,	6,	224,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL },  // CGHSI
    { 811,	2,	0,	6,	250,	0,	1,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL },  // CGHRL
    { 810,	2,	0,	4,	223,	0,	1,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL },  // CGHI
    { 809,	4,	0,	6,	249,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x384cULL },  // CGH
    { 808,	2,	0,	6,	253,	0,	1,	SystemZOpInfoBase + 759,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3800ULL },  // CGFRL
    { 807,	2,	0,	4,	254,	0,	1,	SystemZOpInfoBase + 757,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL },  // CGFR
    { 806,	2,	0,	6,	223,	0,	1,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL },  // CGFI
    { 805,	4,	0,	6,	252,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x388cULL },  // CGF
    { 804,	3,	1,	4,	430,	0,	1,	SystemZOpInfoBase + 750,	0,	0, 0x0ULL },  // CGER
    { 803,	4,	1,	4,	371,	1,	1,	SystemZOpInfoBase + 753,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CGEBRA
    { 802,	3,	1,	4,	371,	1,	1,	SystemZOpInfoBase + 750,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CGEBR
    { 801,	4,	1,	4,	486,	1,	1,	SystemZOpInfoBase + 746,	1,	0, 0x0ULL },  // CGDTRA
    { 800,	3,	1,	4,	486,	1,	1,	SystemZOpInfoBase + 743,	1,	0, 0x0ULL },  // CGDTR
    { 799,	3,	1,	4,	430,	0,	1,	SystemZOpInfoBase + 743,	0,	0, 0x0ULL },  // CGDR
    { 798,	4,	1,	4,	371,	1,	1,	SystemZOpInfoBase + 746,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CGDBRA
    { 797,	3,	1,	4,	371,	1,	1,	SystemZOpInfoBase + 743,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CGDBR
    { 796,	4,	0,	6,	220,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x390cULL },  // CG
    { 795,	4,	1,	4,	946,	1,	1,	SystemZOpInfoBase + 739,	1,	0, 0x0ULL },  // CFXTR
    { 794,	3,	1,	4,	431,	0,	1,	SystemZOpInfoBase + 736,	0,	0, 0x0ULL },  // CFXR
    { 793,	4,	1,	4,	372,	1,	1,	SystemZOpInfoBase + 739,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CFXBRA
    { 792,	3,	1,	4,	372,	1,	1,	SystemZOpInfoBase + 736,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CFXBR
    { 791,	2,	0,	6,	222,	0,	1,	SystemZOpInfoBase + 734,	0,	0|(1ULL<<MCID::Compare), 0x3800ULL },  // CFI
    { 790,	3,	1,	4,	430,	0,	1,	SystemZOpInfoBase + 727,	0,	0, 0x0ULL },  // CFER
    { 789,	4,	1,	4,	371,	1,	1,	SystemZOpInfoBase + 730,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CFEBRA
    { 788,	3,	1,	4,	371,	1,	1,	SystemZOpInfoBase + 727,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CFEBR
    { 787,	4,	1,	4,	945,	1,	1,	SystemZOpInfoBase + 723,	1,	0, 0x0ULL },  // CFDTR
    { 786,	3,	1,	4,	430,	0,	1,	SystemZOpInfoBase + 720,	0,	0, 0x0ULL },  // CFDR
    { 785,	4,	1,	4,	371,	1,	1,	SystemZOpInfoBase + 723,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CFDBRA
    { 784,	3,	1,	4,	371,	1,	1,	SystemZOpInfoBase + 720,	1,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CFDBR
    { 783,	2,	0,	4,	338,	3,	4,	SystemZOpInfoBase + 260,	28,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CFC
    { 782,	2,	0,	4,	528,	0,	1,	SystemZOpInfoBase + 718,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CEXTR
    { 781,	2,	0,	2,	470,	0,	1,	SystemZOpInfoBase + 704,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CER
    { 780,	4,	1,	4,	942,	1,	0,	SystemZOpInfoBase + 714,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CELGBR
    { 779,	4,	1,	4,	942,	1,	0,	SystemZOpInfoBase + 708,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CELFBR
    { 778,	2,	1,	4,	428,	0,	0,	SystemZOpInfoBase + 712,	0,	0, 0x0ULL },  // CEGR
    { 777,	4,	1,	4,	367,	1,	0,	SystemZOpInfoBase + 714,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CEGBRA
    { 776,	2,	1,	4,	367,	1,	0,	SystemZOpInfoBase + 712,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CEGBR
    { 775,	2,	1,	4,	428,	0,	0,	SystemZOpInfoBase + 706,	0,	0, 0x0ULL },  // CEFR
    { 774,	4,	1,	4,	367,	1,	0,	SystemZOpInfoBase + 708,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CEFBRA
    { 773,	2,	1,	4,	367,	1,	0,	SystemZOpInfoBase + 706,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CEFBR
    { 772,	2,	0,	4,	527,	0,	1,	SystemZOpInfoBase + 676,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CEDTR
    { 771,	2,	0,	4,	408,	1,	1,	SystemZOpInfoBase + 704,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x3c00ULL },  // CEBR
    { 770,	4,	0,	6,	407,	1,	1,	SystemZOpInfoBase + 700,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3c88ULL },  // CEB
    { 769,	4,	0,	4,	469,	0,	1,	SystemZOpInfoBase + 700,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x88ULL },  // CE
    { 768,	5,	1,	6,	494,	0,	0,	SystemZOpInfoBase + 690,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CDZT
    { 767,	2,	1,	4,	490,	0,	0,	SystemZOpInfoBase + 684,	0,	0, 0x0ULL },  // CDUTR
    { 766,	2,	0,	4,	525,	1,	1,	SystemZOpInfoBase + 676,	1,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CDTR
    { 765,	5,	1,	6,	277,	0,	1,	SystemZOpInfoBase + 695,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // CDSY
    { 764,	2,	1,	4,	490,	0,	0,	SystemZOpInfoBase + 684,	0,	0, 0x0ULL },  // CDSTR
    { 763,	5,	1,	6,	278,	0,	1,	SystemZOpInfoBase + 695,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x4ULL },  // CDSG
    { 762,	5,	1,	4,	277,	0,	1,	SystemZOpInfoBase + 695,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CDS
    { 761,	2,	0,	2,	470,	0,	1,	SystemZOpInfoBase + 676,	0,	0|(1ULL<<MCID::Compare), 0x0ULL },  // CDR
    { 760,	5,	1,	6,	498,	0,	0,	SystemZOpInfoBase + 690,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CDPT
    { 759,	4,	1,	4,	483,	1,	0,	SystemZOpInfoBase + 686,	12,	0, 0x0ULL },  // CDLGTR
    { 758,	4,	1,	4,	369,	1,	0,	SystemZOpInfoBase + 686,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CDLGBR
    { 757,	4,	1,	4,	482,	1,	0,	SystemZOpInfoBase + 680,	12,	0, 0x0ULL },  // CDLFTR
    { 756,	4,	1,	4,	369,	1,	0,	SystemZOpInfoBase + 680,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CDLFBR
    { 755,	4,	1,	4,	479,	1,	0,	SystemZOpInfoBase + 686,	12,	0, 0x0ULL },  // CDGTRA
    { 754,	2,	1,	4,	479,	1,	0,	SystemZOpInfoBase + 684,	12,	0, 0x0ULL },  // CDGTR
    { 753,	2,	1,	4,	428,	0,	0,	SystemZOpInfoBase + 684,	0,	0, 0x0ULL },  // CDGR
    { 752,	4,	1,	4,	367,	1,	0,	SystemZOpInfoBase + 686,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CDGBRA
    { 751,	2,	1,	4,	367,	1,	0,	SystemZOpInfoBase + 684,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CDGBR
    { 750,	4,	1,	4,	478,	1,	0,	SystemZOpInfoBase + 680,	12,	0, 0x0ULL },  // CDFTR
    { 749,	2,	1,	4,	428,	0,	0,	SystemZOpInfoBase + 678,	0,	0, 0x0ULL },  // CDFR
    { 748,	4,	1,	4,	367,	1,	0,	SystemZOpInfoBase + 680,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CDFBRA
    { 747,	2,	1,	4,	367,	1,	0,	SystemZOpInfoBase + 678,	12,	0|(1ULL<<MCID::MayRaiseFPException), 0x0ULL },  // CDFBR
    { 746,	2,	0,	4,	408,	1,	1,	SystemZOpInfoBase + 676,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayRaiseFPException), 0x3c00ULL },  // CDBR
    { 745,	4,	0,	6,	407,	1,	1,	SystemZOpInfoBase + 672,	1,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3d08ULL },  // CDB
    { 744,	4,	0,	4,	469,	0,	1,	SystemZOpInfoBase + 672,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x108ULL },  // CD
    { 743,	5,	1,	6,	284,	0,	1,	SystemZOpInfoBase + 667,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CALGF
    { 742,	5,	1,	6,	284,	0,	1,	SystemZOpInfoBase + 667,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CALG
    { 741,	5,	1,	6,	284,	0,	1,	SystemZOpInfoBase + 662,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // CAL
    { 740,	4,	0,	4,	220,	0,	1,	SystemZOpInfoBase + 658,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::MayLoad), 0x3888ULL },  // C
    { 739,	5,	1,	6,	10,	0,	0,	SystemZOpInfoBase + 653,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x4ULL },  // BXLEG
    { 738,	5,	1,	4,	10,	0,	0,	SystemZOpInfoBase + 648,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BXLE
    { 737,	5,	1,	6,	10,	0,	0,	SystemZOpInfoBase + 653,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x4ULL },  // BXHG
    { 736,	5,	1,	4,	10,	0,	0,	SystemZOpInfoBase + 648,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BXH
    { 735,	2,	0,	2,	324,	0,	0,	SystemZOpInfoBase + 600,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // BSM
    { 734,	2,	1,	4,	829,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BSG
    { 733,	2,	1,	4,	829,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BSA
    { 732,	4,	1,	6,	10,	0,	1,	SystemZOpInfoBase + 644,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRXLG
    { 731,	4,	1,	4,	10,	0,	1,	SystemZOpInfoBase + 640,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRXLE
    { 730,	4,	1,	6,	10,	0,	1,	SystemZOpInfoBase + 644,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRXHG
    { 729,	4,	1,	4,	10,	0,	1,	SystemZOpInfoBase + 640,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRXH
    { 728,	3,	1,	6,	8,	0,	0,	SystemZOpInfoBase + 637,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRCTH
    { 727,	3,	1,	4,	7,	0,	1,	SystemZOpInfoBase + 634,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRCTG
    { 726,	3,	1,	4,	7,	0,	1,	SystemZOpInfoBase + 631,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRCT
    { 725,	2,	0,	6,	2,	1,	0,	SystemZOpInfoBase + 629,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRCLAsm
    { 724,	3,	0,	6,	2,	1,	0,	SystemZOpInfoBase + 266,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x40000ULL },  // BRCL
    { 723,	2,	0,	4,	2,	1,	0,	SystemZOpInfoBase + 629,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRCAsm
    { 722,	3,	0,	4,	2,	1,	0,	SystemZOpInfoBase + 266,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x40000ULL },  // BRC
    { 721,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmZ
    { 720,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmP
    { 719,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmO
    { 718,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmNZ
    { 717,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmNP
    { 716,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmNO
    { 715,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmNM
    { 714,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmNLH
    { 713,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmNLE
    { 712,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmNL
    { 711,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmNHE
    { 710,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmNH
    { 709,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmNE
    { 708,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmM
    { 707,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmLH
    { 706,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmLE
    { 705,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmL
    { 704,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmHE
    { 703,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmH
    { 702,	1,	0,	2,	5,	1,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BRAsmE
    { 701,	3,	0,	6,	19,	0,	1,	SystemZOpInfoBase + 626,	0,	0|(1ULL<<MCID::Call), 0x0ULL },  // BRASL
    { 700,	3,	0,	4,	18,	0,	1,	SystemZOpInfoBase + 626,	0,	0|(1ULL<<MCID::Call), 0x0ULL },  // BRAS
    { 699,	1,	0,	2,	5,	0,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // BR
    { 698,	3,	0,	6,	267,	0,	0,	SystemZOpInfoBase + 623,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPRP
    { 697,	4,	0,	6,	266,	0,	0,	SystemZOpInfoBase + 619,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPP
    { 696,	4,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 607,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BICAsm
    { 695,	5,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 602,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0x4000cULL },  // BIC
    { 694,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmZ
    { 693,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmP
    { 692,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmO
    { 691,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmNZ
    { 690,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmNP
    { 689,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmNO
    { 688,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmNM
    { 687,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmNLH
    { 686,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmNLE
    { 685,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmNL
    { 684,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmNHE
    { 683,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmNH
    { 682,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmNE
    { 681,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmM
    { 680,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmLH
    { 679,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmLE
    { 678,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmL
    { 677,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmHE
    { 676,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmH
    { 675,	3,	0,	6,	6,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BIAsmE
    { 674,	3,	0,	6,	6,	0,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator), 0xcULL },  // BI
    { 673,	3,	1,	4,	335,	0,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // BEXTG
    { 672,	3,	1,	4,	335,	0,	0,	SystemZOpInfoBase + 391,	0,	0, 0x0ULL },  // BDEPG
    { 671,	3,	1,	2,	9,	0,	0,	SystemZOpInfoBase + 616,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BCTR
    { 670,	3,	1,	4,	9,	0,	0,	SystemZOpInfoBase + 561,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BCTGR
    { 669,	5,	1,	6,	9,	0,	0,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xcULL },  // BCTG
    { 668,	5,	1,	4,	9,	0,	0,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BCT
    { 667,	2,	0,	2,	4,	1,	0,	SystemZOpInfoBase + 614,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BCRAsm
    { 666,	3,	0,	2,	4,	1,	0,	SystemZOpInfoBase + 611,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x40000ULL },  // BCR
    { 665,	4,	0,	4,	4,	1,	0,	SystemZOpInfoBase + 607,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BCAsm
    { 664,	5,	0,	4,	4,	1,	0,	SystemZOpInfoBase + 602,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x40008ULL },  // BC
    { 663,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmZ
    { 662,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmP
    { 661,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmO
    { 660,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmNZ
    { 659,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmNP
    { 658,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmNO
    { 657,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmNM
    { 656,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmNLH
    { 655,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmNLE
    { 654,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmNL
    { 653,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmNHE
    { 652,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmNH
    { 651,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmNE
    { 650,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmM
    { 649,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmLH
    { 648,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmLE
    { 647,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmL
    { 646,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmHE
    { 645,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmH
    { 644,	3,	0,	4,	5,	1,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Terminator), 0x8ULL },  // BAsmE
    { 643,	2,	0,	2,	325,	0,	1,	SystemZOpInfoBase + 600,	0,	0|(1ULL<<MCID::Call), 0x0ULL },  // BASSM
    { 642,	2,	0,	2,	20,	0,	1,	SystemZOpInfoBase + 600,	0,	0|(1ULL<<MCID::Call), 0x0ULL },  // BASR
    { 641,	4,	0,	4,	20,	0,	1,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::Call), 0x8ULL },  // BAS
    { 640,	2,	0,	2,	321,	1,	1,	SystemZOpInfoBase + 600,	26,	0|(1ULL<<MCID::Call), 0x0ULL },  // BALR
    { 639,	4,	0,	4,	321,	1,	1,	SystemZOpInfoBase + 160,	26,	0|(1ULL<<MCID::Call), 0x8ULL },  // BAL
    { 638,	2,	0,	4,	831,	0,	0,	SystemZOpInfoBase + 598,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BAKR
    { 637,	3,	0,	4,	5,	0,	0,	SystemZOpInfoBase + 595,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x8ULL },  // B
    { 636,	5,	1,	6,	104,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x203c8cULL },  // AY
    { 635,	4,	1,	4,	510,	1,	1,	SystemZOpInfoBase + 591,	1,	0, 0x0ULL },  // AXTRA
    { 634,	3,	1,	4,	510,	1,	1,	SystemZOpInfoBase + 588,	1,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // AXTR
    { 633,	3,	1,	2,	445,	0,	1,	SystemZOpInfoBase + 585,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // AXR
    { 632,	3,	1,	4,	388,	1,	1,	SystemZOpInfoBase + 585,	1,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x3fc00ULL },  // AXBR
    { 631,	3,	1,	2,	444,	0,	1,	SystemZOpInfoBase + 532,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // AWR
    { 630,	5,	1,	4,	443,	0,	1,	SystemZOpInfoBase + 527,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // AW
    { 629,	3,	1,	2,	444,	0,	1,	SystemZOpInfoBase + 547,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // AUR
    { 628,	5,	1,	4,	443,	0,	1,	SystemZOpInfoBase + 542,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // AU
    { 627,	3,	0,	6,	939,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x203c04ULL },  // ASI
    { 626,	3,	1,	4,	121,	0,	1,	SystemZOpInfoBase + 576,	0,	0|(1ULL<<MCID::Commutable), 0x203c00ULL },  // ARK
    { 625,	3,	1,	2,	121,	0,	1,	SystemZOpInfoBase + 573,	0,	0|(1ULL<<MCID::Commutable), 0x203c00ULL },  // AR
    { 624,	6,	0,	6,	308,	0,	1,	SystemZOpInfoBase + 579,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // AP
    { 623,	5,	1,	6,	114,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x103c8cULL },  // ALY
    { 622,	3,	1,	6,	124,	0,	0,	SystemZOpInfoBase + 570,	0,	0, 0x0ULL },  // ALSIHN
    { 621,	3,	1,	6,	124,	0,	1,	SystemZOpInfoBase + 570,	0,	0, 0x103c00ULL },  // ALSIH
    { 620,	3,	0,	6,	939,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x103c04ULL },  // ALSI
    { 619,	3,	1,	4,	120,	0,	1,	SystemZOpInfoBase + 576,	0,	0|(1ULL<<MCID::Commutable), 0x103c00ULL },  // ALRK
    { 618,	3,	1,	2,	120,	0,	1,	SystemZOpInfoBase + 573,	0,	0|(1ULL<<MCID::Commutable), 0x103c00ULL },  // ALR
    { 617,	3,	1,	6,	115,	0,	1,	SystemZOpInfoBase + 250,	0,	0, 0x103c00ULL },  // ALHSIK
    { 616,	3,	1,	4,	123,	0,	1,	SystemZOpInfoBase + 567,	0,	0, 0x103c00ULL },  // ALHHLR
    { 615,	3,	1,	4,	122,	0,	1,	SystemZOpInfoBase + 564,	0,	0, 0x103c00ULL },  // ALHHHR
    { 614,	3,	0,	6,	125,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x103c04ULL },  // ALGSI
    { 613,	3,	1,	4,	119,	0,	1,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::Commutable), 0x103c00ULL },  // ALGRK
    { 612,	3,	1,	4,	119,	0,	1,	SystemZOpInfoBase + 561,	0,	0|(1ULL<<MCID::Commutable), 0x103c00ULL },  // ALGR
    { 611,	3,	1,	6,	117,	0,	1,	SystemZOpInfoBase + 222,	0,	0, 0x103c00ULL },  // ALGHSIK
    { 610,	3,	1,	4,	118,	0,	1,	SystemZOpInfoBase + 558,	0,	0, 0x103c00ULL },  // ALGFR
    { 609,	3,	1,	6,	118,	0,	1,	SystemZOpInfoBase + 308,	0,	0, 0x103c00ULL },  // ALGFI
    { 608,	5,	1,	6,	940,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x103c8cULL },  // ALGF
    { 607,	5,	1,	6,	116,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x103d0cULL },  // ALG
    { 606,	3,	1,	6,	115,	0,	1,	SystemZOpInfoBase + 550,	0,	0, 0x103c00ULL },  // ALFI
    { 605,	3,	1,	4,	127,	1,	1,	SystemZOpInfoBase + 573,	26,	0, 0x103c00ULL },  // ALCR
    { 604,	3,	1,	4,	127,	1,	1,	SystemZOpInfoBase + 561,	26,	0, 0x103c00ULL },  // ALCGR
    { 603,	5,	1,	6,	126,	1,	1,	SystemZOpInfoBase + 553,	26,	0|(1ULL<<MCID::MayLoad), 0x103d0cULL },  // ALCG
    { 602,	5,	1,	6,	126,	1,	1,	SystemZOpInfoBase + 522,	26,	0|(1ULL<<MCID::MayLoad), 0x103c8cULL },  // ALC
    { 601,	5,	1,	4,	114,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x103c88ULL },  // AL
    { 600,	3,	1,	6,	106,	0,	1,	SystemZOpInfoBase + 570,	0,	0, 0x203c00ULL },  // AIH
    { 599,	5,	1,	6,	105,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x203c4cULL },  // AHY
    { 598,	3,	1,	6,	112,	0,	1,	SystemZOpInfoBase + 250,	0,	0, 0x203c00ULL },  // AHIK
    { 597,	3,	1,	4,	112,	0,	1,	SystemZOpInfoBase + 550,	0,	0, 0x203c00ULL },  // AHI
    { 596,	3,	1,	4,	123,	0,	1,	SystemZOpInfoBase + 567,	0,	0, 0x203c00ULL },  // AHHLR
    { 595,	3,	1,	4,	122,	0,	1,	SystemZOpInfoBase + 564,	0,	0, 0x203c00ULL },  // AHHHR
    { 594,	5,	1,	4,	105,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x203c48ULL },  // AH
    { 593,	3,	0,	6,	125,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x203c04ULL },  // AGSI
    { 592,	3,	1,	4,	111,	0,	1,	SystemZOpInfoBase + 391,	0,	0|(1ULL<<MCID::Commutable), 0x203c00ULL },  // AGRK
    { 591,	3,	1,	4,	111,	0,	1,	SystemZOpInfoBase + 561,	0,	0|(1ULL<<MCID::Commutable), 0x203c00ULL },  // AGR
    { 590,	3,	1,	6,	110,	0,	1,	SystemZOpInfoBase + 222,	0,	0, 0x203c00ULL },  // AGHIK
    { 589,	3,	1,	4,	110,	0,	1,	SystemZOpInfoBase + 308,	0,	0, 0x203c00ULL },  // AGHI
    { 588,	5,	1,	6,	128,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x203c4cULL },  // AGH
    { 587,	3,	1,	4,	129,	0,	1,	SystemZOpInfoBase + 558,	0,	0, 0x203c00ULL },  // AGFR
    { 586,	3,	1,	6,	109,	0,	1,	SystemZOpInfoBase + 308,	0,	0, 0x203c00ULL },  // AGFI
    { 585,	5,	1,	6,	921,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x203c8cULL },  // AGF
    { 584,	5,	1,	6,	108,	0,	1,	SystemZOpInfoBase + 553,	0,	0|(1ULL<<MCID::MayLoad), 0x203d0cULL },  // AG
    { 583,	3,	1,	6,	107,	0,	1,	SystemZOpInfoBase + 550,	0,	0, 0x203c00ULL },  // AFI
    { 582,	3,	1,	2,	444,	0,	1,	SystemZOpInfoBase + 547,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // AER
    { 581,	3,	1,	4,	387,	1,	1,	SystemZOpInfoBase + 547,	1,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x3fc00ULL },  // AEBR
    { 580,	5,	1,	6,	386,	1,	1,	SystemZOpInfoBase + 542,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3fc88ULL },  // AEB
    { 579,	5,	1,	4,	443,	0,	1,	SystemZOpInfoBase + 542,	0,	0|(1ULL<<MCID::MayLoad), 0x88ULL },  // AE
    { 578,	4,	1,	4,	509,	1,	1,	SystemZOpInfoBase + 538,	1,	0, 0x0ULL },  // ADTRA
    { 577,	3,	1,	4,	509,	1,	1,	SystemZOpInfoBase + 535,	1,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // ADTR
    { 576,	3,	1,	2,	444,	0,	1,	SystemZOpInfoBase + 532,	0,	0|(1ULL<<MCID::Commutable), 0x0ULL },  // ADR
    { 575,	3,	1,	4,	387,	1,	1,	SystemZOpInfoBase + 532,	1,	0|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable), 0x3fc00ULL },  // ADBR
    { 574,	5,	1,	6,	386,	1,	1,	SystemZOpInfoBase + 527,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3fd08ULL },  // ADB
    { 573,	5,	1,	4,	443,	0,	1,	SystemZOpInfoBase + 527,	0,	0|(1ULL<<MCID::MayLoad), 0x108ULL },  // AD
    { 572,	5,	1,	4,	104,	0,	1,	SystemZOpInfoBase + 522,	0,	0|(1ULL<<MCID::MayLoad), 0x203c88ULL },  // A
    { 571,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 169,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ZEXT128
    { 570,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 182,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x23088ULL },  // X_MemFoldPseudo
    { 569,	0,	0,	0,	0,	2,	2,	SystemZOpInfoBase + 1,	22,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XPLINK_STACKALLOC
    { 568,	3,	1,	6,	174,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // XILF64
    { 567,	3,	1,	6,	173,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // XIHF64
    { 566,	3,	1,	0,	171,	0,	1,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo), 0x23000ULL },  // XIFMux
    { 565,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 174,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x2310cULL },  // XG_MemFoldPseudo
    { 564,	5,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 237,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // XCReg
    { 563,	5,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 232,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // XCImm
    { 562,	4,	0,	6,	550,	0,	0,	SystemZOpInfoBase + 509,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x2ULL },  // VST64
    { 561,	4,	0,	6,	550,	0,	0,	SystemZOpInfoBase + 505,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x2ULL },  // VST32
    { 560,	4,	0,	6,	550,	0,	0,	SystemZOpInfoBase + 501,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x2ULL },  // VST16
    { 559,	3,	1,	6,	534,	0,	0,	SystemZOpInfoBase + 519,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // VLVGP32
    { 558,	2,	1,	6,	531,	0,	0,	SystemZOpInfoBase + 517,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MoveReg), 0x0ULL },  // VLR64
    { 557,	2,	1,	6,	531,	0,	0,	SystemZOpInfoBase + 515,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MoveReg), 0x0ULL },  // VLR32
    { 556,	2,	1,	6,	531,	0,	0,	SystemZOpInfoBase + 513,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MoveReg), 0x0ULL },  // VLR16
    { 555,	4,	1,	6,	543,	0,	0,	SystemZOpInfoBase + 509,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x1ULL },  // VL64
    { 554,	4,	1,	6,	543,	0,	0,	SystemZOpInfoBase + 505,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x1ULL },  // VL32
    { 553,	4,	1,	6,	543,	0,	0,	SystemZOpInfoBase + 501,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x1ULL },  // VL16
    { 552,	2,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // UCmp128Hi
    { 551,	0,	0,	4,	13,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // Trap
    { 550,	2,	0,	0,	259,	0,	1,	SystemZOpInfoBase + 209,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x0ULL },  // TMLMux
    { 549,	2,	0,	4,	263,	0,	1,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x0ULL },  // TMLL64
    { 548,	2,	0,	4,	262,	0,	1,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x0ULL },  // TMLH64
    { 547,	2,	0,	0,	259,	0,	1,	SystemZOpInfoBase + 209,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x0ULL },  // TMHMux
    { 546,	2,	0,	4,	261,	0,	1,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x0ULL },  // TMHL64
    { 545,	2,	0,	4,	260,	0,	1,	SystemZOpInfoBase + 499,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x0ULL },  // TMHH64
    { 544,	1,	0,	6,	21,	0,	2,	SystemZOpInfoBase + 0,	20,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL },  // TLS_LDCALL
    { 543,	1,	0,	6,	21,	0,	2,	SystemZOpInfoBase + 0,	20,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL },  // TLS_GDCALL
    { 542,	3,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 496,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TBEGIN_nofloat
    { 541,	0,	0,	2,	269,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // Serialize
    { 540,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 491,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SelectVR64
    { 539,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 486,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SelectVR32
    { 538,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 456,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SelectVR128
    { 537,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 481,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SelectF64
    { 536,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 476,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SelectF32
    { 535,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 471,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SelectF128
    { 534,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 466,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // Select64
    { 533,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 461,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // Select32
    { 532,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 456,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // Select128
    { 531,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 182,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x223c88ULL },  // S_MemFoldPseudo
    { 530,	4,	0,	0,	360,	0,	0,	SystemZOpInfoBase + 356,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x1eULL },  // STX
    { 529,	5,	0,	0,	54,	1,	0,	SystemZOpInfoBase + 451,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x80080ULL },  // STOCMux
    { 528,	4,	0,	0,	48,	0,	0,	SystemZOpInfoBase + 242,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x8eULL },  // STMux
    { 527,	4,	0,	0,	77,	0,	0,	SystemZOpInfoBase + 242,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x2cULL },  // STHMux
    { 526,	4,	0,	0,	76,	0,	0,	SystemZOpInfoBase + 242,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x2cULL },  // STCMux
    { 525,	4,	0,	0,	47,	0,	0,	SystemZOpInfoBase + 311,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x1eULL },  // ST128
    { 524,	4,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 253,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SRSTLoop
    { 523,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 182,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x101c88ULL },  // SL_MemFoldPseudo
    { 522,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 174,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x101d0cULL },  // SLG_MemFoldPseudo
    { 521,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 174,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x223d0cULL },  // SG_MemFoldPseudo
    { 520,	5,	1,	0,	55,	1,	0,	SystemZOpInfoBase + 446,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x80000ULL },  // SELRMux
    { 519,	5,	1,	0,	0,	1,	1,	SystemZOpInfoBase + 164,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3fc88ULL },  // SEB_MemFoldPseudo
    { 518,	5,	1,	0,	0,	1,	1,	SystemZOpInfoBase + 155,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3fd08ULL },  // SDB_MemFoldPseudo
    { 517,	2,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 444,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SCmp128Hi
    { 516,	0,	0,	4,	22,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // Return_XPLINK
    { 515,	0,	0,	2,	22,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // Return
    { 514,	6,	1,	0,	218,	0,	0,	SystemZOpInfoBase + 438,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // RISBMux
    { 513,	5,	1,	6,	216,	0,	0,	SystemZOpInfoBase + 433,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // RISBLLOpt
    { 512,	6,	1,	6,	216,	0,	0,	SystemZOpInfoBase + 427,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // RISBLL
    { 511,	5,	1,	6,	216,	0,	0,	SystemZOpInfoBase + 422,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // RISBLHOpt
    { 510,	6,	1,	6,	216,	0,	0,	SystemZOpInfoBase + 416,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // RISBLH
    { 509,	5,	1,	6,	215,	0,	0,	SystemZOpInfoBase + 411,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // RISBHLOpt
    { 508,	6,	1,	6,	215,	0,	0,	SystemZOpInfoBase + 405,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // RISBHL
    { 507,	5,	1,	6,	215,	0,	0,	SystemZOpInfoBase + 400,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // RISBHHOpt
    { 506,	6,	1,	6,	215,	0,	0,	SystemZOpInfoBase + 394,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // RISBHH
    { 505,	1,	0,	0,	0,	1,	3,	SystemZOpInfoBase + 1,	16,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PROBED_STACKALLOC
    { 504,	3,	1,	0,	0,	1,	2,	SystemZOpInfoBase + 391,	13,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PROBED_ALLOCA
    { 503,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 388,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PAIR128
    { 502,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 182,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x23088ULL },  // O_MemFoldPseudo
    { 501,	3,	1,	0,	160,	0,	1,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // OILMux
    { 500,	3,	1,	4,	166,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // OILL64
    { 499,	3,	1,	4,	165,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // OILH64
    { 498,	3,	1,	6,	164,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // OILF64
    { 497,	3,	1,	0,	160,	0,	1,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // OIHMux
    { 496,	3,	1,	4,	163,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // OIHL64
    { 495,	3,	1,	4,	162,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // OIHH64
    { 494,	3,	1,	6,	161,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // OIHF64
    { 493,	3,	1,	0,	160,	0,	1,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo), 0x23000ULL },  // OIFMux
    { 492,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 174,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x2310cULL },  // OG_MemFoldPseudo
    { 491,	5,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 237,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // OCReg
    { 490,	5,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 232,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // OCImm
    { 489,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 182,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x23088ULL },  // N_MemFoldPseudo
    { 488,	3,	1,	0,	147,	0,	1,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NILMux
    { 487,	3,	1,	4,	154,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NILL64
    { 486,	3,	1,	4,	153,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NILH64
    { 485,	3,	1,	6,	152,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NILF64
    { 484,	3,	1,	0,	147,	0,	1,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NIHMux
    { 483,	3,	1,	4,	151,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NIHL64
    { 482,	3,	1,	4,	150,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NIHH64
    { 481,	3,	1,	6,	149,	0,	1,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x0ULL },  // NIHF64
    { 480,	3,	1,	0,	147,	0,	1,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ConvertibleTo3Addr), 0x23000ULL },  // NIFMux
    { 479,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 174,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x2310cULL },  // NG_MemFoldPseudo
    { 478,	5,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 237,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // NCReg
    { 477,	5,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 232,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // NCImm
    { 476,	4,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 384,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MemsetRegReg
    { 475,	4,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 380,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MemsetRegImm
    { 474,	4,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 376,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MemsetImmReg
    { 473,	4,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 372,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MemsetImmImm
    { 472,	4,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 253,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MVSTLoop
    { 471,	5,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 237,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MVCReg
    { 470,	5,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 232,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MVCImm
    { 469,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 174,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x10cULL },  // MSGC_MemFoldPseudo
    { 468,	6,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 366,	12,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // MSEB_MemFoldPseudo
    { 467,	6,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 360,	12,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // MSDB_MemFoldPseudo
    { 466,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 182,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x8cULL },  // MSC_MemFoldPseudo
    { 465,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MOV_STACKGUARD_DAG
    { 464,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 257,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MOV_STACKGUARD
    { 463,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 164,	12,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // MEEB_MemFoldPseudo
    { 462,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 155,	12,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // MDB_MemFoldPseudo
    { 461,	6,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 366,	12,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // MAEB_MemFoldPseudo
    { 460,	6,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 360,	12,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // MADB_MemFoldPseudo
    { 459,	4,	1,	0,	358,	0,	0,	SystemZOpInfoBase + 356,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x1dULL },  // LX
    { 458,	1,	0,	0,	0,	1,	1,	SystemZOpInfoBase + 355,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // LTXBRCompare_Pseudo
    { 457,	1,	0,	0,	0,	1,	1,	SystemZOpInfoBase + 354,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // LTEBRCompare_Pseudo
    { 456,	1,	0,	0,	0,	1,	1,	SystemZOpInfoBase + 353,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // LTDBRCompare_Pseudo
    { 455,	5,	1,	0,	50,	1,	0,	SystemZOpInfoBase + 348,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x80000ULL },  // LOCRMux
    { 454,	6,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 342,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x80ULL },  // LOCMux_MemFoldPseudo
    { 453,	6,	1,	0,	53,	1,	0,	SystemZOpInfoBase + 336,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x80080ULL },  // LOCMux
    { 452,	5,	1,	0,	52,	1,	0,	SystemZOpInfoBase + 331,	0,	0|(1ULL<<MCID::Pseudo), 0x80000ULL },  // LOCHIMux
    { 451,	6,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 325,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x100ULL },  // LOCG_MemFoldPseudo
    { 450,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LOAD_TLS_BLOCK_ADDR
    { 449,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LOAD_GLOBAL_STACKGUARD_ADDR
    { 448,	4,	1,	0,	33,	0,	0,	SystemZOpInfoBase + 242,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x8dULL },  // LMux
    { 447,	2,	1,	0,	67,	0,	0,	SystemZOpInfoBase + 323,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LLHRMux
    { 446,	4,	1,	0,	70,	0,	0,	SystemZOpInfoBase + 242,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x4cULL },  // LLHMux
    { 445,	2,	1,	0,	66,	0,	0,	SystemZOpInfoBase + 323,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LLCRMux
    { 444,	4,	1,	0,	69,	0,	0,	SystemZOpInfoBase + 242,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x2cULL },  // LLCMux
    { 443,	4,	1,	0,	63,	0,	0,	SystemZOpInfoBase + 242,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x4cULL },  // LHMux
    { 442,	2,	1,	0,	40,	0,	0,	SystemZOpInfoBase + 209,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // LHIMux
    { 441,	2,	1,	6,	742,	0,	0,	SystemZOpInfoBase + 321,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LFER_16
    { 440,	2,	1,	6,	742,	0,	0,	SystemZOpInfoBase + 319,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LFER
    { 439,	2,	1,	6,	741,	0,	0,	SystemZOpInfoBase + 317,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LEFR_16
    { 438,	2,	1,	6,	741,	0,	0,	SystemZOpInfoBase + 315,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LEFR
    { 437,	4,	1,	0,	61,	0,	0,	SystemZOpInfoBase + 242,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x2cULL },  // LBMux
    { 436,	4,	1,	0,	36,	0,	0,	SystemZOpInfoBase + 311,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x1dULL },  // L128
    { 435,	3,	1,	0,	97,	0,	0,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // IILMux
    { 434,	3,	1,	4,	103,	0,	0,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // IILL64
    { 433,	3,	1,	4,	102,	0,	0,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // IILH64
    { 432,	3,	1,	6,	101,	0,	0,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // IILF64
    { 431,	3,	1,	0,	97,	0,	0,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // IIHMux
    { 430,	3,	1,	4,	100,	0,	0,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // IIHL64
    { 429,	3,	1,	4,	99,	0,	0,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // IIHH64
    { 428,	3,	1,	6,	98,	0,	0,	SystemZOpInfoBase + 308,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // IIHF64
    { 427,	2,	1,	0,	97,	0,	0,	SystemZOpInfoBase + 209,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // IIFMux
    { 426,	1,	1,	6,	87,	0,	0,	SystemZOpInfoBase + 307,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // GOT
    { 425,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // FENCE
    { 424,	6,	0,	6,	0,	0,	0,	SystemZOpInfoBase + 301,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EXRL_Pseudo
    { 423,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // EH_SjLj_Setup
    { 422,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 299,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EH_SjLj_SetJmp
    { 421,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EH_SjLj_LongJmp
    { 420,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 164,	12,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x88ULL },  // DEB_MemFoldPseudo
    { 419,	5,	1,	0,	0,	1,	0,	SystemZOpInfoBase + 155,	12,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x108ULL },  // DDB_MemFoldPseudo
    { 418,	2,	0,	4,	13,	1,	0,	SystemZOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CondTrap
    { 417,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 293,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStoreF64Inv
    { 416,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 293,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStoreF64
    { 415,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 287,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStoreF32Inv
    { 414,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 287,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStoreF32
    { 413,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 275,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore8MuxInv
    { 412,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 275,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore8Mux
    { 411,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 269,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore8Inv
    { 410,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 269,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore8
    { 409,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 281,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore64Inv
    { 408,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 281,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore64
    { 407,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 275,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore32MuxInv
    { 406,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 275,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore32Mux
    { 405,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 269,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore32Inv
    { 404,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 269,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore32
    { 403,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 275,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore16MuxInv
    { 402,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 275,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore16Mux
    { 401,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 269,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore16Inv
    { 400,	6,	0,	0,	0,	1,	0,	SystemZOpInfoBase + 269,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CondStore16
    { 399,	2,	0,	4,	23,	1,	0,	SystemZOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator), 0x40000ULL },  // CondReturn_XPLINK
    { 398,	2,	0,	2,	23,	1,	0,	SystemZOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator), 0x40000ULL },  // CondReturn
    { 397,	1,	0,	6,	3,	0,	0,	SystemZOpInfoBase + 265,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // CallJG
    { 396,	3,	0,	6,	2,	0,	0,	SystemZOpInfoBase + 266,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x40000ULL },  // CallBRCL
    { 395,	1,	0,	8,	19,	1,	2,	SystemZOpInfoBase + 265,	9,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL },  // CallBRASL_XPLINK64
    { 394,	1,	0,	6,	19,	1,	2,	SystemZOpInfoBase + 265,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL },  // CallBRASL
    { 393,	1,	0,	2,	5,	0,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // CallBR
    { 392,	3,	0,	2,	4,	0,	0,	SystemZOpInfoBase + 262,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x40000ULL },  // CallBCR
    { 391,	1,	0,	4,	20,	1,	2,	SystemZOpInfoBase + 28,	9,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL },  // CallBASR_XPLINK64
    { 390,	1,	0,	4,	20,	1,	2,	SystemZOpInfoBase + 28,	6,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL },  // CallBASR_STACKEXT
    { 389,	1,	0,	2,	20,	1,	2,	SystemZOpInfoBase + 28,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL },  // CallBASR
    { 388,	3,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 250,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBReturn
    { 387,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 246,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // CRBCall
    { 386,	4,	0,	0,	220,	0,	1,	SystemZOpInfoBase + 242,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x388cULL },  // CMux
    { 385,	2,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 260,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMP_STACKGUARD_DAG
    { 384,	3,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 257,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMP_STACKGUARD
    { 383,	4,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 253,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CLSTLoop
    { 382,	3,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 250,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBReturn
    { 381,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 246,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLRBCall
    { 380,	4,	0,	0,	229,	0,	1,	SystemZOpInfoBase + 242,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x10388cULL },  // CLMux
    { 379,	3,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 229,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBReturn
    { 378,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 225,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLIBCall
    { 377,	3,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 222,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBReturn
    { 376,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 218,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGRBCall
    { 375,	3,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBReturn
    { 374,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 211,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // CLGIBCall
    { 373,	2,	0,	0,	231,	0,	1,	SystemZOpInfoBase + 209,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x103800ULL },  // CLFIMux
    { 372,	5,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 237,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CLCReg
    { 371,	5,	0,	0,	0,	0,	1,	SystemZOpInfoBase + 232,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // CLCImm
    { 370,	3,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 229,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBReturn
    { 369,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 225,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // CIBCall
    { 368,	2,	0,	0,	222,	0,	1,	SystemZOpInfoBase + 209,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x3800ULL },  // CHIMux
    { 367,	3,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 222,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBReturn
    { 366,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 218,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGRBCall
    { 365,	3,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBReturn
    { 364,	4,	0,	6,	12,	0,	0,	SystemZOpInfoBase + 211,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // CGIBCall
    { 363,	2,	0,	0,	222,	0,	1,	SystemZOpInfoBase + 209,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Compare), 0x3800ULL },  // CFIMux
    { 362,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 182,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x203c88ULL },  // A_MemFoldPseudo
    { 361,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_SWAPW
    { 360,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_XR
    { 359,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 195,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_XILF
    { 358,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_UMIN
    { 357,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_UMAX
    { 356,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_SR
    { 355,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_OR
    { 354,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 195,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_OILH
    { 353,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_NRi
    { 352,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_NR
    { 351,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 195,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_NILHi
    { 350,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 195,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_NILH
    { 349,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_MIN
    { 348,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_MAX
    { 347,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 202,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_AR
    { 346,	7,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 195,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x4ULL },  // ATOMIC_LOADW_AFI
    { 345,	8,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 187,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // ATOMIC_CMP_SWAPW
    { 344,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 182,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x103c88ULL },  // AL_MemFoldPseudo
    { 343,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 174,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x103d0cULL },  // ALG_MemFoldPseudo
    { 342,	3,	1,	0,	113,	0,	1,	SystemZOpInfoBase + 179,	0,	0|(1ULL<<MCID::Pseudo), 0x203c00ULL },  // AHIMuxK
    { 341,	3,	1,	0,	113,	0,	1,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo), 0x203c00ULL },  // AHIMux
    { 340,	5,	1,	0,	0,	0,	1,	SystemZOpInfoBase + 174,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x203d0cULL },  // AG_MemFoldPseudo
    { 339,	3,	1,	0,	107,	0,	1,	SystemZOpInfoBase + 171,	0,	0|(1ULL<<MCID::Pseudo), 0x203c00ULL },  // AFIMux
    { 338,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 169,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // AEXT128
    { 337,	5,	1,	0,	0,	1,	1,	SystemZOpInfoBase + 164,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3fc88ULL },  // AEB_MemFoldPseudo
    { 336,	4,	1,	0,	1,	0,	0,	SystemZOpInfoBase + 160,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // ADJDYNALLOC
    { 335,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADJCALLSTACKUP
    { 334,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADJCALLSTACKDOWN
    { 333,	5,	1,	0,	0,	1,	1,	SystemZOpInfoBase + 155,	1,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayRaiseFPException), 0x3fd08ULL },  // ADB_MemFoldPseudo
    { 332,	4,	1,	12,	0,	0,	1,	SystemZOpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // ADA_ENTRY_VALUE
    { 331,	4,	1,	12,	0,	0,	1,	SystemZOpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // ADA_ENTRY
    { 330,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	SystemZOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_21102
    { 41,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_21101
    { 40,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_21100
    { 31,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	29,	0,	0,	SystemZOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	32,	0,	0,	SystemZOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	29,	0,	0,	SystemZOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	31,	0,	0,	SystemZOpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	30,	0,	0,	SystemZOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	SystemZOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	SystemZOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // PHI
  }, {
    /* 0 */
    /* 0 */ SystemZ::CC,
    /* 1 */ SystemZ::FPC, SystemZ::CC,
    /* 3 */ SystemZ::FPC, SystemZ::R14D, SystemZ::CC,
    /* 6 */ SystemZ::FPC, SystemZ::R3D, SystemZ::CC,
    /* 9 */ SystemZ::FPC, SystemZ::R7D, SystemZ::CC,
    /* 12 */ SystemZ::FPC,
    /* 13 */ SystemZ::R15D, SystemZ::R15D, SystemZ::CC,
    /* 16 */ SystemZ::R15D, SystemZ::R1D, SystemZ::R15D, SystemZ::CC,
    /* 20 */ SystemZ::R14D, SystemZ::CC,
    /* 22 */ SystemZ::R3D, SystemZ::R4D, SystemZ::R3D, SystemZ::CC,
    /* 26 */ SystemZ::CC, SystemZ::CC,
    /* 28 */ SystemZ::R1D, SystemZ::R2D, SystemZ::R3D, SystemZ::CC, SystemZ::R1D, SystemZ::R2D, SystemZ::R3D,
    /* 35 */ SystemZ::R0L, SystemZ::CC,
    /* 37 */ SystemZ::R0L, SystemZ::R1D, SystemZ::CC, SystemZ::R1D,
    /* 41 */ SystemZ::R1L, SystemZ::CC,
    /* 43 */ SystemZ::R0L, SystemZ::R1D, SystemZ::CC,
    /* 46 */ SystemZ::R0L, SystemZ::R1L, SystemZ::CC,
    /* 49 */ SystemZ::R0D, SystemZ::R1D,
    /* 51 */ SystemZ::R2L, SystemZ::R2L,
    /* 53 */ SystemZ::R0L, SystemZ::R1L,
    /* 55 */ SystemZ::R0L,
    /* 56 */ SystemZ::R0D, SystemZ::R1D, SystemZ::R0D, SystemZ::CC,
    /* 60 */ SystemZ::R0L, SystemZ::R1D,
    /* 62 */ SystemZ::R0D, SystemZ::CC,
    /* 64 */ SystemZ::FPC, SystemZ::R0L, SystemZ::F4Q, SystemZ::CC, SystemZ::R1L, SystemZ::F0Q,
    /* 70 */ SystemZ::R0D, SystemZ::R0D, SystemZ::CC,
    /* 73 */ SystemZ::R1L,
    /* 74 */ SystemZ::R1L, SystemZ::R2D,
    /* 76 */ SystemZ::R0D, SystemZ::R1D, SystemZ::R2D, SystemZ::R3D, SystemZ::CC,
    /* 81 */ SystemZ::FPC, SystemZ::FPC,
    /* 83 */ SystemZ::R0L, SystemZ::R1L, SystemZ::R0L, SystemZ::CC,
    /* 87 */ SystemZ::CC, SystemZ::R0L, SystemZ::R1D,
    /* 90 */ SystemZ::R1D, SystemZ::CC,
    /* 92 */ SystemZ::R0D, SystemZ::R1D, SystemZ::R2D, SystemZ::R3D, SystemZ::R4D, SystemZ::R5D, SystemZ::CC, SystemZ::R0D, SystemZ::R1D, SystemZ::R2D, SystemZ::R3D, SystemZ::R5D,
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
    /* 28 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
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
    /* 151 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 155 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 160 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 164 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 169 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 171 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 174 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 179 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 182 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 187 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 195 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 202 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 209 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 211 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 215 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 218 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 222 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 225 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 229 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 232 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 237 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 242 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 246 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 250 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 253 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 257 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 260 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 262 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 265 */ { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 266 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 269 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 275 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 281 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 287 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 293 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 299 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 301 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 307 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 308 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 311 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 315 */ { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 317 */ { SystemZ::VR16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 319 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 321 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 323 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 325 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 331 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 336 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 342 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 348 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 353 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 354 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 355 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 356 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 360 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 366 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 372 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 376 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 380 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 384 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 388 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 391 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 394 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 400 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 405 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 411 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 416 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 422 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 427 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 433 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 438 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 444 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 446 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 451 */ { SystemZ::GRX32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 456 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 461 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 466 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 471 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 476 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 481 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 486 */ { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 491 */ { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 496 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 499 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 501 */ { SystemZ::VR16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 505 */ { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 509 */ { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 513 */ { SystemZ::VR16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 515 */ { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 517 */ { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 519 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 522 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 527 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 532 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 535 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 538 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 542 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 547 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 550 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 553 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 558 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 561 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 564 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 567 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 570 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 573 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 576 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 579 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 585 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 588 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 591 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 595 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 598 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 600 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 602 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 607 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 611 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 614 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 616 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 619 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 623 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 626 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 629 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 631 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 634 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 637 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 640 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 644 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 648 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 653 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 658 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 662 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 667 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 672 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 676 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 678 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 680 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 684 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 686 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 690 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 695 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 700 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 704 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 706 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 708 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 712 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 714 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 718 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 720 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 723 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 727 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 730 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 734 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 736 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 739 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 743 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 746 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 750 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 753 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 757 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 759 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 761 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 766 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 770 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 774 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 777 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 782 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 786 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 790 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 793 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 796 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 800 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 804 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 806 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 808 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 810 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 815 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 819 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 821 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 825 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 828 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) },
    /* 832 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 837 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) },
    /* 841 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 847 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 851 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 854 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 858 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 860 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 865 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 869 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 873 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 876 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) },
    /* 880 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 884 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 887 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 890 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 893 */ { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 896 */ { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 899 */ { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 902 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 905 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 908 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 911 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 916 */ { SystemZ::AR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::AR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 918 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 922 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 925 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 928 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 931 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 936 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 939 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 944 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 946 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 948 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 950 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 954 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 956 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 960 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 962 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 967 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 972 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 977 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 982 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 985 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::AR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 987 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 991 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 993 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 995 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 996 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 998 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1000 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1004 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 1006 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1009 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1013 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1016 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1020 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1023 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1027 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1032 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1037 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1041 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1044 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1047 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1051 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1054 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1057 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 1061 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 1064 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1070 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1073 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1078 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1084 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1089 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1094 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1100 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1103 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1107 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1114 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1119 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1125 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1131 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1138 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::AnyRegBitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1144 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1150 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1156 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1161 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 1164 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1169 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(2) },
    /* 1175 */ { SystemZ::AR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::AR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1179 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1183 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1188 */ { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1190 */ { SystemZ::CR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::CR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1194 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1196 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1199 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1201 */ { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1205 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1207 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1211 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1213 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1217 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1223 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1227 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1233 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1238 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1242 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1248 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1253 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1257 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1261 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1264 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1270 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1275 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1279 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1284 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1288 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1293 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1297 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1302 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1306 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1311 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1315 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1319 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1324 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1329 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1331 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1334 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1336 */ { SystemZ::FP16BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1337 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1343 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1347 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1353 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1357 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1360 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1361 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1367 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1372 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1375 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1380 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1383 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 1386 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1391 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1397 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 1399 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1404 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1410 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1416 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1421 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1427 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1432 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1436 */ { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1441 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1446 */ { SystemZ::AR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1448 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1453 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1457 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1461 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1465 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1469 */ { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::FP128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1474 */ { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1476 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1482 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1485 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1490 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1495 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1499 */ { SystemZ::GRH32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1502 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1507 */ { SystemZ::FP32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SystemZ::FP64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1510 */ { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1513 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) },
    /* 1517 */ { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1522 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1526 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) },
    /* 1529 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1533 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1536 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1541 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1545 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1550 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1554 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1557 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1560 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1563 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1567 */ { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1571 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1575 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1579 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1585 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1590 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1595 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1599 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1605 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1611 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1613 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1619 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1623 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1626 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1630 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1635 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1641 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1645 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1650 */ { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1654 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1658 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1662 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1667 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1671 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1677 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1682 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR32BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 1687 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::GR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1690 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1691 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::ADDR64BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1696 */ { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1700 */ { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1704 */ { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1707 */ { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1710 */ { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1712 */ { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1714 */ { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1718 */ { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR128BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1722 */ { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1726 */ { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 1730 */ { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1734 */ { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1738 */ { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR64BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 1741 */ { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SystemZ::VR32BitRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
  }
};




static inline void InitSystemZMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(SystemZDescs.Insts, nullptr, nullptr, nullptr, nullptr, 3314, nullptr, 0);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct SystemZGenInstrInfo : public TargetInstrInfo {
  explicit SystemZGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~SystemZGenInstrInfo() override = default;
};

} // namespace llvm_ks

namespace llvm_ks::SystemZ {

constexpr unsigned SUBOP_brtarget16tls_func = 0;
constexpr unsigned SUBOP_brtarget16tls_sym = 1;
constexpr unsigned SUBOP_brtarget32tls_func = 0;
constexpr unsigned SUBOP_brtarget32tls_sym = 1;

} // namespace llvm_ks::SystemZ

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

extern const SystemZInstrTable SystemZDescs;
SystemZGenInstrInfo::SystemZGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(SystemZDescs.Insts, nullptr, nullptr, nullptr, nullptr, 3314);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace SystemZ_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace SystemZ_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::SystemZ_MC {


} // namespace llvm_ks::SystemZ_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::SystemZ_MC {

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_FeatureSoftFloatBit = 37,
  Feature_FeatureBackChainBit = 1,
  Feature_FeatureUnalignedSymbolsBit = 40,
  Feature_FeatureDistinctOpsBit = 6,
  Feature_FeatureFastSerializationBit = 11,
  Feature_FeatureFPExtensionBit = 10,
  Feature_FeatureHighWordBit = 13,
  Feature_FeatureInterlockedAccess1Bit = 15,
  Feature_FeatureLoadStoreOnCondBit = 18,
  Feature_FeaturePopulationCountBit = 32,
  Feature_FeatureMessageSecurityAssist3Bit = 20,
  Feature_FeatureMessageSecurityAssist4Bit = 21,
  Feature_FeatureResetReferenceBitsMultipleBit = 36,
  Feature_FeatureExecutionHintBit = 9,
  Feature_FeatureLoadAndTrapBit = 16,
  Feature_FeatureMiscellaneousExtensionsBit = 27,
  Feature_FeatureProcessorAssistBit = 34,
  Feature_FeatureTransactionalExecutionBit = 39,
  Feature_FeatureDFPZonedConversionBit = 4,
  Feature_FeatureEnhancedDAT2Bit = 7,
  Feature_FeatureLoadAndZeroRightmostByteBit = 17,
  Feature_FeatureLoadStoreOnCond2Bit = 19,
  Feature_FeatureMessageSecurityAssist5Bit = 22,
  Feature_FeatureDFPPackedConversionBit = 3,
  Feature_FeatureVectorBit = 41,
  Feature_FeatureMiscellaneousExtensions2Bit = 28,
  Feature_FeatureGuardedStorageBit = 12,
  Feature_FeatureMessageSecurityAssist7Bit = 23,
  Feature_FeatureMessageSecurityAssist8Bit = 24,
  Feature_FeatureVectorEnhancements1Bit = 42,
  Feature_FeatureVectorPackedDecimalBit = 45,
  Feature_FeatureInsertReferenceBitsMultipleBit = 14,
  Feature_FeatureTestPendingExternalInterruptionBit = 38,
  Feature_FeatureMiscellaneousExtensions3Bit = 29,
  Feature_FeatureMessageSecurityAssist9Bit = 25,
  Feature_FeatureVectorEnhancements2Bit = 43,
  Feature_FeatureVectorPackedDecimalEnhancementBit = 46,
  Feature_FeatureEnhancedSortBit = 8,
  Feature_FeatureDeflateConversionBit = 5,
  Feature_FeatureVectorPackedDecimalEnhancement2Bit = 47,
  Feature_FeatureNNPAssistBit = 31,
  Feature_FeatureBEAREnhancementBit = 0,
  Feature_FeatureResetDATProtectionBit = 35,
  Feature_FeatureProcessorActivityInstrumentationBit = 33,
  Feature_FeatureMiscellaneousExtensions4Bit = 30,
  Feature_FeatureVectorEnhancements3Bit = 44,
  Feature_FeatureVectorPackedDecimalEnhancement3Bit = 48,
  Feature_FeatureMessageSecurityAssist12Bit = 26,
  Feature_FeatureConcurrentFunctionsBit = 2,
};

inline FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) {
  FeatureBitset Features;
  if (FB[SystemZ::FeatureSoftFloat])
    Features.set(Feature_FeatureSoftFloatBit);
  if (FB[SystemZ::FeatureBackChain])
    Features.set(Feature_FeatureBackChainBit);
  if (FB[SystemZ::FeatureUnalignedSymbols])
    Features.set(Feature_FeatureUnalignedSymbolsBit);
  if (FB[SystemZ::FeatureDistinctOps])
    Features.set(Feature_FeatureDistinctOpsBit);
  if (FB[SystemZ::FeatureFastSerialization])
    Features.set(Feature_FeatureFastSerializationBit);
  if (FB[SystemZ::FeatureFPExtension])
    Features.set(Feature_FeatureFPExtensionBit);
  if (FB[SystemZ::FeatureHighWord])
    Features.set(Feature_FeatureHighWordBit);
  if (FB[SystemZ::FeatureInterlockedAccess1])
    Features.set(Feature_FeatureInterlockedAccess1Bit);
  if (FB[SystemZ::FeatureLoadStoreOnCond])
    Features.set(Feature_FeatureLoadStoreOnCondBit);
  if (FB[SystemZ::FeaturePopulationCount])
    Features.set(Feature_FeaturePopulationCountBit);
  if (FB[SystemZ::FeatureMessageSecurityAssist3])
    Features.set(Feature_FeatureMessageSecurityAssist3Bit);
  if (FB[SystemZ::FeatureMessageSecurityAssist4])
    Features.set(Feature_FeatureMessageSecurityAssist4Bit);
  if (FB[SystemZ::FeatureResetReferenceBitsMultiple])
    Features.set(Feature_FeatureResetReferenceBitsMultipleBit);
  if (FB[SystemZ::FeatureExecutionHint])
    Features.set(Feature_FeatureExecutionHintBit);
  if (FB[SystemZ::FeatureLoadAndTrap])
    Features.set(Feature_FeatureLoadAndTrapBit);
  if (FB[SystemZ::FeatureMiscellaneousExtensions])
    Features.set(Feature_FeatureMiscellaneousExtensionsBit);
  if (FB[SystemZ::FeatureProcessorAssist])
    Features.set(Feature_FeatureProcessorAssistBit);
  if (FB[SystemZ::FeatureTransactionalExecution])
    Features.set(Feature_FeatureTransactionalExecutionBit);
  if (FB[SystemZ::FeatureDFPZonedConversion])
    Features.set(Feature_FeatureDFPZonedConversionBit);
  if (FB[SystemZ::FeatureEnhancedDAT2])
    Features.set(Feature_FeatureEnhancedDAT2Bit);
  if (FB[SystemZ::FeatureLoadAndZeroRightmostByte])
    Features.set(Feature_FeatureLoadAndZeroRightmostByteBit);
  if (FB[SystemZ::FeatureLoadStoreOnCond2])
    Features.set(Feature_FeatureLoadStoreOnCond2Bit);
  if (FB[SystemZ::FeatureMessageSecurityAssist5])
    Features.set(Feature_FeatureMessageSecurityAssist5Bit);
  if (FB[SystemZ::FeatureDFPPackedConversion])
    Features.set(Feature_FeatureDFPPackedConversionBit);
  if (FB[SystemZ::FeatureVector])
    Features.set(Feature_FeatureVectorBit);
  if (FB[SystemZ::FeatureMiscellaneousExtensions2])
    Features.set(Feature_FeatureMiscellaneousExtensions2Bit);
  if (FB[SystemZ::FeatureGuardedStorage])
    Features.set(Feature_FeatureGuardedStorageBit);
  if (FB[SystemZ::FeatureMessageSecurityAssist7])
    Features.set(Feature_FeatureMessageSecurityAssist7Bit);
  if (FB[SystemZ::FeatureMessageSecurityAssist8])
    Features.set(Feature_FeatureMessageSecurityAssist8Bit);
  if (FB[SystemZ::FeatureVectorEnhancements1])
    Features.set(Feature_FeatureVectorEnhancements1Bit);
  if (FB[SystemZ::FeatureVectorPackedDecimal])
    Features.set(Feature_FeatureVectorPackedDecimalBit);
  if (FB[SystemZ::FeatureInsertReferenceBitsMultiple])
    Features.set(Feature_FeatureInsertReferenceBitsMultipleBit);
  if (FB[SystemZ::FeatureTestPendingExternalInterruption])
    Features.set(Feature_FeatureTestPendingExternalInterruptionBit);
  if (FB[SystemZ::FeatureMiscellaneousExtensions3])
    Features.set(Feature_FeatureMiscellaneousExtensions3Bit);
  if (FB[SystemZ::FeatureMessageSecurityAssist9])
    Features.set(Feature_FeatureMessageSecurityAssist9Bit);
  if (FB[SystemZ::FeatureVectorEnhancements2])
    Features.set(Feature_FeatureVectorEnhancements2Bit);
  if (FB[SystemZ::FeatureVectorPackedDecimalEnhancement])
    Features.set(Feature_FeatureVectorPackedDecimalEnhancementBit);
  if (FB[SystemZ::FeatureEnhancedSort])
    Features.set(Feature_FeatureEnhancedSortBit);
  if (FB[SystemZ::FeatureDeflateConversion])
    Features.set(Feature_FeatureDeflateConversionBit);
  if (FB[SystemZ::FeatureVectorPackedDecimalEnhancement2])
    Features.set(Feature_FeatureVectorPackedDecimalEnhancement2Bit);
  if (FB[SystemZ::FeatureNNPAssist])
    Features.set(Feature_FeatureNNPAssistBit);
  if (FB[SystemZ::FeatureBEAREnhancement])
    Features.set(Feature_FeatureBEAREnhancementBit);
  if (FB[SystemZ::FeatureResetDATProtection])
    Features.set(Feature_FeatureResetDATProtectionBit);
  if (FB[SystemZ::FeatureProcessorActivityInstrumentation])
    Features.set(Feature_FeatureProcessorActivityInstrumentationBit);
  if (FB[SystemZ::FeatureMiscellaneousExtensions4])
    Features.set(Feature_FeatureMiscellaneousExtensions4Bit);
  if (FB[SystemZ::FeatureVectorEnhancements3])
    Features.set(Feature_FeatureVectorEnhancements3Bit);
  if (FB[SystemZ::FeatureVectorPackedDecimalEnhancement3])
    Features.set(Feature_FeatureVectorPackedDecimalEnhancement3Bit);
  if (FB[SystemZ::FeatureMessageSecurityAssist12])
    Features.set(Feature_FeatureMessageSecurityAssist12Bit);
  if (FB[SystemZ::FeatureConcurrentFunctions])
    Features.set(Feature_FeatureConcurrentFunctionsBit);
  return Features;
}

inline FeatureBitset computeRequiredFeatures(unsigned Opcode) {
  enum : uint8_t {
    CEFBS_None,
    CEFBS_FeatureBEAREnhancement,
    CEFBS_FeatureConcurrentFunctions,
    CEFBS_FeatureDFPPackedConversion,
    CEFBS_FeatureDFPZonedConversion,
    CEFBS_FeatureDeflateConversion,
    CEFBS_FeatureDistinctOps,
    CEFBS_FeatureEnhancedDAT2,
    CEFBS_FeatureEnhancedSort,
    CEFBS_FeatureExecutionHint,
    CEFBS_FeatureFPExtension,
    CEFBS_FeatureGuardedStorage,
    CEFBS_FeatureHighWord,
    CEFBS_FeatureInsertReferenceBitsMultiple,
    CEFBS_FeatureInterlockedAccess1,
    CEFBS_FeatureLoadAndTrap,
    CEFBS_FeatureLoadAndZeroRightmostByte,
    CEFBS_FeatureLoadStoreOnCond,
    CEFBS_FeatureLoadStoreOnCond2,
    CEFBS_FeatureMessageSecurityAssist12,
    CEFBS_FeatureMessageSecurityAssist3,
    CEFBS_FeatureMessageSecurityAssist4,
    CEFBS_FeatureMessageSecurityAssist5,
    CEFBS_FeatureMessageSecurityAssist7,
    CEFBS_FeatureMessageSecurityAssist8,
    CEFBS_FeatureMessageSecurityAssist9,
    CEFBS_FeatureMiscellaneousExtensions,
    CEFBS_FeatureMiscellaneousExtensions2,
    CEFBS_FeatureMiscellaneousExtensions3,
    CEFBS_FeatureMiscellaneousExtensions4,
    CEFBS_FeatureNNPAssist,
    CEFBS_FeaturePopulationCount,
    CEFBS_FeatureProcessorActivityInstrumentation,
    CEFBS_FeatureProcessorAssist,
    CEFBS_FeatureResetDATProtection,
    CEFBS_FeatureResetReferenceBitsMultiple,
    CEFBS_FeatureTestPendingExternalInterruption,
    CEFBS_FeatureTransactionalExecution,
    CEFBS_FeatureVector,
    CEFBS_FeatureVectorEnhancements1,
    CEFBS_FeatureVectorEnhancements2,
    CEFBS_FeatureVectorEnhancements3,
    CEFBS_FeatureVectorPackedDecimal,
    CEFBS_FeatureVectorPackedDecimalEnhancement,
    CEFBS_FeatureVectorPackedDecimalEnhancement2,
    CEFBS_FeatureVectorPackedDecimalEnhancement3,
    CEFBS_FeatureHighWord_FeatureDistinctOps,
    CEFBS_FeatureVector_FeatureNNPAssist,
  };

  static constexpr FeatureBitset FeatureBitsets[] = {
    {}, // CEFBS_None
    {Feature_FeatureBEAREnhancementBit, },
    {Feature_FeatureConcurrentFunctionsBit, },
    {Feature_FeatureDFPPackedConversionBit, },
    {Feature_FeatureDFPZonedConversionBit, },
    {Feature_FeatureDeflateConversionBit, },
    {Feature_FeatureDistinctOpsBit, },
    {Feature_FeatureEnhancedDAT2Bit, },
    {Feature_FeatureEnhancedSortBit, },
    {Feature_FeatureExecutionHintBit, },
    {Feature_FeatureFPExtensionBit, },
    {Feature_FeatureGuardedStorageBit, },
    {Feature_FeatureHighWordBit, },
    {Feature_FeatureInsertReferenceBitsMultipleBit, },
    {Feature_FeatureInterlockedAccess1Bit, },
    {Feature_FeatureLoadAndTrapBit, },
    {Feature_FeatureLoadAndZeroRightmostByteBit, },
    {Feature_FeatureLoadStoreOnCondBit, },
    {Feature_FeatureLoadStoreOnCond2Bit, },
    {Feature_FeatureMessageSecurityAssist12Bit, },
    {Feature_FeatureMessageSecurityAssist3Bit, },
    {Feature_FeatureMessageSecurityAssist4Bit, },
    {Feature_FeatureMessageSecurityAssist5Bit, },
    {Feature_FeatureMessageSecurityAssist7Bit, },
    {Feature_FeatureMessageSecurityAssist8Bit, },
    {Feature_FeatureMessageSecurityAssist9Bit, },
    {Feature_FeatureMiscellaneousExtensionsBit, },
    {Feature_FeatureMiscellaneousExtensions2Bit, },
    {Feature_FeatureMiscellaneousExtensions3Bit, },
    {Feature_FeatureMiscellaneousExtensions4Bit, },
    {Feature_FeatureNNPAssistBit, },
    {Feature_FeaturePopulationCountBit, },
    {Feature_FeatureProcessorActivityInstrumentationBit, },
    {Feature_FeatureProcessorAssistBit, },
    {Feature_FeatureResetDATProtectionBit, },
    {Feature_FeatureResetReferenceBitsMultipleBit, },
    {Feature_FeatureTestPendingExternalInterruptionBit, },
    {Feature_FeatureTransactionalExecutionBit, },
    {Feature_FeatureVectorBit, },
    {Feature_FeatureVectorEnhancements1Bit, },
    {Feature_FeatureVectorEnhancements2Bit, },
    {Feature_FeatureVectorEnhancements3Bit, },
    {Feature_FeatureVectorPackedDecimalBit, },
    {Feature_FeatureVectorPackedDecimalEnhancementBit, },
    {Feature_FeatureVectorPackedDecimalEnhancement2Bit, },
    {Feature_FeatureVectorPackedDecimalEnhancement3Bit, },
    {Feature_FeatureHighWordBit, Feature_FeatureDistinctOpsBit, },
    {Feature_FeatureVectorBit, Feature_FeatureNNPAssistBit, },
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
    CEFBS_None, // ADA_ENTRY
    CEFBS_None, // ADA_ENTRY_VALUE
    CEFBS_None, // ADB_MemFoldPseudo
    CEFBS_None, // ADJCALLSTACKDOWN
    CEFBS_None, // ADJCALLSTACKUP
    CEFBS_None, // ADJDYNALLOC
    CEFBS_None, // AEB_MemFoldPseudo
    CEFBS_None, // AEXT128
    CEFBS_FeatureHighWord, // AFIMux
    CEFBS_None, // AG_MemFoldPseudo
    CEFBS_FeatureHighWord, // AHIMux
    CEFBS_FeatureHighWord_FeatureDistinctOps, // AHIMuxK
    CEFBS_None, // ALG_MemFoldPseudo
    CEFBS_None, // AL_MemFoldPseudo
    CEFBS_None, // ATOMIC_CMP_SWAPW
    CEFBS_None, // ATOMIC_LOADW_AFI
    CEFBS_None, // ATOMIC_LOADW_AR
    CEFBS_None, // ATOMIC_LOADW_MAX
    CEFBS_None, // ATOMIC_LOADW_MIN
    CEFBS_None, // ATOMIC_LOADW_NILH
    CEFBS_None, // ATOMIC_LOADW_NILHi
    CEFBS_None, // ATOMIC_LOADW_NR
    CEFBS_None, // ATOMIC_LOADW_NRi
    CEFBS_None, // ATOMIC_LOADW_OILH
    CEFBS_None, // ATOMIC_LOADW_OR
    CEFBS_None, // ATOMIC_LOADW_SR
    CEFBS_None, // ATOMIC_LOADW_UMAX
    CEFBS_None, // ATOMIC_LOADW_UMIN
    CEFBS_None, // ATOMIC_LOADW_XILF
    CEFBS_None, // ATOMIC_LOADW_XR
    CEFBS_None, // ATOMIC_SWAPW
    CEFBS_None, // A_MemFoldPseudo
    CEFBS_FeatureHighWord, // CFIMux
    CEFBS_None, // CGIBCall
    CEFBS_None, // CGIBReturn
    CEFBS_None, // CGRBCall
    CEFBS_None, // CGRBReturn
    CEFBS_FeatureHighWord, // CHIMux
    CEFBS_None, // CIBCall
    CEFBS_None, // CIBReturn
    CEFBS_None, // CLCImm
    CEFBS_None, // CLCReg
    CEFBS_FeatureHighWord, // CLFIMux
    CEFBS_None, // CLGIBCall
    CEFBS_None, // CLGIBReturn
    CEFBS_None, // CLGRBCall
    CEFBS_None, // CLGRBReturn
    CEFBS_None, // CLIBCall
    CEFBS_None, // CLIBReturn
    CEFBS_FeatureHighWord, // CLMux
    CEFBS_None, // CLRBCall
    CEFBS_None, // CLRBReturn
    CEFBS_None, // CLSTLoop
    CEFBS_None, // CMP_STACKGUARD
    CEFBS_None, // CMP_STACKGUARD_DAG
    CEFBS_FeatureHighWord, // CMux
    CEFBS_None, // CRBCall
    CEFBS_None, // CRBReturn
    CEFBS_None, // CallBASR
    CEFBS_None, // CallBASR_STACKEXT
    CEFBS_None, // CallBASR_XPLINK64
    CEFBS_None, // CallBCR
    CEFBS_None, // CallBR
    CEFBS_None, // CallBRASL
    CEFBS_None, // CallBRASL_XPLINK64
    CEFBS_None, // CallBRCL
    CEFBS_None, // CallJG
    CEFBS_None, // CondReturn
    CEFBS_None, // CondReturn_XPLINK
    CEFBS_None, // CondStore16
    CEFBS_None, // CondStore16Inv
    CEFBS_FeatureHighWord, // CondStore16Mux
    CEFBS_FeatureHighWord, // CondStore16MuxInv
    CEFBS_None, // CondStore32
    CEFBS_None, // CondStore32Inv
    CEFBS_FeatureLoadStoreOnCond2, // CondStore32Mux
    CEFBS_FeatureLoadStoreOnCond2, // CondStore32MuxInv
    CEFBS_None, // CondStore64
    CEFBS_None, // CondStore64Inv
    CEFBS_None, // CondStore8
    CEFBS_None, // CondStore8Inv
    CEFBS_FeatureHighWord, // CondStore8Mux
    CEFBS_FeatureHighWord, // CondStore8MuxInv
    CEFBS_None, // CondStoreF32
    CEFBS_None, // CondStoreF32Inv
    CEFBS_None, // CondStoreF64
    CEFBS_None, // CondStoreF64Inv
    CEFBS_None, // CondTrap
    CEFBS_None, // DDB_MemFoldPseudo
    CEFBS_None, // DEB_MemFoldPseudo
    CEFBS_None, // EH_SjLj_LongJmp
    CEFBS_None, // EH_SjLj_SetJmp
    CEFBS_None, // EH_SjLj_Setup
    CEFBS_None, // EXRL_Pseudo
    CEFBS_None, // FENCE
    CEFBS_None, // GOT
    CEFBS_FeatureHighWord, // IIFMux
    CEFBS_None, // IIHF64
    CEFBS_None, // IIHH64
    CEFBS_None, // IIHL64
    CEFBS_FeatureHighWord, // IIHMux
    CEFBS_None, // IILF64
    CEFBS_None, // IILH64
    CEFBS_None, // IILL64
    CEFBS_FeatureHighWord, // IILMux
    CEFBS_None, // L128
    CEFBS_FeatureHighWord, // LBMux
    CEFBS_FeatureVector, // LEFR
    CEFBS_FeatureVector, // LEFR_16
    CEFBS_FeatureVector, // LFER
    CEFBS_FeatureVector, // LFER_16
    CEFBS_FeatureHighWord, // LHIMux
    CEFBS_FeatureHighWord, // LHMux
    CEFBS_FeatureHighWord, // LLCMux
    CEFBS_FeatureHighWord, // LLCRMux
    CEFBS_FeatureHighWord, // LLHMux
    CEFBS_FeatureHighWord, // LLHRMux
    CEFBS_FeatureHighWord, // LMux
    CEFBS_None, // LOAD_GLOBAL_STACKGUARD_ADDR
    CEFBS_None, // LOAD_TLS_BLOCK_ADDR
    CEFBS_FeatureLoadStoreOnCond, // LOCG_MemFoldPseudo
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIMux
    CEFBS_FeatureLoadStoreOnCond2, // LOCMux
    CEFBS_FeatureLoadStoreOnCond2, // LOCMux_MemFoldPseudo
    CEFBS_FeatureLoadStoreOnCond2, // LOCRMux
    CEFBS_None, // LTDBRCompare_Pseudo
    CEFBS_None, // LTEBRCompare_Pseudo
    CEFBS_None, // LTXBRCompare_Pseudo
    CEFBS_None, // LX
    CEFBS_None, // MADB_MemFoldPseudo
    CEFBS_None, // MAEB_MemFoldPseudo
    CEFBS_None, // MDB_MemFoldPseudo
    CEFBS_None, // MEEB_MemFoldPseudo
    CEFBS_None, // MOV_STACKGUARD
    CEFBS_None, // MOV_STACKGUARD_DAG
    CEFBS_FeatureMiscellaneousExtensions2, // MSC_MemFoldPseudo
    CEFBS_None, // MSDB_MemFoldPseudo
    CEFBS_None, // MSEB_MemFoldPseudo
    CEFBS_FeatureMiscellaneousExtensions2, // MSGC_MemFoldPseudo
    CEFBS_None, // MVCImm
    CEFBS_None, // MVCReg
    CEFBS_None, // MVSTLoop
    CEFBS_None, // MemsetImmImm
    CEFBS_None, // MemsetImmReg
    CEFBS_None, // MemsetRegImm
    CEFBS_None, // MemsetRegReg
    CEFBS_None, // NCImm
    CEFBS_None, // NCReg
    CEFBS_None, // NG_MemFoldPseudo
    CEFBS_FeatureHighWord, // NIFMux
    CEFBS_None, // NIHF64
    CEFBS_None, // NIHH64
    CEFBS_None, // NIHL64
    CEFBS_FeatureHighWord, // NIHMux
    CEFBS_None, // NILF64
    CEFBS_None, // NILH64
    CEFBS_None, // NILL64
    CEFBS_FeatureHighWord, // NILMux
    CEFBS_None, // N_MemFoldPseudo
    CEFBS_None, // OCImm
    CEFBS_None, // OCReg
    CEFBS_None, // OG_MemFoldPseudo
    CEFBS_FeatureHighWord, // OIFMux
    CEFBS_None, // OIHF64
    CEFBS_None, // OIHH64
    CEFBS_None, // OIHL64
    CEFBS_FeatureHighWord, // OIHMux
    CEFBS_None, // OILF64
    CEFBS_None, // OILH64
    CEFBS_None, // OILL64
    CEFBS_FeatureHighWord, // OILMux
    CEFBS_None, // O_MemFoldPseudo
    CEFBS_None, // PAIR128
    CEFBS_None, // PROBED_ALLOCA
    CEFBS_None, // PROBED_STACKALLOC
    CEFBS_FeatureHighWord, // RISBHH
    CEFBS_FeatureHighWord, // RISBHHOpt
    CEFBS_FeatureHighWord, // RISBHL
    CEFBS_FeatureHighWord, // RISBHLOpt
    CEFBS_FeatureHighWord, // RISBLH
    CEFBS_FeatureHighWord, // RISBLHOpt
    CEFBS_FeatureHighWord, // RISBLL
    CEFBS_FeatureHighWord, // RISBLLOpt
    CEFBS_FeatureHighWord, // RISBMux
    CEFBS_None, // Return
    CEFBS_None, // Return_XPLINK
    CEFBS_FeatureVector, // SCmp128Hi
    CEFBS_None, // SDB_MemFoldPseudo
    CEFBS_None, // SEB_MemFoldPseudo
    CEFBS_FeatureMiscellaneousExtensions3, // SELRMux
    CEFBS_None, // SG_MemFoldPseudo
    CEFBS_None, // SLG_MemFoldPseudo
    CEFBS_None, // SL_MemFoldPseudo
    CEFBS_None, // SRSTLoop
    CEFBS_None, // ST128
    CEFBS_FeatureHighWord, // STCMux
    CEFBS_FeatureHighWord, // STHMux
    CEFBS_FeatureHighWord, // STMux
    CEFBS_FeatureLoadStoreOnCond2, // STOCMux
    CEFBS_None, // STX
    CEFBS_None, // S_MemFoldPseudo
    CEFBS_FeatureVector, // Select128
    CEFBS_None, // Select32
    CEFBS_None, // Select64
    CEFBS_None, // SelectF128
    CEFBS_None, // SelectF32
    CEFBS_None, // SelectF64
    CEFBS_FeatureVectorEnhancements1, // SelectVR128
    CEFBS_FeatureVector, // SelectVR32
    CEFBS_FeatureVector, // SelectVR64
    CEFBS_None, // Serialize
    CEFBS_FeatureTransactionalExecution, // TBEGIN_nofloat
    CEFBS_None, // TLS_GDCALL
    CEFBS_None, // TLS_LDCALL
    CEFBS_None, // TMHH64
    CEFBS_None, // TMHL64
    CEFBS_FeatureHighWord, // TMHMux
    CEFBS_None, // TMLH64
    CEFBS_None, // TMLL64
    CEFBS_FeatureHighWord, // TMLMux
    CEFBS_None, // Trap
    CEFBS_FeatureVector, // UCmp128Hi
    CEFBS_FeatureVector, // VL16
    CEFBS_FeatureVector, // VL32
    CEFBS_FeatureVector, // VL64
    CEFBS_FeatureVector, // VLR16
    CEFBS_FeatureVector, // VLR32
    CEFBS_FeatureVector, // VLR64
    CEFBS_FeatureVector, // VLVGP32
    CEFBS_FeatureVector, // VST16
    CEFBS_FeatureVector, // VST32
    CEFBS_FeatureVector, // VST64
    CEFBS_None, // XCImm
    CEFBS_None, // XCReg
    CEFBS_None, // XG_MemFoldPseudo
    CEFBS_FeatureHighWord, // XIFMux
    CEFBS_None, // XIHF64
    CEFBS_None, // XILF64
    CEFBS_None, // XPLINK_STACKALLOC
    CEFBS_None, // X_MemFoldPseudo
    CEFBS_None, // ZEXT128
    CEFBS_None, // A
    CEFBS_None, // AD
    CEFBS_None, // ADB
    CEFBS_None, // ADBR
    CEFBS_None, // ADR
    CEFBS_None, // ADTR
    CEFBS_FeatureFPExtension, // ADTRA
    CEFBS_None, // AE
    CEFBS_None, // AEB
    CEFBS_None, // AEBR
    CEFBS_None, // AER
    CEFBS_None, // AFI
    CEFBS_None, // AG
    CEFBS_None, // AGF
    CEFBS_None, // AGFI
    CEFBS_None, // AGFR
    CEFBS_FeatureMiscellaneousExtensions2, // AGH
    CEFBS_None, // AGHI
    CEFBS_FeatureDistinctOps, // AGHIK
    CEFBS_None, // AGR
    CEFBS_FeatureDistinctOps, // AGRK
    CEFBS_None, // AGSI
    CEFBS_None, // AH
    CEFBS_FeatureHighWord, // AHHHR
    CEFBS_FeatureHighWord, // AHHLR
    CEFBS_None, // AHI
    CEFBS_FeatureDistinctOps, // AHIK
    CEFBS_None, // AHY
    CEFBS_FeatureHighWord, // AIH
    CEFBS_None, // AL
    CEFBS_None, // ALC
    CEFBS_None, // ALCG
    CEFBS_None, // ALCGR
    CEFBS_None, // ALCR
    CEFBS_None, // ALFI
    CEFBS_None, // ALG
    CEFBS_None, // ALGF
    CEFBS_None, // ALGFI
    CEFBS_None, // ALGFR
    CEFBS_FeatureDistinctOps, // ALGHSIK
    CEFBS_None, // ALGR
    CEFBS_FeatureDistinctOps, // ALGRK
    CEFBS_None, // ALGSI
    CEFBS_FeatureHighWord, // ALHHHR
    CEFBS_FeatureHighWord, // ALHHLR
    CEFBS_FeatureDistinctOps, // ALHSIK
    CEFBS_None, // ALR
    CEFBS_FeatureDistinctOps, // ALRK
    CEFBS_None, // ALSI
    CEFBS_FeatureHighWord, // ALSIH
    CEFBS_FeatureHighWord, // ALSIHN
    CEFBS_None, // ALY
    CEFBS_None, // AP
    CEFBS_None, // AR
    CEFBS_FeatureDistinctOps, // ARK
    CEFBS_None, // ASI
    CEFBS_None, // AU
    CEFBS_None, // AUR
    CEFBS_None, // AW
    CEFBS_None, // AWR
    CEFBS_None, // AXBR
    CEFBS_None, // AXR
    CEFBS_None, // AXTR
    CEFBS_FeatureFPExtension, // AXTRA
    CEFBS_None, // AY
    CEFBS_None, // B
    CEFBS_None, // BAKR
    CEFBS_None, // BAL
    CEFBS_None, // BALR
    CEFBS_None, // BAS
    CEFBS_None, // BASR
    CEFBS_None, // BASSM
    CEFBS_None, // BAsmE
    CEFBS_None, // BAsmH
    CEFBS_None, // BAsmHE
    CEFBS_None, // BAsmL
    CEFBS_None, // BAsmLE
    CEFBS_None, // BAsmLH
    CEFBS_None, // BAsmM
    CEFBS_None, // BAsmNE
    CEFBS_None, // BAsmNH
    CEFBS_None, // BAsmNHE
    CEFBS_None, // BAsmNL
    CEFBS_None, // BAsmNLE
    CEFBS_None, // BAsmNLH
    CEFBS_None, // BAsmNM
    CEFBS_None, // BAsmNO
    CEFBS_None, // BAsmNP
    CEFBS_None, // BAsmNZ
    CEFBS_None, // BAsmO
    CEFBS_None, // BAsmP
    CEFBS_None, // BAsmZ
    CEFBS_None, // BC
    CEFBS_None, // BCAsm
    CEFBS_None, // BCR
    CEFBS_None, // BCRAsm
    CEFBS_None, // BCT
    CEFBS_None, // BCTG
    CEFBS_None, // BCTGR
    CEFBS_None, // BCTR
    CEFBS_FeatureMiscellaneousExtensions4, // BDEPG
    CEFBS_FeatureMiscellaneousExtensions4, // BEXTG
    CEFBS_FeatureMiscellaneousExtensions2, // BI
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmE
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmH
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmHE
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmL
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmLE
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmLH
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmM
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmNE
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmNH
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmNHE
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmNL
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmNLE
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmNLH
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmNM
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmNO
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmNP
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmNZ
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmO
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmP
    CEFBS_FeatureMiscellaneousExtensions2, // BIAsmZ
    CEFBS_FeatureMiscellaneousExtensions2, // BIC
    CEFBS_FeatureMiscellaneousExtensions2, // BICAsm
    CEFBS_FeatureExecutionHint, // BPP
    CEFBS_FeatureExecutionHint, // BPRP
    CEFBS_None, // BR
    CEFBS_None, // BRAS
    CEFBS_None, // BRASL
    CEFBS_None, // BRAsmE
    CEFBS_None, // BRAsmH
    CEFBS_None, // BRAsmHE
    CEFBS_None, // BRAsmL
    CEFBS_None, // BRAsmLE
    CEFBS_None, // BRAsmLH
    CEFBS_None, // BRAsmM
    CEFBS_None, // BRAsmNE
    CEFBS_None, // BRAsmNH
    CEFBS_None, // BRAsmNHE
    CEFBS_None, // BRAsmNL
    CEFBS_None, // BRAsmNLE
    CEFBS_None, // BRAsmNLH
    CEFBS_None, // BRAsmNM
    CEFBS_None, // BRAsmNO
    CEFBS_None, // BRAsmNP
    CEFBS_None, // BRAsmNZ
    CEFBS_None, // BRAsmO
    CEFBS_None, // BRAsmP
    CEFBS_None, // BRAsmZ
    CEFBS_None, // BRC
    CEFBS_None, // BRCAsm
    CEFBS_None, // BRCL
    CEFBS_None, // BRCLAsm
    CEFBS_None, // BRCT
    CEFBS_None, // BRCTG
    CEFBS_FeatureHighWord, // BRCTH
    CEFBS_None, // BRXH
    CEFBS_None, // BRXHG
    CEFBS_None, // BRXLE
    CEFBS_None, // BRXLG
    CEFBS_None, // BSA
    CEFBS_None, // BSG
    CEFBS_None, // BSM
    CEFBS_None, // BXH
    CEFBS_None, // BXHG
    CEFBS_None, // BXLE
    CEFBS_None, // BXLEG
    CEFBS_None, // C
    CEFBS_FeatureConcurrentFunctions, // CAL
    CEFBS_FeatureConcurrentFunctions, // CALG
    CEFBS_FeatureConcurrentFunctions, // CALGF
    CEFBS_None, // CD
    CEFBS_None, // CDB
    CEFBS_None, // CDBR
    CEFBS_None, // CDFBR
    CEFBS_FeatureFPExtension, // CDFBRA
    CEFBS_None, // CDFR
    CEFBS_FeatureFPExtension, // CDFTR
    CEFBS_None, // CDGBR
    CEFBS_FeatureFPExtension, // CDGBRA
    CEFBS_None, // CDGR
    CEFBS_None, // CDGTR
    CEFBS_FeatureFPExtension, // CDGTRA
    CEFBS_FeatureFPExtension, // CDLFBR
    CEFBS_FeatureFPExtension, // CDLFTR
    CEFBS_FeatureFPExtension, // CDLGBR
    CEFBS_FeatureFPExtension, // CDLGTR
    CEFBS_FeatureDFPPackedConversion, // CDPT
    CEFBS_None, // CDR
    CEFBS_None, // CDS
    CEFBS_None, // CDSG
    CEFBS_None, // CDSTR
    CEFBS_None, // CDSY
    CEFBS_None, // CDTR
    CEFBS_None, // CDUTR
    CEFBS_FeatureDFPZonedConversion, // CDZT
    CEFBS_None, // CE
    CEFBS_None, // CEB
    CEFBS_None, // CEBR
    CEFBS_None, // CEDTR
    CEFBS_None, // CEFBR
    CEFBS_FeatureFPExtension, // CEFBRA
    CEFBS_None, // CEFR
    CEFBS_None, // CEGBR
    CEFBS_FeatureFPExtension, // CEGBRA
    CEFBS_None, // CEGR
    CEFBS_FeatureFPExtension, // CELFBR
    CEFBS_FeatureFPExtension, // CELGBR
    CEFBS_None, // CER
    CEFBS_None, // CEXTR
    CEFBS_None, // CFC
    CEFBS_None, // CFDBR
    CEFBS_FeatureFPExtension, // CFDBRA
    CEFBS_None, // CFDR
    CEFBS_FeatureFPExtension, // CFDTR
    CEFBS_None, // CFEBR
    CEFBS_FeatureFPExtension, // CFEBRA
    CEFBS_None, // CFER
    CEFBS_None, // CFI
    CEFBS_None, // CFXBR
    CEFBS_FeatureFPExtension, // CFXBRA
    CEFBS_None, // CFXR
    CEFBS_FeatureFPExtension, // CFXTR
    CEFBS_None, // CG
    CEFBS_None, // CGDBR
    CEFBS_FeatureFPExtension, // CGDBRA
    CEFBS_None, // CGDR
    CEFBS_None, // CGDTR
    CEFBS_FeatureFPExtension, // CGDTRA
    CEFBS_None, // CGEBR
    CEFBS_FeatureFPExtension, // CGEBRA
    CEFBS_None, // CGER
    CEFBS_None, // CGF
    CEFBS_None, // CGFI
    CEFBS_None, // CGFR
    CEFBS_None, // CGFRL
    CEFBS_None, // CGH
    CEFBS_None, // CGHI
    CEFBS_None, // CGHRL
    CEFBS_None, // CGHSI
    CEFBS_None, // CGIB
    CEFBS_None, // CGIBAsm
    CEFBS_None, // CGIBAsmE
    CEFBS_None, // CGIBAsmH
    CEFBS_None, // CGIBAsmHE
    CEFBS_None, // CGIBAsmL
    CEFBS_None, // CGIBAsmLE
    CEFBS_None, // CGIBAsmLH
    CEFBS_None, // CGIBAsmNE
    CEFBS_None, // CGIBAsmNH
    CEFBS_None, // CGIBAsmNHE
    CEFBS_None, // CGIBAsmNL
    CEFBS_None, // CGIBAsmNLE
    CEFBS_None, // CGIBAsmNLH
    CEFBS_None, // CGIJ
    CEFBS_None, // CGIJAsm
    CEFBS_None, // CGIJAsmE
    CEFBS_None, // CGIJAsmH
    CEFBS_None, // CGIJAsmHE
    CEFBS_None, // CGIJAsmL
    CEFBS_None, // CGIJAsmLE
    CEFBS_None, // CGIJAsmLH
    CEFBS_None, // CGIJAsmNE
    CEFBS_None, // CGIJAsmNH
    CEFBS_None, // CGIJAsmNHE
    CEFBS_None, // CGIJAsmNL
    CEFBS_None, // CGIJAsmNLE
    CEFBS_None, // CGIJAsmNLH
    CEFBS_None, // CGIT
    CEFBS_None, // CGITAsm
    CEFBS_None, // CGITAsmE
    CEFBS_None, // CGITAsmH
    CEFBS_None, // CGITAsmHE
    CEFBS_None, // CGITAsmL
    CEFBS_None, // CGITAsmLE
    CEFBS_None, // CGITAsmLH
    CEFBS_None, // CGITAsmNE
    CEFBS_None, // CGITAsmNH
    CEFBS_None, // CGITAsmNHE
    CEFBS_None, // CGITAsmNL
    CEFBS_None, // CGITAsmNLE
    CEFBS_None, // CGITAsmNLH
    CEFBS_None, // CGR
    CEFBS_None, // CGRB
    CEFBS_None, // CGRBAsm
    CEFBS_None, // CGRBAsmE
    CEFBS_None, // CGRBAsmH
    CEFBS_None, // CGRBAsmHE
    CEFBS_None, // CGRBAsmL
    CEFBS_None, // CGRBAsmLE
    CEFBS_None, // CGRBAsmLH
    CEFBS_None, // CGRBAsmNE
    CEFBS_None, // CGRBAsmNH
    CEFBS_None, // CGRBAsmNHE
    CEFBS_None, // CGRBAsmNL
    CEFBS_None, // CGRBAsmNLE
    CEFBS_None, // CGRBAsmNLH
    CEFBS_None, // CGRJ
    CEFBS_None, // CGRJAsm
    CEFBS_None, // CGRJAsmE
    CEFBS_None, // CGRJAsmH
    CEFBS_None, // CGRJAsmHE
    CEFBS_None, // CGRJAsmL
    CEFBS_None, // CGRJAsmLE
    CEFBS_None, // CGRJAsmLH
    CEFBS_None, // CGRJAsmNE
    CEFBS_None, // CGRJAsmNH
    CEFBS_None, // CGRJAsmNHE
    CEFBS_None, // CGRJAsmNL
    CEFBS_None, // CGRJAsmNLE
    CEFBS_None, // CGRJAsmNLH
    CEFBS_None, // CGRL
    CEFBS_None, // CGRT
    CEFBS_None, // CGRTAsm
    CEFBS_None, // CGRTAsmE
    CEFBS_None, // CGRTAsmH
    CEFBS_None, // CGRTAsmHE
    CEFBS_None, // CGRTAsmL
    CEFBS_None, // CGRTAsmLE
    CEFBS_None, // CGRTAsmLH
    CEFBS_None, // CGRTAsmNE
    CEFBS_None, // CGRTAsmNH
    CEFBS_None, // CGRTAsmNHE
    CEFBS_None, // CGRTAsmNL
    CEFBS_None, // CGRTAsmNLE
    CEFBS_None, // CGRTAsmNLH
    CEFBS_None, // CGXBR
    CEFBS_FeatureFPExtension, // CGXBRA
    CEFBS_None, // CGXR
    CEFBS_None, // CGXTR
    CEFBS_FeatureFPExtension, // CGXTRA
    CEFBS_None, // CH
    CEFBS_FeatureHighWord, // CHF
    CEFBS_FeatureHighWord, // CHHR
    CEFBS_None, // CHHSI
    CEFBS_None, // CHI
    CEFBS_FeatureHighWord, // CHLR
    CEFBS_None, // CHRL
    CEFBS_None, // CHSI
    CEFBS_None, // CHY
    CEFBS_None, // CIB
    CEFBS_None, // CIBAsm
    CEFBS_None, // CIBAsmE
    CEFBS_None, // CIBAsmH
    CEFBS_None, // CIBAsmHE
    CEFBS_None, // CIBAsmL
    CEFBS_None, // CIBAsmLE
    CEFBS_None, // CIBAsmLH
    CEFBS_None, // CIBAsmNE
    CEFBS_None, // CIBAsmNH
    CEFBS_None, // CIBAsmNHE
    CEFBS_None, // CIBAsmNL
    CEFBS_None, // CIBAsmNLE
    CEFBS_None, // CIBAsmNLH
    CEFBS_FeatureHighWord, // CIH
    CEFBS_None, // CIJ
    CEFBS_None, // CIJAsm
    CEFBS_None, // CIJAsmE
    CEFBS_None, // CIJAsmH
    CEFBS_None, // CIJAsmHE
    CEFBS_None, // CIJAsmL
    CEFBS_None, // CIJAsmLE
    CEFBS_None, // CIJAsmLH
    CEFBS_None, // CIJAsmNE
    CEFBS_None, // CIJAsmNH
    CEFBS_None, // CIJAsmNHE
    CEFBS_None, // CIJAsmNL
    CEFBS_None, // CIJAsmNLE
    CEFBS_None, // CIJAsmNLH
    CEFBS_None, // CIT
    CEFBS_None, // CITAsm
    CEFBS_None, // CITAsmE
    CEFBS_None, // CITAsmH
    CEFBS_None, // CITAsmHE
    CEFBS_None, // CITAsmL
    CEFBS_None, // CITAsmLE
    CEFBS_None, // CITAsmLH
    CEFBS_None, // CITAsmNE
    CEFBS_None, // CITAsmNH
    CEFBS_None, // CITAsmNHE
    CEFBS_None, // CITAsmNL
    CEFBS_None, // CITAsmNLE
    CEFBS_None, // CITAsmNLH
    CEFBS_None, // CKSM
    CEFBS_None, // CL
    CEFBS_None, // CLC
    CEFBS_None, // CLCL
    CEFBS_None, // CLCLE
    CEFBS_None, // CLCLU
    CEFBS_FeatureFPExtension, // CLFDBR
    CEFBS_FeatureFPExtension, // CLFDTR
    CEFBS_FeatureFPExtension, // CLFEBR
    CEFBS_None, // CLFHSI
    CEFBS_None, // CLFI
    CEFBS_None, // CLFIT
    CEFBS_None, // CLFITAsm
    CEFBS_None, // CLFITAsmE
    CEFBS_None, // CLFITAsmH
    CEFBS_None, // CLFITAsmHE
    CEFBS_None, // CLFITAsmL
    CEFBS_None, // CLFITAsmLE
    CEFBS_None, // CLFITAsmLH
    CEFBS_None, // CLFITAsmNE
    CEFBS_None, // CLFITAsmNH
    CEFBS_None, // CLFITAsmNHE
    CEFBS_None, // CLFITAsmNL
    CEFBS_None, // CLFITAsmNLE
    CEFBS_None, // CLFITAsmNLH
    CEFBS_FeatureFPExtension, // CLFXBR
    CEFBS_FeatureFPExtension, // CLFXTR
    CEFBS_None, // CLG
    CEFBS_FeatureFPExtension, // CLGDBR
    CEFBS_FeatureFPExtension, // CLGDTR
    CEFBS_FeatureFPExtension, // CLGEBR
    CEFBS_None, // CLGF
    CEFBS_None, // CLGFI
    CEFBS_None, // CLGFR
    CEFBS_None, // CLGFRL
    CEFBS_None, // CLGHRL
    CEFBS_None, // CLGHSI
    CEFBS_None, // CLGIB
    CEFBS_None, // CLGIBAsm
    CEFBS_None, // CLGIBAsmE
    CEFBS_None, // CLGIBAsmH
    CEFBS_None, // CLGIBAsmHE
    CEFBS_None, // CLGIBAsmL
    CEFBS_None, // CLGIBAsmLE
    CEFBS_None, // CLGIBAsmLH
    CEFBS_None, // CLGIBAsmNE
    CEFBS_None, // CLGIBAsmNH
    CEFBS_None, // CLGIBAsmNHE
    CEFBS_None, // CLGIBAsmNL
    CEFBS_None, // CLGIBAsmNLE
    CEFBS_None, // CLGIBAsmNLH
    CEFBS_None, // CLGIJ
    CEFBS_None, // CLGIJAsm
    CEFBS_None, // CLGIJAsmE
    CEFBS_None, // CLGIJAsmH
    CEFBS_None, // CLGIJAsmHE
    CEFBS_None, // CLGIJAsmL
    CEFBS_None, // CLGIJAsmLE
    CEFBS_None, // CLGIJAsmLH
    CEFBS_None, // CLGIJAsmNE
    CEFBS_None, // CLGIJAsmNH
    CEFBS_None, // CLGIJAsmNHE
    CEFBS_None, // CLGIJAsmNL
    CEFBS_None, // CLGIJAsmNLE
    CEFBS_None, // CLGIJAsmNLH
    CEFBS_None, // CLGIT
    CEFBS_None, // CLGITAsm
    CEFBS_None, // CLGITAsmE
    CEFBS_None, // CLGITAsmH
    CEFBS_None, // CLGITAsmHE
    CEFBS_None, // CLGITAsmL
    CEFBS_None, // CLGITAsmLE
    CEFBS_None, // CLGITAsmLH
    CEFBS_None, // CLGITAsmNE
    CEFBS_None, // CLGITAsmNH
    CEFBS_None, // CLGITAsmNHE
    CEFBS_None, // CLGITAsmNL
    CEFBS_None, // CLGITAsmNLE
    CEFBS_None, // CLGITAsmNLH
    CEFBS_None, // CLGR
    CEFBS_None, // CLGRB
    CEFBS_None, // CLGRBAsm
    CEFBS_None, // CLGRBAsmE
    CEFBS_None, // CLGRBAsmH
    CEFBS_None, // CLGRBAsmHE
    CEFBS_None, // CLGRBAsmL
    CEFBS_None, // CLGRBAsmLE
    CEFBS_None, // CLGRBAsmLH
    CEFBS_None, // CLGRBAsmNE
    CEFBS_None, // CLGRBAsmNH
    CEFBS_None, // CLGRBAsmNHE
    CEFBS_None, // CLGRBAsmNL
    CEFBS_None, // CLGRBAsmNLE
    CEFBS_None, // CLGRBAsmNLH
    CEFBS_None, // CLGRJ
    CEFBS_None, // CLGRJAsm
    CEFBS_None, // CLGRJAsmE
    CEFBS_None, // CLGRJAsmH
    CEFBS_None, // CLGRJAsmHE
    CEFBS_None, // CLGRJAsmL
    CEFBS_None, // CLGRJAsmLE
    CEFBS_None, // CLGRJAsmLH
    CEFBS_None, // CLGRJAsmNE
    CEFBS_None, // CLGRJAsmNH
    CEFBS_None, // CLGRJAsmNHE
    CEFBS_None, // CLGRJAsmNL
    CEFBS_None, // CLGRJAsmNLE
    CEFBS_None, // CLGRJAsmNLH
    CEFBS_None, // CLGRL
    CEFBS_None, // CLGRT
    CEFBS_None, // CLGRTAsm
    CEFBS_None, // CLGRTAsmE
    CEFBS_None, // CLGRTAsmH
    CEFBS_None, // CLGRTAsmHE
    CEFBS_None, // CLGRTAsmL
    CEFBS_None, // CLGRTAsmLE
    CEFBS_None, // CLGRTAsmLH
    CEFBS_None, // CLGRTAsmNE
    CEFBS_None, // CLGRTAsmNH
    CEFBS_None, // CLGRTAsmNHE
    CEFBS_None, // CLGRTAsmNL
    CEFBS_None, // CLGRTAsmNLE
    CEFBS_None, // CLGRTAsmNLH
    CEFBS_FeatureMiscellaneousExtensions, // CLGT
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsm
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmE
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmH
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmHE
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmL
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmLE
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmLH
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmNE
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmNH
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmNHE
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmNL
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmNLE
    CEFBS_FeatureMiscellaneousExtensions, // CLGTAsmNLH
    CEFBS_FeatureFPExtension, // CLGXBR
    CEFBS_FeatureFPExtension, // CLGXTR
    CEFBS_FeatureHighWord, // CLHF
    CEFBS_FeatureHighWord, // CLHHR
    CEFBS_None, // CLHHSI
    CEFBS_FeatureHighWord, // CLHLR
    CEFBS_None, // CLHRL
    CEFBS_None, // CLI
    CEFBS_None, // CLIB
    CEFBS_None, // CLIBAsm
    CEFBS_None, // CLIBAsmE
    CEFBS_None, // CLIBAsmH
    CEFBS_None, // CLIBAsmHE
    CEFBS_None, // CLIBAsmL
    CEFBS_None, // CLIBAsmLE
    CEFBS_None, // CLIBAsmLH
    CEFBS_None, // CLIBAsmNE
    CEFBS_None, // CLIBAsmNH
    CEFBS_None, // CLIBAsmNHE
    CEFBS_None, // CLIBAsmNL
    CEFBS_None, // CLIBAsmNLE
    CEFBS_None, // CLIBAsmNLH
    CEFBS_FeatureHighWord, // CLIH
    CEFBS_None, // CLIJ
    CEFBS_None, // CLIJAsm
    CEFBS_None, // CLIJAsmE
    CEFBS_None, // CLIJAsmH
    CEFBS_None, // CLIJAsmHE
    CEFBS_None, // CLIJAsmL
    CEFBS_None, // CLIJAsmLE
    CEFBS_None, // CLIJAsmLH
    CEFBS_None, // CLIJAsmNE
    CEFBS_None, // CLIJAsmNH
    CEFBS_None, // CLIJAsmNHE
    CEFBS_None, // CLIJAsmNL
    CEFBS_None, // CLIJAsmNLE
    CEFBS_None, // CLIJAsmNLH
    CEFBS_None, // CLIY
    CEFBS_None, // CLM
    CEFBS_None, // CLMH
    CEFBS_None, // CLMY
    CEFBS_None, // CLR
    CEFBS_None, // CLRB
    CEFBS_None, // CLRBAsm
    CEFBS_None, // CLRBAsmE
    CEFBS_None, // CLRBAsmH
    CEFBS_None, // CLRBAsmHE
    CEFBS_None, // CLRBAsmL
    CEFBS_None, // CLRBAsmLE
    CEFBS_None, // CLRBAsmLH
    CEFBS_None, // CLRBAsmNE
    CEFBS_None, // CLRBAsmNH
    CEFBS_None, // CLRBAsmNHE
    CEFBS_None, // CLRBAsmNL
    CEFBS_None, // CLRBAsmNLE
    CEFBS_None, // CLRBAsmNLH
    CEFBS_None, // CLRJ
    CEFBS_None, // CLRJAsm
    CEFBS_None, // CLRJAsmE
    CEFBS_None, // CLRJAsmH
    CEFBS_None, // CLRJAsmHE
    CEFBS_None, // CLRJAsmL
    CEFBS_None, // CLRJAsmLE
    CEFBS_None, // CLRJAsmLH
    CEFBS_None, // CLRJAsmNE
    CEFBS_None, // CLRJAsmNH
    CEFBS_None, // CLRJAsmNHE
    CEFBS_None, // CLRJAsmNL
    CEFBS_None, // CLRJAsmNLE
    CEFBS_None, // CLRJAsmNLH
    CEFBS_None, // CLRL
    CEFBS_None, // CLRT
    CEFBS_None, // CLRTAsm
    CEFBS_None, // CLRTAsmE
    CEFBS_None, // CLRTAsmH
    CEFBS_None, // CLRTAsmHE
    CEFBS_None, // CLRTAsmL
    CEFBS_None, // CLRTAsmLE
    CEFBS_None, // CLRTAsmLH
    CEFBS_None, // CLRTAsmNE
    CEFBS_None, // CLRTAsmNH
    CEFBS_None, // CLRTAsmNHE
    CEFBS_None, // CLRTAsmNL
    CEFBS_None, // CLRTAsmNLE
    CEFBS_None, // CLRTAsmNLH
    CEFBS_None, // CLST
    CEFBS_FeatureMiscellaneousExtensions, // CLT
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsm
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmE
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmH
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmHE
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmL
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmLE
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmLH
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmNE
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmNH
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmNHE
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmNL
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmNLE
    CEFBS_FeatureMiscellaneousExtensions, // CLTAsmNLH
    CEFBS_None, // CLY
    CEFBS_FeatureMiscellaneousExtensions4, // CLZG
    CEFBS_None, // CMPSC
    CEFBS_None, // CP
    CEFBS_FeatureDFPPackedConversion, // CPDT
    CEFBS_None, // CPSDRdd
    CEFBS_None, // CPSDRdh
    CEFBS_None, // CPSDRds
    CEFBS_None, // CPSDRhd
    CEFBS_None, // CPSDRhh
    CEFBS_None, // CPSDRhs
    CEFBS_None, // CPSDRsd
    CEFBS_None, // CPSDRsh
    CEFBS_None, // CPSDRss
    CEFBS_FeatureDFPPackedConversion, // CPXT
    CEFBS_None, // CPYA
    CEFBS_None, // CR
    CEFBS_None, // CRB
    CEFBS_None, // CRBAsm
    CEFBS_None, // CRBAsmE
    CEFBS_None, // CRBAsmH
    CEFBS_None, // CRBAsmHE
    CEFBS_None, // CRBAsmL
    CEFBS_None, // CRBAsmLE
    CEFBS_None, // CRBAsmLH
    CEFBS_None, // CRBAsmNE
    CEFBS_None, // CRBAsmNH
    CEFBS_None, // CRBAsmNHE
    CEFBS_None, // CRBAsmNL
    CEFBS_None, // CRBAsmNLE
    CEFBS_None, // CRBAsmNLH
    CEFBS_FeatureEnhancedDAT2, // CRDTE
    CEFBS_FeatureEnhancedDAT2, // CRDTEOpt
    CEFBS_None, // CRJ
    CEFBS_None, // CRJAsm
    CEFBS_None, // CRJAsmE
    CEFBS_None, // CRJAsmH
    CEFBS_None, // CRJAsmHE
    CEFBS_None, // CRJAsmL
    CEFBS_None, // CRJAsmLE
    CEFBS_None, // CRJAsmLH
    CEFBS_None, // CRJAsmNE
    CEFBS_None, // CRJAsmNH
    CEFBS_None, // CRJAsmNHE
    CEFBS_None, // CRJAsmNL
    CEFBS_None, // CRJAsmNLE
    CEFBS_None, // CRJAsmNLH
    CEFBS_None, // CRL
    CEFBS_None, // CRT
    CEFBS_None, // CRTAsm
    CEFBS_None, // CRTAsmE
    CEFBS_None, // CRTAsmH
    CEFBS_None, // CRTAsmHE
    CEFBS_None, // CRTAsmL
    CEFBS_None, // CRTAsmLE
    CEFBS_None, // CRTAsmLH
    CEFBS_None, // CRTAsmNE
    CEFBS_None, // CRTAsmNH
    CEFBS_None, // CRTAsmNHE
    CEFBS_None, // CRTAsmNL
    CEFBS_None, // CRTAsmNLE
    CEFBS_None, // CRTAsmNLH
    CEFBS_None, // CS
    CEFBS_None, // CSCH
    CEFBS_None, // CSDTR
    CEFBS_None, // CSG
    CEFBS_None, // CSP
    CEFBS_None, // CSPG
    CEFBS_None, // CSST
    CEFBS_None, // CSXTR
    CEFBS_None, // CSY
    CEFBS_FeatureMiscellaneousExtensions4, // CTZG
    CEFBS_None, // CU12
    CEFBS_None, // CU12Opt
    CEFBS_None, // CU14
    CEFBS_None, // CU14Opt
    CEFBS_None, // CU21
    CEFBS_None, // CU21Opt
    CEFBS_None, // CU24
    CEFBS_None, // CU24Opt
    CEFBS_None, // CU41
    CEFBS_None, // CU42
    CEFBS_None, // CUDTR
    CEFBS_None, // CUSE
    CEFBS_None, // CUTFU
    CEFBS_None, // CUTFUOpt
    CEFBS_None, // CUUTF
    CEFBS_None, // CUUTFOpt
    CEFBS_None, // CUXTR
    CEFBS_None, // CVB
    CEFBS_None, // CVBG
    CEFBS_None, // CVBY
    CEFBS_None, // CVD
    CEFBS_None, // CVDG
    CEFBS_None, // CVDY
    CEFBS_None, // CXBR
    CEFBS_None, // CXFBR
    CEFBS_FeatureFPExtension, // CXFBRA
    CEFBS_None, // CXFR
    CEFBS_FeatureFPExtension, // CXFTR
    CEFBS_None, // CXGBR
    CEFBS_FeatureFPExtension, // CXGBRA
    CEFBS_None, // CXGR
    CEFBS_None, // CXGTR
    CEFBS_FeatureFPExtension, // CXGTRA
    CEFBS_FeatureFPExtension, // CXLFBR
    CEFBS_FeatureFPExtension, // CXLFTR
    CEFBS_FeatureFPExtension, // CXLGBR
    CEFBS_FeatureFPExtension, // CXLGTR
    CEFBS_FeatureDFPPackedConversion, // CXPT
    CEFBS_None, // CXR
    CEFBS_None, // CXSTR
    CEFBS_None, // CXTR
    CEFBS_None, // CXUTR
    CEFBS_FeatureDFPZonedConversion, // CXZT
    CEFBS_None, // CY
    CEFBS_FeatureDFPZonedConversion, // CZDT
    CEFBS_FeatureDFPZonedConversion, // CZXT
    CEFBS_None, // D
    CEFBS_None, // DD
    CEFBS_None, // DDB
    CEFBS_None, // DDBR
    CEFBS_None, // DDR
    CEFBS_None, // DDTR
    CEFBS_FeatureFPExtension, // DDTRA
    CEFBS_None, // DE
    CEFBS_None, // DEB
    CEFBS_None, // DEBR
    CEFBS_None, // DER
    CEFBS_FeatureDeflateConversion, // DFLTCC
    CEFBS_None, // DIAG
    CEFBS_None, // DIDBR
    CEFBS_None, // DIEBR
    CEFBS_None, // DL
    CEFBS_None, // DLG
    CEFBS_None, // DLGR
    CEFBS_None, // DLR
    CEFBS_None, // DP
    CEFBS_None, // DR
    CEFBS_None, // DSG
    CEFBS_None, // DSGF
    CEFBS_None, // DSGFR
    CEFBS_None, // DSGR
    CEFBS_None, // DXBR
    CEFBS_None, // DXR
    CEFBS_None, // DXTR
    CEFBS_FeatureFPExtension, // DXTRA
    CEFBS_None, // EAR
    CEFBS_None, // ECAG
    CEFBS_None, // ECCTR
    CEFBS_None, // ECPGA
    CEFBS_None, // ECTG
    CEFBS_None, // ED
    CEFBS_None, // EDMK
    CEFBS_None, // EEDTR
    CEFBS_None, // EEXTR
    CEFBS_None, // EFPC
    CEFBS_None, // EPAIR
    CEFBS_None, // EPAR
    CEFBS_None, // EPCTR
    CEFBS_None, // EPSW
    CEFBS_None, // EREG
    CEFBS_None, // EREGG
    CEFBS_None, // ESAIR
    CEFBS_None, // ESAR
    CEFBS_None, // ESDTR
    CEFBS_None, // ESEA
    CEFBS_None, // ESTA
    CEFBS_None, // ESXTR
    CEFBS_FeatureTransactionalExecution, // ETND
    CEFBS_None, // EX
    CEFBS_None, // EXRL
    CEFBS_None, // FIDBR
    CEFBS_FeatureFPExtension, // FIDBRA
    CEFBS_None, // FIDR
    CEFBS_None, // FIDTR
    CEFBS_None, // FIEBR
    CEFBS_FeatureFPExtension, // FIEBRA
    CEFBS_None, // FIER
    CEFBS_None, // FIXBR
    CEFBS_FeatureFPExtension, // FIXBRA
    CEFBS_None, // FIXR
    CEFBS_None, // FIXTR
    CEFBS_None, // FLOGR
    CEFBS_None, // HDR
    CEFBS_None, // HER
    CEFBS_None, // HSCH
    CEFBS_None, // IAC
    CEFBS_None, // IC
    CEFBS_None, // IC32
    CEFBS_None, // IC32Y
    CEFBS_None, // ICM
    CEFBS_None, // ICMH
    CEFBS_None, // ICMY
    CEFBS_None, // ICY
    CEFBS_None, // IDTE
    CEFBS_None, // IDTEOpt
    CEFBS_None, // IEDTR
    CEFBS_None, // IEXTR
    CEFBS_None, // IIHF
    CEFBS_None, // IIHH
    CEFBS_None, // IIHL
    CEFBS_None, // IILF
    CEFBS_None, // IILH
    CEFBS_None, // IILL
    CEFBS_None, // IPK
    CEFBS_None, // IPM
    CEFBS_None, // IPTE
    CEFBS_None, // IPTEOpt
    CEFBS_None, // IPTEOptOpt
    CEFBS_FeatureInsertReferenceBitsMultiple, // IRBM
    CEFBS_None, // ISKE
    CEFBS_None, // IVSK
    CEFBS_None, // InsnE
    CEFBS_None, // InsnRI
    CEFBS_None, // InsnRIE
    CEFBS_None, // InsnRIL
    CEFBS_None, // InsnRILU
    CEFBS_None, // InsnRIS
    CEFBS_None, // InsnRR
    CEFBS_None, // InsnRRE
    CEFBS_None, // InsnRRF
    CEFBS_None, // InsnRRS
    CEFBS_None, // InsnRS
    CEFBS_None, // InsnRSE
    CEFBS_None, // InsnRSI
    CEFBS_None, // InsnRSY
    CEFBS_None, // InsnRX
    CEFBS_None, // InsnRXE
    CEFBS_None, // InsnRXF
    CEFBS_None, // InsnRXY
    CEFBS_None, // InsnS
    CEFBS_None, // InsnSI
    CEFBS_None, // InsnSIL
    CEFBS_None, // InsnSIY
    CEFBS_None, // InsnSS
    CEFBS_None, // InsnSSE
    CEFBS_None, // InsnSSF
    CEFBS_None, // InsnVRI
    CEFBS_None, // InsnVRR
    CEFBS_None, // InsnVRS
    CEFBS_None, // InsnVRV
    CEFBS_None, // InsnVRX
    CEFBS_None, // InsnVSI
    CEFBS_None, // J
    CEFBS_None, // JAsmE
    CEFBS_None, // JAsmH
    CEFBS_None, // JAsmHE
    CEFBS_None, // JAsmL
    CEFBS_None, // JAsmLE
    CEFBS_None, // JAsmLH
    CEFBS_None, // JAsmM
    CEFBS_None, // JAsmNE
    CEFBS_None, // JAsmNH
    CEFBS_None, // JAsmNHE
    CEFBS_None, // JAsmNL
    CEFBS_None, // JAsmNLE
    CEFBS_None, // JAsmNLH
    CEFBS_None, // JAsmNM
    CEFBS_None, // JAsmNO
    CEFBS_None, // JAsmNP
    CEFBS_None, // JAsmNZ
    CEFBS_None, // JAsmO
    CEFBS_None, // JAsmP
    CEFBS_None, // JAsmZ
    CEFBS_None, // JG
    CEFBS_None, // JGAsmE
    CEFBS_None, // JGAsmH
    CEFBS_None, // JGAsmHE
    CEFBS_None, // JGAsmL
    CEFBS_None, // JGAsmLE
    CEFBS_None, // JGAsmLH
    CEFBS_None, // JGAsmM
    CEFBS_None, // JGAsmNE
    CEFBS_None, // JGAsmNH
    CEFBS_None, // JGAsmNHE
    CEFBS_None, // JGAsmNL
    CEFBS_None, // JGAsmNLE
    CEFBS_None, // JGAsmNLH
    CEFBS_None, // JGAsmNM
    CEFBS_None, // JGAsmNO
    CEFBS_None, // JGAsmNP
    CEFBS_None, // JGAsmNZ
    CEFBS_None, // JGAsmO
    CEFBS_None, // JGAsmP
    CEFBS_None, // JGAsmZ
    CEFBS_None, // JGNOP
    CEFBS_None, // JNOP
    CEFBS_None, // KDB
    CEFBS_None, // KDBR
    CEFBS_FeatureMessageSecurityAssist9, // KDSA
    CEFBS_None, // KDTR
    CEFBS_None, // KEB
    CEFBS_None, // KEBR
    CEFBS_None, // KIMD
    CEFBS_FeatureMessageSecurityAssist12, // KIMDOpt
    CEFBS_None, // KLMD
    CEFBS_FeatureMessageSecurityAssist12, // KLMDOpt
    CEFBS_None, // KM
    CEFBS_FeatureMessageSecurityAssist8, // KMA
    CEFBS_None, // KMAC
    CEFBS_None, // KMC
    CEFBS_FeatureMessageSecurityAssist4, // KMCTR
    CEFBS_FeatureMessageSecurityAssist4, // KMF
    CEFBS_FeatureMessageSecurityAssist4, // KMO
    CEFBS_None, // KXBR
    CEFBS_None, // KXTR
    CEFBS_None, // L
    CEFBS_None, // LA
    CEFBS_FeatureInterlockedAccess1, // LAA
    CEFBS_FeatureInterlockedAccess1, // LAAG
    CEFBS_FeatureInterlockedAccess1, // LAAL
    CEFBS_FeatureInterlockedAccess1, // LAALG
    CEFBS_None, // LAE
    CEFBS_None, // LAEY
    CEFBS_None, // LAM
    CEFBS_None, // LAMY
    CEFBS_FeatureInterlockedAccess1, // LAN
    CEFBS_FeatureInterlockedAccess1, // LANG
    CEFBS_FeatureInterlockedAccess1, // LAO
    CEFBS_FeatureInterlockedAccess1, // LAOG
    CEFBS_None, // LARL
    CEFBS_None, // LASP
    CEFBS_FeatureLoadAndTrap, // LAT
    CEFBS_FeatureInterlockedAccess1, // LAX
    CEFBS_FeatureInterlockedAccess1, // LAXG
    CEFBS_None, // LAY
    CEFBS_None, // LB
    CEFBS_FeatureBEAREnhancement, // LBEAR
    CEFBS_FeatureHighWord, // LBH
    CEFBS_None, // LBR
    CEFBS_FeatureVector, // LCBB
    CEFBS_None, // LCCTL
    CEFBS_None, // LCDBR
    CEFBS_None, // LCDFR
    CEFBS_None, // LCDFR_16
    CEFBS_None, // LCDFR_32
    CEFBS_None, // LCDR
    CEFBS_None, // LCEBR
    CEFBS_None, // LCER
    CEFBS_None, // LCGFR
    CEFBS_None, // LCGR
    CEFBS_None, // LCR
    CEFBS_None, // LCTL
    CEFBS_None, // LCTLG
    CEFBS_None, // LCXBR
    CEFBS_None, // LCXR
    CEFBS_None, // LD
    CEFBS_None, // LDE
    CEFBS_None, // LDE32
    CEFBS_None, // LDEB
    CEFBS_None, // LDEBR
    CEFBS_None, // LDER
    CEFBS_None, // LDETR
    CEFBS_None, // LDGR
    CEFBS_None, // LDR
    CEFBS_None, // LDR16
    CEFBS_None, // LDR32
    CEFBS_None, // LDXBR
    CEFBS_FeatureFPExtension, // LDXBRA
    CEFBS_None, // LDXR
    CEFBS_None, // LDXTR
    CEFBS_None, // LDY
    CEFBS_None, // LE
    CEFBS_None, // LE16
    CEFBS_None, // LE16Y
    CEFBS_None, // LEDBR
    CEFBS_FeatureFPExtension, // LEDBRA
    CEFBS_None, // LEDR
    CEFBS_None, // LEDTR
    CEFBS_None, // LER
    CEFBS_None, // LER16
    CEFBS_None, // LEXBR
    CEFBS_FeatureFPExtension, // LEXBRA
    CEFBS_None, // LEXR
    CEFBS_None, // LEY
    CEFBS_None, // LFAS
    CEFBS_FeatureHighWord, // LFH
    CEFBS_FeatureLoadAndTrap, // LFHAT
    CEFBS_None, // LFPC
    CEFBS_None, // LG
    CEFBS_FeatureLoadAndTrap, // LGAT
    CEFBS_None, // LGB
    CEFBS_None, // LGBR
    CEFBS_None, // LGDR
    CEFBS_None, // LGF
    CEFBS_None, // LGFI
    CEFBS_None, // LGFR
    CEFBS_None, // LGFRL
    CEFBS_FeatureGuardedStorage, // LGG
    CEFBS_None, // LGH
    CEFBS_None, // LGHI
    CEFBS_None, // LGHR
    CEFBS_None, // LGHRL
    CEFBS_None, // LGR
    CEFBS_None, // LGRL
    CEFBS_FeatureGuardedStorage, // LGSC
    CEFBS_None, // LH
    CEFBS_FeatureHighWord, // LHH
    CEFBS_None, // LHI
    CEFBS_None, // LHR
    CEFBS_None, // LHRL
    CEFBS_None, // LHY
    CEFBS_None, // LLC
    CEFBS_FeatureHighWord, // LLCH
    CEFBS_None, // LLCR
    CEFBS_None, // LLGC
    CEFBS_None, // LLGCR
    CEFBS_None, // LLGF
    CEFBS_FeatureLoadAndTrap, // LLGFAT
    CEFBS_None, // LLGFR
    CEFBS_None, // LLGFRL
    CEFBS_FeatureGuardedStorage, // LLGFSG
    CEFBS_None, // LLGH
    CEFBS_None, // LLGHR
    CEFBS_None, // LLGHRL
    CEFBS_None, // LLGT
    CEFBS_FeatureLoadAndTrap, // LLGTAT
    CEFBS_None, // LLGTR
    CEFBS_None, // LLH
    CEFBS_FeatureHighWord, // LLHH
    CEFBS_None, // LLHR
    CEFBS_None, // LLHRL
    CEFBS_None, // LLIHF
    CEFBS_None, // LLIHH
    CEFBS_None, // LLIHL
    CEFBS_None, // LLILF
    CEFBS_None, // LLILH
    CEFBS_None, // LLILL
    CEFBS_FeatureMiscellaneousExtensions4, // LLXAB
    CEFBS_FeatureMiscellaneousExtensions4, // LLXAF
    CEFBS_FeatureMiscellaneousExtensions4, // LLXAG
    CEFBS_FeatureMiscellaneousExtensions4, // LLXAH
    CEFBS_FeatureMiscellaneousExtensions4, // LLXAQ
    CEFBS_FeatureLoadAndZeroRightmostByte, // LLZRGF
    CEFBS_None, // LM
    CEFBS_None, // LMD
    CEFBS_None, // LMG
    CEFBS_None, // LMH
    CEFBS_None, // LMY
    CEFBS_None, // LNDBR
    CEFBS_None, // LNDFR
    CEFBS_None, // LNDFR_16
    CEFBS_None, // LNDFR_32
    CEFBS_None, // LNDR
    CEFBS_None, // LNEBR
    CEFBS_None, // LNER
    CEFBS_None, // LNGFR
    CEFBS_None, // LNGR
    CEFBS_None, // LNR
    CEFBS_None, // LNXBR
    CEFBS_None, // LNXR
    CEFBS_FeatureLoadStoreOnCond, // LOC
    CEFBS_FeatureLoadStoreOnCond, // LOCAsm
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmE
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmH
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmHE
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmL
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmLE
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmLH
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmM
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmNE
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmNH
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmNHE
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmNL
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmNLE
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmNLH
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmNM
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmNO
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmNP
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmNZ
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmO
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmP
    CEFBS_FeatureLoadStoreOnCond, // LOCAsmZ
    CEFBS_FeatureLoadStoreOnCond2, // LOCFH
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsm
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmH
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmHE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmL
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmLE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmLH
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmM
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmNE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmNH
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmNHE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmNL
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmNLE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmNLH
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmNM
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmNO
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmNP
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmNZ
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmO
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmP
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHAsmZ
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHR
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsm
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmH
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmHE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmL
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmLE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmLH
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmM
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmNE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmNH
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmNHE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmNL
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmNLE
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmNLH
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmNM
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmNO
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmNP
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmNZ
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmO
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmP
    CEFBS_FeatureLoadStoreOnCond2, // LOCFHRAsmZ
    CEFBS_FeatureLoadStoreOnCond, // LOCG
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsm
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmE
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmH
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmHE
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmL
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmLE
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmLH
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmM
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmNE
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmNH
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmNHE
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmNL
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmNLE
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmNLH
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmNM
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmNO
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmNP
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmNZ
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmO
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmP
    CEFBS_FeatureLoadStoreOnCond, // LOCGAsmZ
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHI
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsm
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmE
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmH
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmHE
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmL
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmLE
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmLH
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmM
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmNE
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmNH
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmNHE
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmNL
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmNLE
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmNLH
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmNM
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmNO
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmNP
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmNZ
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmO
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmP
    CEFBS_FeatureLoadStoreOnCond2, // LOCGHIAsmZ
    CEFBS_FeatureLoadStoreOnCond, // LOCGR
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsm
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmE
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmH
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmHE
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmL
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmLE
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmLH
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmM
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmNE
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmNH
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmNHE
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmNL
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmNLE
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmNLH
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmNM
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmNO
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmNP
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmNZ
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmO
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmP
    CEFBS_FeatureLoadStoreOnCond, // LOCGRAsmZ
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHI
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsm
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmH
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmHE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmL
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmLE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmLH
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmM
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmNE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmNH
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmNHE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmNL
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmNLE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmNLH
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmNM
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmNO
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmNP
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmNZ
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmO
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmP
    CEFBS_FeatureLoadStoreOnCond2, // LOCHHIAsmZ
    CEFBS_FeatureLoadStoreOnCond2, // LOCHI
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsm
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmH
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmHE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmL
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmLE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmLH
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmM
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmNE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmNH
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmNHE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmNL
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmNLE
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmNLH
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmNM
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmNO
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmNP
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmNZ
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmO
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmP
    CEFBS_FeatureLoadStoreOnCond2, // LOCHIAsmZ
    CEFBS_FeatureLoadStoreOnCond, // LOCR
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsm
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmE
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmH
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmHE
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmL
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmLE
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmLH
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmM
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmNE
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmNH
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmNHE
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmNL
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmNLE
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmNLH
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmNM
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmNO
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmNP
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmNZ
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmO
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmP
    CEFBS_FeatureLoadStoreOnCond, // LOCRAsmZ
    CEFBS_None, // LPCTL
    CEFBS_FeatureInterlockedAccess1, // LPD
    CEFBS_None, // LPDBR
    CEFBS_None, // LPDFR
    CEFBS_None, // LPDFR_16
    CEFBS_None, // LPDFR_32
    CEFBS_FeatureInterlockedAccess1, // LPDG
    CEFBS_None, // LPDR
    CEFBS_None, // LPEBR
    CEFBS_None, // LPER
    CEFBS_None, // LPGFR
    CEFBS_None, // LPGR
    CEFBS_None, // LPP
    CEFBS_None, // LPQ
    CEFBS_None, // LPR
    CEFBS_None, // LPSW
    CEFBS_None, // LPSWE
    CEFBS_FeatureBEAREnhancement, // LPSWEY
    CEFBS_None, // LPTEA
    CEFBS_None, // LPXBR
    CEFBS_None, // LPXR
    CEFBS_None, // LR
    CEFBS_None, // LRA
    CEFBS_None, // LRAG
    CEFBS_None, // LRAY
    CEFBS_None, // LRDR
    CEFBS_None, // LRER
    CEFBS_None, // LRL
    CEFBS_None, // LRV
    CEFBS_None, // LRVG
    CEFBS_None, // LRVGR
    CEFBS_None, // LRVH
    CEFBS_None, // LRVR
    CEFBS_None, // LSCTL
    CEFBS_None, // LT
    CEFBS_None, // LTDBR
    CEFBS_None, // LTDR
    CEFBS_None, // LTDTR
    CEFBS_None, // LTEBR
    CEFBS_None, // LTER
    CEFBS_None, // LTG
    CEFBS_None, // LTGF
    CEFBS_None, // LTGFR
    CEFBS_None, // LTGR
    CEFBS_None, // LTR
    CEFBS_None, // LTXBR
    CEFBS_None, // LTXR
    CEFBS_None, // LTXTR
    CEFBS_None, // LURA
    CEFBS_None, // LURAG
    CEFBS_FeatureMiscellaneousExtensions4, // LXAB
    CEFBS_FeatureMiscellaneousExtensions4, // LXAF
    CEFBS_FeatureMiscellaneousExtensions4, // LXAG
    CEFBS_FeatureMiscellaneousExtensions4, // LXAH
    CEFBS_FeatureMiscellaneousExtensions4, // LXAQ
    CEFBS_None, // LXD
    CEFBS_None, // LXDB
    CEFBS_None, // LXDBR
    CEFBS_None, // LXDR
    CEFBS_None, // LXDTR
    CEFBS_None, // LXE
    CEFBS_None, // LXEB
    CEFBS_None, // LXEBR
    CEFBS_None, // LXER
    CEFBS_None, // LXR
    CEFBS_None, // LY
    CEFBS_None, // LZDR
    CEFBS_None, // LZER
    CEFBS_None, // LZER_16
    CEFBS_FeatureLoadAndZeroRightmostByte, // LZRF
    CEFBS_FeatureLoadAndZeroRightmostByte, // LZRG
    CEFBS_None, // LZXR
    CEFBS_None, // M
    CEFBS_None, // MAD
    CEFBS_None, // MADB
    CEFBS_None, // MADBR
    CEFBS_None, // MADR
    CEFBS_None, // MAE
    CEFBS_None, // MAEB
    CEFBS_None, // MAEBR
    CEFBS_None, // MAER
    CEFBS_None, // MAY
    CEFBS_None, // MAYH
    CEFBS_None, // MAYHR
    CEFBS_None, // MAYL
    CEFBS_None, // MAYLR
    CEFBS_None, // MAYR
    CEFBS_None, // MC
    CEFBS_None, // MD
    CEFBS_None, // MDB
    CEFBS_None, // MDBR
    CEFBS_None, // MDE
    CEFBS_None, // MDEB
    CEFBS_None, // MDEBR
    CEFBS_None, // MDER
    CEFBS_None, // MDR
    CEFBS_None, // MDTR
    CEFBS_FeatureFPExtension, // MDTRA
    CEFBS_None, // ME
    CEFBS_None, // MEE
    CEFBS_None, // MEEB
    CEFBS_None, // MEEBR
    CEFBS_None, // MEER
    CEFBS_None, // MER
    CEFBS_None, // MFY
    CEFBS_FeatureMiscellaneousExtensions2, // MG
    CEFBS_FeatureMiscellaneousExtensions2, // MGH
    CEFBS_None, // MGHI
    CEFBS_FeatureMiscellaneousExtensions2, // MGRK
    CEFBS_None, // MH
    CEFBS_None, // MHI
    CEFBS_None, // MHY
    CEFBS_None, // ML
    CEFBS_None, // MLG
    CEFBS_None, // MLGR
    CEFBS_None, // MLR
    CEFBS_None, // MP
    CEFBS_None, // MR
    CEFBS_None, // MS
    CEFBS_FeatureMiscellaneousExtensions2, // MSC
    CEFBS_None, // MSCH
    CEFBS_None, // MSD
    CEFBS_None, // MSDB
    CEFBS_None, // MSDBR
    CEFBS_None, // MSDR
    CEFBS_None, // MSE
    CEFBS_None, // MSEB
    CEFBS_None, // MSEBR
    CEFBS_None, // MSER
    CEFBS_None, // MSFI
    CEFBS_None, // MSG
    CEFBS_FeatureMiscellaneousExtensions2, // MSGC
    CEFBS_None, // MSGF
    CEFBS_None, // MSGFI
    CEFBS_None, // MSGFR
    CEFBS_None, // MSGR
    CEFBS_FeatureMiscellaneousExtensions2, // MSGRKC
    CEFBS_None, // MSR
    CEFBS_FeatureMiscellaneousExtensions2, // MSRKC
    CEFBS_None, // MSTA
    CEFBS_None, // MSY
    CEFBS_None, // MVC
    CEFBS_None, // MVCDK
    CEFBS_None, // MVCIN
    CEFBS_None, // MVCK
    CEFBS_None, // MVCL
    CEFBS_None, // MVCLE
    CEFBS_None, // MVCLU
    CEFBS_None, // MVCOS
    CEFBS_None, // MVCP
    CEFBS_FeatureMiscellaneousExtensions3, // MVCRL
    CEFBS_None, // MVCS
    CEFBS_None, // MVCSK
    CEFBS_None, // MVGHI
    CEFBS_None, // MVHHI
    CEFBS_None, // MVHI
    CEFBS_None, // MVI
    CEFBS_None, // MVIY
    CEFBS_None, // MVN
    CEFBS_None, // MVO
    CEFBS_None, // MVPG
    CEFBS_None, // MVST
    CEFBS_None, // MVZ
    CEFBS_None, // MXBR
    CEFBS_None, // MXD
    CEFBS_None, // MXDB
    CEFBS_None, // MXDBR
    CEFBS_None, // MXDR
    CEFBS_None, // MXR
    CEFBS_None, // MXTR
    CEFBS_FeatureFPExtension, // MXTRA
    CEFBS_None, // MY
    CEFBS_None, // MYH
    CEFBS_None, // MYHR
    CEFBS_None, // MYL
    CEFBS_None, // MYLR
    CEFBS_None, // MYR
    CEFBS_None, // N
    CEFBS_None, // NC
    CEFBS_FeatureMiscellaneousExtensions3, // NCGRK
    CEFBS_FeatureMiscellaneousExtensions3, // NCRK
    CEFBS_None, // NG
    CEFBS_None, // NGR
    CEFBS_FeatureDistinctOps, // NGRK
    CEFBS_None, // NI
    CEFBS_FeatureExecutionHint, // NIAI
    CEFBS_None, // NIHF
    CEFBS_None, // NIHH
    CEFBS_None, // NIHL
    CEFBS_None, // NILF
    CEFBS_None, // NILH
    CEFBS_None, // NILL
    CEFBS_None, // NIY
    CEFBS_FeatureMiscellaneousExtensions3, // NNGRK
    CEFBS_FeatureNNPAssist, // NNPA
    CEFBS_FeatureMiscellaneousExtensions3, // NNRK
    CEFBS_FeatureMiscellaneousExtensions3, // NOGRK
    CEFBS_None, // NOP
    CEFBS_None, // NOPOpt
    CEFBS_None, // NOPR
    CEFBS_None, // NOPROpt
    CEFBS_FeatureMiscellaneousExtensions3, // NORK
    CEFBS_FeatureMiscellaneousExtensions3, // NOTGR
    CEFBS_FeatureMiscellaneousExtensions3, // NOTR
    CEFBS_None, // NR
    CEFBS_FeatureDistinctOps, // NRK
    CEFBS_FeatureTransactionalExecution, // NTSTG
    CEFBS_FeatureMiscellaneousExtensions3, // NXGRK
    CEFBS_FeatureMiscellaneousExtensions3, // NXRK
    CEFBS_None, // NY
    CEFBS_None, // O
    CEFBS_None, // OC
    CEFBS_FeatureMiscellaneousExtensions3, // OCGRK
    CEFBS_FeatureMiscellaneousExtensions3, // OCRK
    CEFBS_None, // OG
    CEFBS_None, // OGR
    CEFBS_FeatureDistinctOps, // OGRK
    CEFBS_None, // OI
    CEFBS_None, // OIHF
    CEFBS_None, // OIHH
    CEFBS_None, // OIHL
    CEFBS_None, // OILF
    CEFBS_None, // OILH
    CEFBS_None, // OILL
    CEFBS_None, // OIY
    CEFBS_None, // OR
    CEFBS_FeatureDistinctOps, // ORK
    CEFBS_None, // OY
    CEFBS_None, // PACK
    CEFBS_None, // PALB
    CEFBS_None, // PC
    CEFBS_FeatureMessageSecurityAssist4, // PCC
    CEFBS_FeatureMessageSecurityAssist3, // PCKMO
    CEFBS_FeatureConcurrentFunctions, // PFCR
    CEFBS_None, // PFD
    CEFBS_None, // PFDRL
    CEFBS_None, // PFMF
    CEFBS_None, // PFPO
    CEFBS_None, // PGIN
    CEFBS_None, // PGOUT
    CEFBS_None, // PKA
    CEFBS_None, // PKU
    CEFBS_None, // PLO
    CEFBS_FeaturePopulationCount, // POPCNT
    CEFBS_FeatureMiscellaneousExtensions3, // POPCNTOpt
    CEFBS_FeatureProcessorAssist, // PPA
    CEFBS_FeatureMessageSecurityAssist5, // PPNO
    CEFBS_None, // PR
    CEFBS_FeatureMessageSecurityAssist7, // PRNO
    CEFBS_None, // PT
    CEFBS_None, // PTF
    CEFBS_None, // PTFF
    CEFBS_None, // PTI
    CEFBS_None, // PTLB
    CEFBS_None, // QADTR
    CEFBS_None, // QAXTR
    CEFBS_None, // QCTRI
    CEFBS_FeatureProcessorActivityInstrumentation, // QPACI
    CEFBS_None, // QSI
    CEFBS_None, // RCHP
    CEFBS_FeatureResetDATProtection, // RDP
    CEFBS_FeatureResetDATProtection, // RDPOpt
    CEFBS_None, // RISBG
    CEFBS_None, // RISBG32
    CEFBS_None, // RISBG32Opt
    CEFBS_FeatureMiscellaneousExtensions, // RISBGN
    CEFBS_FeatureMiscellaneousExtensions, // RISBGNOpt
    CEFBS_FeatureMiscellaneousExtensions, // RISBGNZ
    CEFBS_FeatureMiscellaneousExtensions, // RISBGNZOpt
    CEFBS_None, // RISBGOpt
    CEFBS_None, // RISBGZ
    CEFBS_None, // RISBGZOpt
    CEFBS_FeatureHighWord, // RISBHG
    CEFBS_FeatureHighWord, // RISBHGOpt
    CEFBS_FeatureHighWord, // RISBLG
    CEFBS_FeatureHighWord, // RISBLGOpt
    CEFBS_None, // RLL
    CEFBS_None, // RLLG
    CEFBS_None, // RNSBG
    CEFBS_None, // RNSBGOpt
    CEFBS_None, // ROSBG
    CEFBS_None, // ROSBGOpt
    CEFBS_None, // RP
    CEFBS_None, // RRBE
    CEFBS_FeatureResetReferenceBitsMultiple, // RRBM
    CEFBS_None, // RRDTR
    CEFBS_None, // RRXTR
    CEFBS_None, // RSCH
    CEFBS_None, // RXSBG
    CEFBS_None, // RXSBGOpt
    CEFBS_None, // S
    CEFBS_None, // SAC
    CEFBS_None, // SACF
    CEFBS_None, // SAL
    CEFBS_None, // SAM24
    CEFBS_None, // SAM31
    CEFBS_None, // SAM64
    CEFBS_None, // SAR
    CEFBS_None, // SCCTR
    CEFBS_None, // SCHM
    CEFBS_None, // SCK
    CEFBS_None, // SCKC
    CEFBS_None, // SCKPF
    CEFBS_None, // SD
    CEFBS_None, // SDB
    CEFBS_None, // SDBR
    CEFBS_None, // SDR
    CEFBS_None, // SDTR
    CEFBS_FeatureFPExtension, // SDTRA
    CEFBS_None, // SE
    CEFBS_None, // SEB
    CEFBS_None, // SEBR
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHR
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsm
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmE
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmH
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmHE
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmL
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmLE
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmLH
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmM
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmNE
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmNH
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmNHE
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmNL
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmNLE
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmNLH
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmNM
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmNO
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmNP
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmNZ
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmO
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmP
    CEFBS_FeatureMiscellaneousExtensions3, // SELFHRAsmZ
    CEFBS_FeatureMiscellaneousExtensions3, // SELGR
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsm
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmE
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmH
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmHE
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmL
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmLE
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmLH
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmM
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmNE
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmNH
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmNHE
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmNL
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmNLE
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmNLH
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmNM
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmNO
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmNP
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmNZ
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmO
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmP
    CEFBS_FeatureMiscellaneousExtensions3, // SELGRAsmZ
    CEFBS_FeatureMiscellaneousExtensions3, // SELR
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsm
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmE
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmH
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmHE
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmL
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmLE
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmLH
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmM
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmNE
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmNH
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmNHE
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmNL
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmNLE
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmNLH
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmNM
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmNO
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmNP
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmNZ
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmO
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmP
    CEFBS_FeatureMiscellaneousExtensions3, // SELRAsmZ
    CEFBS_None, // SER
    CEFBS_None, // SFASR
    CEFBS_None, // SFPC
    CEFBS_None, // SG
    CEFBS_None, // SGF
    CEFBS_None, // SGFR
    CEFBS_FeatureMiscellaneousExtensions2, // SGH
    CEFBS_None, // SGR
    CEFBS_FeatureDistinctOps, // SGRK
    CEFBS_None, // SH
    CEFBS_FeatureHighWord, // SHHHR
    CEFBS_FeatureHighWord, // SHHLR
    CEFBS_None, // SHY
    CEFBS_None, // SIE
    CEFBS_None, // SIGA
    CEFBS_None, // SIGP
    CEFBS_None, // SL
    CEFBS_None, // SLA
    CEFBS_None, // SLAG
    CEFBS_FeatureDistinctOps, // SLAK
    CEFBS_None, // SLB
    CEFBS_None, // SLBG
    CEFBS_None, // SLBGR
    CEFBS_None, // SLBR
    CEFBS_None, // SLDA
    CEFBS_None, // SLDL
    CEFBS_None, // SLDT
    CEFBS_None, // SLFI
    CEFBS_None, // SLG
    CEFBS_None, // SLGF
    CEFBS_None, // SLGFI
    CEFBS_None, // SLGFR
    CEFBS_None, // SLGR
    CEFBS_FeatureDistinctOps, // SLGRK
    CEFBS_FeatureHighWord, // SLHHHR
    CEFBS_FeatureHighWord, // SLHHLR
    CEFBS_None, // SLL
    CEFBS_None, // SLLG
    CEFBS_FeatureDistinctOps, // SLLK
    CEFBS_None, // SLR
    CEFBS_FeatureDistinctOps, // SLRK
    CEFBS_None, // SLXT
    CEFBS_None, // SLY
    CEFBS_FeatureEnhancedSort, // SORTL
    CEFBS_None, // SP
    CEFBS_None, // SPCTR
    CEFBS_None, // SPKA
    CEFBS_None, // SPM
    CEFBS_None, // SPT
    CEFBS_None, // SPX
    CEFBS_None, // SQD
    CEFBS_None, // SQDB
    CEFBS_None, // SQDBR
    CEFBS_None, // SQDR
    CEFBS_None, // SQE
    CEFBS_None, // SQEB
    CEFBS_None, // SQEBR
    CEFBS_None, // SQER
    CEFBS_None, // SQXBR
    CEFBS_None, // SQXR
    CEFBS_None, // SR
    CEFBS_None, // SRA
    CEFBS_None, // SRAG
    CEFBS_FeatureDistinctOps, // SRAK
    CEFBS_None, // SRDA
    CEFBS_None, // SRDL
    CEFBS_None, // SRDT
    CEFBS_FeatureDistinctOps, // SRK
    CEFBS_None, // SRL
    CEFBS_None, // SRLG
    CEFBS_FeatureDistinctOps, // SRLK
    CEFBS_None, // SRNM
    CEFBS_FeatureFPExtension, // SRNMB
    CEFBS_None, // SRNMT
    CEFBS_None, // SRP
    CEFBS_None, // SRST
    CEFBS_None, // SRSTU
    CEFBS_None, // SRXT
    CEFBS_None, // SSAIR
    CEFBS_None, // SSAR
    CEFBS_None, // SSCH
    CEFBS_None, // SSKE
    CEFBS_None, // SSKEOpt
    CEFBS_None, // SSM
    CEFBS_None, // ST
    CEFBS_None, // STAM
    CEFBS_None, // STAMY
    CEFBS_None, // STAP
    CEFBS_FeatureBEAREnhancement, // STBEAR
    CEFBS_None, // STC
    CEFBS_FeatureHighWord, // STCH
    CEFBS_None, // STCK
    CEFBS_None, // STCKC
    CEFBS_None, // STCKE
    CEFBS_None, // STCKF
    CEFBS_None, // STCM
    CEFBS_None, // STCMH
    CEFBS_None, // STCMY
    CEFBS_None, // STCPS
    CEFBS_None, // STCRW
    CEFBS_None, // STCTG
    CEFBS_None, // STCTL
    CEFBS_None, // STCY
    CEFBS_None, // STD
    CEFBS_None, // STDY
    CEFBS_None, // STE
    CEFBS_None, // STE16
    CEFBS_None, // STE16Y
    CEFBS_None, // STEY
    CEFBS_FeatureHighWord, // STFH
    CEFBS_None, // STFL
    CEFBS_None, // STFLE
    CEFBS_None, // STFPC
    CEFBS_None, // STG
    CEFBS_None, // STGRL
    CEFBS_FeatureGuardedStorage, // STGSC
    CEFBS_None, // STH
    CEFBS_FeatureHighWord, // STHH
    CEFBS_None, // STHRL
    CEFBS_None, // STHY
    CEFBS_None, // STIDP
    CEFBS_None, // STM
    CEFBS_None, // STMG
    CEFBS_None, // STMH
    CEFBS_None, // STMY
    CEFBS_None, // STNSM
    CEFBS_FeatureLoadStoreOnCond, // STOC
    CEFBS_FeatureLoadStoreOnCond, // STOCAsm
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmE
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmH
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmHE
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmL
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmLE
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmLH
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmM
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmNE
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmNH
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmNHE
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmNL
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmNLE
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmNLH
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmNM
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmNO
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmNP
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmNZ
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmO
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmP
    CEFBS_FeatureLoadStoreOnCond, // STOCAsmZ
    CEFBS_FeatureLoadStoreOnCond2, // STOCFH
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsm
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmE
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmH
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmHE
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmL
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmLE
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmLH
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmM
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmNE
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmNH
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmNHE
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmNL
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmNLE
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmNLH
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmNM
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmNO
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmNP
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmNZ
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmO
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmP
    CEFBS_FeatureLoadStoreOnCond2, // STOCFHAsmZ
    CEFBS_FeatureLoadStoreOnCond, // STOCG
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsm
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmE
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmH
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmHE
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmL
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmLE
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmLH
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmM
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmNE
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmNH
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmNHE
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmNL
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmNLE
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmNLH
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmNM
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmNO
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmNP
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmNZ
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmO
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmP
    CEFBS_FeatureLoadStoreOnCond, // STOCGAsmZ
    CEFBS_None, // STOSM
    CEFBS_None, // STPQ
    CEFBS_None, // STPT
    CEFBS_None, // STPX
    CEFBS_None, // STRAG
    CEFBS_None, // STRL
    CEFBS_None, // STRV
    CEFBS_None, // STRVG
    CEFBS_None, // STRVH
    CEFBS_None, // STSCH
    CEFBS_None, // STSI
    CEFBS_None, // STURA
    CEFBS_None, // STURG
    CEFBS_None, // STY
    CEFBS_None, // SU
    CEFBS_None, // SUR
    CEFBS_None, // SVC
    CEFBS_None, // SW
    CEFBS_None, // SWR
    CEFBS_None, // SXBR
    CEFBS_None, // SXR
    CEFBS_None, // SXTR
    CEFBS_FeatureFPExtension, // SXTRA
    CEFBS_None, // SY
    CEFBS_FeatureTransactionalExecution, // TABORT
    CEFBS_None, // TAM
    CEFBS_None, // TAR
    CEFBS_None, // TB
    CEFBS_None, // TBDR
    CEFBS_None, // TBEDR
    CEFBS_FeatureTransactionalExecution, // TBEGIN
    CEFBS_FeatureTransactionalExecution, // TBEGINC
    CEFBS_None, // TCDB
    CEFBS_None, // TCEB
    CEFBS_None, // TCXB
    CEFBS_None, // TDCDT
    CEFBS_None, // TDCET
    CEFBS_None, // TDCXT
    CEFBS_None, // TDGDT
    CEFBS_None, // TDGET
    CEFBS_None, // TDGXT
    CEFBS_FeatureTransactionalExecution, // TEND
    CEFBS_None, // THDER
    CEFBS_None, // THDR
    CEFBS_None, // TM
    CEFBS_None, // TMHH
    CEFBS_None, // TMHL
    CEFBS_None, // TMLH
    CEFBS_None, // TMLL
    CEFBS_None, // TMY
    CEFBS_None, // TP
    CEFBS_FeatureTestPendingExternalInterruption, // TPEI
    CEFBS_None, // TPI
    CEFBS_None, // TPROT
    CEFBS_None, // TR
    CEFBS_None, // TRACE
    CEFBS_None, // TRACG
    CEFBS_None, // TRAP2
    CEFBS_None, // TRAP4
    CEFBS_None, // TRE
    CEFBS_None, // TROO
    CEFBS_None, // TROOOpt
    CEFBS_None, // TROT
    CEFBS_None, // TROTOpt
    CEFBS_None, // TRT
    CEFBS_None, // TRTE
    CEFBS_None, // TRTEOpt
    CEFBS_None, // TRTO
    CEFBS_None, // TRTOOpt
    CEFBS_None, // TRTR
    CEFBS_None, // TRTRE
    CEFBS_None, // TRTREOpt
    CEFBS_None, // TRTT
    CEFBS_None, // TRTTOpt
    CEFBS_None, // TS
    CEFBS_None, // TSCH
    CEFBS_None, // UNPK
    CEFBS_None, // UNPKA
    CEFBS_None, // UNPKU
    CEFBS_None, // UPT
    CEFBS_FeatureVector, // VA
    CEFBS_FeatureVector, // VAB
    CEFBS_FeatureVector, // VAC
    CEFBS_FeatureVector, // VACC
    CEFBS_FeatureVector, // VACCB
    CEFBS_FeatureVector, // VACCC
    CEFBS_FeatureVector, // VACCCQ
    CEFBS_FeatureVector, // VACCF
    CEFBS_FeatureVector, // VACCG
    CEFBS_FeatureVector, // VACCH
    CEFBS_FeatureVector, // VACCQ
    CEFBS_FeatureVector, // VACQ
    CEFBS_FeatureVector, // VAF
    CEFBS_FeatureVector, // VAG
    CEFBS_FeatureVector, // VAH
    CEFBS_FeatureVectorPackedDecimal, // VAP
    CEFBS_FeatureVector, // VAQ
    CEFBS_FeatureVector, // VAVG
    CEFBS_FeatureVector, // VAVGB
    CEFBS_FeatureVector, // VAVGF
    CEFBS_FeatureVector, // VAVGG
    CEFBS_FeatureVector, // VAVGH
    CEFBS_FeatureVector, // VAVGL
    CEFBS_FeatureVector, // VAVGLB
    CEFBS_FeatureVector, // VAVGLF
    CEFBS_FeatureVector, // VAVGLG
    CEFBS_FeatureVector, // VAVGLH
    CEFBS_FeatureVectorEnhancements3, // VAVGLQ
    CEFBS_FeatureVectorEnhancements3, // VAVGQ
    CEFBS_FeatureVectorEnhancements3, // VBLEND
    CEFBS_FeatureVectorEnhancements3, // VBLENDB
    CEFBS_FeatureVectorEnhancements3, // VBLENDF
    CEFBS_FeatureVectorEnhancements3, // VBLENDG
    CEFBS_FeatureVectorEnhancements3, // VBLENDH
    CEFBS_FeatureVectorEnhancements3, // VBLENDQ
    CEFBS_FeatureVectorEnhancements1, // VBPERM
    CEFBS_FeatureVector, // VCDG
    CEFBS_FeatureVector, // VCDGB
    CEFBS_FeatureVector, // VCDLG
    CEFBS_FeatureVector, // VCDLGB
    CEFBS_FeatureVectorEnhancements2, // VCEFB
    CEFBS_FeatureVectorEnhancements2, // VCELFB
    CEFBS_FeatureVector, // VCEQ
    CEFBS_FeatureVector, // VCEQB
    CEFBS_FeatureVector, // VCEQBS
    CEFBS_FeatureVector, // VCEQF
    CEFBS_FeatureVector, // VCEQFS
    CEFBS_FeatureVector, // VCEQG
    CEFBS_FeatureVector, // VCEQGS
    CEFBS_FeatureVector, // VCEQH
    CEFBS_FeatureVector, // VCEQHS
    CEFBS_FeatureVectorEnhancements3, // VCEQQ
    CEFBS_FeatureVectorEnhancements3, // VCEQQS
    CEFBS_FeatureVectorEnhancements2, // VCFEB
    CEFBS_FeatureVector_FeatureNNPAssist, // VCFN
    CEFBS_FeatureVectorEnhancements2, // VCFPL
    CEFBS_FeatureVectorEnhancements2, // VCFPS
    CEFBS_FeatureVector, // VCGD
    CEFBS_FeatureVector, // VCGDB
    CEFBS_FeatureVector, // VCH
    CEFBS_FeatureVector, // VCHB
    CEFBS_FeatureVector, // VCHBS
    CEFBS_FeatureVector, // VCHF
    CEFBS_FeatureVector, // VCHFS
    CEFBS_FeatureVector, // VCHG
    CEFBS_FeatureVector, // VCHGS
    CEFBS_FeatureVector, // VCHH
    CEFBS_FeatureVector, // VCHHS
    CEFBS_FeatureVector, // VCHL
    CEFBS_FeatureVector, // VCHLB
    CEFBS_FeatureVector, // VCHLBS
    CEFBS_FeatureVector, // VCHLF
    CEFBS_FeatureVector, // VCHLFS
    CEFBS_FeatureVector, // VCHLG
    CEFBS_FeatureVector, // VCHLGS
    CEFBS_FeatureVector, // VCHLH
    CEFBS_FeatureVector, // VCHLHS
    CEFBS_FeatureVectorEnhancements3, // VCHLQ
    CEFBS_FeatureVectorEnhancements3, // VCHLQS
    CEFBS_FeatureVectorEnhancements3, // VCHQ
    CEFBS_FeatureVectorEnhancements3, // VCHQS
    CEFBS_FeatureVector, // VCKSM
    CEFBS_FeatureVectorEnhancements2, // VCLFEB
    CEFBS_FeatureVector_FeatureNNPAssist, // VCLFNH
    CEFBS_FeatureVector_FeatureNNPAssist, // VCLFNL
    CEFBS_FeatureVectorEnhancements2, // VCLFP
    CEFBS_FeatureVector, // VCLGD
    CEFBS_FeatureVector, // VCLGDB
    CEFBS_FeatureVector, // VCLZ
    CEFBS_FeatureVector, // VCLZB
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VCLZDP
    CEFBS_FeatureVector, // VCLZF
    CEFBS_FeatureVector, // VCLZG
    CEFBS_FeatureVector, // VCLZH
    CEFBS_FeatureVectorEnhancements3, // VCLZQ
    CEFBS_FeatureVector_FeatureNNPAssist, // VCNF
    CEFBS_FeatureVectorPackedDecimal, // VCP
    CEFBS_FeatureVector_FeatureNNPAssist, // VCRNF
    CEFBS_FeatureVectorEnhancements2, // VCSFP
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VCSPH
    CEFBS_FeatureVector, // VCTZ
    CEFBS_FeatureVector, // VCTZB
    CEFBS_FeatureVector, // VCTZF
    CEFBS_FeatureVector, // VCTZG
    CEFBS_FeatureVector, // VCTZH
    CEFBS_FeatureVectorEnhancements3, // VCTZQ
    CEFBS_FeatureVectorPackedDecimal, // VCVB
    CEFBS_FeatureVectorPackedDecimal, // VCVBG
    CEFBS_FeatureVectorPackedDecimalEnhancement, // VCVBGOpt
    CEFBS_FeatureVectorPackedDecimalEnhancement, // VCVBOpt
    CEFBS_FeatureVectorPackedDecimalEnhancement3, // VCVBQ
    CEFBS_FeatureVectorPackedDecimal, // VCVD
    CEFBS_FeatureVectorPackedDecimal, // VCVDG
    CEFBS_FeatureVectorPackedDecimalEnhancement3, // VCVDQ
    CEFBS_FeatureVectorEnhancements3, // VD
    CEFBS_FeatureVectorEnhancements3, // VDF
    CEFBS_FeatureVectorEnhancements3, // VDG
    CEFBS_FeatureVectorEnhancements3, // VDL
    CEFBS_FeatureVectorEnhancements3, // VDLF
    CEFBS_FeatureVectorEnhancements3, // VDLG
    CEFBS_FeatureVectorEnhancements3, // VDLQ
    CEFBS_FeatureVectorPackedDecimal, // VDP
    CEFBS_FeatureVectorEnhancements3, // VDQ
    CEFBS_FeatureVector, // VEC
    CEFBS_FeatureVector, // VECB
    CEFBS_FeatureVector, // VECF
    CEFBS_FeatureVector, // VECG
    CEFBS_FeatureVector, // VECH
    CEFBS_FeatureVector, // VECL
    CEFBS_FeatureVector, // VECLB
    CEFBS_FeatureVector, // VECLF
    CEFBS_FeatureVector, // VECLG
    CEFBS_FeatureVector, // VECLH
    CEFBS_FeatureVectorEnhancements3, // VECLQ
    CEFBS_FeatureVectorEnhancements3, // VECQ
    CEFBS_FeatureVector, // VERIM
    CEFBS_FeatureVector, // VERIMB
    CEFBS_FeatureVector, // VERIMF
    CEFBS_FeatureVector, // VERIMG
    CEFBS_FeatureVector, // VERIMH
    CEFBS_FeatureVector, // VERLL
    CEFBS_FeatureVector, // VERLLB
    CEFBS_FeatureVector, // VERLLF
    CEFBS_FeatureVector, // VERLLG
    CEFBS_FeatureVector, // VERLLH
    CEFBS_FeatureVector, // VERLLV
    CEFBS_FeatureVector, // VERLLVB
    CEFBS_FeatureVector, // VERLLVF
    CEFBS_FeatureVector, // VERLLVG
    CEFBS_FeatureVector, // VERLLVH
    CEFBS_FeatureVector, // VESL
    CEFBS_FeatureVector, // VESLB
    CEFBS_FeatureVector, // VESLF
    CEFBS_FeatureVector, // VESLG
    CEFBS_FeatureVector, // VESLH
    CEFBS_FeatureVector, // VESLV
    CEFBS_FeatureVector, // VESLVB
    CEFBS_FeatureVector, // VESLVF
    CEFBS_FeatureVector, // VESLVG
    CEFBS_FeatureVector, // VESLVH
    CEFBS_FeatureVector, // VESRA
    CEFBS_FeatureVector, // VESRAB
    CEFBS_FeatureVector, // VESRAF
    CEFBS_FeatureVector, // VESRAG
    CEFBS_FeatureVector, // VESRAH
    CEFBS_FeatureVector, // VESRAV
    CEFBS_FeatureVector, // VESRAVB
    CEFBS_FeatureVector, // VESRAVF
    CEFBS_FeatureVector, // VESRAVG
    CEFBS_FeatureVector, // VESRAVH
    CEFBS_FeatureVector, // VESRL
    CEFBS_FeatureVector, // VESRLB
    CEFBS_FeatureVector, // VESRLF
    CEFBS_FeatureVector, // VESRLG
    CEFBS_FeatureVector, // VESRLH
    CEFBS_FeatureVector, // VESRLV
    CEFBS_FeatureVector, // VESRLVB
    CEFBS_FeatureVector, // VESRLVF
    CEFBS_FeatureVector, // VESRLVG
    CEFBS_FeatureVector, // VESRLVH
    CEFBS_FeatureVectorEnhancements3, // VEVAL
    CEFBS_FeatureVector, // VFA
    CEFBS_FeatureVector, // VFADB
    CEFBS_FeatureVector, // VFAE
    CEFBS_FeatureVector, // VFAEB
    CEFBS_FeatureVector, // VFAEBS
    CEFBS_FeatureVector, // VFAEF
    CEFBS_FeatureVector, // VFAEFS
    CEFBS_FeatureVector, // VFAEH
    CEFBS_FeatureVector, // VFAEHS
    CEFBS_FeatureVector, // VFAEZB
    CEFBS_FeatureVector, // VFAEZBS
    CEFBS_FeatureVector, // VFAEZF
    CEFBS_FeatureVector, // VFAEZFS
    CEFBS_FeatureVector, // VFAEZH
    CEFBS_FeatureVector, // VFAEZHS
    CEFBS_FeatureVectorEnhancements1, // VFASB
    CEFBS_FeatureVector, // VFCE
    CEFBS_FeatureVector, // VFCEDB
    CEFBS_FeatureVector, // VFCEDBS
    CEFBS_FeatureVectorEnhancements1, // VFCESB
    CEFBS_FeatureVectorEnhancements1, // VFCESBS
    CEFBS_FeatureVector, // VFCH
    CEFBS_FeatureVector, // VFCHDB
    CEFBS_FeatureVector, // VFCHDBS
    CEFBS_FeatureVector, // VFCHE
    CEFBS_FeatureVector, // VFCHEDB
    CEFBS_FeatureVector, // VFCHEDBS
    CEFBS_FeatureVectorEnhancements1, // VFCHESB
    CEFBS_FeatureVectorEnhancements1, // VFCHESBS
    CEFBS_FeatureVectorEnhancements1, // VFCHSB
    CEFBS_FeatureVectorEnhancements1, // VFCHSBS
    CEFBS_FeatureVector, // VFD
    CEFBS_FeatureVector, // VFDDB
    CEFBS_FeatureVectorEnhancements1, // VFDSB
    CEFBS_FeatureVector, // VFEE
    CEFBS_FeatureVector, // VFEEB
    CEFBS_FeatureVector, // VFEEBS
    CEFBS_FeatureVector, // VFEEF
    CEFBS_FeatureVector, // VFEEFS
    CEFBS_FeatureVector, // VFEEH
    CEFBS_FeatureVector, // VFEEHS
    CEFBS_FeatureVector, // VFEEZB
    CEFBS_FeatureVector, // VFEEZBS
    CEFBS_FeatureVector, // VFEEZF
    CEFBS_FeatureVector, // VFEEZFS
    CEFBS_FeatureVector, // VFEEZH
    CEFBS_FeatureVector, // VFEEZHS
    CEFBS_FeatureVector, // VFENE
    CEFBS_FeatureVector, // VFENEB
    CEFBS_FeatureVector, // VFENEBS
    CEFBS_FeatureVector, // VFENEF
    CEFBS_FeatureVector, // VFENEFS
    CEFBS_FeatureVector, // VFENEH
    CEFBS_FeatureVector, // VFENEHS
    CEFBS_FeatureVector, // VFENEZB
    CEFBS_FeatureVector, // VFENEZBS
    CEFBS_FeatureVector, // VFENEZF
    CEFBS_FeatureVector, // VFENEZFS
    CEFBS_FeatureVector, // VFENEZH
    CEFBS_FeatureVector, // VFENEZHS
    CEFBS_FeatureVector, // VFI
    CEFBS_FeatureVector, // VFIDB
    CEFBS_FeatureVectorEnhancements1, // VFISB
    CEFBS_FeatureVectorEnhancements1, // VFKEDB
    CEFBS_FeatureVectorEnhancements1, // VFKEDBS
    CEFBS_FeatureVectorEnhancements1, // VFKESB
    CEFBS_FeatureVectorEnhancements1, // VFKESBS
    CEFBS_FeatureVectorEnhancements1, // VFKHDB
    CEFBS_FeatureVectorEnhancements1, // VFKHDBS
    CEFBS_FeatureVectorEnhancements1, // VFKHEDB
    CEFBS_FeatureVectorEnhancements1, // VFKHEDBS
    CEFBS_FeatureVectorEnhancements1, // VFKHESB
    CEFBS_FeatureVectorEnhancements1, // VFKHESBS
    CEFBS_FeatureVectorEnhancements1, // VFKHSB
    CEFBS_FeatureVectorEnhancements1, // VFKHSBS
    CEFBS_FeatureVector, // VFLCDB
    CEFBS_FeatureVectorEnhancements1, // VFLCSB
    CEFBS_FeatureVectorEnhancements1, // VFLL
    CEFBS_FeatureVectorEnhancements1, // VFLLS
    CEFBS_FeatureVector, // VFLNDB
    CEFBS_FeatureVectorEnhancements1, // VFLNSB
    CEFBS_FeatureVector, // VFLPDB
    CEFBS_FeatureVectorEnhancements1, // VFLPSB
    CEFBS_FeatureVectorEnhancements1, // VFLR
    CEFBS_FeatureVectorEnhancements1, // VFLRD
    CEFBS_FeatureVector, // VFM
    CEFBS_FeatureVector, // VFMA
    CEFBS_FeatureVector, // VFMADB
    CEFBS_FeatureVectorEnhancements1, // VFMASB
    CEFBS_FeatureVectorEnhancements1, // VFMAX
    CEFBS_FeatureVectorEnhancements1, // VFMAXDB
    CEFBS_FeatureVectorEnhancements1, // VFMAXSB
    CEFBS_FeatureVector, // VFMDB
    CEFBS_FeatureVectorEnhancements1, // VFMIN
    CEFBS_FeatureVectorEnhancements1, // VFMINDB
    CEFBS_FeatureVectorEnhancements1, // VFMINSB
    CEFBS_FeatureVector, // VFMS
    CEFBS_FeatureVectorEnhancements1, // VFMSB
    CEFBS_FeatureVector, // VFMSDB
    CEFBS_FeatureVectorEnhancements1, // VFMSSB
    CEFBS_FeatureVectorEnhancements1, // VFNMA
    CEFBS_FeatureVectorEnhancements1, // VFNMADB
    CEFBS_FeatureVectorEnhancements1, // VFNMASB
    CEFBS_FeatureVectorEnhancements1, // VFNMS
    CEFBS_FeatureVectorEnhancements1, // VFNMSDB
    CEFBS_FeatureVectorEnhancements1, // VFNMSSB
    CEFBS_FeatureVector, // VFPSO
    CEFBS_FeatureVector, // VFPSODB
    CEFBS_FeatureVectorEnhancements1, // VFPSOSB
    CEFBS_FeatureVector, // VFS
    CEFBS_FeatureVector, // VFSDB
    CEFBS_FeatureVector, // VFSQ
    CEFBS_FeatureVector, // VFSQDB
    CEFBS_FeatureVectorEnhancements1, // VFSQSB
    CEFBS_FeatureVectorEnhancements1, // VFSSB
    CEFBS_FeatureVector, // VFTCI
    CEFBS_FeatureVector, // VFTCIDB
    CEFBS_FeatureVectorEnhancements1, // VFTCISB
    CEFBS_FeatureVector, // VGBM
    CEFBS_FeatureVector, // VGEF
    CEFBS_FeatureVector, // VGEG
    CEFBS_FeatureVectorEnhancements3, // VGEM
    CEFBS_FeatureVectorEnhancements3, // VGEMB
    CEFBS_FeatureVectorEnhancements3, // VGEMF
    CEFBS_FeatureVectorEnhancements3, // VGEMG
    CEFBS_FeatureVectorEnhancements3, // VGEMH
    CEFBS_FeatureVectorEnhancements3, // VGEMQ
    CEFBS_FeatureVector, // VGFM
    CEFBS_FeatureVector, // VGFMA
    CEFBS_FeatureVector, // VGFMAB
    CEFBS_FeatureVector, // VGFMAF
    CEFBS_FeatureVector, // VGFMAG
    CEFBS_FeatureVector, // VGFMAH
    CEFBS_FeatureVector, // VGFMB
    CEFBS_FeatureVector, // VGFMF
    CEFBS_FeatureVector, // VGFMG
    CEFBS_FeatureVector, // VGFMH
    CEFBS_FeatureVector, // VGM
    CEFBS_FeatureVector, // VGMB
    CEFBS_FeatureVector, // VGMF
    CEFBS_FeatureVector, // VGMG
    CEFBS_FeatureVector, // VGMH
    CEFBS_FeatureVector, // VISTR
    CEFBS_FeatureVector, // VISTRB
    CEFBS_FeatureVector, // VISTRBS
    CEFBS_FeatureVector, // VISTRF
    CEFBS_FeatureVector, // VISTRFS
    CEFBS_FeatureVector, // VISTRH
    CEFBS_FeatureVector, // VISTRHS
    CEFBS_FeatureVector, // VL
    CEFBS_FeatureVector, // VLAlign
    CEFBS_FeatureVector, // VLBB
    CEFBS_FeatureVectorEnhancements2, // VLBR
    CEFBS_FeatureVectorEnhancements2, // VLBRF
    CEFBS_FeatureVectorEnhancements2, // VLBRG
    CEFBS_FeatureVectorEnhancements2, // VLBRH
    CEFBS_FeatureVectorEnhancements2, // VLBRQ
    CEFBS_FeatureVectorEnhancements2, // VLBRREP
    CEFBS_FeatureVectorEnhancements2, // VLBRREPF
    CEFBS_FeatureVectorEnhancements2, // VLBRREPG
    CEFBS_FeatureVectorEnhancements2, // VLBRREPH
    CEFBS_FeatureVector, // VLC
    CEFBS_FeatureVector, // VLCB
    CEFBS_FeatureVector, // VLCF
    CEFBS_FeatureVector, // VLCG
    CEFBS_FeatureVector, // VLCH
    CEFBS_FeatureVectorEnhancements3, // VLCQ
    CEFBS_FeatureVector, // VLDE
    CEFBS_FeatureVector, // VLDEB
    CEFBS_FeatureVector, // VLEB
    CEFBS_FeatureVectorEnhancements2, // VLEBRF
    CEFBS_FeatureVectorEnhancements2, // VLEBRG
    CEFBS_FeatureVectorEnhancements2, // VLEBRH
    CEFBS_FeatureVector, // VLED
    CEFBS_FeatureVector, // VLEDB
    CEFBS_FeatureVector, // VLEF
    CEFBS_FeatureVector, // VLEG
    CEFBS_FeatureVector, // VLEH
    CEFBS_FeatureVector, // VLEIB
    CEFBS_FeatureVector, // VLEIF
    CEFBS_FeatureVector, // VLEIG
    CEFBS_FeatureVector, // VLEIH
    CEFBS_FeatureVectorEnhancements2, // VLER
    CEFBS_FeatureVectorEnhancements2, // VLERF
    CEFBS_FeatureVectorEnhancements2, // VLERG
    CEFBS_FeatureVectorEnhancements2, // VLERH
    CEFBS_FeatureVector, // VLGV
    CEFBS_FeatureVector, // VLGVB
    CEFBS_FeatureVector, // VLGVF
    CEFBS_FeatureVector, // VLGVG
    CEFBS_FeatureVector, // VLGVH
    CEFBS_FeatureVectorPackedDecimal, // VLIP
    CEFBS_FeatureVector, // VLL
    CEFBS_FeatureVectorEnhancements2, // VLLEBRZ
    CEFBS_FeatureVectorEnhancements2, // VLLEBRZE
    CEFBS_FeatureVectorEnhancements2, // VLLEBRZF
    CEFBS_FeatureVectorEnhancements2, // VLLEBRZG
    CEFBS_FeatureVectorEnhancements2, // VLLEBRZH
    CEFBS_FeatureVector, // VLLEZ
    CEFBS_FeatureVector, // VLLEZB
    CEFBS_FeatureVector, // VLLEZF
    CEFBS_FeatureVector, // VLLEZG
    CEFBS_FeatureVector, // VLLEZH
    CEFBS_FeatureVectorEnhancements1, // VLLEZLF
    CEFBS_FeatureVector, // VLM
    CEFBS_FeatureVector, // VLMAlign
    CEFBS_FeatureVector, // VLP
    CEFBS_FeatureVector, // VLPB
    CEFBS_FeatureVector, // VLPF
    CEFBS_FeatureVector, // VLPG
    CEFBS_FeatureVector, // VLPH
    CEFBS_FeatureVectorEnhancements3, // VLPQ
    CEFBS_FeatureVector, // VLR
    CEFBS_FeatureVector, // VLREP
    CEFBS_FeatureVector, // VLREPB
    CEFBS_FeatureVector, // VLREPF
    CEFBS_FeatureVector, // VLREPG
    CEFBS_FeatureVector, // VLREPH
    CEFBS_FeatureVectorPackedDecimal, // VLRL
    CEFBS_FeatureVectorPackedDecimal, // VLRLR
    CEFBS_FeatureVector, // VLVG
    CEFBS_FeatureVector, // VLVGB
    CEFBS_FeatureVector, // VLVGF
    CEFBS_FeatureVector, // VLVGG
    CEFBS_FeatureVector, // VLVGH
    CEFBS_FeatureVector, // VLVGP
    CEFBS_FeatureVector, // VMAE
    CEFBS_FeatureVector, // VMAEB
    CEFBS_FeatureVector, // VMAEF
    CEFBS_FeatureVectorEnhancements3, // VMAEG
    CEFBS_FeatureVector, // VMAEH
    CEFBS_FeatureVector, // VMAH
    CEFBS_FeatureVector, // VMAHB
    CEFBS_FeatureVector, // VMAHF
    CEFBS_FeatureVectorEnhancements3, // VMAHG
    CEFBS_FeatureVector, // VMAHH
    CEFBS_FeatureVectorEnhancements3, // VMAHQ
    CEFBS_FeatureVector, // VMAL
    CEFBS_FeatureVector, // VMALB
    CEFBS_FeatureVector, // VMALE
    CEFBS_FeatureVector, // VMALEB
    CEFBS_FeatureVector, // VMALEF
    CEFBS_FeatureVectorEnhancements3, // VMALEG
    CEFBS_FeatureVector, // VMALEH
    CEFBS_FeatureVector, // VMALF
    CEFBS_FeatureVectorEnhancements3, // VMALG
    CEFBS_FeatureVector, // VMALH
    CEFBS_FeatureVector, // VMALHB
    CEFBS_FeatureVector, // VMALHF
    CEFBS_FeatureVectorEnhancements3, // VMALHG
    CEFBS_FeatureVector, // VMALHH
    CEFBS_FeatureVectorEnhancements3, // VMALHQ
    CEFBS_FeatureVector, // VMALHW
    CEFBS_FeatureVector, // VMALO
    CEFBS_FeatureVector, // VMALOB
    CEFBS_FeatureVector, // VMALOF
    CEFBS_FeatureVectorEnhancements3, // VMALOG
    CEFBS_FeatureVector, // VMALOH
    CEFBS_FeatureVectorEnhancements3, // VMALQ
    CEFBS_FeatureVector, // VMAO
    CEFBS_FeatureVector, // VMAOB
    CEFBS_FeatureVector, // VMAOF
    CEFBS_FeatureVectorEnhancements3, // VMAOG
    CEFBS_FeatureVector, // VMAOH
    CEFBS_FeatureVector, // VME
    CEFBS_FeatureVector, // VMEB
    CEFBS_FeatureVector, // VMEF
    CEFBS_FeatureVectorEnhancements3, // VMEG
    CEFBS_FeatureVector, // VMEH
    CEFBS_FeatureVector, // VMH
    CEFBS_FeatureVector, // VMHB
    CEFBS_FeatureVector, // VMHF
    CEFBS_FeatureVectorEnhancements3, // VMHG
    CEFBS_FeatureVector, // VMHH
    CEFBS_FeatureVectorEnhancements3, // VMHQ
    CEFBS_FeatureVector, // VML
    CEFBS_FeatureVector, // VMLB
    CEFBS_FeatureVector, // VMLE
    CEFBS_FeatureVector, // VMLEB
    CEFBS_FeatureVector, // VMLEF
    CEFBS_FeatureVectorEnhancements3, // VMLEG
    CEFBS_FeatureVector, // VMLEH
    CEFBS_FeatureVector, // VMLF
    CEFBS_FeatureVectorEnhancements3, // VMLG
    CEFBS_FeatureVector, // VMLH
    CEFBS_FeatureVector, // VMLHB
    CEFBS_FeatureVector, // VMLHF
    CEFBS_FeatureVectorEnhancements3, // VMLHG
    CEFBS_FeatureVector, // VMLHH
    CEFBS_FeatureVectorEnhancements3, // VMLHQ
    CEFBS_FeatureVector, // VMLHW
    CEFBS_FeatureVector, // VMLO
    CEFBS_FeatureVector, // VMLOB
    CEFBS_FeatureVector, // VMLOF
    CEFBS_FeatureVectorEnhancements3, // VMLOG
    CEFBS_FeatureVector, // VMLOH
    CEFBS_FeatureVectorEnhancements3, // VMLQ
    CEFBS_FeatureVector, // VMN
    CEFBS_FeatureVector, // VMNB
    CEFBS_FeatureVector, // VMNF
    CEFBS_FeatureVector, // VMNG
    CEFBS_FeatureVector, // VMNH
    CEFBS_FeatureVector, // VMNL
    CEFBS_FeatureVector, // VMNLB
    CEFBS_FeatureVector, // VMNLF
    CEFBS_FeatureVector, // VMNLG
    CEFBS_FeatureVector, // VMNLH
    CEFBS_FeatureVectorEnhancements3, // VMNLQ
    CEFBS_FeatureVectorEnhancements3, // VMNQ
    CEFBS_FeatureVector, // VMO
    CEFBS_FeatureVector, // VMOB
    CEFBS_FeatureVector, // VMOF
    CEFBS_FeatureVectorEnhancements3, // VMOG
    CEFBS_FeatureVector, // VMOH
    CEFBS_FeatureVectorPackedDecimal, // VMP
    CEFBS_FeatureVector, // VMRH
    CEFBS_FeatureVector, // VMRHB
    CEFBS_FeatureVector, // VMRHF
    CEFBS_FeatureVector, // VMRHG
    CEFBS_FeatureVector, // VMRHH
    CEFBS_FeatureVector, // VMRL
    CEFBS_FeatureVector, // VMRLB
    CEFBS_FeatureVector, // VMRLF
    CEFBS_FeatureVector, // VMRLG
    CEFBS_FeatureVector, // VMRLH
    CEFBS_FeatureVectorEnhancements1, // VMSL
    CEFBS_FeatureVectorEnhancements1, // VMSLG
    CEFBS_FeatureVectorPackedDecimal, // VMSP
    CEFBS_FeatureVector, // VMX
    CEFBS_FeatureVector, // VMXB
    CEFBS_FeatureVector, // VMXF
    CEFBS_FeatureVector, // VMXG
    CEFBS_FeatureVector, // VMXH
    CEFBS_FeatureVector, // VMXL
    CEFBS_FeatureVector, // VMXLB
    CEFBS_FeatureVector, // VMXLF
    CEFBS_FeatureVector, // VMXLG
    CEFBS_FeatureVector, // VMXLH
    CEFBS_FeatureVectorEnhancements3, // VMXLQ
    CEFBS_FeatureVectorEnhancements3, // VMXQ
    CEFBS_FeatureVector, // VN
    CEFBS_FeatureVector, // VNC
    CEFBS_FeatureVectorEnhancements1, // VNN
    CEFBS_FeatureVector, // VNO
    CEFBS_FeatureVectorEnhancements1, // VNX
    CEFBS_FeatureVector, // VO
    CEFBS_FeatureVectorEnhancements1, // VOC
    CEFBS_FeatureVector, // VONE
    CEFBS_FeatureVector, // VPDI
    CEFBS_FeatureVector, // VPERM
    CEFBS_FeatureVector, // VPK
    CEFBS_FeatureVector, // VPKF
    CEFBS_FeatureVector, // VPKG
    CEFBS_FeatureVector, // VPKH
    CEFBS_FeatureVector, // VPKLS
    CEFBS_FeatureVector, // VPKLSF
    CEFBS_FeatureVector, // VPKLSFS
    CEFBS_FeatureVector, // VPKLSG
    CEFBS_FeatureVector, // VPKLSGS
    CEFBS_FeatureVector, // VPKLSH
    CEFBS_FeatureVector, // VPKLSHS
    CEFBS_FeatureVector, // VPKS
    CEFBS_FeatureVector, // VPKSF
    CEFBS_FeatureVector, // VPKSFS
    CEFBS_FeatureVector, // VPKSG
    CEFBS_FeatureVector, // VPKSGS
    CEFBS_FeatureVector, // VPKSH
    CEFBS_FeatureVector, // VPKSHS
    CEFBS_FeatureVectorPackedDecimal, // VPKZ
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VPKZR
    CEFBS_FeatureVector, // VPOPCT
    CEFBS_FeatureVectorEnhancements1, // VPOPCTB
    CEFBS_FeatureVectorEnhancements1, // VPOPCTF
    CEFBS_FeatureVectorEnhancements1, // VPOPCTG
    CEFBS_FeatureVectorEnhancements1, // VPOPCTH
    CEFBS_FeatureVectorPackedDecimal, // VPSOP
    CEFBS_FeatureVectorEnhancements3, // VR
    CEFBS_FeatureVector, // VREP
    CEFBS_FeatureVector, // VREPB
    CEFBS_FeatureVector, // VREPF
    CEFBS_FeatureVector, // VREPG
    CEFBS_FeatureVector, // VREPH
    CEFBS_FeatureVector, // VREPI
    CEFBS_FeatureVector, // VREPIB
    CEFBS_FeatureVector, // VREPIF
    CEFBS_FeatureVector, // VREPIG
    CEFBS_FeatureVector, // VREPIH
    CEFBS_FeatureVectorEnhancements3, // VRF
    CEFBS_FeatureVectorEnhancements3, // VRG
    CEFBS_FeatureVectorEnhancements3, // VRL
    CEFBS_FeatureVectorEnhancements3, // VRLF
    CEFBS_FeatureVectorEnhancements3, // VRLG
    CEFBS_FeatureVectorEnhancements3, // VRLQ
    CEFBS_FeatureVectorPackedDecimal, // VRP
    CEFBS_FeatureVectorEnhancements3, // VRQ
    CEFBS_FeatureVector, // VS
    CEFBS_FeatureVector, // VSB
    CEFBS_FeatureVector, // VSBCBI
    CEFBS_FeatureVector, // VSBCBIQ
    CEFBS_FeatureVector, // VSBI
    CEFBS_FeatureVector, // VSBIQ
    CEFBS_FeatureVector, // VSCBI
    CEFBS_FeatureVector, // VSCBIB
    CEFBS_FeatureVector, // VSCBIF
    CEFBS_FeatureVector, // VSCBIG
    CEFBS_FeatureVector, // VSCBIH
    CEFBS_FeatureVector, // VSCBIQ
    CEFBS_FeatureVector, // VSCEF
    CEFBS_FeatureVector, // VSCEG
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VSCHDP
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VSCHP
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VSCHSP
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VSCHXP
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VSCSHP
    CEFBS_FeatureVectorPackedDecimal, // VSDP
    CEFBS_FeatureVector, // VSEG
    CEFBS_FeatureVector, // VSEGB
    CEFBS_FeatureVector, // VSEGF
    CEFBS_FeatureVector, // VSEGH
    CEFBS_FeatureVector, // VSEL
    CEFBS_FeatureVector, // VSF
    CEFBS_FeatureVector, // VSG
    CEFBS_FeatureVector, // VSH
    CEFBS_FeatureVector, // VSL
    CEFBS_FeatureVector, // VSLB
    CEFBS_FeatureVectorEnhancements2, // VSLD
    CEFBS_FeatureVector, // VSLDB
    CEFBS_FeatureVectorPackedDecimal, // VSP
    CEFBS_FeatureVector, // VSQ
    CEFBS_FeatureVector, // VSRA
    CEFBS_FeatureVector, // VSRAB
    CEFBS_FeatureVectorEnhancements2, // VSRD
    CEFBS_FeatureVector, // VSRL
    CEFBS_FeatureVector, // VSRLB
    CEFBS_FeatureVectorPackedDecimal, // VSRP
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VSRPR
    CEFBS_FeatureVector, // VST
    CEFBS_FeatureVector, // VSTAlign
    CEFBS_FeatureVectorEnhancements2, // VSTBR
    CEFBS_FeatureVectorEnhancements2, // VSTBRF
    CEFBS_FeatureVectorEnhancements2, // VSTBRG
    CEFBS_FeatureVectorEnhancements2, // VSTBRH
    CEFBS_FeatureVectorEnhancements2, // VSTBRQ
    CEFBS_FeatureVector, // VSTEB
    CEFBS_FeatureVectorEnhancements2, // VSTEBRF
    CEFBS_FeatureVectorEnhancements2, // VSTEBRG
    CEFBS_FeatureVectorEnhancements2, // VSTEBRH
    CEFBS_FeatureVector, // VSTEF
    CEFBS_FeatureVector, // VSTEG
    CEFBS_FeatureVector, // VSTEH
    CEFBS_FeatureVectorEnhancements2, // VSTER
    CEFBS_FeatureVectorEnhancements2, // VSTERF
    CEFBS_FeatureVectorEnhancements2, // VSTERG
    CEFBS_FeatureVectorEnhancements2, // VSTERH
    CEFBS_FeatureVector, // VSTL
    CEFBS_FeatureVector, // VSTM
    CEFBS_FeatureVector, // VSTMAlign
    CEFBS_FeatureVector, // VSTRC
    CEFBS_FeatureVector, // VSTRCB
    CEFBS_FeatureVector, // VSTRCBS
    CEFBS_FeatureVector, // VSTRCF
    CEFBS_FeatureVector, // VSTRCFS
    CEFBS_FeatureVector, // VSTRCH
    CEFBS_FeatureVector, // VSTRCHS
    CEFBS_FeatureVector, // VSTRCZB
    CEFBS_FeatureVector, // VSTRCZBS
    CEFBS_FeatureVector, // VSTRCZF
    CEFBS_FeatureVector, // VSTRCZFS
    CEFBS_FeatureVector, // VSTRCZH
    CEFBS_FeatureVector, // VSTRCZHS
    CEFBS_FeatureVectorPackedDecimal, // VSTRL
    CEFBS_FeatureVectorPackedDecimal, // VSTRLR
    CEFBS_FeatureVectorEnhancements2, // VSTRS
    CEFBS_FeatureVectorEnhancements2, // VSTRSB
    CEFBS_FeatureVectorEnhancements2, // VSTRSF
    CEFBS_FeatureVectorEnhancements2, // VSTRSH
    CEFBS_FeatureVectorEnhancements2, // VSTRSZB
    CEFBS_FeatureVectorEnhancements2, // VSTRSZF
    CEFBS_FeatureVectorEnhancements2, // VSTRSZH
    CEFBS_FeatureVector, // VSUM
    CEFBS_FeatureVector, // VSUMB
    CEFBS_FeatureVector, // VSUMG
    CEFBS_FeatureVector, // VSUMGF
    CEFBS_FeatureVector, // VSUMGH
    CEFBS_FeatureVector, // VSUMH
    CEFBS_FeatureVector, // VSUMQ
    CEFBS_FeatureVector, // VSUMQF
    CEFBS_FeatureVector, // VSUMQG
    CEFBS_FeatureVector, // VTM
    CEFBS_FeatureVectorPackedDecimal, // VTP
    CEFBS_FeatureVectorPackedDecimalEnhancement3, // VTPOpt
    CEFBS_FeatureVectorPackedDecimalEnhancement3, // VTZ
    CEFBS_FeatureVector, // VUPH
    CEFBS_FeatureVector, // VUPHB
    CEFBS_FeatureVector, // VUPHF
    CEFBS_FeatureVectorEnhancements3, // VUPHG
    CEFBS_FeatureVector, // VUPHH
    CEFBS_FeatureVectorPackedDecimal, // VUPKZ
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VUPKZH
    CEFBS_FeatureVectorPackedDecimalEnhancement2, // VUPKZL
    CEFBS_FeatureVector, // VUPL
    CEFBS_FeatureVector, // VUPLB
    CEFBS_FeatureVector, // VUPLF
    CEFBS_FeatureVectorEnhancements3, // VUPLG
    CEFBS_FeatureVector, // VUPLH
    CEFBS_FeatureVector, // VUPLHB
    CEFBS_FeatureVector, // VUPLHF
    CEFBS_FeatureVectorEnhancements3, // VUPLHG
    CEFBS_FeatureVector, // VUPLHH
    CEFBS_FeatureVector, // VUPLHW
    CEFBS_FeatureVector, // VUPLL
    CEFBS_FeatureVector, // VUPLLB
    CEFBS_FeatureVector, // VUPLLF
    CEFBS_FeatureVectorEnhancements3, // VUPLLG
    CEFBS_FeatureVector, // VUPLLH
    CEFBS_FeatureVector, // VX
    CEFBS_FeatureVector, // VZERO
    CEFBS_FeatureVector, // WCDGB
    CEFBS_FeatureVector, // WCDLGB
    CEFBS_FeatureVectorEnhancements2, // WCEFB
    CEFBS_FeatureVectorEnhancements2, // WCELFB
    CEFBS_FeatureVectorEnhancements2, // WCFEB
    CEFBS_FeatureVector, // WCGDB
    CEFBS_FeatureVectorEnhancements2, // WCLFEB
    CEFBS_FeatureVector, // WCLGDB
    CEFBS_FeatureVector, // WFADB
    CEFBS_FeatureVectorEnhancements1, // WFASB
    CEFBS_FeatureVectorEnhancements1, // WFAXB
    CEFBS_FeatureVector, // WFC
    CEFBS_FeatureVector, // WFCDB
    CEFBS_FeatureVector, // WFCEDB
    CEFBS_FeatureVector, // WFCEDBS
    CEFBS_FeatureVectorEnhancements1, // WFCESB
    CEFBS_FeatureVectorEnhancements1, // WFCESBS
    CEFBS_FeatureVectorEnhancements1, // WFCEXB
    CEFBS_FeatureVectorEnhancements1, // WFCEXBS
    CEFBS_FeatureVector, // WFCHDB
    CEFBS_FeatureVector, // WFCHDBS
    CEFBS_FeatureVector, // WFCHEDB
    CEFBS_FeatureVector, // WFCHEDBS
    CEFBS_FeatureVectorEnhancements1, // WFCHESB
    CEFBS_FeatureVectorEnhancements1, // WFCHESBS
    CEFBS_FeatureVectorEnhancements1, // WFCHEXB
    CEFBS_FeatureVectorEnhancements1, // WFCHEXBS
    CEFBS_FeatureVectorEnhancements1, // WFCHSB
    CEFBS_FeatureVectorEnhancements1, // WFCHSBS
    CEFBS_FeatureVectorEnhancements1, // WFCHXB
    CEFBS_FeatureVectorEnhancements1, // WFCHXBS
    CEFBS_FeatureVectorEnhancements1, // WFCSB
    CEFBS_FeatureVectorEnhancements1, // WFCXB
    CEFBS_FeatureVector, // WFDDB
    CEFBS_FeatureVectorEnhancements1, // WFDSB
    CEFBS_FeatureVectorEnhancements1, // WFDXB
    CEFBS_FeatureVector, // WFIDB
    CEFBS_FeatureVectorEnhancements1, // WFISB
    CEFBS_FeatureVectorEnhancements1, // WFIXB
    CEFBS_FeatureVector, // WFK
    CEFBS_FeatureVector, // WFKDB
    CEFBS_FeatureVectorEnhancements1, // WFKEDB
    CEFBS_FeatureVectorEnhancements1, // WFKEDBS
    CEFBS_FeatureVectorEnhancements1, // WFKESB
    CEFBS_FeatureVectorEnhancements1, // WFKESBS
    CEFBS_FeatureVectorEnhancements1, // WFKEXB
    CEFBS_FeatureVectorEnhancements1, // WFKEXBS
    CEFBS_FeatureVectorEnhancements1, // WFKHDB
    CEFBS_FeatureVectorEnhancements1, // WFKHDBS
    CEFBS_FeatureVectorEnhancements1, // WFKHEDB
    CEFBS_FeatureVectorEnhancements1, // WFKHEDBS
    CEFBS_FeatureVectorEnhancements1, // WFKHESB
    CEFBS_FeatureVectorEnhancements1, // WFKHESBS
    CEFBS_FeatureVectorEnhancements1, // WFKHEXB
    CEFBS_FeatureVectorEnhancements1, // WFKHEXBS
    CEFBS_FeatureVectorEnhancements1, // WFKHSB
    CEFBS_FeatureVectorEnhancements1, // WFKHSBS
    CEFBS_FeatureVectorEnhancements1, // WFKHXB
    CEFBS_FeatureVectorEnhancements1, // WFKHXBS
    CEFBS_FeatureVectorEnhancements1, // WFKSB
    CEFBS_FeatureVectorEnhancements1, // WFKXB
    CEFBS_FeatureVector, // WFLCDB
    CEFBS_FeatureVectorEnhancements1, // WFLCSB
    CEFBS_FeatureVectorEnhancements1, // WFLCXB
    CEFBS_FeatureVectorEnhancements1, // WFLLD
    CEFBS_FeatureVectorEnhancements1, // WFLLS
    CEFBS_FeatureVector, // WFLNDB
    CEFBS_FeatureVectorEnhancements1, // WFLNSB
    CEFBS_FeatureVectorEnhancements1, // WFLNXB
    CEFBS_FeatureVector, // WFLPDB
    CEFBS_FeatureVectorEnhancements1, // WFLPSB
    CEFBS_FeatureVectorEnhancements1, // WFLPXB
    CEFBS_FeatureVectorEnhancements1, // WFLRD
    CEFBS_FeatureVectorEnhancements1, // WFLRX
    CEFBS_FeatureVector, // WFMADB
    CEFBS_FeatureVectorEnhancements1, // WFMASB
    CEFBS_FeatureVectorEnhancements1, // WFMAXB
    CEFBS_FeatureVectorEnhancements1, // WFMAXDB
    CEFBS_FeatureVectorEnhancements1, // WFMAXSB
    CEFBS_FeatureVectorEnhancements1, // WFMAXXB
    CEFBS_FeatureVector, // WFMDB
    CEFBS_FeatureVectorEnhancements1, // WFMINDB
    CEFBS_FeatureVectorEnhancements1, // WFMINSB
    CEFBS_FeatureVectorEnhancements1, // WFMINXB
    CEFBS_FeatureVectorEnhancements1, // WFMSB
    CEFBS_FeatureVector, // WFMSDB
    CEFBS_FeatureVectorEnhancements1, // WFMSSB
    CEFBS_FeatureVectorEnhancements1, // WFMSXB
    CEFBS_FeatureVectorEnhancements1, // WFMXB
    CEFBS_FeatureVectorEnhancements1, // WFNMADB
    CEFBS_FeatureVectorEnhancements1, // WFNMASB
    CEFBS_FeatureVectorEnhancements1, // WFNMAXB
    CEFBS_FeatureVectorEnhancements1, // WFNMSDB
    CEFBS_FeatureVectorEnhancements1, // WFNMSSB
    CEFBS_FeatureVectorEnhancements1, // WFNMSXB
    CEFBS_FeatureVector, // WFPSODB
    CEFBS_FeatureVectorEnhancements1, // WFPSOSB
    CEFBS_FeatureVectorEnhancements1, // WFPSOXB
    CEFBS_FeatureVector, // WFSDB
    CEFBS_FeatureVector, // WFSQDB
    CEFBS_FeatureVectorEnhancements1, // WFSQSB
    CEFBS_FeatureVectorEnhancements1, // WFSQXB
    CEFBS_FeatureVectorEnhancements1, // WFSSB
    CEFBS_FeatureVectorEnhancements1, // WFSXB
    CEFBS_FeatureVector, // WFTCIDB
    CEFBS_FeatureVectorEnhancements1, // WFTCISB
    CEFBS_FeatureVectorEnhancements1, // WFTCIXB
    CEFBS_FeatureVector, // WLDEB
    CEFBS_FeatureVector, // WLEDB
    CEFBS_None, // X
    CEFBS_None, // XC
    CEFBS_None, // XG
    CEFBS_None, // XGR
    CEFBS_FeatureDistinctOps, // XGRK
    CEFBS_None, // XI
    CEFBS_None, // XIHF
    CEFBS_None, // XILF
    CEFBS_None, // XIY
    CEFBS_None, // XR
    CEFBS_FeatureDistinctOps, // XRK
    CEFBS_None, // XSCH
    CEFBS_None, // XY
    CEFBS_None, // ZAP
  };

  assert(Opcode < 3314);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::SystemZ_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::SystemZ_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::SystemZ_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::SystemZ_MC {

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_FeatureBEAREnhancement",
  "Feature_FeatureBackChain",
  "Feature_FeatureConcurrentFunctions",
  "Feature_FeatureDFPPackedConversion",
  "Feature_FeatureDFPZonedConversion",
  "Feature_FeatureDeflateConversion",
  "Feature_FeatureDistinctOps",
  "Feature_FeatureEnhancedDAT2",
  "Feature_FeatureEnhancedSort",
  "Feature_FeatureExecutionHint",
  "Feature_FeatureFPExtension",
  "Feature_FeatureFastSerialization",
  "Feature_FeatureGuardedStorage",
  "Feature_FeatureHighWord",
  "Feature_FeatureInsertReferenceBitsMultiple",
  "Feature_FeatureInterlockedAccess1",
  "Feature_FeatureLoadAndTrap",
  "Feature_FeatureLoadAndZeroRightmostByte",
  "Feature_FeatureLoadStoreOnCond",
  "Feature_FeatureLoadStoreOnCond2",
  "Feature_FeatureMessageSecurityAssist3",
  "Feature_FeatureMessageSecurityAssist4",
  "Feature_FeatureMessageSecurityAssist5",
  "Feature_FeatureMessageSecurityAssist7",
  "Feature_FeatureMessageSecurityAssist8",
  "Feature_FeatureMessageSecurityAssist9",
  "Feature_FeatureMessageSecurityAssist12",
  "Feature_FeatureMiscellaneousExtensions",
  "Feature_FeatureMiscellaneousExtensions2",
  "Feature_FeatureMiscellaneousExtensions3",
  "Feature_FeatureMiscellaneousExtensions4",
  "Feature_FeatureNNPAssist",
  "Feature_FeaturePopulationCount",
  "Feature_FeatureProcessorActivityInstrumentation",
  "Feature_FeatureProcessorAssist",
  "Feature_FeatureResetDATProtection",
  "Feature_FeatureResetReferenceBitsMultiple",
  "Feature_FeatureSoftFloat",
  "Feature_FeatureTestPendingExternalInterruption",
  "Feature_FeatureTransactionalExecution",
  "Feature_FeatureUnalignedSymbols",
  "Feature_FeatureVector",
  "Feature_FeatureVectorEnhancements1",
  "Feature_FeatureVectorEnhancements2",
  "Feature_FeatureVectorEnhancements3",
  "Feature_FeatureVectorPackedDecimal",
  "Feature_FeatureVectorPackedDecimalEnhancement",
  "Feature_FeatureVectorPackedDecimalEnhancement2",
  "Feature_FeatureVectorPackedDecimalEnhancement3",
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
    Msg << "Attempting to emit " << "opcode " << Opcode
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::SystemZ_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

#ifdef GET_INSTRMAP_INFO
#undef GET_INSTRMAP_INFO

namespace llvm_ks::SystemZ {

enum DispSize {
  DispSize_12,
  DispSize_20
};

enum MemType {
  MemType_target
};

enum NumOpsValue {
  NumOpsValue_2
};

enum OpType {
  OpType_mem
};

// getDisp12Opcode
LLVM_READONLY
int32_t getDisp12Opcode(uint32_t Opcode) {
  using namespace SystemZ;
  static constexpr uint32_t Table[][2] = {
    { AHY, AH },
    { ALY, AL },
    { AY, A },
    { CDSY, CDS },
    { CHY, CH },
    { CLIY, CLI },
    { CLMY, CLM },
    { CLY, CL },
    { CSY, CS },
    { CVBY, CVB },
    { CVDY, CVD },
    { CY, C },
    { IC32Y, IC32 },
    { ICMY, ICM },
    { ICY, IC },
    { LAEY, LAE },
    { LAMY, LAM },
    { LAY, LA },
    { LDY, LD },
    { LE16Y, LE16 },
    { LEY, LE },
    { LHY, LH },
    { LMY, LM },
    { LRAY, LRA },
    { LY, L },
    { MHY, MH },
    { MSY, MS },
    { MVIY, MVI },
    { NIY, NI },
    { NY, N },
    { OIY, OI },
    { OY, O },
    { SHY, SH },
    { SLY, SL },
    { STAMY, STAM },
    { STCMY, STCM },
    { STCY, STC },
    { STDY, STD },
    { STE16Y, STE16 },
    { STEY, STE },
    { STHY, STH },
    { STMY, STM },
    { STY, ST },
    { SY, S },
    { TMY, TM },
    { XIY, XI },
    { XY, X },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 47;
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

// getDisp20Opcode
LLVM_READONLY
int32_t getDisp20Opcode(uint32_t Opcode) {
  using namespace SystemZ;
  static constexpr uint32_t Table[][2] = {
    { A, AY },
    { AH, AHY },
    { AL, ALY },
    { C, CY },
    { CDS, CDSY },
    { CH, CHY },
    { CL, CLY },
    { CLI, CLIY },
    { CLM, CLMY },
    { CS, CSY },
    { CVB, CVBY },
    { CVD, CVDY },
    { IC, ICY },
    { IC32, IC32Y },
    { ICM, ICMY },
    { L, LY },
    { LA, LAY },
    { LAE, LAEY },
    { LAM, LAMY },
    { LD, LDY },
    { LE, LEY },
    { LE16, LE16Y },
    { LH, LHY },
    { LM, LMY },
    { LRA, LRAY },
    { MH, MHY },
    { MS, MSY },
    { MVI, MVIY },
    { N, NY },
    { NI, NIY },
    { O, OY },
    { OI, OIY },
    { S, SY },
    { SH, SHY },
    { SL, SLY },
    { ST, STY },
    { STAM, STAMY },
    { STC, STCY },
    { STCM, STCMY },
    { STD, STDY },
    { STE, STEY },
    { STE16, STE16Y },
    { STH, STHY },
    { STM, STMY },
    { TM, TMY },
    { X, XY },
    { XI, XIY },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 47;
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

// getMemOpcode
LLVM_READONLY
int32_t getMemOpcode(uint32_t Opcode) {
  using namespace SystemZ;
  static constexpr uint32_t Table[][2] = {
    { LLCRMux, LLCMux },
    { LLHRMux, LLHMux },
    { LOCRMux, LOCMux },
    { SELRMux, LOCMux_MemFoldPseudo },
    { ADBR, ADB },
    { ADR, AD },
    { AEBR, AEB },
    { AER, AE },
    { AGFR, AGF },
    { AGR, AG },
    { AGRK, AG_MemFoldPseudo },
    { ALCGR, ALCG },
    { ALCR, ALC },
    { ALGFR, ALGF },
    { ALGR, ALG },
    { ALGRK, ALG_MemFoldPseudo },
    { ALR, AL },
    { ALRK, AL_MemFoldPseudo },
    { AR, A },
    { ARK, A_MemFoldPseudo },
    { AUR, AU },
    { AWR, AW },
    { CDBR, CDB },
    { CDR, CD },
    { CEBR, CEB },
    { CER, CE },
    { CGFR, CGF },
    { CGR, CG },
    { CLGFR, CLGF },
    { CLGR, CLG },
    { CLR, CL },
    { CR, C },
    { DDBR, DDB },
    { DDR, DD },
    { DEBR, DEB },
    { DER, DE },
    { DLGR, DLG },
    { DLR, DL },
    { DR, D },
    { DSGFR, DSGF },
    { DSGR, DSG },
    { KDBR, KDB },
    { KEBR, KEB },
    { LBR, LB },
    { LDEBR, LDEB },
    { LDER, LDE },
    { LDR, LD },
    { LER, LE },
    { LER16, LE16 },
    { LGBR, LGB },
    { LGFR, LGF },
    { LGHR, LGH },
    { LGR, LG },
    { LHR, LH },
    { LLCR, LLC },
    { LLGCR, LLGC },
    { LLGFR, LLGF },
    { LLGHR, LLGH },
    { LLGTR, LLGT },
    { LLHR, LLH },
    { LOCFHR, LOCFH },
    { LOCGR, LOCG },
    { LOCR, LOC },
    { LR, L },
    { LRVGR, LRVG },
    { LRVR, LRV },
    { LTGFR, LTGF },
    { LTGR, LTG },
    { LTR, LT },
    { LXDBR, LXDB },
    { LXDR, LXD },
    { LXEBR, LXEB },
    { LXER, LXE },
    { MADBR, MADB },
    { MADR, MAD },
    { MAEBR, MAEB },
    { MAER, MAE },
    { MAYHR, MAYH },
    { MAYLR, MAYL },
    { MAYR, MAY },
    { MDBR, MDB },
    { MDEBR, MDEB },
    { MDER, MDE },
    { MDR, MD },
    { MEEBR, MEEB },
    { MEER, MEE },
    { MER, ME },
    { MLGR, MLG },
    { MLR, ML },
    { MR, M },
    { MSDBR, MSDB },
    { MSDR, MSD },
    { MSEBR, MSEB },
    { MSER, MSE },
    { MSGFR, MSGF },
    { MSGR, MSG },
    { MSGRKC, MSGC_MemFoldPseudo },
    { MSR, MS },
    { MSRKC, MSC_MemFoldPseudo },
    { MXDBR, MXDB },
    { MXDR, MXD },
    { MYHR, MYH },
    { MYLR, MYL },
    { MYR, MY },
    { NGR, NG },
    { NGRK, NG_MemFoldPseudo },
    { NR, N },
    { NRK, N_MemFoldPseudo },
    { OGR, OG },
    { OGRK, OG_MemFoldPseudo },
    { OR, O },
    { ORK, O_MemFoldPseudo },
    { SDBR, SDB },
    { SDR, SD },
    { SEBR, SEB },
    { SELGR, LOCG_MemFoldPseudo },
    { SER, SE },
    { SGFR, SGF },
    { SGR, SG },
    { SGRK, SG_MemFoldPseudo },
    { SLBGR, SLBG },
    { SLBR, SLB },
    { SLGFR, SLGF },
    { SLGR, SLG },
    { SLGRK, SLG_MemFoldPseudo },
    { SLR, SL },
    { SLRK, SL_MemFoldPseudo },
    { SQDBR, SQDB },
    { SQDR, SQD },
    { SQEBR, SQEB },
    { SQER, SQE },
    { SR, S },
    { SRK, S_MemFoldPseudo },
    { SUR, SU },
    { SWR, SW },
    { WFADB, ADB_MemFoldPseudo },
    { WFASB, AEB_MemFoldPseudo },
    { WFCDB, CDB },
    { WFCSB, CEB },
    { WFDDB, DDB_MemFoldPseudo },
    { WFDSB, DEB_MemFoldPseudo },
    { WFKDB, KDB },
    { WFKSB, KEB },
    { WFMADB, MADB_MemFoldPseudo },
    { WFMASB, MAEB_MemFoldPseudo },
    { WFMDB, MDB_MemFoldPseudo },
    { WFMSB, MEEB_MemFoldPseudo },
    { WFMSDB, MSDB_MemFoldPseudo },
    { WFMSSB, MSEB_MemFoldPseudo },
    { WFSDB, SDB_MemFoldPseudo },
    { WFSQDB, SQDB },
    { WFSQSB, SQEB },
    { WFSSB, SEB_MemFoldPseudo },
    { WLDEB, LDEB },
    { XGR, XG },
    { XGRK, XG_MemFoldPseudo },
    { XR, X },
    { XRK, X_MemFoldPseudo },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 158;
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

// getTargetMemOpcode
LLVM_READONLY
int32_t getTargetMemOpcode(uint32_t Opcode) {
  using namespace SystemZ;
  static constexpr uint32_t Table[][2] = {
    { ADB_MemFoldPseudo, ADB },
    { AEB_MemFoldPseudo, AEB },
    { AG_MemFoldPseudo, AG },
    { ALG_MemFoldPseudo, ALG },
    { AL_MemFoldPseudo, AL },
    { A_MemFoldPseudo, A },
    { DDB_MemFoldPseudo, DDB },
    { DEB_MemFoldPseudo, DEB },
    { LOCG_MemFoldPseudo, LOCG },
    { LOCMux_MemFoldPseudo, LOCMux },
    { MADB_MemFoldPseudo, MADB },
    { MAEB_MemFoldPseudo, MAEB },
    { MDB_MemFoldPseudo, MDB },
    { MEEB_MemFoldPseudo, MEEB },
    { MSC_MemFoldPseudo, MSC },
    { MSDB_MemFoldPseudo, MSDB },
    { MSEB_MemFoldPseudo, MSEB },
    { MSGC_MemFoldPseudo, MSGC },
    { NG_MemFoldPseudo, NG },
    { N_MemFoldPseudo, N },
    { OG_MemFoldPseudo, OG },
    { O_MemFoldPseudo, O },
    { SDB_MemFoldPseudo, SDB },
    { SEB_MemFoldPseudo, SEB },
    { SG_MemFoldPseudo, SG },
    { SLG_MemFoldPseudo, SLG },
    { SL_MemFoldPseudo, SL },
    { S_MemFoldPseudo, S },
    { XG_MemFoldPseudo, XG },
    { X_MemFoldPseudo, X },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 30;
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

// getTwoOperandOpcode
LLVM_READONLY
int32_t getTwoOperandOpcode(uint32_t Opcode) {
  using namespace SystemZ;
  static constexpr uint32_t Table[][2] = {
    { AHIMuxK, AHIMux },
    { SELRMux, LOCRMux },
    { AGHIK, AGHI },
    { AGRK, AGR },
    { AHIK, AHI },
    { ALGRK, ALGR },
    { ALRK, ALR },
    { ARK, AR },
    { NGRK, NGR },
    { NRK, NR },
    { OGRK, OGR },
    { ORK, OR },
    { SELFHR, LOCFHR },
    { SELGR, LOCGR },
    { SELR, LOCR },
    { SGRK, SGR },
    { SLAK, SLA },
    { SLGRK, SLGR },
    { SLLK, SLL },
    { SLRK, SLR },
    { SRAK, SRA },
    { SRK, SR },
    { SRLK, SRL },
    { XGRK, XGR },
    { XRK, XR },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 25;
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


} // namespace llvm_ks::SystemZ

#endif // GET_INSTRMAP_INFO

