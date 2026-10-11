/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::SP {

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
    ADJCALLSTACKDOWN                      = 331, // SparcInstrInfo.td:613
    ADJCALLSTACKUP                        = 332, // SparcInstrInfo.td:616
    GETPCX                                = 333, // SparcInstrInfo.td:609
    SELECT_CC_DFP_FCC                     = 334, // SparcInstrInfo.td:689
    SELECT_CC_DFP_ICC                     = 335, // SparcInstrInfo.td:646
    SELECT_CC_DFP_XCC                     = 336, // SparcInstrInfo.td:667
    SELECT_CC_FP_FCC                      = 337, // SparcInstrInfo.td:685
    SELECT_CC_FP_ICC                      = 338, // SparcInstrInfo.td:641
    SELECT_CC_FP_XCC                      = 339, // SparcInstrInfo.td:662
    SELECT_CC_Int_FCC                     = 340, // SparcInstrInfo.td:680
    SELECT_CC_Int_ICC                     = 341, // SparcInstrInfo.td:637
    SELECT_CC_Int_XCC                     = 342, // SparcInstrInfo.td:658
    SELECT_CC_QFP_FCC                     = 343, // SparcInstrInfo.td:693
    SELECT_CC_QFP_ICC                     = 344, // SparcInstrInfo.td:651
    SELECT_CC_QFP_XCC                     = 345, // SparcInstrInfo.td:672
    SET                                   = 346, // SparcInstrAliases.td:562
    SETSW                                 = 347, // SparcInstrAliases.td:566
    SETX                                  = 348, // SparcInstrAliases.td:570
    V8BAR                                 = 349, // SparcInstrInfo.td:605
    ADDCCri                               = 350, // SparcInstrInfo.td:502
    ADDCCrr                               = 351, // SparcInstrInfo.td:497
    ADDCri                                = 352, // SparcInstrInfo.td:516
    ADDCrr                                = 353, // SparcInstrInfo.td:512
    ADDEri                                = 354, // SparcInstrInfo.td:502
    ADDErr                                = 355, // SparcInstrInfo.td:497
    ADDXC                                 = 356, // SparcInstrVIS.td:185
    ADDXCCC                               = 357, // SparcInstrVIS.td:188
    ADDri                                 = 358, // SparcInstrInfo.td:502
    ADDrr                                 = 359, // SparcInstrInfo.td:497
    AES_DROUND01                          = 360, // SparcInstrCrypto.td:23
    AES_DROUND01_LAST                     = 361, // SparcInstrCrypto.td:27
    AES_DROUND23                          = 362, // SparcInstrCrypto.td:24
    AES_DROUND23_LAST                     = 363, // SparcInstrCrypto.td:28
    AES_EROUND01                          = 364, // SparcInstrCrypto.td:21
    AES_EROUND01_LAST                     = 365, // SparcInstrCrypto.td:25
    AES_EROUND23                          = 366, // SparcInstrCrypto.td:22
    AES_EROUND23_LAST                     = 367, // SparcInstrCrypto.td:26
    AES_KEXPAND0                          = 368, // SparcInstrCrypto.td:29
    AES_KEXPAND1                          = 369, // SparcInstrCrypto.td:32
    AES_KEXPAND2                          = 370, // SparcInstrCrypto.td:33
    ALIGNADDR                             = 371, // SparcInstrVIS.td:96
    ALIGNADDRL                            = 372, // SparcInstrVIS.td:97
    ALLCLEAN                              = 373, // SparcInstrUAOSA.td:39
    ANDCCri                               = 374, // SparcInstrInfo.td:516
    ANDCCrr                               = 375, // SparcInstrInfo.td:512
    ANDNCCri                              = 376, // SparcInstrInfo.td:516
    ANDNCCrr                              = 377, // SparcInstrInfo.td:512
    ANDNri                                = 378, // SparcInstrInfo.td:874
    ANDNrr                                = 379, // SparcInstrInfo.td:870
    ANDri                                 = 380, // SparcInstrInfo.td:502
    ANDrr                                 = 381, // SparcInstrInfo.td:497
    ARRAY16                               = 382, // SparcInstrVIS.td:154
    ARRAY32                               = 383, // SparcInstrVIS.td:155
    ARRAY8                                = 384, // SparcInstrVIS.td:153
    BA                                    = 385, // SparcInstrInfo.td:987
    BCOND                                 = 386, // SparcInstrInfo.td:1036
    BCONDA                                = 387, // SparcInstrInfo.td:1039
    BINDri                                = 388, // SparcInstrInfo.td:1029
    BINDrr                                = 389, // SparcInstrInfo.td:1025
    BMASK                                 = 390, // SparcInstrVIS.td:165
    BPFCC                                 = 391, // SparcInstrInfo.td:1060
    BPFCCA                                = 392, // SparcInstrInfo.td:1063
    BPFCCANT                              = 393, // SparcInstrInfo.td:1069
    BPFCCNT                               = 394, // SparcInstrInfo.td:1066
    BPICC                                 = 395, // SparcInstrInfo.td:1001
    BPICCA                                = 396, // SparcInstrInfo.td:1005
    BPICCANT                              = 397, // SparcInstrInfo.td:1013
    BPICCNT                               = 398, // SparcInstrInfo.td:1009
    BPR                                   = 399, // SparcInstr64Bit.td:334
    BPRA                                  = 400, // SparcInstr64Bit.td:336
    BPRANT                                = 401, // SparcInstr64Bit.td:340
    BPRNT                                 = 402, // SparcInstr64Bit.td:338
    BPXCC                                 = 403, // SparcInstrInfo.td:1001
    BPXCCA                                = 404, // SparcInstrInfo.td:1005
    BPXCCANT                              = 405, // SparcInstrInfo.td:1013
    BPXCCNT                               = 406, // SparcInstrInfo.td:1009
    BSHUFFLE                              = 407, // SparcInstrVIS.td:166
    CALL                                  = 408, // SparcInstrInfo.td:1122
    CALLi                                 = 409, // SparcInstrInfo.td:1134
    CALLri                                = 410, // SparcInstrInfo.td:1149
    CALLrii                               = 411, // SparcInstrInfo.td:1160
    CALLrr                                = 412, // SparcInstrInfo.td:1144
    CALLrri                               = 413, // SparcInstrInfo.td:1157
    CAMELLIA_F                            = 414, // SparcInstrCrypto.td:37
    CAMELLIA_FL                           = 415, // SparcInstrCrypto.td:38
    CAMELLIA_FLI                          = 416, // SparcInstrCrypto.td:41
    CASAri                                = 417, // SparcInstrInfo.td:1822
    CASArr                                = 418, // SparcInstrInfo.td:1814
    CASXAri                               = 419, // SparcInstr64Bit.td:452
    CASXArr                               = 420, // SparcInstr64Bit.td:445
    CMASK16                               = 421, // SparcInstrVIS.td:193
    CMASK32                               = 422, // SparcInstrVIS.td:195
    CMASK8                                = 423, // SparcInstrVIS.td:191
    CPBCOND                               = 424, // SparcInstrInfo.td:1112
    CPBCONDA                              = 425, // SparcInstrInfo.td:1115
    CRC32C                                = 426, // SparcInstrCrypto.td:45
    CWBCONDri                             = 427, // SparcInstrUAOSA.td:31
    CWBCONDrr                             = 428, // SparcInstrUAOSA.td:28
    CXBCONDri                             = 429, // SparcInstrUAOSA.td:31
    CXBCONDrr                             = 430, // SparcInstrUAOSA.td:28
    DES_IIP                               = 431, // SparcInstrCrypto.td:54
    DES_IP                                = 432, // SparcInstrCrypto.td:51
    DES_KEXPAND                           = 433, // SparcInstrCrypto.td:58
    DES_ROUND                             = 434, // SparcInstrCrypto.td:49
    DONE                                  = 435, // SparcInstrInfo.td:1876
    EDGE16                                = 436, // SparcInstrVIS.td:146
    EDGE16L                               = 437, // SparcInstrVIS.td:147
    EDGE16LN                              = 438, // SparcInstrVIS.td:175
    EDGE16N                               = 439, // SparcInstrVIS.td:174
    EDGE32                                = 440, // SparcInstrVIS.td:148
    EDGE32L                               = 441, // SparcInstrVIS.td:149
    EDGE32LN                              = 442, // SparcInstrVIS.td:177
    EDGE32N                               = 443, // SparcInstrVIS.td:176
    EDGE8                                 = 444, // SparcInstrVIS.td:144
    EDGE8L                                = 445, // SparcInstrVIS.td:145
    EDGE8LN                               = 446, // SparcInstrVIS.td:173
    EDGE8N                                = 447, // SparcInstrVIS.td:172
    FABSD                                 = 448, // SparcInstrInfo.td:1730
    FABSQ                                 = 449, // SparcInstrInfo.td:1735
    FABSS                                 = 450, // SparcInstrInfo.td:1415
    FADDD                                 = 451, // SparcInstrInfo.td:1450
    FADDQ                                 = 452, // SparcInstrInfo.td:1455
    FADDS                                 = 453, // SparcInstrInfo.td:1445
    FALIGNADATA                           = 454, // SparcInstrVIS.td:98
    FAND                                  = 455, // SparcInstrVIS.td:116
    FANDNOT1                              = 456, // SparcInstrVIS.td:129
    FANDNOT1S                             = 457, // SparcInstrVIS.td:130
    FANDNOT2                              = 458, // SparcInstrVIS.td:131
    FANDNOT2S                             = 459, // SparcInstrVIS.td:132
    FANDS                                 = 460, // SparcInstrVIS.td:117
    FBCOND                                = 461, // SparcInstrInfo.td:1076
    FBCONDA                               = 462, // SparcInstrInfo.td:1079
    FBCONDA_V9                            = 463, // SparcInstrInfo.td:1090
    FBCOND_V9                             = 464, // SparcInstrInfo.td:1086
    FCHKSM16                              = 465, // SparcInstrVIS.td:200
    FCMPD                                 = 466, // SparcInstrInfo.td:1541
    FCMPD_V9                              = 467, // SparcInstrInfo.td:1566
    FCMPEQ16                              = 468, // SparcInstrVIS.td:140
    FCMPEQ32                              = 469, // SparcInstrVIS.td:141
    FCMPGT16                              = 470, // SparcInstrVIS.td:134
    FCMPGT32                              = 471, // SparcInstrVIS.td:135
    FCMPLE16                              = 472, // SparcInstrVIS.td:136
    FCMPLE32                              = 473, // SparcInstrVIS.td:137
    FCMPNE16                              = 474, // SparcInstrVIS.td:138
    FCMPNE32                              = 475, // SparcInstrVIS.td:139
    FCMPQ                                 = 476, // SparcInstrInfo.td:1546
    FCMPQ_V9                              = 477, // SparcInstrInfo.td:1571
    FCMPS                                 = 478, // SparcInstrInfo.td:1536
    FCMPS_V9                              = 479, // SparcInstrInfo.td:1561
    FDIVD                                 = 480, // SparcInstrInfo.td:1517
    FDIVQ                                 = 481, // SparcInstrInfo.td:1522
    FDIVS                                 = 482, // SparcInstrInfo.td:1512
    FDMULQ                                = 483, // SparcInstrInfo.td:1503
    FDTOI                                 = 484, // SparcInstrInfo.td:1363
    FDTOQ                                 = 485, // SparcInstrInfo.td:1390
    FDTOS                                 = 486, // SparcInstrInfo.td:1385
    FDTOX                                 = 487, // SparcInstr64Bit.td:408
    FEXPAND                               = 488, // SparcInstrVIS.td:72
    FHADDD                                = 489, // SparcInstrVIS.td:205
    FHADDS                                = 490, // SparcInstrVIS.td:202
    FHSUBD                                = 491, // SparcInstrVIS.td:211
    FHSUBS                                = 492, // SparcInstrVIS.td:208
    FITOD                                 = 493, // SparcInstrInfo.td:1346
    FITOQ                                 = 494, // SparcInstrInfo.td:1351
    FITOS                                 = 495, // SparcInstrInfo.td:1341
    FLCMPD                                = 496, // SparcInstrVIS.td:217
    FLCMPS                                = 497, // SparcInstrVIS.td:214
    FLUSH                                 = 498, // SparcInstrInfo.td:1335
    FLUSHW                                = 499, // SparcInstrInfo.td:623
    FLUSHri                               = 500, // SparcInstrInfo.td:1328
    FLUSHrr                               = 501, // SparcInstrInfo.td:1326
    FMADDD                                = 502, // SparcInstrUAOSA.td:49
    FMADDS                                = 503, // SparcInstrUAOSA.td:48
    FMEAN16                               = 504, // SparcInstrVIS.td:221
    FMOVD                                 = 505, // SparcInstrInfo.td:1714
    FMOVD_FCC                             = 506, // SparcInstrInfo.td:1697
    FMOVD_ICC                             = 507, // SparcInstrInfo.td:1678
    FMOVD_XCC                             = 508, // SparcInstr64Bit.td:315
    FMOVQ                                 = 509, // SparcInstrInfo.td:1718
    FMOVQ_FCC                             = 510, // SparcInstrInfo.td:1703
    FMOVQ_ICC                             = 511, // SparcInstrInfo.td:1684
    FMOVQ_XCC                             = 512, // SparcInstr64Bit.td:321
    FMOVRD                                = 513, // SparcInstr64Bit.td:373
    FMOVRQ                                = 514, // SparcInstr64Bit.td:378
    FMOVRS                                = 515, // SparcInstr64Bit.td:369
    FMOVS                                 = 516, // SparcInstrInfo.td:1407
    FMOVS_FCC                             = 517, // SparcInstrInfo.td:1692
    FMOVS_ICC                             = 518, // SparcInstrInfo.td:1673
    FMOVS_XCC                             = 519, // SparcInstr64Bit.td:310
    FMSUBD                                = 520, // SparcInstrUAOSA.td:51
    FMSUBS                                = 521, // SparcInstrUAOSA.td:50
    FMUL8SUX16                            = 522, // SparcInstrVIS.td:87
    FMUL8ULX16                            = 523, // SparcInstrVIS.td:88
    FMUL8X16                              = 524, // SparcInstrVIS.td:78
    FMUL8X16AL                            = 525, // SparcInstrVIS.td:84
    FMUL8X16AU                            = 526, // SparcInstrVIS.td:81
    FMULD                                 = 527, // SparcInstrInfo.td:1485
    FMULD8SUX16                           = 528, // SparcInstrVIS.td:89
    FMULD8ULX16                           = 529, // SparcInstrVIS.td:92
    FMULQ                                 = 530, // SparcInstrInfo.td:1490
    FMULS                                 = 531, // SparcInstrInfo.td:1479
    FNADDD                                = 532, // SparcInstrVIS.td:226
    FNADDS                                = 533, // SparcInstrVIS.td:223
    FNAND                                 = 534, // SparcInstrVIS.td:118
    FNANDS                                = 535, // SparcInstrVIS.td:119
    FNEGD                                 = 536, // SparcInstrInfo.td:1721
    FNEGQ                                 = 537, // SparcInstrInfo.td:1726
    FNEGS                                 = 538, // SparcInstrInfo.td:1410
    FNHADDD                               = 539, // SparcInstrVIS.td:232
    FNHADDS                               = 540, // SparcInstrVIS.td:229
    FNMADDD                               = 541, // SparcInstrUAOSA.td:54
    FNMADDS                               = 542, // SparcInstrUAOSA.td:53
    FNMSUBD                               = 543, // SparcInstrUAOSA.td:56
    FNMSUBS                               = 544, // SparcInstrUAOSA.td:55
    FNMULD                                = 545, // SparcInstrVIS.td:239
    FNMULS                                = 546, // SparcInstrVIS.td:236
    FNOR                                  = 547, // SparcInstrVIS.td:114
    FNORS                                 = 548, // SparcInstrVIS.td:115
    FNOT1                                 = 549, // SparcInstrVIS.td:108
    FNOT1S                                = 550, // SparcInstrVIS.td:109
    FNOT2                                 = 551, // SparcInstrVIS.td:110
    FNOT2S                                = 552, // SparcInstrVIS.td:111
    FNSMULD                               = 553, // SparcInstrVIS.td:242
    FONE                                  = 554, // SparcInstrVIS.td:102
    FONES                                 = 555, // SparcInstrVIS.td:103
    FOR                                   = 556, // SparcInstrVIS.td:112
    FORNOT1                               = 557, // SparcInstrVIS.td:125
    FORNOT1S                              = 558, // SparcInstrVIS.td:126
    FORNOT2                               = 559, // SparcInstrVIS.td:127
    FORNOT2S                              = 560, // SparcInstrVIS.td:128
    FORS                                  = 561, // SparcInstrVIS.td:113
    FPACK16                               = 562, // SparcInstrVIS.td:66
    FPACK32                               = 563, // SparcInstrVIS.td:67
    FPACKFIX                              = 564, // SparcInstrVIS.td:69
    FPADD16                               = 565, // SparcInstrVIS.td:57
    FPADD16S                              = 566, // SparcInstrVIS.td:58
    FPADD32                               = 567, // SparcInstrVIS.td:59
    FPADD32S                              = 568, // SparcInstrVIS.td:60
    FPADD64                               = 569, // SparcInstrVIS.td:246
    FPMADDX                               = 570, // SparcInstrUAOSA.td:66
    FPMADDXHI                             = 571, // SparcInstrUAOSA.td:67
    FPMERGE                               = 572, // SparcInstrVIS.td:74
    FPSUB16                               = 573, // SparcInstrVIS.td:61
    FPSUB16S                              = 574, // SparcInstrVIS.td:62
    FPSUB32                               = 575, // SparcInstrVIS.td:63
    FPSUB32S                              = 576, // SparcInstrVIS.td:64
    FQTOD                                 = 577, // SparcInstrInfo.td:1400
    FQTOI                                 = 578, // SparcInstrInfo.td:1368
    FQTOS                                 = 579, // SparcInstrInfo.td:1395
    FQTOX                                 = 580, // SparcInstr64Bit.td:413
    FSLAS16                               = 581, // SparcInstrVIS.td:252
    FSLAS32                               = 582, // SparcInstrVIS.td:254
    FSLL16                                = 583, // SparcInstrVIS.td:248
    FSLL32                                = 584, // SparcInstrVIS.td:250
    FSMULD                                = 585, // SparcInstrInfo.td:1496
    FSQRTD                                = 586, // SparcInstrInfo.td:1431
    FSQRTQ                                = 587, // SparcInstrInfo.td:1436
    FSQRTS                                = 588, // SparcInstrInfo.td:1426
    FSRA16                                = 589, // SparcInstrVIS.td:253
    FSRA32                                = 590, // SparcInstrVIS.td:255
    FSRC1                                 = 591, // SparcInstrVIS.td:104
    FSRC1S                                = 592, // SparcInstrVIS.td:105
    FSRC2                                 = 593, // SparcInstrVIS.td:106
    FSRC2S                                = 594, // SparcInstrVIS.td:107
    FSRL16                                = 595, // SparcInstrVIS.td:249
    FSRL32                                = 596, // SparcInstrVIS.td:251
    FSTOD                                 = 597, // SparcInstrInfo.td:1375
    FSTOI                                 = 598, // SparcInstrInfo.td:1358
    FSTOQ                                 = 599, // SparcInstrInfo.td:1380
    FSTOX                                 = 600, // SparcInstr64Bit.td:404
    FSUBD                                 = 601, // SparcInstrInfo.td:1466
    FSUBQ                                 = 602, // SparcInstrInfo.td:1471
    FSUBS                                 = 603, // SparcInstrInfo.td:1461
    FXNOR                                 = 604, // SparcInstrVIS.td:122
    FXNORS                                = 605, // SparcInstrVIS.td:123
    FXOR                                  = 606, // SparcInstrVIS.td:120
    FXORS                                 = 607, // SparcInstrVIS.td:121
    FXTOD                                 = 608, // SparcInstr64Bit.td:394
    FXTOQ                                 = 609, // SparcInstr64Bit.td:399
    FXTOS                                 = 610, // SparcInstr64Bit.td:390
    FZERO                                 = 611, // SparcInstrVIS.td:100
    FZEROS                                = 612, // SparcInstrVIS.td:101
    GDOP_LDXrr                            = 613, // SparcInstr64Bit.td:219
    GDOP_LDrr                             = 614, // SparcInstrInfo.td:749
    INVALW                                = 615, // SparcInstrUAOSA.td:40
    JMPLri                                = 616, // SparcInstrInfo.td:1175
    JMPLrr                                = 617, // SparcInstrInfo.td:1170
    LDAri                                 = 618, // SparcInstrInfo.td:545
    LDArr                                 = 619, // SparcInstrInfo.td:540
    LDCSRri                               = 620, // SparcInstrInfo.td:728
    LDCSRrr                               = 621, // SparcInstrInfo.td:726
    LDCri                                 = 622, // SparcInstrInfo.td:530
    LDCrr                                 = 623, // SparcInstrInfo.td:525
    LDDAri                                = 624, // SparcInstrInfo.td:545
    LDDArr                                = 625, // SparcInstrInfo.td:540
    LDDCri                                = 626, // SparcInstrInfo.td:530
    LDDCrr                                = 627, // SparcInstrInfo.td:525
    LDDFAri                               = 628, // SparcInstrInfo.td:545
    LDDFArr                               = 629, // SparcInstrInfo.td:540
    LDDFri                                = 630, // SparcInstrInfo.td:530
    LDDFrr                                = 631, // SparcInstrInfo.td:525
    LDDri                                 = 632, // SparcInstrInfo.td:530
    LDDrr                                 = 633, // SparcInstrInfo.td:525
    LDFAri                                = 634, // SparcInstrInfo.td:545
    LDFArr                                = 635, // SparcInstrInfo.td:540
    LDFSRri                               = 636, // SparcInstrInfo.td:737
    LDFSRrr                               = 637, // SparcInstrInfo.td:735
    LDFri                                 = 638, // SparcInstrInfo.td:530
    LDFrr                                 = 639, // SparcInstrInfo.td:525
    LDQFAri                               = 640, // SparcInstrInfo.td:545
    LDQFArr                               = 641, // SparcInstrInfo.td:540
    LDQFri                                = 642, // SparcInstrInfo.td:530
    LDQFrr                                = 643, // SparcInstrInfo.td:525
    LDSBAri                               = 644, // SparcInstrInfo.td:545
    LDSBArr                               = 645, // SparcInstrInfo.td:540
    LDSBri                                = 646, // SparcInstrInfo.td:530
    LDSBrr                                = 647, // SparcInstrInfo.td:525
    LDSHAri                               = 648, // SparcInstrInfo.td:545
    LDSHArr                               = 649, // SparcInstrInfo.td:540
    LDSHri                                = 650, // SparcInstrInfo.td:530
    LDSHrr                                = 651, // SparcInstrInfo.td:525
    LDSTUBAri                             = 652, // SparcInstrInfo.td:828
    LDSTUBArr                             = 653, // SparcInstrInfo.td:824
    LDSTUBri                              = 654, // SparcInstrInfo.td:822
    LDSTUBrr                              = 655, // SparcInstrInfo.td:820
    LDSWAri                               = 656, // SparcInstrInfo.td:545
    LDSWArr                               = 657, // SparcInstrInfo.td:540
    LDSWri                                = 658, // SparcInstrInfo.td:530
    LDSWrr                                = 659, // SparcInstrInfo.td:525
    LDUBAri                               = 660, // SparcInstrInfo.td:545
    LDUBArr                               = 661, // SparcInstrInfo.td:540
    LDUBri                                = 662, // SparcInstrInfo.td:530
    LDUBrr                                = 663, // SparcInstrInfo.td:525
    LDUHAri                               = 664, // SparcInstrInfo.td:545
    LDUHArr                               = 665, // SparcInstrInfo.td:540
    LDUHri                                = 666, // SparcInstrInfo.td:530
    LDUHrr                                = 667, // SparcInstrInfo.td:525
    LDXAri                                = 668, // SparcInstrInfo.td:545
    LDXArr                                = 669, // SparcInstrInfo.td:540
    LDXFSRri                              = 670, // SparcInstrInfo.td:743
    LDXFSRrr                              = 671, // SparcInstrInfo.td:741
    LDXri                                 = 672, // SparcInstrInfo.td:530
    LDXrr                                 = 673, // SparcInstrInfo.td:525
    LDri                                  = 674, // SparcInstrInfo.td:530
    LDrr                                  = 675, // SparcInstrInfo.td:525
    LZCNT                                 = 676, // SparcInstrVIS.td:258
    MD5                                   = 677, // SparcInstrCrypto.td:65
    MEMBARi                               = 678, // SparcInstrInfo.td:1804
    MONTMUL                               = 679, // SparcInstrCrypto.td:95
    MONTSQR                               = 680, // SparcInstrCrypto.td:96
    MOVDTOX                               = 681, // SparcInstrVIS.td:266
    MOVFCCri                              = 682, // SparcInstrInfo.td:1664
    MOVFCCrr                              = 683, // SparcInstrInfo.td:1659
    MOVICCri                              = 684, // SparcInstrInfo.td:1650
    MOVICCrr                              = 685, // SparcInstrInfo.td:1644
    MOVRri                                = 686, // SparcInstr64Bit.td:361
    MOVRrr                                = 687, // SparcInstr64Bit.td:356
    MOVSTOSW                              = 688, // SparcInstrVIS.td:262
    MOVSTOUW                              = 689, // SparcInstrVIS.td:264
    MOVWTOS                               = 690, // SparcInstrVIS.td:268
    MOVXCCri                              = 691, // SparcInstr64Bit.td:302
    MOVXCCrr                              = 692, // SparcInstr64Bit.td:297
    MOVXTOD                               = 693, // SparcInstrVIS.td:270
    MPMUL                                 = 694, // SparcInstrCrypto.td:94
    MULSCCri                              = 695, // SparcInstrInfo.td:516
    MULSCCrr                              = 696, // SparcInstrInfo.td:512
    MULXri                                = 697, // SparcInstrInfo.td:502
    MULXrr                                = 698, // SparcInstrInfo.td:497
    NOP                                   = 699, // SparcInstrInfo.td:865
    NORMALW                               = 700, // SparcInstrUAOSA.td:41
    ORCCri                                = 701, // SparcInstrInfo.td:516
    ORCCrr                                = 702, // SparcInstrInfo.td:512
    ORNCCri                               = 703, // SparcInstrInfo.td:516
    ORNCCrr                               = 704, // SparcInstrInfo.td:512
    ORNri                                 = 705, // SparcInstrInfo.td:884
    ORNrr                                 = 706, // SparcInstrInfo.td:880
    ORri                                  = 707, // SparcInstrInfo.td:502
    ORrr                                  = 708, // SparcInstrInfo.td:497
    OTHERW                                = 709, // SparcInstrUAOSA.td:42
    PDIST                                 = 710, // SparcInstrVIS.td:151
    PDISTN                                = 711, // SparcInstrVIS.td:274
    POPCrr                                = 712, // SparcInstrInfo.td:1797
    PREFETCHAi                            = 713, // SparcInstrInfo.td:1900
    PREFETCHAr                            = 714, // SparcInstrInfo.td:1896
    PREFETCHi                             = 715, // SparcInstrInfo.td:1893
    PREFETCHr                             = 716, // SparcInstrInfo.td:1890
    PWRPSRri                              = 717, // SparcInstrInfo.td:1857
    PWRPSRrr                              = 718, // SparcInstrInfo.td:1854
    RDASR                                 = 719, // SparcInstrInfo.td:1254
    RDFQ                                  = 720, // SparcInstrInfo.td:1919
    RDPR                                  = 721, // SparcInstrInfo.td:1910
    RDPSR                                 = 722, // SparcInstrInfo.td:1261
    RDTBR                                 = 723, // SparcInstrInfo.td:1271
    RDWIM                                 = 724, // SparcInstrInfo.td:1266
    RESTORED                              = 725, // SparcInstrInfo.td:1885
    RESTOREri                             = 726, // SparcInstrInfo.td:516
    RESTORErr                             = 727, // SparcInstrInfo.td:512
    RET                                   = 728, // SparcInstrInfo.td:1194
    RETL                                  = 729, // SparcInstrInfo.td:1187
    RETRY                                 = 730, // SparcInstrInfo.td:1879
    RETTri                                = 731, // SparcInstrInfo.td:1209
    RETTrr                                = 732, // SparcInstrInfo.td:1204
    SAVED                                 = 733, // SparcInstrInfo.td:1882
    SAVEri                                = 734, // SparcInstrInfo.td:516
    SAVErr                                = 735, // SparcInstrInfo.td:512
    SDIVCCri                              = 736, // SparcInstrInfo.td:516
    SDIVCCrr                              = 737, // SparcInstrInfo.td:512
    SDIVXri                               = 738, // SparcInstrInfo.td:502
    SDIVXrr                               = 739, // SparcInstrInfo.td:497
    SDIVri                                = 740, // SparcInstrInfo.td:516
    SDIVrr                                = 741, // SparcInstrInfo.td:512
    SETHIi                                = 742, // SparcInstrInfo.td:856
    SHA1                                  = 743, // SparcInstrCrypto.td:68
    SHA256                                = 744, // SparcInstrCrypto.td:71
    SHA512                                = 745, // SparcInstrCrypto.td:75
    SHUTDOWN                              = 746, // SparcInstrVIS.td:157
    SIAM                                  = 747, // SparcInstrVIS.td:169
    SIR                                   = 748, // SparcInstrInfo.td:1808
    SLLXri                                = 749, // SparcInstrFormats.td:299
    SLLXrr                                = 750, // SparcInstrFormats.td:295
    SLLri                                 = 751, // SparcInstrFormats.td:299
    SLLrr                                 = 752, // SparcInstrFormats.td:295
    SMACri                                = 753, // SparcInstrInfo.td:1835
    SMACrr                                = 754, // SparcInstrInfo.td:1830
    SMULCCri                              = 755, // SparcInstrInfo.td:516
    SMULCCrr                              = 756, // SparcInstrInfo.td:512
    SMULri                                = 757, // SparcInstrInfo.td:502
    SMULrr                                = 758, // SparcInstrInfo.td:497
    SRAXri                                = 759, // SparcInstrFormats.td:299
    SRAXrr                                = 760, // SparcInstrFormats.td:295
    SRAri                                 = 761, // SparcInstrFormats.td:299
    SRArr                                 = 762, // SparcInstrFormats.td:295
    SRLXri                                = 763, // SparcInstrFormats.td:299
    SRLXrr                                = 764, // SparcInstrFormats.td:295
    SRLri                                 = 765, // SparcInstrFormats.td:299
    SRLrr                                 = 766, // SparcInstrFormats.td:295
    STAri                                 = 767, // SparcInstrInfo.td:581
    STArr                                 = 768, // SparcInstrInfo.td:575
    STBAR                                 = 769, // SparcInstrInfo.td:1316
    STBAri                                = 770, // SparcInstrInfo.td:581
    STBArr                                = 771, // SparcInstrInfo.td:575
    STBri                                 = 772, // SparcInstrInfo.td:566
    STBrr                                 = 773, // SparcInstrInfo.td:561
    STCSRri                               = 774, // SparcInstrInfo.td:784
    STCSRrr                               = 775, // SparcInstrInfo.td:782
    STCri                                 = 776, // SparcInstrInfo.td:566
    STCrr                                 = 777, // SparcInstrInfo.td:561
    STDAri                                = 778, // SparcInstrInfo.td:581
    STDArr                                = 779, // SparcInstrInfo.td:575
    STDCQri                               = 780, // SparcInstrInfo.td:790
    STDCQrr                               = 781, // SparcInstrInfo.td:788
    STDCri                                = 782, // SparcInstrInfo.td:566
    STDCrr                                = 783, // SparcInstrInfo.td:561
    STDFAri                               = 784, // SparcInstrInfo.td:581
    STDFArr                               = 785, // SparcInstrInfo.td:575
    STDFQri                               = 786, // SparcInstrInfo.td:805
    STDFQrr                               = 787, // SparcInstrInfo.td:803
    STDFri                                = 788, // SparcInstrInfo.td:566
    STDFrr                                = 789, // SparcInstrInfo.td:561
    STDri                                 = 790, // SparcInstrInfo.td:566
    STDrr                                 = 791, // SparcInstrInfo.td:561
    STFAri                                = 792, // SparcInstrInfo.td:581
    STFArr                                = 793, // SparcInstrInfo.td:575
    STFSRri                               = 794, // SparcInstrInfo.td:799
    STFSRrr                               = 795, // SparcInstrInfo.td:797
    STFri                                 = 796, // SparcInstrInfo.td:566
    STFrr                                 = 797, // SparcInstrInfo.td:561
    STHAri                                = 798, // SparcInstrInfo.td:581
    STHArr                                = 799, // SparcInstrInfo.td:575
    STHri                                 = 800, // SparcInstrInfo.td:566
    STHrr                                 = 801, // SparcInstrInfo.td:561
    STQFAri                               = 802, // SparcInstrInfo.td:581
    STQFArr                               = 803, // SparcInstrInfo.td:575
    STQFri                                = 804, // SparcInstrInfo.td:566
    STQFrr                                = 805, // SparcInstrInfo.td:561
    STXAri                                = 806, // SparcInstrInfo.td:581
    STXArr                                = 807, // SparcInstrInfo.td:575
    STXFSRri                              = 808, // SparcInstrInfo.td:812
    STXFSRrr                              = 809, // SparcInstrInfo.td:810
    STXri                                 = 810, // SparcInstrInfo.td:566
    STXrr                                 = 811, // SparcInstrInfo.td:561
    STri                                  = 812, // SparcInstrInfo.td:566
    STrr                                  = 813, // SparcInstrInfo.td:561
    SUBCCri                               = 814, // SparcInstrInfo.td:502
    SUBCCrr                               = 815, // SparcInstrInfo.td:497
    SUBCri                                = 816, // SparcInstrInfo.td:516
    SUBCrr                                = 817, // SparcInstrInfo.td:512
    SUBEri                                = 818, // SparcInstrInfo.td:502
    SUBErr                                = 819, // SparcInstrInfo.td:497
    SUBri                                 = 820, // SparcInstrInfo.td:502
    SUBrr                                 = 821, // SparcInstrInfo.td:497
    SWAPAri                               = 822, // SparcInstrInfo.td:848
    SWAPArr                               = 823, // SparcInstrInfo.td:843
    SWAPri                                = 824, // SparcInstrInfo.td:839
    SWAPrr                                = 825, // SparcInstrInfo.td:835
    TA1                                   = 826, // SparcInstrInfo.td:1250
    TA3                                   = 827, // SparcInstrInfo.td:627
    TA5                                   = 828, // SparcInstrInfo.td:1247
    TADDCCTVri                            = 829, // SparcInstrInfo.td:516
    TADDCCTVrr                            = 830, // SparcInstrInfo.td:512
    TADDCCri                              = 831, // SparcInstrInfo.td:516
    TADDCCrr                              = 832, // SparcInstrInfo.td:512
    TAIL_CALL                             = 833, // SparcInstrInfo.td:1616
    TAIL_CALLri                           = 834, // SparcInstrInfo.td:1630
    TICCri                                = 835, // SparcInstrInfo.td:1236
    TICCrr                                = 836, // SparcInstrInfo.td:1232
    TLS_ADDrr                             = 837, // SparcInstrInfo.td:1582
    TLS_CALL                              = 838, // SparcInstrInfo.td:1599
    TLS_LDXrr                             = 839, // SparcInstr64Bit.td:213
    TLS_LDrr                              = 840, // SparcInstrInfo.td:1590
    TRAPri                                = 841, // SparcInstrInfo.td:1225
    TRAPrr                                = 842, // SparcInstrInfo.td:1221
    TSUBCCTVri                            = 843, // SparcInstrInfo.td:516
    TSUBCCTVrr                            = 844, // SparcInstrInfo.td:512
    TSUBCCri                              = 845, // SparcInstrInfo.td:516
    TSUBCCrr                              = 846, // SparcInstrInfo.td:512
    TXCCri                                = 847, // SparcInstrInfo.td:1236
    TXCCrr                                = 848, // SparcInstrInfo.td:1232
    UDIVCCri                              = 849, // SparcInstrInfo.td:516
    UDIVCCrr                              = 850, // SparcInstrInfo.td:512
    UDIVXri                               = 851, // SparcInstrInfo.td:502
    UDIVXrr                               = 852, // SparcInstrInfo.td:497
    UDIVri                                = 853, // SparcInstrInfo.td:516
    UDIVrr                                = 854, // SparcInstrInfo.td:512
    UMACri                                = 855, // SparcInstrInfo.td:1845
    UMACrr                                = 856, // SparcInstrInfo.td:1840
    UMULCCri                              = 857, // SparcInstrInfo.td:516
    UMULCCrr                              = 858, // SparcInstrInfo.td:512
    UMULXHI                               = 859, // SparcInstrVIS.td:276
    UMULri                                = 860, // SparcInstrInfo.td:502
    UMULrr                                = 861, // SparcInstrInfo.td:497
    UNIMP                                 = 862, // SparcInstrInfo.td:1321
    V9FCMPD                               = 863, // SparcInstrInfo.td:1745
    V9FCMPED                              = 864, // SparcInstrInfo.td:1757
    V9FCMPEQ                              = 865, // SparcInstrInfo.td:1760
    V9FCMPES                              = 866, // SparcInstrInfo.td:1754
    V9FCMPQ                               = 867, // SparcInstrInfo.td:1748
    V9FCMPS                               = 868, // SparcInstrInfo.td:1742
    V9FMOVD_FCC                           = 869, // SparcInstrInfo.td:1781
    V9FMOVQ_FCC                           = 870, // SparcInstrInfo.td:1786
    V9FMOVS_FCC                           = 871, // SparcInstrInfo.td:1777
    V9MOVFCCri                            = 872, // SparcInstrInfo.td:1773
    V9MOVFCCrr                            = 873, // SparcInstrInfo.td:1769
    WRASRri                               = 874, // SparcInstrInfo.td:1280
    WRASRrr                               = 875, // SparcInstrInfo.td:1277
    WRPRri                                = 876, // SparcInstrInfo.td:1929
    WRPRrr                                = 877, // SparcInstrInfo.td:1926
    WRPSRri                               = 878, // SparcInstrInfo.td:1290
    WRPSRrr                               = 879, // SparcInstrInfo.td:1287
    WRTBRri                               = 880, // SparcInstrInfo.td:1308
    WRTBRrr                               = 881, // SparcInstrInfo.td:1305
    WRWIMri                               = 882, // SparcInstrInfo.td:1299
    WRWIMrr                               = 883, // SparcInstrInfo.td:1296
    XMULX                                 = 884, // SparcInstrVIS.td:277
    XMULXHI                               = 885, // SparcInstrVIS.td:278
    XNORCCri                              = 886, // SparcInstrInfo.td:516
    XNORCCrr                              = 887, // SparcInstrInfo.td:512
    XNORri                                = 888, // SparcInstrInfo.td:893
    XNORrr                                = 889, // SparcInstrInfo.td:889
    XORCCri                               = 890, // SparcInstrInfo.td:516
    XORCCrr                               = 891, // SparcInstrInfo.td:512
    XORri                                 = 892, // SparcInstrInfo.td:502
    XORrr                                 = 893, // SparcInstrInfo.td:497
    INSTRUCTION_LIST_END = 894
  };
  enum RegClassByHwModeUses : uint16_t {
    sparc_ptr_rc,
  };

} // namespace llvm_ks::SP

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::SP::Sched {

  enum {
    NoInstrModel	= 0,
    IIC_iu_instr	= 1,
    IIC_fpu_normal_instr	= 2,
    IIC_jmp_or_call	= 3,
    IIC_fpu_abs	= 4,
    IIC_fpu_fast_instr	= 5,
    IIC_fpu_divd	= 6,
    IIC_fpu_divs	= 7,
    IIC_fpu_muld	= 8,
    IIC_fpu_muls	= 9,
    IIC_fpu_negs	= 10,
    IIC_fpu_sqrtd	= 11,
    IIC_fpu_sqrts	= 12,
    IIC_fpu_stod	= 13,
    IIC_ldd	= 14,
    IIC_iu_or_fpu_instr	= 15,
    IIC_iu_div	= 16,
    IIC_smac_umac	= 17,
    IIC_iu_smul	= 18,
    IIC_st	= 19,
    IIC_std	= 20,
    IIC_iu_umul	= 21,
    SCHED_LIST_END = 22
  };

} // namespace llvm_ks::SP::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct SparcInstrTable {
  MCInstrDesc Insts[894];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[218];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[575];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof SparcInstrTable::ImplicitOps + sizeof SparcInstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned SparcOpInfoBase = (sizeof SparcInstrTable::ImplicitOps + sizeof SparcInstrTable::Padding) / sizeof(MCOperandInfo);

extern const SparcInstrTable SparcDescs = {
  {
    { 893,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // XORrr
    { 892,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 172,	0,	0, 0x0ULL },  // XORri
    { 891,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XORCCrr
    { 890,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XORCCri
    { 889,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // XNORrr
    { 888,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 172,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XNORri
    { 887,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XNORCCrr
    { 886,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XNORCCri
    { 885,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XMULXHI
    { 884,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // XMULX
    { 883,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 417,	141,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRWIMrr
    { 882,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 167,	141,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRWIMri
    { 881,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 417,	140,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRTBRrr
    { 880,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 167,	140,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRTBRri
    { 879,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 417,	138,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRPSRrr
    { 878,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 167,	138,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRPSRri
    { 877,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 572,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRPRrr
    { 876,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 569,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRPRri
    { 875,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 566,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRASRrr
    { 874,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 563,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRASRri
    { 873,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 558,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9MOVFCCrr
    { 872,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 553,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9MOVFCCri
    { 871,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 548,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9FMOVS_FCC
    { 870,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 543,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9FMOVQ_FCC
    { 869,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 538,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9FMOVD_FCC
    { 868,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 268,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9FCMPS
    { 867,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 535,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9FCMPQ
    { 866,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 268,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9FCMPES
    { 865,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 535,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9FCMPEQ
    { 864,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 265,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9FCMPED
    { 863,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 265,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V9FCMPD
    { 862,	1,	0,	4,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UNIMP
    { 861,	3,	1,	4,	21,	0,	1,	SparcOpInfoBase + 175,	215,	0, 0x0ULL },  // UMULrr
    { 860,	3,	1,	4,	21,	0,	1,	SparcOpInfoBase + 172,	215,	0, 0x0ULL },  // UMULri
    { 859,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0, 0x0ULL },  // UMULXHI
    { 858,	3,	1,	4,	21,	0,	2,	SparcOpInfoBase + 175,	213,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UMULCCrr
    { 857,	3,	1,	4,	21,	0,	2,	SparcOpInfoBase + 172,	213,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UMULCCri
    { 856,	3,	1,	4,	17,	2,	2,	SparcOpInfoBase + 175,	209,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UMACrr
    { 855,	3,	1,	4,	17,	2,	2,	SparcOpInfoBase + 172,	209,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UMACri
    { 854,	3,	1,	4,	16,	1,	1,	SparcOpInfoBase + 175,	145,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UDIVrr
    { 853,	3,	1,	4,	16,	1,	1,	SparcOpInfoBase + 172,	145,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UDIVri
    { 852,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UDIVXrr
    { 851,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 414,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UDIVXri
    { 850,	3,	1,	4,	16,	1,	2,	SparcOpInfoBase + 175,	142,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UDIVCCrr
    { 849,	3,	1,	4,	16,	1,	2,	SparcOpInfoBase + 172,	142,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UDIVCCri
    { 848,	3,	0,	4,	0,	1,	0,	SparcOpInfoBase + 440,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TXCCrr
    { 847,	3,	0,	4,	0,	1,	0,	SparcOpInfoBase + 528,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TXCCri
    { 846,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TSUBCCrr
    { 845,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TSUBCCri
    { 844,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TSUBCCTVrr
    { 843,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TSUBCCTVri
    { 842,	3,	0,	4,	0,	1,	0,	SparcOpInfoBase + 440,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TRAPrr
    { 841,	3,	0,	4,	0,	1,	0,	SparcOpInfoBase + 528,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TRAPri
    { 840,	4,	1,	4,	1,	0,	0,	SparcOpInfoBase + 318,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // TLS_LDrr
    { 839,	4,	1,	4,	1,	0,	0,	SparcOpInfoBase + 318,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // TLS_LDXrr
    { 838,	2,	0,	4,	3,	1,	0,	SparcOpInfoBase + 189,	217,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL },  // TLS_CALL
    { 837,	4,	1,	4,	1,	0,	0,	SparcOpInfoBase + 531,	0,	0, 0x0ULL },  // TLS_ADDrr
    { 836,	3,	0,	4,	0,	1,	0,	SparcOpInfoBase + 440,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TICCrr
    { 835,	3,	0,	4,	0,	1,	0,	SparcOpInfoBase + 528,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TICCri
    { 834,	2,	0,	4,	1,	0,	0,	SparcOpInfoBase + 191,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic), 0x0ULL },  // TAIL_CALLri
    { 833,	1,	0,	4,	0,	0,	0,	SparcOpInfoBase + 188,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic), 0x0ULL },  // TAIL_CALL
    { 832,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TADDCCrr
    { 831,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TADDCCri
    { 830,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TADDCCTVrr
    { 829,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TADDCCTVri
    { 828,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TA5
    { 827,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TA3
    { 826,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TA1
    { 825,	4,	1,	4,	1,	0,	0,	SparcOpInfoBase + 524,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // SWAPrr
    { 824,	4,	1,	4,	1,	0,	0,	SparcOpInfoBase + 515,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // SWAPri
    { 823,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 519,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SWAPArr
    { 822,	4,	1,	4,	1,	1,	0,	SparcOpInfoBase + 515,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SWAPAri
    { 821,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // SUBrr
    { 820,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 172,	0,	0, 0x0ULL },  // SUBri
    { 819,	3,	1,	4,	1,	1,	1,	SparcOpInfoBase + 175,	5,	0, 0x0ULL },  // SUBErr
    { 818,	3,	1,	4,	1,	1,	1,	SparcOpInfoBase + 172,	5,	0, 0x0ULL },  // SUBEri
    { 817,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBCrr
    { 816,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SUBCri
    { 815,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::HasPostISelHook), 0x0ULL },  // SUBCCrr
    { 814,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::HasPostISelHook), 0x0ULL },  // SUBCCri
    { 813,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 450,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STrr
    { 812,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 443,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STri
    { 811,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 512,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STXrr
    { 810,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 505,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STXri
    { 809,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 193,	11,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STXFSRrr
    { 808,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 191,	11,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STXFSRri
    { 807,	4,	0,	4,	19,	0,	0,	SparcOpInfoBase + 508,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STXArr
    { 806,	3,	0,	4,	19,	1,	0,	SparcOpInfoBase + 505,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STXAri
    { 805,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 502,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STQFrr
    { 804,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 495,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STQFri
    { 803,	4,	0,	4,	19,	0,	0,	SparcOpInfoBase + 498,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STQFArr
    { 802,	3,	0,	4,	19,	1,	0,	SparcOpInfoBase + 495,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STQFAri
    { 801,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 450,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STHrr
    { 800,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 443,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STHri
    { 799,	4,	0,	4,	19,	0,	0,	SparcOpInfoBase + 446,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STHArr
    { 798,	3,	0,	4,	19,	1,	0,	SparcOpInfoBase + 443,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STHAri
    { 797,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 492,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STFrr
    { 796,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 485,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STFri
    { 795,	2,	0,	4,	19,	1,	0,	SparcOpInfoBase + 193,	11,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STFSRrr
    { 794,	2,	0,	4,	19,	1,	0,	SparcOpInfoBase + 191,	11,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STFSRri
    { 793,	4,	0,	4,	19,	0,	0,	SparcOpInfoBase + 488,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STFArr
    { 792,	3,	0,	4,	19,	1,	0,	SparcOpInfoBase + 485,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STFAri
    { 791,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 482,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STDrr
    { 790,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 459,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STDri
    { 789,	3,	0,	4,	20,	0,	0,	SparcOpInfoBase + 479,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STDFrr
    { 788,	3,	0,	4,	20,	0,	0,	SparcOpInfoBase + 472,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STDFri
    { 787,	2,	0,	4,	20,	0,	1,	SparcOpInfoBase + 193,	139,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STDFQrr
    { 786,	2,	0,	4,	20,	0,	1,	SparcOpInfoBase + 191,	139,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STDFQri
    { 785,	4,	0,	4,	19,	0,	0,	SparcOpInfoBase + 475,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STDFArr
    { 784,	3,	0,	4,	19,	1,	0,	SparcOpInfoBase + 472,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STDFAri
    { 783,	3,	0,	4,	20,	0,	0,	SparcOpInfoBase + 469,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STDCrr
    { 782,	3,	0,	4,	20,	0,	0,	SparcOpInfoBase + 466,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STDCri
    { 781,	2,	0,	4,	20,	1,	0,	SparcOpInfoBase + 193,	216,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STDCQrr
    { 780,	2,	0,	4,	20,	1,	0,	SparcOpInfoBase + 191,	216,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STDCQri
    { 779,	4,	0,	4,	19,	0,	0,	SparcOpInfoBase + 462,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STDArr
    { 778,	3,	0,	4,	19,	1,	0,	SparcOpInfoBase + 459,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STDAri
    { 777,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 456,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STCrr
    { 776,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 453,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STCri
    { 775,	2,	0,	4,	19,	1,	0,	SparcOpInfoBase + 193,	10,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STCSRrr
    { 774,	2,	0,	4,	19,	1,	0,	SparcOpInfoBase + 191,	10,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STCSRri
    { 773,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 450,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STBrr
    { 772,	3,	0,	4,	19,	0,	0,	SparcOpInfoBase + 443,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STBri
    { 771,	4,	0,	4,	19,	0,	0,	SparcOpInfoBase + 446,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STBArr
    { 770,	3,	0,	4,	19,	1,	0,	SparcOpInfoBase + 443,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STBAri
    { 769,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STBAR
    { 768,	4,	0,	4,	19,	0,	0,	SparcOpInfoBase + 446,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STArr
    { 767,	3,	0,	4,	19,	1,	0,	SparcOpInfoBase + 443,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STAri
    { 766,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // SRLrr
    { 765,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 440,	0,	0, 0x0ULL },  // SRLri
    { 764,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 437,	0,	0, 0x0ULL },  // SRLXrr
    { 763,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 434,	0,	0, 0x0ULL },  // SRLXri
    { 762,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // SRArr
    { 761,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 440,	0,	0, 0x0ULL },  // SRAri
    { 760,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 437,	0,	0, 0x0ULL },  // SRAXrr
    { 759,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 434,	0,	0, 0x0ULL },  // SRAXri
    { 758,	3,	1,	4,	18,	0,	1,	SparcOpInfoBase + 175,	215,	0, 0x0ULL },  // SMULrr
    { 757,	3,	1,	4,	18,	0,	1,	SparcOpInfoBase + 172,	215,	0, 0x0ULL },  // SMULri
    { 756,	3,	1,	4,	18,	0,	2,	SparcOpInfoBase + 175,	213,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SMULCCrr
    { 755,	3,	1,	4,	18,	0,	2,	SparcOpInfoBase + 172,	213,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SMULCCri
    { 754,	3,	1,	4,	17,	2,	2,	SparcOpInfoBase + 175,	209,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SMACrr
    { 753,	3,	1,	4,	17,	2,	2,	SparcOpInfoBase + 172,	209,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SMACri
    { 752,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // SLLrr
    { 751,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 440,	0,	0, 0x0ULL },  // SLLri
    { 750,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 437,	0,	0, 0x0ULL },  // SLLXrr
    { 749,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 434,	0,	0, 0x0ULL },  // SLLXri
    { 748,	1,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SIR
    { 747,	1,	0,	4,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SIAM
    { 746,	0,	0,	4,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SHUTDOWN
    { 745,	0,	0,	4,	0,	24,	8,	SparcOpInfoBase + 1,	177,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SHA512
    { 744,	0,	0,	4,	0,	12,	4,	SparcOpInfoBase + 1,	161,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SHA256
    { 743,	0,	0,	4,	0,	11,	3,	SparcOpInfoBase + 1,	147,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SHA1
    { 742,	2,	1,	4,	1,	0,	0,	SparcOpInfoBase + 167,	0,	0, 0x0ULL },  // SETHIi
    { 741,	3,	1,	4,	16,	1,	1,	SparcOpInfoBase + 175,	145,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SDIVrr
    { 740,	3,	1,	4,	16,	1,	1,	SparcOpInfoBase + 172,	145,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SDIVri
    { 739,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SDIVXrr
    { 738,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 414,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SDIVXri
    { 737,	3,	1,	4,	16,	1,	2,	SparcOpInfoBase + 175,	142,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SDIVCCrr
    { 736,	3,	1,	4,	16,	1,	2,	SparcOpInfoBase + 172,	142,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SDIVCCri
    { 735,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SAVErr
    { 734,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 172,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SAVEri
    { 733,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SAVED
    { 732,	2,	0,	4,	3,	0,	0,	SparcOpInfoBase + 193,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RETTrr
    { 731,	2,	0,	4,	3,	0,	0,	SparcOpInfoBase + 191,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RETTri
    { 730,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RETRY
    { 729,	1,	0,	4,	3,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // RETL
    { 728,	1,	0,	4,	3,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RET
    { 727,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RESTORErr
    { 726,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 172,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RESTOREri
    { 725,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RESTORED
    { 724,	1,	1,	4,	1,	1,	0,	SparcOpInfoBase + 431,	141,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDWIM
    { 723,	1,	1,	4,	1,	1,	0,	SparcOpInfoBase + 431,	140,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDTBR
    { 722,	1,	1,	4,	1,	1,	0,	SparcOpInfoBase + 431,	138,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDPSR
    { 721,	2,	1,	4,	1,	0,	0,	SparcOpInfoBase + 432,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDPR
    { 720,	1,	1,	4,	1,	1,	0,	SparcOpInfoBase + 431,	139,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDFQ
    { 719,	2,	1,	4,	1,	0,	0,	SparcOpInfoBase + 429,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDASR
    { 718,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 417,	138,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PWRPSRrr
    { 717,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 167,	138,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PWRPSRri
    { 716,	3,	0,	4,	1,	0,	0,	SparcOpInfoBase + 426,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREFETCHr
    { 715,	3,	0,	4,	1,	0,	0,	SparcOpInfoBase + 419,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREFETCHi
    { 714,	4,	0,	4,	0,	0,	0,	SparcOpInfoBase + 422,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREFETCHAr
    { 713,	3,	0,	4,	1,	1,	0,	SparcOpInfoBase + 419,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREFETCHAi
    { 712,	2,	1,	4,	1,	0,	0,	SparcOpInfoBase + 417,	0,	0, 0x0ULL },  // POPCrr
    { 711,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PDISTN
    { 710,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PDIST
    { 709,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // OTHERW
    { 708,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // ORrr
    { 707,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 172,	0,	0, 0x0ULL },  // ORri
    { 706,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // ORNrr
    { 705,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 172,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ORNri
    { 704,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ORNCCrr
    { 703,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ORNCCri
    { 702,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ORCCrr
    { 701,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ORCCri
    { 700,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // NORMALW
    { 699,	0,	0,	4,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // NOP
    { 698,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 178,	0,	0, 0x0ULL },  // MULXrr
    { 697,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 414,	0,	0, 0x0ULL },  // MULXri
    { 696,	3,	1,	4,	1,	2,	2,	SparcOpInfoBase + 175,	134,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MULSCCrr
    { 695,	3,	1,	4,	1,	2,	2,	SparcOpInfoBase + 172,	134,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MULSCCri
    { 694,	1,	0,	4,	0,	52,	52,	SparcOpInfoBase + 1,	30,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MPMUL
    { 693,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 412,	0,	0, 0x0ULL },  // MOVXTOD
    { 692,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 394,	4,	0, 0x0ULL },  // MOVXCCrr
    { 691,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 390,	4,	0, 0x0ULL },  // MOVXCCri
    { 690,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 410,	0,	0, 0x0ULL },  // MOVWTOS
    { 689,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 408,	0,	0, 0x0ULL },  // MOVSTOUW
    { 688,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 408,	0,	0, 0x0ULL },  // MOVSTOSW
    { 687,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 403,	0,	0, 0x0ULL },  // MOVRrr
    { 686,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 398,	0,	0, 0x0ULL },  // MOVRri
    { 685,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 394,	4,	0, 0x0ULL },  // MOVICCrr
    { 684,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 390,	4,	0, 0x0ULL },  // MOVICCri
    { 683,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 394,	3,	0, 0x0ULL },  // MOVFCCrr
    { 682,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 390,	3,	0, 0x0ULL },  // MOVFCCri
    { 681,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 388,	0,	0, 0x0ULL },  // MOVDTOX
    { 680,	1,	0,	4,	0,	52,	52,	SparcOpInfoBase + 1,	30,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MONTSQR
    { 679,	1,	0,	4,	0,	52,	52,	SparcOpInfoBase + 1,	30,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MONTMUL
    { 678,	1,	0,	4,	1,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MEMBARi
    { 677,	0,	0,	4,	0,	10,	8,	SparcOpInfoBase + 1,	12,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MD5
    { 676,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 386,	0,	0, 0x0ULL },  // LZCNT
    { 675,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 325,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDrr
    { 674,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 322,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDri
    { 673,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 383,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDXrr
    { 672,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 380,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDXri
    { 671,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 193,	11,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDXFSRrr
    { 670,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 191,	11,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDXFSRri
    { 669,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 314,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDXArr
    { 668,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 380,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDXAri
    { 667,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 325,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDUHrr
    { 666,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 322,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDUHri
    { 665,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 318,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDUHArr
    { 664,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 322,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDUHAri
    { 663,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 325,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDUBrr
    { 662,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 322,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDUBri
    { 661,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 318,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDUBArr
    { 660,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 322,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDUBAri
    { 659,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 383,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDSWrr
    { 658,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 380,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDSWri
    { 657,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 314,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDSWArr
    { 656,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 380,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDSWAri
    { 655,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 325,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDSTUBrr
    { 654,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 322,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDSTUBri
    { 653,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 318,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDSTUBArr
    { 652,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 322,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDSTUBAri
    { 651,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 325,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDSHrr
    { 650,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 322,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDSHri
    { 649,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 318,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDSHArr
    { 648,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 322,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDSHAri
    { 647,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 325,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDSBrr
    { 646,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 322,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDSBri
    { 645,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 318,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDSBArr
    { 644,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 322,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDSBAri
    { 643,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 377,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDQFrr
    { 642,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 370,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDQFri
    { 641,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 373,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDQFArr
    { 640,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 370,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDQFAri
    { 639,	3,	1,	4,	15,	0,	0,	SparcOpInfoBase + 367,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDFrr
    { 638,	3,	1,	4,	15,	0,	0,	SparcOpInfoBase + 360,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDFri
    { 637,	2,	0,	4,	15,	0,	1,	SparcOpInfoBase + 193,	11,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDFSRrr
    { 636,	2,	0,	4,	15,	0,	1,	SparcOpInfoBase + 191,	11,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDFSRri
    { 635,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 363,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDFArr
    { 634,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 360,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDFAri
    { 633,	3,	1,	4,	14,	0,	0,	SparcOpInfoBase + 357,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDDrr
    { 632,	3,	1,	4,	14,	0,	0,	SparcOpInfoBase + 334,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDDri
    { 631,	3,	1,	4,	14,	0,	0,	SparcOpInfoBase + 354,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDDFrr
    { 630,	3,	1,	4,	14,	0,	0,	SparcOpInfoBase + 347,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDDFri
    { 629,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 350,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDDFArr
    { 628,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 347,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDDFAri
    { 627,	3,	1,	4,	14,	0,	0,	SparcOpInfoBase + 344,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDDCrr
    { 626,	3,	1,	4,	14,	0,	0,	SparcOpInfoBase + 341,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDDCri
    { 625,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 337,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDDArr
    { 624,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 334,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDDAri
    { 623,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 331,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDCrr
    { 622,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 328,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDCri
    { 621,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 193,	10,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDCSRrr
    { 620,	2,	0,	4,	1,	0,	1,	SparcOpInfoBase + 191,	10,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDCSRri
    { 619,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 318,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDArr
    { 618,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 322,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDAri
    { 617,	3,	1,	4,	3,	0,	0,	SparcOpInfoBase + 325,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JMPLrr
    { 616,	3,	1,	4,	3,	0,	0,	SparcOpInfoBase + 322,	0,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // JMPLri
    { 615,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INVALW
    { 614,	4,	1,	4,	1,	0,	0,	SparcOpInfoBase + 318,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // GDOP_LDrr
    { 613,	4,	1,	4,	1,	0,	0,	SparcOpInfoBase + 314,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // GDOP_LDXrr
    { 612,	1,	1,	4,	0,	0,	0,	SparcOpInfoBase + 309,	0,	0, 0x0ULL },  // FZEROS
    { 611,	1,	1,	4,	0,	0,	0,	SparcOpInfoBase + 308,	0,	0, 0x0ULL },  // FZERO
    { 610,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 257,	0,	0, 0x0ULL },  // FXTOS
    { 609,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 259,	0,	0, 0x0ULL },  // FXTOQ
    { 608,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0, 0x0ULL },  // FXTOD
    { 607,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FXORS
    { 606,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FXOR
    { 605,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FXNORS
    { 604,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FXNOR
    { 603,	3,	1,	4,	5,	0,	0,	SparcOpInfoBase + 248,	0,	0, 0x0ULL },  // FSUBS
    { 602,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 245,	0,	0, 0x0ULL },  // FSUBQ
    { 601,	3,	1,	4,	5,	0,	0,	SparcOpInfoBase + 185,	0,	0, 0x0ULL },  // FSUBD
    { 600,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 261,	0,	0, 0x0ULL },  // FSTOX
    { 599,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 263,	0,	0, 0x0ULL },  // FSTOQ
    { 598,	2,	1,	4,	5,	0,	0,	SparcOpInfoBase + 243,	0,	0, 0x0ULL },  // FSTOI
    { 597,	2,	1,	4,	13,	0,	0,	SparcOpInfoBase + 261,	0,	0, 0x0ULL },  // FSTOD
    { 596,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSRL32
    { 595,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSRL16
    { 594,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 243,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSRC2S
    { 593,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSRC2
    { 592,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 243,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSRC1S
    { 591,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSRC1
    { 590,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSRA32
    { 589,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSRA16
    { 588,	2,	1,	4,	12,	0,	0,	SparcOpInfoBase + 243,	0,	0, 0x0ULL },  // FSQRTS
    { 587,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 241,	0,	0, 0x0ULL },  // FSQRTQ
    { 586,	2,	1,	4,	11,	0,	0,	SparcOpInfoBase + 236,	0,	0, 0x0ULL },  // FSQRTD
    { 585,	3,	1,	4,	8,	0,	0,	SparcOpInfoBase + 305,	0,	0, 0x0ULL },  // FSMULD
    { 584,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSLL32
    { 583,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSLL16
    { 582,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSLAS32
    { 581,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FSLAS16
    { 580,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 310,	0,	0, 0x0ULL },  // FQTOX
    { 579,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 312,	0,	0, 0x0ULL },  // FQTOS
    { 578,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 312,	0,	0, 0x0ULL },  // FQTOI
    { 577,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 310,	0,	0, 0x0ULL },  // FQTOD
    { 576,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPSUB32S
    { 575,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPSUB32
    { 574,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPSUB16S
    { 573,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPSUB16
    { 572,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 305,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPMERGE
    { 571,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPMADDXHI
    { 570,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPMADDX
    { 569,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPADD64
    { 568,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPADD32S
    { 567,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPADD32
    { 566,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPADD16S
    { 565,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPADD16
    { 564,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 257,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPACKFIX
    { 563,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPACK32
    { 562,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FPACK16
    { 561,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FORS
    { 560,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FORNOT2S
    { 559,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FORNOT2
    { 558,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FORNOT1S
    { 557,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FORNOT1
    { 556,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FOR
    { 555,	1,	1,	4,	0,	0,	0,	SparcOpInfoBase + 309,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FONES
    { 554,	1,	1,	4,	0,	0,	0,	SparcOpInfoBase + 308,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FONE
    { 553,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 305,	0,	0, 0x0ULL },  // FNSMULD
    { 552,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 243,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FNOT2S
    { 551,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FNOT2
    { 550,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 243,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FNOT1S
    { 549,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FNOT1
    { 548,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FNORS
    { 547,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FNOR
    { 546,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0, 0x0ULL },  // FNMULS
    { 545,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0, 0x0ULL },  // FNMULD
    { 544,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 271,	0,	0, 0x0ULL },  // FNMSUBS
    { 543,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0, 0x0ULL },  // FNMSUBD
    { 542,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 271,	0,	0, 0x0ULL },  // FNMADDS
    { 541,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0, 0x0ULL },  // FNMADDD
    { 540,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0, 0x0ULL },  // FNHADDS
    { 539,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0, 0x0ULL },  // FNHADDD
    { 538,	2,	1,	4,	10,	0,	0,	SparcOpInfoBase + 243,	0,	0, 0x0ULL },  // FNEGS
    { 537,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 241,	0,	0, 0x0ULL },  // FNEGQ
    { 536,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0, 0x0ULL },  // FNEGD
    { 535,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FNANDS
    { 534,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FNAND
    { 533,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0, 0x0ULL },  // FNADDS
    { 532,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0, 0x0ULL },  // FNADDD
    { 531,	3,	1,	4,	9,	0,	0,	SparcOpInfoBase + 248,	0,	0, 0x0ULL },  // FMULS
    { 530,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 245,	0,	0, 0x0ULL },  // FMULQ
    { 529,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 305,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMULD8ULX16
    { 528,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 305,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMULD8SUX16
    { 527,	3,	1,	4,	8,	0,	0,	SparcOpInfoBase + 185,	0,	0, 0x0ULL },  // FMULD
    { 526,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 305,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMUL8X16AU
    { 525,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 305,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMUL8X16AL
    { 524,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 302,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMUL8X16
    { 523,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMUL8ULX16
    { 522,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMUL8SUX16
    { 521,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 271,	0,	0, 0x0ULL },  // FMSUBS
    { 520,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0, 0x0ULL },  // FMSUBD
    { 519,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 298,	4,	0, 0x0ULL },  // FMOVS_XCC
    { 518,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 298,	4,	0, 0x0ULL },  // FMOVS_ICC
    { 517,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 298,	3,	0, 0x0ULL },  // FMOVS_FCC
    { 516,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 243,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMOVS
    { 515,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 293,	0,	0, 0x0ULL },  // FMOVRS
    { 514,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 288,	0,	0, 0x0ULL },  // FMOVRQ
    { 513,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 283,	0,	0, 0x0ULL },  // FMOVRD
    { 512,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 279,	4,	0, 0x0ULL },  // FMOVQ_XCC
    { 511,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 279,	4,	0, 0x0ULL },  // FMOVQ_ICC
    { 510,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 279,	3,	0, 0x0ULL },  // FMOVQ_FCC
    { 509,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 241,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMOVQ
    { 508,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 275,	4,	0, 0x0ULL },  // FMOVD_XCC
    { 507,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 275,	4,	0, 0x0ULL },  // FMOVD_ICC
    { 506,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 275,	3,	0, 0x0ULL },  // FMOVD_FCC
    { 505,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMOVD
    { 504,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FMEAN16
    { 503,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 271,	0,	0, 0x0ULL },  // FMADDS
    { 502,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0, 0x0ULL },  // FMADDD
    { 501,	2,	0,	4,	1,	0,	0,	SparcOpInfoBase + 193,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FLUSHrr
    { 500,	2,	0,	4,	1,	0,	0,	SparcOpInfoBase + 191,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FLUSHri
    { 499,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FLUSHW
    { 498,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FLUSH
    { 497,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 268,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FLCMPS
    { 496,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 265,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FLCMPD
    { 495,	2,	1,	4,	5,	0,	0,	SparcOpInfoBase + 243,	0,	0, 0x0ULL },  // FITOS
    { 494,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 263,	0,	0, 0x0ULL },  // FITOQ
    { 493,	2,	1,	4,	5,	0,	0,	SparcOpInfoBase + 261,	0,	0, 0x0ULL },  // FITOD
    { 492,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0, 0x0ULL },  // FHSUBS
    { 491,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0, 0x0ULL },  // FHSUBD
    { 490,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0, 0x0ULL },  // FHADDS
    { 489,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0, 0x0ULL },  // FHADDD
    { 488,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 261,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FEXPAND
    { 487,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0, 0x0ULL },  // FDTOX
    { 486,	2,	1,	4,	5,	0,	0,	SparcOpInfoBase + 257,	0,	0, 0x0ULL },  // FDTOS
    { 485,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 259,	0,	0, 0x0ULL },  // FDTOQ
    { 484,	2,	1,	4,	5,	0,	0,	SparcOpInfoBase + 257,	0,	0, 0x0ULL },  // FDTOI
    { 483,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 254,	0,	0, 0x0ULL },  // FDMULQ
    { 482,	3,	1,	4,	7,	0,	0,	SparcOpInfoBase + 248,	0,	0, 0x0ULL },  // FDIVS
    { 481,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 245,	0,	0, 0x0ULL },  // FDIVQ
    { 480,	3,	1,	4,	6,	0,	0,	SparcOpInfoBase + 185,	0,	0, 0x0ULL },  // FDIVD
    { 479,	2,	0,	4,	5,	0,	1,	SparcOpInfoBase + 243,	3,	0, 0x0ULL },  // FCMPS_V9
    { 478,	2,	0,	4,	5,	0,	1,	SparcOpInfoBase + 243,	3,	0, 0x0ULL },  // FCMPS
    { 477,	2,	0,	4,	0,	0,	1,	SparcOpInfoBase + 241,	3,	0, 0x0ULL },  // FCMPQ_V9
    { 476,	2,	0,	4,	0,	0,	1,	SparcOpInfoBase + 241,	3,	0, 0x0ULL },  // FCMPQ
    { 475,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPNE32
    { 474,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPNE16
    { 473,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPLE32
    { 472,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPLE16
    { 471,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPGT32
    { 470,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPGT16
    { 469,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPEQ32
    { 468,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCMPEQ16
    { 467,	2,	0,	4,	5,	0,	1,	SparcOpInfoBase + 236,	3,	0, 0x0ULL },  // FCMPD_V9
    { 466,	2,	0,	4,	5,	0,	1,	SparcOpInfoBase + 236,	3,	0, 0x0ULL },  // FCMPD
    { 465,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FCHKSM16
    { 464,	2,	0,	4,	2,	1,	0,	SparcOpInfoBase + 189,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // FBCOND_V9
    { 463,	2,	0,	4,	2,	1,	0,	SparcOpInfoBase + 189,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // FBCONDA_V9
    { 462,	2,	0,	4,	2,	1,	0,	SparcOpInfoBase + 189,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FBCONDA
    { 461,	2,	0,	4,	2,	1,	0,	SparcOpInfoBase + 189,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // FBCOND
    { 460,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FANDS
    { 459,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FANDNOT2S
    { 458,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FANDNOT2
    { 457,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 248,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FANDNOT1S
    { 456,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FANDNOT1
    { 455,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FAND
    { 454,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FALIGNADATA
    { 453,	3,	1,	4,	5,	0,	0,	SparcOpInfoBase + 248,	0,	0, 0x0ULL },  // FADDS
    { 452,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 245,	0,	0, 0x0ULL },  // FADDQ
    { 451,	3,	1,	4,	5,	0,	0,	SparcOpInfoBase + 185,	0,	0, 0x0ULL },  // FADDD
    { 450,	2,	1,	4,	4,	0,	0,	SparcOpInfoBase + 243,	0,	0, 0x0ULL },  // FABSS
    { 449,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 241,	0,	0, 0x0ULL },  // FABSQ
    { 448,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0, 0x0ULL },  // FABSD
    { 447,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE8N
    { 446,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE8LN
    { 445,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE8L
    { 444,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE8
    { 443,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE32N
    { 442,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE32LN
    { 441,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE32L
    { 440,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE32
    { 439,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE16N
    { 438,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE16LN
    { 437,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE16L
    { 436,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // EDGE16
    { 435,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DONE
    { 434,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DES_ROUND
    { 433,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 238,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DES_KEXPAND
    { 432,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DES_IP
    { 431,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 236,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DES_IIP
    { 430,	4,	0,	4,	0,	0,	0,	SparcOpInfoBase + 232,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CXBCONDrr
    { 429,	4,	0,	4,	0,	0,	0,	SparcOpInfoBase + 228,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CXBCONDri
    { 428,	4,	0,	4,	0,	0,	0,	SparcOpInfoBase + 232,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CWBCONDrr
    { 427,	4,	0,	4,	0,	0,	0,	SparcOpInfoBase + 228,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CWBCONDri
    { 426,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CRC32C
    { 425,	2,	0,	4,	0,	0,	0,	SparcOpInfoBase + 189,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CPBCONDA
    { 424,	2,	0,	4,	0,	0,	0,	SparcOpInfoBase + 189,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // CPBCOND
    { 423,	1,	0,	4,	0,	0,	0,	SparcOpInfoBase + 227,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMASK8
    { 422,	1,	0,	4,	0,	0,	0,	SparcOpInfoBase + 227,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMASK32
    { 421,	1,	0,	4,	0,	0,	0,	SparcOpInfoBase + 227,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CMASK16
    { 420,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 222,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CASXArr
    { 419,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 218,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CASXAri
    { 418,	5,	1,	4,	0,	0,	0,	SparcOpInfoBase + 213,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // CASArr
    { 417,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 209,	9,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CASAri
    { 416,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CAMELLIA_FLI
    { 415,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CAMELLIA_FL
    { 414,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CAMELLIA_F
    { 413,	3,	0,	4,	1,	1,	1,	SparcOpInfoBase + 206,	7,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CALLrri
    { 412,	2,	0,	4,	3,	1,	1,	SparcOpInfoBase + 193,	7,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL },  // CALLrr
    { 411,	3,	0,	4,	1,	1,	1,	SparcOpInfoBase + 203,	7,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CALLrii
    { 410,	2,	0,	4,	3,	1,	1,	SparcOpInfoBase + 191,	7,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL },  // CALLri
    { 409,	2,	0,	4,	0,	1,	1,	SparcOpInfoBase + 201,	7,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CALLi
    { 408,	1,	0,	4,	3,	1,	1,	SparcOpInfoBase + 188,	7,	0|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic), 0x0ULL },  // CALL
    { 407,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BSHUFFLE
    { 406,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 189,	4,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPXCCNT
    { 405,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 189,	4,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPXCCANT
    { 404,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 189,	4,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPXCCA
    { 403,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 189,	4,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // BPXCC
    { 402,	3,	0,	4,	0,	0,	0,	SparcOpInfoBase + 198,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPRNT
    { 401,	3,	0,	4,	0,	0,	0,	SparcOpInfoBase + 198,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPRANT
    { 400,	3,	0,	4,	0,	0,	0,	SparcOpInfoBase + 198,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPRA
    { 399,	3,	0,	4,	0,	0,	0,	SparcOpInfoBase + 198,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // BPR
    { 398,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 189,	4,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPICCNT
    { 397,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 189,	4,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPICCANT
    { 396,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 189,	4,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPICCA
    { 395,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 189,	4,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // BPICC
    { 394,	3,	0,	4,	2,	0,	0,	SparcOpInfoBase + 195,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPFCCNT
    { 393,	3,	0,	4,	2,	0,	0,	SparcOpInfoBase + 195,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPFCCANT
    { 392,	3,	0,	4,	2,	0,	0,	SparcOpInfoBase + 195,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPFCCA
    { 391,	3,	0,	4,	2,	0,	0,	SparcOpInfoBase + 195,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BPFCC
    { 390,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BMASK
    { 389,	2,	0,	4,	1,	0,	0,	SparcOpInfoBase + 193,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // BINDrr
    { 388,	2,	0,	4,	1,	0,	0,	SparcOpInfoBase + 191,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // BINDri
    { 387,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 189,	4,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BCONDA
    { 386,	2,	0,	4,	1,	1,	0,	SparcOpInfoBase + 189,	4,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // BCOND
    { 385,	1,	0,	4,	0,	0,	0,	SparcOpInfoBase + 188,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::DelaySlot)|(1ULL<<MCID::Terminator), 0x0ULL },  // BA
    { 384,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ARRAY8
    { 383,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ARRAY32
    { 382,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ARRAY16
    { 381,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // ANDrr
    { 380,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 172,	0,	0, 0x0ULL },  // ANDri
    { 379,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // ANDNrr
    { 378,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 172,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ANDNri
    { 377,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ANDNCCrr
    { 376,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ANDNCCri
    { 375,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ANDCCrr
    { 374,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ANDCCri
    { 373,	0,	0,	4,	1,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ALLCLEAN
    { 372,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ALIGNADDRL
    { 371,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 178,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ALIGNADDR
    { 370,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_KEXPAND2
    { 369,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 151,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_KEXPAND1
    { 368,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 185,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_KEXPAND0
    { 367,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_EROUND23_LAST
    { 366,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_EROUND23
    { 365,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_EROUND01_LAST
    { 364,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_EROUND01
    { 363,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_DROUND23_LAST
    { 362,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_DROUND23
    { 361,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_DROUND01_LAST
    { 360,	4,	1,	4,	0,	0,	0,	SparcOpInfoBase + 181,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // AES_DROUND01
    { 359,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 175,	0,	0, 0x0ULL },  // ADDrr
    { 358,	3,	1,	4,	1,	0,	0,	SparcOpInfoBase + 172,	0,	0, 0x0ULL },  // ADDri
    { 357,	3,	1,	4,	0,	1,	1,	SparcOpInfoBase + 178,	5,	0, 0x0ULL },  // ADDXCCC
    { 356,	3,	1,	4,	0,	1,	0,	SparcOpInfoBase + 178,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDXC
    { 355,	3,	1,	4,	1,	1,	1,	SparcOpInfoBase + 175,	5,	0, 0x0ULL },  // ADDErr
    { 354,	3,	1,	4,	1,	1,	1,	SparcOpInfoBase + 172,	5,	0, 0x0ULL },  // ADDEri
    { 353,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 175,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDCrr
    { 352,	3,	1,	4,	1,	1,	0,	SparcOpInfoBase + 172,	4,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ADDCri
    { 351,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 175,	4,	0, 0x0ULL },  // ADDCCrr
    { 350,	3,	1,	4,	1,	0,	1,	SparcOpInfoBase + 172,	4,	0, 0x0ULL },  // ADDCCri
    { 349,	0,	0,	4,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // V8BAR
    { 348,	3,	1,	4,	0,	0,	0,	SparcOpInfoBase + 169,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SETX
    { 347,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 167,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SETSW
    { 346,	2,	1,	4,	0,	0,	0,	SparcOpInfoBase + 167,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SET
    { 345,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 163,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_QFP_XCC
    { 344,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 163,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_QFP_ICC
    { 343,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 163,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_QFP_FCC
    { 342,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 159,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_Int_XCC
    { 341,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 159,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_Int_ICC
    { 340,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 159,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_Int_FCC
    { 339,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 155,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_FP_XCC
    { 338,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 155,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_FP_ICC
    { 337,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 155,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_FP_FCC
    { 336,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 151,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_DFP_XCC
    { 335,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 151,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_DFP_ICC
    { 334,	4,	1,	4,	0,	1,	0,	SparcOpInfoBase + 151,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SELECT_CC_DFP_FCC
    { 333,	1,	1,	4,	0,	0,	1,	SparcOpInfoBase + 0,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // GETPCX
    { 332,	2,	0,	4,	0,	1,	1,	SparcOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // ADJCALLSTACKUP
    { 331,	2,	0,	4,	0,	1,	1,	SparcOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // ADJCALLSTACKDOWN
    { 330,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	SparcOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	SparcOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	SparcOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	SparcOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	SparcOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	SparcOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	SparcOpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	SparcOpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	SparcOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	SparcOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	SparcOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	SparcOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	SparcOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	SparcOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	SparcOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	SparcOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	SparcOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	SparcOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	SparcOpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	SparcOpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	SparcOpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	SparcOpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	SparcOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	SparcOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	SparcOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	SparcOpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	SparcOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	SparcOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	SparcOpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_16445
    { 41,	2,	0,	0,	0,	0,	0,	SparcOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_16444
    { 40,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	SparcOpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_16443
    { 31,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	SparcOpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	SparcOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	SparcOpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	0,	0,	0,	SparcOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	0,	0,	0,	SparcOpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	0,	0,	0,	SparcOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	SparcOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	SparcOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // PHI
  }, {
    /* 0 */
    /* 0 */ SP::O6, SP::O6,
    /* 2 */ SP::O7,
    /* 3 */ SP::FCC0,
    /* 4 */ SP::ICC,
    /* 5 */ SP::ICC, SP::ICC,
    /* 7 */ SP::O6, SP::O7,
    /* 9 */ SP::ASR3,
    /* 10 */ SP::CPSR,
    /* 11 */ SP::FSR,
    /* 12 */ SP::D0, SP::D1, SP::D2, SP::D5, SP::D6, SP::D7, SP::D8, SP::D9, SP::D10, SP::D11, SP::D0, SP::D1, SP::D2, SP::D3, SP::D4, SP::D5, SP::D6, SP::D7,
    /* 30 */ SP::D0, SP::D1, SP::D2, SP::D3, SP::D4, SP::D5, SP::D6, SP::D7, SP::D8, SP::D9, SP::D10, SP::D11, SP::D12, SP::D13, SP::D14, SP::D15, SP::D16, SP::D17, SP::D18, SP::D19, SP::D20, SP::D21, SP::D22, SP::D23, SP::D24, SP::D25, SP::D26, SP::D27, SP::D28, SP::D29, SP::D30, SP::D31, SP::O0, SP::O1, SP::O2, SP::O3, SP::O4, SP::O5, SP::L0, SP::L1, SP::L2, SP::L3, SP::L4, SP::L5, SP::L6, SP::L7, SP::I0, SP::I1, SP::I2, SP::I3, SP::I4, SP::I5, SP::D0, SP::D1, SP::D2, SP::D3, SP::D4, SP::D5, SP::D6, SP::D7, SP::D8, SP::D9, SP::D10, SP::D11, SP::D12, SP::D13, SP::D14, SP::D15, SP::D16, SP::D17, SP::D18, SP::D19, SP::D20, SP::D21, SP::D22, SP::D23, SP::D24, SP::D25, SP::D26, SP::D27, SP::D28, SP::D29, SP::D30, SP::D31, SP::O0, SP::O1, SP::O2, SP::O3, SP::O4, SP::O5, SP::L0, SP::L1, SP::L2, SP::L3, SP::L4, SP::L5, SP::L6, SP::L7, SP::I0, SP::I1, SP::I2, SP::I3, SP::I4, SP::I5,
    /* 134 */ SP::Y, SP::ICC, SP::Y, SP::ICC,
    /* 138 */ SP::PSR,
    /* 139 */ SP::FQ,
    /* 140 */ SP::TBR,
    /* 141 */ SP::WIM,
    /* 142 */ SP::Y, SP::Y, SP::ICC,
    /* 145 */ SP::Y, SP::Y,
    /* 147 */ SP::D0, SP::D1, SP::D2, SP::D4, SP::D5, SP::D6, SP::D7, SP::D8, SP::D9, SP::D10, SP::D11, SP::D0, SP::D1, SP::D2,
    /* 161 */ SP::D0, SP::D1, SP::D2, SP::D3, SP::D4, SP::D5, SP::D6, SP::D7, SP::D8, SP::D9, SP::D10, SP::D11, SP::D0, SP::D1, SP::D2, SP::D3,
    /* 177 */ SP::D0, SP::D1, SP::D2, SP::D3, SP::D4, SP::D5, SP::D6, SP::D7, SP::D8, SP::D9, SP::D10, SP::D11, SP::D12, SP::D13, SP::D14, SP::D15, SP::D16, SP::D17, SP::D18, SP::D19, SP::D20, SP::D21, SP::D22, SP::D23, SP::D0, SP::D1, SP::D2, SP::D3, SP::D4, SP::D5, SP::D6, SP::D7,
    /* 209 */ SP::Y, SP::ASR18, SP::Y, SP::ASR18,
    /* 213 */ SP::Y, SP::ICC,
    /* 215 */ SP::Y,
    /* 216 */ SP::CPQ,
    /* 217 */ SP::O6,
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
    /* 28 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
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
    /* 151 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 155 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 159 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 163 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 167 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 169 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 172 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 175 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 178 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 181 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 185 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 188 */ { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 189 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 191 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 193 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 195 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::FCCRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 198 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 201 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 203 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 206 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 209 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 213 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 218 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 222 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 227 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 228 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 232 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 236 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 238 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 241 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 243 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 245 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 248 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 251 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 254 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 257 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 259 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 261 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 263 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 265 */ { SP::FCCRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 268 */ { SP::FCCRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 271 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 275 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 279 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 283 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 288 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 293 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 298 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 302 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 305 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 308 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 309 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 310 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 312 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 314 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 318 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 322 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 325 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 328 */ { SP::CoprocRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 331 */ { SP::CoprocRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 334 */ { SP::IntPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 337 */ { SP::IntPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 341 */ { SP::CoprocPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 344 */ { SP::CoprocPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 347 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 350 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 354 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 357 */ { SP::IntPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 360 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 363 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 367 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 370 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 373 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 377 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 380 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 383 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 },
    /* 386 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 388 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 390 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 394 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 398 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 403 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 408 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 410 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 412 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 414 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 417 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 419 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 422 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 426 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 429 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::ASRRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 431 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 432 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::PRRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 434 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 437 */ { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 440 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 443 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 446 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 450 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 453 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::CoprocRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 456 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::CoprocRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 459 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 462 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 466 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::CoprocPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 469 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::CoprocPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 472 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 475 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 479 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 482 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntPairRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 485 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 488 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 492 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 495 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 498 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 502 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 505 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 508 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 512 */ { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::I64RegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 515 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 519 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 524 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::sparc_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_UNKNOWN, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 528 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 531 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 535 */ { SP::FCCRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 538 */ { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FCCRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::DFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 543 */ { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FCCRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::QFPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 548 */ { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FCCRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FPRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 553 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FCCRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 558 */ { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::FCCRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 563 */ { SP::ASRRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 566 */ { SP::ASRRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 569 */ { SP::PRRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 572 */ { SP::PRRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { SP::IntRegsRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
  }
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char SparcInstrNameData[] = {
  /* 0 */ "G_FLOG10\000"
  /* 9 */ "G_FEXP10\000"
  /* 18 */ "AES_KEXPAND0\000"
  /* 31 */ "AES_DROUND01\000"
  /* 44 */ "AES_EROUND01\000"
  /* 57 */ "SHA1\000"
  /* 62 */ "TA1\000"
  /* 66 */ "FSRC1\000"
  /* 72 */ "AES_KEXPAND1\000"
  /* 85 */ "FANDNOT1\000"
  /* 94 */ "FNOT1\000"
  /* 100 */ "FORNOT1\000"
  /* 108 */ "SHA512\000"
  /* 115 */ "FSRA32\000"
  /* 122 */ "FPSUB32\000"
  /* 130 */ "FPADD32\000"
  /* 138 */ "EDGE32\000"
  /* 145 */ "FCMPLE32\000"
  /* 154 */ "FCMPNE32\000"
  /* 163 */ "FPACK32\000"
  /* 171 */ "CMASK32\000"
  /* 179 */ "FSLL32\000"
  /* 186 */ "FSRL32\000"
  /* 193 */ "FCMPEQ32\000"
  /* 202 */ "FSLAS32\000"
  /* 210 */ "FCMPGT32\000"
  /* 219 */ "ARRAY32\000"
  /* 227 */ "FSRC2\000"
  /* 233 */ "AES_KEXPAND2\000"
  /* 246 */ "G_FLOG2\000"
  /* 254 */ "G_FATAN2\000"
  /* 263 */ "G_FEXP2\000"
  /* 271 */ "FANDNOT2\000"
  /* 280 */ "FNOT2\000"
  /* 286 */ "FORNOT2\000"
  /* 294 */ "AES_DROUND23\000"
  /* 307 */ "AES_EROUND23\000"
  /* 320 */ "TA3\000"
  /* 324 */ "FPADD64\000"
  /* 332 */ "TA5\000"
  /* 336 */ "MD5\000"
  /* 340 */ "FSRA16\000"
  /* 347 */ "FPSUB16\000"
  /* 355 */ "FPADD16\000"
  /* 363 */ "EDGE16\000"
  /* 370 */ "FCMPLE16\000"
  /* 379 */ "FCMPNE16\000"
  /* 388 */ "FPACK16\000"
  /* 396 */ "CMASK16\000"
  /* 404 */ "FSLL16\000"
  /* 411 */ "FSRL16\000"
  /* 418 */ "FCHKSM16\000"
  /* 427 */ "FMEAN16\000"
  /* 435 */ "FCMPEQ16\000"
  /* 444 */ "FSLAS16\000"
  /* 452 */ "FCMPGT16\000"
  /* 461 */ "FMUL8X16\000"
  /* 470 */ "FMULD8ULX16\000"
  /* 482 */ "FMUL8ULX16\000"
  /* 493 */ "FMULD8SUX16\000"
  /* 505 */ "FMUL8SUX16\000"
  /* 516 */ "ARRAY16\000"
  /* 524 */ "SHA256\000"
  /* 531 */ "EDGE8\000"
  /* 537 */ "CMASK8\000"
  /* 544 */ "ARRAY8\000"
  /* 551 */ "FBCONDA_V9\000"
  /* 562 */ "FBCOND_V9\000"
  /* 572 */ "FCMPD_V9\000"
  /* 581 */ "FCMPQ_V9\000"
  /* 590 */ "FCMPS_V9\000"
  /* 599 */ "BA\000"
  /* 602 */ "BPFCCA\000"
  /* 609 */ "BPICCA\000"
  /* 616 */ "BPXCCA\000"
  /* 623 */ "FBCONDA\000"
  /* 631 */ "CPBCONDA\000"
  /* 640 */ "G_FMA\000"
  /* 646 */ "G_STRICT_FMA\000"
  /* 659 */ "BPRA\000"
  /* 664 */ "FALIGNADATA\000"
  /* 676 */ "G_FSUB\000"
  /* 683 */ "G_STRICT_FSUB\000"
  /* 697 */ "G_ATOMICRMW_FSUB\000"
  /* 714 */ "G_SUB\000"
  /* 720 */ "G_ATOMICRMW_SUB\000"
  /* 736 */ "CRC32C\000"
  /* 743 */ "ADDXCCC\000"
  /* 751 */ "BPFCC\000"
  /* 757 */ "V9FMOVD_FCC\000"
  /* 769 */ "SELECT_CC_DFP_FCC\000"
  /* 787 */ "SELECT_CC_QFP_FCC\000"
  /* 805 */ "SELECT_CC_FP_FCC\000"
  /* 822 */ "V9FMOVQ_FCC\000"
  /* 834 */ "V9FMOVS_FCC\000"
  /* 846 */ "SELECT_CC_Int_FCC\000"
  /* 864 */ "BPICC\000"
  /* 870 */ "FMOVD_ICC\000"
  /* 880 */ "SELECT_CC_DFP_ICC\000"
  /* 898 */ "SELECT_CC_QFP_ICC\000"
  /* 916 */ "SELECT_CC_FP_ICC\000"
  /* 933 */ "FMOVQ_ICC\000"
  /* 943 */ "FMOVS_ICC\000"
  /* 953 */ "SELECT_CC_Int_ICC\000"
  /* 971 */ "BPXCC\000"
  /* 977 */ "FMOVD_XCC\000"
  /* 987 */ "SELECT_CC_DFP_XCC\000"
  /* 1005 */ "SELECT_CC_QFP_XCC\000"
  /* 1023 */ "SELECT_CC_FP_XCC\000"
  /* 1040 */ "FMOVQ_XCC\000"
  /* 1050 */ "FMOVS_XCC\000"
  /* 1060 */ "SELECT_CC_Int_XCC\000"
  /* 1078 */ "G_INTRINSIC\000"
  /* 1090 */ "G_FPTRUNC\000"
  /* 1100 */ "G_INTRINSIC_TRUNC\000"
  /* 1118 */ "G_TRUNC\000"
  /* 1126 */ "G_BUILD_VECTOR_TRUNC\000"
  /* 1147 */ "G_DYN_STACKALLOC\000"
  /* 1164 */ "ADDXC\000"
  /* 1170 */ "G_FMAD\000"
  /* 1177 */ "G_FPEXTLOAD\000"
  /* 1189 */ "G_INDEXED_SEXTLOAD\000"
  /* 1208 */ "G_SEXTLOAD\000"
  /* 1219 */ "G_INDEXED_ZEXTLOAD\000"
  /* 1238 */ "G_ZEXTLOAD\000"
  /* 1249 */ "G_INDEXED_LOAD\000"
  /* 1264 */ "G_LOAD\000"
  /* 1271 */ "FSUBD\000"
  /* 1277 */ "FHSUBD\000"
  /* 1284 */ "FMSUBD\000"
  /* 1291 */ "FNMSUBD\000"
  /* 1299 */ "G_VECREDUCE_FADD\000"
  /* 1316 */ "G_FADD\000"
  /* 1323 */ "G_VECREDUCE_SEQ_FADD\000"
  /* 1344 */ "G_STRICT_FADD\000"
  /* 1358 */ "G_ATOMICRMW_FADD\000"
  /* 1375 */ "G_VECREDUCE_ADD\000"
  /* 1391 */ "G_ADD\000"
  /* 1397 */ "G_PTR_ADD\000"
  /* 1407 */ "G_ATOMICRMW_ADD\000"
  /* 1423 */ "FADDD\000"
  /* 1429 */ "FHADDD\000"
  /* 1436 */ "FNHADDD\000"
  /* 1444 */ "FMADDD\000"
  /* 1451 */ "FNMADDD\000"
  /* 1459 */ "FNADDD\000"
  /* 1466 */ "V9FCMPED\000"
  /* 1475 */ "RESTORED\000"
  /* 1484 */ "SAVED\000"
  /* 1490 */ "FNEGD\000"
  /* 1496 */ "FMULD\000"
  /* 1502 */ "FNMULD\000"
  /* 1509 */ "FSMULD\000"
  /* 1516 */ "FNSMULD\000"
  /* 1524 */ "FAND\000"
  /* 1529 */ "FNAND\000"
  /* 1535 */ "G_ATOMICRMW_NAND\000"
  /* 1552 */ "FEXPAND\000"
  /* 1560 */ "DES_KEXPAND\000"
  /* 1572 */ "G_VECREDUCE_AND\000"
  /* 1588 */ "G_AND\000"
  /* 1594 */ "G_ATOMICRMW_AND\000"
  /* 1610 */ "LIFETIME_END\000"
  /* 1623 */ "FBCOND\000"
  /* 1630 */ "CPBCOND\000"
  /* 1638 */ "G_BRCOND\000"
  /* 1647 */ "G_ATOMICRMW_USUB_COND\000"
  /* 1669 */ "G_LLROUND\000"
  /* 1679 */ "G_LROUND\000"
  /* 1688 */ "G_INTRINSIC_ROUND\000"
  /* 1706 */ "G_INTRINSIC_FPTRUNC_ROUND\000"
  /* 1732 */ "DES_ROUND\000"
  /* 1742 */ "FITOD\000"
  /* 1748 */ "FQTOD\000"
  /* 1754 */ "FSTOD\000"
  /* 1760 */ "FXTOD\000"
  /* 1766 */ "MOVXTOD\000"
  /* 1774 */ "V9FCMPD\000"
  /* 1782 */ "FLCMPD\000"
  /* 1789 */ "LOAD_STACK_GUARD\000"
  /* 1806 */ "FMOVRD\000"
  /* 1813 */ "FABSD\000"
  /* 1819 */ "FSQRTD\000"
  /* 1826 */ "FDIVD\000"
  /* 1832 */ "FMOVD\000"
  /* 1838 */ "PSEUDO_PROBE\000"
  /* 1851 */ "G_SSUBE\000"
  /* 1859 */ "G_USUBE\000"
  /* 1867 */ "G_FENCE\000"
  /* 1875 */ "ARITH_FENCE\000"
  /* 1887 */ "REG_SEQUENCE\000"
  /* 1900 */ "G_SADDE\000"
  /* 1908 */ "G_UADDE\000"
  /* 1916 */ "G_GET_FPMODE\000"
  /* 1929 */ "G_RESET_FPMODE\000"
  /* 1944 */ "G_SET_FPMODE\000"
  /* 1957 */ "G_FMINNUM_IEEE\000"
  /* 1972 */ "G_FMAXNUM_IEEE\000"
  /* 1987 */ "FPMERGE\000"
  /* 1995 */ "G_VSCALE\000"
  /* 2004 */ "G_JUMP_TABLE\000"
  /* 2017 */ "BUNDLE\000"
  /* 2024 */ "BSHUFFLE\000"
  /* 2033 */ "G_MEMSET_INLINE\000"
  /* 2049 */ "G_MEMCPY_INLINE\000"
  /* 2065 */ "DONE\000"
  /* 2070 */ "FONE\000"
  /* 2075 */ "RELOC_NONE\000"
  /* 2086 */ "LOCAL_ESCAPE\000"
  /* 2099 */ "G_FPTRUNCSTORE\000"
  /* 2114 */ "G_STACKRESTORE\000"
  /* 2129 */ "G_INDEXED_STORE\000"
  /* 2145 */ "G_STORE\000"
  /* 2153 */ "G_BITREVERSE\000"
  /* 2166 */ "FAKE_USE\000"
  /* 2175 */ "DBG_VALUE\000"
  /* 2185 */ "G_GLOBAL_VALUE\000"
  /* 2200 */ "G_PTRAUTH_GLOBAL_VALUE\000"
  /* 2223 */ "CONVERGENCECTRL_GLUE\000"
  /* 2244 */ "G_STACKSAVE\000"
  /* 2256 */ "G_MEMMOVE\000"
  /* 2266 */ "G_FREEZE\000"
  /* 2275 */ "G_FCANONICALIZE\000"
  /* 2291 */ "G_FMODF\000"
  /* 2299 */ "INIT_UNDEF\000"
  /* 2310 */ "G_IMPLICIT_DEF\000"
  /* 2325 */ "DBG_INSTR_REF\000"
  /* 2339 */ "CAMELLIA_F\000"
  /* 2350 */ "G_FNEG\000"
  /* 2357 */ "EXTRACT_SUBREG\000"
  /* 2372 */ "INSERT_SUBREG\000"
  /* 2386 */ "G_SEXT_INREG\000"
  /* 2399 */ "SUBREG_TO_REG\000"
  /* 2413 */ "G_ATOMIC_CMPXCHG\000"
  /* 2430 */ "G_ATOMICRMW_XCHG\000"
  /* 2447 */ "G_GET_ROUNDING\000"
  /* 2462 */ "G_SET_ROUNDING\000"
  /* 2477 */ "G_FLOG\000"
  /* 2484 */ "G_VAARG\000"
  /* 2492 */ "PREALLOCATED_ARG\000"
  /* 2509 */ "G_PREFETCH\000"
  /* 2520 */ "G_SMULH\000"
  /* 2528 */ "G_UMULH\000"
  /* 2536 */ "G_FTANH\000"
  /* 2544 */ "G_FSINH\000"
  /* 2552 */ "G_FCOSH\000"
  /* 2560 */ "FLUSH\000"
  /* 2566 */ "DBG_PHI\000"
  /* 2574 */ "FPMADDXHI\000"
  /* 2584 */ "UMULXHI\000"
  /* 2592 */ "XMULXHI\000"
  /* 2600 */ "CAMELLIA_FLI\000"
  /* 2613 */ "FDTOI\000"
  /* 2619 */ "FQTOI\000"
  /* 2625 */ "FSTOI\000"
  /* 2631 */ "G_FPTOSI\000"
  /* 2640 */ "G_FPTOUI\000"
  /* 2649 */ "G_FPOWI\000"
  /* 2657 */ "BMASK\000"
  /* 2663 */ "COPY_LANEMASK\000"
  /* 2677 */ "G_PTRMASK\000"
  /* 2687 */ "EDGE32L\000"
  /* 2695 */ "EDGE16L\000"
  /* 2703 */ "EDGE8L\000"
  /* 2710 */ "FMUL8X16AL\000"
  /* 2721 */ "GC_LABEL\000"
  /* 2730 */ "DBG_LABEL\000"
  /* 2740 */ "EH_LABEL\000"
  /* 2749 */ "ANNOTATION_LABEL\000"
  /* 2766 */ "ICALL_BRANCH_FUNNEL\000"
  /* 2786 */ "CAMELLIA_FL\000"
  /* 2798 */ "G_FSHL\000"
  /* 2805 */ "G_SHL\000"
  /* 2811 */ "G_FCEIL\000"
  /* 2819 */ "G_SAVGCEIL\000"
  /* 2830 */ "G_UAVGCEIL\000"
  /* 2841 */ "PATCHABLE_TAIL_CALL\000"
  /* 2861 */ "TLS_CALL\000"
  /* 2870 */ "PATCHABLE_TYPED_EVENT_CALL\000"
  /* 2897 */ "PATCHABLE_EVENT_CALL\000"
  /* 2918 */ "FENTRY_CALL\000"
  /* 2930 */ "KILL\000"
  /* 2935 */ "G_CONSTANT_POOL\000"
  /* 2951 */ "ALIGNADDRL\000"
  /* 2962 */ "RETL\000"
  /* 2967 */ "G_ROTL\000"
  /* 2974 */ "G_VECREDUCE_FMUL\000"
  /* 2991 */ "G_FMUL\000"
  /* 2998 */ "G_VECREDUCE_SEQ_FMUL\000"
  /* 3019 */ "G_STRICT_FMUL\000"
  /* 3033 */ "G_CLMUL\000"
  /* 3041 */ "MPMUL\000"
  /* 3047 */ "MONTMUL\000"
  /* 3055 */ "G_VECREDUCE_MUL\000"
  /* 3071 */ "G_MUL\000"
  /* 3077 */ "SIAM\000"
  /* 3082 */ "G_FREM\000"
  /* 3089 */ "G_STRICT_FREM\000"
  /* 3103 */ "G_SREM\000"
  /* 3110 */ "G_UREM\000"
  /* 3117 */ "G_SDIVREM\000"
  /* 3127 */ "G_UDIVREM\000"
  /* 3137 */ "RDWIM\000"
  /* 3143 */ "INLINEASM\000"
  /* 3153 */ "G_VECREDUCE_FMINIMUM\000"
  /* 3174 */ "G_FMINIMUM\000"
  /* 3185 */ "G_ATOMICRMW_FMINIMUM\000"
  /* 3206 */ "G_VECREDUCE_FMAXIMUM\000"
  /* 3227 */ "G_FMAXIMUM\000"
  /* 3238 */ "G_ATOMICRMW_FMAXIMUM\000"
  /* 3259 */ "G_FMINIMUMNUM\000"
  /* 3273 */ "G_ATOMICRMW_FMINIMUMNUM\000"
  /* 3297 */ "G_FMAXIMUMNUM\000"
  /* 3311 */ "G_ATOMICRMW_FMAXIMUMNUM\000"
  /* 3335 */ "G_FMINNUM\000"
  /* 3345 */ "G_FMAXNUM\000"
  /* 3355 */ "EDGE32N\000"
  /* 3363 */ "EDGE16N\000"
  /* 3371 */ "EDGE8N\000"
  /* 3378 */ "ALLCLEAN\000"
  /* 3387 */ "G_FATAN\000"
  /* 3395 */ "G_FTAN\000"
  /* 3402 */ "G_INTRINSIC_ROUNDEVEN\000"
  /* 3424 */ "G_ASSERT_ALIGN\000"
  /* 3439 */ "G_FCOPYSIGN\000"
  /* 3451 */ "G_VECREDUCE_FMIN\000"
  /* 3468 */ "G_ATOMICRMW_FMIN\000"
  /* 3485 */ "G_VECREDUCE_SMIN\000"
  /* 3502 */ "G_SMIN\000"
  /* 3509 */ "G_VECREDUCE_UMIN\000"
  /* 3526 */ "G_UMIN\000"
  /* 3533 */ "G_ATOMICRMW_UMIN\000"
  /* 3550 */ "G_ATOMICRMW_MIN\000"
  /* 3566 */ "G_FASIN\000"
  /* 3574 */ "G_FSIN\000"
  /* 3581 */ "EDGE32LN\000"
  /* 3590 */ "EDGE16LN\000"
  /* 3599 */ "EDGE8LN\000"
  /* 3607 */ "CFI_INSTRUCTION\000"
  /* 3623 */ "G_CTLZ_ZERO_POISON\000"
  /* 3642 */ "G_CTTZ_ZERO_POISON\000"
  /* 3661 */ "PDISTN\000"
  /* 3668 */ "ADJCALLSTACKDOWN\000"
  /* 3685 */ "SHUTDOWN\000"
  /* 3694 */ "G_SSUBO\000"
  /* 3702 */ "G_USUBO\000"
  /* 3710 */ "G_SADDO\000"
  /* 3718 */ "G_UADDO\000"
  /* 3726 */ "JUMP_TABLE_DEBUG_INFO\000"
  /* 3748 */ "G_SMULO\000"
  /* 3756 */ "G_UMULO\000"
  /* 3764 */ "G_BZERO\000"
  /* 3772 */ "FZERO\000"
  /* 3778 */ "STACKMAP\000"
  /* 3787 */ "G_DEBUGTRAP\000"
  /* 3799 */ "G_UBSANTRAP\000"
  /* 3811 */ "G_TRAP\000"
  /* 3818 */ "G_ATOMICRMW_UDEC_WRAP\000"
  /* 3840 */ "G_ATOMICRMW_UINC_WRAP\000"
  /* 3862 */ "G_BSWAP\000"
  /* 3870 */ "G_SITOFP\000"
  /* 3879 */ "G_UITOFP\000"
  /* 3888 */ "DES_IIP\000"
  /* 3896 */ "DES_IP\000"
  /* 3903 */ "G_FCMP\000"
  /* 3910 */ "G_STRICT_FCMP\000"
  /* 3924 */ "G_ICMP\000"
  /* 3931 */ "G_SCMP\000"
  /* 3938 */ "G_UCMP\000"
  /* 3945 */ "UNIMP\000"
  /* 3951 */ "NOP\000"
  /* 3955 */ "CONVERGENCECTRL_LOOP\000"
  /* 3976 */ "G_CTPOP\000"
  /* 3984 */ "PATCHABLE_OP\000"
  /* 3997 */ "FAULTING_OP\000"
  /* 4009 */ "ADJCALLSTACKUP\000"
  /* 4024 */ "PREALLOCATED_SETUP\000"
  /* 4043 */ "G_FLDEXP\000"
  /* 4052 */ "G_STRICT_FLDEXP\000"
  /* 4068 */ "G_FEXP\000"
  /* 4075 */ "G_FFREXP\000"
  /* 4084 */ "FSUBQ\000"
  /* 4090 */ "FADDQ\000"
  /* 4096 */ "V9FCMPEQ\000"
  /* 4105 */ "RDFQ\000"
  /* 4110 */ "FNEGQ\000"
  /* 4116 */ "FDMULQ\000"
  /* 4123 */ "FMULQ\000"
  /* 4129 */ "FDTOQ\000"
  /* 4135 */ "FITOQ\000"
  /* 4141 */ "FSTOQ\000"
  /* 4147 */ "FXTOQ\000"
  /* 4153 */ "V9FCMPQ\000"
  /* 4161 */ "FMOVRQ\000"
  /* 4168 */ "FABSQ\000"
  /* 4174 */ "FSQRTQ\000"
  /* 4181 */ "FDIVQ\000"
  /* 4187 */ "FMOVQ\000"
  /* 4193 */ "V8BAR\000"
  /* 4199 */ "STBAR\000"
  /* 4205 */ "RDTBR\000"
  /* 4211 */ "G_BR\000"
  /* 4216 */ "INLINEASM_BR\000"
  /* 4229 */ "ALIGNADDR\000"
  /* 4239 */ "G_BLOCK_ADDR\000"
  /* 4252 */ "MEMBARRIER\000"
  /* 4263 */ "G_CONSTANT_FOLD_BARRIER\000"
  /* 4287 */ "PATCHABLE_FUNCTION_ENTER\000"
  /* 4312 */ "G_READCYCLECOUNTER\000"
  /* 4331 */ "G_READSTEADYCOUNTER\000"
  /* 4351 */ "G_READ_REGISTER\000"
  /* 4367 */ "G_WRITE_REGISTER\000"
  /* 4384 */ "G_ASHR\000"
  /* 4391 */ "G_FSHR\000"
  /* 4398 */ "G_LSHR\000"
  /* 4405 */ "SIR\000"
  /* 4409 */ "FOR\000"
  /* 4413 */ "CONVERGENCECTRL_ANCHOR\000"
  /* 4436 */ "FNOR\000"
  /* 4441 */ "FXNOR\000"
  /* 4447 */ "G_FFLOOR\000"
  /* 4456 */ "G_SAVGFLOOR\000"
  /* 4468 */ "G_UAVGFLOOR\000"
  /* 4480 */ "G_EXTRACT_SUBVECTOR\000"
  /* 4500 */ "G_INSERT_SUBVECTOR\000"
  /* 4519 */ "G_BUILD_VECTOR\000"
  /* 4534 */ "G_SHUFFLE_VECTOR\000"
  /* 4551 */ "G_STEP_VECTOR\000"
  /* 4565 */ "G_SPLAT_VECTOR\000"
  /* 4580 */ "FXOR\000"
  /* 4585 */ "G_VECREDUCE_XOR\000"
  /* 4601 */ "G_XOR\000"
  /* 4607 */ "G_ATOMICRMW_XOR\000"
  /* 4623 */ "G_VECREDUCE_OR\000"
  /* 4638 */ "G_OR\000"
  /* 4643 */ "G_ATOMICRMW_OR\000"
  /* 4658 */ "BPR\000"
  /* 4662 */ "RDPR\000"
  /* 4667 */ "MONTSQR\000"
  /* 4675 */ "RDASR\000"
  /* 4681 */ "RDPSR\000"
  /* 4687 */ "G_ROTR\000"
  /* 4694 */ "G_INTTOPTR\000"
  /* 4705 */ "FSRC1S\000"
  /* 4712 */ "FANDNOT1S\000"
  /* 4722 */ "FNOT1S\000"
  /* 4729 */ "FORNOT1S\000"
  /* 4738 */ "FPSUB32S\000"
  /* 4747 */ "FPADD32S\000"
  /* 4756 */ "FSRC2S\000"
  /* 4763 */ "FANDNOT2S\000"
  /* 4773 */ "FNOT2S\000"
  /* 4780 */ "FORNOT2S\000"
  /* 4789 */ "FPSUB16S\000"
  /* 4798 */ "FPADD16S\000"
  /* 4807 */ "G_FABS\000"
  /* 4814 */ "G_ABS\000"
  /* 4820 */ "FSUBS\000"
  /* 4826 */ "FHSUBS\000"
  /* 4833 */ "FMSUBS\000"
  /* 4840 */ "FNMSUBS\000"
  /* 4848 */ "G_ABDS\000"
  /* 4855 */ "FADDS\000"
  /* 4861 */ "FHADDS\000"
  /* 4868 */ "FNHADDS\000"
  /* 4876 */ "FMADDS\000"
  /* 4883 */ "FNMADDS\000"
  /* 4891 */ "FNADDS\000"
  /* 4898 */ "FANDS\000"
  /* 4904 */ "FNANDS\000"
  /* 4911 */ "FONES\000"
  /* 4917 */ "V9FCMPES\000"
  /* 4926 */ "G_UNMERGE_VALUES\000"
  /* 4943 */ "G_MERGE_VALUES\000"
  /* 4958 */ "FNEGS\000"
  /* 4964 */ "G_CTLS\000"
  /* 4971 */ "FMULS\000"
  /* 4977 */ "FNMULS\000"
  /* 4984 */ "G_FACOS\000"
  /* 4992 */ "G_FCOS\000"
  /* 4999 */ "G_FSINCOS\000"
  /* 5009 */ "FZEROS\000"
  /* 5016 */ "FDTOS\000"
  /* 5022 */ "FITOS\000"
  /* 5028 */ "FQTOS\000"
  /* 5034 */ "MOVWTOS\000"
  /* 5042 */ "FXTOS\000"
  /* 5048 */ "V9FCMPS\000"
  /* 5056 */ "G_STRICT_FCMPS\000"
  /* 5071 */ "FLCMPS\000"
  /* 5078 */ "FORS\000"
  /* 5083 */ "FNORS\000"
  /* 5089 */ "FXNORS\000"
  /* 5096 */ "G_CONCAT_VECTORS\000"
  /* 5113 */ "FXORS\000"
  /* 5119 */ "FMOVRS\000"
  /* 5126 */ "COPY_TO_REGCLASS\000"
  /* 5143 */ "G_IS_FPCLASS\000"
  /* 5156 */ "FABSS\000"
  /* 5162 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\000"
  /* 5192 */ "G_VECTOR_COMPRESS\000"
  /* 5210 */ "G_INTRINSIC_W_SIDE_EFFECTS\000"
  /* 5237 */ "G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS\000"
  /* 5275 */ "FSQRTS\000"
  /* 5282 */ "FDIVS\000"
  /* 5288 */ "FMOVS\000"
  /* 5294 */ "G_TRUNC_SSAT_S\000"
  /* 5309 */ "G_SSUBSAT\000"
  /* 5319 */ "G_USUBSAT\000"
  /* 5329 */ "G_SADDSAT\000"
  /* 5339 */ "G_UADDSAT\000"
  /* 5349 */ "G_SSHLSAT\000"
  /* 5359 */ "G_USHLSAT\000"
  /* 5369 */ "G_SMULFIXSAT\000"
  /* 5382 */ "G_UMULFIXSAT\000"
  /* 5395 */ "G_SDIVFIXSAT\000"
  /* 5408 */ "G_UDIVFIXSAT\000"
  /* 5421 */ "G_ATOMICRMW_USUB_SAT\000"
  /* 5442 */ "G_FPTOSI_SAT\000"
  /* 5455 */ "G_FPTOUI_SAT\000"
  /* 5468 */ "G_EXTRACT\000"
  /* 5478 */ "G_SELECT\000"
  /* 5487 */ "G_BRINDIRECT\000"
  /* 5500 */ "PATCHABLE_RET\000"
  /* 5514 */ "G_MEMSET\000"
  /* 5523 */ "PATCHABLE_FUNCTION_EXIT\000"
  /* 5547 */ "G_BRJT\000"
  /* 5554 */ "G_EXTRACT_VECTOR_ELT\000"
  /* 5575 */ "G_INSERT_VECTOR_ELT\000"
  /* 5595 */ "BPFCCANT\000"
  /* 5604 */ "BPICCANT\000"
  /* 5613 */ "BPXCCANT\000"
  /* 5622 */ "BPRANT\000"
  /* 5629 */ "G_FCONSTANT\000"
  /* 5641 */ "G_CONSTANT\000"
  /* 5652 */ "BPFCCNT\000"
  /* 5660 */ "BPICCNT\000"
  /* 5668 */ "BPXCCNT\000"
  /* 5676 */ "LZCNT\000"
  /* 5682 */ "G_INTRINSIC_CONVERGENT\000"
  /* 5705 */ "STATEPOINT\000"
  /* 5716 */ "PATCHPOINT\000"
  /* 5727 */ "G_PTRTOINT\000"
  /* 5738 */ "G_FRINT\000"
  /* 5746 */ "G_INTRINSIC_LLRINT\000"
  /* 5765 */ "G_INTRINSIC_LRINT\000"
  /* 5783 */ "G_FNEARBYINT\000"
  /* 5796 */ "BPRNT\000"
  /* 5802 */ "G_VASTART\000"
  /* 5812 */ "LIFETIME_START\000"
  /* 5827 */ "G_INVOKE_REGION_START\000"
  /* 5849 */ "G_INSERT\000"
  /* 5858 */ "G_FSQRT\000"
  /* 5866 */ "G_STRICT_FSQRT\000"
  /* 5881 */ "G_BITCAST\000"
  /* 5891 */ "G_ADDRSPACE_CAST\000"
  /* 5908 */ "AES_DROUND01_LAST\000"
  /* 5926 */ "AES_EROUND01_LAST\000"
  /* 5944 */ "AES_DROUND23_LAST\000"
  /* 5962 */ "AES_EROUND23_LAST\000"
  /* 5980 */ "PDIST\000"
  /* 5986 */ "DBG_VALUE_LIST\000"
  /* 6001 */ "G_FPEXT\000"
  /* 6009 */ "G_SEXT\000"
  /* 6016 */ "G_ASSERT_SEXT\000"
  /* 6030 */ "G_ANYEXT\000"
  /* 6039 */ "G_ZEXT\000"
  /* 6046 */ "G_ASSERT_ZEXT\000"
  /* 6060 */ "FMUL8X16AU\000"
  /* 6071 */ "G_ABDU\000"
  /* 6078 */ "G_TRUNC_SSAT_U\000"
  /* 6093 */ "G_TRUNC_USAT_U\000"
  /* 6108 */ "G_FDIV\000"
  /* 6115 */ "G_STRICT_FDIV\000"
  /* 6129 */ "G_SDIV\000"
  /* 6136 */ "G_UDIV\000"
  /* 6143 */ "G_GET_FPENV\000"
  /* 6155 */ "G_RESET_FPENV\000"
  /* 6169 */ "G_SET_FPENV\000"
  /* 6181 */ "FLUSHW\000"
  /* 6188 */ "NORMALW\000"
  /* 6196 */ "INVALW\000"
  /* 6203 */ "G_FPOW\000"
  /* 6210 */ "OTHERW\000"
  /* 6217 */ "MOVSTOSW\000"
  /* 6226 */ "SETSW\000"
  /* 6232 */ "MOVSTOUW\000"
  /* 6241 */ "G_VECREDUCE_FMAX\000"
  /* 6258 */ "G_ATOMICRMW_FMAX\000"
  /* 6275 */ "G_VECREDUCE_SMAX\000"
  /* 6292 */ "G_SMAX\000"
  /* 6299 */ "G_VECREDUCE_UMAX\000"
  /* 6316 */ "G_UMAX\000"
  /* 6323 */ "G_ATOMICRMW_UMAX\000"
  /* 6340 */ "G_ATOMICRMW_MAX\000"
  /* 6356 */ "GETPCX\000"
  /* 6363 */ "FPMADDX\000"
  /* 6371 */ "G_FRAME_INDEX\000"
  /* 6385 */ "G_SBFX\000"
  /* 6392 */ "G_UBFX\000"
  /* 6399 */ "FPACKFIX\000"
  /* 6408 */ "G_SMULFIX\000"
  /* 6418 */ "G_UMULFIX\000"
  /* 6428 */ "G_SDIVFIX\000"
  /* 6438 */ "G_UDIVFIX\000"
  /* 6448 */ "XMULX\000"
  /* 6454 */ "FDTOX\000"
  /* 6460 */ "MOVDTOX\000"
  /* 6468 */ "FQTOX\000"
  /* 6474 */ "FSTOX\000"
  /* 6480 */ "SETX\000"
  /* 6485 */ "G_MEMCPY\000"
  /* 6494 */ "COPY\000"
  /* 6499 */ "RETRY\000"
  /* 6505 */ "CONVERGENCECTRL_ENTRY\000"
  /* 6527 */ "G_CTLZ\000"
  /* 6534 */ "G_CTTZ\000"
  /* 6541 */ "PREFETCHAi\000"
  /* 6552 */ "PREFETCHi\000"
  /* 6562 */ "SETHIi\000"
  /* 6569 */ "CALLi\000"
  /* 6575 */ "MEMBARi\000"
  /* 6583 */ "CALLrii\000"
  /* 6591 */ "LDSBAri\000"
  /* 6599 */ "STBAri\000"
  /* 6606 */ "LDUBAri\000"
  /* 6614 */ "LDSTUBAri\000"
  /* 6624 */ "LDDAri\000"
  /* 6631 */ "LDAri\000"
  /* 6637 */ "STDAri\000"
  /* 6644 */ "LDDFAri\000"
  /* 6652 */ "LDFAri\000"
  /* 6659 */ "STDFAri\000"
  /* 6667 */ "LDQFAri\000"
  /* 6675 */ "STQFAri\000"
  /* 6683 */ "STFAri\000"
  /* 6690 */ "LDSHAri\000"
  /* 6698 */ "STHAri\000"
  /* 6705 */ "LDUHAri\000"
  /* 6713 */ "SWAPAri\000"
  /* 6721 */ "SRAri\000"
  /* 6727 */ "CASAri\000"
  /* 6734 */ "STAri\000"
  /* 6740 */ "LDSWAri\000"
  /* 6748 */ "LDXAri\000"
  /* 6755 */ "CASXAri\000"
  /* 6763 */ "STXAri\000"
  /* 6770 */ "LDSBri\000"
  /* 6777 */ "STBri\000"
  /* 6783 */ "LDUBri\000"
  /* 6790 */ "SUBri\000"
  /* 6796 */ "LDSTUBri\000"
  /* 6805 */ "SMACri\000"
  /* 6812 */ "UMACri\000"
  /* 6819 */ "SUBCri\000"
  /* 6826 */ "TSUBCCri\000"
  /* 6835 */ "TADDCCri\000"
  /* 6844 */ "ANDCCri\000"
  /* 6852 */ "V9MOVFCCri\000"
  /* 6863 */ "TICCri\000"
  /* 6870 */ "MOVICCri\000"
  /* 6879 */ "SMULCCri\000"
  /* 6888 */ "UMULCCri\000"
  /* 6897 */ "ANDNCCri\000"
  /* 6906 */ "ORNCCri\000"
  /* 6914 */ "XNORCCri\000"
  /* 6923 */ "XORCCri\000"
  /* 6931 */ "MULSCCri\000"
  /* 6940 */ "SDIVCCri\000"
  /* 6949 */ "UDIVCCri\000"
  /* 6958 */ "TXCCri\000"
  /* 6965 */ "MOVXCCri\000"
  /* 6974 */ "ADDCri\000"
  /* 6981 */ "LDDCri\000"
  /* 6988 */ "LDCri\000"
  /* 6994 */ "STDCri\000"
  /* 7001 */ "STCri\000"
  /* 7007 */ "ADDri\000"
  /* 7013 */ "LDDri\000"
  /* 7019 */ "LDri\000"
  /* 7024 */ "ANDri\000"
  /* 7030 */ "BINDri\000"
  /* 7037 */ "CWBCONDri\000"
  /* 7047 */ "CXBCONDri\000"
  /* 7057 */ "STDri\000"
  /* 7063 */ "SUBEri\000"
  /* 7070 */ "ADDEri\000"
  /* 7077 */ "RESTOREri\000"
  /* 7087 */ "SAVEri\000"
  /* 7094 */ "LDDFri\000"
  /* 7101 */ "LDFri\000"
  /* 7107 */ "STDFri\000"
  /* 7114 */ "LDQFri\000"
  /* 7121 */ "STQFri\000"
  /* 7128 */ "STFri\000"
  /* 7134 */ "LDSHri\000"
  /* 7141 */ "FLUSHri\000"
  /* 7149 */ "STHri\000"
  /* 7155 */ "LDUHri\000"
  /* 7162 */ "TAIL_CALLri\000"
  /* 7174 */ "SLLri\000"
  /* 7180 */ "JMPLri\000"
  /* 7187 */ "SRLri\000"
  /* 7193 */ "SMULri\000"
  /* 7200 */ "UMULri\000"
  /* 7207 */ "WRWIMri\000"
  /* 7215 */ "ANDNri\000"
  /* 7222 */ "ORNri\000"
  /* 7228 */ "TRAPri\000"
  /* 7235 */ "SWAPri\000"
  /* 7242 */ "STDCQri\000"
  /* 7250 */ "STDFQri\000"
  /* 7258 */ "WRTBRri\000"
  /* 7266 */ "XNORri\000"
  /* 7273 */ "XORri\000"
  /* 7279 */ "WRPRri\000"
  /* 7286 */ "WRASRri\000"
  /* 7294 */ "LDCSRri\000"
  /* 7302 */ "STCSRri\000"
  /* 7310 */ "LDFSRri\000"
  /* 7318 */ "STFSRri\000"
  /* 7326 */ "LDXFSRri\000"
  /* 7335 */ "STXFSRri\000"
  /* 7344 */ "PWRPSRri\000"
  /* 7353 */ "MOVRri\000"
  /* 7360 */ "STri\000"
  /* 7365 */ "RETTri\000"
  /* 7372 */ "SDIVri\000"
  /* 7379 */ "UDIVri\000"
  /* 7386 */ "TSUBCCTVri\000"
  /* 7397 */ "TADDCCTVri\000"
  /* 7408 */ "LDSWri\000"
  /* 7415 */ "SRAXri\000"
  /* 7422 */ "LDXri\000"
  /* 7428 */ "SLLXri\000"
  /* 7435 */ "SRLXri\000"
  /* 7442 */ "MULXri\000"
  /* 7449 */ "STXri\000"
  /* 7455 */ "SDIVXri\000"
  /* 7463 */ "UDIVXri\000"
  /* 7471 */ "CALLrri\000"
  /* 7479 */ "PREFETCHAr\000"
  /* 7490 */ "PREFETCHr\000"
  /* 7500 */ "LDSBArr\000"
  /* 7508 */ "STBArr\000"
  /* 7515 */ "LDUBArr\000"
  /* 7523 */ "LDSTUBArr\000"
  /* 7533 */ "LDDArr\000"
  /* 7540 */ "LDArr\000"
  /* 7546 */ "STDArr\000"
  /* 7553 */ "LDDFArr\000"
  /* 7561 */ "LDFArr\000"
  /* 7568 */ "STDFArr\000"
  /* 7576 */ "LDQFArr\000"
  /* 7584 */ "STQFArr\000"
  /* 7592 */ "STFArr\000"
  /* 7599 */ "LDSHArr\000"
  /* 7607 */ "STHArr\000"
  /* 7614 */ "LDUHArr\000"
  /* 7622 */ "SWAPArr\000"
  /* 7630 */ "SRArr\000"
  /* 7636 */ "CASArr\000"
  /* 7643 */ "STArr\000"
  /* 7649 */ "LDSWArr\000"
  /* 7657 */ "LDXArr\000"
  /* 7664 */ "CASXArr\000"
  /* 7672 */ "STXArr\000"
  /* 7679 */ "LDSBrr\000"
  /* 7686 */ "STBrr\000"
  /* 7692 */ "LDUBrr\000"
  /* 7699 */ "SUBrr\000"
  /* 7705 */ "LDSTUBrr\000"
  /* 7714 */ "SMACrr\000"
  /* 7721 */ "UMACrr\000"
  /* 7728 */ "SUBCrr\000"
  /* 7735 */ "TSUBCCrr\000"
  /* 7744 */ "TADDCCrr\000"
  /* 7753 */ "ANDCCrr\000"
  /* 7761 */ "V9MOVFCCrr\000"
  /* 7772 */ "TICCrr\000"
  /* 7779 */ "MOVICCrr\000"
  /* 7788 */ "SMULCCrr\000"
  /* 7797 */ "UMULCCrr\000"
  /* 7806 */ "ANDNCCrr\000"
  /* 7815 */ "ORNCCrr\000"
  /* 7823 */ "XNORCCrr\000"
  /* 7832 */ "XORCCrr\000"
  /* 7840 */ "MULSCCrr\000"
  /* 7849 */ "SDIVCCrr\000"
  /* 7858 */ "UDIVCCrr\000"
  /* 7867 */ "TXCCrr\000"
  /* 7874 */ "MOVXCCrr\000"
  /* 7883 */ "ADDCrr\000"
  /* 7890 */ "LDDCrr\000"
  /* 7897 */ "LDCrr\000"
  /* 7903 */ "STDCrr\000"
  /* 7910 */ "POPCrr\000"
  /* 7917 */ "STCrr\000"
  /* 7923 */ "TLS_ADDrr\000"
  /* 7933 */ "LDDrr\000"
  /* 7939 */ "GDOP_LDrr\000"
  /* 7949 */ "TLS_LDrr\000"
  /* 7958 */ "ANDrr\000"
  /* 7964 */ "BINDrr\000"
  /* 7971 */ "CWBCONDrr\000"
  /* 7981 */ "CXBCONDrr\000"
  /* 7991 */ "STDrr\000"
  /* 7997 */ "SUBErr\000"
  /* 8004 */ "ADDErr\000"
  /* 8011 */ "RESTORErr\000"
  /* 8021 */ "SAVErr\000"
  /* 8028 */ "LDDFrr\000"
  /* 8035 */ "LDFrr\000"
  /* 8041 */ "STDFrr\000"
  /* 8048 */ "LDQFrr\000"
  /* 8055 */ "STQFrr\000"
  /* 8062 */ "STFrr\000"
  /* 8068 */ "LDSHrr\000"
  /* 8075 */ "FLUSHrr\000"
  /* 8083 */ "STHrr\000"
  /* 8089 */ "LDUHrr\000"
  /* 8096 */ "CALLrr\000"
  /* 8103 */ "SLLrr\000"
  /* 8109 */ "JMPLrr\000"
  /* 8116 */ "SRLrr\000"
  /* 8122 */ "SMULrr\000"
  /* 8129 */ "UMULrr\000"
  /* 8136 */ "WRWIMrr\000"
  /* 8144 */ "ANDNrr\000"
  /* 8151 */ "ORNrr\000"
  /* 8157 */ "TRAPrr\000"
  /* 8164 */ "SWAPrr\000"
  /* 8171 */ "STDCQrr\000"
  /* 8179 */ "STDFQrr\000"
  /* 8187 */ "WRTBRrr\000"
  /* 8195 */ "XNORrr\000"
  /* 8202 */ "XORrr\000"
  /* 8208 */ "WRPRrr\000"
  /* 8215 */ "WRASRrr\000"
  /* 8223 */ "LDCSRrr\000"
  /* 8231 */ "STCSRrr\000"
  /* 8239 */ "LDFSRrr\000"
  /* 8247 */ "STFSRrr\000"
  /* 8255 */ "LDXFSRrr\000"
  /* 8264 */ "STXFSRrr\000"
  /* 8273 */ "PWRPSRrr\000"
  /* 8282 */ "MOVRrr\000"
  /* 8289 */ "STrr\000"
  /* 8294 */ "RETTrr\000"
  /* 8301 */ "SDIVrr\000"
  /* 8308 */ "UDIVrr\000"
  /* 8315 */ "TSUBCCTVrr\000"
  /* 8326 */ "TADDCCTVrr\000"
  /* 8337 */ "LDSWrr\000"
  /* 8344 */ "SRAXrr\000"
  /* 8351 */ "GDOP_LDXrr\000"
  /* 8362 */ "TLS_LDXrr\000"
  /* 8372 */ "SLLXrr\000"
  /* 8379 */ "SRLXrr\000"
  /* 8386 */ "MULXrr\000"
  /* 8393 */ "STXrr\000"
  /* 8399 */ "SDIVXrr\000"
  /* 8407 */ "UDIVXrr\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned SparcInstrNameIndices[] = {
    2570U, 3143U, 4216U, 3607U, 2740U, 2721U, 2749U, 2930U, 
    2357U, 2372U, 2312U, 2299U, 2399U, 5126U, 2175U, 5986U, 
    2325U, 2566U, 2730U, 1887U, 6494U, 2663U, 2017U, 5812U, 
    1610U, 1838U, 1875U, 3778U, 2918U, 5716U, 1789U, 4024U, 
    2492U, 5705U, 2086U, 3997U, 3984U, 4287U, 5500U, 5523U, 
    2841U, 2897U, 2870U, 2766U, 2166U, 4252U, 3726U, 2075U, 
    6505U, 4413U, 3955U, 2223U, 6016U, 6046U, 3424U, 1391U, 
    714U, 3071U, 6129U, 6136U, 3103U, 3110U, 3117U, 3127U, 
    1588U, 4638U, 4601U, 4848U, 6071U, 4468U, 2830U, 4456U, 
    2819U, 2310U, 2568U, 6371U, 2185U, 2200U, 2935U, 5468U, 
    4926U, 5849U, 4943U, 4519U, 1126U, 5096U, 5727U, 4694U, 
    5881U, 2266U, 4263U, 1706U, 1100U, 1688U, 5765U, 5746U, 
    3402U, 4312U, 4331U, 1264U, 1208U, 1238U, 1177U, 1249U, 
    1189U, 1219U, 2145U, 2099U, 2129U, 5162U, 2413U, 2430U, 
    1407U, 720U, 1594U, 1535U, 4643U, 4607U, 6340U, 3550U, 
    6323U, 3533U, 1358U, 697U, 6258U, 3468U, 3238U, 3185U, 
    3311U, 3273U, 3840U, 3818U, 1647U, 5421U, 1867U, 2509U, 
    1638U, 5487U, 5827U, 1078U, 5210U, 5682U, 5237U, 6030U, 
    1118U, 5294U, 6078U, 6093U, 5641U, 5629U, 5802U, 2484U, 
    6009U, 2386U, 6039U, 2805U, 4398U, 4384U, 2798U, 4391U, 
    4687U, 2967U, 3924U, 3903U, 3931U, 3938U, 5478U, 3718U, 
    1908U, 3702U, 1859U, 3710U, 1900U, 3694U, 1851U, 3756U, 
    3748U, 2528U, 2520U, 5339U, 5329U, 5319U, 5309U, 5359U, 
    5349U, 6408U, 6418U, 5369U, 5382U, 6428U, 6438U, 5395U, 
    5408U, 1316U, 676U, 2991U, 640U, 1170U, 6108U, 3082U, 
    2291U, 6203U, 2649U, 4068U, 263U, 9U, 2477U, 246U, 
    0U, 4043U, 4075U, 2350U, 6001U, 1090U, 2631U, 2640U, 
    3870U, 3879U, 5442U, 5455U, 4807U, 3439U, 5143U, 2275U, 
    3335U, 3345U, 1957U, 1972U, 3174U, 3227U, 3259U, 3297U, 
    6143U, 6169U, 6155U, 1916U, 1944U, 1929U, 2447U, 2462U, 
    1397U, 2677U, 3502U, 6292U, 3526U, 6316U, 4814U, 1679U, 
    1669U, 4211U, 5547U, 1995U, 4500U, 4480U, 5575U, 5554U, 
    4534U, 4565U, 4551U, 5192U, 6534U, 3642U, 6527U, 3623U, 
    4964U, 3976U, 3862U, 2153U, 3033U, 2811U, 4992U, 3574U, 
    4999U, 3395U, 4984U, 3566U, 3387U, 254U, 2552U, 2544U, 
    2536U, 5858U, 4447U, 5738U, 5783U, 5891U, 4239U, 2004U, 
    1147U, 2244U, 2114U, 1344U, 683U, 3019U, 6115U, 3089U, 
    646U, 5866U, 4052U, 3910U, 5056U, 4351U, 4367U, 6485U, 
    2049U, 2256U, 5514U, 3764U, 2033U, 3811U, 3787U, 3799U, 
    1323U, 2998U, 1299U, 2974U, 6241U, 3451U, 3206U, 3153U, 
    1375U, 3055U, 1572U, 4623U, 4585U, 6275U, 3485U, 6299U, 
    3509U, 6385U, 6392U, 3668U, 4009U, 6356U, 769U, 880U, 
    987U, 805U, 916U, 1023U, 846U, 953U, 1060U, 787U, 
    898U, 1005U, 5519U, 6226U, 6480U, 4193U, 6836U, 7745U, 
    6974U, 7883U, 7070U, 8004U, 1164U, 743U, 7007U, 7927U, 
    31U, 5908U, 294U, 5944U, 44U, 5926U, 307U, 5962U, 
    18U, 72U, 233U, 4229U, 2951U, 3378U, 6844U, 7753U, 
    6897U, 7806U, 7215U, 8144U, 7024U, 7958U, 516U, 219U, 
    544U, 599U, 1624U, 624U, 7030U, 7964U, 2657U, 751U, 
    602U, 5595U, 5652U, 864U, 609U, 5604U, 5660U, 4658U, 
    659U, 5622U, 5796U, 971U, 616U, 5613U, 5668U, 2024U, 
    2856U, 6569U, 7167U, 6583U, 8096U, 7471U, 2339U, 2786U, 
    2600U, 6727U, 7636U, 6755U, 7664U, 396U, 171U, 537U, 
    1630U, 631U, 736U, 7037U, 7971U, 7047U, 7981U, 3888U, 
    3896U, 1560U, 1732U, 2065U, 363U, 2695U, 3590U, 3363U, 
    138U, 2687U, 3581U, 3355U, 531U, 2703U, 3599U, 3371U, 
    1813U, 4168U, 5156U, 1423U, 4090U, 4855U, 664U, 1524U, 
    85U, 4712U, 271U, 4763U, 4898U, 1623U, 623U, 551U, 
    562U, 418U, 1776U, 572U, 435U, 193U, 452U, 210U, 
    370U, 145U, 379U, 154U, 4155U, 581U, 5050U, 590U, 
    1826U, 4181U, 5282U, 4116U, 2613U, 4129U, 5016U, 6454U, 
    1552U, 1429U, 4861U, 1277U, 4826U, 1742U, 4135U, 5022U, 
    1782U, 5071U, 2560U, 6181U, 7141U, 8075U, 1444U, 4876U, 
    427U, 1832U, 759U, 870U, 977U, 4187U, 824U, 933U, 
    1040U, 1806U, 4161U, 5119U, 5288U, 836U, 943U, 1050U, 
    1284U, 4833U, 505U, 482U, 461U, 2710U, 6060U, 1496U, 
    493U, 470U, 4123U, 4971U, 1459U, 4891U, 1529U, 4904U, 
    1490U, 4110U, 4958U, 1436U, 4868U, 1451U, 4883U, 1291U, 
    4840U, 1502U, 4977U, 4436U, 5083U, 94U, 4722U, 280U, 
    4773U, 1516U, 2070U, 4911U, 4409U, 100U, 4729U, 286U, 
    4780U, 5078U, 388U, 163U, 6399U, 355U, 4798U, 130U, 
    4747U, 324U, 6363U, 2574U, 1987U, 347U, 4789U, 122U, 
    4738U, 1748U, 2619U, 5028U, 6468U, 444U, 202U, 404U, 
    179U, 1509U, 1819U, 4174U, 5275U, 340U, 115U, 66U, 
    4705U, 227U, 4756U, 411U, 186U, 1754U, 2625U, 4141U, 
    6474U, 1271U, 4084U, 4820U, 4441U, 5089U, 4580U, 5113U, 
    1760U, 4147U, 5042U, 3772U, 5009U, 8351U, 7939U, 6196U, 
    7180U, 8109U, 6631U, 7540U, 7294U, 8223U, 6988U, 7897U, 
    6624U, 7533U, 6981U, 7890U, 6644U, 7553U, 7094U, 8028U, 
    7013U, 7933U, 6652U, 7561U, 7310U, 8239U, 7101U, 8035U, 
    6667U, 7576U, 7114U, 8048U, 6591U, 7500U, 6770U, 7679U, 
    6690U, 7599U, 7134U, 8068U, 6614U, 7523U, 6796U, 7705U, 
    6740U, 7649U, 7408U, 8337U, 6606U, 7515U, 6783U, 7692U, 
    6705U, 7614U, 7155U, 8089U, 6748U, 7657U, 7326U, 8255U, 
    7422U, 8356U, 7019U, 7944U, 5676U, 336U, 6575U, 3047U, 
    4667U, 6460U, 6854U, 7763U, 6870U, 7779U, 7353U, 8282U, 
    6217U, 6232U, 5034U, 6965U, 7874U, 1766U, 3041U, 6931U, 
    7840U, 7442U, 8386U, 3951U, 6188U, 6916U, 7825U, 6906U, 
    7815U, 7222U, 8151U, 7268U, 8197U, 6210U, 5980U, 3661U, 
    7910U, 6541U, 7479U, 6552U, 7490U, 7344U, 8273U, 4675U, 
    4105U, 4662U, 4681U, 4205U, 3137U, 1475U, 7077U, 8011U, 
    5510U, 2962U, 6499U, 7365U, 8294U, 1484U, 7087U, 8021U, 
    6940U, 7849U, 7455U, 8399U, 7372U, 8301U, 6562U, 57U, 
    524U, 108U, 3685U, 3077U, 4405U, 7428U, 8372U, 7174U, 
    8103U, 6805U, 7714U, 6879U, 7788U, 7193U, 8122U, 7415U, 
    8344U, 6721U, 7630U, 7435U, 8379U, 7187U, 8116U, 6734U, 
    7643U, 4199U, 6599U, 7508U, 6777U, 7686U, 7302U, 8231U, 
    7001U, 7917U, 6637U, 7546U, 7242U, 8171U, 6994U, 7903U, 
    6659U, 7568U, 7250U, 8179U, 7107U, 8041U, 7057U, 7991U, 
    6683U, 7592U, 7318U, 8247U, 7128U, 8062U, 6698U, 7607U, 
    7149U, 8083U, 6675U, 7584U, 7121U, 8055U, 6763U, 7672U, 
    7335U, 8264U, 7449U, 8393U, 7360U, 8289U, 6827U, 7736U, 
    6819U, 7728U, 7063U, 7997U, 6790U, 7699U, 6713U, 7622U, 
    7235U, 8164U, 62U, 320U, 332U, 7397U, 8326U, 6835U, 
    7744U, 2851U, 7162U, 6863U, 7772U, 7923U, 2861U, 8362U, 
    7949U, 7228U, 8157U, 7386U, 8315U, 6826U, 7735U, 6958U, 
    7867U, 6949U, 7858U, 7463U, 8407U, 7379U, 8308U, 6812U, 
    7721U, 6888U, 7797U, 2584U, 7200U, 8129U, 3945U, 1774U, 
    1466U, 4096U, 4917U, 4153U, 5048U, 757U, 822U, 834U, 
    6852U, 7761U, 7286U, 8215U, 7279U, 8208U, 7345U, 8274U, 
    7258U, 8187U, 7207U, 8136U, 6448U, 2592U, 6914U, 7823U, 
    7266U, 8195U, 6923U, 7832U, 7273U, 8202U, 
};

extern const int16_t SparcRegClassByHwModeTables[2][1] = {
  { // DefaultMode
    SP::IntRegsRegClassID, // sparc_ptr_rc
  },
  { // SPARC64
    SP::I64RegsRegClassID, // sparc_ptr_rc
  },
};

static inline void InitSparcMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(SparcDescs.Insts, SparcInstrNameIndices, SparcInstrNameData, nullptr, nullptr, 894, &SparcRegClassByHwModeTables[0][0], 1);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct SparcGenInstrInfo : public TargetInstrInfo {
  explicit SparcGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~SparcGenInstrInfo() override = default;
};
extern const int16_t SparcRegClassByHwModeTables[2][1];

} // namespace llvm_ks

namespace llvm_ks::SP {


} // namespace llvm_ks::SP

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

extern const SparcInstrTable SparcDescs;
extern const unsigned SparcInstrNameIndices[];
extern const char SparcInstrNameData[];
SparcGenInstrInfo::SparcGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode, SparcRegClassByHwModeTables[STI.getHwMode(MCSubtargetInfo::HwMode_RegInfo)]) {
  InitMCInstrInfo(SparcDescs.Insts, SparcInstrNameIndices, SparcInstrNameData, nullptr, nullptr, 894, &SparcRegClassByHwModeTables[0][0], 1);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace Sparc_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace Sparc_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::Sparc_MC {


} // namespace llvm_ks::Sparc_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::Sparc_MC {

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_Is32BitBit = 10,
  Feature_Is64BitBit = 11,
  Feature_UseSoftMulDivBit = 12,
  Feature_HasV9Bit = 6,
  Feature_HasVISBit = 7,
  Feature_HasVIS2Bit = 8,
  Feature_HasVIS3Bit = 9,
  Feature_HasUA2005Bit = 4,
  Feature_HasUA2007Bit = 5,
  Feature_HasOSA2011Bit = 2,
  Feature_HasCryptoBit = 1,
  Feature_HasCASABit = 0,
  Feature_HasPWRPSRBit = 3,
};

inline FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) {
  FeatureBitset Features;
  if (!FB[Sparc::Feature64Bit])
    Features.set(Feature_Is32BitBit);
  if (FB[Sparc::Feature64Bit])
    Features.set(Feature_Is64BitBit);
  if (FB[Sparc::FeatureSoftMulDiv])
    Features.set(Feature_UseSoftMulDivBit);
  if (FB[Sparc::FeatureV9])
    Features.set(Feature_HasV9Bit);
  if (FB[Sparc::FeatureVIS])
    Features.set(Feature_HasVISBit);
  if (FB[Sparc::FeatureVIS2])
    Features.set(Feature_HasVIS2Bit);
  if (FB[Sparc::FeatureVIS3])
    Features.set(Feature_HasVIS3Bit);
  if (FB[Sparc::FeatureUA2005])
    Features.set(Feature_HasUA2005Bit);
  if (FB[Sparc::FeatureUA2007])
    Features.set(Feature_HasUA2007Bit);
  if (FB[Sparc::FeatureOSA2011])
    Features.set(Feature_HasOSA2011Bit);
  if (FB[Sparc::FeatureCrypto])
    Features.set(Feature_HasCryptoBit);
  if (FB[Sparc::LeonCASA] || FB[Sparc::FeatureV9])
    Features.set(Feature_HasCASABit);
  if (FB[Sparc::FeaturePWRPSR])
    Features.set(Feature_HasPWRPSRBit);
  return Features;
}

inline FeatureBitset computeRequiredFeatures(unsigned Opcode) {
  enum : uint8_t {
    CEFBS_None,
    CEFBS_HasCASA,
    CEFBS_HasCrypto,
    CEFBS_HasOSA2011,
    CEFBS_HasPWRPSR,
    CEFBS_HasUA2005,
    CEFBS_HasUA2007,
    CEFBS_HasV9,
    CEFBS_HasVIS,
    CEFBS_HasVIS2,
    CEFBS_HasVIS3,
    CEFBS_Is64Bit,
    CEFBS_Is64Bit_HasV9,
  };

  static constexpr FeatureBitset FeatureBitsets[] = {
    {}, // CEFBS_None
    {Feature_HasCASABit, },
    {Feature_HasCryptoBit, },
    {Feature_HasOSA2011Bit, },
    {Feature_HasPWRPSRBit, },
    {Feature_HasUA2005Bit, },
    {Feature_HasUA2007Bit, },
    {Feature_HasV9Bit, },
    {Feature_HasVISBit, },
    {Feature_HasVIS2Bit, },
    {Feature_HasVIS3Bit, },
    {Feature_Is64BitBit, },
    {Feature_Is64BitBit, Feature_HasV9Bit, },
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
    CEFBS_None, // GETPCX
    CEFBS_None, // SELECT_CC_DFP_FCC
    CEFBS_None, // SELECT_CC_DFP_ICC
    CEFBS_None, // SELECT_CC_DFP_XCC
    CEFBS_None, // SELECT_CC_FP_FCC
    CEFBS_None, // SELECT_CC_FP_ICC
    CEFBS_None, // SELECT_CC_FP_XCC
    CEFBS_None, // SELECT_CC_Int_FCC
    CEFBS_None, // SELECT_CC_Int_ICC
    CEFBS_None, // SELECT_CC_Int_XCC
    CEFBS_None, // SELECT_CC_QFP_FCC
    CEFBS_None, // SELECT_CC_QFP_ICC
    CEFBS_None, // SELECT_CC_QFP_XCC
    CEFBS_None, // SET
    CEFBS_HasV9, // SETSW
    CEFBS_Is64Bit_HasV9, // SETX
    CEFBS_None, // V8BAR
    CEFBS_None, // ADDCCri
    CEFBS_None, // ADDCCrr
    CEFBS_None, // ADDCri
    CEFBS_None, // ADDCrr
    CEFBS_None, // ADDEri
    CEFBS_None, // ADDErr
    CEFBS_HasVIS3, // ADDXC
    CEFBS_HasVIS3, // ADDXCCC
    CEFBS_None, // ADDri
    CEFBS_None, // ADDrr
    CEFBS_HasCrypto, // AES_DROUND01
    CEFBS_HasCrypto, // AES_DROUND01_LAST
    CEFBS_HasCrypto, // AES_DROUND23
    CEFBS_HasCrypto, // AES_DROUND23_LAST
    CEFBS_HasCrypto, // AES_EROUND01
    CEFBS_HasCrypto, // AES_EROUND01_LAST
    CEFBS_HasCrypto, // AES_EROUND23
    CEFBS_HasCrypto, // AES_EROUND23_LAST
    CEFBS_HasCrypto, // AES_KEXPAND0
    CEFBS_HasCrypto, // AES_KEXPAND1
    CEFBS_HasCrypto, // AES_KEXPAND2
    CEFBS_HasVIS, // ALIGNADDR
    CEFBS_HasVIS, // ALIGNADDRL
    CEFBS_HasUA2005, // ALLCLEAN
    CEFBS_None, // ANDCCri
    CEFBS_None, // ANDCCrr
    CEFBS_None, // ANDNCCri
    CEFBS_None, // ANDNCCrr
    CEFBS_None, // ANDNri
    CEFBS_None, // ANDNrr
    CEFBS_None, // ANDri
    CEFBS_None, // ANDrr
    CEFBS_HasVIS, // ARRAY16
    CEFBS_HasVIS, // ARRAY32
    CEFBS_HasVIS, // ARRAY8
    CEFBS_None, // BA
    CEFBS_None, // BCOND
    CEFBS_None, // BCONDA
    CEFBS_None, // BINDri
    CEFBS_None, // BINDrr
    CEFBS_HasVIS2, // BMASK
    CEFBS_HasV9, // BPFCC
    CEFBS_HasV9, // BPFCCA
    CEFBS_HasV9, // BPFCCANT
    CEFBS_HasV9, // BPFCCNT
    CEFBS_HasV9, // BPICC
    CEFBS_HasV9, // BPICCA
    CEFBS_HasV9, // BPICCANT
    CEFBS_HasV9, // BPICCNT
    CEFBS_HasV9, // BPR
    CEFBS_HasV9, // BPRA
    CEFBS_HasV9, // BPRANT
    CEFBS_HasV9, // BPRNT
    CEFBS_Is64Bit, // BPXCC
    CEFBS_Is64Bit, // BPXCCA
    CEFBS_Is64Bit, // BPXCCANT
    CEFBS_Is64Bit, // BPXCCNT
    CEFBS_HasVIS2, // BSHUFFLE
    CEFBS_None, // CALL
    CEFBS_None, // CALLi
    CEFBS_None, // CALLri
    CEFBS_None, // CALLrii
    CEFBS_None, // CALLrr
    CEFBS_None, // CALLrri
    CEFBS_HasCrypto, // CAMELLIA_F
    CEFBS_HasCrypto, // CAMELLIA_FL
    CEFBS_HasCrypto, // CAMELLIA_FLI
    CEFBS_HasV9, // CASAri
    CEFBS_HasCASA, // CASArr
    CEFBS_HasV9, // CASXAri
    CEFBS_HasV9, // CASXArr
    CEFBS_HasVIS3, // CMASK16
    CEFBS_HasVIS3, // CMASK32
    CEFBS_HasVIS3, // CMASK8
    CEFBS_None, // CPBCOND
    CEFBS_None, // CPBCONDA
    CEFBS_HasCrypto, // CRC32C
    CEFBS_HasOSA2011, // CWBCONDri
    CEFBS_HasOSA2011, // CWBCONDrr
    CEFBS_HasOSA2011, // CXBCONDri
    CEFBS_HasOSA2011, // CXBCONDrr
    CEFBS_HasCrypto, // DES_IIP
    CEFBS_HasCrypto, // DES_IP
    CEFBS_HasCrypto, // DES_KEXPAND
    CEFBS_HasCrypto, // DES_ROUND
    CEFBS_HasV9, // DONE
    CEFBS_HasVIS, // EDGE16
    CEFBS_HasVIS, // EDGE16L
    CEFBS_HasVIS2, // EDGE16LN
    CEFBS_HasVIS2, // EDGE16N
    CEFBS_HasVIS, // EDGE32
    CEFBS_HasVIS, // EDGE32L
    CEFBS_HasVIS2, // EDGE32LN
    CEFBS_HasVIS2, // EDGE32N
    CEFBS_HasVIS, // EDGE8
    CEFBS_HasVIS, // EDGE8L
    CEFBS_HasVIS2, // EDGE8LN
    CEFBS_HasVIS2, // EDGE8N
    CEFBS_HasV9, // FABSD
    CEFBS_HasV9, // FABSQ
    CEFBS_None, // FABSS
    CEFBS_None, // FADDD
    CEFBS_None, // FADDQ
    CEFBS_None, // FADDS
    CEFBS_HasVIS, // FALIGNADATA
    CEFBS_HasVIS, // FAND
    CEFBS_HasVIS, // FANDNOT1
    CEFBS_HasVIS, // FANDNOT1S
    CEFBS_HasVIS, // FANDNOT2
    CEFBS_HasVIS, // FANDNOT2S
    CEFBS_HasVIS, // FANDS
    CEFBS_None, // FBCOND
    CEFBS_None, // FBCONDA
    CEFBS_HasV9, // FBCONDA_V9
    CEFBS_HasV9, // FBCOND_V9
    CEFBS_HasVIS3, // FCHKSM16
    CEFBS_None, // FCMPD
    CEFBS_HasV9, // FCMPD_V9
    CEFBS_HasVIS, // FCMPEQ16
    CEFBS_HasVIS, // FCMPEQ32
    CEFBS_HasVIS, // FCMPGT16
    CEFBS_HasVIS, // FCMPGT32
    CEFBS_HasVIS, // FCMPLE16
    CEFBS_HasVIS, // FCMPLE32
    CEFBS_HasVIS, // FCMPNE16
    CEFBS_HasVIS, // FCMPNE32
    CEFBS_None, // FCMPQ
    CEFBS_HasV9, // FCMPQ_V9
    CEFBS_None, // FCMPS
    CEFBS_HasV9, // FCMPS_V9
    CEFBS_None, // FDIVD
    CEFBS_None, // FDIVQ
    CEFBS_None, // FDIVS
    CEFBS_None, // FDMULQ
    CEFBS_None, // FDTOI
    CEFBS_None, // FDTOQ
    CEFBS_None, // FDTOS
    CEFBS_HasV9, // FDTOX
    CEFBS_HasVIS, // FEXPAND
    CEFBS_HasVIS3, // FHADDD
    CEFBS_HasVIS3, // FHADDS
    CEFBS_HasVIS3, // FHSUBD
    CEFBS_HasVIS3, // FHSUBS
    CEFBS_None, // FITOD
    CEFBS_None, // FITOQ
    CEFBS_None, // FITOS
    CEFBS_HasVIS3, // FLCMPD
    CEFBS_HasVIS3, // FLCMPS
    CEFBS_None, // FLUSH
    CEFBS_HasV9, // FLUSHW
    CEFBS_None, // FLUSHri
    CEFBS_None, // FLUSHrr
    CEFBS_HasUA2007, // FMADDD
    CEFBS_HasUA2007, // FMADDS
    CEFBS_HasVIS3, // FMEAN16
    CEFBS_HasV9, // FMOVD
    CEFBS_HasV9, // FMOVD_FCC
    CEFBS_HasV9, // FMOVD_ICC
    CEFBS_Is64Bit, // FMOVD_XCC
    CEFBS_HasV9, // FMOVQ
    CEFBS_HasV9, // FMOVQ_FCC
    CEFBS_HasV9, // FMOVQ_ICC
    CEFBS_Is64Bit, // FMOVQ_XCC
    CEFBS_HasV9, // FMOVRD
    CEFBS_HasV9, // FMOVRQ
    CEFBS_HasV9, // FMOVRS
    CEFBS_None, // FMOVS
    CEFBS_HasV9, // FMOVS_FCC
    CEFBS_HasV9, // FMOVS_ICC
    CEFBS_Is64Bit, // FMOVS_XCC
    CEFBS_HasUA2007, // FMSUBD
    CEFBS_HasUA2007, // FMSUBS
    CEFBS_HasVIS, // FMUL8SUX16
    CEFBS_HasVIS, // FMUL8ULX16
    CEFBS_HasVIS, // FMUL8X16
    CEFBS_HasVIS, // FMUL8X16AL
    CEFBS_HasVIS, // FMUL8X16AU
    CEFBS_None, // FMULD
    CEFBS_HasVIS, // FMULD8SUX16
    CEFBS_HasVIS, // FMULD8ULX16
    CEFBS_None, // FMULQ
    CEFBS_None, // FMULS
    CEFBS_HasVIS3, // FNADDD
    CEFBS_HasVIS3, // FNADDS
    CEFBS_HasVIS, // FNAND
    CEFBS_HasVIS, // FNANDS
    CEFBS_HasV9, // FNEGD
    CEFBS_HasV9, // FNEGQ
    CEFBS_None, // FNEGS
    CEFBS_HasVIS3, // FNHADDD
    CEFBS_HasVIS3, // FNHADDS
    CEFBS_HasUA2007, // FNMADDD
    CEFBS_HasUA2007, // FNMADDS
    CEFBS_HasUA2007, // FNMSUBD
    CEFBS_HasUA2007, // FNMSUBS
    CEFBS_HasVIS3, // FNMULD
    CEFBS_HasVIS3, // FNMULS
    CEFBS_HasVIS, // FNOR
    CEFBS_HasVIS, // FNORS
    CEFBS_HasVIS, // FNOT1
    CEFBS_HasVIS, // FNOT1S
    CEFBS_HasVIS, // FNOT2
    CEFBS_HasVIS, // FNOT2S
    CEFBS_HasVIS3, // FNSMULD
    CEFBS_HasVIS, // FONE
    CEFBS_HasVIS, // FONES
    CEFBS_HasVIS, // FOR
    CEFBS_HasVIS, // FORNOT1
    CEFBS_HasVIS, // FORNOT1S
    CEFBS_HasVIS, // FORNOT2
    CEFBS_HasVIS, // FORNOT2S
    CEFBS_HasVIS, // FORS
    CEFBS_HasVIS, // FPACK16
    CEFBS_HasVIS, // FPACK32
    CEFBS_HasVIS, // FPACKFIX
    CEFBS_HasVIS, // FPADD16
    CEFBS_HasVIS, // FPADD16S
    CEFBS_HasVIS, // FPADD32
    CEFBS_HasVIS, // FPADD32S
    CEFBS_HasVIS3, // FPADD64
    CEFBS_HasOSA2011, // FPMADDX
    CEFBS_HasOSA2011, // FPMADDXHI
    CEFBS_HasVIS, // FPMERGE
    CEFBS_HasVIS, // FPSUB16
    CEFBS_HasVIS, // FPSUB16S
    CEFBS_HasVIS, // FPSUB32
    CEFBS_HasVIS, // FPSUB32S
    CEFBS_None, // FQTOD
    CEFBS_None, // FQTOI
    CEFBS_None, // FQTOS
    CEFBS_HasV9, // FQTOX
    CEFBS_HasVIS3, // FSLAS16
    CEFBS_HasVIS3, // FSLAS32
    CEFBS_HasVIS3, // FSLL16
    CEFBS_HasVIS3, // FSLL32
    CEFBS_None, // FSMULD
    CEFBS_None, // FSQRTD
    CEFBS_None, // FSQRTQ
    CEFBS_None, // FSQRTS
    CEFBS_HasVIS3, // FSRA16
    CEFBS_HasVIS3, // FSRA32
    CEFBS_HasVIS, // FSRC1
    CEFBS_HasVIS, // FSRC1S
    CEFBS_HasVIS, // FSRC2
    CEFBS_HasVIS, // FSRC2S
    CEFBS_HasVIS3, // FSRL16
    CEFBS_HasVIS3, // FSRL32
    CEFBS_None, // FSTOD
    CEFBS_None, // FSTOI
    CEFBS_None, // FSTOQ
    CEFBS_HasV9, // FSTOX
    CEFBS_None, // FSUBD
    CEFBS_None, // FSUBQ
    CEFBS_None, // FSUBS
    CEFBS_HasVIS, // FXNOR
    CEFBS_HasVIS, // FXNORS
    CEFBS_HasVIS, // FXOR
    CEFBS_HasVIS, // FXORS
    CEFBS_HasV9, // FXTOD
    CEFBS_HasV9, // FXTOQ
    CEFBS_HasV9, // FXTOS
    CEFBS_HasVIS, // FZERO
    CEFBS_HasVIS, // FZEROS
    CEFBS_HasV9, // GDOP_LDXrr
    CEFBS_None, // GDOP_LDrr
    CEFBS_HasUA2005, // INVALW
    CEFBS_None, // JMPLri
    CEFBS_None, // JMPLrr
    CEFBS_HasV9, // LDAri
    CEFBS_None, // LDArr
    CEFBS_None, // LDCSRri
    CEFBS_None, // LDCSRrr
    CEFBS_None, // LDCri
    CEFBS_None, // LDCrr
    CEFBS_HasV9, // LDDAri
    CEFBS_None, // LDDArr
    CEFBS_None, // LDDCri
    CEFBS_None, // LDDCrr
    CEFBS_HasV9, // LDDFAri
    CEFBS_HasV9, // LDDFArr
    CEFBS_None, // LDDFri
    CEFBS_None, // LDDFrr
    CEFBS_None, // LDDri
    CEFBS_None, // LDDrr
    CEFBS_HasV9, // LDFAri
    CEFBS_HasV9, // LDFArr
    CEFBS_None, // LDFSRri
    CEFBS_None, // LDFSRrr
    CEFBS_None, // LDFri
    CEFBS_None, // LDFrr
    CEFBS_HasV9, // LDQFAri
    CEFBS_HasV9, // LDQFArr
    CEFBS_HasV9, // LDQFri
    CEFBS_HasV9, // LDQFrr
    CEFBS_HasV9, // LDSBAri
    CEFBS_None, // LDSBArr
    CEFBS_None, // LDSBri
    CEFBS_None, // LDSBrr
    CEFBS_HasV9, // LDSHAri
    CEFBS_None, // LDSHArr
    CEFBS_None, // LDSHri
    CEFBS_None, // LDSHrr
    CEFBS_HasV9, // LDSTUBAri
    CEFBS_None, // LDSTUBArr
    CEFBS_None, // LDSTUBri
    CEFBS_None, // LDSTUBrr
    CEFBS_HasV9, // LDSWAri
    CEFBS_HasV9, // LDSWArr
    CEFBS_HasV9, // LDSWri
    CEFBS_HasV9, // LDSWrr
    CEFBS_HasV9, // LDUBAri
    CEFBS_None, // LDUBArr
    CEFBS_None, // LDUBri
    CEFBS_None, // LDUBrr
    CEFBS_HasV9, // LDUHAri
    CEFBS_None, // LDUHArr
    CEFBS_None, // LDUHri
    CEFBS_None, // LDUHrr
    CEFBS_HasV9, // LDXAri
    CEFBS_HasV9, // LDXArr
    CEFBS_HasV9, // LDXFSRri
    CEFBS_HasV9, // LDXFSRrr
    CEFBS_HasV9, // LDXri
    CEFBS_HasV9, // LDXrr
    CEFBS_None, // LDri
    CEFBS_None, // LDrr
    CEFBS_HasVIS3, // LZCNT
    CEFBS_HasCrypto, // MD5
    CEFBS_HasV9, // MEMBARi
    CEFBS_HasCrypto, // MONTMUL
    CEFBS_HasCrypto, // MONTSQR
    CEFBS_HasVIS3, // MOVDTOX
    CEFBS_HasV9, // MOVFCCri
    CEFBS_HasV9, // MOVFCCrr
    CEFBS_HasV9, // MOVICCri
    CEFBS_HasV9, // MOVICCrr
    CEFBS_HasV9, // MOVRri
    CEFBS_HasV9, // MOVRrr
    CEFBS_HasVIS3, // MOVSTOSW
    CEFBS_HasVIS3, // MOVSTOUW
    CEFBS_HasVIS3, // MOVWTOS
    CEFBS_Is64Bit, // MOVXCCri
    CEFBS_Is64Bit, // MOVXCCrr
    CEFBS_HasVIS3, // MOVXTOD
    CEFBS_HasCrypto, // MPMUL
    CEFBS_None, // MULSCCri
    CEFBS_None, // MULSCCrr
    CEFBS_HasV9, // MULXri
    CEFBS_HasV9, // MULXrr
    CEFBS_None, // NOP
    CEFBS_HasUA2005, // NORMALW
    CEFBS_None, // ORCCri
    CEFBS_None, // ORCCrr
    CEFBS_None, // ORNCCri
    CEFBS_None, // ORNCCrr
    CEFBS_None, // ORNri
    CEFBS_None, // ORNrr
    CEFBS_None, // ORri
    CEFBS_None, // ORrr
    CEFBS_HasUA2005, // OTHERW
    CEFBS_HasVIS, // PDIST
    CEFBS_HasVIS3, // PDISTN
    CEFBS_HasV9, // POPCrr
    CEFBS_HasV9, // PREFETCHAi
    CEFBS_HasV9, // PREFETCHAr
    CEFBS_HasV9, // PREFETCHi
    CEFBS_HasV9, // PREFETCHr
    CEFBS_HasPWRPSR, // PWRPSRri
    CEFBS_HasPWRPSR, // PWRPSRrr
    CEFBS_None, // RDASR
    CEFBS_HasV9, // RDFQ
    CEFBS_HasV9, // RDPR
    CEFBS_None, // RDPSR
    CEFBS_None, // RDTBR
    CEFBS_None, // RDWIM
    CEFBS_HasV9, // RESTORED
    CEFBS_None, // RESTOREri
    CEFBS_None, // RESTORErr
    CEFBS_None, // RET
    CEFBS_None, // RETL
    CEFBS_HasV9, // RETRY
    CEFBS_None, // RETTri
    CEFBS_None, // RETTrr
    CEFBS_HasV9, // SAVED
    CEFBS_None, // SAVEri
    CEFBS_None, // SAVErr
    CEFBS_None, // SDIVCCri
    CEFBS_None, // SDIVCCrr
    CEFBS_HasV9, // SDIVXri
    CEFBS_HasV9, // SDIVXrr
    CEFBS_None, // SDIVri
    CEFBS_None, // SDIVrr
    CEFBS_None, // SETHIi
    CEFBS_HasCrypto, // SHA1
    CEFBS_HasCrypto, // SHA256
    CEFBS_HasCrypto, // SHA512
    CEFBS_HasVIS, // SHUTDOWN
    CEFBS_HasVIS2, // SIAM
    CEFBS_HasV9, // SIR
    CEFBS_HasV9, // SLLXri
    CEFBS_HasV9, // SLLXrr
    CEFBS_None, // SLLri
    CEFBS_None, // SLLrr
    CEFBS_None, // SMACri
    CEFBS_None, // SMACrr
    CEFBS_None, // SMULCCri
    CEFBS_None, // SMULCCrr
    CEFBS_None, // SMULri
    CEFBS_None, // SMULrr
    CEFBS_HasV9, // SRAXri
    CEFBS_HasV9, // SRAXrr
    CEFBS_None, // SRAri
    CEFBS_None, // SRArr
    CEFBS_HasV9, // SRLXri
    CEFBS_HasV9, // SRLXrr
    CEFBS_None, // SRLri
    CEFBS_None, // SRLrr
    CEFBS_HasV9, // STAri
    CEFBS_None, // STArr
    CEFBS_None, // STBAR
    CEFBS_HasV9, // STBAri
    CEFBS_None, // STBArr
    CEFBS_None, // STBri
    CEFBS_None, // STBrr
    CEFBS_None, // STCSRri
    CEFBS_None, // STCSRrr
    CEFBS_None, // STCri
    CEFBS_None, // STCrr
    CEFBS_HasV9, // STDAri
    CEFBS_None, // STDArr
    CEFBS_None, // STDCQri
    CEFBS_None, // STDCQrr
    CEFBS_None, // STDCri
    CEFBS_None, // STDCrr
    CEFBS_HasV9, // STDFAri
    CEFBS_HasV9, // STDFArr
    CEFBS_None, // STDFQri
    CEFBS_None, // STDFQrr
    CEFBS_None, // STDFri
    CEFBS_None, // STDFrr
    CEFBS_None, // STDri
    CEFBS_None, // STDrr
    CEFBS_HasV9, // STFAri
    CEFBS_HasV9, // STFArr
    CEFBS_None, // STFSRri
    CEFBS_None, // STFSRrr
    CEFBS_None, // STFri
    CEFBS_None, // STFrr
    CEFBS_HasV9, // STHAri
    CEFBS_None, // STHArr
    CEFBS_None, // STHri
    CEFBS_None, // STHrr
    CEFBS_HasV9, // STQFAri
    CEFBS_HasV9, // STQFArr
    CEFBS_HasV9, // STQFri
    CEFBS_HasV9, // STQFrr
    CEFBS_HasV9, // STXAri
    CEFBS_HasV9, // STXArr
    CEFBS_HasV9, // STXFSRri
    CEFBS_HasV9, // STXFSRrr
    CEFBS_HasV9, // STXri
    CEFBS_HasV9, // STXrr
    CEFBS_None, // STri
    CEFBS_None, // STrr
    CEFBS_None, // SUBCCri
    CEFBS_None, // SUBCCrr
    CEFBS_None, // SUBCri
    CEFBS_None, // SUBCrr
    CEFBS_None, // SUBEri
    CEFBS_None, // SUBErr
    CEFBS_None, // SUBri
    CEFBS_None, // SUBrr
    CEFBS_HasV9, // SWAPAri
    CEFBS_None, // SWAPArr
    CEFBS_None, // SWAPri
    CEFBS_None, // SWAPrr
    CEFBS_None, // TA1
    CEFBS_None, // TA3
    CEFBS_None, // TA5
    CEFBS_None, // TADDCCTVri
    CEFBS_None, // TADDCCTVrr
    CEFBS_None, // TADDCCri
    CEFBS_None, // TADDCCrr
    CEFBS_None, // TAIL_CALL
    CEFBS_None, // TAIL_CALLri
    CEFBS_HasV9, // TICCri
    CEFBS_HasV9, // TICCrr
    CEFBS_None, // TLS_ADDrr
    CEFBS_None, // TLS_CALL
    CEFBS_HasV9, // TLS_LDXrr
    CEFBS_None, // TLS_LDrr
    CEFBS_None, // TRAPri
    CEFBS_None, // TRAPrr
    CEFBS_None, // TSUBCCTVri
    CEFBS_None, // TSUBCCTVrr
    CEFBS_None, // TSUBCCri
    CEFBS_None, // TSUBCCrr
    CEFBS_Is64Bit, // TXCCri
    CEFBS_Is64Bit, // TXCCrr
    CEFBS_None, // UDIVCCri
    CEFBS_None, // UDIVCCrr
    CEFBS_HasV9, // UDIVXri
    CEFBS_HasV9, // UDIVXrr
    CEFBS_None, // UDIVri
    CEFBS_None, // UDIVrr
    CEFBS_None, // UMACri
    CEFBS_None, // UMACrr
    CEFBS_None, // UMULCCri
    CEFBS_None, // UMULCCrr
    CEFBS_HasVIS3, // UMULXHI
    CEFBS_None, // UMULri
    CEFBS_None, // UMULrr
    CEFBS_None, // UNIMP
    CEFBS_None, // V9FCMPD
    CEFBS_None, // V9FCMPED
    CEFBS_None, // V9FCMPEQ
    CEFBS_None, // V9FCMPES
    CEFBS_None, // V9FCMPQ
    CEFBS_None, // V9FCMPS
    CEFBS_HasV9, // V9FMOVD_FCC
    CEFBS_HasV9, // V9FMOVQ_FCC
    CEFBS_HasV9, // V9FMOVS_FCC
    CEFBS_HasV9, // V9MOVFCCri
    CEFBS_HasV9, // V9MOVFCCrr
    CEFBS_None, // WRASRri
    CEFBS_None, // WRASRrr
    CEFBS_HasV9, // WRPRri
    CEFBS_HasV9, // WRPRrr
    CEFBS_None, // WRPSRri
    CEFBS_None, // WRPSRrr
    CEFBS_None, // WRTBRri
    CEFBS_None, // WRTBRrr
    CEFBS_None, // WRWIMri
    CEFBS_None, // WRWIMrr
    CEFBS_HasVIS3, // XMULX
    CEFBS_HasVIS3, // XMULXHI
    CEFBS_None, // XNORCCri
    CEFBS_None, // XNORCCrr
    CEFBS_None, // XNORri
    CEFBS_None, // XNORrr
    CEFBS_None, // XORCCri
    CEFBS_None, // XORCCrr
    CEFBS_None, // XORri
    CEFBS_None, // XORrr
  };

  assert(Opcode < 894);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::Sparc_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::Sparc_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::Sparc_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::Sparc_MC {

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_HasCASA",
  "Feature_HasCrypto",
  "Feature_HasOSA2011",
  "Feature_HasPWRPSR",
  "Feature_HasUA2005",
  "Feature_HasUA2007",
  "Feature_HasV9",
  "Feature_HasVIS",
  "Feature_HasVIS2",
  "Feature_HasVIS3",
  "Feature_Is32Bit",
  "Feature_Is64Bit",
  "Feature_UseSoftMulDiv",
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
    Msg << "Attempting to emit " << &SparcInstrNameData[SparcInstrNameIndices[Opcode]]
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::Sparc_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

