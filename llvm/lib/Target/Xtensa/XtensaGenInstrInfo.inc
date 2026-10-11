/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::Xtensa {

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
    ADJCALLSTACKDOWN                      = 331, // XtensaInstrInfo.td:596
    ADJCALLSTACKUP                        = 332, // XtensaInstrInfo.td:599
    ATOMIC_CMP_SWAP_32_P                  = 333, // XtensaInstrInfo.td:1558
    BRCC_FP                               = 334, // XtensaInstrInfo.td:1333
    BR_JT                                 = 335, // XtensaInstrInfo.td:475
    MOVSP_P                               = 336, // XtensaInstrInfo.td:762
    SELECT                                = 337, // XtensaInstrInfo.td:608
    SELECT_CC_FP_FP                       = 338, // XtensaInstrInfo.td:1327
    SELECT_CC_FP_INT                      = 339, // XtensaInstrInfo.td:1324
    SELECT_CC_INT_FP                      = 340, // XtensaInstrInfo.td:1321
    ABS                                   = 341, // XtensaInstrInfo.td:54
    ABS_S                                 = 342, // XtensaInstrInfo.td:1120
    ADD                                   = 343, // XtensaInstrInfo.td:32
    ADDEXPM_S                             = 344, // XtensaInstrInfo.td:1133
    ADDEXP_S                              = 345, // XtensaInstrInfo.td:1128
    ADDI                                  = 346, // XtensaInstrInfo.td:59
    ADDI_N                                = 347, // XtensaInstrInfo.td:628
    ADDMI                                 = 348, // XtensaInstrInfo.td:65
    ADDX2                                 = 349, // XtensaInstrInfo.td:42
    ADDX4                                 = 350, // XtensaInstrInfo.td:43
    ADDX8                                 = 351, // XtensaInstrInfo.td:44
    ADD_N                                 = 352, // XtensaInstrInfo.td:626
    ADD_S                                 = 353, // XtensaInstrInfo.td:1036
    ALL4                                  = 354, // XtensaInstrInfo.td:838
    ALL8                                  = 355, // XtensaInstrInfo.td:843
    AND                                   = 356, // XtensaInstrInfo.td:34
    ANDB                                  = 357, // XtensaInstrInfo.td:848
    ANDBC                                 = 358, // XtensaInstrInfo.td:850
    ANY4                                  = 359, // XtensaInstrInfo.td:859
    ANY8                                  = 360, // XtensaInstrInfo.td:864
    BALL                                  = 361, // XtensaInstrInfo.td:340
    BANY                                  = 362, // XtensaInstrInfo.td:349
    BBC                                   = 363, // XtensaInstrInfo.td:358
    BBCI                                  = 364, // XtensaInstrInfo.td:394
    BBS                                   = 365, // XtensaInstrInfo.td:367
    BBSI                                  = 366, // XtensaInstrInfo.td:406
    BEQ                                   = 367, // XtensaInstrInfo.td:321
    BEQI                                  = 368, // XtensaInstrInfo.td:328
    BEQZ                                  = 369, // XtensaInstrInfo.td:335
    BEQZ_N                                = 370, // XtensaInstrInfo.td:638
    BF                                    = 371, // XtensaInstrInfo.td:881
    BGE                                   = 372, // XtensaInstrInfo.td:323
    BGEI                                  = 373, // XtensaInstrInfo.td:330
    BGEU                                  = 374, // XtensaInstrInfo.td:325
    BGEUI                                 = 375, // XtensaInstrInfo.td:332
    BGEZ                                  = 376, // XtensaInstrInfo.td:337
    BLT                                   = 377, // XtensaInstrInfo.td:324
    BLTI                                  = 378, // XtensaInstrInfo.td:331
    BLTU                                  = 379, // XtensaInstrInfo.td:326
    BLTUI                                 = 380, // XtensaInstrInfo.td:333
    BLTZ                                  = 381, // XtensaInstrInfo.td:338
    BNALL                                 = 382, // XtensaInstrInfo.td:376
    BNE                                   = 383, // XtensaInstrInfo.td:322
    BNEI                                  = 384, // XtensaInstrInfo.td:329
    BNEZ                                  = 385, // XtensaInstrInfo.td:336
    BNEZ_N                                = 386, // XtensaInstrInfo.td:645
    BNONE                                 = 387, // XtensaInstrInfo.td:385
    BREAK                                 = 388, // XtensaInstrInfo.td:1407
    BREAK_N                               = 389, // XtensaInstrInfo.td:1412
    BT                                    = 390, // XtensaInstrInfo.td:870
    CALL0                                 = 391, // XtensaInstrInfo.td:441
    CALL12                                = 392, // XtensaInstrInfo.td:731
    CALL4                                 = 393, // XtensaInstrInfo.td:731
    CALL8                                 = 394, // XtensaInstrInfo.td:731
    CALLX0                                = 395, // XtensaInstrInfo.td:446
    CALLX12                               = 396, // XtensaInstrInfo.td:736
    CALLX4                                = 397, // XtensaInstrInfo.td:736
    CALLX8                                = 398, // XtensaInstrInfo.td:736
    CEIL_S                                = 399, // XtensaInstrInfo.td:1138
    CLAMPS                                = 400, // XtensaInstrInfo.td:922
    CLR_BIT_GPIO_OUT                      = 401, // XtensaInstrInfo.td:1581
    CONST_S                               = 402, // XtensaInstrInfo.td:1145
    DIV0_S                                = 403, // XtensaInstrInfo.td:1153
    DIVN_S                                = 404, // XtensaInstrInfo.td:1158
    DSYNC                                 = 405, // XtensaInstrInfo.td:518
    ENTRY                                 = 406, // XtensaInstrInfo.td:719
    ESYNC                                 = 407, // XtensaInstrInfo.td:542
    EXCW                                  = 408, // XtensaInstrInfo.td:1464
    EXTUI                                 = 409, // XtensaInstrInfo.td:140
    EXTW                                  = 410, // XtensaInstrInfo.td:491
    FLOAT_S                               = 411, // XtensaInstrInfo.td:1161
    FLOOR_S                               = 412, // XtensaInstrInfo.td:1170
    GET_GPIO_IN                           = 413, // XtensaInstrInfo.td:1590
    IDTLB                                 = 414, // XtensaInstrInfo.td:1349
    IITLB                                 = 415, // XtensaInstrInfo.td:1355
    ILL                                   = 416, // XtensaInstrInfo.td:505
    ILL_N                                 = 417, // XtensaInstrInfo.td:653
    ISYNC                                 = 418, // XtensaInstrInfo.td:526
    J                                     = 419, // XtensaInstrInfo.td:424
    JX                                    = 420, // XtensaInstrInfo.td:430
    L16SI                                 = 421, // XtensaInstrInfo.td:214
    L16UI                                 = 422, // XtensaInstrInfo.td:215
    L32E                                  = 423, // XtensaInstrInfo.td:798
    L32I                                  = 424, // XtensaInstrInfo.td:216
    L32I_N                                = 425, // XtensaInstrInfo.td:683
    L32R                                  = 426, // XtensaInstrInfo.td:238
    L8UI                                  = 427, // XtensaInstrInfo.td:213
    LDDEC                                 = 428, // XtensaDSPInstrInfo.td:333
    LDDR32P                               = 429, // XtensaInstrInfo.td:1445
    LDINC                                 = 430, // XtensaDSPInstrInfo.td:344
    LEA_ADD                               = 431, // XtensaInstrInfo.td:253
    LOOP                                  = 432, // XtensaInstrInfo.td:959
    LOOPGTZ                               = 433, // XtensaInstrInfo.td:970
    LOOPNEZ                               = 434, // XtensaInstrInfo.td:981
    LSI                                   = 435, // XtensaInstrInfo.td:1042
    LSIP                                  = 436, // XtensaInstrInfo.td:1051
    LSX                                   = 437, // XtensaInstrInfo.td:1060
    LSXP                                  = 438, // XtensaInstrInfo.td:1063
    MADDN_S                               = 439, // XtensaInstrInfo.td:1177
    MADD_S                                = 440, // XtensaInstrInfo.td:1183
    MAX                                   = 441, // XtensaInstrInfo.td:950
    MAXU                                  = 442, // XtensaInstrInfo.td:952
    MEMW                                  = 443, // XtensaInstrInfo.td:484
    MIN                                   = 444, // XtensaInstrInfo.td:949
    MINU                                  = 445, // XtensaInstrInfo.td:951
    MKDADJ_S                              = 446, // XtensaInstrInfo.td:1196
    MKSADJ_S                              = 447, // XtensaInstrInfo.td:1201
    MOVEQZ                                = 448, // XtensaInstrInfo.td:93
    MOVEQZ_S                              = 449, // XtensaInstrInfo.td:1213
    MOVF                                  = 450, // XtensaInstrInfo.td:897
    MOVF_S                                = 451, // XtensaInstrInfo.td:1216
    MOVGEZ                                = 452, // XtensaInstrInfo.td:99
    MOVGEZ_S                              = 453, // XtensaInstrInfo.td:1219
    MOVI                                  = 454, // XtensaInstrInfo.td:83
    MOVI_N                                = 455, // XtensaInstrInfo.td:668
    MOVLTZ                                = 456, // XtensaInstrInfo.td:97
    MOVLTZ_S                              = 457, // XtensaInstrInfo.td:1222
    MOVNEZ                                = 458, // XtensaInstrInfo.td:95
    MOVNEZ_S                              = 459, // XtensaInstrInfo.td:1225
    MOVSP                                 = 460, // XtensaInstrInfo.td:754
    MOVT                                  = 461, // XtensaInstrInfo.td:900
    MOVT_S                                = 462, // XtensaInstrInfo.td:1228
    MOV_N                                 = 463, // XtensaInstrInfo.td:661
    MOV_S                                 = 464, // XtensaInstrInfo.td:1207
    MSUB_S                                = 465, // XtensaInstrInfo.td:1232
    MUL16S                                = 466, // XtensaInstrInfo.td:997
    MUL16U                                = 467, // XtensaInstrInfo.td:999
    MULA_AA_HH                            = 468, // XtensaDSPInstrInfo.td:105
    MULA_AA_HL                            = 469, // XtensaDSPInstrInfo.td:103
    MULA_AA_LH                            = 470, // XtensaDSPInstrInfo.td:104
    MULA_AA_LL                            = 471, // XtensaDSPInstrInfo.td:102
    MULA_AD_HH                            = 472, // XtensaDSPInstrInfo.td:124
    MULA_AD_HL                            = 473, // XtensaDSPInstrInfo.td:122
    MULA_AD_LH                            = 474, // XtensaDSPInstrInfo.td:123
    MULA_AD_LL                            = 475, // XtensaDSPInstrInfo.td:121
    MULA_DA_HH                            = 476, // XtensaDSPInstrInfo.td:143
    MULA_DA_HH_LDDEC                      = 477, // XtensaDSPInstrInfo.td:263
    MULA_DA_HH_LDINC                      = 478, // XtensaDSPInstrInfo.td:283
    MULA_DA_HL                            = 479, // XtensaDSPInstrInfo.td:141
    MULA_DA_HL_LDDEC                      = 480, // XtensaDSPInstrInfo.td:261
    MULA_DA_HL_LDINC                      = 481, // XtensaDSPInstrInfo.td:281
    MULA_DA_LH                            = 482, // XtensaDSPInstrInfo.td:142
    MULA_DA_LH_LDDEC                      = 483, // XtensaDSPInstrInfo.td:262
    MULA_DA_LH_LDINC                      = 484, // XtensaDSPInstrInfo.td:282
    MULA_DA_LL                            = 485, // XtensaDSPInstrInfo.td:140
    MULA_DA_LL_LDDEC                      = 486, // XtensaDSPInstrInfo.td:260
    MULA_DA_LL_LDINC                      = 487, // XtensaDSPInstrInfo.td:280
    MULA_DD_HH                            = 488, // XtensaDSPInstrInfo.td:166
    MULA_DD_HH_LDDEC                      = 489, // XtensaDSPInstrInfo.td:307
    MULA_DD_HH_LDINC                      = 490, // XtensaDSPInstrInfo.td:331
    MULA_DD_HL                            = 491, // XtensaDSPInstrInfo.td:164
    MULA_DD_HL_LDDEC                      = 492, // XtensaDSPInstrInfo.td:305
    MULA_DD_HL_LDINC                      = 493, // XtensaDSPInstrInfo.td:329
    MULA_DD_LH                            = 494, // XtensaDSPInstrInfo.td:165
    MULA_DD_LH_LDDEC                      = 495, // XtensaDSPInstrInfo.td:306
    MULA_DD_LH_LDINC                      = 496, // XtensaDSPInstrInfo.td:330
    MULA_DD_LL                            = 497, // XtensaDSPInstrInfo.td:163
    MULA_DD_LL_LDDEC                      = 498, // XtensaDSPInstrInfo.td:304
    MULA_DD_LL_LDINC                      = 499, // XtensaDSPInstrInfo.td:328
    MULL                                  = 500, // XtensaInstrInfo.td:1007
    MULSH                                 = 501, // XtensaInstrInfo.td:1009
    MULS_AA_HH                            = 502, // XtensaDSPInstrInfo.td:179
    MULS_AA_HL                            = 503, // XtensaDSPInstrInfo.td:177
    MULS_AA_LH                            = 504, // XtensaDSPInstrInfo.td:178
    MULS_AA_LL                            = 505, // XtensaDSPInstrInfo.td:176
    MULS_AD_HH                            = 506, // XtensaDSPInstrInfo.td:198
    MULS_AD_HL                            = 507, // XtensaDSPInstrInfo.td:196
    MULS_AD_LH                            = 508, // XtensaDSPInstrInfo.td:197
    MULS_AD_LL                            = 509, // XtensaDSPInstrInfo.td:195
    MULS_DA_HH                            = 510, // XtensaDSPInstrInfo.td:217
    MULS_DA_HL                            = 511, // XtensaDSPInstrInfo.td:215
    MULS_DA_LH                            = 512, // XtensaDSPInstrInfo.td:216
    MULS_DA_LL                            = 513, // XtensaDSPInstrInfo.td:214
    MULS_DD_HH                            = 514, // XtensaDSPInstrInfo.td:240
    MULS_DD_HL                            = 515, // XtensaDSPInstrInfo.td:238
    MULS_DD_LH                            = 516, // XtensaDSPInstrInfo.td:239
    MULS_DD_LL                            = 517, // XtensaDSPInstrInfo.td:237
    MULUH                                 = 518, // XtensaInstrInfo.td:1008
    MUL_AA_HH                             = 519, // XtensaDSPInstrInfo.td:38
    MUL_AA_HL                             = 520, // XtensaDSPInstrInfo.td:36
    MUL_AA_LH                             = 521, // XtensaDSPInstrInfo.td:37
    MUL_AA_LL                             = 522, // XtensaDSPInstrInfo.td:35
    MUL_AD_HH                             = 523, // XtensaDSPInstrInfo.td:55
    MUL_AD_HL                             = 524, // XtensaDSPInstrInfo.td:53
    MUL_AD_LH                             = 525, // XtensaDSPInstrInfo.td:54
    MUL_AD_LL                             = 526, // XtensaDSPInstrInfo.td:52
    MUL_DA_HH                             = 527, // XtensaDSPInstrInfo.td:72
    MUL_DA_HL                             = 528, // XtensaDSPInstrInfo.td:70
    MUL_DA_LH                             = 529, // XtensaDSPInstrInfo.td:71
    MUL_DA_LL                             = 530, // XtensaDSPInstrInfo.td:69
    MUL_DD_HH                             = 531, // XtensaDSPInstrInfo.td:93
    MUL_DD_HL                             = 532, // XtensaDSPInstrInfo.td:91
    MUL_DD_LH                             = 533, // XtensaDSPInstrInfo.td:92
    MUL_DD_LL                             = 534, // XtensaDSPInstrInfo.td:90
    MUL_S                                 = 535, // XtensaInstrInfo.td:1038
    NEG                                   = 536, // XtensaInstrInfo.td:74
    NEG_S                                 = 537, // XtensaInstrInfo.td:1245
    NEXP01_S                              = 538, // XtensaInstrInfo.td:1240
    NOP                                   = 539, // XtensaInstrInfo.td:550
    NOP_N                                 = 540, // XtensaInstrInfo.td:674
    NSA                                   = 541, // XtensaInstrInfo.td:933
    NSAU                                  = 542, // XtensaInstrInfo.td:938
    OEQ_S                                 = 543, // XtensaInstrInfo.td:1111
    OLE_S                                 = 544, // XtensaInstrInfo.td:1113
    OLT_S                                 = 545, // XtensaInstrInfo.td:1112
    OR                                    = 546, // XtensaInstrInfo.td:35
    ORB                                   = 547, // XtensaInstrInfo.td:852
    ORBC                                  = 548, // XtensaInstrInfo.td:854
    PDTLB                                 = 549, // XtensaInstrInfo.td:1361
    PITLB                                 = 550, // XtensaInstrInfo.td:1366
    QUOS                                  = 551, // XtensaInstrInfo.td:1016
    QUOU                                  = 552, // XtensaInstrInfo.td:1017
    RDTLB0                                = 553, // XtensaInstrInfo.td:1371
    RDTLB1                                = 554, // XtensaInstrInfo.td:1376
    RECIP0_S                              = 555, // XtensaInstrInfo.td:1251
    REMS                                  = 556, // XtensaInstrInfo.td:1018
    REMU                                  = 557, // XtensaInstrInfo.td:1019
    RET                                   = 558, // XtensaInstrInfo.td:457
    RETW                                  = 559, // XtensaInstrInfo.td:776
    RETW_N                                = 560, // XtensaInstrInfo.td:768
    RET_N                                 = 561, // XtensaInstrInfo.td:706
    RFDE                                  = 562, // XtensaInstrInfo.td:1471
    RFE                                   = 563, // XtensaInstrInfo.td:1479
    RFI                                   = 564, // XtensaInstrInfo.td:1514
    RFR                                   = 565, // XtensaInstrInfo.td:1256
    RFWO                                  = 566, // XtensaInstrInfo.td:816
    RFWU                                  = 567, // XtensaInstrInfo.td:807
    RITLB0                                = 568, // XtensaInstrInfo.td:1381
    RITLB1                                = 569, // XtensaInstrInfo.td:1386
    ROTW                                  = 570, // XtensaInstrInfo.td:825
    ROUND_S                               = 571, // XtensaInstrInfo.td:1262
    RSIL                                  = 572, // XtensaInstrInfo.td:1497
    RSQRT0_S                              = 573, // XtensaInstrInfo.td:1269
    RSR                                   = 574, // XtensaInstrInfo.td:560
    RSYNC                                 = 575, // XtensaInstrInfo.td:534
    RUR                                   = 576, // XtensaInstrInfo.td:580
    S16I                                  = 577, // XtensaInstrInfo.td:234
    S32C1I                                = 578, // XtensaInstrInfo.td:1528
    S32E                                  = 579, // XtensaInstrInfo.td:789
    S32I                                  = 580, // XtensaInstrInfo.td:235
    S32I_N                                = 581, // XtensaInstrInfo.td:694
    S8I                                   = 582, // XtensaInstrInfo.td:233
    SDDR32P                               = 583, // XtensaInstrInfo.td:1453
    SET_BIT_GPIO_OUT                      = 584, // XtensaInstrInfo.td:1572
    SEXT                                  = 585, // XtensaInstrInfo.td:908
    SLL                                   = 586, // XtensaInstrInfo.td:107
    SLLI                                  = 587, // XtensaInstrInfo.td:168
    SQRT0_S                               = 588, // XtensaInstrInfo.td:1274
    SRA                                   = 589, // XtensaInstrInfo.td:112
    SRAI                                  = 590, // XtensaInstrInfo.td:151
    SRC                                   = 591, // XtensaInstrInfo.td:117
    SRL                                   = 592, // XtensaInstrInfo.td:120
    SRLI                                  = 593, // XtensaInstrInfo.td:160
    SSA8L                                 = 594, // XtensaInstrInfo.td:177
    SSAI                                  = 595, // XtensaInstrInfo.td:183
    SSI                                   = 596, // XtensaInstrInfo.td:1071
    SSIP                                  = 597, // XtensaInstrInfo.td:1080
    SSL                                   = 598, // XtensaInstrInfo.td:127
    SSR                                   = 599, // XtensaInstrInfo.td:133
    SSX                                   = 600, // XtensaInstrInfo.td:1089
    SSXP                                  = 601, // XtensaInstrInfo.td:1092
    SUB                                   = 602, // XtensaInstrInfo.td:33
    SUBX2                                 = 603, // XtensaInstrInfo.td:50
    SUBX4                                 = 604, // XtensaInstrInfo.td:51
    SUBX8                                 = 605, // XtensaInstrInfo.td:52
    SUB_S                                 = 606, // XtensaInstrInfo.td:1037
    SYSCALL                               = 607, // XtensaInstrInfo.td:1486
    TRUNC_S                               = 608, // XtensaInstrInfo.td:1279
    UEQ_S                                 = 609, // XtensaInstrInfo.td:1115
    UFLOAT_S                              = 610, // XtensaInstrInfo.td:1288
    ULE_S                                 = 611, // XtensaInstrInfo.td:1117
    ULT_S                                 = 612, // XtensaInstrInfo.td:1116
    UMUL_AA_HH                            = 613, // XtensaDSPInstrInfo.td:26
    UMUL_AA_HL                            = 614, // XtensaDSPInstrInfo.td:24
    UMUL_AA_LH                            = 615, // XtensaDSPInstrInfo.td:25
    UMUL_AA_LL                            = 616, // XtensaDSPInstrInfo.td:23
    UN_S                                  = 617, // XtensaInstrInfo.td:1118
    UTRUNC_S                              = 618, // XtensaInstrInfo.td:1297
    WAITI                                 = 619, // XtensaInstrInfo.td:1505
    WDTLB                                 = 620, // XtensaInstrInfo.td:1391
    WFR                                   = 621, // XtensaInstrInfo.td:1306
    WITLB                                 = 622, // XtensaInstrInfo.td:1396
    WR_MASK_GPIO_OUT                      = 623, // XtensaInstrInfo.td:1567
    WSR                                   = 624, // XtensaInstrInfo.td:557
    WUR                                   = 625, // XtensaInstrInfo.td:572
    XOR                                   = 626, // XtensaInstrInfo.td:36
    XORB                                  = 627, // XtensaInstrInfo.td:856
    XSR                                   = 628, // XtensaInstrInfo.td:563
    INSTRUCTION_LIST_END = 629
  };

} // namespace llvm_ks::Xtensa

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::Xtensa::Sched {

  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };

} // namespace llvm_ks::Xtensa::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct XtensaInstrTable {
  MCInstrDesc Insts[629];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[16];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[298];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof XtensaInstrTable::ImplicitOps + sizeof XtensaInstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned XtensaOpInfoBase = (sizeof XtensaInstrTable::ImplicitOps + sizeof XtensaInstrTable::Padding) / sizeof(MCOperandInfo);

extern const XtensaInstrTable XtensaDescs = {
  {
    { 628,	4,	2,	3,	0,	0,	0,	XtensaOpInfoBase + 294,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XSR
    { 627,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 202,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XORB
    { 626,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR
    { 625,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 292,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // WUR
    { 624,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 290,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // WSR
    { 623,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // WR_MASK_GPIO_OUT
    { 622,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // WITLB
    { 621,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 288,	0,	0|(1ULL<<MCID::Bitcast)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // WFR
    { 620,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // WDTLB
    { 619,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // WAITI
    { 618,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 216,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UTRUNC_S
    { 617,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UN_S
    { 616,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UMUL_AA_LL
    { 615,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UMUL_AA_LH
    { 614,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UMUL_AA_HL
    { 613,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UMUL_AA_HH
    { 612,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ULT_S
    { 611,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ULE_S
    { 610,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 225,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UFLOAT_S
    { 609,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UEQ_S
    { 608,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 216,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_S
    { 607,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SYSCALL
    { 606,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 197,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_S
    { 605,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBX8
    { 604,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBX4
    { 603,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBX2
    { 602,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB
    { 601,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 237,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SSXP
    { 600,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 237,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SSX
    { 599,	1,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 28,	15,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SSR
    { 598,	1,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 28,	15,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SSL
    { 597,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 234,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SSIP
    { 596,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 234,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SSI
    { 595,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SSAI
    { 594,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SSA8L
    { 593,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 194,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SRLI
    { 592,	2,	1,	3,	0,	1,	0,	XtensaOpInfoBase + 187,	15,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SRL
    { 591,	3,	1,	3,	0,	1,	0,	XtensaOpInfoBase + 191,	15,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SRC
    { 590,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 194,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SRAI
    { 589,	2,	1,	3,	0,	1,	0,	XtensaOpInfoBase + 187,	15,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SRA
    { 588,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT0_S
    { 587,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 194,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SLLI
    { 586,	2,	1,	3,	0,	1,	0,	XtensaOpInfoBase + 187,	15,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SLL
    { 585,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 194,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SEXT
    { 584,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SET_BIT_GPIO_OUT
    { 583,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 28,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SDDR32P
    { 582,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 228,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // S8I
    { 581,	3,	0,	2,	0,	0,	0,	XtensaOpInfoBase + 228,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // S32I_N
    { 580,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 228,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // S32I
    { 579,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 194,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // S32E
    { 578,	4,	1,	3,	0,	1,	0,	XtensaOpInfoBase + 284,	14,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // S32C1I
    { 577,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 228,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // S16I
    { 576,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 282,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RUR
    { 575,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RSYNC
    { 574,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 280,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RSR
    { 573,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RSQRT0_S
    { 572,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 34,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RSIL
    { 571,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 216,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROUND_S
    { 570,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROTW
    { 569,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RITLB1
    { 568,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RITLB0
    { 567,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RFWU
    { 566,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RFWO
    { 565,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 278,	0,	0|(1ULL<<MCID::Bitcast)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RFR
    { 564,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RFI
    { 563,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RFE
    { 562,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RFDE
    { 561,	0,	0,	2,	0,	1,	0,	XtensaOpInfoBase + 1,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET_N
    { 560,	0,	0,	2,	0,	1,	0,	XtensaOpInfoBase + 1,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RETW_N
    { 559,	0,	0,	3,	0,	1,	0,	XtensaOpInfoBase + 1,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RETW
    { 558,	0,	0,	3,	0,	1,	0,	XtensaOpInfoBase + 1,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET
    { 557,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REMU
    { 556,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REMS
    { 555,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RECIP0_S
    { 554,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RDTLB1
    { 553,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RDTLB0
    { 552,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // QUOU
    { 551,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // QUOS
    { 550,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PITLB
    { 549,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PDTLB
    { 548,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 202,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ORBC
    { 547,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 202,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ORB
    { 546,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR
    { 545,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OLT_S
    { 544,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OLE_S
    { 543,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 275,	0,	0|(1ULL<<MCID::Compare)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OEQ_S
    { 542,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NSAU
    { 541,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NSA
    { 540,	0,	0,	2,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOP_N
    { 539,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOP
    { 538,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEXP01_S
    { 537,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_S
    { 536,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG
    { 535,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 197,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_S
    { 534,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 268,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_DD_LL
    { 533,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 268,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_DD_LH
    { 532,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 268,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_DD_HL
    { 531,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 268,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_DD_HH
    { 530,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 256,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_DA_LL
    { 529,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 256,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_DA_LH
    { 528,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 256,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_DA_HL
    { 527,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 256,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_DA_HH
    { 526,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 254,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_AD_LL
    { 525,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 254,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_AD_LH
    { 524,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 254,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_AD_HL
    { 523,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 254,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_AD_HH
    { 522,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_AA_LL
    { 521,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_AA_LH
    { 520,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_AA_HL
    { 519,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_AA_HH
    { 518,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULUH
    { 517,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 268,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_DD_LL
    { 516,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 268,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_DD_LH
    { 515,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 268,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_DD_HL
    { 514,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 268,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_DD_HH
    { 513,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 256,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_DA_LL
    { 512,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 256,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_DA_LH
    { 511,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 256,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_DA_HL
    { 510,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 256,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_DA_HH
    { 509,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 254,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_AD_LL
    { 508,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 254,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_AD_LH
    { 507,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 254,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_AD_HL
    { 506,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 254,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_AD_HH
    { 505,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 187,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_AA_LL
    { 504,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 187,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_AA_LH
    { 503,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 187,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_AA_HL
    { 502,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 187,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULS_AA_HH
    { 501,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULSH
    { 500,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULL
    { 499,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 270,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_LL_LDINC
    { 498,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 270,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_LL_LDDEC
    { 497,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 268,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_LL
    { 496,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 270,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_LH_LDINC
    { 495,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 270,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_LH_LDDEC
    { 494,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 268,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_LH
    { 493,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 270,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_HL_LDINC
    { 492,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 270,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_HL_LDDEC
    { 491,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 268,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_HL
    { 490,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 270,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_HH_LDINC
    { 489,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 270,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_HH_LDDEC
    { 488,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 268,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DD_HH
    { 487,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 263,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_LL_LDINC
    { 486,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 258,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_LL_LDDEC
    { 485,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 256,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_LL
    { 484,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 263,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_LH_LDINC
    { 483,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 258,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_LH_LDDEC
    { 482,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 256,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_LH
    { 481,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 263,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_HL_LDINC
    { 480,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 258,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_HL_LDDEC
    { 479,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 256,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_HL
    { 478,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 263,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_HH_LDINC
    { 477,	5,	2,	3,	0,	2,	4,	XtensaOpInfoBase + 258,	8,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_HH_LDDEC
    { 476,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 256,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_DA_HH
    { 475,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 254,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_AD_LL
    { 474,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 254,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_AD_LH
    { 473,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 254,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_AD_HL
    { 472,	2,	0,	3,	0,	2,	4,	XtensaOpInfoBase + 254,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_AD_HH
    { 471,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_AA_LL
    { 470,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_AA_LH
    { 469,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_AA_HL
    { 468,	2,	0,	3,	0,	0,	4,	XtensaOpInfoBase + 187,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULA_AA_HH
    { 467,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL16U
    { 466,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL16S
    { 465,	4,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 240,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MSUB_S
    { 464,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV_S
    { 463,	2,	1,	2,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV_N
    { 462,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVT_S
    { 461,	4,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 247,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVT
    { 460,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSP
    { 459,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 244,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVNEZ_S
    { 458,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVNEZ
    { 457,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 244,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVLTZ_S
    { 456,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVLTZ
    { 455,	2,	1,	2,	0,	0,	0,	XtensaOpInfoBase + 34,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVI_N
    { 454,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 34,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVI
    { 453,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 244,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVGEZ_S
    { 452,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVGEZ
    { 451,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 251,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVF_S
    { 450,	4,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 247,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVF
    { 449,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 244,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVEQZ_S
    { 448,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVEQZ
    { 447,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MKSADJ_S
    { 446,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MKDADJ_S
    { 445,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MINU
    { 444,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN
    { 443,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMW
    { 442,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAXU
    { 441,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX
    { 440,	4,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 240,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MADD_S
    { 439,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 197,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MADDN_S
    { 438,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 237,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSXP
    { 437,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 237,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSX
    { 436,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 234,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSIP
    { 435,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 234,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSI
    { 434,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 211,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOOPNEZ
    { 433,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 211,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOOPGTZ
    { 432,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 211,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOOP
    { 431,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 228,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LEA_ADD
    { 430,	3,	2,	3,	0,	0,	0,	XtensaOpInfoBase + 231,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDINC
    { 429,	1,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 28,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDDR32P
    { 428,	3,	2,	3,	0,	0,	0,	XtensaOpInfoBase + 231,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDDEC
    { 427,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 228,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // L8UI
    { 426,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 211,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // L32R
    { 425,	3,	1,	2,	0,	0,	0,	XtensaOpInfoBase + 228,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // L32I_N
    { 424,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 228,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // L32I
    { 423,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 194,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // L32E
    { 422,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 228,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // L16UI
    { 421,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 228,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // L16SI
    { 420,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // JX
    { 419,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 215,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // J
    { 418,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ISYNC
    { 417,	0,	0,	2,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Trap)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ILL_N
    { 416,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Trap)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ILL
    { 415,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // IITLB
    { 414,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // IDTLB
    { 413,	1,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 28,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GET_GPIO_IN
    { 412,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 216,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_S
    { 411,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 225,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOAT_S
    { 410,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTW
    { 409,	4,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 221,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTUI
    { 408,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXCW
    { 407,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ESYNC
    { 406,	2,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 34,	2,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ENTRY
    { 405,	0,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DSYNC
    { 404,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 197,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIVN_S
    { 403,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV0_S
    { 402,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 219,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_S
    { 401,	1,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CLR_BIT_GPIO_OUT
    { 400,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 194,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CLAMPS
    { 399,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 216,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_S
    { 398,	1,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 28,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLX8
    { 397,	1,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 28,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLX4
    { 396,	1,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 28,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLX12
    { 395,	1,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 28,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLX0
    { 394,	1,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 215,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALL8
    { 393,	1,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 215,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALL4
    { 392,	1,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 215,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALL12
    { 391,	1,	0,	3,	0,	0,	1,	XtensaOpInfoBase + 215,	3,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALL0
    { 390,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 213,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BT
    { 389,	1,	0,	2,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::Trap)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BREAK_N
    { 388,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 9,	0,	0|(1ULL<<MCID::Trap)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BREAK
    { 387,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BNONE
    { 386,	2,	0,	2,	0,	0,	0,	XtensaOpInfoBase + 211,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BNEZ_N
    { 385,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 211,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BNEZ
    { 384,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 208,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BNEI
    { 383,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BNE
    { 382,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BNALL
    { 381,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 211,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BLTZ
    { 380,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 208,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BLTUI
    { 379,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BLTU
    { 378,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 208,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BLTI
    { 377,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BLT
    { 376,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 211,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BGEZ
    { 375,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 208,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BGEUI
    { 374,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BGEU
    { 373,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 208,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BGEI
    { 372,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BGE
    { 371,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 213,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BF
    { 370,	2,	0,	2,	0,	0,	0,	XtensaOpInfoBase + 211,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BEQZ_N
    { 369,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 211,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BEQZ
    { 368,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 208,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BEQI
    { 367,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BEQ
    { 366,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 208,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BBSI
    { 365,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BBS
    { 364,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 208,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BBCI
    { 363,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BBC
    { 362,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BANY
    { 361,	3,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 205,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BALL
    { 360,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 200,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANY8
    { 359,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 200,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANY4
    { 358,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 202,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANDBC
    { 357,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 202,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANDB
    { 356,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND
    { 355,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 200,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ALL8
    { 354,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 200,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ALL4
    { 353,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 197,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_S
    { 352,	3,	1,	2,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_N
    { 351,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDX8
    { 350,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDX4
    { 349,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDX2
    { 348,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 194,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDMI
    { 347,	3,	1,	2,	0,	0,	0,	XtensaOpInfoBase + 194,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDI_N
    { 346,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 194,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDI
    { 345,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDEXP_S
    { 344,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDEXPM_S
    { 343,	3,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 191,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD
    { 342,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 189,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_S
    { 341,	2,	1,	3,	0,	0,	0,	XtensaOpInfoBase + 187,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS
    { 340,	6,	1,	2,	0,	0,	0,	XtensaOpInfoBase + 181,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_CC_INT_FP
    { 339,	7,	1,	2,	0,	0,	0,	XtensaOpInfoBase + 174,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_CC_FP_INT
    { 338,	7,	1,	2,	0,	0,	0,	XtensaOpInfoBase + 167,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_CC_FP_FP
    { 337,	6,	1,	2,	0,	0,	0,	XtensaOpInfoBase + 161,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT
    { 336,	1,	0,	2,	0,	0,	1,	XtensaOpInfoBase + 28,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSP_P
    { 335,	2,	0,	3,	0,	0,	0,	XtensaOpInfoBase + 159,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR_JT
    { 334,	4,	0,	2,	0,	0,	0,	XtensaOpInfoBase + 155,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRCC_FP
    { 333,	4,	1,	2,	0,	0,	0,	XtensaOpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_CMP_SWAP_32_P
    { 332,	2,	0,	2,	0,	1,	1,	XtensaOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKUP
    { 331,	2,	0,	2,	0,	1,	1,	XtensaOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKDOWN
    { 330,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	XtensaOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13931
    { 41,	2,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13930
    { 40,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13929
    { 31,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	XtensaOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	XtensaOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PHI
  }, {
    /* 0 */
    /* 0 */ Xtensa::SP, Xtensa::SP,
    /* 2 */ Xtensa::SP,
    /* 3 */ Xtensa::A0,
    /* 4 */ Xtensa::M1, Xtensa::M2, Xtensa::ACCLO, Xtensa::ACCHI,
    /* 8 */ Xtensa::ACCLO, Xtensa::ACCHI, Xtensa::M1, Xtensa::M2, Xtensa::ACCLO, Xtensa::ACCHI,
    /* 14 */ Xtensa::SCOMPARE1,
    /* 15 */ Xtensa::SAR,
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
    /* 28 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
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
    /* 151 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 155 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 159 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 161 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 167 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 174 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 181 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 187 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 189 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 191 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 194 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 197 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 200 */ { Xtensa::BRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::BRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 202 */ { Xtensa::BRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::BRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::BRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 205 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 208 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 211 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 213 */ { Xtensa::BRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 215 */ { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 216 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 219 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 221 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 225 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 228 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 231 */ { Xtensa::MRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) },
    /* 234 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 237 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 240 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 244 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 247 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::BRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 251 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::BRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 254 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::MR23RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 256 */ { Xtensa::MR01RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 258 */ { Xtensa::MRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { Xtensa::MR01RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 263 */ { Xtensa::MRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { Xtensa::MRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 268 */ { Xtensa::MR01RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::MR23RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 270 */ { Xtensa::MRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) }, { Xtensa::MR01RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::MR23RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 275 */ { Xtensa::BRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 278 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 280 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::SRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 282 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::URRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 284 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 288 */ { Xtensa::FPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 290 */ { Xtensa::SRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 292 */ { Xtensa::URRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 294 */ { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::SRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { Xtensa::ARRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { Xtensa::SRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) },
  }
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char XtensaInstrNameData[] = {
  /* 0 */ "G_FLOG10\000"
  /* 9 */ "G_FEXP10\000"
  /* 18 */ "RDTLB0\000"
  /* 25 */ "RITLB0\000"
  /* 32 */ "CALL0\000"
  /* 38 */ "CALLX0\000"
  /* 45 */ "RDTLB1\000"
  /* 52 */ "RITLB1\000"
  /* 59 */ "CALL12\000"
  /* 66 */ "CALLX12\000"
  /* 74 */ "G_FLOG2\000"
  /* 82 */ "G_FATAN2\000"
  /* 91 */ "G_FEXP2\000"
  /* 99 */ "SUBX2\000"
  /* 105 */ "ADDX2\000"
  /* 111 */ "CALL4\000"
  /* 117 */ "SUBX4\000"
  /* 123 */ "ADDX4\000"
  /* 129 */ "CALLX4\000"
  /* 136 */ "ANY4\000"
  /* 141 */ "CALL8\000"
  /* 147 */ "SUBX8\000"
  /* 153 */ "ADDX8\000"
  /* 159 */ "CALLX8\000"
  /* 166 */ "ANY8\000"
  /* 171 */ "G_FMA\000"
  /* 177 */ "G_STRICT_FMA\000"
  /* 190 */ "SRA\000"
  /* 194 */ "NSA\000"
  /* 198 */ "ANDB\000"
  /* 203 */ "IDTLB\000"
  /* 209 */ "PDTLB\000"
  /* 215 */ "WDTLB\000"
  /* 221 */ "IITLB\000"
  /* 227 */ "PITLB\000"
  /* 233 */ "WITLB\000"
  /* 239 */ "XORB\000"
  /* 244 */ "G_FSUB\000"
  /* 251 */ "G_STRICT_FSUB\000"
  /* 265 */ "G_ATOMICRMW_FSUB\000"
  /* 282 */ "G_SUB\000"
  /* 288 */ "G_ATOMICRMW_SUB\000"
  /* 304 */ "BBC\000"
  /* 308 */ "ANDBC\000"
  /* 314 */ "ORBC\000"
  /* 319 */ "MULA_DA_HH_LDDEC\000"
  /* 336 */ "MULA_DD_HH_LDDEC\000"
  /* 353 */ "MULA_DA_LH_LDDEC\000"
  /* 370 */ "MULA_DD_LH_LDDEC\000"
  /* 387 */ "MULA_DA_HL_LDDEC\000"
  /* 404 */ "MULA_DD_HL_LDDEC\000"
  /* 421 */ "MULA_DA_LL_LDDEC\000"
  /* 438 */ "MULA_DD_LL_LDDEC\000"
  /* 455 */ "G_INTRINSIC\000"
  /* 467 */ "MULA_DA_HH_LDINC\000"
  /* 484 */ "MULA_DD_HH_LDINC\000"
  /* 501 */ "MULA_DA_LH_LDINC\000"
  /* 518 */ "MULA_DD_LH_LDINC\000"
  /* 535 */ "MULA_DA_HL_LDINC\000"
  /* 552 */ "MULA_DD_HL_LDINC\000"
  /* 569 */ "MULA_DA_LL_LDINC\000"
  /* 586 */ "MULA_DD_LL_LDINC\000"
  /* 603 */ "G_FPTRUNC\000"
  /* 613 */ "G_INTRINSIC_TRUNC\000"
  /* 631 */ "G_TRUNC\000"
  /* 639 */ "G_BUILD_VECTOR_TRUNC\000"
  /* 660 */ "DSYNC\000"
  /* 666 */ "ESYNC\000"
  /* 672 */ "ISYNC\000"
  /* 678 */ "RSYNC\000"
  /* 684 */ "G_DYN_STACKALLOC\000"
  /* 701 */ "SRC\000"
  /* 705 */ "G_FMAD\000"
  /* 712 */ "G_FPEXTLOAD\000"
  /* 724 */ "G_INDEXED_SEXTLOAD\000"
  /* 743 */ "G_SEXTLOAD\000"
  /* 754 */ "G_INDEXED_ZEXTLOAD\000"
  /* 773 */ "G_ZEXTLOAD\000"
  /* 784 */ "G_INDEXED_LOAD\000"
  /* 799 */ "G_LOAD\000"
  /* 806 */ "G_VECREDUCE_FADD\000"
  /* 823 */ "G_FADD\000"
  /* 830 */ "G_VECREDUCE_SEQ_FADD\000"
  /* 851 */ "G_STRICT_FADD\000"
  /* 865 */ "G_ATOMICRMW_FADD\000"
  /* 882 */ "LEA_ADD\000"
  /* 890 */ "G_VECREDUCE_ADD\000"
  /* 906 */ "G_ADD\000"
  /* 912 */ "G_PTR_ADD\000"
  /* 922 */ "G_ATOMICRMW_ADD\000"
  /* 938 */ "G_ATOMICRMW_NAND\000"
  /* 955 */ "G_VECREDUCE_AND\000"
  /* 971 */ "G_AND\000"
  /* 977 */ "G_ATOMICRMW_AND\000"
  /* 993 */ "LIFETIME_END\000"
  /* 1006 */ "G_BRCOND\000"
  /* 1015 */ "G_ATOMICRMW_USUB_COND\000"
  /* 1037 */ "G_LLROUND\000"
  /* 1047 */ "G_LROUND\000"
  /* 1056 */ "G_INTRINSIC_ROUND\000"
  /* 1074 */ "G_INTRINSIC_FPTRUNC_ROUND\000"
  /* 1100 */ "LOAD_STACK_GUARD\000"
  /* 1117 */ "L32E\000"
  /* 1122 */ "S32E\000"
  /* 1127 */ "PSEUDO_PROBE\000"
  /* 1140 */ "G_SSUBE\000"
  /* 1148 */ "G_USUBE\000"
  /* 1156 */ "G_FENCE\000"
  /* 1164 */ "ARITH_FENCE\000"
  /* 1176 */ "REG_SEQUENCE\000"
  /* 1189 */ "G_SADDE\000"
  /* 1197 */ "G_UADDE\000"
  /* 1205 */ "RFDE\000"
  /* 1210 */ "G_GET_FPMODE\000"
  /* 1223 */ "G_RESET_FPMODE\000"
  /* 1238 */ "G_SET_FPMODE\000"
  /* 1251 */ "G_FMINNUM_IEEE\000"
  /* 1266 */ "G_FMAXNUM_IEEE\000"
  /* 1281 */ "RFE\000"
  /* 1285 */ "BGE\000"
  /* 1289 */ "G_VSCALE\000"
  /* 1298 */ "G_JUMP_TABLE\000"
  /* 1311 */ "BUNDLE\000"
  /* 1318 */ "BNE\000"
  /* 1322 */ "G_MEMSET_INLINE\000"
  /* 1338 */ "G_MEMCPY_INLINE\000"
  /* 1354 */ "BNONE\000"
  /* 1360 */ "RELOC_NONE\000"
  /* 1371 */ "LOCAL_ESCAPE\000"
  /* 1384 */ "G_FPTRUNCSTORE\000"
  /* 1399 */ "G_STACKRESTORE\000"
  /* 1414 */ "G_INDEXED_STORE\000"
  /* 1430 */ "G_STORE\000"
  /* 1438 */ "G_BITREVERSE\000"
  /* 1451 */ "FAKE_USE\000"
  /* 1460 */ "DBG_VALUE\000"
  /* 1470 */ "G_GLOBAL_VALUE\000"
  /* 1485 */ "G_PTRAUTH_GLOBAL_VALUE\000"
  /* 1508 */ "CONVERGENCECTRL_GLUE\000"
  /* 1529 */ "G_STACKSAVE\000"
  /* 1541 */ "G_MEMMOVE\000"
  /* 1551 */ "G_FREEZE\000"
  /* 1560 */ "G_FCANONICALIZE\000"
  /* 1576 */ "BF\000"
  /* 1579 */ "G_FMODF\000"
  /* 1587 */ "INIT_UNDEF\000"
  /* 1598 */ "G_IMPLICIT_DEF\000"
  /* 1613 */ "DBG_INSTR_REF\000"
  /* 1627 */ "MOVF\000"
  /* 1632 */ "G_FNEG\000"
  /* 1639 */ "EXTRACT_SUBREG\000"
  /* 1654 */ "INSERT_SUBREG\000"
  /* 1668 */ "G_SEXT_INREG\000"
  /* 1681 */ "SUBREG_TO_REG\000"
  /* 1695 */ "G_ATOMIC_CMPXCHG\000"
  /* 1712 */ "G_ATOMICRMW_XCHG\000"
  /* 1729 */ "G_GET_ROUNDING\000"
  /* 1744 */ "G_SET_ROUNDING\000"
  /* 1759 */ "G_FLOG\000"
  /* 1766 */ "G_VAARG\000"
  /* 1774 */ "PREALLOCATED_ARG\000"
  /* 1791 */ "G_PREFETCH\000"
  /* 1802 */ "MULA_AA_HH\000"
  /* 1813 */ "UMUL_AA_HH\000"
  /* 1824 */ "MULS_AA_HH\000"
  /* 1835 */ "MULA_DA_HH\000"
  /* 1846 */ "MUL_DA_HH\000"
  /* 1856 */ "MULS_DA_HH\000"
  /* 1867 */ "MULA_AD_HH\000"
  /* 1878 */ "MUL_AD_HH\000"
  /* 1888 */ "MULS_AD_HH\000"
  /* 1899 */ "MULA_DD_HH\000"
  /* 1910 */ "MUL_DD_HH\000"
  /* 1920 */ "MULS_DD_HH\000"
  /* 1931 */ "G_SMULH\000"
  /* 1939 */ "G_UMULH\000"
  /* 1947 */ "MULA_AA_LH\000"
  /* 1958 */ "UMUL_AA_LH\000"
  /* 1969 */ "MULS_AA_LH\000"
  /* 1980 */ "MULA_DA_LH\000"
  /* 1991 */ "MUL_DA_LH\000"
  /* 2001 */ "MULS_DA_LH\000"
  /* 2012 */ "MULA_AD_LH\000"
  /* 2023 */ "MUL_AD_LH\000"
  /* 2033 */ "MULS_AD_LH\000"
  /* 2044 */ "MULA_DD_LH\000"
  /* 2055 */ "MUL_DD_LH\000"
  /* 2065 */ "MULS_DD_LH\000"
  /* 2076 */ "G_FTANH\000"
  /* 2084 */ "G_FSINH\000"
  /* 2092 */ "MULSH\000"
  /* 2098 */ "G_FCOSH\000"
  /* 2106 */ "MULUH\000"
  /* 2112 */ "S32C1I\000"
  /* 2119 */ "L32I\000"
  /* 2124 */ "S32I\000"
  /* 2129 */ "S16I\000"
  /* 2134 */ "S8I\000"
  /* 2138 */ "SRAI\000"
  /* 2143 */ "SSAI\000"
  /* 2148 */ "BBCI\000"
  /* 2153 */ "ADDI\000"
  /* 2158 */ "BGEI\000"
  /* 2163 */ "BNEI\000"
  /* 2168 */ "RFI\000"
  /* 2172 */ "DBG_PHI\000"
  /* 2180 */ "SLLI\000"
  /* 2185 */ "SRLI\000"
  /* 2190 */ "ADDMI\000"
  /* 2196 */ "BEQI\000"
  /* 2201 */ "L16SI\000"
  /* 2207 */ "BBSI\000"
  /* 2212 */ "LSI\000"
  /* 2216 */ "G_FPTOSI\000"
  /* 2225 */ "SSI\000"
  /* 2229 */ "WAITI\000"
  /* 2235 */ "BLTI\000"
  /* 2240 */ "L16UI\000"
  /* 2246 */ "L8UI\000"
  /* 2251 */ "BGEUI\000"
  /* 2257 */ "G_FPTOUI\000"
  /* 2266 */ "BLTUI\000"
  /* 2272 */ "EXTUI\000"
  /* 2278 */ "MOVI\000"
  /* 2283 */ "G_FPOWI\000"
  /* 2291 */ "J\000"
  /* 2293 */ "BREAK\000"
  /* 2299 */ "COPY_LANEMASK\000"
  /* 2313 */ "G_PTRMASK\000"
  /* 2323 */ "SSA8L\000"
  /* 2329 */ "GC_LABEL\000"
  /* 2338 */ "DBG_LABEL\000"
  /* 2348 */ "EH_LABEL\000"
  /* 2357 */ "ANNOTATION_LABEL\000"
  /* 2374 */ "ICALL_BRANCH_FUNNEL\000"
  /* 2394 */ "G_FSHL\000"
  /* 2401 */ "G_SHL\000"
  /* 2407 */ "MULA_AA_HL\000"
  /* 2418 */ "UMUL_AA_HL\000"
  /* 2429 */ "MULS_AA_HL\000"
  /* 2440 */ "MULA_DA_HL\000"
  /* 2451 */ "MUL_DA_HL\000"
  /* 2461 */ "MULS_DA_HL\000"
  /* 2472 */ "MULA_AD_HL\000"
  /* 2483 */ "MUL_AD_HL\000"
  /* 2493 */ "MULS_AD_HL\000"
  /* 2504 */ "MULA_DD_HL\000"
  /* 2515 */ "MUL_DD_HL\000"
  /* 2525 */ "MULS_DD_HL\000"
  /* 2536 */ "G_FCEIL\000"
  /* 2544 */ "G_SAVGCEIL\000"
  /* 2555 */ "G_UAVGCEIL\000"
  /* 2566 */ "RSIL\000"
  /* 2571 */ "BALL\000"
  /* 2576 */ "SYSCALL\000"
  /* 2584 */ "PATCHABLE_TAIL_CALL\000"
  /* 2604 */ "PATCHABLE_TYPED_EVENT_CALL\000"
  /* 2631 */ "PATCHABLE_EVENT_CALL\000"
  /* 2652 */ "FENTRY_CALL\000"
  /* 2664 */ "BNALL\000"
  /* 2670 */ "KILL\000"
  /* 2675 */ "SLL\000"
  /* 2679 */ "MULL\000"
  /* 2684 */ "MULA_AA_LL\000"
  /* 2695 */ "UMUL_AA_LL\000"
  /* 2706 */ "MULS_AA_LL\000"
  /* 2717 */ "MULA_DA_LL\000"
  /* 2728 */ "MUL_DA_LL\000"
  /* 2738 */ "MULS_DA_LL\000"
  /* 2749 */ "MULA_AD_LL\000"
  /* 2760 */ "MUL_AD_LL\000"
  /* 2770 */ "MULS_AD_LL\000"
  /* 2781 */ "MULA_DD_LL\000"
  /* 2792 */ "MUL_DD_LL\000"
  /* 2802 */ "MULS_DD_LL\000"
  /* 2813 */ "G_CONSTANT_POOL\000"
  /* 2829 */ "SRL\000"
  /* 2833 */ "SSL\000"
  /* 2837 */ "G_ROTL\000"
  /* 2844 */ "G_VECREDUCE_FMUL\000"
  /* 2861 */ "G_FMUL\000"
  /* 2868 */ "G_VECREDUCE_SEQ_FMUL\000"
  /* 2889 */ "G_STRICT_FMUL\000"
  /* 2903 */ "G_CLMUL\000"
  /* 2911 */ "G_VECREDUCE_MUL\000"
  /* 2927 */ "G_MUL\000"
  /* 2933 */ "G_FREM\000"
  /* 2940 */ "G_STRICT_FREM\000"
  /* 2954 */ "G_SREM\000"
  /* 2961 */ "G_UREM\000"
  /* 2968 */ "G_SDIVREM\000"
  /* 2978 */ "G_UDIVREM\000"
  /* 2988 */ "INLINEASM\000"
  /* 2998 */ "G_VECREDUCE_FMINIMUM\000"
  /* 3019 */ "G_FMINIMUM\000"
  /* 3030 */ "G_ATOMICRMW_FMINIMUM\000"
  /* 3051 */ "G_VECREDUCE_FMAXIMUM\000"
  /* 3072 */ "G_FMAXIMUM\000"
  /* 3083 */ "G_ATOMICRMW_FMAXIMUM\000"
  /* 3104 */ "G_FMINIMUMNUM\000"
  /* 3118 */ "G_ATOMICRMW_FMINIMUMNUM\000"
  /* 3142 */ "G_FMAXIMUMNUM\000"
  /* 3156 */ "G_ATOMICRMW_FMAXIMUMNUM\000"
  /* 3180 */ "G_FMINNUM\000"
  /* 3190 */ "G_FMAXNUM\000"
  /* 3200 */ "G_FATAN\000"
  /* 3208 */ "G_FTAN\000"
  /* 3215 */ "G_INTRINSIC_ROUNDEVEN\000"
  /* 3237 */ "G_ASSERT_ALIGN\000"
  /* 3252 */ "G_FCOPYSIGN\000"
  /* 3264 */ "G_VECREDUCE_FMIN\000"
  /* 3281 */ "G_ATOMICRMW_FMIN\000"
  /* 3298 */ "G_VECREDUCE_SMIN\000"
  /* 3315 */ "G_SMIN\000"
  /* 3322 */ "G_VECREDUCE_UMIN\000"
  /* 3339 */ "G_UMIN\000"
  /* 3346 */ "G_ATOMICRMW_UMIN\000"
  /* 3363 */ "G_ATOMICRMW_MIN\000"
  /* 3379 */ "G_FASIN\000"
  /* 3387 */ "G_FSIN\000"
  /* 3394 */ "GET_GPIO_IN\000"
  /* 3406 */ "CFI_INSTRUCTION\000"
  /* 3422 */ "G_CTLZ_ZERO_POISON\000"
  /* 3441 */ "G_CTTZ_ZERO_POISON\000"
  /* 3460 */ "ADJCALLSTACKDOWN\000"
  /* 3477 */ "ADD_N\000"
  /* 3483 */ "L32I_N\000"
  /* 3490 */ "S32I_N\000"
  /* 3497 */ "ADDI_N\000"
  /* 3504 */ "MOVI_N\000"
  /* 3511 */ "BREAK_N\000"
  /* 3519 */ "ILL_N\000"
  /* 3525 */ "NOP_N\000"
  /* 3531 */ "RET_N\000"
  /* 3537 */ "MOV_N\000"
  /* 3543 */ "RETW_N\000"
  /* 3550 */ "BNEZ_N\000"
  /* 3557 */ "BEQZ_N\000"
  /* 3564 */ "G_SSUBO\000"
  /* 3572 */ "G_USUBO\000"
  /* 3580 */ "G_SADDO\000"
  /* 3588 */ "G_UADDO\000"
  /* 3596 */ "JUMP_TABLE_DEBUG_INFO\000"
  /* 3618 */ "G_SMULO\000"
  /* 3626 */ "G_UMULO\000"
  /* 3634 */ "G_BZERO\000"
  /* 3642 */ "RFWO\000"
  /* 3647 */ "LDDR32P\000"
  /* 3655 */ "SDDR32P\000"
  /* 3663 */ "STACKMAP\000"
  /* 3672 */ "G_DEBUGTRAP\000"
  /* 3684 */ "G_UBSANTRAP\000"
  /* 3696 */ "G_TRAP\000"
  /* 3703 */ "G_ATOMICRMW_UDEC_WRAP\000"
  /* 3725 */ "G_ATOMICRMW_UINC_WRAP\000"
  /* 3747 */ "G_BSWAP\000"
  /* 3755 */ "G_SITOFP\000"
  /* 3764 */ "G_UITOFP\000"
  /* 3773 */ "BRCC_FP\000"
  /* 3781 */ "SELECT_CC_FP_FP\000"
  /* 3797 */ "SELECT_CC_INT_FP\000"
  /* 3814 */ "LSIP\000"
  /* 3819 */ "SSIP\000"
  /* 3824 */ "G_FCMP\000"
  /* 3831 */ "G_STRICT_FCMP\000"
  /* 3845 */ "G_ICMP\000"
  /* 3852 */ "G_SCMP\000"
  /* 3859 */ "G_UCMP\000"
  /* 3866 */ "NOP\000"
  /* 3870 */ "CONVERGENCECTRL_LOOP\000"
  /* 3891 */ "G_CTPOP\000"
  /* 3899 */ "PATCHABLE_OP\000"
  /* 3912 */ "FAULTING_OP\000"
  /* 3924 */ "MOVSP\000"
  /* 3930 */ "ADJCALLSTACKUP\000"
  /* 3945 */ "PREALLOCATED_SETUP\000"
  /* 3964 */ "G_FLDEXP\000"
  /* 3973 */ "G_STRICT_FLDEXP\000"
  /* 3989 */ "G_FEXP\000"
  /* 3996 */ "G_FFREXP\000"
  /* 4005 */ "LSXP\000"
  /* 4010 */ "SSXP\000"
  /* 4015 */ "ATOMIC_CMP_SWAP_32_P\000"
  /* 4036 */ "MOVSP_P\000"
  /* 4044 */ "BEQ\000"
  /* 4048 */ "L32R\000"
  /* 4053 */ "G_BR\000"
  /* 4058 */ "INLINEASM_BR\000"
  /* 4071 */ "G_BLOCK_ADDR\000"
  /* 4084 */ "MEMBARRIER\000"
  /* 4095 */ "G_CONSTANT_FOLD_BARRIER\000"
  /* 4119 */ "PATCHABLE_FUNCTION_ENTER\000"
  /* 4144 */ "G_READCYCLECOUNTER\000"
  /* 4163 */ "G_READSTEADYCOUNTER\000"
  /* 4183 */ "G_READ_REGISTER\000"
  /* 4199 */ "G_WRITE_REGISTER\000"
  /* 4216 */ "RFR\000"
  /* 4220 */ "WFR\000"
  /* 4224 */ "G_ASHR\000"
  /* 4231 */ "G_FSHR\000"
  /* 4238 */ "G_LSHR\000"
  /* 4245 */ "CONVERGENCECTRL_ANCHOR\000"
  /* 4268 */ "G_FFLOOR\000"
  /* 4277 */ "G_SAVGFLOOR\000"
  /* 4289 */ "G_UAVGFLOOR\000"
  /* 4301 */ "G_EXTRACT_SUBVECTOR\000"
  /* 4321 */ "G_INSERT_SUBVECTOR\000"
  /* 4340 */ "G_BUILD_VECTOR\000"
  /* 4355 */ "G_SHUFFLE_VECTOR\000"
  /* 4372 */ "G_STEP_VECTOR\000"
  /* 4386 */ "G_SPLAT_VECTOR\000"
  /* 4401 */ "G_VECREDUCE_XOR\000"
  /* 4417 */ "G_XOR\000"
  /* 4423 */ "G_ATOMICRMW_XOR\000"
  /* 4439 */ "G_VECREDUCE_OR\000"
  /* 4454 */ "G_OR\000"
  /* 4459 */ "G_ATOMICRMW_OR\000"
  /* 4474 */ "RSR\000"
  /* 4478 */ "SSR\000"
  /* 4482 */ "WSR\000"
  /* 4486 */ "XSR\000"
  /* 4490 */ "G_ROTR\000"
  /* 4497 */ "G_INTTOPTR\000"
  /* 4508 */ "RUR\000"
  /* 4512 */ "WUR\000"
  /* 4516 */ "MUL16S\000"
  /* 4523 */ "G_FABS\000"
  /* 4530 */ "G_ABS\000"
  /* 4536 */ "BBS\000"
  /* 4540 */ "G_ABDS\000"
  /* 4547 */ "G_UNMERGE_VALUES\000"
  /* 4564 */ "G_MERGE_VALUES\000"
  /* 4579 */ "G_CTLS\000"
  /* 4586 */ "REMS\000"
  /* 4591 */ "G_FACOS\000"
  /* 4599 */ "G_FCOS\000"
  /* 4606 */ "G_FSINCOS\000"
  /* 4616 */ "QUOS\000"
  /* 4621 */ "CLAMPS\000"
  /* 4628 */ "G_STRICT_FCMPS\000"
  /* 4643 */ "G_CONCAT_VECTORS\000"
  /* 4660 */ "COPY_TO_REGCLASS\000"
  /* 4677 */ "G_IS_FPCLASS\000"
  /* 4690 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\000"
  /* 4720 */ "G_VECTOR_COMPRESS\000"
  /* 4738 */ "G_INTRINSIC_W_SIDE_EFFECTS\000"
  /* 4765 */ "G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS\000"
  /* 4803 */ "RECIP0_S\000"
  /* 4812 */ "RSQRT0_S\000"
  /* 4821 */ "DIV0_S\000"
  /* 4828 */ "NEXP01_S\000"
  /* 4837 */ "MSUB_S\000"
  /* 4844 */ "UTRUNC_S\000"
  /* 4853 */ "MADD_S\000"
  /* 4860 */ "ROUND_S\000"
  /* 4868 */ "OLE_S\000"
  /* 4874 */ "ULE_S\000"
  /* 4880 */ "MOVF_S\000"
  /* 4887 */ "NEG_S\000"
  /* 4893 */ "MKDADJ_S\000"
  /* 4902 */ "MKSADJ_S\000"
  /* 4911 */ "CEIL_S\000"
  /* 4918 */ "MUL_S\000"
  /* 4924 */ "ADDEXPM_S\000"
  /* 4934 */ "MADDN_S\000"
  /* 4942 */ "UN_S\000"
  /* 4947 */ "DIVN_S\000"
  /* 4954 */ "ADDEXP_S\000"
  /* 4963 */ "OEQ_S\000"
  /* 4969 */ "UEQ_S\000"
  /* 4975 */ "FLOOR_S\000"
  /* 4983 */ "ABS_S\000"
  /* 4989 */ "UFLOAT_S\000"
  /* 4998 */ "G_TRUNC_SSAT_S\000"
  /* 5013 */ "OLT_S\000"
  /* 5019 */ "ULT_S\000"
  /* 5025 */ "CONST_S\000"
  /* 5033 */ "MOVT_S\000"
  /* 5040 */ "MOV_S\000"
  /* 5046 */ "MOVGEZ_S\000"
  /* 5055 */ "MOVNEZ_S\000"
  /* 5064 */ "MOVEQZ_S\000"
  /* 5073 */ "MOVLTZ_S\000"
  /* 5082 */ "G_SSUBSAT\000"
  /* 5092 */ "G_USUBSAT\000"
  /* 5102 */ "G_SADDSAT\000"
  /* 5112 */ "G_UADDSAT\000"
  /* 5122 */ "G_SSHLSAT\000"
  /* 5132 */ "G_USHLSAT\000"
  /* 5142 */ "G_SMULFIXSAT\000"
  /* 5155 */ "G_UMULFIXSAT\000"
  /* 5168 */ "G_SDIVFIXSAT\000"
  /* 5181 */ "G_UDIVFIXSAT\000"
  /* 5194 */ "G_ATOMICRMW_USUB_SAT\000"
  /* 5215 */ "G_FPTOSI_SAT\000"
  /* 5228 */ "G_FPTOUI_SAT\000"
  /* 5241 */ "BT\000"
  /* 5244 */ "G_EXTRACT\000"
  /* 5254 */ "G_SELECT\000"
  /* 5263 */ "G_BRINDIRECT\000"
  /* 5276 */ "PATCHABLE_RET\000"
  /* 5290 */ "G_MEMSET\000"
  /* 5299 */ "PATCHABLE_FUNCTION_EXIT\000"
  /* 5323 */ "G_BRJT\000"
  /* 5330 */ "BR_JT\000"
  /* 5336 */ "BLT\000"
  /* 5340 */ "G_EXTRACT_VECTOR_ELT\000"
  /* 5361 */ "G_INSERT_VECTOR_ELT\000"
  /* 5381 */ "G_FCONSTANT\000"
  /* 5393 */ "G_CONSTANT\000"
  /* 5404 */ "G_INTRINSIC_CONVERGENT\000"
  /* 5427 */ "STATEPOINT\000"
  /* 5438 */ "PATCHPOINT\000"
  /* 5449 */ "G_PTRTOINT\000"
  /* 5460 */ "G_FRINT\000"
  /* 5468 */ "G_INTRINSIC_LLRINT\000"
  /* 5487 */ "G_INTRINSIC_LRINT\000"
  /* 5505 */ "G_FNEARBYINT\000"
  /* 5518 */ "SELECT_CC_FP_INT\000"
  /* 5535 */ "G_VASTART\000"
  /* 5545 */ "LIFETIME_START\000"
  /* 5560 */ "G_INVOKE_REGION_START\000"
  /* 5582 */ "G_INSERT\000"
  /* 5591 */ "G_FSQRT\000"
  /* 5599 */ "G_STRICT_FSQRT\000"
  /* 5614 */ "G_BITCAST\000"
  /* 5624 */ "G_ADDRSPACE_CAST\000"
  /* 5641 */ "DBG_VALUE_LIST\000"
  /* 5656 */ "WR_MASK_GPIO_OUT\000"
  /* 5673 */ "CLR_BIT_GPIO_OUT\000"
  /* 5690 */ "SET_BIT_GPIO_OUT\000"
  /* 5707 */ "MOVT\000"
  /* 5712 */ "G_FPEXT\000"
  /* 5720 */ "G_SEXT\000"
  /* 5727 */ "G_ASSERT_SEXT\000"
  /* 5741 */ "G_ANYEXT\000"
  /* 5750 */ "G_ZEXT\000"
  /* 5757 */ "G_ASSERT_ZEXT\000"
  /* 5771 */ "MUL16U\000"
  /* 5778 */ "NSAU\000"
  /* 5783 */ "G_ABDU\000"
  /* 5790 */ "BGEU\000"
  /* 5795 */ "REMU\000"
  /* 5800 */ "MINU\000"
  /* 5805 */ "QUOU\000"
  /* 5810 */ "BLTU\000"
  /* 5815 */ "RFWU\000"
  /* 5820 */ "MAXU\000"
  /* 5825 */ "G_TRUNC_SSAT_U\000"
  /* 5840 */ "G_TRUNC_USAT_U\000"
  /* 5855 */ "G_FDIV\000"
  /* 5862 */ "G_STRICT_FDIV\000"
  /* 5876 */ "G_SDIV\000"
  /* 5883 */ "G_UDIV\000"
  /* 5890 */ "G_GET_FPENV\000"
  /* 5902 */ "G_RESET_FPENV\000"
  /* 5916 */ "G_SET_FPENV\000"
  /* 5928 */ "EXCW\000"
  /* 5933 */ "MEMW\000"
  /* 5938 */ "G_FPOW\000"
  /* 5945 */ "RETW\000"
  /* 5950 */ "ROTW\000"
  /* 5955 */ "EXTW\000"
  /* 5960 */ "G_VECREDUCE_FMAX\000"
  /* 5977 */ "G_ATOMICRMW_FMAX\000"
  /* 5994 */ "G_VECREDUCE_SMAX\000"
  /* 6011 */ "G_SMAX\000"
  /* 6018 */ "G_VECREDUCE_UMAX\000"
  /* 6035 */ "G_UMAX\000"
  /* 6042 */ "G_ATOMICRMW_UMAX\000"
  /* 6059 */ "G_ATOMICRMW_MAX\000"
  /* 6075 */ "G_FRAME_INDEX\000"
  /* 6089 */ "G_SBFX\000"
  /* 6096 */ "G_UBFX\000"
  /* 6103 */ "G_SMULFIX\000"
  /* 6113 */ "G_UMULFIX\000"
  /* 6123 */ "G_SDIVFIX\000"
  /* 6133 */ "G_UDIVFIX\000"
  /* 6143 */ "JX\000"
  /* 6146 */ "LSX\000"
  /* 6150 */ "SSX\000"
  /* 6154 */ "BANY\000"
  /* 6159 */ "G_MEMCPY\000"
  /* 6168 */ "COPY\000"
  /* 6173 */ "CONVERGENCECTRL_ENTRY\000"
  /* 6195 */ "BGEZ\000"
  /* 6200 */ "MOVGEZ\000"
  /* 6207 */ "BNEZ\000"
  /* 6212 */ "LOOPNEZ\000"
  /* 6220 */ "MOVNEZ\000"
  /* 6227 */ "G_CTLZ\000"
  /* 6234 */ "BEQZ\000"
  /* 6239 */ "MOVEQZ\000"
  /* 6246 */ "LOOPGTZ\000"
  /* 6254 */ "BLTZ\000"
  /* 6259 */ "MOVLTZ\000"
  /* 6266 */ "G_CTTZ\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned XtensaInstrNameIndices[] = {
    2176U, 2988U, 4058U, 3406U, 2348U, 2329U, 2357U, 2670U, 
    1639U, 1654U, 1600U, 1587U, 1681U, 4660U, 1460U, 5641U, 
    1613U, 2172U, 2338U, 1176U, 6168U, 2299U, 1311U, 5545U, 
    993U, 1127U, 1164U, 3663U, 2652U, 5438U, 1100U, 3945U, 
    1774U, 5427U, 1371U, 3912U, 3899U, 4119U, 5276U, 5299U, 
    2584U, 2631U, 2604U, 2374U, 1451U, 4084U, 3596U, 1360U, 
    6173U, 4245U, 3870U, 1508U, 5727U, 5757U, 3237U, 906U, 
    282U, 2927U, 5876U, 5883U, 2954U, 2961U, 2968U, 2978U, 
    971U, 4454U, 4417U, 4540U, 5783U, 4289U, 2555U, 4277U, 
    2544U, 1598U, 2174U, 6075U, 1470U, 1485U, 2813U, 5244U, 
    4547U, 5582U, 4564U, 4340U, 639U, 4643U, 5449U, 4497U, 
    5614U, 1551U, 4095U, 1074U, 613U, 1056U, 5487U, 5468U, 
    3215U, 4144U, 4163U, 799U, 743U, 773U, 712U, 784U, 
    724U, 754U, 1430U, 1384U, 1414U, 4690U, 1695U, 1712U, 
    922U, 288U, 977U, 938U, 4459U, 4423U, 6059U, 3363U, 
    6042U, 3346U, 865U, 265U, 5977U, 3281U, 3083U, 3030U, 
    3156U, 3118U, 3725U, 3703U, 1015U, 5194U, 1156U, 1791U, 
    1006U, 5263U, 5560U, 455U, 4738U, 5404U, 4765U, 5741U, 
    631U, 4998U, 5825U, 5840U, 5393U, 5381U, 5535U, 1766U, 
    5720U, 1668U, 5750U, 2401U, 4238U, 4224U, 2394U, 4231U, 
    4490U, 2837U, 3845U, 3824U, 3852U, 3859U, 5254U, 3588U, 
    1197U, 3572U, 1148U, 3580U, 1189U, 3564U, 1140U, 3626U, 
    3618U, 1939U, 1931U, 5112U, 5102U, 5092U, 5082U, 5132U, 
    5122U, 6103U, 6113U, 5142U, 5155U, 6123U, 6133U, 5168U, 
    5181U, 823U, 244U, 2861U, 171U, 705U, 5855U, 2933U, 
    1579U, 5938U, 2283U, 3989U, 91U, 9U, 1759U, 74U, 
    0U, 3964U, 3996U, 1632U, 5712U, 603U, 2216U, 2257U, 
    3755U, 3764U, 5215U, 5228U, 4523U, 3252U, 4677U, 1560U, 
    3180U, 3190U, 1251U, 1266U, 3019U, 3072U, 3104U, 3142U, 
    5890U, 5916U, 5902U, 1210U, 1238U, 1223U, 1729U, 1744U, 
    912U, 2313U, 3315U, 6011U, 3339U, 6035U, 4530U, 1047U, 
    1037U, 4053U, 5323U, 1289U, 4321U, 4301U, 5361U, 5340U, 
    4355U, 4386U, 4372U, 4720U, 6266U, 3441U, 6227U, 3422U, 
    4579U, 3891U, 3747U, 1438U, 2903U, 2536U, 4599U, 3387U, 
    4606U, 3208U, 4591U, 3379U, 3200U, 82U, 2098U, 2084U, 
    2076U, 5591U, 4268U, 5460U, 5505U, 5624U, 4071U, 1298U, 
    684U, 1529U, 1399U, 851U, 251U, 2889U, 5862U, 2940U, 
    177U, 5599U, 3973U, 3831U, 4628U, 4183U, 4199U, 6159U, 
    1338U, 1541U, 5290U, 3634U, 1322U, 3696U, 3672U, 3684U, 
    830U, 2868U, 806U, 2844U, 5960U, 3264U, 3051U, 2998U, 
    890U, 2911U, 955U, 4439U, 4401U, 5994U, 3298U, 6018U, 
    3322U, 6089U, 6096U, 3460U, 3930U, 4015U, 3773U, 5330U, 
    4036U, 5256U, 3781U, 5518U, 3797U, 4526U, 4983U, 819U, 
    4924U, 4954U, 2153U, 3497U, 2190U, 105U, 123U, 153U, 
    3477U, 4854U, 112U, 142U, 951U, 198U, 308U, 136U, 
    166U, 2571U, 6154U, 304U, 2148U, 4536U, 2207U, 4044U, 
    2196U, 6234U, 3557U, 1576U, 1285U, 2158U, 5790U, 2251U, 
    6195U, 5336U, 2235U, 5810U, 2266U, 6254U, 2664U, 1318U, 
    2163U, 6207U, 3550U, 1354U, 2293U, 3511U, 5241U, 32U, 
    59U, 111U, 141U, 38U, 66U, 129U, 159U, 4911U, 
    4621U, 5673U, 5025U, 4821U, 4947U, 660U, 6189U, 666U, 
    5928U, 2272U, 5955U, 4990U, 4975U, 3394U, 203U, 221U, 
    2671U, 3519U, 672U, 2291U, 6143U, 2201U, 2240U, 1117U, 
    2119U, 3483U, 4048U, 2246U, 330U, 3647U, 478U, 882U, 
    3886U, 6246U, 6212U, 2212U, 3814U, 6146U, 4005U, 4934U, 
    4853U, 5973U, 5820U, 5933U, 3277U, 5800U, 4893U, 4902U, 
    6239U, 5064U, 1627U, 4880U, 6200U, 5046U, 2278U, 3504U, 
    6259U, 5073U, 6220U, 5055U, 3924U, 5707U, 5033U, 3537U, 
    5040U, 4837U, 4516U, 5771U, 1802U, 2407U, 1947U, 2684U, 
    1867U, 2472U, 2012U, 2749U, 1835U, 319U, 467U, 2440U, 
    387U, 535U, 1980U, 353U, 501U, 2717U, 421U, 569U, 
    1899U, 336U, 484U, 2504U, 404U, 552U, 2044U, 370U, 
    518U, 2781U, 438U, 586U, 2679U, 2092U, 1824U, 2429U, 
    1969U, 2706U, 1888U, 2493U, 2033U, 2770U, 1856U, 2461U, 
    2001U, 2738U, 1920U, 2525U, 2065U, 2802U, 2106U, 1814U, 
    2419U, 1959U, 2696U, 1878U, 2483U, 2023U, 2760U, 1846U, 
    2451U, 1991U, 2728U, 1910U, 2515U, 2055U, 2792U, 4918U, 
    1635U, 4887U, 4828U, 3866U, 3525U, 194U, 5778U, 4963U, 
    4868U, 5013U, 4265U, 240U, 314U, 209U, 227U, 4616U, 
    5805U, 18U, 45U, 4803U, 4586U, 5795U, 5286U, 5945U, 
    3543U, 3531U, 1205U, 1281U, 2168U, 4216U, 3642U, 5815U, 
    25U, 52U, 5950U, 4860U, 2566U, 4812U, 4474U, 678U, 
    4508U, 2129U, 2112U, 1122U, 2124U, 3490U, 2134U, 3655U, 
    5690U, 5722U, 2675U, 2180U, 4813U, 190U, 2138U, 701U, 
    2829U, 2185U, 2323U, 2143U, 2225U, 3819U, 2833U, 4478U, 
    6150U, 4010U, 247U, 99U, 117U, 147U, 4838U, 2576U, 
    4845U, 4969U, 4989U, 4874U, 5019U, 1813U, 2418U, 1958U, 
    2695U, 4942U, 4844U, 2229U, 215U, 4220U, 233U, 5656U, 
    4482U, 4512U, 4413U, 239U, 4486U, 
};

static inline void InitXtensaMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(XtensaDescs.Insts, XtensaInstrNameIndices, XtensaInstrNameData, nullptr, nullptr, 629, nullptr, 0);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct XtensaGenInstrInfo : public TargetInstrInfo {
  explicit XtensaGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~XtensaGenInstrInfo() override = default;
};

} // namespace llvm_ks

namespace llvm_ks::Xtensa {


} // namespace llvm_ks::Xtensa

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

extern const XtensaInstrTable XtensaDescs;
extern const unsigned XtensaInstrNameIndices[];
extern const char XtensaInstrNameData[];
XtensaGenInstrInfo::XtensaGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(XtensaDescs.Insts, XtensaInstrNameIndices, XtensaInstrNameData, nullptr, nullptr, 629);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace Xtensa_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace Xtensa_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::Xtensa_MC {


} // namespace llvm_ks::Xtensa_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::Xtensa_MC {

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_HasDensityBit = 6,
  Feature_HasSingleFloatBit = 27,
  Feature_HasWindowedBit = 29,
  Feature_HasMAC16Bit = 15,
  Feature_HasBooleanBit = 0,
  Feature_HasLoopBit = 14,
  Feature_HasSEXTBit = 26,
  Feature_HasCLAMPSBit = 1,
  Feature_HasNSABit = 21,
  Feature_HasMINMAXBit = 16,
  Feature_HasMul16Bit = 18,
  Feature_HasMul32Bit = 19,
  Feature_HasMul32HighBit = 20,
  Feature_HasDiv32Bit = 7,
  Feature_HasS32C1IBit = 25,
  Feature_HasForcedAtomicsBit = 11,
  Feature_HasRegionProtectionBit = 23,
  Feature_HasRelocatableVectorBit = 24,
  Feature_HasMiscSRBit = 17,
  Feature_HasExtendedL32RBit = 10,
  Feature_HasDataCacheBit = 4,
  Feature_HasTHREADPTRBit = 28,
  Feature_HasHighPriInterruptsBit = 12,
  Feature_HasInterruptBit = 13,
  Feature_HasExceptionBit = 9,
  Feature_HasDebugBit = 5,
  Feature_HasPRIDBit = 22,
  Feature_HasCoprocessorBit = 2,
  Feature_HasDFPAccelBit = 3,
  Feature_HasESP32S2OpsBit = 8,
};

inline FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) {
  FeatureBitset Features;
  if (FB[Xtensa::FeatureDensity])
    Features.set(Feature_HasDensityBit);
  if (FB[Xtensa::FeatureSingleFloat])
    Features.set(Feature_HasSingleFloatBit);
  if (FB[Xtensa::FeatureWindowed])
    Features.set(Feature_HasWindowedBit);
  if (FB[Xtensa::FeatureMAC16])
    Features.set(Feature_HasMAC16Bit);
  if (FB[Xtensa::FeatureBoolean])
    Features.set(Feature_HasBooleanBit);
  if (FB[Xtensa::FeatureLoop])
    Features.set(Feature_HasLoopBit);
  if (FB[Xtensa::FeatureSEXT])
    Features.set(Feature_HasSEXTBit);
  if (FB[Xtensa::FeatureCLAMPS])
    Features.set(Feature_HasCLAMPSBit);
  if (FB[Xtensa::FeatureNSA])
    Features.set(Feature_HasNSABit);
  if (FB[Xtensa::FeatureMINMAX])
    Features.set(Feature_HasMINMAXBit);
  if (FB[Xtensa::FeatureMul16])
    Features.set(Feature_HasMul16Bit);
  if (FB[Xtensa::FeatureMul32])
    Features.set(Feature_HasMul32Bit);
  if (FB[Xtensa::FeatureMul32High])
    Features.set(Feature_HasMul32HighBit);
  if (FB[Xtensa::FeatureDiv32])
    Features.set(Feature_HasDiv32Bit);
  if (FB[Xtensa::FeatureS32C1I])
    Features.set(Feature_HasS32C1IBit);
  if (FB[Xtensa::FeatureForcedAtomics])
    Features.set(Feature_HasForcedAtomicsBit);
  if (FB[Xtensa::FeatureRegionProtection])
    Features.set(Feature_HasRegionProtectionBit);
  if (FB[Xtensa::FeatureRelocatableVector])
    Features.set(Feature_HasRelocatableVectorBit);
  if (FB[Xtensa::FeatureMiscSR])
    Features.set(Feature_HasMiscSRBit);
  if (FB[Xtensa::FeatureExtendedL32R])
    Features.set(Feature_HasExtendedL32RBit);
  if (FB[Xtensa::FeatureDataCache])
    Features.set(Feature_HasDataCacheBit);
  if (FB[Xtensa::FeatureTHREADPTR])
    Features.set(Feature_HasTHREADPTRBit);
  if (FB[Xtensa::FeatureHighPriInterrupts])
    Features.set(Feature_HasHighPriInterruptsBit);
  if (FB[Xtensa::FeatureInterrupt])
    Features.set(Feature_HasInterruptBit);
  if (FB[Xtensa::FeatureException])
    Features.set(Feature_HasExceptionBit);
  if (FB[Xtensa::FeatureDebug])
    Features.set(Feature_HasDebugBit);
  if (FB[Xtensa::FeaturePRID])
    Features.set(Feature_HasPRIDBit);
  if (FB[Xtensa::FeatureCoprocessor])
    Features.set(Feature_HasCoprocessorBit);
  if (FB[Xtensa::FeatureDFPAccel])
    Features.set(Feature_HasDFPAccelBit);
  if (FB[Xtensa::FeatureESP32S2Ops])
    Features.set(Feature_HasESP32S2OpsBit);
  return Features;
}

inline FeatureBitset computeRequiredFeatures(unsigned Opcode) {
  enum : uint8_t {
    CEFBS_None,
    CEFBS_HasBoolean,
    CEFBS_HasCLAMPS,
    CEFBS_HasDebug,
    CEFBS_HasDensity,
    CEFBS_HasDiv32,
    CEFBS_HasESP32S2Ops,
    CEFBS_HasException,
    CEFBS_HasHighPriInterrupts,
    CEFBS_HasInterrupt,
    CEFBS_HasLoop,
    CEFBS_HasMAC16,
    CEFBS_HasMINMAX,
    CEFBS_HasMul16,
    CEFBS_HasMul32,
    CEFBS_HasMul32High,
    CEFBS_HasNSA,
    CEFBS_HasRegionProtection,
    CEFBS_HasS32C1I,
    CEFBS_HasSEXT,
    CEFBS_HasSingleFloat,
    CEFBS_HasWindowed,
    CEFBS_HasBoolean_HasSingleFloat,
    CEFBS_HasDensity_HasDebug,
    CEFBS_HasWindowed_HasDensity,
  };

  static constexpr FeatureBitset FeatureBitsets[] = {
    {}, // CEFBS_None
    {Feature_HasBooleanBit, },
    {Feature_HasCLAMPSBit, },
    {Feature_HasDebugBit, },
    {Feature_HasDensityBit, },
    {Feature_HasDiv32Bit, },
    {Feature_HasESP32S2OpsBit, },
    {Feature_HasExceptionBit, },
    {Feature_HasHighPriInterruptsBit, },
    {Feature_HasInterruptBit, },
    {Feature_HasLoopBit, },
    {Feature_HasMAC16Bit, },
    {Feature_HasMINMAXBit, },
    {Feature_HasMul16Bit, },
    {Feature_HasMul32Bit, },
    {Feature_HasMul32HighBit, },
    {Feature_HasNSABit, },
    {Feature_HasRegionProtectionBit, },
    {Feature_HasS32C1IBit, },
    {Feature_HasSEXTBit, },
    {Feature_HasSingleFloatBit, },
    {Feature_HasWindowedBit, },
    {Feature_HasBooleanBit, Feature_HasSingleFloatBit, },
    {Feature_HasDensityBit, Feature_HasDebugBit, },
    {Feature_HasWindowedBit, Feature_HasDensityBit, },
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
    CEFBS_HasS32C1I, // ATOMIC_CMP_SWAP_32_P
    CEFBS_HasSingleFloat, // BRCC_FP
    CEFBS_None, // BR_JT
    CEFBS_HasWindowed, // MOVSP_P
    CEFBS_None, // SELECT
    CEFBS_HasSingleFloat, // SELECT_CC_FP_FP
    CEFBS_HasSingleFloat, // SELECT_CC_FP_INT
    CEFBS_HasSingleFloat, // SELECT_CC_INT_FP
    CEFBS_None, // ABS
    CEFBS_HasSingleFloat, // ABS_S
    CEFBS_None, // ADD
    CEFBS_HasSingleFloat, // ADDEXPM_S
    CEFBS_HasSingleFloat, // ADDEXP_S
    CEFBS_None, // ADDI
    CEFBS_HasDensity, // ADDI_N
    CEFBS_None, // ADDMI
    CEFBS_None, // ADDX2
    CEFBS_None, // ADDX4
    CEFBS_None, // ADDX8
    CEFBS_HasDensity, // ADD_N
    CEFBS_HasSingleFloat, // ADD_S
    CEFBS_HasBoolean, // ALL4
    CEFBS_HasBoolean, // ALL8
    CEFBS_None, // AND
    CEFBS_HasBoolean, // ANDB
    CEFBS_HasBoolean, // ANDBC
    CEFBS_HasBoolean, // ANY4
    CEFBS_HasBoolean, // ANY8
    CEFBS_None, // BALL
    CEFBS_None, // BANY
    CEFBS_None, // BBC
    CEFBS_None, // BBCI
    CEFBS_None, // BBS
    CEFBS_None, // BBSI
    CEFBS_None, // BEQ
    CEFBS_None, // BEQI
    CEFBS_None, // BEQZ
    CEFBS_HasDensity, // BEQZ_N
    CEFBS_HasBoolean, // BF
    CEFBS_None, // BGE
    CEFBS_None, // BGEI
    CEFBS_None, // BGEU
    CEFBS_None, // BGEUI
    CEFBS_None, // BGEZ
    CEFBS_None, // BLT
    CEFBS_None, // BLTI
    CEFBS_None, // BLTU
    CEFBS_None, // BLTUI
    CEFBS_None, // BLTZ
    CEFBS_None, // BNALL
    CEFBS_None, // BNE
    CEFBS_None, // BNEI
    CEFBS_None, // BNEZ
    CEFBS_HasDensity, // BNEZ_N
    CEFBS_None, // BNONE
    CEFBS_HasDebug, // BREAK
    CEFBS_HasDensity_HasDebug, // BREAK_N
    CEFBS_HasBoolean, // BT
    CEFBS_None, // CALL0
    CEFBS_HasWindowed, // CALL12
    CEFBS_HasWindowed, // CALL4
    CEFBS_HasWindowed, // CALL8
    CEFBS_None, // CALLX0
    CEFBS_HasWindowed, // CALLX12
    CEFBS_HasWindowed, // CALLX4
    CEFBS_HasWindowed, // CALLX8
    CEFBS_HasSingleFloat, // CEIL_S
    CEFBS_HasCLAMPS, // CLAMPS
    CEFBS_HasESP32S2Ops, // CLR_BIT_GPIO_OUT
    CEFBS_HasSingleFloat, // CONST_S
    CEFBS_HasSingleFloat, // DIV0_S
    CEFBS_HasSingleFloat, // DIVN_S
    CEFBS_None, // DSYNC
    CEFBS_HasWindowed, // ENTRY
    CEFBS_None, // ESYNC
    CEFBS_HasException, // EXCW
    CEFBS_None, // EXTUI
    CEFBS_None, // EXTW
    CEFBS_HasSingleFloat, // FLOAT_S
    CEFBS_HasSingleFloat, // FLOOR_S
    CEFBS_HasESP32S2Ops, // GET_GPIO_IN
    CEFBS_HasRegionProtection, // IDTLB
    CEFBS_HasRegionProtection, // IITLB
    CEFBS_None, // ILL
    CEFBS_HasDensity, // ILL_N
    CEFBS_None, // ISYNC
    CEFBS_None, // J
    CEFBS_None, // JX
    CEFBS_None, // L16SI
    CEFBS_None, // L16UI
    CEFBS_HasWindowed, // L32E
    CEFBS_None, // L32I
    CEFBS_HasDensity, // L32I_N
    CEFBS_None, // L32R
    CEFBS_None, // L8UI
    CEFBS_HasMAC16, // LDDEC
    CEFBS_HasDebug, // LDDR32P
    CEFBS_HasMAC16, // LDINC
    CEFBS_None, // LEA_ADD
    CEFBS_HasLoop, // LOOP
    CEFBS_HasLoop, // LOOPGTZ
    CEFBS_HasLoop, // LOOPNEZ
    CEFBS_HasSingleFloat, // LSI
    CEFBS_HasSingleFloat, // LSIP
    CEFBS_HasSingleFloat, // LSX
    CEFBS_HasSingleFloat, // LSXP
    CEFBS_HasSingleFloat, // MADDN_S
    CEFBS_HasSingleFloat, // MADD_S
    CEFBS_HasMINMAX, // MAX
    CEFBS_HasMINMAX, // MAXU
    CEFBS_None, // MEMW
    CEFBS_HasMINMAX, // MIN
    CEFBS_HasMINMAX, // MINU
    CEFBS_HasSingleFloat, // MKDADJ_S
    CEFBS_HasSingleFloat, // MKSADJ_S
    CEFBS_None, // MOVEQZ
    CEFBS_HasSingleFloat, // MOVEQZ_S
    CEFBS_HasBoolean, // MOVF
    CEFBS_HasBoolean_HasSingleFloat, // MOVF_S
    CEFBS_None, // MOVGEZ
    CEFBS_HasSingleFloat, // MOVGEZ_S
    CEFBS_None, // MOVI
    CEFBS_HasDensity, // MOVI_N
    CEFBS_None, // MOVLTZ
    CEFBS_HasSingleFloat, // MOVLTZ_S
    CEFBS_None, // MOVNEZ
    CEFBS_HasSingleFloat, // MOVNEZ_S
    CEFBS_HasWindowed, // MOVSP
    CEFBS_HasBoolean, // MOVT
    CEFBS_HasBoolean_HasSingleFloat, // MOVT_S
    CEFBS_HasDensity, // MOV_N
    CEFBS_HasSingleFloat, // MOV_S
    CEFBS_HasSingleFloat, // MSUB_S
    CEFBS_HasMul16, // MUL16S
    CEFBS_HasMul16, // MUL16U
    CEFBS_HasMAC16, // MULA_AA_HH
    CEFBS_HasMAC16, // MULA_AA_HL
    CEFBS_HasMAC16, // MULA_AA_LH
    CEFBS_HasMAC16, // MULA_AA_LL
    CEFBS_HasMAC16, // MULA_AD_HH
    CEFBS_HasMAC16, // MULA_AD_HL
    CEFBS_HasMAC16, // MULA_AD_LH
    CEFBS_HasMAC16, // MULA_AD_LL
    CEFBS_HasMAC16, // MULA_DA_HH
    CEFBS_HasMAC16, // MULA_DA_HH_LDDEC
    CEFBS_HasMAC16, // MULA_DA_HH_LDINC
    CEFBS_HasMAC16, // MULA_DA_HL
    CEFBS_HasMAC16, // MULA_DA_HL_LDDEC
    CEFBS_HasMAC16, // MULA_DA_HL_LDINC
    CEFBS_HasMAC16, // MULA_DA_LH
    CEFBS_HasMAC16, // MULA_DA_LH_LDDEC
    CEFBS_HasMAC16, // MULA_DA_LH_LDINC
    CEFBS_HasMAC16, // MULA_DA_LL
    CEFBS_HasMAC16, // MULA_DA_LL_LDDEC
    CEFBS_HasMAC16, // MULA_DA_LL_LDINC
    CEFBS_HasMAC16, // MULA_DD_HH
    CEFBS_HasMAC16, // MULA_DD_HH_LDDEC
    CEFBS_HasMAC16, // MULA_DD_HH_LDINC
    CEFBS_HasMAC16, // MULA_DD_HL
    CEFBS_HasMAC16, // MULA_DD_HL_LDDEC
    CEFBS_HasMAC16, // MULA_DD_HL_LDINC
    CEFBS_HasMAC16, // MULA_DD_LH
    CEFBS_HasMAC16, // MULA_DD_LH_LDDEC
    CEFBS_HasMAC16, // MULA_DD_LH_LDINC
    CEFBS_HasMAC16, // MULA_DD_LL
    CEFBS_HasMAC16, // MULA_DD_LL_LDDEC
    CEFBS_HasMAC16, // MULA_DD_LL_LDINC
    CEFBS_HasMul32, // MULL
    CEFBS_HasMul32High, // MULSH
    CEFBS_HasMAC16, // MULS_AA_HH
    CEFBS_HasMAC16, // MULS_AA_HL
    CEFBS_HasMAC16, // MULS_AA_LH
    CEFBS_HasMAC16, // MULS_AA_LL
    CEFBS_HasMAC16, // MULS_AD_HH
    CEFBS_HasMAC16, // MULS_AD_HL
    CEFBS_HasMAC16, // MULS_AD_LH
    CEFBS_HasMAC16, // MULS_AD_LL
    CEFBS_HasMAC16, // MULS_DA_HH
    CEFBS_HasMAC16, // MULS_DA_HL
    CEFBS_HasMAC16, // MULS_DA_LH
    CEFBS_HasMAC16, // MULS_DA_LL
    CEFBS_HasMAC16, // MULS_DD_HH
    CEFBS_HasMAC16, // MULS_DD_HL
    CEFBS_HasMAC16, // MULS_DD_LH
    CEFBS_HasMAC16, // MULS_DD_LL
    CEFBS_HasMul32High, // MULUH
    CEFBS_HasMAC16, // MUL_AA_HH
    CEFBS_HasMAC16, // MUL_AA_HL
    CEFBS_HasMAC16, // MUL_AA_LH
    CEFBS_HasMAC16, // MUL_AA_LL
    CEFBS_HasMAC16, // MUL_AD_HH
    CEFBS_HasMAC16, // MUL_AD_HL
    CEFBS_HasMAC16, // MUL_AD_LH
    CEFBS_HasMAC16, // MUL_AD_LL
    CEFBS_HasMAC16, // MUL_DA_HH
    CEFBS_HasMAC16, // MUL_DA_HL
    CEFBS_HasMAC16, // MUL_DA_LH
    CEFBS_HasMAC16, // MUL_DA_LL
    CEFBS_HasMAC16, // MUL_DD_HH
    CEFBS_HasMAC16, // MUL_DD_HL
    CEFBS_HasMAC16, // MUL_DD_LH
    CEFBS_HasMAC16, // MUL_DD_LL
    CEFBS_HasSingleFloat, // MUL_S
    CEFBS_None, // NEG
    CEFBS_HasSingleFloat, // NEG_S
    CEFBS_HasSingleFloat, // NEXP01_S
    CEFBS_None, // NOP
    CEFBS_HasDensity, // NOP_N
    CEFBS_HasNSA, // NSA
    CEFBS_HasNSA, // NSAU
    CEFBS_HasSingleFloat, // OEQ_S
    CEFBS_HasSingleFloat, // OLE_S
    CEFBS_HasSingleFloat, // OLT_S
    CEFBS_None, // OR
    CEFBS_HasBoolean, // ORB
    CEFBS_HasBoolean, // ORBC
    CEFBS_HasRegionProtection, // PDTLB
    CEFBS_HasRegionProtection, // PITLB
    CEFBS_HasDiv32, // QUOS
    CEFBS_HasDiv32, // QUOU
    CEFBS_HasRegionProtection, // RDTLB0
    CEFBS_HasRegionProtection, // RDTLB1
    CEFBS_HasSingleFloat, // RECIP0_S
    CEFBS_HasDiv32, // REMS
    CEFBS_HasDiv32, // REMU
    CEFBS_None, // RET
    CEFBS_HasWindowed, // RETW
    CEFBS_HasWindowed_HasDensity, // RETW_N
    CEFBS_HasDensity, // RET_N
    CEFBS_HasException, // RFDE
    CEFBS_HasException, // RFE
    CEFBS_HasHighPriInterrupts, // RFI
    CEFBS_HasSingleFloat, // RFR
    CEFBS_HasWindowed, // RFWO
    CEFBS_HasWindowed, // RFWU
    CEFBS_HasRegionProtection, // RITLB0
    CEFBS_HasRegionProtection, // RITLB1
    CEFBS_HasWindowed, // ROTW
    CEFBS_HasSingleFloat, // ROUND_S
    CEFBS_HasInterrupt, // RSIL
    CEFBS_HasSingleFloat, // RSQRT0_S
    CEFBS_None, // RSR
    CEFBS_None, // RSYNC
    CEFBS_None, // RUR
    CEFBS_None, // S16I
    CEFBS_HasS32C1I, // S32C1I
    CEFBS_HasWindowed, // S32E
    CEFBS_None, // S32I
    CEFBS_HasDensity, // S32I_N
    CEFBS_None, // S8I
    CEFBS_HasDebug, // SDDR32P
    CEFBS_HasESP32S2Ops, // SET_BIT_GPIO_OUT
    CEFBS_HasSEXT, // SEXT
    CEFBS_None, // SLL
    CEFBS_None, // SLLI
    CEFBS_HasSingleFloat, // SQRT0_S
    CEFBS_None, // SRA
    CEFBS_None, // SRAI
    CEFBS_None, // SRC
    CEFBS_None, // SRL
    CEFBS_None, // SRLI
    CEFBS_None, // SSA8L
    CEFBS_None, // SSAI
    CEFBS_HasSingleFloat, // SSI
    CEFBS_HasSingleFloat, // SSIP
    CEFBS_None, // SSL
    CEFBS_None, // SSR
    CEFBS_HasSingleFloat, // SSX
    CEFBS_HasSingleFloat, // SSXP
    CEFBS_None, // SUB
    CEFBS_None, // SUBX2
    CEFBS_None, // SUBX4
    CEFBS_None, // SUBX8
    CEFBS_HasSingleFloat, // SUB_S
    CEFBS_HasException, // SYSCALL
    CEFBS_HasSingleFloat, // TRUNC_S
    CEFBS_HasSingleFloat, // UEQ_S
    CEFBS_HasSingleFloat, // UFLOAT_S
    CEFBS_HasSingleFloat, // ULE_S
    CEFBS_HasSingleFloat, // ULT_S
    CEFBS_HasMAC16, // UMUL_AA_HH
    CEFBS_HasMAC16, // UMUL_AA_HL
    CEFBS_HasMAC16, // UMUL_AA_LH
    CEFBS_HasMAC16, // UMUL_AA_LL
    CEFBS_HasSingleFloat, // UN_S
    CEFBS_HasSingleFloat, // UTRUNC_S
    CEFBS_HasInterrupt, // WAITI
    CEFBS_HasRegionProtection, // WDTLB
    CEFBS_HasSingleFloat, // WFR
    CEFBS_HasRegionProtection, // WITLB
    CEFBS_HasESP32S2Ops, // WR_MASK_GPIO_OUT
    CEFBS_None, // WSR
    CEFBS_None, // WUR
    CEFBS_None, // XOR
    CEFBS_HasBoolean, // XORB
    CEFBS_None, // XSR
  };

  assert(Opcode < 629);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::Xtensa_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::Xtensa_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::Xtensa_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::Xtensa_MC {

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_HasBoolean",
  "Feature_HasCLAMPS",
  "Feature_HasCoprocessor",
  "Feature_HasDFPAccel",
  "Feature_HasDataCache",
  "Feature_HasDebug",
  "Feature_HasDensity",
  "Feature_HasDiv32",
  "Feature_HasESP32S2Ops",
  "Feature_HasException",
  "Feature_HasExtendedL32R",
  "Feature_HasForcedAtomics",
  "Feature_HasHighPriInterrupts",
  "Feature_HasInterrupt",
  "Feature_HasLoop",
  "Feature_HasMAC16",
  "Feature_HasMINMAX",
  "Feature_HasMiscSR",
  "Feature_HasMul16",
  "Feature_HasMul32",
  "Feature_HasMul32High",
  "Feature_HasNSA",
  "Feature_HasPRID",
  "Feature_HasRegionProtection",
  "Feature_HasRelocatableVector",
  "Feature_HasS32C1I",
  "Feature_HasSEXT",
  "Feature_HasSingleFloat",
  "Feature_HasTHREADPTR",
  "Feature_HasWindowed",
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
    Msg << "Attempting to emit " << &XtensaInstrNameData[XtensaInstrNameIndices[Opcode]]
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::Xtensa_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

