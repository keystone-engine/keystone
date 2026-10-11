/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::LoongArch {

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
    ADJCALLSTACKDOWN                      = 331, // LoongArchInstrInfo.td:2459
    ADJCALLSTACKUP                        = 332, // LoongArchInstrInfo.td:2461
    BuildPairF64Pseudo                    = 333, // LoongArchFloat64InstrInfo.td:362
    PROBED_STACKALLOC                     = 334, // LoongArchInstrInfo.td:2470
    PROBED_STACKALLOC_DYN                 = 335, // LoongArchInstrInfo.td:2475
    PseudoAddTPRel_D                      = 336, // LoongArchInstrInfo.td:1773
    PseudoAddTPRel_W                      = 337, // LoongArchInstrInfo.td:1769
    PseudoAtomicLoadAdd32                 = 338, // LoongArchInstrInfo.td:2123
    PseudoAtomicLoadAnd32                 = 339, // LoongArchInstrInfo.td:2125
    PseudoAtomicLoadMax32                 = 340, // LoongArchInstrInfo.td:2130
    PseudoAtomicLoadMin32                 = 341, // LoongArchInstrInfo.td:2131
    PseudoAtomicLoadNand32                = 342, // LoongArchInstrInfo.td:2121
    PseudoAtomicLoadNand64                = 343, // LoongArchInstrInfo.td:2122
    PseudoAtomicLoadOr32                  = 344, // LoongArchInstrInfo.td:2126
    PseudoAtomicLoadSub32                 = 345, // LoongArchInstrInfo.td:2124
    PseudoAtomicLoadUMax32                = 346, // LoongArchInstrInfo.td:2128
    PseudoAtomicLoadUMin32                = 347, // LoongArchInstrInfo.td:2129
    PseudoAtomicLoadXor32                 = 348, // LoongArchInstrInfo.td:2127
    PseudoAtomicStoreD                    = 349, // LoongArchInstrInfo.td:2082
    PseudoAtomicStoreW                    = 350, // LoongArchInstrInfo.td:2074
    PseudoAtomicSwap32                    = 351, // LoongArchInstrInfo.td:2120
    PseudoBR                              = 352, // LoongArchInstrInfo.td:1625
    PseudoBRIND                           = 353, // LoongArchInstrInfo.td:1629
    PseudoB_TAIL                          = 354, // LoongArchInstrInfo.td:1722
    PseudoCALL                            = 355, // LoongArchInstrInfo.td:1734
    PseudoCALL30                          = 356, // LoongArchInstrInfo.td:1744
    PseudoCALL36                          = 357, // LoongArchInstrInfo.td:1754
    PseudoCALLIndirect                    = 358, // LoongArchInstrInfo.td:1666
    PseudoCALL_LARGE                      = 359, // LoongArchInstrInfo.td:1656
    PseudoCALL_MEDIUM                     = 360, // LoongArchInstrInfo.td:1647
    PseudoCALL_SMALL                      = 361, // LoongArchInstrInfo.td:1638
    PseudoCTPOP_B                         = 362, // LoongArchLSXInstrInfo.td:1343
    PseudoCTPOP_D                         = 363, // LoongArchLSXInstrInfo.td:1359
    PseudoCTPOP_H                         = 364, // LoongArchLSXInstrInfo.td:1345
    PseudoCTPOP_H_LA32                    = 365, // LoongArchLSXInstrInfo.td:1349
    PseudoCTPOP_W                         = 366, // LoongArchLSXInstrInfo.td:1356
    PseudoCTPOP_W_LA32                    = 367, // LoongArchLSXInstrInfo.td:1351
    PseudoCmpXchg128                      = 368, // LoongArchInstrInfo.td:2209
    PseudoCmpXchg128Acquire               = 369, // LoongArchInstrInfo.td:2210
    PseudoCmpXchg32                       = 370, // LoongArchInstrInfo.td:2195
    PseudoCmpXchg64                       = 371, // LoongArchInstrInfo.td:2196
    PseudoCopyCFR                         = 372, // LoongArchFloat32InstrInfo.td:162
    PseudoDESC_CALL                       = 373, // LoongArchInstrInfo.td:1829
    PseudoJIRL_CALL                       = 374, // LoongArchInstrInfo.td:1674
    PseudoJIRL_TAIL                       = 375, // LoongArchInstrInfo.td:1727
    PseudoLA_ABS                          = 376, // LoongArchInstrInfo.td:1784
    PseudoLA_ABS_LARGE                    = 377, // LoongArchInstrInfo.td:1786
    PseudoLA_GOT                          = 378, // LoongArchInstrInfo.td:1812
    PseudoLA_GOT_LARGE                    = 379, // LoongArchInstrInfo.td:1816
    PseudoLA_PCREL                        = 380, // LoongArchInstrInfo.td:1789
    PseudoLA_PCREL_LARGE                  = 381, // LoongArchInstrInfo.td:1795
    PseudoLA_TLS_DESC                     = 382, // LoongArchInstrInfo.td:1835
    PseudoLA_TLS_DESC_LARGE               = 383, // LoongArchInstrInfo.td:1839
    PseudoLA_TLS_GD                       = 384, // LoongArchInstrInfo.td:1793
    PseudoLA_TLS_GD_LARGE                 = 385, // LoongArchInstrInfo.td:1805
    PseudoLA_TLS_IE                       = 386, // LoongArchInstrInfo.td:1814
    PseudoLA_TLS_IE_LARGE                 = 387, // LoongArchInstrInfo.td:1820
    PseudoLA_TLS_LD                       = 388, // LoongArchInstrInfo.td:1791
    PseudoLA_TLS_LD_LARGE                 = 389, // LoongArchInstrInfo.td:1801
    PseudoLA_TLS_LE                       = 390, // LoongArchInstrInfo.td:1799
    PseudoLD_CFR                          = 391, // LoongArchFloat32InstrInfo.td:150
    PseudoLI_D                            = 392, // LoongArchInstrInfo.td:2527
    PseudoLI_W                            = 393, // LoongArchInstrInfo.td:2525
    PseudoMaskedAtomicLoadAdd32           = 394, // LoongArchInstrInfo.td:2107
    PseudoMaskedAtomicLoadMax32           = 395, // LoongArchInstrInfo.td:2172
    PseudoMaskedAtomicLoadMin32           = 396, // LoongArchInstrInfo.td:2173
    PseudoMaskedAtomicLoadNand32          = 397, // LoongArchInstrInfo.td:2109
    PseudoMaskedAtomicLoadSub32           = 398, // LoongArchInstrInfo.td:2108
    PseudoMaskedAtomicLoadUMax32          = 399, // LoongArchInstrInfo.td:2157
    PseudoMaskedAtomicLoadUMin32          = 400, // LoongArchInstrInfo.td:2158
    PseudoMaskedAtomicSwap32              = 401, // LoongArchInstrInfo.td:2106
    PseudoMaskedCmpXchg32                 = 402, // LoongArchInstrInfo.td:2212
    PseudoRET                             = 403, // LoongArchInstrInfo.td:1679
    PseudoST_CFR                          = 404, // LoongArchFloat32InstrInfo.td:147
    PseudoTAIL                            = 405, // LoongArchInstrInfo.td:1738
    PseudoTAIL30                          = 406, // LoongArchInstrInfo.td:1748
    PseudoTAIL36                          = 407, // LoongArchInstrInfo.td:1760
    PseudoTAILIndirect                    = 408, // LoongArchInstrInfo.td:1713
    PseudoTAIL_LARGE                      = 409, // LoongArchInstrInfo.td:1703
    PseudoTAIL_MEDIUM                     = 410, // LoongArchInstrInfo.td:1694
    PseudoTAIL_SMALL                      = 411, // LoongArchInstrInfo.td:1684
    PseudoUNIMP                           = 412, // LoongArchInstrInfo.td:1431
    PseudoVBNZ                            = 413, // LoongArchLSXInstrInfo.td:1334
    PseudoVBNZ_B                          = 414, // LoongArchLSXInstrInfo.td:1330
    PseudoVBNZ_D                          = 415, // LoongArchLSXInstrInfo.td:1333
    PseudoVBNZ_H                          = 416, // LoongArchLSXInstrInfo.td:1331
    PseudoVBNZ_W                          = 417, // LoongArchLSXInstrInfo.td:1332
    PseudoVBZ                             = 418, // LoongArchLSXInstrInfo.td:1340
    PseudoVBZ_B                           = 419, // LoongArchLSXInstrInfo.td:1336
    PseudoVBZ_D                           = 420, // LoongArchLSXInstrInfo.td:1339
    PseudoVBZ_H                           = 421, // LoongArchLSXInstrInfo.td:1337
    PseudoVBZ_W                           = 422, // LoongArchLSXInstrInfo.td:1338
    PseudoVMSKEQZ_B                       = 423, // LoongArchLSXInstrInfo.td:1370
    PseudoVMSKGEZ_B                       = 424, // LoongArchLSXInstrInfo.td:1369
    PseudoVMSKLTZ_B                       = 425, // LoongArchLSXInstrInfo.td:1365
    PseudoVMSKLTZ_D                       = 426, // LoongArchLSXInstrInfo.td:1368
    PseudoVMSKLTZ_H                       = 427, // LoongArchLSXInstrInfo.td:1366
    PseudoVMSKLTZ_W                       = 428, // LoongArchLSXInstrInfo.td:1367
    PseudoVMSKNEZ_B                       = 429, // LoongArchLSXInstrInfo.td:1371
    PseudoVREPLI_B                        = 430, // LoongArchLSXInstrInfo.td:1320
    PseudoVREPLI_D                        = 431, // LoongArchLSXInstrInfo.td:1326
    PseudoVREPLI_H                        = 432, // LoongArchLSXInstrInfo.td:1322
    PseudoVREPLI_W                        = 433, // LoongArchLSXInstrInfo.td:1324
    PseudoXVBNZ                           = 434, // LoongArchLASXInstrInfo.td:1093
    PseudoXVBNZ_B                         = 435, // LoongArchLASXInstrInfo.td:1089
    PseudoXVBNZ_D                         = 436, // LoongArchLASXInstrInfo.td:1092
    PseudoXVBNZ_H                         = 437, // LoongArchLASXInstrInfo.td:1090
    PseudoXVBNZ_W                         = 438, // LoongArchLASXInstrInfo.td:1091
    PseudoXVBZ                            = 439, // LoongArchLASXInstrInfo.td:1099
    PseudoXVBZ_B                          = 440, // LoongArchLASXInstrInfo.td:1095
    PseudoXVBZ_D                          = 441, // LoongArchLASXInstrInfo.td:1098
    PseudoXVBZ_H                          = 442, // LoongArchLASXInstrInfo.td:1096
    PseudoXVBZ_W                          = 443, // LoongArchLASXInstrInfo.td:1097
    PseudoXVINSGR2VR_B                    = 444, // LoongArchLASXInstrInfo.td:1102
    PseudoXVINSGR2VR_H                    = 445, // LoongArchLASXInstrInfo.td:1104
    PseudoXVMSKEQZ_B                      = 446, // LoongArchLASXInstrInfo.td:1114
    PseudoXVMSKGEZ_B                      = 447, // LoongArchLASXInstrInfo.td:1113
    PseudoXVMSKLTZ_B                      = 448, // LoongArchLASXInstrInfo.td:1109
    PseudoXVMSKLTZ_D                      = 449, // LoongArchLASXInstrInfo.td:1112
    PseudoXVMSKLTZ_H                      = 450, // LoongArchLASXInstrInfo.td:1110
    PseudoXVMSKLTZ_W                      = 451, // LoongArchLASXInstrInfo.td:1111
    PseudoXVMSKNEZ_B                      = 452, // LoongArchLASXInstrInfo.td:1115
    PseudoXVREPLI_B                       = 453, // LoongArchLASXInstrInfo.td:1079
    PseudoXVREPLI_D                       = 454, // LoongArchLASXInstrInfo.td:1085
    PseudoXVREPLI_H                       = 455, // LoongArchLASXInstrInfo.td:1081
    PseudoXVREPLI_W                       = 456, // LoongArchLASXInstrInfo.td:1083
    RDFCSR                                = 457, // LoongArchInstrInfo.td:2541
    Select_GPR_Using_CC_GPR               = 458, // LoongArchInstrInfo.td:1575
    SplitPairF64Pseudo                    = 459, // LoongArchFloat64InstrInfo.td:368
    WRFCSR                                = 460, // LoongArchInstrInfo.td:2539
    ADC_B                                 = 461, // LoongArchLBTInstrInfo.td:27
    ADC_D                                 = 462, // LoongArchLBTInstrInfo.td:192
    ADC_H                                 = 463, // LoongArchLBTInstrInfo.td:28
    ADC_W                                 = 464, // LoongArchLBTInstrInfo.td:29
    ADDI_D                                = 465, // LoongArchInstrInfo.td:1003
    ADDI_W                                = 466, // LoongArchInstrInfo.td:860
    ADDU12I_D                             = 467, // LoongArchLBTInstrInfo.td:191
    ADDU12I_W                             = 468, // LoongArchLBTInstrInfo.td:25
    ADDU16I_D                             = 469, // LoongArchInstrInfo.td:1005
    ADD_D                                 = 470, // LoongArchInstrInfo.td:997
    ADD_W                                 = 471, // LoongArchInstrInfo.td:858
    ALSL_D                                = 472, // LoongArchInstrInfo.td:1007
    ALSL_W                                = 473, // LoongArchInstrInfo.td:955
    ALSL_WU                               = 474, // LoongArchInstrInfo.td:1006
    AMADD_B                               = 475, // LoongArchInstrInfo.td:1109
    AMADD_D                               = 476, // LoongArchInstrInfo.td:1112
    AMADD_H                               = 477, // LoongArchInstrInfo.td:1110
    AMADD_W                               = 478, // LoongArchInstrInfo.td:1111
    AMADD__DB_B                           = 479, // LoongArchInstrInfo.td:1131
    AMADD__DB_D                           = 480, // LoongArchInstrInfo.td:1134
    AMADD__DB_H                           = 481, // LoongArchInstrInfo.td:1132
    AMADD__DB_W                           = 482, // LoongArchInstrInfo.td:1133
    AMAND_D                               = 483, // LoongArchInstrInfo.td:1114
    AMAND_W                               = 484, // LoongArchInstrInfo.td:1113
    AMAND__DB_D                           = 485, // LoongArchInstrInfo.td:1136
    AMAND__DB_W                           = 486, // LoongArchInstrInfo.td:1135
    AMCAS_B                               = 487, // LoongArchInstrInfo.td:1149
    AMCAS_D                               = 488, // LoongArchInstrInfo.td:1152
    AMCAS_H                               = 489, // LoongArchInstrInfo.td:1150
    AMCAS_W                               = 490, // LoongArchInstrInfo.td:1151
    AMCAS__DB_B                           = 491, // LoongArchInstrInfo.td:1153
    AMCAS__DB_D                           = 492, // LoongArchInstrInfo.td:1156
    AMCAS__DB_H                           = 493, // LoongArchInstrInfo.td:1154
    AMCAS__DB_W                           = 494, // LoongArchInstrInfo.td:1155
    AMMAX_D                               = 495, // LoongArchInstrInfo.td:1120
    AMMAX_DU                              = 496, // LoongArchInstrInfo.td:1124
    AMMAX_W                               = 497, // LoongArchInstrInfo.td:1119
    AMMAX_WU                              = 498, // LoongArchInstrInfo.td:1123
    AMMAX__DB_D                           = 499, // LoongArchInstrInfo.td:1142
    AMMAX__DB_DU                          = 500, // LoongArchInstrInfo.td:1146
    AMMAX__DB_W                           = 501, // LoongArchInstrInfo.td:1141
    AMMAX__DB_WU                          = 502, // LoongArchInstrInfo.td:1145
    AMMIN_D                               = 503, // LoongArchInstrInfo.td:1122
    AMMIN_DU                              = 504, // LoongArchInstrInfo.td:1126
    AMMIN_W                               = 505, // LoongArchInstrInfo.td:1121
    AMMIN_WU                              = 506, // LoongArchInstrInfo.td:1125
    AMMIN__DB_D                           = 507, // LoongArchInstrInfo.td:1144
    AMMIN__DB_DU                          = 508, // LoongArchInstrInfo.td:1148
    AMMIN__DB_W                           = 509, // LoongArchInstrInfo.td:1143
    AMMIN__DB_WU                          = 510, // LoongArchInstrInfo.td:1147
    AMOR_D                                = 511, // LoongArchInstrInfo.td:1116
    AMOR_W                                = 512, // LoongArchInstrInfo.td:1115
    AMOR__DB_D                            = 513, // LoongArchInstrInfo.td:1138
    AMOR__DB_W                            = 514, // LoongArchInstrInfo.td:1137
    AMSWAP_B                              = 515, // LoongArchInstrInfo.td:1105
    AMSWAP_D                              = 516, // LoongArchInstrInfo.td:1108
    AMSWAP_H                              = 517, // LoongArchInstrInfo.td:1106
    AMSWAP_W                              = 518, // LoongArchInstrInfo.td:1107
    AMSWAP__DB_B                          = 519, // LoongArchInstrInfo.td:1127
    AMSWAP__DB_D                          = 520, // LoongArchInstrInfo.td:1130
    AMSWAP__DB_H                          = 521, // LoongArchInstrInfo.td:1128
    AMSWAP__DB_W                          = 522, // LoongArchInstrInfo.td:1129
    AMXOR_D                               = 523, // LoongArchInstrInfo.td:1118
    AMXOR_W                               = 524, // LoongArchInstrInfo.td:1117
    AMXOR__DB_D                           = 525, // LoongArchInstrInfo.td:1140
    AMXOR__DB_W                           = 526, // LoongArchInstrInfo.td:1139
    AND                                   = 527, // LoongArchInstrInfo.td:869
    ANDI                                  = 528, // LoongArchInstrInfo.td:873
    ANDN                                  = 529, // LoongArchInstrInfo.td:956
    ARMADC_W                              = 530, // LoongArchLBTInstrInfo.td:168
    ARMADD_W                              = 531, // LoongArchLBTInstrInfo.td:166
    ARMAND_W                              = 532, // LoongArchLBTInstrInfo.td:170
    ARMMFFLAG                             = 533, // LoongArchLBTInstrInfo.td:186
    ARMMOVE                               = 534, // LoongArchLBTInstrInfo.td:183
    ARMMOV_D                              = 535, // LoongArchLBTInstrInfo.td:238
    ARMMOV_W                              = 536, // LoongArchLBTInstrInfo.td:184
    ARMMTFLAG                             = 537, // LoongArchLBTInstrInfo.td:187
    ARMNOT_W                              = 538, // LoongArchLBTInstrInfo.td:173
    ARMOR_W                               = 539, // LoongArchLBTInstrInfo.td:171
    ARMROTRI_W                            = 540, // LoongArchLBTInstrInfo.td:181
    ARMROTR_W                             = 541, // LoongArchLBTInstrInfo.td:177
    ARMRRX_W                              = 542, // LoongArchLBTInstrInfo.td:182
    ARMSBC_W                              = 543, // LoongArchLBTInstrInfo.td:169
    ARMSLLI_W                             = 544, // LoongArchLBTInstrInfo.td:178
    ARMSLL_W                              = 545, // LoongArchLBTInstrInfo.td:174
    ARMSRAI_W                             = 546, // LoongArchLBTInstrInfo.td:180
    ARMSRA_W                              = 547, // LoongArchLBTInstrInfo.td:176
    ARMSRLI_W                             = 548, // LoongArchLBTInstrInfo.td:179
    ARMSRL_W                              = 549, // LoongArchLBTInstrInfo.td:175
    ARMSUB_W                              = 550, // LoongArchLBTInstrInfo.td:167
    ARMXOR_W                              = 551, // LoongArchLBTInstrInfo.td:172
    ASRTGT_D                              = 552, // LoongArchInstrInfo.td:1178
    ASRTLE_D                              = 553, // LoongArchInstrInfo.td:1176
    B                                     = 554, // LoongArchInstrInfo.td:905
    BCEQZ                                 = 555, // LoongArchFloat32InstrInfo.td:130
    BCNEZ                                 = 556, // LoongArchFloat32InstrInfo.td:131
    BEQ                                   = 557, // LoongArchInstrInfo.td:899
    BEQZ                                  = 558, // LoongArchInstrInfo.td:988
    BGE                                   = 559, // LoongArchInstrInfo.td:902
    BGEU                                  = 560, // LoongArchInstrInfo.td:904
    BITREV_4B                             = 561, // LoongArchInstrInfo.td:974
    BITREV_8B                             = 562, // LoongArchInstrInfo.td:1052
    BITREV_D                              = 563, // LoongArchInstrInfo.td:1053
    BITREV_W                              = 564, // LoongArchInstrInfo.td:975
    BL                                    = 565, // LoongArchInstrInfo.td:908
    BLT                                   = 566, // LoongArchInstrInfo.td:901
    BLTU                                  = 567, // LoongArchInstrInfo.td:903
    BNE                                   = 568, // LoongArchInstrInfo.td:900
    BNEZ                                  = 569, // LoongArchInstrInfo.td:989
    BREAK                                 = 570, // LoongArchInstrInfo.td:936
    BSTRINS_D                             = 571, // LoongArchInstrInfo.td:1055
    BSTRINS_W                             = 572, // LoongArchInstrInfo.td:977
    BSTRPICK_D                            = 573, // LoongArchInstrInfo.td:1059
    BSTRPICK_W                            = 574, // LoongArchInstrInfo.td:981
    BYTEPICK_D                            = 575, // LoongArchInstrInfo.td:1046
    BYTEPICK_W                            = 576, // LoongArchInstrInfo.td:972
    CACOP                                 = 577, // LoongArchInstrInfo.td:950
    CLO_D                                 = 578, // LoongArchInstrInfo.td:1042
    CLO_W                                 = 579, // LoongArchInstrInfo.td:968
    CLZ_D                                 = 580, // LoongArchInstrInfo.td:1043
    CLZ_W                                 = 581, // LoongArchInstrInfo.td:969
    CPUCFG                                = 582, // LoongArchInstrInfo.td:947
    CRCC_W_B_W                            = 583, // LoongArchInstrInfo.td:1170
    CRCC_W_D_W                            = 584, // LoongArchInstrInfo.td:1173
    CRCC_W_H_W                            = 585, // LoongArchInstrInfo.td:1171
    CRCC_W_W_W                            = 586, // LoongArchInstrInfo.td:1172
    CRC_W_B_W                             = 587, // LoongArchInstrInfo.td:1166
    CRC_W_D_W                             = 588, // LoongArchInstrInfo.td:1169
    CRC_W_H_W                             = 589, // LoongArchInstrInfo.td:1167
    CRC_W_W_W                             = 590, // LoongArchInstrInfo.td:1168
    CSRRD                                 = 591, // LoongArchInstrInfo.td:2551
    CSRWR                                 = 592, // LoongArchInstrInfo.td:2554
    CSRXCHG                               = 593, // LoongArchInstrInfo.td:2556
    CTO_D                                 = 594, // LoongArchInstrInfo.td:1044
    CTO_W                                 = 595, // LoongArchInstrInfo.td:970
    CTZ_D                                 = 596, // LoongArchInstrInfo.td:1045
    CTZ_W                                 = 597, // LoongArchInstrInfo.td:971
    DBAR                                  = 598, // LoongArchInstrInfo.td:931
    DBCL                                  = 599, // LoongArchInstrInfo.td:2594
    DIV_D                                 = 600, // LoongArchInstrInfo.td:1025
    DIV_DU                                = 601, // LoongArchInstrInfo.td:1027
    DIV_W                                 = 602, // LoongArchInstrInfo.td:883
    DIV_WU                                = 603, // LoongArchInstrInfo.td:885
    ERTN                                  = 604, // LoongArchInstrInfo.td:2593
    EXT_W_B                               = 605, // LoongArchInstrInfo.td:966
    EXT_W_H                               = 606, // LoongArchInstrInfo.td:967
    FABS_D                                = 607, // LoongArchFloat64InstrInfo.td:48
    FABS_S                                = 608, // LoongArchFloat32InstrInfo.td:69
    FADD_D                                = 609, // LoongArchFloat64InstrInfo.td:36
    FADD_S                                = 610, // LoongArchFloat32InstrInfo.td:57
    FCLASS_D                              = 611, // LoongArchFloat64InstrInfo.td:58
    FCLASS_S                              = 612, // LoongArchFloat32InstrInfo.td:79
    FCMP_CAF_D                            = 613, // LoongArchFloat64InstrInfo.td:61
    FCMP_CAF_S                            = 614, // LoongArchFloat32InstrInfo.td:83
    FCMP_CEQ_D                            = 615, // LoongArchFloat64InstrInfo.td:63
    FCMP_CEQ_S                            = 616, // LoongArchFloat32InstrInfo.td:85
    FCMP_CLE_D                            = 617, // LoongArchFloat64InstrInfo.td:67
    FCMP_CLE_S                            = 618, // LoongArchFloat32InstrInfo.td:89
    FCMP_CLT_D                            = 619, // LoongArchFloat64InstrInfo.td:65
    FCMP_CLT_S                            = 620, // LoongArchFloat32InstrInfo.td:87
    FCMP_CNE_D                            = 621, // LoongArchFloat64InstrInfo.td:69
    FCMP_CNE_S                            = 622, // LoongArchFloat32InstrInfo.td:91
    FCMP_COR_D                            = 623, // LoongArchFloat64InstrInfo.td:70
    FCMP_COR_S                            = 624, // LoongArchFloat32InstrInfo.td:92
    FCMP_CUEQ_D                           = 625, // LoongArchFloat64InstrInfo.td:64
    FCMP_CUEQ_S                           = 626, // LoongArchFloat32InstrInfo.td:86
    FCMP_CULE_D                           = 627, // LoongArchFloat64InstrInfo.td:68
    FCMP_CULE_S                           = 628, // LoongArchFloat32InstrInfo.td:90
    FCMP_CULT_D                           = 629, // LoongArchFloat64InstrInfo.td:66
    FCMP_CULT_S                           = 630, // LoongArchFloat32InstrInfo.td:88
    FCMP_CUNE_D                           = 631, // LoongArchFloat64InstrInfo.td:71
    FCMP_CUNE_S                           = 632, // LoongArchFloat32InstrInfo.td:93
    FCMP_CUN_D                            = 633, // LoongArchFloat64InstrInfo.td:62
    FCMP_CUN_S                            = 634, // LoongArchFloat32InstrInfo.td:84
    FCMP_SAF_D                            = 635, // LoongArchFloat64InstrInfo.td:72
    FCMP_SAF_S                            = 636, // LoongArchFloat32InstrInfo.td:94
    FCMP_SEQ_D                            = 637, // LoongArchFloat64InstrInfo.td:74
    FCMP_SEQ_S                            = 638, // LoongArchFloat32InstrInfo.td:96
    FCMP_SLE_D                            = 639, // LoongArchFloat64InstrInfo.td:78
    FCMP_SLE_S                            = 640, // LoongArchFloat32InstrInfo.td:100
    FCMP_SLT_D                            = 641, // LoongArchFloat64InstrInfo.td:76
    FCMP_SLT_S                            = 642, // LoongArchFloat32InstrInfo.td:98
    FCMP_SNE_D                            = 643, // LoongArchFloat64InstrInfo.td:80
    FCMP_SNE_S                            = 644, // LoongArchFloat32InstrInfo.td:102
    FCMP_SOR_D                            = 645, // LoongArchFloat64InstrInfo.td:81
    FCMP_SOR_S                            = 646, // LoongArchFloat32InstrInfo.td:103
    FCMP_SUEQ_D                           = 647, // LoongArchFloat64InstrInfo.td:75
    FCMP_SUEQ_S                           = 648, // LoongArchFloat32InstrInfo.td:97
    FCMP_SULE_D                           = 649, // LoongArchFloat64InstrInfo.td:79
    FCMP_SULE_S                           = 650, // LoongArchFloat32InstrInfo.td:101
    FCMP_SULT_D                           = 651, // LoongArchFloat64InstrInfo.td:77
    FCMP_SULT_S                           = 652, // LoongArchFloat32InstrInfo.td:99
    FCMP_SUNE_D                           = 653, // LoongArchFloat64InstrInfo.td:82
    FCMP_SUNE_S                           = 654, // LoongArchFloat32InstrInfo.td:104
    FCMP_SUN_D                            = 655, // LoongArchFloat64InstrInfo.td:73
    FCMP_SUN_S                            = 656, // LoongArchFloat32InstrInfo.td:95
    FCOPYSIGN_D                           = 657, // LoongArchFloat64InstrInfo.td:57
    FCOPYSIGN_S                           = 658, // LoongArchFloat32InstrInfo.td:78
    FCVT_D_LD                             = 659, // LoongArchLBTInstrInfo.td:51
    FCVT_D_S                              = 660, // LoongArchFloat64InstrInfo.td:92
    FCVT_LD_D                             = 661, // LoongArchLBTInstrInfo.td:50
    FCVT_S_D                              = 662, // LoongArchFloat64InstrInfo.td:91
    FCVT_UD_D                             = 663, // LoongArchLBTInstrInfo.td:49
    FDIV_D                                = 664, // LoongArchFloat64InstrInfo.td:39
    FDIV_S                                = 665, // LoongArchFloat32InstrInfo.td:60
    FFINT_D_L                             = 666, // LoongArchFloat64InstrInfo.td:94
    FFINT_D_W                             = 667, // LoongArchFloat64InstrInfo.td:93
    FFINT_S_L                             = 668, // LoongArchFloat64InstrInfo.td:85
    FFINT_S_W                             = 669, // LoongArchFloat32InstrInfo.td:107
    FLDGT_D                               = 670, // LoongArchFloat64InstrInfo.td:127
    FLDGT_S                               = 671, // LoongArchFloat32InstrInfo.td:140
    FLDLE_D                               = 672, // LoongArchFloat64InstrInfo.td:128
    FLDLE_S                               = 673, // LoongArchFloat32InstrInfo.td:141
    FLDX_D                                = 674, // LoongArchFloat64InstrInfo.td:123
    FLDX_S                                = 675, // LoongArchFloat32InstrInfo.td:136
    FLD_D                                 = 676, // LoongArchFloat64InstrInfo.td:121
    FLD_S                                 = 677, // LoongArchFloat32InstrInfo.td:134
    FLOGB_D                               = 678, // LoongArchFloat64InstrInfo.td:56
    FLOGB_S                               = 679, // LoongArchFloat32InstrInfo.td:77
    FMADD_D                               = 680, // LoongArchFloat64InstrInfo.td:40
    FMADD_S                               = 681, // LoongArchFloat32InstrInfo.td:61
    FMAXA_D                               = 682, // LoongArchFloat64InstrInfo.td:46
    FMAXA_S                               = 683, // LoongArchFloat32InstrInfo.td:67
    FMAX_D                                = 684, // LoongArchFloat64InstrInfo.td:44
    FMAX_S                                = 685, // LoongArchFloat32InstrInfo.td:65
    FMINA_D                               = 686, // LoongArchFloat64InstrInfo.td:47
    FMINA_S                               = 687, // LoongArchFloat32InstrInfo.td:68
    FMIN_D                                = 688, // LoongArchFloat64InstrInfo.td:45
    FMIN_S                                = 689, // LoongArchFloat32InstrInfo.td:66
    FMOV_D                                = 690, // LoongArchFloat64InstrInfo.td:108
    FMOV_S                                = 691, // LoongArchFloat32InstrInfo.td:117
    FMSUB_D                               = 692, // LoongArchFloat64InstrInfo.td:41
    FMSUB_S                               = 693, // LoongArchFloat32InstrInfo.td:62
    FMUL_D                                = 694, // LoongArchFloat64InstrInfo.td:38
    FMUL_S                                = 695, // LoongArchFloat32InstrInfo.td:59
    FNEG_D                                = 696, // LoongArchFloat64InstrInfo.td:49
    FNEG_S                                = 697, // LoongArchFloat32InstrInfo.td:70
    FNMADD_D                              = 698, // LoongArchFloat64InstrInfo.td:42
    FNMADD_S                              = 699, // LoongArchFloat32InstrInfo.td:63
    FNMSUB_D                              = 700, // LoongArchFloat64InstrInfo.td:43
    FNMSUB_S                              = 701, // LoongArchFloat32InstrInfo.td:64
    FRECIPE_D                             = 702, // LoongArchFloat64InstrInfo.td:53
    FRECIPE_S                             = 703, // LoongArchFloat32InstrInfo.td:74
    FRECIP_D                              = 704, // LoongArchFloat64InstrInfo.td:51
    FRECIP_S                              = 705, // LoongArchFloat32InstrInfo.td:72
    FRINT_D                               = 706, // LoongArchFloat64InstrInfo.td:105
    FRINT_S                               = 707, // LoongArchFloat32InstrInfo.td:113
    FRSQRTE_D                             = 708, // LoongArchFloat64InstrInfo.td:54
    FRSQRTE_S                             = 709, // LoongArchFloat32InstrInfo.td:75
    FRSQRT_D                              = 710, // LoongArchFloat64InstrInfo.td:52
    FRSQRT_S                              = 711, // LoongArchFloat32InstrInfo.td:73
    FSCALEB_D                             = 712, // LoongArchFloat64InstrInfo.td:55
    FSCALEB_S                             = 713, // LoongArchFloat32InstrInfo.td:76
    FSEL_xD                               = 714, // LoongArchFloat64InstrInfo.td:112
    FSEL_xS                               = 715, // LoongArchFloat32InstrInfo.td:116
    FSQRT_D                               = 716, // LoongArchFloat64InstrInfo.td:50
    FSQRT_S                               = 717, // LoongArchFloat32InstrInfo.td:71
    FSTGT_D                               = 718, // LoongArchFloat64InstrInfo.td:129
    FSTGT_S                               = 719, // LoongArchFloat32InstrInfo.td:142
    FSTLE_D                               = 720, // LoongArchFloat64InstrInfo.td:130
    FSTLE_S                               = 721, // LoongArchFloat32InstrInfo.td:143
    FSTX_D                                = 722, // LoongArchFloat64InstrInfo.td:124
    FSTX_S                                = 723, // LoongArchFloat32InstrInfo.td:137
    FST_D                                 = 724, // LoongArchFloat64InstrInfo.td:122
    FST_S                                 = 725, // LoongArchFloat32InstrInfo.td:135
    FSUB_D                                = 726, // LoongArchFloat64InstrInfo.td:37
    FSUB_S                                = 727, // LoongArchFloat32InstrInfo.td:58
    FTINTRM_L_D                           = 728, // LoongArchFloat64InstrInfo.td:98
    FTINTRM_L_S                           = 729, // LoongArchFloat64InstrInfo.td:87
    FTINTRM_W_D                           = 730, // LoongArchFloat64InstrInfo.td:97
    FTINTRM_W_S                           = 731, // LoongArchFloat32InstrInfo.td:109
    FTINTRNE_L_D                          = 732, // LoongArchFloat64InstrInfo.td:104
    FTINTRNE_L_S                          = 733, // LoongArchFloat64InstrInfo.td:90
    FTINTRNE_W_D                          = 734, // LoongArchFloat64InstrInfo.td:103
    FTINTRNE_W_S                          = 735, // LoongArchFloat32InstrInfo.td:112
    FTINTRP_L_D                           = 736, // LoongArchFloat64InstrInfo.td:100
    FTINTRP_L_S                           = 737, // LoongArchFloat64InstrInfo.td:88
    FTINTRP_W_D                           = 738, // LoongArchFloat64InstrInfo.td:99
    FTINTRP_W_S                           = 739, // LoongArchFloat32InstrInfo.td:110
    FTINTRZ_L_D                           = 740, // LoongArchFloat64InstrInfo.td:102
    FTINTRZ_L_S                           = 741, // LoongArchFloat64InstrInfo.td:89
    FTINTRZ_W_D                           = 742, // LoongArchFloat64InstrInfo.td:101
    FTINTRZ_W_S                           = 743, // LoongArchFloat32InstrInfo.td:111
    FTINT_L_D                             = 744, // LoongArchFloat64InstrInfo.td:96
    FTINT_L_S                             = 745, // LoongArchFloat64InstrInfo.td:86
    FTINT_W_D                             = 746, // LoongArchFloat64InstrInfo.td:95
    FTINT_W_S                             = 747, // LoongArchFloat32InstrInfo.td:108
    GCSRRD                                = 748, // LoongArchLVZInstrInfo.td:19
    GCSRWR                                = 749, // LoongArchLVZInstrInfo.td:23
    GCSRXCHG                              = 750, // LoongArchLVZInstrInfo.td:25
    GTLBFLUSH                             = 751, // LoongArchLVZInstrInfo.td:30
    HVCL                                  = 752, // LoongArchLVZInstrInfo.td:31
    IBAR                                  = 753, // LoongArchInstrInfo.td:932
    IDLE                                  = 754, // LoongArchInstrInfo.td:2595
    INVTLB                                = 755, // LoongArchInstrInfo.td:2581
    IOCSRRD_B                             = 756, // LoongArchInstrInfo.td:2562
    IOCSRRD_D                             = 757, // LoongArchInstrInfo.td:2569
    IOCSRRD_H                             = 758, // LoongArchInstrInfo.td:2563
    IOCSRRD_W                             = 759, // LoongArchInstrInfo.td:2564
    IOCSRWR_B                             = 760, // LoongArchInstrInfo.td:2565
    IOCSRWR_D                             = 761, // LoongArchInstrInfo.td:2570
    IOCSRWR_H                             = 762, // LoongArchInstrInfo.td:2566
    IOCSRWR_W                             = 763, // LoongArchInstrInfo.td:2567
    JIRL                                  = 764, // LoongArchInstrInfo.td:910
    JISCR0                                = 765, // LoongArchLBTInstrInfo.td:22
    JISCR1                                = 766, // LoongArchLBTInstrInfo.td:23
    LDDIR                                 = 767, // LoongArchInstrInfo.td:2586
    LDGT_B                                = 768, // LoongArchInstrInfo.td:1087
    LDGT_D                                = 769, // LoongArchInstrInfo.td:1090
    LDGT_H                                = 770, // LoongArchInstrInfo.td:1088
    LDGT_W                                = 771, // LoongArchInstrInfo.td:1089
    LDLE_B                                = 772, // LoongArchInstrInfo.td:1091
    LDLE_D                                = 773, // LoongArchInstrInfo.td:1094
    LDLE_H                                = 774, // LoongArchInstrInfo.td:1092
    LDLE_W                                = 775, // LoongArchInstrInfo.td:1093
    LDL_D                                 = 776, // LoongArchLBTInstrInfo.td:199
    LDL_W                                 = 777, // LoongArchLBTInstrInfo.td:54
    LDPTE                                 = 778, // LoongArchInstrInfo.td:2588
    LDPTR_D                               = 779, // LoongArchInstrInfo.td:1079
    LDPTR_W                               = 780, // LoongArchInstrInfo.td:1078
    LDR_D                                 = 781, // LoongArchLBTInstrInfo.td:200
    LDR_W                                 = 782, // LoongArchLBTInstrInfo.td:55
    LDX_B                                 = 783, // LoongArchInstrInfo.td:1067
    LDX_BU                                = 784, // LoongArchInstrInfo.td:1071
    LDX_D                                 = 785, // LoongArchInstrInfo.td:1070
    LDX_H                                 = 786, // LoongArchInstrInfo.td:1068
    LDX_HU                                = 787, // LoongArchInstrInfo.td:1072
    LDX_W                                 = 788, // LoongArchInstrInfo.td:1069
    LDX_WU                                = 789, // LoongArchInstrInfo.td:1073
    LD_B                                  = 790, // LoongArchInstrInfo.td:914
    LD_BU                                 = 791, // LoongArchInstrInfo.td:917
    LD_D                                  = 792, // LoongArchInstrInfo.td:1065
    LD_H                                  = 793, // LoongArchInstrInfo.td:915
    LD_HU                                 = 794, // LoongArchInstrInfo.td:918
    LD_W                                  = 795, // LoongArchInstrInfo.td:916
    LD_WU                                 = 796, // LoongArchInstrInfo.td:1064
    LLACQ_D                               = 797, // LoongArchInstrInfo.td:1162
    LLACQ_W                               = 798, // LoongArchInstrInfo.td:1160
    LL_D                                  = 799, // LoongArchInstrInfo.td:1157
    LL_W                                  = 800, // LoongArchInstrInfo.td:927
    LU12I_W                               = 801, // LoongArchInstrInfo.td:862
    LU32I_D                               = 802, // LoongArchInstrInfo.td:1011
    LU52I_D                               = 803, // LoongArchInstrInfo.td:1016
    MASKEQZ                               = 804, // LoongArchInstrInfo.td:984
    MASKNEZ                               = 805, // LoongArchInstrInfo.td:985
    MOD_D                                 = 806, // LoongArchInstrInfo.td:1026
    MOD_DU                                = 807, // LoongArchInstrInfo.td:1028
    MOD_W                                 = 808, // LoongArchInstrInfo.td:884
    MOD_WU                                = 809, // LoongArchInstrInfo.td:886
    MOVCF2FR_xS                           = 810, // LoongArchFloat32InstrInfo.td:125
    MOVCF2GR                              = 811, // LoongArchFloat32InstrInfo.td:127
    MOVFCSR2GR                            = 812, // LoongArchFloat32InstrInfo.td:122
    MOVFR2CF_xS                           = 813, // LoongArchFloat32InstrInfo.td:124
    MOVFR2GR_D                            = 814, // LoongArchFloat64InstrInfo.td:137
    MOVFR2GR_S                            = 815, // LoongArchFloat32InstrInfo.td:119
    MOVFR2GR_S_64                         = 816, // LoongArchFloat64InstrInfo.td:111
    MOVFRH2GR_S                           = 817, // LoongArchFloat64InstrInfo.td:109
    MOVGR2CF                              = 818, // LoongArchFloat32InstrInfo.td:126
    MOVGR2FCSR                            = 819, // LoongArchFloat32InstrInfo.td:121
    MOVGR2FRH_W                           = 820, // LoongArchFloat64InstrInfo.td:115
    MOVGR2FR_D                            = 821, // LoongArchFloat64InstrInfo.td:136
    MOVGR2FR_W                            = 822, // LoongArchFloat32InstrInfo.td:118
    MOVGR2FR_W_64                         = 823, // LoongArchFloat64InstrInfo.td:142
    MOVGR2SCR                             = 824, // LoongArchLBTInstrInfo.td:19
    MOVSCR2GR                             = 825, // LoongArchLBTInstrInfo.td:20
    MULH_D                                = 826, // LoongArchInstrInfo.td:1020
    MULH_DU                               = 827, // LoongArchInstrInfo.td:1021
    MULH_W                                = 828, // LoongArchInstrInfo.td:880
    MULH_WU                               = 829, // LoongArchInstrInfo.td:881
    MULW_D_W                              = 830, // LoongArchInstrInfo.td:1022
    MULW_D_WU                             = 831, // LoongArchInstrInfo.td:1023
    MUL_D                                 = 832, // LoongArchInstrInfo.td:1019
    MUL_W                                 = 833, // LoongArchInstrInfo.td:879
    NOR                                   = 834, // LoongArchInstrInfo.td:871
    OR                                    = 835, // LoongArchInstrInfo.td:870
    ORI                                   = 836, // LoongArchInstrInfo.td:876
    ORN                                   = 837, // LoongArchInstrInfo.td:957
    PCADDI                                = 838, // LoongArchInstrInfo.td:958
    PCADDU12I                             = 839, // LoongArchInstrInfo.td:868
    PCADDU18I                             = 840, // LoongArchInstrInfo.td:1018
    PCALAU12I                             = 841, // LoongArchInstrInfo.td:959
    PRELD                                 = 842, // LoongArchInstrInfo.td:923
    PRELDX                                = 843, // LoongArchInstrInfo.td:1083
    RCRI_B                                = 844, // LoongArchLBTInstrInfo.td:45
    RCRI_D                                = 845, // LoongArchLBTInstrInfo.td:195
    RCRI_H                                = 846, // LoongArchLBTInstrInfo.td:46
    RCRI_W                                = 847, // LoongArchLBTInstrInfo.td:47
    RCR_B                                 = 848, // LoongArchLBTInstrInfo.td:41
    RCR_D                                 = 849, // LoongArchLBTInstrInfo.td:194
    RCR_H                                 = 850, // LoongArchLBTInstrInfo.td:42
    RCR_W                                 = 851, // LoongArchLBTInstrInfo.td:43
    RDTIMEH_W                             = 852, // LoongArchInstrInfo.td:938
    RDTIMEL_W                             = 853, // LoongArchInstrInfo.td:937
    RDTIME_D                              = 854, // LoongArchInstrInfo.td:1180
    REVB_2H                               = 855, // LoongArchInstrInfo.td:973
    REVB_2W                               = 856, // LoongArchInstrInfo.td:1048
    REVB_4H                               = 857, // LoongArchInstrInfo.td:1047
    REVB_D                                = 858, // LoongArchInstrInfo.td:1049
    REVH_2W                               = 859, // LoongArchInstrInfo.td:1050
    REVH_D                                = 860, // LoongArchInstrInfo.td:1051
    ROTRI_B                               = 861, // LoongArchLBTInstrInfo.td:38
    ROTRI_D                               = 862, // LoongArchInstrInfo.td:1039
    ROTRI_H                               = 863, // LoongArchLBTInstrInfo.td:39
    ROTRI_W                               = 864, // LoongArchInstrInfo.td:963
    ROTR_B                                = 865, // LoongArchLBTInstrInfo.td:35
    ROTR_D                                = 866, // LoongArchInstrInfo.td:1035
    ROTR_H                                = 867, // LoongArchLBTInstrInfo.td:36
    ROTR_W                                = 868, // LoongArchInstrInfo.td:962
    SBC_B                                 = 869, // LoongArchLBTInstrInfo.td:31
    SBC_D                                 = 870, // LoongArchLBTInstrInfo.td:193
    SBC_H                                 = 871, // LoongArchLBTInstrInfo.td:32
    SBC_W                                 = 872, // LoongArchLBTInstrInfo.td:33
    SCREL_D                               = 873, // LoongArchInstrInfo.td:1163
    SCREL_W                               = 874, // LoongArchInstrInfo.td:1161
    SC_D                                  = 875, // LoongArchInstrInfo.td:1158
    SC_Q                                  = 876, // LoongArchInstrInfo.td:1159
    SC_W                                  = 877, // LoongArchInstrInfo.td:928
    SETARMJ                               = 878, // LoongArchLBTInstrInfo.td:188
    SETX86J                               = 879, // LoongArchLBTInstrInfo.td:152
    SETX86LOOPE                           = 880, // LoongArchLBTInstrInfo.td:153
    SETX86LOOPNE                          = 881, // LoongArchLBTInstrInfo.td:154
    SET_CFR_FALSE                         = 882, // LoongArchFloat32InstrInfo.td:157
    SET_CFR_TRUE                          = 883, // LoongArchFloat32InstrInfo.td:159
    SLLI_D                                = 884, // LoongArchInstrInfo.td:1036
    SLLI_W                                = 885, // LoongArchInstrInfo.td:894
    SLL_D                                 = 886, // LoongArchInstrInfo.td:1032
    SLL_W                                 = 887, // LoongArchInstrInfo.td:890
    SLT                                   = 888, // LoongArchInstrInfo.td:864
    SLTI                                  = 889, // LoongArchInstrInfo.td:866
    SLTU                                  = 890, // LoongArchInstrInfo.td:865
    SLTUI                                 = 891, // LoongArchInstrInfo.td:867
    SRAI_D                                = 892, // LoongArchInstrInfo.td:1038
    SRAI_W                                = 893, // LoongArchInstrInfo.td:896
    SRA_D                                 = 894, // LoongArchInstrInfo.td:1034
    SRA_W                                 = 895, // LoongArchInstrInfo.td:892
    SRLI_D                                = 896, // LoongArchInstrInfo.td:1037
    SRLI_W                                = 897, // LoongArchInstrInfo.td:895
    SRL_D                                 = 898, // LoongArchInstrInfo.td:1033
    SRL_W                                 = 899, // LoongArchInstrInfo.td:891
    STGT_B                                = 900, // LoongArchInstrInfo.td:1095
    STGT_D                                = 901, // LoongArchInstrInfo.td:1098
    STGT_H                                = 902, // LoongArchInstrInfo.td:1096
    STGT_W                                = 903, // LoongArchInstrInfo.td:1097
    STLE_B                                = 904, // LoongArchInstrInfo.td:1099
    STLE_D                                = 905, // LoongArchInstrInfo.td:1102
    STLE_H                                = 906, // LoongArchInstrInfo.td:1100
    STLE_W                                = 907, // LoongArchInstrInfo.td:1101
    STL_D                                 = 908, // LoongArchLBTInstrInfo.td:204
    STL_W                                 = 909, // LoongArchLBTInstrInfo.td:59
    STPTR_D                               = 910, // LoongArchInstrInfo.td:1081
    STPTR_W                               = 911, // LoongArchInstrInfo.td:1080
    STR_D                                 = 912, // LoongArchLBTInstrInfo.td:205
    STR_W                                 = 913, // LoongArchLBTInstrInfo.td:60
    STX_B                                 = 914, // LoongArchInstrInfo.td:1074
    STX_D                                 = 915, // LoongArchInstrInfo.td:1077
    STX_H                                 = 916, // LoongArchInstrInfo.td:1075
    STX_W                                 = 917, // LoongArchInstrInfo.td:1076
    ST_B                                  = 918, // LoongArchInstrInfo.td:919
    ST_D                                  = 919, // LoongArchInstrInfo.td:1066
    ST_H                                  = 920, // LoongArchInstrInfo.td:920
    ST_W                                  = 921, // LoongArchInstrInfo.td:921
    SUB_D                                 = 922, // LoongArchInstrInfo.td:998
    SUB_W                                 = 923, // LoongArchInstrInfo.td:859
    SYSCALL                               = 924, // LoongArchInstrInfo.td:935
    TLBCLR                                = 925, // LoongArchInstrInfo.td:2579
    TLBFILL                               = 926, // LoongArchInstrInfo.td:2578
    TLBFLUSH                              = 927, // LoongArchInstrInfo.td:2580
    TLBRD                                 = 928, // LoongArchInstrInfo.td:2576
    TLBSRCH                               = 929, // LoongArchInstrInfo.td:2575
    TLBWR                                 = 930, // LoongArchInstrInfo.td:2577
    UD                                    = 931, // LoongArchInstrInfo.td:941
    VABSD_B                               = 932, // LoongArchLSXInstrInfo.td:616
    VABSD_BU                              = 933, // LoongArchLSXInstrInfo.td:620
    VABSD_D                               = 934, // LoongArchLSXInstrInfo.td:619
    VABSD_DU                              = 935, // LoongArchLSXInstrInfo.td:623
    VABSD_H                               = 936, // LoongArchLSXInstrInfo.td:617
    VABSD_HU                              = 937, // LoongArchLSXInstrInfo.td:621
    VABSD_W                               = 938, // LoongArchLSXInstrInfo.td:618
    VABSD_WU                              = 939, // LoongArchLSXInstrInfo.td:622
    VADDA_B                               = 940, // LoongArchLSXInstrInfo.td:625
    VADDA_D                               = 941, // LoongArchLSXInstrInfo.td:628
    VADDA_H                               = 942, // LoongArchLSXInstrInfo.td:626
    VADDA_W                               = 943, // LoongArchLSXInstrInfo.td:627
    VADDI_BU                              = 944, // LoongArchLSXInstrInfo.td:503
    VADDI_DU                              = 945, // LoongArchLSXInstrInfo.td:506
    VADDI_HU                              = 946, // LoongArchLSXInstrInfo.td:504
    VADDI_WU                              = 947, // LoongArchLSXInstrInfo.td:505
    VADDWEV_D_W                           = 948, // LoongArchLSXInstrInfo.td:556
    VADDWEV_D_WU                          = 949, // LoongArchLSXInstrInfo.td:574
    VADDWEV_D_WU_W                        = 950, // LoongArchLSXInstrInfo.td:592
    VADDWEV_H_B                           = 951, // LoongArchLSXInstrInfo.td:554
    VADDWEV_H_BU                          = 952, // LoongArchLSXInstrInfo.td:572
    VADDWEV_H_BU_B                        = 953, // LoongArchLSXInstrInfo.td:590
    VADDWEV_Q_D                           = 954, // LoongArchLSXInstrInfo.td:557
    VADDWEV_Q_DU                          = 955, // LoongArchLSXInstrInfo.td:575
    VADDWEV_Q_DU_D                        = 956, // LoongArchLSXInstrInfo.td:593
    VADDWEV_W_H                           = 957, // LoongArchLSXInstrInfo.td:555
    VADDWEV_W_HU                          = 958, // LoongArchLSXInstrInfo.td:573
    VADDWEV_W_HU_H                        = 959, // LoongArchLSXInstrInfo.td:591
    VADDWOD_D_W                           = 960, // LoongArchLSXInstrInfo.td:560
    VADDWOD_D_WU                          = 961, // LoongArchLSXInstrInfo.td:578
    VADDWOD_D_WU_W                        = 962, // LoongArchLSXInstrInfo.td:596
    VADDWOD_H_B                           = 963, // LoongArchLSXInstrInfo.td:558
    VADDWOD_H_BU                          = 964, // LoongArchLSXInstrInfo.td:576
    VADDWOD_H_BU_B                        = 965, // LoongArchLSXInstrInfo.td:594
    VADDWOD_Q_D                           = 966, // LoongArchLSXInstrInfo.td:561
    VADDWOD_Q_DU                          = 967, // LoongArchLSXInstrInfo.td:579
    VADDWOD_Q_DU_D                        = 968, // LoongArchLSXInstrInfo.td:597
    VADDWOD_W_H                           = 969, // LoongArchLSXInstrInfo.td:559
    VADDWOD_W_HU                          = 970, // LoongArchLSXInstrInfo.td:577
    VADDWOD_W_HU_H                        = 971, // LoongArchLSXInstrInfo.td:595
    VADD_B                                = 972, // LoongArchLSXInstrInfo.td:491
    VADD_D                                = 973, // LoongArchLSXInstrInfo.td:494
    VADD_H                                = 974, // LoongArchLSXInstrInfo.td:492
    VADD_Q                                = 975, // LoongArchLSXInstrInfo.td:495
    VADD_W                                = 976, // LoongArchLSXInstrInfo.td:493
    VANDI_B                               = 977, // LoongArchLSXInstrInfo.td:799
    VANDN_V                               = 978, // LoongArchLSXInstrInfo.td:796
    VAND_V                                = 979, // LoongArchLSXInstrInfo.td:792
    VAVGR_B                               = 980, // LoongArchLSXInstrInfo.td:607
    VAVGR_BU                              = 981, // LoongArchLSXInstrInfo.td:611
    VAVGR_D                               = 982, // LoongArchLSXInstrInfo.td:610
    VAVGR_DU                              = 983, // LoongArchLSXInstrInfo.td:614
    VAVGR_H                               = 984, // LoongArchLSXInstrInfo.td:608
    VAVGR_HU                              = 985, // LoongArchLSXInstrInfo.td:612
    VAVGR_W                               = 986, // LoongArchLSXInstrInfo.td:609
    VAVGR_WU                              = 987, // LoongArchLSXInstrInfo.td:613
    VAVG_B                                = 988, // LoongArchLSXInstrInfo.td:599
    VAVG_BU                               = 989, // LoongArchLSXInstrInfo.td:603
    VAVG_D                                = 990, // LoongArchLSXInstrInfo.td:602
    VAVG_DU                               = 991, // LoongArchLSXInstrInfo.td:606
    VAVG_H                                = 992, // LoongArchLSXInstrInfo.td:600
    VAVG_HU                               = 993, // LoongArchLSXInstrInfo.td:604
    VAVG_W                                = 994, // LoongArchLSXInstrInfo.td:601
    VAVG_WU                               = 995, // LoongArchLSXInstrInfo.td:605
    VBITCLRI_B                            = 996, // LoongArchLSXInstrInfo.td:977
    VBITCLRI_D                            = 997, // LoongArchLSXInstrInfo.td:980
    VBITCLRI_H                            = 998, // LoongArchLSXInstrInfo.td:978
    VBITCLRI_W                            = 999, // LoongArchLSXInstrInfo.td:979
    VBITCLR_B                             = 1000, // LoongArchLSXInstrInfo.td:973
    VBITCLR_D                             = 1001, // LoongArchLSXInstrInfo.td:976
    VBITCLR_H                             = 1002, // LoongArchLSXInstrInfo.td:974
    VBITCLR_W                             = 1003, // LoongArchLSXInstrInfo.td:975
    VBITREVI_B                            = 1004, // LoongArchLSXInstrInfo.td:995
    VBITREVI_D                            = 1005, // LoongArchLSXInstrInfo.td:998
    VBITREVI_H                            = 1006, // LoongArchLSXInstrInfo.td:996
    VBITREVI_W                            = 1007, // LoongArchLSXInstrInfo.td:997
    VBITREV_B                             = 1008, // LoongArchLSXInstrInfo.td:991
    VBITREV_D                             = 1009, // LoongArchLSXInstrInfo.td:994
    VBITREV_H                             = 1010, // LoongArchLSXInstrInfo.td:992
    VBITREV_W                             = 1011, // LoongArchLSXInstrInfo.td:993
    VBITSELI_B                            = 1012, // LoongArchLSXInstrInfo.td:1201
    VBITSEL_V                             = 1013, // LoongArchLSXInstrInfo.td:1199
    VBITSETI_B                            = 1014, // LoongArchLSXInstrInfo.td:986
    VBITSETI_D                            = 1015, // LoongArchLSXInstrInfo.td:989
    VBITSETI_H                            = 1016, // LoongArchLSXInstrInfo.td:987
    VBITSETI_W                            = 1017, // LoongArchLSXInstrInfo.td:988
    VBITSET_B                             = 1018, // LoongArchLSXInstrInfo.td:982
    VBITSET_D                             = 1019, // LoongArchLSXInstrInfo.td:985
    VBITSET_H                             = 1020, // LoongArchLSXInstrInfo.td:983
    VBITSET_W                             = 1021, // LoongArchLSXInstrInfo.td:984
    VBSLL_V                               = 1022, // LoongArchLSXInstrInfo.td:1243
    VBSRL_V                               = 1023, // LoongArchLSXInstrInfo.td:1244
    VCLO_B                                = 1024, // LoongArchLSXInstrInfo.td:959
    VCLO_D                                = 1025, // LoongArchLSXInstrInfo.td:962
    VCLO_H                                = 1026, // LoongArchLSXInstrInfo.td:960
    VCLO_W                                = 1027, // LoongArchLSXInstrInfo.td:961
    VCLZ_B                                = 1028, // LoongArchLSXInstrInfo.td:963
    VCLZ_D                                = 1029, // LoongArchLSXInstrInfo.td:966
    VCLZ_H                                = 1030, // LoongArchLSXInstrInfo.td:964
    VCLZ_W                                = 1031, // LoongArchLSXInstrInfo.td:965
    VDIV_B                                = 1032, // LoongArchLSXInstrInfo.td:738
    VDIV_BU                               = 1033, // LoongArchLSXInstrInfo.td:742
    VDIV_D                                = 1034, // LoongArchLSXInstrInfo.td:741
    VDIV_DU                               = 1035, // LoongArchLSXInstrInfo.td:745
    VDIV_H                                = 1036, // LoongArchLSXInstrInfo.td:739
    VDIV_HU                               = 1037, // LoongArchLSXInstrInfo.td:743
    VDIV_W                                = 1038, // LoongArchLSXInstrInfo.td:740
    VDIV_WU                               = 1039, // LoongArchLSXInstrInfo.td:744
    VEXT2XV_DU_BU                         = 1040, // LoongArchLASXInstrInfo.td:518
    VEXT2XV_DU_HU                         = 1041, // LoongArchLASXInstrInfo.td:520
    VEXT2XV_DU_WU                         = 1042, // LoongArchLASXInstrInfo.td:521
    VEXT2XV_D_B                           = 1043, // LoongArchLASXInstrInfo.td:512
    VEXT2XV_D_H                           = 1044, // LoongArchLASXInstrInfo.td:514
    VEXT2XV_D_W                           = 1045, // LoongArchLASXInstrInfo.td:515
    VEXT2XV_HU_BU                         = 1046, // LoongArchLASXInstrInfo.td:516
    VEXT2XV_H_B                           = 1047, // LoongArchLASXInstrInfo.td:510
    VEXT2XV_WU_BU                         = 1048, // LoongArchLASXInstrInfo.td:517
    VEXT2XV_WU_HU                         = 1049, // LoongArchLASXInstrInfo.td:519
    VEXT2XV_W_B                           = 1050, // LoongArchLASXInstrInfo.td:511
    VEXT2XV_W_H                           = 1051, // LoongArchLASXInstrInfo.td:513
    VEXTH_DU_WU                           = 1052, // LoongArchLSXInstrInfo.td:771
    VEXTH_D_W                             = 1053, // LoongArchLSXInstrInfo.td:767
    VEXTH_HU_BU                           = 1054, // LoongArchLSXInstrInfo.td:769
    VEXTH_H_B                             = 1055, // LoongArchLSXInstrInfo.td:765
    VEXTH_QU_DU                           = 1056, // LoongArchLSXInstrInfo.td:772
    VEXTH_Q_D                             = 1057, // LoongArchLSXInstrInfo.td:768
    VEXTH_WU_HU                           = 1058, // LoongArchLSXInstrInfo.td:770
    VEXTH_W_H                             = 1059, // LoongArchLSXInstrInfo.td:766
    VEXTL_QU_DU                           = 1060, // LoongArchLSXInstrInfo.td:847
    VEXTL_Q_D                             = 1061, // LoongArchLSXInstrInfo.td:843
    VEXTRINS_B                            = 1062, // LoongArchLSXInstrInfo.td:1289
    VEXTRINS_D                            = 1063, // LoongArchLSXInstrInfo.td:1286
    VEXTRINS_H                            = 1064, // LoongArchLSXInstrInfo.td:1288
    VEXTRINS_W                            = 1065, // LoongArchLSXInstrInfo.td:1287
    VFADD_D                               = 1066, // LoongArchLSXInstrInfo.td:1006
    VFADD_S                               = 1067, // LoongArchLSXInstrInfo.td:1005
    VFCLASS_D                             = 1068, // LoongArchLSXInstrInfo.td:1037
    VFCLASS_S                             = 1069, // LoongArchLSXInstrInfo.td:1036
    VFCMP_CAF_D                           = 1070, // LoongArchLSXInstrInfo.td:1176
    VFCMP_CAF_S                           = 1071, // LoongArchLSXInstrInfo.td:1153
    VFCMP_CEQ_D                           = 1072, // LoongArchLSXInstrInfo.td:1180
    VFCMP_CEQ_S                           = 1073, // LoongArchLSXInstrInfo.td:1157
    VFCMP_CLE_D                           = 1074, // LoongArchLSXInstrInfo.td:1182
    VFCMP_CLE_S                           = 1075, // LoongArchLSXInstrInfo.td:1159
    VFCMP_CLT_D                           = 1076, // LoongArchLSXInstrInfo.td:1178
    VFCMP_CLT_S                           = 1077, // LoongArchLSXInstrInfo.td:1155
    VFCMP_CNE_D                           = 1078, // LoongArchLSXInstrInfo.td:1192
    VFCMP_CNE_S                           = 1079, // LoongArchLSXInstrInfo.td:1169
    VFCMP_COR_D                           = 1080, // LoongArchLSXInstrInfo.td:1194
    VFCMP_COR_S                           = 1081, // LoongArchLSXInstrInfo.td:1171
    VFCMP_CUEQ_D                          = 1082, // LoongArchLSXInstrInfo.td:1188
    VFCMP_CUEQ_S                          = 1083, // LoongArchLSXInstrInfo.td:1165
    VFCMP_CULE_D                          = 1084, // LoongArchLSXInstrInfo.td:1190
    VFCMP_CULE_S                          = 1085, // LoongArchLSXInstrInfo.td:1167
    VFCMP_CULT_D                          = 1086, // LoongArchLSXInstrInfo.td:1186
    VFCMP_CULT_S                          = 1087, // LoongArchLSXInstrInfo.td:1163
    VFCMP_CUNE_D                          = 1088, // LoongArchLSXInstrInfo.td:1196
    VFCMP_CUNE_S                          = 1089, // LoongArchLSXInstrInfo.td:1173
    VFCMP_CUN_D                           = 1090, // LoongArchLSXInstrInfo.td:1184
    VFCMP_CUN_S                           = 1091, // LoongArchLSXInstrInfo.td:1161
    VFCMP_SAF_D                           = 1092, // LoongArchLSXInstrInfo.td:1177
    VFCMP_SAF_S                           = 1093, // LoongArchLSXInstrInfo.td:1154
    VFCMP_SEQ_D                           = 1094, // LoongArchLSXInstrInfo.td:1181
    VFCMP_SEQ_S                           = 1095, // LoongArchLSXInstrInfo.td:1158
    VFCMP_SLE_D                           = 1096, // LoongArchLSXInstrInfo.td:1183
    VFCMP_SLE_S                           = 1097, // LoongArchLSXInstrInfo.td:1160
    VFCMP_SLT_D                           = 1098, // LoongArchLSXInstrInfo.td:1179
    VFCMP_SLT_S                           = 1099, // LoongArchLSXInstrInfo.td:1156
    VFCMP_SNE_D                           = 1100, // LoongArchLSXInstrInfo.td:1193
    VFCMP_SNE_S                           = 1101, // LoongArchLSXInstrInfo.td:1170
    VFCMP_SOR_D                           = 1102, // LoongArchLSXInstrInfo.td:1195
    VFCMP_SOR_S                           = 1103, // LoongArchLSXInstrInfo.td:1172
    VFCMP_SUEQ_D                          = 1104, // LoongArchLSXInstrInfo.td:1189
    VFCMP_SUEQ_S                          = 1105, // LoongArchLSXInstrInfo.td:1166
    VFCMP_SULE_D                          = 1106, // LoongArchLSXInstrInfo.td:1191
    VFCMP_SULE_S                          = 1107, // LoongArchLSXInstrInfo.td:1168
    VFCMP_SULT_D                          = 1108, // LoongArchLSXInstrInfo.td:1187
    VFCMP_SULT_S                          = 1109, // LoongArchLSXInstrInfo.td:1164
    VFCMP_SUNE_D                          = 1110, // LoongArchLSXInstrInfo.td:1197
    VFCMP_SUNE_S                          = 1111, // LoongArchLSXInstrInfo.td:1174
    VFCMP_SUN_D                           = 1112, // LoongArchLSXInstrInfo.td:1185
    VFCMP_SUN_S                           = 1113, // LoongArchLSXInstrInfo.td:1162
    VFCVTH_D_S                            = 1114, // LoongArchLSXInstrInfo.td:1053
    VFCVTH_S_H                            = 1115, // LoongArchLSXInstrInfo.td:1051
    VFCVTL_D_S                            = 1116, // LoongArchLSXInstrInfo.td:1052
    VFCVTL_S_H                            = 1117, // LoongArchLSXInstrInfo.td:1050
    VFCVT_H_S                             = 1118, // LoongArchLSXInstrInfo.td:1054
    VFCVT_S_D                             = 1119, // LoongArchLSXInstrInfo.td:1055
    VFDIV_D                               = 1120, // LoongArchLSXInstrInfo.td:1012
    VFDIV_S                               = 1121, // LoongArchLSXInstrInfo.td:1011
    VFFINTH_D_W                           = 1122, // LoongArchLSXInstrInfo.td:1105
    VFFINTL_D_W                           = 1123, // LoongArchLSXInstrInfo.td:1104
    VFFINT_D_L                            = 1124, // LoongArchLSXInstrInfo.td:1101
    VFFINT_D_LU                           = 1125, // LoongArchLSXInstrInfo.td:1103
    VFFINT_S_L                            = 1126, // LoongArchLSXInstrInfo.td:1106
    VFFINT_S_W                            = 1127, // LoongArchLSXInstrInfo.td:1100
    VFFINT_S_WU                           = 1128, // LoongArchLSXInstrInfo.td:1102
    VFLOGB_D                              = 1129, // LoongArchLSXInstrInfo.td:1034
    VFLOGB_S                              = 1130, // LoongArchLSXInstrInfo.td:1033
    VFMADD_D                              = 1131, // LoongArchLSXInstrInfo.td:1015
    VFMADD_S                              = 1132, // LoongArchLSXInstrInfo.td:1014
    VFMAXA_D                              = 1133, // LoongArchLSXInstrInfo.td:1029
    VFMAXA_S                              = 1134, // LoongArchLSXInstrInfo.td:1028
    VFMAX_D                               = 1135, // LoongArchLSXInstrInfo.td:1024
    VFMAX_S                               = 1136, // LoongArchLSXInstrInfo.td:1023
    VFMINA_D                              = 1137, // LoongArchLSXInstrInfo.td:1031
    VFMINA_S                              = 1138, // LoongArchLSXInstrInfo.td:1030
    VFMIN_D                               = 1139, // LoongArchLSXInstrInfo.td:1026
    VFMIN_S                               = 1140, // LoongArchLSXInstrInfo.td:1025
    VFMSUB_D                              = 1141, // LoongArchLSXInstrInfo.td:1017
    VFMSUB_S                              = 1142, // LoongArchLSXInstrInfo.td:1016
    VFMUL_D                               = 1143, // LoongArchLSXInstrInfo.td:1010
    VFMUL_S                               = 1144, // LoongArchLSXInstrInfo.td:1009
    VFNMADD_D                             = 1145, // LoongArchLSXInstrInfo.td:1019
    VFNMADD_S                             = 1146, // LoongArchLSXInstrInfo.td:1018
    VFNMSUB_D                             = 1147, // LoongArchLSXInstrInfo.td:1021
    VFNMSUB_S                             = 1148, // LoongArchLSXInstrInfo.td:1020
    VFRECIPE_D                            = 1149, // LoongArchLSXInstrInfo.td:1046
    VFRECIPE_S                            = 1150, // LoongArchLSXInstrInfo.td:1045
    VFRECIP_D                             = 1151, // LoongArchLSXInstrInfo.td:1042
    VFRECIP_S                             = 1152, // LoongArchLSXInstrInfo.td:1041
    VFRINTRM_D                            = 1153, // LoongArchLSXInstrInfo.td:1064
    VFRINTRM_S                            = 1154, // LoongArchLSXInstrInfo.td:1063
    VFRINTRNE_D                           = 1155, // LoongArchLSXInstrInfo.td:1058
    VFRINTRNE_S                           = 1156, // LoongArchLSXInstrInfo.td:1057
    VFRINTRP_D                            = 1157, // LoongArchLSXInstrInfo.td:1062
    VFRINTRP_S                            = 1158, // LoongArchLSXInstrInfo.td:1061
    VFRINTRZ_D                            = 1159, // LoongArchLSXInstrInfo.td:1060
    VFRINTRZ_S                            = 1160, // LoongArchLSXInstrInfo.td:1059
    VFRINT_D                              = 1161, // LoongArchLSXInstrInfo.td:1066
    VFRINT_S                              = 1162, // LoongArchLSXInstrInfo.td:1065
    VFRSQRTE_D                            = 1163, // LoongArchLSXInstrInfo.td:1048
    VFRSQRTE_S                            = 1164, // LoongArchLSXInstrInfo.td:1047
    VFRSQRT_D                             = 1165, // LoongArchLSXInstrInfo.td:1044
    VFRSQRT_S                             = 1166, // LoongArchLSXInstrInfo.td:1043
    VFRSTPI_B                             = 1167, // LoongArchLSXInstrInfo.td:1002
    VFRSTPI_H                             = 1168, // LoongArchLSXInstrInfo.td:1003
    VFRSTP_B                              = 1169, // LoongArchLSXInstrInfo.td:1000
    VFRSTP_H                              = 1170, // LoongArchLSXInstrInfo.td:1001
    VFSQRT_D                              = 1171, // LoongArchLSXInstrInfo.td:1040
    VFSQRT_S                              = 1172, // LoongArchLSXInstrInfo.td:1039
    VFSUB_D                               = 1173, // LoongArchLSXInstrInfo.td:1008
    VFSUB_S                               = 1174, // LoongArchLSXInstrInfo.td:1007
    VFTINTH_L_S                           = 1175, // LoongArchLSXInstrInfo.td:1098
    VFTINTL_L_S                           = 1176, // LoongArchLSXInstrInfo.td:1097
    VFTINTRMH_L_S                         = 1177, // LoongArchLSXInstrInfo.td:1096
    VFTINTRML_L_S                         = 1178, // LoongArchLSXInstrInfo.td:1095
    VFTINTRM_L_D                          = 1179, // LoongArchLSXInstrInfo.td:1075
    VFTINTRM_W_D                          = 1180, // LoongArchLSXInstrInfo.td:1086
    VFTINTRM_W_S                          = 1181, // LoongArchLSXInstrInfo.td:1074
    VFTINTRNEH_L_S                        = 1182, // LoongArchLSXInstrInfo.td:1090
    VFTINTRNEL_L_S                        = 1183, // LoongArchLSXInstrInfo.td:1089
    VFTINTRNE_L_D                         = 1184, // LoongArchLSXInstrInfo.td:1069
    VFTINTRNE_W_D                         = 1185, // LoongArchLSXInstrInfo.td:1083
    VFTINTRNE_W_S                         = 1186, // LoongArchLSXInstrInfo.td:1068
    VFTINTRPH_L_S                         = 1187, // LoongArchLSXInstrInfo.td:1094
    VFTINTRPL_L_S                         = 1188, // LoongArchLSXInstrInfo.td:1093
    VFTINTRP_L_D                          = 1189, // LoongArchLSXInstrInfo.td:1073
    VFTINTRP_W_D                          = 1190, // LoongArchLSXInstrInfo.td:1085
    VFTINTRP_W_S                          = 1191, // LoongArchLSXInstrInfo.td:1072
    VFTINTRZH_L_S                         = 1192, // LoongArchLSXInstrInfo.td:1092
    VFTINTRZL_L_S                         = 1193, // LoongArchLSXInstrInfo.td:1091
    VFTINTRZ_LU_D                         = 1194, // LoongArchLSXInstrInfo.td:1079
    VFTINTRZ_L_D                          = 1195, // LoongArchLSXInstrInfo.td:1071
    VFTINTRZ_WU_S                         = 1196, // LoongArchLSXInstrInfo.td:1078
    VFTINTRZ_W_D                          = 1197, // LoongArchLSXInstrInfo.td:1084
    VFTINTRZ_W_S                          = 1198, // LoongArchLSXInstrInfo.td:1070
    VFTINT_LU_D                           = 1199, // LoongArchLSXInstrInfo.td:1081
    VFTINT_L_D                            = 1200, // LoongArchLSXInstrInfo.td:1077
    VFTINT_WU_S                           = 1201, // LoongArchLSXInstrInfo.td:1080
    VFTINT_W_D                            = 1202, // LoongArchLSXInstrInfo.td:1087
    VFTINT_W_S                            = 1203, // LoongArchLSXInstrInfo.td:1076
    VHADDW_DU_WU                          = 1204, // LoongArchLSXInstrInfo.td:542
    VHADDW_D_W                            = 1205, // LoongArchLSXInstrInfo.td:538
    VHADDW_HU_BU                          = 1206, // LoongArchLSXInstrInfo.td:540
    VHADDW_H_B                            = 1207, // LoongArchLSXInstrInfo.td:536
    VHADDW_QU_DU                          = 1208, // LoongArchLSXInstrInfo.td:543
    VHADDW_Q_D                            = 1209, // LoongArchLSXInstrInfo.td:539
    VHADDW_WU_HU                          = 1210, // LoongArchLSXInstrInfo.td:541
    VHADDW_W_H                            = 1211, // LoongArchLSXInstrInfo.td:537
    VHSUBW_DU_WU                          = 1212, // LoongArchLSXInstrInfo.td:551
    VHSUBW_D_W                            = 1213, // LoongArchLSXInstrInfo.td:547
    VHSUBW_HU_BU                          = 1214, // LoongArchLSXInstrInfo.td:549
    VHSUBW_H_B                            = 1215, // LoongArchLSXInstrInfo.td:545
    VHSUBW_QU_DU                          = 1216, // LoongArchLSXInstrInfo.td:552
    VHSUBW_Q_D                            = 1217, // LoongArchLSXInstrInfo.td:548
    VHSUBW_WU_HU                          = 1218, // LoongArchLSXInstrInfo.td:550
    VHSUBW_W_H                            = 1219, // LoongArchLSXInstrInfo.td:546
    VILVH_B                               = 1220, // LoongArchLSXInstrInfo.td:1268
    VILVH_D                               = 1221, // LoongArchLSXInstrInfo.td:1271
    VILVH_H                               = 1222, // LoongArchLSXInstrInfo.td:1269
    VILVH_W                               = 1223, // LoongArchLSXInstrInfo.td:1270
    VILVL_B                               = 1224, // LoongArchLSXInstrInfo.td:1264
    VILVL_D                               = 1225, // LoongArchLSXInstrInfo.td:1267
    VILVL_H                               = 1226, // LoongArchLSXInstrInfo.td:1265
    VILVL_W                               = 1227, // LoongArchLSXInstrInfo.td:1266
    VINSGR2VR_B                           = 1228, // LoongArchLSXInstrInfo.td:1214
    VINSGR2VR_D                           = 1229, // LoongArchLSXInstrInfo.td:1217
    VINSGR2VR_H                           = 1230, // LoongArchLSXInstrInfo.td:1215
    VINSGR2VR_W                           = 1231, // LoongArchLSXInstrInfo.td:1216
    VLD                                   = 1232, // LoongArchLSXInstrInfo.td:1293
    VLDI                                  = 1233, // LoongArchLSXInstrInfo.td:789
    VLDREPL_B                             = 1234, // LoongArchLSXInstrInfo.td:1296
    VLDREPL_D                             = 1235, // LoongArchLSXInstrInfo.td:1299
    VLDREPL_H                             = 1236, // LoongArchLSXInstrInfo.td:1297
    VLDREPL_W                             = 1237, // LoongArchLSXInstrInfo.td:1298
    VLDX                                  = 1238, // LoongArchLSXInstrInfo.td:1294
    VMADDWEV_D_W                          = 1239, // LoongArchLSXInstrInfo.td:715
    VMADDWEV_D_WU                         = 1240, // LoongArchLSXInstrInfo.td:723
    VMADDWEV_D_WU_W                       = 1241, // LoongArchLSXInstrInfo.td:731
    VMADDWEV_H_B                          = 1242, // LoongArchLSXInstrInfo.td:713
    VMADDWEV_H_BU                         = 1243, // LoongArchLSXInstrInfo.td:721
    VMADDWEV_H_BU_B                       = 1244, // LoongArchLSXInstrInfo.td:729
    VMADDWEV_Q_D                          = 1245, // LoongArchLSXInstrInfo.td:716
    VMADDWEV_Q_DU                         = 1246, // LoongArchLSXInstrInfo.td:724
    VMADDWEV_Q_DU_D                       = 1247, // LoongArchLSXInstrInfo.td:732
    VMADDWEV_W_H                          = 1248, // LoongArchLSXInstrInfo.td:714
    VMADDWEV_W_HU                         = 1249, // LoongArchLSXInstrInfo.td:722
    VMADDWEV_W_HU_H                       = 1250, // LoongArchLSXInstrInfo.td:730
    VMADDWOD_D_W                          = 1251, // LoongArchLSXInstrInfo.td:719
    VMADDWOD_D_WU                         = 1252, // LoongArchLSXInstrInfo.td:727
    VMADDWOD_D_WU_W                       = 1253, // LoongArchLSXInstrInfo.td:735
    VMADDWOD_H_B                          = 1254, // LoongArchLSXInstrInfo.td:717
    VMADDWOD_H_BU                         = 1255, // LoongArchLSXInstrInfo.td:725
    VMADDWOD_H_BU_B                       = 1256, // LoongArchLSXInstrInfo.td:733
    VMADDWOD_Q_D                          = 1257, // LoongArchLSXInstrInfo.td:720
    VMADDWOD_Q_DU                         = 1258, // LoongArchLSXInstrInfo.td:728
    VMADDWOD_Q_DU_D                       = 1259, // LoongArchLSXInstrInfo.td:736
    VMADDWOD_W_H                          = 1260, // LoongArchLSXInstrInfo.td:718
    VMADDWOD_W_HU                         = 1261, // LoongArchLSXInstrInfo.td:726
    VMADDWOD_W_HU_H                       = 1262, // LoongArchLSXInstrInfo.td:734
    VMADD_B                               = 1263, // LoongArchLSXInstrInfo.td:703
    VMADD_D                               = 1264, // LoongArchLSXInstrInfo.td:706
    VMADD_H                               = 1265, // LoongArchLSXInstrInfo.td:704
    VMADD_W                               = 1266, // LoongArchLSXInstrInfo.td:705
    VMAXI_B                               = 1267, // LoongArchLSXInstrInfo.td:634
    VMAXI_BU                              = 1268, // LoongArchLSXInstrInfo.td:642
    VMAXI_D                               = 1269, // LoongArchLSXInstrInfo.td:637
    VMAXI_DU                              = 1270, // LoongArchLSXInstrInfo.td:645
    VMAXI_H                               = 1271, // LoongArchLSXInstrInfo.td:635
    VMAXI_HU                              = 1272, // LoongArchLSXInstrInfo.td:643
    VMAXI_W                               = 1273, // LoongArchLSXInstrInfo.td:636
    VMAXI_WU                              = 1274, // LoongArchLSXInstrInfo.td:644
    VMAX_B                                = 1275, // LoongArchLSXInstrInfo.td:630
    VMAX_BU                               = 1276, // LoongArchLSXInstrInfo.td:638
    VMAX_D                                = 1277, // LoongArchLSXInstrInfo.td:633
    VMAX_DU                               = 1278, // LoongArchLSXInstrInfo.td:641
    VMAX_H                                = 1279, // LoongArchLSXInstrInfo.td:631
    VMAX_HU                               = 1280, // LoongArchLSXInstrInfo.td:639
    VMAX_W                                = 1281, // LoongArchLSXInstrInfo.td:632
    VMAX_WU                               = 1282, // LoongArchLSXInstrInfo.td:640
    VMINI_B                               = 1283, // LoongArchLSXInstrInfo.td:651
    VMINI_BU                              = 1284, // LoongArchLSXInstrInfo.td:659
    VMINI_D                               = 1285, // LoongArchLSXInstrInfo.td:654
    VMINI_DU                              = 1286, // LoongArchLSXInstrInfo.td:662
    VMINI_H                               = 1287, // LoongArchLSXInstrInfo.td:652
    VMINI_HU                              = 1288, // LoongArchLSXInstrInfo.td:660
    VMINI_W                               = 1289, // LoongArchLSXInstrInfo.td:653
    VMINI_WU                              = 1290, // LoongArchLSXInstrInfo.td:661
    VMIN_B                                = 1291, // LoongArchLSXInstrInfo.td:647
    VMIN_BU                               = 1292, // LoongArchLSXInstrInfo.td:655
    VMIN_D                                = 1293, // LoongArchLSXInstrInfo.td:650
    VMIN_DU                               = 1294, // LoongArchLSXInstrInfo.td:658
    VMIN_H                                = 1295, // LoongArchLSXInstrInfo.td:648
    VMIN_HU                               = 1296, // LoongArchLSXInstrInfo.td:656
    VMIN_W                                = 1297, // LoongArchLSXInstrInfo.td:649
    VMIN_WU                               = 1298, // LoongArchLSXInstrInfo.td:657
    VMOD_B                                = 1299, // LoongArchLSXInstrInfo.td:747
    VMOD_BU                               = 1300, // LoongArchLSXInstrInfo.td:751
    VMOD_D                                = 1301, // LoongArchLSXInstrInfo.td:750
    VMOD_DU                               = 1302, // LoongArchLSXInstrInfo.td:754
    VMOD_H                                = 1303, // LoongArchLSXInstrInfo.td:748
    VMOD_HU                               = 1304, // LoongArchLSXInstrInfo.td:752
    VMOD_W                                = 1305, // LoongArchLSXInstrInfo.td:749
    VMOD_WU                               = 1306, // LoongArchLSXInstrInfo.td:753
    VMSKGEZ_B                             = 1307, // LoongArchLSXInstrInfo.td:784
    VMSKLTZ_B                             = 1308, // LoongArchLSXInstrInfo.td:779
    VMSKLTZ_D                             = 1309, // LoongArchLSXInstrInfo.td:782
    VMSKLTZ_H                             = 1310, // LoongArchLSXInstrInfo.td:780
    VMSKLTZ_W                             = 1311, // LoongArchLSXInstrInfo.td:781
    VMSKNZ_B                              = 1312, // LoongArchLSXInstrInfo.td:786
    VMSUB_B                               = 1313, // LoongArchLSXInstrInfo.td:708
    VMSUB_D                               = 1314, // LoongArchLSXInstrInfo.td:711
    VMSUB_H                               = 1315, // LoongArchLSXInstrInfo.td:709
    VMSUB_W                               = 1316, // LoongArchLSXInstrInfo.td:710
    VMUH_B                                = 1317, // LoongArchLSXInstrInfo.td:669
    VMUH_BU                               = 1318, // LoongArchLSXInstrInfo.td:673
    VMUH_D                                = 1319, // LoongArchLSXInstrInfo.td:672
    VMUH_DU                               = 1320, // LoongArchLSXInstrInfo.td:676
    VMUH_H                                = 1321, // LoongArchLSXInstrInfo.td:670
    VMUH_HU                               = 1322, // LoongArchLSXInstrInfo.td:674
    VMUH_W                                = 1323, // LoongArchLSXInstrInfo.td:671
    VMUH_WU                               = 1324, // LoongArchLSXInstrInfo.td:675
    VMULWEV_D_W                           = 1325, // LoongArchLSXInstrInfo.td:680
    VMULWEV_D_WU                          = 1326, // LoongArchLSXInstrInfo.td:688
    VMULWEV_D_WU_W                        = 1327, // LoongArchLSXInstrInfo.td:696
    VMULWEV_H_B                           = 1328, // LoongArchLSXInstrInfo.td:678
    VMULWEV_H_BU                          = 1329, // LoongArchLSXInstrInfo.td:686
    VMULWEV_H_BU_B                        = 1330, // LoongArchLSXInstrInfo.td:694
    VMULWEV_Q_D                           = 1331, // LoongArchLSXInstrInfo.td:681
    VMULWEV_Q_DU                          = 1332, // LoongArchLSXInstrInfo.td:689
    VMULWEV_Q_DU_D                        = 1333, // LoongArchLSXInstrInfo.td:697
    VMULWEV_W_H                           = 1334, // LoongArchLSXInstrInfo.td:679
    VMULWEV_W_HU                          = 1335, // LoongArchLSXInstrInfo.td:687
    VMULWEV_W_HU_H                        = 1336, // LoongArchLSXInstrInfo.td:695
    VMULWOD_D_W                           = 1337, // LoongArchLSXInstrInfo.td:684
    VMULWOD_D_WU                          = 1338, // LoongArchLSXInstrInfo.td:692
    VMULWOD_D_WU_W                        = 1339, // LoongArchLSXInstrInfo.td:700
    VMULWOD_H_B                           = 1340, // LoongArchLSXInstrInfo.td:682
    VMULWOD_H_BU                          = 1341, // LoongArchLSXInstrInfo.td:690
    VMULWOD_H_BU_B                        = 1342, // LoongArchLSXInstrInfo.td:698
    VMULWOD_Q_D                           = 1343, // LoongArchLSXInstrInfo.td:685
    VMULWOD_Q_DU                          = 1344, // LoongArchLSXInstrInfo.td:693
    VMULWOD_Q_DU_D                        = 1345, // LoongArchLSXInstrInfo.td:701
    VMULWOD_W_H                           = 1346, // LoongArchLSXInstrInfo.td:683
    VMULWOD_W_HU                          = 1347, // LoongArchLSXInstrInfo.td:691
    VMULWOD_W_HU_H                        = 1348, // LoongArchLSXInstrInfo.td:699
    VMUL_B                                = 1349, // LoongArchLSXInstrInfo.td:664
    VMUL_D                                = 1350, // LoongArchLSXInstrInfo.td:667
    VMUL_H                                = 1351, // LoongArchLSXInstrInfo.td:665
    VMUL_W                                = 1352, // LoongArchLSXInstrInfo.td:666
    VNEG_B                                = 1353, // LoongArchLSXInstrInfo.td:513
    VNEG_D                                = 1354, // LoongArchLSXInstrInfo.td:516
    VNEG_H                                = 1355, // LoongArchLSXInstrInfo.td:514
    VNEG_W                                = 1356, // LoongArchLSXInstrInfo.td:515
    VNORI_B                               = 1357, // LoongArchLSXInstrInfo.td:802
    VNOR_V                                = 1358, // LoongArchLSXInstrInfo.td:795
    VORI_B                                = 1359, // LoongArchLSXInstrInfo.td:800
    VORN_V                                = 1360, // LoongArchLSXInstrInfo.td:797
    VOR_V                                 = 1361, // LoongArchLSXInstrInfo.td:793
    VPACKEV_B                             = 1362, // LoongArchLSXInstrInfo.td:1246
    VPACKEV_D                             = 1363, // LoongArchLSXInstrInfo.td:1249
    VPACKEV_H                             = 1364, // LoongArchLSXInstrInfo.td:1247
    VPACKEV_W                             = 1365, // LoongArchLSXInstrInfo.td:1248
    VPACKOD_B                             = 1366, // LoongArchLSXInstrInfo.td:1250
    VPACKOD_D                             = 1367, // LoongArchLSXInstrInfo.td:1253
    VPACKOD_H                             = 1368, // LoongArchLSXInstrInfo.td:1251
    VPACKOD_W                             = 1369, // LoongArchLSXInstrInfo.td:1252
    VPCNT_B                               = 1370, // LoongArchLSXInstrInfo.td:968
    VPCNT_D                               = 1371, // LoongArchLSXInstrInfo.td:971
    VPCNT_H                               = 1372, // LoongArchLSXInstrInfo.td:969
    VPCNT_W                               = 1373, // LoongArchLSXInstrInfo.td:970
    VPERMI_W                              = 1374, // LoongArchLSXInstrInfo.td:1284
    VPICKEV_B                             = 1375, // LoongArchLSXInstrInfo.td:1255
    VPICKEV_D                             = 1376, // LoongArchLSXInstrInfo.td:1258
    VPICKEV_H                             = 1377, // LoongArchLSXInstrInfo.td:1256
    VPICKEV_W                             = 1378, // LoongArchLSXInstrInfo.td:1257
    VPICKOD_B                             = 1379, // LoongArchLSXInstrInfo.td:1259
    VPICKOD_D                             = 1380, // LoongArchLSXInstrInfo.td:1262
    VPICKOD_H                             = 1381, // LoongArchLSXInstrInfo.td:1260
    VPICKOD_W                             = 1382, // LoongArchLSXInstrInfo.td:1261
    VPICKVE2GR_B                          = 1383, // LoongArchLSXInstrInfo.td:1218
    VPICKVE2GR_BU                         = 1384, // LoongArchLSXInstrInfo.td:1222
    VPICKVE2GR_D                          = 1385, // LoongArchLSXInstrInfo.td:1221
    VPICKVE2GR_DU                         = 1386, // LoongArchLSXInstrInfo.td:1225
    VPICKVE2GR_H                          = 1387, // LoongArchLSXInstrInfo.td:1219
    VPICKVE2GR_HU                         = 1388, // LoongArchLSXInstrInfo.td:1223
    VPICKVE2GR_W                          = 1389, // LoongArchLSXInstrInfo.td:1220
    VPICKVE2GR_WU                         = 1390, // LoongArchLSXInstrInfo.td:1224
    VREPLGR2VR_B                          = 1391, // LoongArchLSXInstrInfo.td:1228
    VREPLGR2VR_D                          = 1392, // LoongArchLSXInstrInfo.td:1231
    VREPLGR2VR_H                          = 1393, // LoongArchLSXInstrInfo.td:1229
    VREPLGR2VR_W                          = 1394, // LoongArchLSXInstrInfo.td:1230
    VREPLVEI_B                            = 1395, // LoongArchLSXInstrInfo.td:1238
    VREPLVEI_D                            = 1396, // LoongArchLSXInstrInfo.td:1241
    VREPLVEI_H                            = 1397, // LoongArchLSXInstrInfo.td:1239
    VREPLVEI_W                            = 1398, // LoongArchLSXInstrInfo.td:1240
    VREPLVE_B                             = 1399, // LoongArchLSXInstrInfo.td:1234
    VREPLVE_D                             = 1400, // LoongArchLSXInstrInfo.td:1237
    VREPLVE_H                             = 1401, // LoongArchLSXInstrInfo.td:1235
    VREPLVE_W                             = 1402, // LoongArchLSXInstrInfo.td:1236
    VROTRI_B                              = 1403, // LoongArchLSXInstrInfo.td:835
    VROTRI_D                              = 1404, // LoongArchLSXInstrInfo.td:838
    VROTRI_H                              = 1405, // LoongArchLSXInstrInfo.td:836
    VROTRI_W                              = 1406, // LoongArchLSXInstrInfo.td:837
    VROTR_B                               = 1407, // LoongArchLSXInstrInfo.td:831
    VROTR_D                               = 1408, // LoongArchLSXInstrInfo.td:834
    VROTR_H                               = 1409, // LoongArchLSXInstrInfo.td:832
    VROTR_W                               = 1410, // LoongArchLSXInstrInfo.td:833
    VSADD_B                               = 1411, // LoongArchLSXInstrInfo.td:518
    VSADD_BU                              = 1412, // LoongArchLSXInstrInfo.td:522
    VSADD_D                               = 1413, // LoongArchLSXInstrInfo.td:521
    VSADD_DU                              = 1414, // LoongArchLSXInstrInfo.td:525
    VSADD_H                               = 1415, // LoongArchLSXInstrInfo.td:519
    VSADD_HU                              = 1416, // LoongArchLSXInstrInfo.td:523
    VSADD_W                               = 1417, // LoongArchLSXInstrInfo.td:520
    VSADD_WU                              = 1418, // LoongArchLSXInstrInfo.td:524
    VSAT_B                                = 1419, // LoongArchLSXInstrInfo.td:756
    VSAT_BU                               = 1420, // LoongArchLSXInstrInfo.td:760
    VSAT_D                                = 1421, // LoongArchLSXInstrInfo.td:759
    VSAT_DU                               = 1422, // LoongArchLSXInstrInfo.td:763
    VSAT_H                                = 1423, // LoongArchLSXInstrInfo.td:757
    VSAT_HU                               = 1424, // LoongArchLSXInstrInfo.td:761
    VSAT_W                                = 1425, // LoongArchLSXInstrInfo.td:758
    VSAT_WU                               = 1426, // LoongArchLSXInstrInfo.td:762
    VSEQI_B                               = 1427, // LoongArchLSXInstrInfo.td:1112
    VSEQI_D                               = 1428, // LoongArchLSXInstrInfo.td:1115
    VSEQI_H                               = 1429, // LoongArchLSXInstrInfo.td:1113
    VSEQI_W                               = 1430, // LoongArchLSXInstrInfo.td:1114
    VSEQ_B                                = 1431, // LoongArchLSXInstrInfo.td:1108
    VSEQ_D                                = 1432, // LoongArchLSXInstrInfo.td:1111
    VSEQ_H                                = 1433, // LoongArchLSXInstrInfo.td:1109
    VSEQ_W                                = 1434, // LoongArchLSXInstrInfo.td:1110
    VSETALLNEZ_B                          = 1435, // LoongArchLSXInstrInfo.td:1209
    VSETALLNEZ_D                          = 1436, // LoongArchLSXInstrInfo.td:1212
    VSETALLNEZ_H                          = 1437, // LoongArchLSXInstrInfo.td:1210
    VSETALLNEZ_W                          = 1438, // LoongArchLSXInstrInfo.td:1211
    VSETANYEQZ_B                          = 1439, // LoongArchLSXInstrInfo.td:1205
    VSETANYEQZ_D                          = 1440, // LoongArchLSXInstrInfo.td:1208
    VSETANYEQZ_H                          = 1441, // LoongArchLSXInstrInfo.td:1206
    VSETANYEQZ_W                          = 1442, // LoongArchLSXInstrInfo.td:1207
    VSETEQZ_V                             = 1443, // LoongArchLSXInstrInfo.td:1203
    VSETNEZ_V                             = 1444, // LoongArchLSXInstrInfo.td:1204
    VSHUF4I_B                             = 1445, // LoongArchLSXInstrInfo.td:1279
    VSHUF4I_D                             = 1446, // LoongArchLSXInstrInfo.td:1282
    VSHUF4I_H                             = 1447, // LoongArchLSXInstrInfo.td:1280
    VSHUF4I_W                             = 1448, // LoongArchLSXInstrInfo.td:1281
    VSHUF_B                               = 1449, // LoongArchLSXInstrInfo.td:1273
    VSHUF_D                               = 1450, // LoongArchLSXInstrInfo.td:1277
    VSHUF_H                               = 1451, // LoongArchLSXInstrInfo.td:1275
    VSHUF_W                               = 1452, // LoongArchLSXInstrInfo.td:1276
    VSIGNCOV_B                            = 1453, // LoongArchLSXInstrInfo.td:774
    VSIGNCOV_D                            = 1454, // LoongArchLSXInstrInfo.td:777
    VSIGNCOV_H                            = 1455, // LoongArchLSXInstrInfo.td:775
    VSIGNCOV_W                            = 1456, // LoongArchLSXInstrInfo.td:776
    VSLEI_B                               = 1457, // LoongArchLSXInstrInfo.td:1121
    VSLEI_BU                              = 1458, // LoongArchLSXInstrInfo.td:1130
    VSLEI_D                               = 1459, // LoongArchLSXInstrInfo.td:1124
    VSLEI_DU                              = 1460, // LoongArchLSXInstrInfo.td:1133
    VSLEI_H                               = 1461, // LoongArchLSXInstrInfo.td:1122
    VSLEI_HU                              = 1462, // LoongArchLSXInstrInfo.td:1131
    VSLEI_W                               = 1463, // LoongArchLSXInstrInfo.td:1123
    VSLEI_WU                              = 1464, // LoongArchLSXInstrInfo.td:1132
    VSLE_B                                = 1465, // LoongArchLSXInstrInfo.td:1117
    VSLE_BU                               = 1466, // LoongArchLSXInstrInfo.td:1126
    VSLE_D                                = 1467, // LoongArchLSXInstrInfo.td:1120
    VSLE_DU                               = 1468, // LoongArchLSXInstrInfo.td:1129
    VSLE_H                                = 1469, // LoongArchLSXInstrInfo.td:1118
    VSLE_HU                               = 1470, // LoongArchLSXInstrInfo.td:1127
    VSLE_W                                = 1471, // LoongArchLSXInstrInfo.td:1119
    VSLE_WU                               = 1472, // LoongArchLSXInstrInfo.td:1128
    VSLLI_B                               = 1473, // LoongArchLSXInstrInfo.td:808
    VSLLI_D                               = 1474, // LoongArchLSXInstrInfo.td:811
    VSLLI_H                               = 1475, // LoongArchLSXInstrInfo.td:809
    VSLLI_W                               = 1476, // LoongArchLSXInstrInfo.td:810
    VSLLWIL_DU_WU                         = 1477, // LoongArchLSXInstrInfo.td:846
    VSLLWIL_D_W                           = 1478, // LoongArchLSXInstrInfo.td:842
    VSLLWIL_HU_BU                         = 1479, // LoongArchLSXInstrInfo.td:844
    VSLLWIL_H_B                           = 1480, // LoongArchLSXInstrInfo.td:840
    VSLLWIL_WU_HU                         = 1481, // LoongArchLSXInstrInfo.td:845
    VSLLWIL_W_H                           = 1482, // LoongArchLSXInstrInfo.td:841
    VSLL_B                                = 1483, // LoongArchLSXInstrInfo.td:804
    VSLL_D                                = 1484, // LoongArchLSXInstrInfo.td:807
    VSLL_H                                = 1485, // LoongArchLSXInstrInfo.td:805
    VSLL_W                                = 1486, // LoongArchLSXInstrInfo.td:806
    VSLTI_B                               = 1487, // LoongArchLSXInstrInfo.td:1139
    VSLTI_BU                              = 1488, // LoongArchLSXInstrInfo.td:1148
    VSLTI_D                               = 1489, // LoongArchLSXInstrInfo.td:1142
    VSLTI_DU                              = 1490, // LoongArchLSXInstrInfo.td:1151
    VSLTI_H                               = 1491, // LoongArchLSXInstrInfo.td:1140
    VSLTI_HU                              = 1492, // LoongArchLSXInstrInfo.td:1149
    VSLTI_W                               = 1493, // LoongArchLSXInstrInfo.td:1141
    VSLTI_WU                              = 1494, // LoongArchLSXInstrInfo.td:1150
    VSLT_B                                = 1495, // LoongArchLSXInstrInfo.td:1135
    VSLT_BU                               = 1496, // LoongArchLSXInstrInfo.td:1144
    VSLT_D                                = 1497, // LoongArchLSXInstrInfo.td:1138
    VSLT_DU                               = 1498, // LoongArchLSXInstrInfo.td:1147
    VSLT_H                                = 1499, // LoongArchLSXInstrInfo.td:1136
    VSLT_HU                               = 1500, // LoongArchLSXInstrInfo.td:1145
    VSLT_W                                = 1501, // LoongArchLSXInstrInfo.td:1137
    VSLT_WU                               = 1502, // LoongArchLSXInstrInfo.td:1146
    VSRAI_B                               = 1503, // LoongArchLSXInstrInfo.td:826
    VSRAI_D                               = 1504, // LoongArchLSXInstrInfo.td:829
    VSRAI_H                               = 1505, // LoongArchLSXInstrInfo.td:827
    VSRAI_W                               = 1506, // LoongArchLSXInstrInfo.td:828
    VSRANI_B_H                            = 1507, // LoongArchLSXInstrInfo.td:878
    VSRANI_D_Q                            = 1508, // LoongArchLSXInstrInfo.td:881
    VSRANI_H_W                            = 1509, // LoongArchLSXInstrInfo.td:879
    VSRANI_W_D                            = 1510, // LoongArchLSXInstrInfo.td:880
    VSRAN_B_H                             = 1511, // LoongArchLSXInstrInfo.td:870
    VSRAN_H_W                             = 1512, // LoongArchLSXInstrInfo.td:871
    VSRAN_W_D                             = 1513, // LoongArchLSXInstrInfo.td:872
    VSRARI_B                              = 1514, // LoongArchLSXInstrInfo.td:862
    VSRARI_D                              = 1515, // LoongArchLSXInstrInfo.td:865
    VSRARI_H                              = 1516, // LoongArchLSXInstrInfo.td:863
    VSRARI_W                              = 1517, // LoongArchLSXInstrInfo.td:864
    VSRARNI_B_H                           = 1518, // LoongArchLSXInstrInfo.td:894
    VSRARNI_D_Q                           = 1519, // LoongArchLSXInstrInfo.td:897
    VSRARNI_H_W                           = 1520, // LoongArchLSXInstrInfo.td:895
    VSRARNI_W_D                           = 1521, // LoongArchLSXInstrInfo.td:896
    VSRARN_B_H                            = 1522, // LoongArchLSXInstrInfo.td:886
    VSRARN_H_W                            = 1523, // LoongArchLSXInstrInfo.td:887
    VSRARN_W_D                            = 1524, // LoongArchLSXInstrInfo.td:888
    VSRAR_B                               = 1525, // LoongArchLSXInstrInfo.td:858
    VSRAR_D                               = 1526, // LoongArchLSXInstrInfo.td:861
    VSRAR_H                               = 1527, // LoongArchLSXInstrInfo.td:859
    VSRAR_W                               = 1528, // LoongArchLSXInstrInfo.td:860
    VSRA_B                                = 1529, // LoongArchLSXInstrInfo.td:822
    VSRA_D                                = 1530, // LoongArchLSXInstrInfo.td:825
    VSRA_H                                = 1531, // LoongArchLSXInstrInfo.td:823
    VSRA_W                                = 1532, // LoongArchLSXInstrInfo.td:824
    VSRLI_B                               = 1533, // LoongArchLSXInstrInfo.td:817
    VSRLI_D                               = 1534, // LoongArchLSXInstrInfo.td:820
    VSRLI_H                               = 1535, // LoongArchLSXInstrInfo.td:818
    VSRLI_W                               = 1536, // LoongArchLSXInstrInfo.td:819
    VSRLNI_B_H                            = 1537, // LoongArchLSXInstrInfo.td:874
    VSRLNI_D_Q                            = 1538, // LoongArchLSXInstrInfo.td:877
    VSRLNI_H_W                            = 1539, // LoongArchLSXInstrInfo.td:875
    VSRLNI_W_D                            = 1540, // LoongArchLSXInstrInfo.td:876
    VSRLN_B_H                             = 1541, // LoongArchLSXInstrInfo.td:867
    VSRLN_H_W                             = 1542, // LoongArchLSXInstrInfo.td:868
    VSRLN_W_D                             = 1543, // LoongArchLSXInstrInfo.td:869
    VSRLRI_B                              = 1544, // LoongArchLSXInstrInfo.td:853
    VSRLRI_D                              = 1545, // LoongArchLSXInstrInfo.td:856
    VSRLRI_H                              = 1546, // LoongArchLSXInstrInfo.td:854
    VSRLRI_W                              = 1547, // LoongArchLSXInstrInfo.td:855
    VSRLRNI_B_H                           = 1548, // LoongArchLSXInstrInfo.td:890
    VSRLRNI_D_Q                           = 1549, // LoongArchLSXInstrInfo.td:893
    VSRLRNI_H_W                           = 1550, // LoongArchLSXInstrInfo.td:891
    VSRLRNI_W_D                           = 1551, // LoongArchLSXInstrInfo.td:892
    VSRLRN_B_H                            = 1552, // LoongArchLSXInstrInfo.td:883
    VSRLRN_H_W                            = 1553, // LoongArchLSXInstrInfo.td:884
    VSRLRN_W_D                            = 1554, // LoongArchLSXInstrInfo.td:885
    VSRLR_B                               = 1555, // LoongArchLSXInstrInfo.td:849
    VSRLR_D                               = 1556, // LoongArchLSXInstrInfo.td:852
    VSRLR_H                               = 1557, // LoongArchLSXInstrInfo.td:850
    VSRLR_W                               = 1558, // LoongArchLSXInstrInfo.td:851
    VSRL_B                                = 1559, // LoongArchLSXInstrInfo.td:813
    VSRL_D                                = 1560, // LoongArchLSXInstrInfo.td:816
    VSRL_H                                = 1561, // LoongArchLSXInstrInfo.td:814
    VSRL_W                                = 1562, // LoongArchLSXInstrInfo.td:815
    VSSRANI_BU_H                          = 1563, // LoongArchLSXInstrInfo.td:924
    VSSRANI_B_H                           = 1564, // LoongArchLSXInstrInfo.td:916
    VSSRANI_DU_Q                          = 1565, // LoongArchLSXInstrInfo.td:927
    VSSRANI_D_Q                           = 1566, // LoongArchLSXInstrInfo.td:919
    VSSRANI_HU_W                          = 1567, // LoongArchLSXInstrInfo.td:925
    VSSRANI_H_W                           = 1568, // LoongArchLSXInstrInfo.td:917
    VSSRANI_WU_D                          = 1569, // LoongArchLSXInstrInfo.td:926
    VSSRANI_W_D                           = 1570, // LoongArchLSXInstrInfo.td:918
    VSSRAN_BU_H                           = 1571, // LoongArchLSXInstrInfo.td:908
    VSSRAN_B_H                            = 1572, // LoongArchLSXInstrInfo.td:902
    VSSRAN_HU_W                           = 1573, // LoongArchLSXInstrInfo.td:909
    VSSRAN_H_W                            = 1574, // LoongArchLSXInstrInfo.td:903
    VSSRAN_WU_D                           = 1575, // LoongArchLSXInstrInfo.td:910
    VSSRAN_W_D                            = 1576, // LoongArchLSXInstrInfo.td:904
    VSSRARNI_BU_H                         = 1577, // LoongArchLSXInstrInfo.td:954
    VSSRARNI_B_H                          = 1578, // LoongArchLSXInstrInfo.td:946
    VSSRARNI_DU_Q                         = 1579, // LoongArchLSXInstrInfo.td:957
    VSSRARNI_D_Q                          = 1580, // LoongArchLSXInstrInfo.td:949
    VSSRARNI_HU_W                         = 1581, // LoongArchLSXInstrInfo.td:955
    VSSRARNI_H_W                          = 1582, // LoongArchLSXInstrInfo.td:947
    VSSRARNI_WU_D                         = 1583, // LoongArchLSXInstrInfo.td:956
    VSSRARNI_W_D                          = 1584, // LoongArchLSXInstrInfo.td:948
    VSSRARN_BU_H                          = 1585, // LoongArchLSXInstrInfo.td:938
    VSSRARN_B_H                           = 1586, // LoongArchLSXInstrInfo.td:932
    VSSRARN_HU_W                          = 1587, // LoongArchLSXInstrInfo.td:939
    VSSRARN_H_W                           = 1588, // LoongArchLSXInstrInfo.td:933
    VSSRARN_WU_D                          = 1589, // LoongArchLSXInstrInfo.td:940
    VSSRARN_W_D                           = 1590, // LoongArchLSXInstrInfo.td:934
    VSSRLNI_BU_H                          = 1591, // LoongArchLSXInstrInfo.td:920
    VSSRLNI_B_H                           = 1592, // LoongArchLSXInstrInfo.td:912
    VSSRLNI_DU_Q                          = 1593, // LoongArchLSXInstrInfo.td:923
    VSSRLNI_D_Q                           = 1594, // LoongArchLSXInstrInfo.td:915
    VSSRLNI_HU_W                          = 1595, // LoongArchLSXInstrInfo.td:921
    VSSRLNI_H_W                           = 1596, // LoongArchLSXInstrInfo.td:913
    VSSRLNI_WU_D                          = 1597, // LoongArchLSXInstrInfo.td:922
    VSSRLNI_W_D                           = 1598, // LoongArchLSXInstrInfo.td:914
    VSSRLN_BU_H                           = 1599, // LoongArchLSXInstrInfo.td:905
    VSSRLN_B_H                            = 1600, // LoongArchLSXInstrInfo.td:899
    VSSRLN_HU_W                           = 1601, // LoongArchLSXInstrInfo.td:906
    VSSRLN_H_W                            = 1602, // LoongArchLSXInstrInfo.td:900
    VSSRLN_WU_D                           = 1603, // LoongArchLSXInstrInfo.td:907
    VSSRLN_W_D                            = 1604, // LoongArchLSXInstrInfo.td:901
    VSSRLRNI_BU_H                         = 1605, // LoongArchLSXInstrInfo.td:950
    VSSRLRNI_B_H                          = 1606, // LoongArchLSXInstrInfo.td:942
    VSSRLRNI_DU_Q                         = 1607, // LoongArchLSXInstrInfo.td:953
    VSSRLRNI_D_Q                          = 1608, // LoongArchLSXInstrInfo.td:945
    VSSRLRNI_HU_W                         = 1609, // LoongArchLSXInstrInfo.td:951
    VSSRLRNI_H_W                          = 1610, // LoongArchLSXInstrInfo.td:943
    VSSRLRNI_WU_D                         = 1611, // LoongArchLSXInstrInfo.td:952
    VSSRLRNI_W_D                          = 1612, // LoongArchLSXInstrInfo.td:944
    VSSRLRN_BU_H                          = 1613, // LoongArchLSXInstrInfo.td:935
    VSSRLRN_B_H                           = 1614, // LoongArchLSXInstrInfo.td:929
    VSSRLRN_HU_W                          = 1615, // LoongArchLSXInstrInfo.td:936
    VSSRLRN_H_W                           = 1616, // LoongArchLSXInstrInfo.td:930
    VSSRLRN_WU_D                          = 1617, // LoongArchLSXInstrInfo.td:937
    VSSRLRN_W_D                           = 1618, // LoongArchLSXInstrInfo.td:931
    VSSUB_B                               = 1619, // LoongArchLSXInstrInfo.td:527
    VSSUB_BU                              = 1620, // LoongArchLSXInstrInfo.td:531
    VSSUB_D                               = 1621, // LoongArchLSXInstrInfo.td:530
    VSSUB_DU                              = 1622, // LoongArchLSXInstrInfo.td:534
    VSSUB_H                               = 1623, // LoongArchLSXInstrInfo.td:528
    VSSUB_HU                              = 1624, // LoongArchLSXInstrInfo.td:532
    VSSUB_W                               = 1625, // LoongArchLSXInstrInfo.td:529
    VSSUB_WU                              = 1626, // LoongArchLSXInstrInfo.td:533
    VST                                   = 1627, // LoongArchLSXInstrInfo.td:1303
    VSTELM_B                              = 1628, // LoongArchLSXInstrInfo.td:1306
    VSTELM_D                              = 1629, // LoongArchLSXInstrInfo.td:1309
    VSTELM_H                              = 1630, // LoongArchLSXInstrInfo.td:1307
    VSTELM_W                              = 1631, // LoongArchLSXInstrInfo.td:1308
    VSTX                                  = 1632, // LoongArchLSXInstrInfo.td:1304
    VSUBI_BU                              = 1633, // LoongArchLSXInstrInfo.td:508
    VSUBI_DU                              = 1634, // LoongArchLSXInstrInfo.td:511
    VSUBI_HU                              = 1635, // LoongArchLSXInstrInfo.td:509
    VSUBI_WU                              = 1636, // LoongArchLSXInstrInfo.td:510
    VSUBWEV_D_W                           = 1637, // LoongArchLSXInstrInfo.td:565
    VSUBWEV_D_WU                          = 1638, // LoongArchLSXInstrInfo.td:583
    VSUBWEV_H_B                           = 1639, // LoongArchLSXInstrInfo.td:563
    VSUBWEV_H_BU                          = 1640, // LoongArchLSXInstrInfo.td:581
    VSUBWEV_Q_D                           = 1641, // LoongArchLSXInstrInfo.td:566
    VSUBWEV_Q_DU                          = 1642, // LoongArchLSXInstrInfo.td:584
    VSUBWEV_W_H                           = 1643, // LoongArchLSXInstrInfo.td:564
    VSUBWEV_W_HU                          = 1644, // LoongArchLSXInstrInfo.td:582
    VSUBWOD_D_W                           = 1645, // LoongArchLSXInstrInfo.td:569
    VSUBWOD_D_WU                          = 1646, // LoongArchLSXInstrInfo.td:587
    VSUBWOD_H_B                           = 1647, // LoongArchLSXInstrInfo.td:567
    VSUBWOD_H_BU                          = 1648, // LoongArchLSXInstrInfo.td:585
    VSUBWOD_Q_D                           = 1649, // LoongArchLSXInstrInfo.td:570
    VSUBWOD_Q_DU                          = 1650, // LoongArchLSXInstrInfo.td:588
    VSUBWOD_W_H                           = 1651, // LoongArchLSXInstrInfo.td:568
    VSUBWOD_W_HU                          = 1652, // LoongArchLSXInstrInfo.td:586
    VSUB_B                                = 1653, // LoongArchLSXInstrInfo.td:497
    VSUB_D                                = 1654, // LoongArchLSXInstrInfo.td:500
    VSUB_H                                = 1655, // LoongArchLSXInstrInfo.td:498
    VSUB_Q                                = 1656, // LoongArchLSXInstrInfo.td:501
    VSUB_W                                = 1657, // LoongArchLSXInstrInfo.td:499
    VXORI_B                               = 1658, // LoongArchLSXInstrInfo.td:801
    VXOR_V                                = 1659, // LoongArchLSXInstrInfo.td:794
    X86ADC_B                              = 1660, // LoongArchLBTInstrInfo.td:63
    X86ADC_D                              = 1661, // LoongArchLBTInstrInfo.td:208
    X86ADC_H                              = 1662, // LoongArchLBTInstrInfo.td:64
    X86ADC_W                              = 1663, // LoongArchLBTInstrInfo.td:65
    X86ADD_B                              = 1664, // LoongArchLBTInstrInfo.td:66
    X86ADD_D                              = 1665, // LoongArchLBTInstrInfo.td:209
    X86ADD_DU                             = 1666, // LoongArchLBTInstrInfo.td:211
    X86ADD_H                              = 1667, // LoongArchLBTInstrInfo.td:67
    X86ADD_W                              = 1668, // LoongArchLBTInstrInfo.td:68
    X86ADD_WU                             = 1669, // LoongArchLBTInstrInfo.td:210
    X86AND_B                              = 1670, // LoongArchLBTInstrInfo.td:85
    X86AND_D                              = 1671, // LoongArchLBTInstrInfo.td:218
    X86AND_H                              = 1672, // LoongArchLBTInstrInfo.td:86
    X86AND_W                              = 1673, // LoongArchLBTInstrInfo.td:87
    X86CLRTM                              = 1674, // LoongArchLBTInstrInfo.td:163
    X86DECTOP                             = 1675, // LoongArchLBTInstrInfo.td:161
    X86DEC_B                              = 1676, // LoongArchLBTInstrInfo.td:81
    X86DEC_D                              = 1677, // LoongArchLBTInstrInfo.td:217
    X86DEC_H                              = 1678, // LoongArchLBTInstrInfo.td:82
    X86DEC_W                              = 1679, // LoongArchLBTInstrInfo.td:83
    X86INCTOP                             = 1680, // LoongArchLBTInstrInfo.td:160
    X86INC_B                              = 1681, // LoongArchLBTInstrInfo.td:70
    X86INC_D                              = 1682, // LoongArchLBTInstrInfo.td:212
    X86INC_H                              = 1683, // LoongArchLBTInstrInfo.td:71
    X86INC_W                              = 1684, // LoongArchLBTInstrInfo.td:72
    X86MFFLAG                             = 1685, // LoongArchLBTInstrInfo.td:155
    X86MFTOP                              = 1686, // LoongArchLBTInstrInfo.td:157
    X86MTFLAG                             = 1687, // LoongArchLBTInstrInfo.td:156
    X86MTTOP                              = 1688, // LoongArchLBTInstrInfo.td:158
    X86MUL_B                              = 1689, // LoongArchLBTInstrInfo.td:97
    X86MUL_BU                             = 1690, // LoongArchLBTInstrInfo.td:100
    X86MUL_D                              = 1691, // LoongArchLBTInstrInfo.td:221
    X86MUL_DU                             = 1692, // LoongArchLBTInstrInfo.td:223
    X86MUL_H                              = 1693, // LoongArchLBTInstrInfo.td:98
    X86MUL_HU                             = 1694, // LoongArchLBTInstrInfo.td:101
    X86MUL_W                              = 1695, // LoongArchLBTInstrInfo.td:99
    X86MUL_WU                             = 1696, // LoongArchLBTInstrInfo.td:222
    X86OR_B                               = 1697, // LoongArchLBTInstrInfo.td:89
    X86OR_D                               = 1698, // LoongArchLBTInstrInfo.td:219
    X86OR_H                               = 1699, // LoongArchLBTInstrInfo.td:90
    X86OR_W                               = 1700, // LoongArchLBTInstrInfo.td:91
    X86RCLI_B                             = 1701, // LoongArchLBTInstrInfo.td:106
    X86RCLI_D                             = 1702, // LoongArchLBTInstrInfo.td:225
    X86RCLI_H                             = 1703, // LoongArchLBTInstrInfo.td:107
    X86RCLI_W                             = 1704, // LoongArchLBTInstrInfo.td:108
    X86RCL_B                              = 1705, // LoongArchLBTInstrInfo.td:103
    X86RCL_D                              = 1706, // LoongArchLBTInstrInfo.td:224
    X86RCL_H                              = 1707, // LoongArchLBTInstrInfo.td:104
    X86RCL_W                              = 1708, // LoongArchLBTInstrInfo.td:105
    X86RCRI_B                             = 1709, // LoongArchLBTInstrInfo.td:113
    X86RCRI_D                             = 1710, // LoongArchLBTInstrInfo.td:227
    X86RCRI_H                             = 1711, // LoongArchLBTInstrInfo.td:114
    X86RCRI_W                             = 1712, // LoongArchLBTInstrInfo.td:115
    X86RCR_B                              = 1713, // LoongArchLBTInstrInfo.td:110
    X86RCR_D                              = 1714, // LoongArchLBTInstrInfo.td:226
    X86RCR_H                              = 1715, // LoongArchLBTInstrInfo.td:111
    X86RCR_W                              = 1716, // LoongArchLBTInstrInfo.td:112
    X86ROTLI_B                            = 1717, // LoongArchLBTInstrInfo.td:120
    X86ROTLI_D                            = 1718, // LoongArchLBTInstrInfo.td:229
    X86ROTLI_H                            = 1719, // LoongArchLBTInstrInfo.td:121
    X86ROTLI_W                            = 1720, // LoongArchLBTInstrInfo.td:122
    X86ROTL_B                             = 1721, // LoongArchLBTInstrInfo.td:117
    X86ROTL_D                             = 1722, // LoongArchLBTInstrInfo.td:228
    X86ROTL_H                             = 1723, // LoongArchLBTInstrInfo.td:118
    X86ROTL_W                             = 1724, // LoongArchLBTInstrInfo.td:119
    X86ROTRI_B                            = 1725, // LoongArchLBTInstrInfo.td:127
    X86ROTRI_D                            = 1726, // LoongArchLBTInstrInfo.td:231
    X86ROTRI_H                            = 1727, // LoongArchLBTInstrInfo.td:128
    X86ROTRI_W                            = 1728, // LoongArchLBTInstrInfo.td:129
    X86ROTR_B                             = 1729, // LoongArchLBTInstrInfo.td:124
    X86ROTR_D                             = 1730, // LoongArchLBTInstrInfo.td:230
    X86ROTR_H                             = 1731, // LoongArchLBTInstrInfo.td:125
    X86ROTR_W                             = 1732, // LoongArchLBTInstrInfo.td:126
    X86SBC_B                              = 1733, // LoongArchLBTInstrInfo.td:74
    X86SBC_D                              = 1734, // LoongArchLBTInstrInfo.td:213
    X86SBC_H                              = 1735, // LoongArchLBTInstrInfo.td:75
    X86SBC_W                              = 1736, // LoongArchLBTInstrInfo.td:76
    X86SETTAG                             = 1737, // LoongArchLBTInstrInfo.td:164
    X86SETTM                              = 1738, // LoongArchLBTInstrInfo.td:162
    X86SLLI_B                             = 1739, // LoongArchLBTInstrInfo.td:134
    X86SLLI_D                             = 1740, // LoongArchLBTInstrInfo.td:233
    X86SLLI_H                             = 1741, // LoongArchLBTInstrInfo.td:135
    X86SLLI_W                             = 1742, // LoongArchLBTInstrInfo.td:136
    X86SLL_B                              = 1743, // LoongArchLBTInstrInfo.td:131
    X86SLL_D                              = 1744, // LoongArchLBTInstrInfo.td:232
    X86SLL_H                              = 1745, // LoongArchLBTInstrInfo.td:132
    X86SLL_W                              = 1746, // LoongArchLBTInstrInfo.td:133
    X86SRAI_B                             = 1747, // LoongArchLBTInstrInfo.td:148
    X86SRAI_D                             = 1748, // LoongArchLBTInstrInfo.td:237
    X86SRAI_H                             = 1749, // LoongArchLBTInstrInfo.td:149
    X86SRAI_W                             = 1750, // LoongArchLBTInstrInfo.td:150
    X86SRA_B                              = 1751, // LoongArchLBTInstrInfo.td:145
    X86SRA_D                              = 1752, // LoongArchLBTInstrInfo.td:236
    X86SRA_H                              = 1753, // LoongArchLBTInstrInfo.td:146
    X86SRA_W                              = 1754, // LoongArchLBTInstrInfo.td:147
    X86SRLI_B                             = 1755, // LoongArchLBTInstrInfo.td:141
    X86SRLI_D                             = 1756, // LoongArchLBTInstrInfo.td:235
    X86SRLI_H                             = 1757, // LoongArchLBTInstrInfo.td:142
    X86SRLI_W                             = 1758, // LoongArchLBTInstrInfo.td:143
    X86SRL_B                              = 1759, // LoongArchLBTInstrInfo.td:138
    X86SRL_D                              = 1760, // LoongArchLBTInstrInfo.td:234
    X86SRL_H                              = 1761, // LoongArchLBTInstrInfo.td:139
    X86SRL_W                              = 1762, // LoongArchLBTInstrInfo.td:140
    X86SUB_B                              = 1763, // LoongArchLBTInstrInfo.td:77
    X86SUB_D                              = 1764, // LoongArchLBTInstrInfo.td:215
    X86SUB_DU                             = 1765, // LoongArchLBTInstrInfo.td:216
    X86SUB_H                              = 1766, // LoongArchLBTInstrInfo.td:78
    X86SUB_W                              = 1767, // LoongArchLBTInstrInfo.td:79
    X86SUB_WU                             = 1768, // LoongArchLBTInstrInfo.td:214
    X86XOR_B                              = 1769, // LoongArchLBTInstrInfo.td:93
    X86XOR_D                              = 1770, // LoongArchLBTInstrInfo.td:220
    X86XOR_H                              = 1771, // LoongArchLBTInstrInfo.td:94
    X86XOR_W                              = 1772, // LoongArchLBTInstrInfo.td:95
    XOR                                   = 1773, // LoongArchInstrInfo.td:872
    XORI                                  = 1774, // LoongArchInstrInfo.td:877
    XVABSD_B                              = 1775, // LoongArchLASXInstrInfo.td:352
    XVABSD_BU                             = 1776, // LoongArchLASXInstrInfo.td:356
    XVABSD_D                              = 1777, // LoongArchLASXInstrInfo.td:355
    XVABSD_DU                             = 1778, // LoongArchLASXInstrInfo.td:359
    XVABSD_H                              = 1779, // LoongArchLASXInstrInfo.td:353
    XVABSD_HU                             = 1780, // LoongArchLASXInstrInfo.td:357
    XVABSD_W                              = 1781, // LoongArchLASXInstrInfo.td:354
    XVABSD_WU                             = 1782, // LoongArchLASXInstrInfo.td:358
    XVADDA_B                              = 1783, // LoongArchLASXInstrInfo.td:361
    XVADDA_D                              = 1784, // LoongArchLASXInstrInfo.td:364
    XVADDA_H                              = 1785, // LoongArchLASXInstrInfo.td:362
    XVADDA_W                              = 1786, // LoongArchLASXInstrInfo.td:363
    XVADDI_BU                             = 1787, // LoongArchLASXInstrInfo.td:239
    XVADDI_DU                             = 1788, // LoongArchLASXInstrInfo.td:242
    XVADDI_HU                             = 1789, // LoongArchLASXInstrInfo.td:240
    XVADDI_WU                             = 1790, // LoongArchLASXInstrInfo.td:241
    XVADDWEV_D_W                          = 1791, // LoongArchLASXInstrInfo.td:292
    XVADDWEV_D_WU                         = 1792, // LoongArchLASXInstrInfo.td:310
    XVADDWEV_D_WU_W                       = 1793, // LoongArchLASXInstrInfo.td:328
    XVADDWEV_H_B                          = 1794, // LoongArchLASXInstrInfo.td:290
    XVADDWEV_H_BU                         = 1795, // LoongArchLASXInstrInfo.td:308
    XVADDWEV_H_BU_B                       = 1796, // LoongArchLASXInstrInfo.td:326
    XVADDWEV_Q_D                          = 1797, // LoongArchLASXInstrInfo.td:293
    XVADDWEV_Q_DU                         = 1798, // LoongArchLASXInstrInfo.td:311
    XVADDWEV_Q_DU_D                       = 1799, // LoongArchLASXInstrInfo.td:329
    XVADDWEV_W_H                          = 1800, // LoongArchLASXInstrInfo.td:291
    XVADDWEV_W_HU                         = 1801, // LoongArchLASXInstrInfo.td:309
    XVADDWEV_W_HU_H                       = 1802, // LoongArchLASXInstrInfo.td:327
    XVADDWOD_D_W                          = 1803, // LoongArchLASXInstrInfo.td:296
    XVADDWOD_D_WU                         = 1804, // LoongArchLASXInstrInfo.td:314
    XVADDWOD_D_WU_W                       = 1805, // LoongArchLASXInstrInfo.td:332
    XVADDWOD_H_B                          = 1806, // LoongArchLASXInstrInfo.td:294
    XVADDWOD_H_BU                         = 1807, // LoongArchLASXInstrInfo.td:312
    XVADDWOD_H_BU_B                       = 1808, // LoongArchLASXInstrInfo.td:330
    XVADDWOD_Q_D                          = 1809, // LoongArchLASXInstrInfo.td:297
    XVADDWOD_Q_DU                         = 1810, // LoongArchLASXInstrInfo.td:315
    XVADDWOD_Q_DU_D                       = 1811, // LoongArchLASXInstrInfo.td:333
    XVADDWOD_W_H                          = 1812, // LoongArchLASXInstrInfo.td:295
    XVADDWOD_W_HU                         = 1813, // LoongArchLASXInstrInfo.td:313
    XVADDWOD_W_HU_H                       = 1814, // LoongArchLASXInstrInfo.td:331
    XVADD_B                               = 1815, // LoongArchLASXInstrInfo.td:227
    XVADD_D                               = 1816, // LoongArchLASXInstrInfo.td:230
    XVADD_H                               = 1817, // LoongArchLASXInstrInfo.td:228
    XVADD_Q                               = 1818, // LoongArchLASXInstrInfo.td:231
    XVADD_W                               = 1819, // LoongArchLASXInstrInfo.td:229
    XVANDI_B                              = 1820, // LoongArchLASXInstrInfo.td:548
    XVANDN_V                              = 1821, // LoongArchLASXInstrInfo.td:545
    XVAND_V                               = 1822, // LoongArchLASXInstrInfo.td:541
    XVAVGR_B                              = 1823, // LoongArchLASXInstrInfo.td:343
    XVAVGR_BU                             = 1824, // LoongArchLASXInstrInfo.td:347
    XVAVGR_D                              = 1825, // LoongArchLASXInstrInfo.td:346
    XVAVGR_DU                             = 1826, // LoongArchLASXInstrInfo.td:350
    XVAVGR_H                              = 1827, // LoongArchLASXInstrInfo.td:344
    XVAVGR_HU                             = 1828, // LoongArchLASXInstrInfo.td:348
    XVAVGR_W                              = 1829, // LoongArchLASXInstrInfo.td:345
    XVAVGR_WU                             = 1830, // LoongArchLASXInstrInfo.td:349
    XVAVG_B                               = 1831, // LoongArchLASXInstrInfo.td:335
    XVAVG_BU                              = 1832, // LoongArchLASXInstrInfo.td:339
    XVAVG_D                               = 1833, // LoongArchLASXInstrInfo.td:338
    XVAVG_DU                              = 1834, // LoongArchLASXInstrInfo.td:342
    XVAVG_H                               = 1835, // LoongArchLASXInstrInfo.td:336
    XVAVG_HU                              = 1836, // LoongArchLASXInstrInfo.td:340
    XVAVG_W                               = 1837, // LoongArchLASXInstrInfo.td:337
    XVAVG_WU                              = 1838, // LoongArchLASXInstrInfo.td:341
    XVBITCLRI_B                           = 1839, // LoongArchLASXInstrInfo.td:726
    XVBITCLRI_D                           = 1840, // LoongArchLASXInstrInfo.td:729
    XVBITCLRI_H                           = 1841, // LoongArchLASXInstrInfo.td:727
    XVBITCLRI_W                           = 1842, // LoongArchLASXInstrInfo.td:728
    XVBITCLR_B                            = 1843, // LoongArchLASXInstrInfo.td:722
    XVBITCLR_D                            = 1844, // LoongArchLASXInstrInfo.td:725
    XVBITCLR_H                            = 1845, // LoongArchLASXInstrInfo.td:723
    XVBITCLR_W                            = 1846, // LoongArchLASXInstrInfo.td:724
    XVBITREVI_B                           = 1847, // LoongArchLASXInstrInfo.td:744
    XVBITREVI_D                           = 1848, // LoongArchLASXInstrInfo.td:747
    XVBITREVI_H                           = 1849, // LoongArchLASXInstrInfo.td:745
    XVBITREVI_W                           = 1850, // LoongArchLASXInstrInfo.td:746
    XVBITREV_B                            = 1851, // LoongArchLASXInstrInfo.td:740
    XVBITREV_D                            = 1852, // LoongArchLASXInstrInfo.td:743
    XVBITREV_H                            = 1853, // LoongArchLASXInstrInfo.td:741
    XVBITREV_W                            = 1854, // LoongArchLASXInstrInfo.td:742
    XVBITSELI_B                           = 1855, // LoongArchLASXInstrInfo.td:950
    XVBITSEL_V                            = 1856, // LoongArchLASXInstrInfo.td:948
    XVBITSETI_B                           = 1857, // LoongArchLASXInstrInfo.td:735
    XVBITSETI_D                           = 1858, // LoongArchLASXInstrInfo.td:738
    XVBITSETI_H                           = 1859, // LoongArchLASXInstrInfo.td:736
    XVBITSETI_W                           = 1860, // LoongArchLASXInstrInfo.td:737
    XVBITSET_B                            = 1861, // LoongArchLASXInstrInfo.td:731
    XVBITSET_D                            = 1862, // LoongArchLASXInstrInfo.td:734
    XVBITSET_H                            = 1863, // LoongArchLASXInstrInfo.td:732
    XVBITSET_W                            = 1864, // LoongArchLASXInstrInfo.td:733
    XVBSLL_V                              = 1865, // LoongArchLASXInstrInfo.td:998
    XVBSRL_V                              = 1866, // LoongArchLASXInstrInfo.td:999
    XVCLO_B                               = 1867, // LoongArchLASXInstrInfo.td:708
    XVCLO_D                               = 1868, // LoongArchLASXInstrInfo.td:711
    XVCLO_H                               = 1869, // LoongArchLASXInstrInfo.td:709
    XVCLO_W                               = 1870, // LoongArchLASXInstrInfo.td:710
    XVCLZ_B                               = 1871, // LoongArchLASXInstrInfo.td:712
    XVCLZ_D                               = 1872, // LoongArchLASXInstrInfo.td:715
    XVCLZ_H                               = 1873, // LoongArchLASXInstrInfo.td:713
    XVCLZ_W                               = 1874, // LoongArchLASXInstrInfo.td:714
    XVDIV_B                               = 1875, // LoongArchLASXInstrInfo.td:474
    XVDIV_BU                              = 1876, // LoongArchLASXInstrInfo.td:478
    XVDIV_D                               = 1877, // LoongArchLASXInstrInfo.td:477
    XVDIV_DU                              = 1878, // LoongArchLASXInstrInfo.td:481
    XVDIV_H                               = 1879, // LoongArchLASXInstrInfo.td:475
    XVDIV_HU                              = 1880, // LoongArchLASXInstrInfo.td:479
    XVDIV_W                               = 1881, // LoongArchLASXInstrInfo.td:476
    XVDIV_WU                              = 1882, // LoongArchLASXInstrInfo.td:480
    XVEXTH_DU_WU                          = 1883, // LoongArchLASXInstrInfo.td:507
    XVEXTH_D_W                            = 1884, // LoongArchLASXInstrInfo.td:503
    XVEXTH_HU_BU                          = 1885, // LoongArchLASXInstrInfo.td:505
    XVEXTH_H_B                            = 1886, // LoongArchLASXInstrInfo.td:501
    XVEXTH_QU_DU                          = 1887, // LoongArchLASXInstrInfo.td:508
    XVEXTH_Q_D                            = 1888, // LoongArchLASXInstrInfo.td:504
    XVEXTH_WU_HU                          = 1889, // LoongArchLASXInstrInfo.td:506
    XVEXTH_W_H                            = 1890, // LoongArchLASXInstrInfo.td:502
    XVEXTL_QU_DU                          = 1891, // LoongArchLASXInstrInfo.td:596
    XVEXTL_Q_D                            = 1892, // LoongArchLASXInstrInfo.td:592
    XVEXTRINS_B                           = 1893, // LoongArchLASXInstrInfo.td:1048
    XVEXTRINS_D                           = 1894, // LoongArchLASXInstrInfo.td:1045
    XVEXTRINS_H                           = 1895, // LoongArchLASXInstrInfo.td:1047
    XVEXTRINS_W                           = 1896, // LoongArchLASXInstrInfo.td:1046
    XVFADD_D                              = 1897, // LoongArchLASXInstrInfo.td:755
    XVFADD_S                              = 1898, // LoongArchLASXInstrInfo.td:754
    XVFCLASS_D                            = 1899, // LoongArchLASXInstrInfo.td:786
    XVFCLASS_S                            = 1900, // LoongArchLASXInstrInfo.td:785
    XVFCMP_CAF_D                          = 1901, // LoongArchLASXInstrInfo.td:925
    XVFCMP_CAF_S                          = 1902, // LoongArchLASXInstrInfo.td:902
    XVFCMP_CEQ_D                          = 1903, // LoongArchLASXInstrInfo.td:929
    XVFCMP_CEQ_S                          = 1904, // LoongArchLASXInstrInfo.td:906
    XVFCMP_CLE_D                          = 1905, // LoongArchLASXInstrInfo.td:931
    XVFCMP_CLE_S                          = 1906, // LoongArchLASXInstrInfo.td:908
    XVFCMP_CLT_D                          = 1907, // LoongArchLASXInstrInfo.td:927
    XVFCMP_CLT_S                          = 1908, // LoongArchLASXInstrInfo.td:904
    XVFCMP_CNE_D                          = 1909, // LoongArchLASXInstrInfo.td:941
    XVFCMP_CNE_S                          = 1910, // LoongArchLASXInstrInfo.td:918
    XVFCMP_COR_D                          = 1911, // LoongArchLASXInstrInfo.td:943
    XVFCMP_COR_S                          = 1912, // LoongArchLASXInstrInfo.td:920
    XVFCMP_CUEQ_D                         = 1913, // LoongArchLASXInstrInfo.td:937
    XVFCMP_CUEQ_S                         = 1914, // LoongArchLASXInstrInfo.td:914
    XVFCMP_CULE_D                         = 1915, // LoongArchLASXInstrInfo.td:939
    XVFCMP_CULE_S                         = 1916, // LoongArchLASXInstrInfo.td:916
    XVFCMP_CULT_D                         = 1917, // LoongArchLASXInstrInfo.td:935
    XVFCMP_CULT_S                         = 1918, // LoongArchLASXInstrInfo.td:912
    XVFCMP_CUNE_D                         = 1919, // LoongArchLASXInstrInfo.td:945
    XVFCMP_CUNE_S                         = 1920, // LoongArchLASXInstrInfo.td:922
    XVFCMP_CUN_D                          = 1921, // LoongArchLASXInstrInfo.td:933
    XVFCMP_CUN_S                          = 1922, // LoongArchLASXInstrInfo.td:910
    XVFCMP_SAF_D                          = 1923, // LoongArchLASXInstrInfo.td:926
    XVFCMP_SAF_S                          = 1924, // LoongArchLASXInstrInfo.td:903
    XVFCMP_SEQ_D                          = 1925, // LoongArchLASXInstrInfo.td:930
    XVFCMP_SEQ_S                          = 1926, // LoongArchLASXInstrInfo.td:907
    XVFCMP_SLE_D                          = 1927, // LoongArchLASXInstrInfo.td:932
    XVFCMP_SLE_S                          = 1928, // LoongArchLASXInstrInfo.td:909
    XVFCMP_SLT_D                          = 1929, // LoongArchLASXInstrInfo.td:928
    XVFCMP_SLT_S                          = 1930, // LoongArchLASXInstrInfo.td:905
    XVFCMP_SNE_D                          = 1931, // LoongArchLASXInstrInfo.td:942
    XVFCMP_SNE_S                          = 1932, // LoongArchLASXInstrInfo.td:919
    XVFCMP_SOR_D                          = 1933, // LoongArchLASXInstrInfo.td:944
    XVFCMP_SOR_S                          = 1934, // LoongArchLASXInstrInfo.td:921
    XVFCMP_SUEQ_D                         = 1935, // LoongArchLASXInstrInfo.td:938
    XVFCMP_SUEQ_S                         = 1936, // LoongArchLASXInstrInfo.td:915
    XVFCMP_SULE_D                         = 1937, // LoongArchLASXInstrInfo.td:940
    XVFCMP_SULE_S                         = 1938, // LoongArchLASXInstrInfo.td:917
    XVFCMP_SULT_D                         = 1939, // LoongArchLASXInstrInfo.td:936
    XVFCMP_SULT_S                         = 1940, // LoongArchLASXInstrInfo.td:913
    XVFCMP_SUNE_D                         = 1941, // LoongArchLASXInstrInfo.td:946
    XVFCMP_SUNE_S                         = 1942, // LoongArchLASXInstrInfo.td:923
    XVFCMP_SUN_D                          = 1943, // LoongArchLASXInstrInfo.td:934
    XVFCMP_SUN_S                          = 1944, // LoongArchLASXInstrInfo.td:911
    XVFCVTH_D_S                           = 1945, // LoongArchLASXInstrInfo.td:802
    XVFCVTH_S_H                           = 1946, // LoongArchLASXInstrInfo.td:800
    XVFCVTL_D_S                           = 1947, // LoongArchLASXInstrInfo.td:801
    XVFCVTL_S_H                           = 1948, // LoongArchLASXInstrInfo.td:799
    XVFCVT_H_S                            = 1949, // LoongArchLASXInstrInfo.td:803
    XVFCVT_S_D                            = 1950, // LoongArchLASXInstrInfo.td:804
    XVFDIV_D                              = 1951, // LoongArchLASXInstrInfo.td:761
    XVFDIV_S                              = 1952, // LoongArchLASXInstrInfo.td:760
    XVFFINTH_D_W                          = 1953, // LoongArchLASXInstrInfo.td:854
    XVFFINTL_D_W                          = 1954, // LoongArchLASXInstrInfo.td:853
    XVFFINT_D_L                           = 1955, // LoongArchLASXInstrInfo.td:850
    XVFFINT_D_LU                          = 1956, // LoongArchLASXInstrInfo.td:852
    XVFFINT_S_L                           = 1957, // LoongArchLASXInstrInfo.td:855
    XVFFINT_S_W                           = 1958, // LoongArchLASXInstrInfo.td:849
    XVFFINT_S_WU                          = 1959, // LoongArchLASXInstrInfo.td:851
    XVFLOGB_D                             = 1960, // LoongArchLASXInstrInfo.td:783
    XVFLOGB_S                             = 1961, // LoongArchLASXInstrInfo.td:782
    XVFMADD_D                             = 1962, // LoongArchLASXInstrInfo.td:764
    XVFMADD_S                             = 1963, // LoongArchLASXInstrInfo.td:763
    XVFMAXA_D                             = 1964, // LoongArchLASXInstrInfo.td:778
    XVFMAXA_S                             = 1965, // LoongArchLASXInstrInfo.td:777
    XVFMAX_D                              = 1966, // LoongArchLASXInstrInfo.td:773
    XVFMAX_S                              = 1967, // LoongArchLASXInstrInfo.td:772
    XVFMINA_D                             = 1968, // LoongArchLASXInstrInfo.td:780
    XVFMINA_S                             = 1969, // LoongArchLASXInstrInfo.td:779
    XVFMIN_D                              = 1970, // LoongArchLASXInstrInfo.td:775
    XVFMIN_S                              = 1971, // LoongArchLASXInstrInfo.td:774
    XVFMSUB_D                             = 1972, // LoongArchLASXInstrInfo.td:766
    XVFMSUB_S                             = 1973, // LoongArchLASXInstrInfo.td:765
    XVFMUL_D                              = 1974, // LoongArchLASXInstrInfo.td:759
    XVFMUL_S                              = 1975, // LoongArchLASXInstrInfo.td:758
    XVFNMADD_D                            = 1976, // LoongArchLASXInstrInfo.td:768
    XVFNMADD_S                            = 1977, // LoongArchLASXInstrInfo.td:767
    XVFNMSUB_D                            = 1978, // LoongArchLASXInstrInfo.td:770
    XVFNMSUB_S                            = 1979, // LoongArchLASXInstrInfo.td:769
    XVFRECIPE_D                           = 1980, // LoongArchLASXInstrInfo.td:795
    XVFRECIPE_S                           = 1981, // LoongArchLASXInstrInfo.td:794
    XVFRECIP_D                            = 1982, // LoongArchLASXInstrInfo.td:791
    XVFRECIP_S                            = 1983, // LoongArchLASXInstrInfo.td:790
    XVFRINTRM_D                           = 1984, // LoongArchLASXInstrInfo.td:813
    XVFRINTRM_S                           = 1985, // LoongArchLASXInstrInfo.td:812
    XVFRINTRNE_D                          = 1986, // LoongArchLASXInstrInfo.td:807
    XVFRINTRNE_S                          = 1987, // LoongArchLASXInstrInfo.td:806
    XVFRINTRP_D                           = 1988, // LoongArchLASXInstrInfo.td:811
    XVFRINTRP_S                           = 1989, // LoongArchLASXInstrInfo.td:810
    XVFRINTRZ_D                           = 1990, // LoongArchLASXInstrInfo.td:809
    XVFRINTRZ_S                           = 1991, // LoongArchLASXInstrInfo.td:808
    XVFRINT_D                             = 1992, // LoongArchLASXInstrInfo.td:815
    XVFRINT_S                             = 1993, // LoongArchLASXInstrInfo.td:814
    XVFRSQRTE_D                           = 1994, // LoongArchLASXInstrInfo.td:797
    XVFRSQRTE_S                           = 1995, // LoongArchLASXInstrInfo.td:796
    XVFRSQRT_D                            = 1996, // LoongArchLASXInstrInfo.td:793
    XVFRSQRT_S                            = 1997, // LoongArchLASXInstrInfo.td:792
    XVFRSTPI_B                            = 1998, // LoongArchLASXInstrInfo.td:751
    XVFRSTPI_H                            = 1999, // LoongArchLASXInstrInfo.td:752
    XVFRSTP_B                             = 2000, // LoongArchLASXInstrInfo.td:749
    XVFRSTP_H                             = 2001, // LoongArchLASXInstrInfo.td:750
    XVFSQRT_D                             = 2002, // LoongArchLASXInstrInfo.td:789
    XVFSQRT_S                             = 2003, // LoongArchLASXInstrInfo.td:788
    XVFSUB_D                              = 2004, // LoongArchLASXInstrInfo.td:757
    XVFSUB_S                              = 2005, // LoongArchLASXInstrInfo.td:756
    XVFTINTH_L_S                          = 2006, // LoongArchLASXInstrInfo.td:847
    XVFTINTL_L_S                          = 2007, // LoongArchLASXInstrInfo.td:846
    XVFTINTRMH_L_S                        = 2008, // LoongArchLASXInstrInfo.td:845
    XVFTINTRML_L_S                        = 2009, // LoongArchLASXInstrInfo.td:844
    XVFTINTRM_L_D                         = 2010, // LoongArchLASXInstrInfo.td:824
    XVFTINTRM_W_D                         = 2011, // LoongArchLASXInstrInfo.td:835
    XVFTINTRM_W_S                         = 2012, // LoongArchLASXInstrInfo.td:823
    XVFTINTRNEH_L_S                       = 2013, // LoongArchLASXInstrInfo.td:839
    XVFTINTRNEL_L_S                       = 2014, // LoongArchLASXInstrInfo.td:838
    XVFTINTRNE_L_D                        = 2015, // LoongArchLASXInstrInfo.td:818
    XVFTINTRNE_W_D                        = 2016, // LoongArchLASXInstrInfo.td:832
    XVFTINTRNE_W_S                        = 2017, // LoongArchLASXInstrInfo.td:817
    XVFTINTRPH_L_S                        = 2018, // LoongArchLASXInstrInfo.td:843
    XVFTINTRPL_L_S                        = 2019, // LoongArchLASXInstrInfo.td:842
    XVFTINTRP_L_D                         = 2020, // LoongArchLASXInstrInfo.td:822
    XVFTINTRP_W_D                         = 2021, // LoongArchLASXInstrInfo.td:834
    XVFTINTRP_W_S                         = 2022, // LoongArchLASXInstrInfo.td:821
    XVFTINTRZH_L_S                        = 2023, // LoongArchLASXInstrInfo.td:841
    XVFTINTRZL_L_S                        = 2024, // LoongArchLASXInstrInfo.td:840
    XVFTINTRZ_LU_D                        = 2025, // LoongArchLASXInstrInfo.td:828
    XVFTINTRZ_L_D                         = 2026, // LoongArchLASXInstrInfo.td:820
    XVFTINTRZ_WU_S                        = 2027, // LoongArchLASXInstrInfo.td:827
    XVFTINTRZ_W_D                         = 2028, // LoongArchLASXInstrInfo.td:833
    XVFTINTRZ_W_S                         = 2029, // LoongArchLASXInstrInfo.td:819
    XVFTINT_LU_D                          = 2030, // LoongArchLASXInstrInfo.td:830
    XVFTINT_L_D                           = 2031, // LoongArchLASXInstrInfo.td:826
    XVFTINT_WU_S                          = 2032, // LoongArchLASXInstrInfo.td:829
    XVFTINT_W_D                           = 2033, // LoongArchLASXInstrInfo.td:836
    XVFTINT_W_S                           = 2034, // LoongArchLASXInstrInfo.td:825
    XVHADDW_DU_WU                         = 2035, // LoongArchLASXInstrInfo.td:278
    XVHADDW_D_W                           = 2036, // LoongArchLASXInstrInfo.td:274
    XVHADDW_HU_BU                         = 2037, // LoongArchLASXInstrInfo.td:276
    XVHADDW_H_B                           = 2038, // LoongArchLASXInstrInfo.td:272
    XVHADDW_QU_DU                         = 2039, // LoongArchLASXInstrInfo.td:279
    XVHADDW_Q_D                           = 2040, // LoongArchLASXInstrInfo.td:275
    XVHADDW_WU_HU                         = 2041, // LoongArchLASXInstrInfo.td:277
    XVHADDW_W_H                           = 2042, // LoongArchLASXInstrInfo.td:273
    XVHSELI_D                             = 2043, // LoongArchLASXInstrInfo.td:523
    XVHSUBW_DU_WU                         = 2044, // LoongArchLASXInstrInfo.td:287
    XVHSUBW_D_W                           = 2045, // LoongArchLASXInstrInfo.td:283
    XVHSUBW_HU_BU                         = 2046, // LoongArchLASXInstrInfo.td:285
    XVHSUBW_H_B                           = 2047, // LoongArchLASXInstrInfo.td:281
    XVHSUBW_QU_DU                         = 2048, // LoongArchLASXInstrInfo.td:288
    XVHSUBW_Q_D                           = 2049, // LoongArchLASXInstrInfo.td:284
    XVHSUBW_WU_HU                         = 2050, // LoongArchLASXInstrInfo.td:286
    XVHSUBW_W_H                           = 2051, // LoongArchLASXInstrInfo.td:282
    XVILVH_B                              = 2052, // LoongArchLASXInstrInfo.td:1023
    XVILVH_D                              = 2053, // LoongArchLASXInstrInfo.td:1026
    XVILVH_H                              = 2054, // LoongArchLASXInstrInfo.td:1024
    XVILVH_W                              = 2055, // LoongArchLASXInstrInfo.td:1025
    XVILVL_B                              = 2056, // LoongArchLASXInstrInfo.td:1019
    XVILVL_D                              = 2057, // LoongArchLASXInstrInfo.td:1022
    XVILVL_H                              = 2058, // LoongArchLASXInstrInfo.td:1020
    XVILVL_W                              = 2059, // LoongArchLASXInstrInfo.td:1021
    XVINSGR2VR_D                          = 2060, // LoongArchLASXInstrInfo.td:964
    XVINSGR2VR_W                          = 2061, // LoongArchLASXInstrInfo.td:963
    XVINSVE0_D                            = 2062, // LoongArchLASXInstrInfo.td:993
    XVINSVE0_W                            = 2063, // LoongArchLASXInstrInfo.td:992
    XVLD                                  = 2064, // LoongArchLASXInstrInfo.td:1052
    XVLDI                                 = 2065, // LoongArchLASXInstrInfo.td:539
    XVLDREPL_B                            = 2066, // LoongArchLASXInstrInfo.td:1055
    XVLDREPL_D                            = 2067, // LoongArchLASXInstrInfo.td:1058
    XVLDREPL_H                            = 2068, // LoongArchLASXInstrInfo.td:1056
    XVLDREPL_W                            = 2069, // LoongArchLASXInstrInfo.td:1057
    XVLDX                                 = 2070, // LoongArchLASXInstrInfo.td:1053
    XVMADDWEV_D_W                         = 2071, // LoongArchLASXInstrInfo.td:451
    XVMADDWEV_D_WU                        = 2072, // LoongArchLASXInstrInfo.td:459
    XVMADDWEV_D_WU_W                      = 2073, // LoongArchLASXInstrInfo.td:467
    XVMADDWEV_H_B                         = 2074, // LoongArchLASXInstrInfo.td:449
    XVMADDWEV_H_BU                        = 2075, // LoongArchLASXInstrInfo.td:457
    XVMADDWEV_H_BU_B                      = 2076, // LoongArchLASXInstrInfo.td:465
    XVMADDWEV_Q_D                         = 2077, // LoongArchLASXInstrInfo.td:452
    XVMADDWEV_Q_DU                        = 2078, // LoongArchLASXInstrInfo.td:460
    XVMADDWEV_Q_DU_D                      = 2079, // LoongArchLASXInstrInfo.td:468
    XVMADDWEV_W_H                         = 2080, // LoongArchLASXInstrInfo.td:450
    XVMADDWEV_W_HU                        = 2081, // LoongArchLASXInstrInfo.td:458
    XVMADDWEV_W_HU_H                      = 2082, // LoongArchLASXInstrInfo.td:466
    XVMADDWOD_D_W                         = 2083, // LoongArchLASXInstrInfo.td:455
    XVMADDWOD_D_WU                        = 2084, // LoongArchLASXInstrInfo.td:463
    XVMADDWOD_D_WU_W                      = 2085, // LoongArchLASXInstrInfo.td:471
    XVMADDWOD_H_B                         = 2086, // LoongArchLASXInstrInfo.td:453
    XVMADDWOD_H_BU                        = 2087, // LoongArchLASXInstrInfo.td:461
    XVMADDWOD_H_BU_B                      = 2088, // LoongArchLASXInstrInfo.td:469
    XVMADDWOD_Q_D                         = 2089, // LoongArchLASXInstrInfo.td:456
    XVMADDWOD_Q_DU                        = 2090, // LoongArchLASXInstrInfo.td:464
    XVMADDWOD_Q_DU_D                      = 2091, // LoongArchLASXInstrInfo.td:472
    XVMADDWOD_W_H                         = 2092, // LoongArchLASXInstrInfo.td:454
    XVMADDWOD_W_HU                        = 2093, // LoongArchLASXInstrInfo.td:462
    XVMADDWOD_W_HU_H                      = 2094, // LoongArchLASXInstrInfo.td:470
    XVMADD_B                              = 2095, // LoongArchLASXInstrInfo.td:439
    XVMADD_D                              = 2096, // LoongArchLASXInstrInfo.td:442
    XVMADD_H                              = 2097, // LoongArchLASXInstrInfo.td:440
    XVMADD_W                              = 2098, // LoongArchLASXInstrInfo.td:441
    XVMAXI_B                              = 2099, // LoongArchLASXInstrInfo.td:370
    XVMAXI_BU                             = 2100, // LoongArchLASXInstrInfo.td:378
    XVMAXI_D                              = 2101, // LoongArchLASXInstrInfo.td:373
    XVMAXI_DU                             = 2102, // LoongArchLASXInstrInfo.td:381
    XVMAXI_H                              = 2103, // LoongArchLASXInstrInfo.td:371
    XVMAXI_HU                             = 2104, // LoongArchLASXInstrInfo.td:379
    XVMAXI_W                              = 2105, // LoongArchLASXInstrInfo.td:372
    XVMAXI_WU                             = 2106, // LoongArchLASXInstrInfo.td:380
    XVMAX_B                               = 2107, // LoongArchLASXInstrInfo.td:366
    XVMAX_BU                              = 2108, // LoongArchLASXInstrInfo.td:374
    XVMAX_D                               = 2109, // LoongArchLASXInstrInfo.td:369
    XVMAX_DU                              = 2110, // LoongArchLASXInstrInfo.td:377
    XVMAX_H                               = 2111, // LoongArchLASXInstrInfo.td:367
    XVMAX_HU                              = 2112, // LoongArchLASXInstrInfo.td:375
    XVMAX_W                               = 2113, // LoongArchLASXInstrInfo.td:368
    XVMAX_WU                              = 2114, // LoongArchLASXInstrInfo.td:376
    XVMINI_B                              = 2115, // LoongArchLASXInstrInfo.td:387
    XVMINI_BU                             = 2116, // LoongArchLASXInstrInfo.td:395
    XVMINI_D                              = 2117, // LoongArchLASXInstrInfo.td:390
    XVMINI_DU                             = 2118, // LoongArchLASXInstrInfo.td:398
    XVMINI_H                              = 2119, // LoongArchLASXInstrInfo.td:388
    XVMINI_HU                             = 2120, // LoongArchLASXInstrInfo.td:396
    XVMINI_W                              = 2121, // LoongArchLASXInstrInfo.td:389
    XVMINI_WU                             = 2122, // LoongArchLASXInstrInfo.td:397
    XVMIN_B                               = 2123, // LoongArchLASXInstrInfo.td:383
    XVMIN_BU                              = 2124, // LoongArchLASXInstrInfo.td:391
    XVMIN_D                               = 2125, // LoongArchLASXInstrInfo.td:386
    XVMIN_DU                              = 2126, // LoongArchLASXInstrInfo.td:394
    XVMIN_H                               = 2127, // LoongArchLASXInstrInfo.td:384
    XVMIN_HU                              = 2128, // LoongArchLASXInstrInfo.td:392
    XVMIN_W                               = 2129, // LoongArchLASXInstrInfo.td:385
    XVMIN_WU                              = 2130, // LoongArchLASXInstrInfo.td:393
    XVMOD_B                               = 2131, // LoongArchLASXInstrInfo.td:483
    XVMOD_BU                              = 2132, // LoongArchLASXInstrInfo.td:487
    XVMOD_D                               = 2133, // LoongArchLASXInstrInfo.td:486
    XVMOD_DU                              = 2134, // LoongArchLASXInstrInfo.td:490
    XVMOD_H                               = 2135, // LoongArchLASXInstrInfo.td:484
    XVMOD_HU                              = 2136, // LoongArchLASXInstrInfo.td:488
    XVMOD_W                               = 2137, // LoongArchLASXInstrInfo.td:485
    XVMOD_WU                              = 2138, // LoongArchLASXInstrInfo.td:489
    XVMSKGEZ_B                            = 2139, // LoongArchLASXInstrInfo.td:535
    XVMSKLTZ_B                            = 2140, // LoongArchLASXInstrInfo.td:530
    XVMSKLTZ_D                            = 2141, // LoongArchLASXInstrInfo.td:533
    XVMSKLTZ_H                            = 2142, // LoongArchLASXInstrInfo.td:531
    XVMSKLTZ_W                            = 2143, // LoongArchLASXInstrInfo.td:532
    XVMSKNZ_B                             = 2144, // LoongArchLASXInstrInfo.td:537
    XVMSUB_B                              = 2145, // LoongArchLASXInstrInfo.td:444
    XVMSUB_D                              = 2146, // LoongArchLASXInstrInfo.td:447
    XVMSUB_H                              = 2147, // LoongArchLASXInstrInfo.td:445
    XVMSUB_W                              = 2148, // LoongArchLASXInstrInfo.td:446
    XVMUH_B                               = 2149, // LoongArchLASXInstrInfo.td:405
    XVMUH_BU                              = 2150, // LoongArchLASXInstrInfo.td:409
    XVMUH_D                               = 2151, // LoongArchLASXInstrInfo.td:408
    XVMUH_DU                              = 2152, // LoongArchLASXInstrInfo.td:412
    XVMUH_H                               = 2153, // LoongArchLASXInstrInfo.td:406
    XVMUH_HU                              = 2154, // LoongArchLASXInstrInfo.td:410
    XVMUH_W                               = 2155, // LoongArchLASXInstrInfo.td:407
    XVMUH_WU                              = 2156, // LoongArchLASXInstrInfo.td:411
    XVMULWEV_D_W                          = 2157, // LoongArchLASXInstrInfo.td:416
    XVMULWEV_D_WU                         = 2158, // LoongArchLASXInstrInfo.td:424
    XVMULWEV_D_WU_W                       = 2159, // LoongArchLASXInstrInfo.td:432
    XVMULWEV_H_B                          = 2160, // LoongArchLASXInstrInfo.td:414
    XVMULWEV_H_BU                         = 2161, // LoongArchLASXInstrInfo.td:422
    XVMULWEV_H_BU_B                       = 2162, // LoongArchLASXInstrInfo.td:430
    XVMULWEV_Q_D                          = 2163, // LoongArchLASXInstrInfo.td:417
    XVMULWEV_Q_DU                         = 2164, // LoongArchLASXInstrInfo.td:425
    XVMULWEV_Q_DU_D                       = 2165, // LoongArchLASXInstrInfo.td:433
    XVMULWEV_W_H                          = 2166, // LoongArchLASXInstrInfo.td:415
    XVMULWEV_W_HU                         = 2167, // LoongArchLASXInstrInfo.td:423
    XVMULWEV_W_HU_H                       = 2168, // LoongArchLASXInstrInfo.td:431
    XVMULWOD_D_W                          = 2169, // LoongArchLASXInstrInfo.td:420
    XVMULWOD_D_WU                         = 2170, // LoongArchLASXInstrInfo.td:428
    XVMULWOD_D_WU_W                       = 2171, // LoongArchLASXInstrInfo.td:436
    XVMULWOD_H_B                          = 2172, // LoongArchLASXInstrInfo.td:418
    XVMULWOD_H_BU                         = 2173, // LoongArchLASXInstrInfo.td:426
    XVMULWOD_H_BU_B                       = 2174, // LoongArchLASXInstrInfo.td:434
    XVMULWOD_Q_D                          = 2175, // LoongArchLASXInstrInfo.td:421
    XVMULWOD_Q_DU                         = 2176, // LoongArchLASXInstrInfo.td:429
    XVMULWOD_Q_DU_D                       = 2177, // LoongArchLASXInstrInfo.td:437
    XVMULWOD_W_H                          = 2178, // LoongArchLASXInstrInfo.td:419
    XVMULWOD_W_HU                         = 2179, // LoongArchLASXInstrInfo.td:427
    XVMULWOD_W_HU_H                       = 2180, // LoongArchLASXInstrInfo.td:435
    XVMUL_B                               = 2181, // LoongArchLASXInstrInfo.td:400
    XVMUL_D                               = 2182, // LoongArchLASXInstrInfo.td:403
    XVMUL_H                               = 2183, // LoongArchLASXInstrInfo.td:401
    XVMUL_W                               = 2184, // LoongArchLASXInstrInfo.td:402
    XVNEG_B                               = 2185, // LoongArchLASXInstrInfo.td:249
    XVNEG_D                               = 2186, // LoongArchLASXInstrInfo.td:252
    XVNEG_H                               = 2187, // LoongArchLASXInstrInfo.td:250
    XVNEG_W                               = 2188, // LoongArchLASXInstrInfo.td:251
    XVNORI_B                              = 2189, // LoongArchLASXInstrInfo.td:551
    XVNOR_V                               = 2190, // LoongArchLASXInstrInfo.td:544
    XVORI_B                               = 2191, // LoongArchLASXInstrInfo.td:549
    XVORN_V                               = 2192, // LoongArchLASXInstrInfo.td:546
    XVOR_V                                = 2193, // LoongArchLASXInstrInfo.td:542
    XVPACKEV_B                            = 2194, // LoongArchLASXInstrInfo.td:1001
    XVPACKEV_D                            = 2195, // LoongArchLASXInstrInfo.td:1004
    XVPACKEV_H                            = 2196, // LoongArchLASXInstrInfo.td:1002
    XVPACKEV_W                            = 2197, // LoongArchLASXInstrInfo.td:1003
    XVPACKOD_B                            = 2198, // LoongArchLASXInstrInfo.td:1005
    XVPACKOD_D                            = 2199, // LoongArchLASXInstrInfo.td:1008
    XVPACKOD_H                            = 2200, // LoongArchLASXInstrInfo.td:1006
    XVPACKOD_W                            = 2201, // LoongArchLASXInstrInfo.td:1007
    XVPCNT_B                              = 2202, // LoongArchLASXInstrInfo.td:717
    XVPCNT_D                              = 2203, // LoongArchLASXInstrInfo.td:720
    XVPCNT_H                              = 2204, // LoongArchLASXInstrInfo.td:718
    XVPCNT_W                              = 2205, // LoongArchLASXInstrInfo.td:719
    XVPERMI_D                             = 2206, // LoongArchLASXInstrInfo.td:1042
    XVPERMI_Q                             = 2207, // LoongArchLASXInstrInfo.td:1043
    XVPERMI_W                             = 2208, // LoongArchLASXInstrInfo.td:1041
    XVPERM_W                              = 2209, // LoongArchLASXInstrInfo.td:1034
    XVPICKEV_B                            = 2210, // LoongArchLASXInstrInfo.td:1010
    XVPICKEV_D                            = 2211, // LoongArchLASXInstrInfo.td:1013
    XVPICKEV_H                            = 2212, // LoongArchLASXInstrInfo.td:1011
    XVPICKEV_W                            = 2213, // LoongArchLASXInstrInfo.td:1012
    XVPICKOD_B                            = 2214, // LoongArchLASXInstrInfo.td:1014
    XVPICKOD_D                            = 2215, // LoongArchLASXInstrInfo.td:1017
    XVPICKOD_H                            = 2216, // LoongArchLASXInstrInfo.td:1015
    XVPICKOD_W                            = 2217, // LoongArchLASXInstrInfo.td:1016
    XVPICKVE2GR_D                         = 2218, // LoongArchLASXInstrInfo.td:966
    XVPICKVE2GR_DU                        = 2219, // LoongArchLASXInstrInfo.td:968
    XVPICKVE2GR_W                         = 2220, // LoongArchLASXInstrInfo.td:965
    XVPICKVE2GR_WU                        = 2221, // LoongArchLASXInstrInfo.td:967
    XVPICKVE_D                            = 2222, // LoongArchLASXInstrInfo.td:996
    XVPICKVE_W                            = 2223, // LoongArchLASXInstrInfo.td:995
    XVREPL128VEI_B                        = 2224, // LoongArchLASXInstrInfo.td:981
    XVREPL128VEI_D                        = 2225, // LoongArchLASXInstrInfo.td:984
    XVREPL128VEI_H                        = 2226, // LoongArchLASXInstrInfo.td:982
    XVREPL128VEI_W                        = 2227, // LoongArchLASXInstrInfo.td:983
    XVREPLGR2VR_B                         = 2228, // LoongArchLASXInstrInfo.td:971
    XVREPLGR2VR_D                         = 2229, // LoongArchLASXInstrInfo.td:974
    XVREPLGR2VR_H                         = 2230, // LoongArchLASXInstrInfo.td:972
    XVREPLGR2VR_W                         = 2231, // LoongArchLASXInstrInfo.td:973
    XVREPLVE0_B                           = 2232, // LoongArchLASXInstrInfo.td:986
    XVREPLVE0_D                           = 2233, // LoongArchLASXInstrInfo.td:989
    XVREPLVE0_H                           = 2234, // LoongArchLASXInstrInfo.td:987
    XVREPLVE0_Q                           = 2235, // LoongArchLASXInstrInfo.td:990
    XVREPLVE0_W                           = 2236, // LoongArchLASXInstrInfo.td:988
    XVREPLVE_B                            = 2237, // LoongArchLASXInstrInfo.td:977
    XVREPLVE_D                            = 2238, // LoongArchLASXInstrInfo.td:980
    XVREPLVE_H                            = 2239, // LoongArchLASXInstrInfo.td:978
    XVREPLVE_W                            = 2240, // LoongArchLASXInstrInfo.td:979
    XVROTRI_B                             = 2241, // LoongArchLASXInstrInfo.td:584
    XVROTRI_D                             = 2242, // LoongArchLASXInstrInfo.td:587
    XVROTRI_H                             = 2243, // LoongArchLASXInstrInfo.td:585
    XVROTRI_W                             = 2244, // LoongArchLASXInstrInfo.td:586
    XVROTR_B                              = 2245, // LoongArchLASXInstrInfo.td:580
    XVROTR_D                              = 2246, // LoongArchLASXInstrInfo.td:583
    XVROTR_H                              = 2247, // LoongArchLASXInstrInfo.td:581
    XVROTR_W                              = 2248, // LoongArchLASXInstrInfo.td:582
    XVSADD_B                              = 2249, // LoongArchLASXInstrInfo.td:254
    XVSADD_BU                             = 2250, // LoongArchLASXInstrInfo.td:258
    XVSADD_D                              = 2251, // LoongArchLASXInstrInfo.td:257
    XVSADD_DU                             = 2252, // LoongArchLASXInstrInfo.td:261
    XVSADD_H                              = 2253, // LoongArchLASXInstrInfo.td:255
    XVSADD_HU                             = 2254, // LoongArchLASXInstrInfo.td:259
    XVSADD_W                              = 2255, // LoongArchLASXInstrInfo.td:256
    XVSADD_WU                             = 2256, // LoongArchLASXInstrInfo.td:260
    XVSAT_B                               = 2257, // LoongArchLASXInstrInfo.td:492
    XVSAT_BU                              = 2258, // LoongArchLASXInstrInfo.td:496
    XVSAT_D                               = 2259, // LoongArchLASXInstrInfo.td:495
    XVSAT_DU                              = 2260, // LoongArchLASXInstrInfo.td:499
    XVSAT_H                               = 2261, // LoongArchLASXInstrInfo.td:493
    XVSAT_HU                              = 2262, // LoongArchLASXInstrInfo.td:497
    XVSAT_W                               = 2263, // LoongArchLASXInstrInfo.td:494
    XVSAT_WU                              = 2264, // LoongArchLASXInstrInfo.td:498
    XVSEQI_B                              = 2265, // LoongArchLASXInstrInfo.td:861
    XVSEQI_D                              = 2266, // LoongArchLASXInstrInfo.td:864
    XVSEQI_H                              = 2267, // LoongArchLASXInstrInfo.td:862
    XVSEQI_W                              = 2268, // LoongArchLASXInstrInfo.td:863
    XVSEQ_B                               = 2269, // LoongArchLASXInstrInfo.td:857
    XVSEQ_D                               = 2270, // LoongArchLASXInstrInfo.td:860
    XVSEQ_H                               = 2271, // LoongArchLASXInstrInfo.td:858
    XVSEQ_W                               = 2272, // LoongArchLASXInstrInfo.td:859
    XVSETALLNEZ_B                         = 2273, // LoongArchLASXInstrInfo.td:958
    XVSETALLNEZ_D                         = 2274, // LoongArchLASXInstrInfo.td:961
    XVSETALLNEZ_H                         = 2275, // LoongArchLASXInstrInfo.td:959
    XVSETALLNEZ_W                         = 2276, // LoongArchLASXInstrInfo.td:960
    XVSETANYEQZ_B                         = 2277, // LoongArchLASXInstrInfo.td:954
    XVSETANYEQZ_D                         = 2278, // LoongArchLASXInstrInfo.td:957
    XVSETANYEQZ_H                         = 2279, // LoongArchLASXInstrInfo.td:955
    XVSETANYEQZ_W                         = 2280, // LoongArchLASXInstrInfo.td:956
    XVSETEQZ_V                            = 2281, // LoongArchLASXInstrInfo.td:952
    XVSETNEZ_V                            = 2282, // LoongArchLASXInstrInfo.td:953
    XVSHUF4I_B                            = 2283, // LoongArchLASXInstrInfo.td:1036
    XVSHUF4I_D                            = 2284, // LoongArchLASXInstrInfo.td:1039
    XVSHUF4I_H                            = 2285, // LoongArchLASXInstrInfo.td:1037
    XVSHUF4I_W                            = 2286, // LoongArchLASXInstrInfo.td:1038
    XVSHUF_B                              = 2287, // LoongArchLASXInstrInfo.td:1028
    XVSHUF_D                              = 2288, // LoongArchLASXInstrInfo.td:1032
    XVSHUF_H                              = 2289, // LoongArchLASXInstrInfo.td:1030
    XVSHUF_W                              = 2290, // LoongArchLASXInstrInfo.td:1031
    XVSIGNCOV_B                           = 2291, // LoongArchLASXInstrInfo.td:525
    XVSIGNCOV_D                           = 2292, // LoongArchLASXInstrInfo.td:528
    XVSIGNCOV_H                           = 2293, // LoongArchLASXInstrInfo.td:526
    XVSIGNCOV_W                           = 2294, // LoongArchLASXInstrInfo.td:527
    XVSLEI_B                              = 2295, // LoongArchLASXInstrInfo.td:870
    XVSLEI_BU                             = 2296, // LoongArchLASXInstrInfo.td:879
    XVSLEI_D                              = 2297, // LoongArchLASXInstrInfo.td:873
    XVSLEI_DU                             = 2298, // LoongArchLASXInstrInfo.td:882
    XVSLEI_H                              = 2299, // LoongArchLASXInstrInfo.td:871
    XVSLEI_HU                             = 2300, // LoongArchLASXInstrInfo.td:880
    XVSLEI_W                              = 2301, // LoongArchLASXInstrInfo.td:872
    XVSLEI_WU                             = 2302, // LoongArchLASXInstrInfo.td:881
    XVSLE_B                               = 2303, // LoongArchLASXInstrInfo.td:866
    XVSLE_BU                              = 2304, // LoongArchLASXInstrInfo.td:875
    XVSLE_D                               = 2305, // LoongArchLASXInstrInfo.td:869
    XVSLE_DU                              = 2306, // LoongArchLASXInstrInfo.td:878
    XVSLE_H                               = 2307, // LoongArchLASXInstrInfo.td:867
    XVSLE_HU                              = 2308, // LoongArchLASXInstrInfo.td:876
    XVSLE_W                               = 2309, // LoongArchLASXInstrInfo.td:868
    XVSLE_WU                              = 2310, // LoongArchLASXInstrInfo.td:877
    XVSLLI_B                              = 2311, // LoongArchLASXInstrInfo.td:557
    XVSLLI_D                              = 2312, // LoongArchLASXInstrInfo.td:560
    XVSLLI_H                              = 2313, // LoongArchLASXInstrInfo.td:558
    XVSLLI_W                              = 2314, // LoongArchLASXInstrInfo.td:559
    XVSLLWIL_DU_WU                        = 2315, // LoongArchLASXInstrInfo.td:595
    XVSLLWIL_D_W                          = 2316, // LoongArchLASXInstrInfo.td:591
    XVSLLWIL_HU_BU                        = 2317, // LoongArchLASXInstrInfo.td:593
    XVSLLWIL_H_B                          = 2318, // LoongArchLASXInstrInfo.td:589
    XVSLLWIL_WU_HU                        = 2319, // LoongArchLASXInstrInfo.td:594
    XVSLLWIL_W_H                          = 2320, // LoongArchLASXInstrInfo.td:590
    XVSLL_B                               = 2321, // LoongArchLASXInstrInfo.td:553
    XVSLL_D                               = 2322, // LoongArchLASXInstrInfo.td:556
    XVSLL_H                               = 2323, // LoongArchLASXInstrInfo.td:554
    XVSLL_W                               = 2324, // LoongArchLASXInstrInfo.td:555
    XVSLTI_B                              = 2325, // LoongArchLASXInstrInfo.td:888
    XVSLTI_BU                             = 2326, // LoongArchLASXInstrInfo.td:897
    XVSLTI_D                              = 2327, // LoongArchLASXInstrInfo.td:891
    XVSLTI_DU                             = 2328, // LoongArchLASXInstrInfo.td:900
    XVSLTI_H                              = 2329, // LoongArchLASXInstrInfo.td:889
    XVSLTI_HU                             = 2330, // LoongArchLASXInstrInfo.td:898
    XVSLTI_W                              = 2331, // LoongArchLASXInstrInfo.td:890
    XVSLTI_WU                             = 2332, // LoongArchLASXInstrInfo.td:899
    XVSLT_B                               = 2333, // LoongArchLASXInstrInfo.td:884
    XVSLT_BU                              = 2334, // LoongArchLASXInstrInfo.td:893
    XVSLT_D                               = 2335, // LoongArchLASXInstrInfo.td:887
    XVSLT_DU                              = 2336, // LoongArchLASXInstrInfo.td:896
    XVSLT_H                               = 2337, // LoongArchLASXInstrInfo.td:885
    XVSLT_HU                              = 2338, // LoongArchLASXInstrInfo.td:894
    XVSLT_W                               = 2339, // LoongArchLASXInstrInfo.td:886
    XVSLT_WU                              = 2340, // LoongArchLASXInstrInfo.td:895
    XVSRAI_B                              = 2341, // LoongArchLASXInstrInfo.td:575
    XVSRAI_D                              = 2342, // LoongArchLASXInstrInfo.td:578
    XVSRAI_H                              = 2343, // LoongArchLASXInstrInfo.td:576
    XVSRAI_W                              = 2344, // LoongArchLASXInstrInfo.td:577
    XVSRANI_B_H                           = 2345, // LoongArchLASXInstrInfo.td:627
    XVSRANI_D_Q                           = 2346, // LoongArchLASXInstrInfo.td:630
    XVSRANI_H_W                           = 2347, // LoongArchLASXInstrInfo.td:628
    XVSRANI_W_D                           = 2348, // LoongArchLASXInstrInfo.td:629
    XVSRAN_B_H                            = 2349, // LoongArchLASXInstrInfo.td:619
    XVSRAN_H_W                            = 2350, // LoongArchLASXInstrInfo.td:620
    XVSRAN_W_D                            = 2351, // LoongArchLASXInstrInfo.td:621
    XVSRARI_B                             = 2352, // LoongArchLASXInstrInfo.td:611
    XVSRARI_D                             = 2353, // LoongArchLASXInstrInfo.td:614
    XVSRARI_H                             = 2354, // LoongArchLASXInstrInfo.td:612
    XVSRARI_W                             = 2355, // LoongArchLASXInstrInfo.td:613
    XVSRARNI_B_H                          = 2356, // LoongArchLASXInstrInfo.td:643
    XVSRARNI_D_Q                          = 2357, // LoongArchLASXInstrInfo.td:646
    XVSRARNI_H_W                          = 2358, // LoongArchLASXInstrInfo.td:644
    XVSRARNI_W_D                          = 2359, // LoongArchLASXInstrInfo.td:645
    XVSRARN_B_H                           = 2360, // LoongArchLASXInstrInfo.td:635
    XVSRARN_H_W                           = 2361, // LoongArchLASXInstrInfo.td:636
    XVSRARN_W_D                           = 2362, // LoongArchLASXInstrInfo.td:637
    XVSRAR_B                              = 2363, // LoongArchLASXInstrInfo.td:607
    XVSRAR_D                              = 2364, // LoongArchLASXInstrInfo.td:610
    XVSRAR_H                              = 2365, // LoongArchLASXInstrInfo.td:608
    XVSRAR_W                              = 2366, // LoongArchLASXInstrInfo.td:609
    XVSRA_B                               = 2367, // LoongArchLASXInstrInfo.td:571
    XVSRA_D                               = 2368, // LoongArchLASXInstrInfo.td:574
    XVSRA_H                               = 2369, // LoongArchLASXInstrInfo.td:572
    XVSRA_W                               = 2370, // LoongArchLASXInstrInfo.td:573
    XVSRLI_B                              = 2371, // LoongArchLASXInstrInfo.td:566
    XVSRLI_D                              = 2372, // LoongArchLASXInstrInfo.td:569
    XVSRLI_H                              = 2373, // LoongArchLASXInstrInfo.td:567
    XVSRLI_W                              = 2374, // LoongArchLASXInstrInfo.td:568
    XVSRLNI_B_H                           = 2375, // LoongArchLASXInstrInfo.td:623
    XVSRLNI_D_Q                           = 2376, // LoongArchLASXInstrInfo.td:626
    XVSRLNI_H_W                           = 2377, // LoongArchLASXInstrInfo.td:624
    XVSRLNI_W_D                           = 2378, // LoongArchLASXInstrInfo.td:625
    XVSRLN_B_H                            = 2379, // LoongArchLASXInstrInfo.td:616
    XVSRLN_H_W                            = 2380, // LoongArchLASXInstrInfo.td:617
    XVSRLN_W_D                            = 2381, // LoongArchLASXInstrInfo.td:618
    XVSRLRI_B                             = 2382, // LoongArchLASXInstrInfo.td:602
    XVSRLRI_D                             = 2383, // LoongArchLASXInstrInfo.td:605
    XVSRLRI_H                             = 2384, // LoongArchLASXInstrInfo.td:603
    XVSRLRI_W                             = 2385, // LoongArchLASXInstrInfo.td:604
    XVSRLRNI_B_H                          = 2386, // LoongArchLASXInstrInfo.td:639
    XVSRLRNI_D_Q                          = 2387, // LoongArchLASXInstrInfo.td:642
    XVSRLRNI_H_W                          = 2388, // LoongArchLASXInstrInfo.td:640
    XVSRLRNI_W_D                          = 2389, // LoongArchLASXInstrInfo.td:641
    XVSRLRN_B_H                           = 2390, // LoongArchLASXInstrInfo.td:632
    XVSRLRN_H_W                           = 2391, // LoongArchLASXInstrInfo.td:633
    XVSRLRN_W_D                           = 2392, // LoongArchLASXInstrInfo.td:634
    XVSRLR_B                              = 2393, // LoongArchLASXInstrInfo.td:598
    XVSRLR_D                              = 2394, // LoongArchLASXInstrInfo.td:601
    XVSRLR_H                              = 2395, // LoongArchLASXInstrInfo.td:599
    XVSRLR_W                              = 2396, // LoongArchLASXInstrInfo.td:600
    XVSRL_B                               = 2397, // LoongArchLASXInstrInfo.td:562
    XVSRL_D                               = 2398, // LoongArchLASXInstrInfo.td:565
    XVSRL_H                               = 2399, // LoongArchLASXInstrInfo.td:563
    XVSRL_W                               = 2400, // LoongArchLASXInstrInfo.td:564
    XVSSRANI_BU_H                         = 2401, // LoongArchLASXInstrInfo.td:673
    XVSSRANI_B_H                          = 2402, // LoongArchLASXInstrInfo.td:665
    XVSSRANI_DU_Q                         = 2403, // LoongArchLASXInstrInfo.td:676
    XVSSRANI_D_Q                          = 2404, // LoongArchLASXInstrInfo.td:668
    XVSSRANI_HU_W                         = 2405, // LoongArchLASXInstrInfo.td:674
    XVSSRANI_H_W                          = 2406, // LoongArchLASXInstrInfo.td:666
    XVSSRANI_WU_D                         = 2407, // LoongArchLASXInstrInfo.td:675
    XVSSRANI_W_D                          = 2408, // LoongArchLASXInstrInfo.td:667
    XVSSRAN_BU_H                          = 2409, // LoongArchLASXInstrInfo.td:657
    XVSSRAN_B_H                           = 2410, // LoongArchLASXInstrInfo.td:651
    XVSSRAN_HU_W                          = 2411, // LoongArchLASXInstrInfo.td:658
    XVSSRAN_H_W                           = 2412, // LoongArchLASXInstrInfo.td:652
    XVSSRAN_WU_D                          = 2413, // LoongArchLASXInstrInfo.td:659
    XVSSRAN_W_D                           = 2414, // LoongArchLASXInstrInfo.td:653
    XVSSRARNI_BU_H                        = 2415, // LoongArchLASXInstrInfo.td:703
    XVSSRARNI_B_H                         = 2416, // LoongArchLASXInstrInfo.td:695
    XVSSRARNI_DU_Q                        = 2417, // LoongArchLASXInstrInfo.td:706
    XVSSRARNI_D_Q                         = 2418, // LoongArchLASXInstrInfo.td:698
    XVSSRARNI_HU_W                        = 2419, // LoongArchLASXInstrInfo.td:704
    XVSSRARNI_H_W                         = 2420, // LoongArchLASXInstrInfo.td:696
    XVSSRARNI_WU_D                        = 2421, // LoongArchLASXInstrInfo.td:705
    XVSSRARNI_W_D                         = 2422, // LoongArchLASXInstrInfo.td:697
    XVSSRARN_BU_H                         = 2423, // LoongArchLASXInstrInfo.td:687
    XVSSRARN_B_H                          = 2424, // LoongArchLASXInstrInfo.td:681
    XVSSRARN_HU_W                         = 2425, // LoongArchLASXInstrInfo.td:688
    XVSSRARN_H_W                          = 2426, // LoongArchLASXInstrInfo.td:682
    XVSSRARN_WU_D                         = 2427, // LoongArchLASXInstrInfo.td:689
    XVSSRARN_W_D                          = 2428, // LoongArchLASXInstrInfo.td:683
    XVSSRLNI_BU_H                         = 2429, // LoongArchLASXInstrInfo.td:669
    XVSSRLNI_B_H                          = 2430, // LoongArchLASXInstrInfo.td:661
    XVSSRLNI_DU_Q                         = 2431, // LoongArchLASXInstrInfo.td:672
    XVSSRLNI_D_Q                          = 2432, // LoongArchLASXInstrInfo.td:664
    XVSSRLNI_HU_W                         = 2433, // LoongArchLASXInstrInfo.td:670
    XVSSRLNI_H_W                          = 2434, // LoongArchLASXInstrInfo.td:662
    XVSSRLNI_WU_D                         = 2435, // LoongArchLASXInstrInfo.td:671
    XVSSRLNI_W_D                          = 2436, // LoongArchLASXInstrInfo.td:663
    XVSSRLN_BU_H                          = 2437, // LoongArchLASXInstrInfo.td:654
    XVSSRLN_B_H                           = 2438, // LoongArchLASXInstrInfo.td:648
    XVSSRLN_HU_W                          = 2439, // LoongArchLASXInstrInfo.td:655
    XVSSRLN_H_W                           = 2440, // LoongArchLASXInstrInfo.td:649
    XVSSRLN_WU_D                          = 2441, // LoongArchLASXInstrInfo.td:656
    XVSSRLN_W_D                           = 2442, // LoongArchLASXInstrInfo.td:650
    XVSSRLRNI_BU_H                        = 2443, // LoongArchLASXInstrInfo.td:699
    XVSSRLRNI_B_H                         = 2444, // LoongArchLASXInstrInfo.td:691
    XVSSRLRNI_DU_Q                        = 2445, // LoongArchLASXInstrInfo.td:702
    XVSSRLRNI_D_Q                         = 2446, // LoongArchLASXInstrInfo.td:694
    XVSSRLRNI_HU_W                        = 2447, // LoongArchLASXInstrInfo.td:700
    XVSSRLRNI_H_W                         = 2448, // LoongArchLASXInstrInfo.td:692
    XVSSRLRNI_WU_D                        = 2449, // LoongArchLASXInstrInfo.td:701
    XVSSRLRNI_W_D                         = 2450, // LoongArchLASXInstrInfo.td:693
    XVSSRLRN_BU_H                         = 2451, // LoongArchLASXInstrInfo.td:684
    XVSSRLRN_B_H                          = 2452, // LoongArchLASXInstrInfo.td:678
    XVSSRLRN_HU_W                         = 2453, // LoongArchLASXInstrInfo.td:685
    XVSSRLRN_H_W                          = 2454, // LoongArchLASXInstrInfo.td:679
    XVSSRLRN_WU_D                         = 2455, // LoongArchLASXInstrInfo.td:686
    XVSSRLRN_W_D                          = 2456, // LoongArchLASXInstrInfo.td:680
    XVSSUB_B                              = 2457, // LoongArchLASXInstrInfo.td:263
    XVSSUB_BU                             = 2458, // LoongArchLASXInstrInfo.td:267
    XVSSUB_D                              = 2459, // LoongArchLASXInstrInfo.td:266
    XVSSUB_DU                             = 2460, // LoongArchLASXInstrInfo.td:270
    XVSSUB_H                              = 2461, // LoongArchLASXInstrInfo.td:264
    XVSSUB_HU                             = 2462, // LoongArchLASXInstrInfo.td:268
    XVSSUB_W                              = 2463, // LoongArchLASXInstrInfo.td:265
    XVSSUB_WU                             = 2464, // LoongArchLASXInstrInfo.td:269
    XVST                                  = 2465, // LoongArchLASXInstrInfo.td:1062
    XVSTELM_B                             = 2466, // LoongArchLASXInstrInfo.td:1065
    XVSTELM_D                             = 2467, // LoongArchLASXInstrInfo.td:1068
    XVSTELM_H                             = 2468, // LoongArchLASXInstrInfo.td:1066
    XVSTELM_W                             = 2469, // LoongArchLASXInstrInfo.td:1067
    XVSTX                                 = 2470, // LoongArchLASXInstrInfo.td:1063
    XVSUBI_BU                             = 2471, // LoongArchLASXInstrInfo.td:244
    XVSUBI_DU                             = 2472, // LoongArchLASXInstrInfo.td:247
    XVSUBI_HU                             = 2473, // LoongArchLASXInstrInfo.td:245
    XVSUBI_WU                             = 2474, // LoongArchLASXInstrInfo.td:246
    XVSUBWEV_D_W                          = 2475, // LoongArchLASXInstrInfo.td:301
    XVSUBWEV_D_WU                         = 2476, // LoongArchLASXInstrInfo.td:319
    XVSUBWEV_H_B                          = 2477, // LoongArchLASXInstrInfo.td:299
    XVSUBWEV_H_BU                         = 2478, // LoongArchLASXInstrInfo.td:317
    XVSUBWEV_Q_D                          = 2479, // LoongArchLASXInstrInfo.td:302
    XVSUBWEV_Q_DU                         = 2480, // LoongArchLASXInstrInfo.td:320
    XVSUBWEV_W_H                          = 2481, // LoongArchLASXInstrInfo.td:300
    XVSUBWEV_W_HU                         = 2482, // LoongArchLASXInstrInfo.td:318
    XVSUBWOD_D_W                          = 2483, // LoongArchLASXInstrInfo.td:305
    XVSUBWOD_D_WU                         = 2484, // LoongArchLASXInstrInfo.td:323
    XVSUBWOD_H_B                          = 2485, // LoongArchLASXInstrInfo.td:303
    XVSUBWOD_H_BU                         = 2486, // LoongArchLASXInstrInfo.td:321
    XVSUBWOD_Q_D                          = 2487, // LoongArchLASXInstrInfo.td:306
    XVSUBWOD_Q_DU                         = 2488, // LoongArchLASXInstrInfo.td:324
    XVSUBWOD_W_H                          = 2489, // LoongArchLASXInstrInfo.td:304
    XVSUBWOD_W_HU                         = 2490, // LoongArchLASXInstrInfo.td:322
    XVSUB_B                               = 2491, // LoongArchLASXInstrInfo.td:233
    XVSUB_D                               = 2492, // LoongArchLASXInstrInfo.td:236
    XVSUB_H                               = 2493, // LoongArchLASXInstrInfo.td:234
    XVSUB_Q                               = 2494, // LoongArchLASXInstrInfo.td:237
    XVSUB_W                               = 2495, // LoongArchLASXInstrInfo.td:235
    XVXORI_B                              = 2496, // LoongArchLASXInstrInfo.td:550
    XVXOR_V                               = 2497, // LoongArchLASXInstrInfo.td:543
    INSTRUCTION_LIST_END = 2498
  };

} // namespace llvm_ks::LoongArch

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::LoongArch::Sched {

  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };

} // namespace llvm_ks::LoongArch::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct LoongArchInstrTable {
  MCInstrDesc Insts[2498];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[12];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[437];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof LoongArchInstrTable::ImplicitOps + sizeof LoongArchInstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned LoongArchOpInfoBase = (sizeof LoongArchInstrTable::ImplicitOps + sizeof LoongArchInstrTable::Padding) / sizeof(MCOperandInfo);

extern const LoongArchInstrTable LoongArchDescs = {
  {
    { 2497,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVXOR_V
    { 2496,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVXORI_B
    { 2495,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUB_W
    { 2494,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUB_Q
    { 2493,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUB_H
    { 2492,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUB_D
    { 2491,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUB_B
    { 2490,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWOD_W_HU
    { 2489,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWOD_W_H
    { 2488,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWOD_Q_DU
    { 2487,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWOD_Q_D
    { 2486,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWOD_H_BU
    { 2485,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWOD_H_B
    { 2484,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWOD_D_WU
    { 2483,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWOD_D_W
    { 2482,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWEV_W_HU
    { 2481,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWEV_W_H
    { 2480,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWEV_Q_DU
    { 2479,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWEV_Q_D
    { 2478,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWEV_H_BU
    { 2477,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWEV_H_B
    { 2476,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWEV_D_WU
    { 2475,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSUBWEV_D_W
    { 2474,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSUBI_WU
    { 2473,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSUBI_HU
    { 2472,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSUBI_DU
    { 2471,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSUBI_BU
    { 2470,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 420,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // XVSTX
    { 2469,	4,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 433,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // XVSTELM_W
    { 2468,	4,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 433,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // XVSTELM_H
    { 2467,	4,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 433,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // XVSTELM_D
    { 2466,	4,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 433,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // XVSTELM_B
    { 2465,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 417,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // XVST
    { 2464,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSUB_WU
    { 2463,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSUB_W
    { 2462,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSUB_HU
    { 2461,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSUB_H
    { 2460,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSUB_DU
    { 2459,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSUB_D
    { 2458,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSUB_BU
    { 2457,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSUB_B
    { 2456,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLRN_W_D
    { 2455,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLRN_WU_D
    { 2454,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLRN_H_W
    { 2453,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLRN_HU_W
    { 2452,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLRN_B_H
    { 2451,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLRN_BU_H
    { 2450,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLRNI_W_D
    { 2449,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLRNI_WU_D
    { 2448,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLRNI_H_W
    { 2447,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLRNI_HU_W
    { 2446,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLRNI_D_Q
    { 2445,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLRNI_DU_Q
    { 2444,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLRNI_B_H
    { 2443,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLRNI_BU_H
    { 2442,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLN_W_D
    { 2441,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLN_WU_D
    { 2440,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLN_H_W
    { 2439,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLN_HU_W
    { 2438,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLN_B_H
    { 2437,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRLN_BU_H
    { 2436,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLNI_W_D
    { 2435,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLNI_WU_D
    { 2434,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLNI_H_W
    { 2433,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLNI_HU_W
    { 2432,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLNI_D_Q
    { 2431,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLNI_DU_Q
    { 2430,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLNI_B_H
    { 2429,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRLNI_BU_H
    { 2428,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRARN_W_D
    { 2427,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRARN_WU_D
    { 2426,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRARN_H_W
    { 2425,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRARN_HU_W
    { 2424,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRARN_B_H
    { 2423,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRARN_BU_H
    { 2422,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRARNI_W_D
    { 2421,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRARNI_WU_D
    { 2420,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRARNI_H_W
    { 2419,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRARNI_HU_W
    { 2418,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRARNI_D_Q
    { 2417,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRARNI_DU_Q
    { 2416,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRARNI_B_H
    { 2415,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRARNI_BU_H
    { 2414,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRAN_W_D
    { 2413,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRAN_WU_D
    { 2412,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRAN_H_W
    { 2411,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRAN_HU_W
    { 2410,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRAN_B_H
    { 2409,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSSRAN_BU_H
    { 2408,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRANI_W_D
    { 2407,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRANI_WU_D
    { 2406,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRANI_H_W
    { 2405,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRANI_HU_W
    { 2404,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRANI_D_Q
    { 2403,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRANI_DU_Q
    { 2402,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRANI_B_H
    { 2401,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSSRANI_BU_H
    { 2400,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRL_W
    { 2399,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRL_H
    { 2398,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRL_D
    { 2397,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRL_B
    { 2396,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRLR_W
    { 2395,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRLR_H
    { 2394,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRLR_D
    { 2393,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRLR_B
    { 2392,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRLRN_W_D
    { 2391,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRLRN_H_W
    { 2390,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRLRN_B_H
    { 2389,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRLRNI_W_D
    { 2388,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRLRNI_H_W
    { 2387,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRLRNI_D_Q
    { 2386,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRLRNI_B_H
    { 2385,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRLRI_W
    { 2384,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRLRI_H
    { 2383,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRLRI_D
    { 2382,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRLRI_B
    { 2381,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRLN_W_D
    { 2380,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRLN_H_W
    { 2379,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRLN_B_H
    { 2378,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRLNI_W_D
    { 2377,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRLNI_H_W
    { 2376,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRLNI_D_Q
    { 2375,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRLNI_B_H
    { 2374,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRLI_W
    { 2373,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRLI_H
    { 2372,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRLI_D
    { 2371,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRLI_B
    { 2370,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRA_W
    { 2369,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRA_H
    { 2368,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRA_D
    { 2367,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRA_B
    { 2366,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRAR_W
    { 2365,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRAR_H
    { 2364,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRAR_D
    { 2363,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRAR_B
    { 2362,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRARN_W_D
    { 2361,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRARN_H_W
    { 2360,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRARN_B_H
    { 2359,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRARNI_W_D
    { 2358,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRARNI_H_W
    { 2357,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRARNI_D_Q
    { 2356,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRARNI_B_H
    { 2355,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRARI_W
    { 2354,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRARI_H
    { 2353,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRARI_D
    { 2352,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRARI_B
    { 2351,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRAN_W_D
    { 2350,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRAN_H_W
    { 2349,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSRAN_B_H
    { 2348,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRANI_W_D
    { 2347,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRANI_H_W
    { 2346,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRANI_D_Q
    { 2345,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSRANI_B_H
    { 2344,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRAI_W
    { 2343,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRAI_H
    { 2342,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRAI_D
    { 2341,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSRAI_B
    { 2340,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLT_WU
    { 2339,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLT_W
    { 2338,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLT_HU
    { 2337,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLT_H
    { 2336,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLT_DU
    { 2335,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLT_D
    { 2334,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLT_BU
    { 2333,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLT_B
    { 2332,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLTI_WU
    { 2331,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLTI_W
    { 2330,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLTI_HU
    { 2329,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLTI_H
    { 2328,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLTI_DU
    { 2327,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLTI_D
    { 2326,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLTI_BU
    { 2325,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLTI_B
    { 2324,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLL_W
    { 2323,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLL_H
    { 2322,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLL_D
    { 2321,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLL_B
    { 2320,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLLWIL_W_H
    { 2319,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLLWIL_WU_HU
    { 2318,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLLWIL_H_B
    { 2317,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLLWIL_HU_BU
    { 2316,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLLWIL_D_W
    { 2315,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLLWIL_DU_WU
    { 2314,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLLI_W
    { 2313,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLLI_H
    { 2312,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLLI_D
    { 2311,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLLI_B
    { 2310,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLE_WU
    { 2309,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLE_W
    { 2308,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLE_HU
    { 2307,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLE_H
    { 2306,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLE_DU
    { 2305,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLE_D
    { 2304,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLE_BU
    { 2303,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSLE_B
    { 2302,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLEI_WU
    { 2301,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLEI_W
    { 2300,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLEI_HU
    { 2299,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLEI_H
    { 2298,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLEI_DU
    { 2297,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLEI_D
    { 2296,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLEI_BU
    { 2295,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSLEI_B
    { 2294,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSIGNCOV_W
    { 2293,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSIGNCOV_H
    { 2292,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSIGNCOV_D
    { 2291,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSIGNCOV_B
    { 2290,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVSHUF_W
    { 2289,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVSHUF_H
    { 2288,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVSHUF_D
    { 2287,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 409,	0,	0, 0x0ULL },  // XVSHUF_B
    { 2286,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSHUF4I_W
    { 2285,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSHUF4I_H
    { 2284,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVSHUF4I_D
    { 2283,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSHUF4I_B
    { 2282,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 431,	0,	0, 0x0ULL },  // XVSETNEZ_V
    { 2281,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 431,	0,	0, 0x0ULL },  // XVSETEQZ_V
    { 2280,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 431,	0,	0, 0x0ULL },  // XVSETANYEQZ_W
    { 2279,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 431,	0,	0, 0x0ULL },  // XVSETANYEQZ_H
    { 2278,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 431,	0,	0, 0x0ULL },  // XVSETANYEQZ_D
    { 2277,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 431,	0,	0, 0x0ULL },  // XVSETANYEQZ_B
    { 2276,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 431,	0,	0, 0x0ULL },  // XVSETALLNEZ_W
    { 2275,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 431,	0,	0, 0x0ULL },  // XVSETALLNEZ_H
    { 2274,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 431,	0,	0, 0x0ULL },  // XVSETALLNEZ_D
    { 2273,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 431,	0,	0, 0x0ULL },  // XVSETALLNEZ_B
    { 2272,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSEQ_W
    { 2271,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSEQ_H
    { 2270,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSEQ_D
    { 2269,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSEQ_B
    { 2268,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSEQI_W
    { 2267,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSEQI_H
    { 2266,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSEQI_D
    { 2265,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSEQI_B
    { 2264,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSAT_WU
    { 2263,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSAT_W
    { 2262,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSAT_HU
    { 2261,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSAT_H
    { 2260,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSAT_DU
    { 2259,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSAT_D
    { 2258,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSAT_BU
    { 2257,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVSAT_B
    { 2256,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSADD_WU
    { 2255,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSADD_W
    { 2254,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSADD_HU
    { 2253,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSADD_H
    { 2252,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSADD_DU
    { 2251,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSADD_D
    { 2250,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSADD_BU
    { 2249,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVSADD_B
    { 2248,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVROTR_W
    { 2247,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVROTR_H
    { 2246,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVROTR_D
    { 2245,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVROTR_B
    { 2244,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVROTRI_W
    { 2243,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVROTRI_H
    { 2242,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVROTRI_D
    { 2241,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVROTRI_B
    { 2240,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 428,	0,	0, 0x0ULL },  // XVREPLVE_W
    { 2239,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 428,	0,	0, 0x0ULL },  // XVREPLVE_H
    { 2238,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 428,	0,	0, 0x0ULL },  // XVREPLVE_D
    { 2237,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 428,	0,	0, 0x0ULL },  // XVREPLVE_B
    { 2236,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVREPLVE0_W
    { 2235,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVREPLVE0_Q
    { 2234,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVREPLVE0_H
    { 2233,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVREPLVE0_D
    { 2232,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVREPLVE0_B
    { 2231,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 426,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // XVREPLGR2VR_W
    { 2230,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 426,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // XVREPLGR2VR_H
    { 2229,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 426,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // XVREPLGR2VR_D
    { 2228,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 426,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // XVREPLGR2VR_B
    { 2227,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVREPL128VEI_W
    { 2226,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVREPL128VEI_H
    { 2225,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVREPL128VEI_D
    { 2224,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVREPL128VEI_B
    { 2223,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVPICKVE_W
    { 2222,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVPICKVE_D
    { 2221,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 423,	0,	0, 0x0ULL },  // XVPICKVE2GR_WU
    { 2220,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 423,	0,	0, 0x0ULL },  // XVPICKVE2GR_W
    { 2219,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 423,	0,	0, 0x0ULL },  // XVPICKVE2GR_DU
    { 2218,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 423,	0,	0, 0x0ULL },  // XVPICKVE2GR_D
    { 2217,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPICKOD_W
    { 2216,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPICKOD_H
    { 2215,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPICKOD_D
    { 2214,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPICKOD_B
    { 2213,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPICKEV_W
    { 2212,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPICKEV_H
    { 2211,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPICKEV_D
    { 2210,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPICKEV_B
    { 2209,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPERM_W
    { 2208,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVPERMI_W
    { 2207,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVPERMI_Q
    { 2206,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVPERMI_D
    { 2205,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVPCNT_W
    { 2204,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVPCNT_H
    { 2203,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVPCNT_D
    { 2202,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVPCNT_B
    { 2201,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPACKOD_W
    { 2200,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPACKOD_H
    { 2199,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPACKOD_D
    { 2198,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPACKOD_B
    { 2197,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPACKEV_W
    { 2196,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPACKEV_H
    { 2195,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPACKEV_D
    { 2194,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVPACKEV_B
    { 2193,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVOR_V
    { 2192,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVORN_V
    { 2191,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVORI_B
    { 2190,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVNOR_V
    { 2189,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVNORI_B
    { 2188,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVNEG_W
    { 2187,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVNEG_H
    { 2186,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVNEG_D
    { 2185,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVNEG_B
    { 2184,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUL_W
    { 2183,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUL_H
    { 2182,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUL_D
    { 2181,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUL_B
    { 2180,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_W_HU_H
    { 2179,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_W_HU
    { 2178,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_W_H
    { 2177,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_Q_DU_D
    { 2176,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_Q_DU
    { 2175,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_Q_D
    { 2174,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_H_BU_B
    { 2173,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_H_BU
    { 2172,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_H_B
    { 2171,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_D_WU_W
    { 2170,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_D_WU
    { 2169,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWOD_D_W
    { 2168,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_W_HU_H
    { 2167,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_W_HU
    { 2166,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_W_H
    { 2165,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_Q_DU_D
    { 2164,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_Q_DU
    { 2163,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_Q_D
    { 2162,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_H_BU_B
    { 2161,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_H_BU
    { 2160,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_H_B
    { 2159,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_D_WU_W
    { 2158,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_D_WU
    { 2157,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMULWEV_D_W
    { 2156,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUH_WU
    { 2155,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUH_W
    { 2154,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUH_HU
    { 2153,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUH_H
    { 2152,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUH_DU
    { 2151,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUH_D
    { 2150,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUH_BU
    { 2149,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMUH_B
    { 2148,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMSUB_W
    { 2147,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMSUB_H
    { 2146,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMSUB_D
    { 2145,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMSUB_B
    { 2144,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVMSKNZ_B
    { 2143,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVMSKLTZ_W
    { 2142,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVMSKLTZ_H
    { 2141,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVMSKLTZ_D
    { 2140,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVMSKLTZ_B
    { 2139,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVMSKGEZ_B
    { 2138,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMOD_WU
    { 2137,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMOD_W
    { 2136,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMOD_HU
    { 2135,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMOD_H
    { 2134,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMOD_DU
    { 2133,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMOD_D
    { 2132,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMOD_BU
    { 2131,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMOD_B
    { 2130,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMIN_WU
    { 2129,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMIN_W
    { 2128,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMIN_HU
    { 2127,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMIN_H
    { 2126,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMIN_DU
    { 2125,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMIN_D
    { 2124,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMIN_BU
    { 2123,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMIN_B
    { 2122,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMINI_WU
    { 2121,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMINI_W
    { 2120,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMINI_HU
    { 2119,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMINI_H
    { 2118,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMINI_DU
    { 2117,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMINI_D
    { 2116,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMINI_BU
    { 2115,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMINI_B
    { 2114,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMAX_WU
    { 2113,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMAX_W
    { 2112,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMAX_HU
    { 2111,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMAX_H
    { 2110,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMAX_DU
    { 2109,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMAX_D
    { 2108,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMAX_BU
    { 2107,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVMAX_B
    { 2106,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMAXI_WU
    { 2105,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMAXI_W
    { 2104,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMAXI_HU
    { 2103,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMAXI_H
    { 2102,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMAXI_DU
    { 2101,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMAXI_D
    { 2100,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMAXI_BU
    { 2099,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVMAXI_B
    { 2098,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADD_W
    { 2097,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADD_H
    { 2096,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADD_D
    { 2095,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADD_B
    { 2094,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_W_HU_H
    { 2093,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_W_HU
    { 2092,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_W_H
    { 2091,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_Q_DU_D
    { 2090,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_Q_DU
    { 2089,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_Q_D
    { 2088,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_H_BU_B
    { 2087,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_H_BU
    { 2086,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_H_B
    { 2085,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_D_WU_W
    { 2084,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_D_WU
    { 2083,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWOD_D_W
    { 2082,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_W_HU_H
    { 2081,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_W_HU
    { 2080,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_W_H
    { 2079,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_Q_DU_D
    { 2078,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_Q_DU
    { 2077,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_Q_D
    { 2076,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_H_BU_B
    { 2075,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_H_BU
    { 2074,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_H_B
    { 2073,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_D_WU_W
    { 2072,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_D_WU
    { 2071,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVMADDWEV_D_W
    { 2070,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 420,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // XVLDX
    { 2069,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 417,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // XVLDREPL_W
    { 2068,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 417,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // XVLDREPL_H
    { 2067,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 417,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // XVLDREPL_D
    { 2066,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 417,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // XVLDREPL_B
    { 2065,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 225,	0,	0, 0x0ULL },  // XVLDI
    { 2064,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 417,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // XVLD
    { 2063,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVINSVE0_W
    { 2062,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVINSVE0_D
    { 2061,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 221,	0,	0, 0x0ULL },  // XVINSGR2VR_W
    { 2060,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 221,	0,	0, 0x0ULL },  // XVINSGR2VR_D
    { 2059,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVILVL_W
    { 2058,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVILVL_H
    { 2057,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVILVL_D
    { 2056,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVILVL_B
    { 2055,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVILVH_W
    { 2054,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVILVH_H
    { 2053,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVILVH_D
    { 2052,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVILVH_B
    { 2051,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHSUBW_W_H
    { 2050,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHSUBW_WU_HU
    { 2049,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHSUBW_Q_D
    { 2048,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHSUBW_QU_DU
    { 2047,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHSUBW_H_B
    { 2046,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHSUBW_HU_BU
    { 2045,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHSUBW_D_W
    { 2044,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHSUBW_DU_WU
    { 2043,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVHSELI_D
    { 2042,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHADDW_W_H
    { 2041,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHADDW_WU_HU
    { 2040,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHADDW_Q_D
    { 2039,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHADDW_QU_DU
    { 2038,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHADDW_H_B
    { 2037,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHADDW_HU_BU
    { 2036,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHADDW_D_W
    { 2035,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVHADDW_DU_WU
    { 2034,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINT_W_S
    { 2033,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFTINT_W_D
    { 2032,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINT_WU_S
    { 2031,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINT_L_D
    { 2030,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINT_LU_D
    { 2029,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRZ_W_S
    { 2028,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFTINTRZ_W_D
    { 2027,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRZ_WU_S
    { 2026,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRZ_L_D
    { 2025,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRZ_LU_D
    { 2024,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRZL_L_S
    { 2023,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRZH_L_S
    { 2022,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRP_W_S
    { 2021,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFTINTRP_W_D
    { 2020,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRP_L_D
    { 2019,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRPL_L_S
    { 2018,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRPH_L_S
    { 2017,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRNE_W_S
    { 2016,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFTINTRNE_W_D
    { 2015,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRNE_L_D
    { 2014,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRNEL_L_S
    { 2013,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRNEH_L_S
    { 2012,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRM_W_S
    { 2011,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFTINTRM_W_D
    { 2010,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRM_L_D
    { 2009,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRML_L_S
    { 2008,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTRMH_L_S
    { 2007,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTL_L_S
    { 2006,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFTINTH_L_S
    { 2005,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFSUB_S
    { 2004,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFSUB_D
    { 2003,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFSQRT_S
    { 2002,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFSQRT_D
    { 2001,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVFRSTP_H
    { 2000,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 413,	0,	0, 0x0ULL },  // XVFRSTP_B
    { 1999,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVFRSTPI_H
    { 1998,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVFRSTPI_B
    { 1997,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRSQRT_S
    { 1996,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRSQRT_D
    { 1995,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRSQRTE_S
    { 1994,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRSQRTE_D
    { 1993,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRINT_S
    { 1992,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRINT_D
    { 1991,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRINTRZ_S
    { 1990,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRINTRZ_D
    { 1989,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRINTRP_S
    { 1988,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRINTRP_D
    { 1987,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRINTRNE_S
    { 1986,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRINTRNE_D
    { 1985,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRINTRM_S
    { 1984,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRINTRM_D
    { 1983,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRECIP_S
    { 1982,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRECIP_D
    { 1981,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRECIPE_S
    { 1980,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFRECIPE_D
    { 1979,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 409,	0,	0, 0x0ULL },  // XVFNMSUB_S
    { 1978,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 409,	0,	0, 0x0ULL },  // XVFNMSUB_D
    { 1977,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 409,	0,	0, 0x0ULL },  // XVFNMADD_S
    { 1976,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 409,	0,	0, 0x0ULL },  // XVFNMADD_D
    { 1975,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFMUL_S
    { 1974,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFMUL_D
    { 1973,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 409,	0,	0, 0x0ULL },  // XVFMSUB_S
    { 1972,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 409,	0,	0, 0x0ULL },  // XVFMSUB_D
    { 1971,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFMIN_S
    { 1970,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFMIN_D
    { 1969,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFMINA_S
    { 1968,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFMINA_D
    { 1967,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFMAX_S
    { 1966,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFMAX_D
    { 1965,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFMAXA_S
    { 1964,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFMAXA_D
    { 1963,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 409,	0,	0, 0x0ULL },  // XVFMADD_S
    { 1962,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 409,	0,	0, 0x0ULL },  // XVFMADD_D
    { 1961,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFLOGB_S
    { 1960,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFLOGB_D
    { 1959,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFFINT_S_WU
    { 1958,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFFINT_S_W
    { 1957,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFFINT_S_L
    { 1956,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFFINT_D_LU
    { 1955,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFFINT_D_L
    { 1954,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFFINTL_D_W
    { 1953,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFFINTH_D_W
    { 1952,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFDIV_S
    { 1951,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFDIV_D
    { 1950,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCVT_S_D
    { 1949,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCVT_H_S
    { 1948,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFCVTL_S_H
    { 1947,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFCVTL_D_S
    { 1946,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFCVTH_S_H
    { 1945,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFCVTH_D_S
    { 1944,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SUN_S
    { 1943,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SUN_D
    { 1942,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SUNE_S
    { 1941,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SUNE_D
    { 1940,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SULT_S
    { 1939,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SULT_D
    { 1938,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SULE_S
    { 1937,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SULE_D
    { 1936,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SUEQ_S
    { 1935,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SUEQ_D
    { 1934,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SOR_S
    { 1933,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SOR_D
    { 1932,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SNE_S
    { 1931,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SNE_D
    { 1930,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SLT_S
    { 1929,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SLT_D
    { 1928,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SLE_S
    { 1927,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SLE_D
    { 1926,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SEQ_S
    { 1925,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SEQ_D
    { 1924,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SAF_S
    { 1923,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_SAF_D
    { 1922,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CUN_S
    { 1921,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CUN_D
    { 1920,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CUNE_S
    { 1919,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CUNE_D
    { 1918,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CULT_S
    { 1917,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CULT_D
    { 1916,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CULE_S
    { 1915,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CULE_D
    { 1914,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CUEQ_S
    { 1913,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CUEQ_D
    { 1912,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_COR_S
    { 1911,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_COR_D
    { 1910,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CNE_S
    { 1909,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CNE_D
    { 1908,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CLT_S
    { 1907,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CLT_D
    { 1906,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CLE_S
    { 1905,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CLE_D
    { 1904,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CEQ_S
    { 1903,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CEQ_D
    { 1902,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CAF_S
    { 1901,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFCMP_CAF_D
    { 1900,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFCLASS_S
    { 1899,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVFCLASS_D
    { 1898,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFADD_S
    { 1897,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVFADD_D
    { 1896,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVEXTRINS_W
    { 1895,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVEXTRINS_H
    { 1894,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVEXTRINS_D
    { 1893,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVEXTRINS_B
    { 1892,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVEXTL_Q_D
    { 1891,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVEXTL_QU_DU
    { 1890,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVEXTH_W_H
    { 1889,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVEXTH_WU_HU
    { 1888,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVEXTH_Q_D
    { 1887,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVEXTH_QU_DU
    { 1886,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVEXTH_H_B
    { 1885,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVEXTH_HU_BU
    { 1884,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVEXTH_D_W
    { 1883,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVEXTH_DU_WU
    { 1882,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVDIV_WU
    { 1881,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVDIV_W
    { 1880,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVDIV_HU
    { 1879,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVDIV_H
    { 1878,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVDIV_DU
    { 1877,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVDIV_D
    { 1876,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVDIV_BU
    { 1875,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVDIV_B
    { 1874,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVCLZ_W
    { 1873,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVCLZ_H
    { 1872,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVCLZ_D
    { 1871,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVCLZ_B
    { 1870,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVCLO_W
    { 1869,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVCLO_H
    { 1868,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVCLO_D
    { 1867,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // XVCLO_B
    { 1866,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBSRL_V
    { 1865,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBSLL_V
    { 1864,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITSET_W
    { 1863,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITSET_H
    { 1862,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITSET_D
    { 1861,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITSET_B
    { 1860,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITSETI_W
    { 1859,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITSETI_H
    { 1858,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITSETI_D
    { 1857,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITSETI_B
    { 1856,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 409,	0,	0, 0x0ULL },  // XVBITSEL_V
    { 1855,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 405,	0,	0, 0x0ULL },  // XVBITSELI_B
    { 1854,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITREV_W
    { 1853,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITREV_H
    { 1852,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITREV_D
    { 1851,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITREV_B
    { 1850,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITREVI_W
    { 1849,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITREVI_H
    { 1848,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITREVI_D
    { 1847,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITREVI_B
    { 1846,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITCLR_W
    { 1845,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITCLR_H
    { 1844,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITCLR_D
    { 1843,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVBITCLR_B
    { 1842,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITCLRI_W
    { 1841,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITCLRI_H
    { 1840,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITCLRI_D
    { 1839,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVBITCLRI_B
    { 1838,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVG_WU
    { 1837,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVG_W
    { 1836,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVG_HU
    { 1835,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVG_H
    { 1834,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVG_DU
    { 1833,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVG_D
    { 1832,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVG_BU
    { 1831,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVG_B
    { 1830,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVGR_WU
    { 1829,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVGR_W
    { 1828,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVGR_HU
    { 1827,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVGR_H
    { 1826,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVGR_DU
    { 1825,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVGR_D
    { 1824,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVGR_BU
    { 1823,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAVGR_B
    { 1822,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVAND_V
    { 1821,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVANDN_V
    { 1820,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVANDI_B
    { 1819,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADD_W
    { 1818,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADD_Q
    { 1817,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADD_H
    { 1816,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADD_D
    { 1815,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADD_B
    { 1814,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_W_HU_H
    { 1813,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_W_HU
    { 1812,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_W_H
    { 1811,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_Q_DU_D
    { 1810,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_Q_DU
    { 1809,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_Q_D
    { 1808,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_H_BU_B
    { 1807,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_H_BU
    { 1806,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_H_B
    { 1805,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_D_WU_W
    { 1804,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_D_WU
    { 1803,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWOD_D_W
    { 1802,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_W_HU_H
    { 1801,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_W_HU
    { 1800,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_W_H
    { 1799,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_Q_DU_D
    { 1798,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_Q_DU
    { 1797,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_Q_D
    { 1796,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_H_BU_B
    { 1795,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_H_BU
    { 1794,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_H_B
    { 1793,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_D_WU_W
    { 1792,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_D_WU
    { 1791,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDWEV_D_W
    { 1790,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVADDI_WU
    { 1789,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVADDI_HU
    { 1788,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVADDI_DU
    { 1787,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 402,	0,	0, 0x0ULL },  // XVADDI_BU
    { 1786,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDA_W
    { 1785,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDA_H
    { 1784,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDA_D
    { 1783,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVADDA_B
    { 1782,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVABSD_WU
    { 1781,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVABSD_W
    { 1780,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVABSD_HU
    { 1779,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVABSD_H
    { 1778,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVABSD_DU
    { 1777,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVABSD_D
    { 1776,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVABSD_BU
    { 1775,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 399,	0,	0, 0x0ULL },  // XVABSD_B
    { 1774,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // XORI
    { 1773,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // XOR
    { 1772,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86XOR_W
    { 1771,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86XOR_H
    { 1770,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86XOR_D
    { 1769,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86XOR_B
    { 1768,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SUB_WU
    { 1767,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SUB_W
    { 1766,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SUB_H
    { 1765,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SUB_DU
    { 1764,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SUB_D
    { 1763,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SUB_B
    { 1762,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SRL_W
    { 1761,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SRL_H
    { 1760,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SRL_D
    { 1759,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SRL_B
    { 1758,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SRLI_W
    { 1757,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SRLI_H
    { 1756,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SRLI_D
    { 1755,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SRLI_B
    { 1754,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SRA_W
    { 1753,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SRA_H
    { 1752,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SRA_D
    { 1751,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SRA_B
    { 1750,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SRAI_W
    { 1749,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SRAI_H
    { 1748,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SRAI_D
    { 1747,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SRAI_B
    { 1746,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SLL_W
    { 1745,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SLL_H
    { 1744,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SLL_D
    { 1743,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SLL_B
    { 1742,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SLLI_W
    { 1741,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SLLI_H
    { 1740,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SLLI_D
    { 1739,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86SLLI_B
    { 1738,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0, 0x0ULL },  // X86SETTM
    { 1737,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 245,	0,	0, 0x0ULL },  // X86SETTAG
    { 1736,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SBC_W
    { 1735,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SBC_H
    { 1734,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SBC_D
    { 1733,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86SBC_B
    { 1732,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ROTR_W
    { 1731,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ROTR_H
    { 1730,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ROTR_D
    { 1729,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ROTR_B
    { 1728,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86ROTRI_W
    { 1727,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86ROTRI_H
    { 1726,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86ROTRI_D
    { 1725,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86ROTRI_B
    { 1724,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ROTL_W
    { 1723,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ROTL_H
    { 1722,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ROTL_D
    { 1721,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ROTL_B
    { 1720,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86ROTLI_W
    { 1719,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86ROTLI_H
    { 1718,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86ROTLI_D
    { 1717,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86ROTLI_B
    { 1716,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86RCR_W
    { 1715,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86RCR_H
    { 1714,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86RCR_D
    { 1713,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86RCR_B
    { 1712,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86RCRI_W
    { 1711,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86RCRI_H
    { 1710,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86RCRI_D
    { 1709,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86RCRI_B
    { 1708,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86RCL_W
    { 1707,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86RCL_H
    { 1706,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86RCL_D
    { 1705,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86RCL_B
    { 1704,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86RCLI_W
    { 1703,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86RCLI_H
    { 1702,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86RCLI_D
    { 1701,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86RCLI_B
    { 1700,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86OR_W
    { 1699,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86OR_H
    { 1698,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86OR_D
    { 1697,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86OR_B
    { 1696,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86MUL_WU
    { 1695,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86MUL_W
    { 1694,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86MUL_HU
    { 1693,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86MUL_H
    { 1692,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86MUL_DU
    { 1691,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86MUL_D
    { 1690,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86MUL_BU
    { 1689,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86MUL_B
    { 1688,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0, 0x0ULL },  // X86MTTOP
    { 1687,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86MTFLAG
    { 1686,	1,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 28,	0,	0, 0x0ULL },  // X86MFTOP
    { 1685,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // X86MFFLAG
    { 1684,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 28,	0,	0, 0x0ULL },  // X86INC_W
    { 1683,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 28,	0,	0, 0x0ULL },  // X86INC_H
    { 1682,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 28,	0,	0, 0x0ULL },  // X86INC_D
    { 1681,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 28,	0,	0, 0x0ULL },  // X86INC_B
    { 1680,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0, 0x0ULL },  // X86INCTOP
    { 1679,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 28,	0,	0, 0x0ULL },  // X86DEC_W
    { 1678,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 28,	0,	0, 0x0ULL },  // X86DEC_H
    { 1677,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 28,	0,	0, 0x0ULL },  // X86DEC_D
    { 1676,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 28,	0,	0, 0x0ULL },  // X86DEC_B
    { 1675,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0, 0x0ULL },  // X86DECTOP
    { 1674,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0, 0x0ULL },  // X86CLRTM
    { 1673,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86AND_W
    { 1672,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86AND_H
    { 1671,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86AND_D
    { 1670,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86AND_B
    { 1669,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ADD_WU
    { 1668,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ADD_W
    { 1667,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ADD_H
    { 1666,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ADD_DU
    { 1665,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ADD_D
    { 1664,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ADD_B
    { 1663,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ADC_W
    { 1662,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ADC_H
    { 1661,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ADC_D
    { 1660,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // X86ADC_B
    { 1659,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VXOR_V
    { 1658,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VXORI_B
    { 1657,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUB_W
    { 1656,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUB_Q
    { 1655,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUB_H
    { 1654,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUB_D
    { 1653,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUB_B
    { 1652,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWOD_W_HU
    { 1651,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWOD_W_H
    { 1650,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWOD_Q_DU
    { 1649,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWOD_Q_D
    { 1648,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWOD_H_BU
    { 1647,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWOD_H_B
    { 1646,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWOD_D_WU
    { 1645,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWOD_D_W
    { 1644,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWEV_W_HU
    { 1643,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWEV_W_H
    { 1642,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWEV_Q_DU
    { 1641,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWEV_Q_D
    { 1640,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWEV_H_BU
    { 1639,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWEV_H_B
    { 1638,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWEV_D_WU
    { 1637,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSUBWEV_D_W
    { 1636,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSUBI_WU
    { 1635,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSUBI_HU
    { 1634,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSUBI_DU
    { 1633,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSUBI_BU
    { 1632,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 382,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTX
    { 1631,	4,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 395,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTELM_W
    { 1630,	4,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 395,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTELM_H
    { 1629,	4,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 395,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTELM_D
    { 1628,	4,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 395,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VSTELM_B
    { 1627,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 379,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // VST
    { 1626,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSUB_WU
    { 1625,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSUB_W
    { 1624,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSUB_HU
    { 1623,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSUB_H
    { 1622,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSUB_DU
    { 1621,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSUB_D
    { 1620,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSUB_BU
    { 1619,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSUB_B
    { 1618,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLRN_W_D
    { 1617,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLRN_WU_D
    { 1616,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLRN_H_W
    { 1615,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLRN_HU_W
    { 1614,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLRN_B_H
    { 1613,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLRN_BU_H
    { 1612,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLRNI_W_D
    { 1611,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLRNI_WU_D
    { 1610,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLRNI_H_W
    { 1609,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLRNI_HU_W
    { 1608,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLRNI_D_Q
    { 1607,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLRNI_DU_Q
    { 1606,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLRNI_B_H
    { 1605,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLRNI_BU_H
    { 1604,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLN_W_D
    { 1603,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLN_WU_D
    { 1602,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLN_H_W
    { 1601,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLN_HU_W
    { 1600,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLN_B_H
    { 1599,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRLN_BU_H
    { 1598,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLNI_W_D
    { 1597,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLNI_WU_D
    { 1596,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLNI_H_W
    { 1595,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLNI_HU_W
    { 1594,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLNI_D_Q
    { 1593,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLNI_DU_Q
    { 1592,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLNI_B_H
    { 1591,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRLNI_BU_H
    { 1590,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRARN_W_D
    { 1589,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRARN_WU_D
    { 1588,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRARN_H_W
    { 1587,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRARN_HU_W
    { 1586,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRARN_B_H
    { 1585,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRARN_BU_H
    { 1584,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRARNI_W_D
    { 1583,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRARNI_WU_D
    { 1582,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRARNI_H_W
    { 1581,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRARNI_HU_W
    { 1580,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRARNI_D_Q
    { 1579,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRARNI_DU_Q
    { 1578,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRARNI_B_H
    { 1577,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRARNI_BU_H
    { 1576,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRAN_W_D
    { 1575,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRAN_WU_D
    { 1574,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRAN_H_W
    { 1573,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRAN_HU_W
    { 1572,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRAN_B_H
    { 1571,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSSRAN_BU_H
    { 1570,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRANI_W_D
    { 1569,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRANI_WU_D
    { 1568,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRANI_H_W
    { 1567,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRANI_HU_W
    { 1566,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRANI_D_Q
    { 1565,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRANI_DU_Q
    { 1564,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRANI_B_H
    { 1563,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSSRANI_BU_H
    { 1562,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRL_W
    { 1561,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRL_H
    { 1560,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRL_D
    { 1559,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRL_B
    { 1558,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRLR_W
    { 1557,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRLR_H
    { 1556,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRLR_D
    { 1555,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRLR_B
    { 1554,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRLRN_W_D
    { 1553,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRLRN_H_W
    { 1552,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRLRN_B_H
    { 1551,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRLRNI_W_D
    { 1550,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRLRNI_H_W
    { 1549,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRLRNI_D_Q
    { 1548,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRLRNI_B_H
    { 1547,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRLRI_W
    { 1546,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRLRI_H
    { 1545,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRLRI_D
    { 1544,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRLRI_B
    { 1543,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRLN_W_D
    { 1542,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRLN_H_W
    { 1541,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRLN_B_H
    { 1540,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRLNI_W_D
    { 1539,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRLNI_H_W
    { 1538,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRLNI_D_Q
    { 1537,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRLNI_B_H
    { 1536,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRLI_W
    { 1535,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRLI_H
    { 1534,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRLI_D
    { 1533,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRLI_B
    { 1532,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRA_W
    { 1531,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRA_H
    { 1530,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRA_D
    { 1529,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRA_B
    { 1528,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRAR_W
    { 1527,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRAR_H
    { 1526,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRAR_D
    { 1525,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRAR_B
    { 1524,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRARN_W_D
    { 1523,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRARN_H_W
    { 1522,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRARN_B_H
    { 1521,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRARNI_W_D
    { 1520,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRARNI_H_W
    { 1519,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRARNI_D_Q
    { 1518,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRARNI_B_H
    { 1517,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRARI_W
    { 1516,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRARI_H
    { 1515,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRARI_D
    { 1514,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRARI_B
    { 1513,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRAN_W_D
    { 1512,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRAN_H_W
    { 1511,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSRAN_B_H
    { 1510,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRANI_W_D
    { 1509,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRANI_H_W
    { 1508,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRANI_D_Q
    { 1507,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSRANI_B_H
    { 1506,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRAI_W
    { 1505,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRAI_H
    { 1504,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRAI_D
    { 1503,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSRAI_B
    { 1502,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLT_WU
    { 1501,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLT_W
    { 1500,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLT_HU
    { 1499,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLT_H
    { 1498,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLT_DU
    { 1497,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLT_D
    { 1496,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLT_BU
    { 1495,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLT_B
    { 1494,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLTI_WU
    { 1493,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLTI_W
    { 1492,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLTI_HU
    { 1491,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLTI_H
    { 1490,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLTI_DU
    { 1489,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLTI_D
    { 1488,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLTI_BU
    { 1487,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLTI_B
    { 1486,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLL_W
    { 1485,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLL_H
    { 1484,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLL_D
    { 1483,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLL_B
    { 1482,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLLWIL_W_H
    { 1481,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLLWIL_WU_HU
    { 1480,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLLWIL_H_B
    { 1479,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLLWIL_HU_BU
    { 1478,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLLWIL_D_W
    { 1477,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLLWIL_DU_WU
    { 1476,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLLI_W
    { 1475,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLLI_H
    { 1474,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLLI_D
    { 1473,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLLI_B
    { 1472,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLE_WU
    { 1471,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLE_W
    { 1470,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLE_HU
    { 1469,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLE_H
    { 1468,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLE_DU
    { 1467,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLE_D
    { 1466,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLE_BU
    { 1465,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSLE_B
    { 1464,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLEI_WU
    { 1463,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLEI_W
    { 1462,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLEI_HU
    { 1461,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLEI_H
    { 1460,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLEI_DU
    { 1459,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLEI_D
    { 1458,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLEI_BU
    { 1457,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSLEI_B
    { 1456,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSIGNCOV_W
    { 1455,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSIGNCOV_H
    { 1454,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSIGNCOV_D
    { 1453,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSIGNCOV_B
    { 1452,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VSHUF_W
    { 1451,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VSHUF_H
    { 1450,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VSHUF_D
    { 1449,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 363,	0,	0, 0x0ULL },  // VSHUF_B
    { 1448,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSHUF4I_W
    { 1447,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSHUF4I_H
    { 1446,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VSHUF4I_D
    { 1445,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSHUF4I_B
    { 1444,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 393,	0,	0, 0x0ULL },  // VSETNEZ_V
    { 1443,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 393,	0,	0, 0x0ULL },  // VSETEQZ_V
    { 1442,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 393,	0,	0, 0x0ULL },  // VSETANYEQZ_W
    { 1441,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 393,	0,	0, 0x0ULL },  // VSETANYEQZ_H
    { 1440,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 393,	0,	0, 0x0ULL },  // VSETANYEQZ_D
    { 1439,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 393,	0,	0, 0x0ULL },  // VSETANYEQZ_B
    { 1438,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 393,	0,	0, 0x0ULL },  // VSETALLNEZ_W
    { 1437,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 393,	0,	0, 0x0ULL },  // VSETALLNEZ_H
    { 1436,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 393,	0,	0, 0x0ULL },  // VSETALLNEZ_D
    { 1435,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 393,	0,	0, 0x0ULL },  // VSETALLNEZ_B
    { 1434,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSEQ_W
    { 1433,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSEQ_H
    { 1432,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSEQ_D
    { 1431,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSEQ_B
    { 1430,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSEQI_W
    { 1429,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSEQI_H
    { 1428,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSEQI_D
    { 1427,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSEQI_B
    { 1426,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSAT_WU
    { 1425,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSAT_W
    { 1424,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSAT_HU
    { 1423,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSAT_H
    { 1422,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSAT_DU
    { 1421,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSAT_D
    { 1420,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSAT_BU
    { 1419,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VSAT_B
    { 1418,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSADD_WU
    { 1417,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSADD_W
    { 1416,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSADD_HU
    { 1415,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSADD_H
    { 1414,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSADD_DU
    { 1413,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSADD_D
    { 1412,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSADD_BU
    { 1411,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VSADD_B
    { 1410,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VROTR_W
    { 1409,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VROTR_H
    { 1408,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VROTR_D
    { 1407,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VROTR_B
    { 1406,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VROTRI_W
    { 1405,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VROTRI_H
    { 1404,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VROTRI_D
    { 1403,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VROTRI_B
    { 1402,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 390,	0,	0, 0x0ULL },  // VREPLVE_W
    { 1401,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 390,	0,	0, 0x0ULL },  // VREPLVE_H
    { 1400,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 390,	0,	0, 0x0ULL },  // VREPLVE_D
    { 1399,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 390,	0,	0, 0x0ULL },  // VREPLVE_B
    { 1398,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VREPLVEI_W
    { 1397,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VREPLVEI_H
    { 1396,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VREPLVEI_D
    { 1395,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VREPLVEI_B
    { 1394,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 388,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // VREPLGR2VR_W
    { 1393,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 388,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // VREPLGR2VR_H
    { 1392,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 388,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // VREPLGR2VR_D
    { 1391,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 388,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // VREPLGR2VR_B
    { 1390,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 385,	0,	0, 0x0ULL },  // VPICKVE2GR_WU
    { 1389,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 385,	0,	0, 0x0ULL },  // VPICKVE2GR_W
    { 1388,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 385,	0,	0, 0x0ULL },  // VPICKVE2GR_HU
    { 1387,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 385,	0,	0, 0x0ULL },  // VPICKVE2GR_H
    { 1386,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 385,	0,	0, 0x0ULL },  // VPICKVE2GR_DU
    { 1385,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 385,	0,	0, 0x0ULL },  // VPICKVE2GR_D
    { 1384,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 385,	0,	0, 0x0ULL },  // VPICKVE2GR_BU
    { 1383,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 385,	0,	0, 0x0ULL },  // VPICKVE2GR_B
    { 1382,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPICKOD_W
    { 1381,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPICKOD_H
    { 1380,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPICKOD_D
    { 1379,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPICKOD_B
    { 1378,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPICKEV_W
    { 1377,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPICKEV_H
    { 1376,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPICKEV_D
    { 1375,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPICKEV_B
    { 1374,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VPERMI_W
    { 1373,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VPCNT_W
    { 1372,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VPCNT_H
    { 1371,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VPCNT_D
    { 1370,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VPCNT_B
    { 1369,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPACKOD_W
    { 1368,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPACKOD_H
    { 1367,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPACKOD_D
    { 1366,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPACKOD_B
    { 1365,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPACKEV_W
    { 1364,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPACKEV_H
    { 1363,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPACKEV_D
    { 1362,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VPACKEV_B
    { 1361,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VOR_V
    { 1360,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VORN_V
    { 1359,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VORI_B
    { 1358,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VNOR_V
    { 1357,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VNORI_B
    { 1356,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VNEG_W
    { 1355,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VNEG_H
    { 1354,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VNEG_D
    { 1353,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VNEG_B
    { 1352,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUL_W
    { 1351,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUL_H
    { 1350,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUL_D
    { 1349,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUL_B
    { 1348,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_W_HU_H
    { 1347,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_W_HU
    { 1346,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_W_H
    { 1345,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_Q_DU_D
    { 1344,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_Q_DU
    { 1343,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_Q_D
    { 1342,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_H_BU_B
    { 1341,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_H_BU
    { 1340,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_H_B
    { 1339,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_D_WU_W
    { 1338,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_D_WU
    { 1337,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWOD_D_W
    { 1336,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_W_HU_H
    { 1335,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_W_HU
    { 1334,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_W_H
    { 1333,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_Q_DU_D
    { 1332,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_Q_DU
    { 1331,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_Q_D
    { 1330,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_H_BU_B
    { 1329,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_H_BU
    { 1328,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_H_B
    { 1327,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_D_WU_W
    { 1326,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_D_WU
    { 1325,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMULWEV_D_W
    { 1324,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUH_WU
    { 1323,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUH_W
    { 1322,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUH_HU
    { 1321,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUH_H
    { 1320,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUH_DU
    { 1319,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUH_D
    { 1318,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUH_BU
    { 1317,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMUH_B
    { 1316,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMSUB_W
    { 1315,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMSUB_H
    { 1314,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMSUB_D
    { 1313,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMSUB_B
    { 1312,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VMSKNZ_B
    { 1311,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VMSKLTZ_W
    { 1310,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VMSKLTZ_H
    { 1309,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VMSKLTZ_D
    { 1308,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VMSKLTZ_B
    { 1307,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VMSKGEZ_B
    { 1306,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMOD_WU
    { 1305,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMOD_W
    { 1304,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMOD_HU
    { 1303,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMOD_H
    { 1302,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMOD_DU
    { 1301,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMOD_D
    { 1300,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMOD_BU
    { 1299,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMOD_B
    { 1298,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMIN_WU
    { 1297,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMIN_W
    { 1296,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMIN_HU
    { 1295,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMIN_H
    { 1294,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMIN_DU
    { 1293,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMIN_D
    { 1292,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMIN_BU
    { 1291,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMIN_B
    { 1290,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMINI_WU
    { 1289,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMINI_W
    { 1288,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMINI_HU
    { 1287,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMINI_H
    { 1286,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMINI_DU
    { 1285,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMINI_D
    { 1284,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMINI_BU
    { 1283,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMINI_B
    { 1282,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMAX_WU
    { 1281,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMAX_W
    { 1280,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMAX_HU
    { 1279,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMAX_H
    { 1278,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMAX_DU
    { 1277,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMAX_D
    { 1276,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMAX_BU
    { 1275,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VMAX_B
    { 1274,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMAXI_WU
    { 1273,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMAXI_W
    { 1272,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMAXI_HU
    { 1271,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMAXI_H
    { 1270,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMAXI_DU
    { 1269,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMAXI_D
    { 1268,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMAXI_BU
    { 1267,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VMAXI_B
    { 1266,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADD_W
    { 1265,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADD_H
    { 1264,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADD_D
    { 1263,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADD_B
    { 1262,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_W_HU_H
    { 1261,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_W_HU
    { 1260,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_W_H
    { 1259,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_Q_DU_D
    { 1258,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_Q_DU
    { 1257,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_Q_D
    { 1256,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_H_BU_B
    { 1255,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_H_BU
    { 1254,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_H_B
    { 1253,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_D_WU_W
    { 1252,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_D_WU
    { 1251,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWOD_D_W
    { 1250,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_W_HU_H
    { 1249,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_W_HU
    { 1248,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_W_H
    { 1247,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_Q_DU_D
    { 1246,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_Q_DU
    { 1245,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_Q_D
    { 1244,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_H_BU_B
    { 1243,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_H_BU
    { 1242,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_H_B
    { 1241,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_D_WU_W
    { 1240,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_D_WU
    { 1239,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VMADDWEV_D_W
    { 1238,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 382,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLDX
    { 1237,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 379,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLDREPL_W
    { 1236,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 379,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLDREPL_H
    { 1235,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 379,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLDREPL_D
    { 1234,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 379,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLDREPL_B
    { 1233,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 217,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // VLDI
    { 1232,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 379,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // VLD
    { 1231,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 375,	0,	0, 0x0ULL },  // VINSGR2VR_W
    { 1230,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 375,	0,	0, 0x0ULL },  // VINSGR2VR_H
    { 1229,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 375,	0,	0, 0x0ULL },  // VINSGR2VR_D
    { 1228,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 375,	0,	0, 0x0ULL },  // VINSGR2VR_B
    { 1227,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VILVL_W
    { 1226,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VILVL_H
    { 1225,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VILVL_D
    { 1224,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VILVL_B
    { 1223,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VILVH_W
    { 1222,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VILVH_H
    { 1221,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VILVH_D
    { 1220,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VILVH_B
    { 1219,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHSUBW_W_H
    { 1218,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHSUBW_WU_HU
    { 1217,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHSUBW_Q_D
    { 1216,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHSUBW_QU_DU
    { 1215,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHSUBW_H_B
    { 1214,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHSUBW_HU_BU
    { 1213,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHSUBW_D_W
    { 1212,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHSUBW_DU_WU
    { 1211,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHADDW_W_H
    { 1210,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHADDW_WU_HU
    { 1209,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHADDW_Q_D
    { 1208,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHADDW_QU_DU
    { 1207,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHADDW_H_B
    { 1206,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHADDW_HU_BU
    { 1205,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHADDW_D_W
    { 1204,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VHADDW_DU_WU
    { 1203,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINT_W_S
    { 1202,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFTINT_W_D
    { 1201,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINT_WU_S
    { 1200,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINT_L_D
    { 1199,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINT_LU_D
    { 1198,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRZ_W_S
    { 1197,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFTINTRZ_W_D
    { 1196,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRZ_WU_S
    { 1195,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRZ_L_D
    { 1194,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRZ_LU_D
    { 1193,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRZL_L_S
    { 1192,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRZH_L_S
    { 1191,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRP_W_S
    { 1190,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFTINTRP_W_D
    { 1189,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRP_L_D
    { 1188,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRPL_L_S
    { 1187,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRPH_L_S
    { 1186,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRNE_W_S
    { 1185,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFTINTRNE_W_D
    { 1184,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRNE_L_D
    { 1183,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRNEL_L_S
    { 1182,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRNEH_L_S
    { 1181,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRM_W_S
    { 1180,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFTINTRM_W_D
    { 1179,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRM_L_D
    { 1178,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRML_L_S
    { 1177,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTRMH_L_S
    { 1176,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTL_L_S
    { 1175,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFTINTH_L_S
    { 1174,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFSUB_S
    { 1173,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFSUB_D
    { 1172,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFSQRT_S
    { 1171,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFSQRT_D
    { 1170,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VFRSTP_H
    { 1169,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 371,	0,	0, 0x0ULL },  // VFRSTP_B
    { 1168,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VFRSTPI_H
    { 1167,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VFRSTPI_B
    { 1166,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRSQRT_S
    { 1165,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRSQRT_D
    { 1164,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRSQRTE_S
    { 1163,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRSQRTE_D
    { 1162,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRINT_S
    { 1161,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRINT_D
    { 1160,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRINTRZ_S
    { 1159,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRINTRZ_D
    { 1158,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRINTRP_S
    { 1157,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRINTRP_D
    { 1156,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRINTRNE_S
    { 1155,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRINTRNE_D
    { 1154,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRINTRM_S
    { 1153,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRINTRM_D
    { 1152,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRECIP_S
    { 1151,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRECIP_D
    { 1150,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRECIPE_S
    { 1149,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFRECIPE_D
    { 1148,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 363,	0,	0, 0x0ULL },  // VFNMSUB_S
    { 1147,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 363,	0,	0, 0x0ULL },  // VFNMSUB_D
    { 1146,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 363,	0,	0, 0x0ULL },  // VFNMADD_S
    { 1145,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 363,	0,	0, 0x0ULL },  // VFNMADD_D
    { 1144,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFMUL_S
    { 1143,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFMUL_D
    { 1142,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 363,	0,	0, 0x0ULL },  // VFMSUB_S
    { 1141,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 363,	0,	0, 0x0ULL },  // VFMSUB_D
    { 1140,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFMIN_S
    { 1139,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFMIN_D
    { 1138,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFMINA_S
    { 1137,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFMINA_D
    { 1136,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFMAX_S
    { 1135,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFMAX_D
    { 1134,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFMAXA_S
    { 1133,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFMAXA_D
    { 1132,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 363,	0,	0, 0x0ULL },  // VFMADD_S
    { 1131,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 363,	0,	0, 0x0ULL },  // VFMADD_D
    { 1130,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFLOGB_S
    { 1129,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFLOGB_D
    { 1128,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFFINT_S_WU
    { 1127,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFFINT_S_W
    { 1126,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFFINT_S_L
    { 1125,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFFINT_D_LU
    { 1124,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFFINT_D_L
    { 1123,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFFINTL_D_W
    { 1122,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFFINTH_D_W
    { 1121,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFDIV_S
    { 1120,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFDIV_D
    { 1119,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCVT_S_D
    { 1118,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCVT_H_S
    { 1117,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFCVTL_S_H
    { 1116,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFCVTL_D_S
    { 1115,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFCVTH_S_H
    { 1114,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFCVTH_D_S
    { 1113,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SUN_S
    { 1112,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SUN_D
    { 1111,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SUNE_S
    { 1110,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SUNE_D
    { 1109,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SULT_S
    { 1108,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SULT_D
    { 1107,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SULE_S
    { 1106,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SULE_D
    { 1105,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SUEQ_S
    { 1104,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SUEQ_D
    { 1103,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SOR_S
    { 1102,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SOR_D
    { 1101,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SNE_S
    { 1100,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SNE_D
    { 1099,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SLT_S
    { 1098,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SLT_D
    { 1097,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SLE_S
    { 1096,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SLE_D
    { 1095,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SEQ_S
    { 1094,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SEQ_D
    { 1093,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SAF_S
    { 1092,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_SAF_D
    { 1091,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CUN_S
    { 1090,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CUN_D
    { 1089,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CUNE_S
    { 1088,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CUNE_D
    { 1087,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CULT_S
    { 1086,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CULT_D
    { 1085,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CULE_S
    { 1084,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CULE_D
    { 1083,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CUEQ_S
    { 1082,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CUEQ_D
    { 1081,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_COR_S
    { 1080,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_COR_D
    { 1079,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CNE_S
    { 1078,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CNE_D
    { 1077,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CLT_S
    { 1076,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CLT_D
    { 1075,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CLE_S
    { 1074,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CLE_D
    { 1073,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CEQ_S
    { 1072,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CEQ_D
    { 1071,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CAF_S
    { 1070,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFCMP_CAF_D
    { 1069,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFCLASS_S
    { 1068,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VFCLASS_D
    { 1067,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFADD_S
    { 1066,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VFADD_D
    { 1065,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VEXTRINS_W
    { 1064,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VEXTRINS_H
    { 1063,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VEXTRINS_D
    { 1062,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VEXTRINS_B
    { 1061,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VEXTL_Q_D
    { 1060,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VEXTL_QU_DU
    { 1059,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VEXTH_W_H
    { 1058,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VEXTH_WU_HU
    { 1057,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VEXTH_Q_D
    { 1056,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VEXTH_QU_DU
    { 1055,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VEXTH_H_B
    { 1054,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VEXTH_HU_BU
    { 1053,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VEXTH_D_W
    { 1052,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VEXTH_DU_WU
    { 1051,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_W_H
    { 1050,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_W_B
    { 1049,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_WU_HU
    { 1048,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_WU_BU
    { 1047,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_H_B
    { 1046,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_HU_BU
    { 1045,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_D_W
    { 1044,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_D_H
    { 1043,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_D_B
    { 1042,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_DU_WU
    { 1041,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_DU_HU
    { 1040,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 369,	0,	0, 0x0ULL },  // VEXT2XV_DU_BU
    { 1039,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VDIV_WU
    { 1038,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VDIV_W
    { 1037,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VDIV_HU
    { 1036,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VDIV_H
    { 1035,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VDIV_DU
    { 1034,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VDIV_D
    { 1033,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VDIV_BU
    { 1032,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VDIV_B
    { 1031,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VCLZ_W
    { 1030,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VCLZ_H
    { 1029,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VCLZ_D
    { 1028,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VCLZ_B
    { 1027,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VCLO_W
    { 1026,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VCLO_H
    { 1025,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VCLO_D
    { 1024,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 367,	0,	0, 0x0ULL },  // VCLO_B
    { 1023,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBSRL_V
    { 1022,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBSLL_V
    { 1021,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITSET_W
    { 1020,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITSET_H
    { 1019,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITSET_D
    { 1018,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITSET_B
    { 1017,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITSETI_W
    { 1016,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITSETI_H
    { 1015,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITSETI_D
    { 1014,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITSETI_B
    { 1013,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 363,	0,	0, 0x0ULL },  // VBITSEL_V
    { 1012,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 359,	0,	0, 0x0ULL },  // VBITSELI_B
    { 1011,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITREV_W
    { 1010,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITREV_H
    { 1009,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITREV_D
    { 1008,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITREV_B
    { 1007,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITREVI_W
    { 1006,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITREVI_H
    { 1005,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITREVI_D
    { 1004,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITREVI_B
    { 1003,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITCLR_W
    { 1002,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITCLR_H
    { 1001,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITCLR_D
    { 1000,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VBITCLR_B
    { 999,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITCLRI_W
    { 998,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITCLRI_H
    { 997,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITCLRI_D
    { 996,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VBITCLRI_B
    { 995,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVG_WU
    { 994,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVG_W
    { 993,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVG_HU
    { 992,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVG_H
    { 991,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVG_DU
    { 990,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVG_D
    { 989,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVG_BU
    { 988,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVG_B
    { 987,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVGR_WU
    { 986,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVGR_W
    { 985,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVGR_HU
    { 984,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVGR_H
    { 983,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVGR_DU
    { 982,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVGR_D
    { 981,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVGR_BU
    { 980,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAVGR_B
    { 979,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VAND_V
    { 978,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VANDN_V
    { 977,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VANDI_B
    { 976,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADD_W
    { 975,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADD_Q
    { 974,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADD_H
    { 973,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADD_D
    { 972,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADD_B
    { 971,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_W_HU_H
    { 970,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_W_HU
    { 969,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_W_H
    { 968,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_Q_DU_D
    { 967,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_Q_DU
    { 966,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_Q_D
    { 965,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_H_BU_B
    { 964,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_H_BU
    { 963,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_H_B
    { 962,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_D_WU_W
    { 961,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_D_WU
    { 960,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWOD_D_W
    { 959,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_W_HU_H
    { 958,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_W_HU
    { 957,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_W_H
    { 956,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_Q_DU_D
    { 955,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_Q_DU
    { 954,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_Q_D
    { 953,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_H_BU_B
    { 952,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_H_BU
    { 951,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_H_B
    { 950,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_D_WU_W
    { 949,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_D_WU
    { 948,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDWEV_D_W
    { 947,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VADDI_WU
    { 946,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VADDI_HU
    { 945,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VADDI_DU
    { 944,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 356,	0,	0, 0x0ULL },  // VADDI_BU
    { 943,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDA_W
    { 942,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDA_H
    { 941,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDA_D
    { 940,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VADDA_B
    { 939,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VABSD_WU
    { 938,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VABSD_W
    { 937,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VABSD_HU
    { 936,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VABSD_H
    { 935,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VABSD_DU
    { 934,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VABSD_D
    { 933,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VABSD_BU
    { 932,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 353,	0,	0, 0x0ULL },  // VABSD_B
    { 931,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // UD
    { 930,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBWR
    { 929,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBSRCH
    { 928,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBRD
    { 927,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBFLUSH
    { 926,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBFILL
    { 925,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // TLBCLR
    { 924,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // SYSCALL
    { 923,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SUB_W
    { 922,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SUB_D
    { 921,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // ST_W
    { 920,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // ST_H
    { 919,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // ST_D
    { 918,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // ST_B
    { 917,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STX_W
    { 916,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STX_H
    { 915,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STX_D
    { 914,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STX_B
    { 913,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STR_W
    { 912,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STR_D
    { 911,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STPTR_W
    { 910,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STPTR_D
    { 909,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STL_W
    { 908,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STL_D
    { 907,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STLE_W
    { 906,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STLE_H
    { 905,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STLE_D
    { 904,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STLE_B
    { 903,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STGT_W
    { 902,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STGT_H
    { 901,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STGT_D
    { 900,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // STGT_B
    { 899,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SRL_W
    { 898,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SRL_D
    { 897,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // SRLI_W
    { 896,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // SRLI_D
    { 895,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SRA_W
    { 894,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SRA_D
    { 893,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // SRAI_W
    { 892,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // SRAI_D
    { 891,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // SLTUI
    { 890,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SLTU
    { 889,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // SLTI
    { 888,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SLT
    { 887,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SLL_W
    { 886,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SLL_D
    { 885,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // SLLI_W
    { 884,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // SLLI_D
    { 883,	1,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 352,	0,	0, 0x0ULL },  // SET_CFR_TRUE
    { 882,	1,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 352,	0,	0, 0x0ULL },  // SET_CFR_FALSE
    { 881,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // SETX86LOOPNE
    { 880,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // SETX86LOOPE
    { 879,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // SETX86J
    { 878,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // SETARMJ
    { 877,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 344,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // SC_W
    { 876,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 348,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // SC_Q
    { 875,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 344,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // SC_D
    { 874,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 341,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // SCREL_W
    { 873,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 341,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // SCREL_D
    { 872,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SBC_W
    { 871,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SBC_H
    { 870,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SBC_D
    { 869,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // SBC_B
    { 868,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ROTR_W
    { 867,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ROTR_H
    { 866,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ROTR_D
    { 865,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ROTR_B
    { 864,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ROTRI_W
    { 863,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ROTRI_H
    { 862,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ROTRI_D
    { 861,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ROTRI_B
    { 860,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // REVH_D
    { 859,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // REVH_2W
    { 858,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // REVB_D
    { 857,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // REVB_4H
    { 856,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // REVB_2W
    { 855,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // REVB_2H
    { 854,	2,	2,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDTIME_D
    { 853,	2,	2,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDTIMEL_W
    { 852,	2,	2,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RDTIMEH_W
    { 851,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // RCR_W
    { 850,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // RCR_H
    { 849,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // RCR_D
    { 848,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // RCR_B
    { 847,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // RCRI_W
    { 846,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // RCRI_H
    { 845,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // RCRI_D
    { 844,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // RCRI_B
    { 843,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 338,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PRELDX
    { 842,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 36,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PRELD
    { 841,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // PCALAU12I
    { 840,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // PCADDU18I
    { 839,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // PCADDU12I
    { 838,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // PCADDI
    { 837,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ORN
    { 836,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ORI
    { 835,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // OR
    { 834,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // NOR
    { 833,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // MUL_W
    { 832,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // MUL_D
    { 831,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // MULW_D_WU
    { 830,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // MULW_D_W
    { 829,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // MULH_WU
    { 828,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // MULH_W
    { 827,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // MULH_DU
    { 826,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // MULH_D
    { 825,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 336,	0,	0, 0x0ULL },  // MOVSCR2GR
    { 824,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 334,	0,	0, 0x0ULL },  // MOVGR2SCR
    { 823,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 330,	0,	0, 0x0ULL },  // MOVGR2FR_W_64
    { 822,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 332,	0,	0, 0x0ULL },  // MOVGR2FR_W
    { 821,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 330,	0,	0, 0x0ULL },  // MOVGR2FR_D
    { 820,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 327,	0,	0, 0x0ULL },  // MOVGR2FRH_W
    { 819,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 325,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MOVGR2FCSR
    { 818,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 323,	0,	0, 0x0ULL },  // MOVGR2CF
    { 817,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 319,	0,	0, 0x0ULL },  // MOVFRH2GR_S
    { 816,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 319,	0,	0, 0x0ULL },  // MOVFR2GR_S_64
    { 815,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 321,	0,	0, 0x0ULL },  // MOVFR2GR_S
    { 814,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 319,	0,	0, 0x0ULL },  // MOVFR2GR_D
    { 813,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 317,	0,	0, 0x0ULL },  // MOVFR2CF_xS
    { 812,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 315,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MOVFCSR2GR
    { 811,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 313,	0,	0, 0x0ULL },  // MOVCF2GR
    { 810,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 311,	0,	0, 0x0ULL },  // MOVCF2FR_xS
    { 809,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MOD_WU
    { 808,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MOD_W
    { 807,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MOD_DU
    { 806,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // MOD_D
    { 805,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // MASKNEZ
    { 804,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // MASKEQZ
    { 803,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LU52I_D
    { 802,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 259,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LU32I_D
    { 801,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Rematerializable), 0x0ULL },  // LU12I_W
    { 800,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LL_W
    { 799,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LL_D
    { 798,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LLACQ_W
    { 797,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LLACQ_D
    { 796,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LD_WU
    { 795,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LD_W
    { 794,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LD_HU
    { 793,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LD_H
    { 792,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LD_D
    { 791,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LD_BU
    { 790,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LD_B
    { 789,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDX_WU
    { 788,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDX_W
    { 787,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDX_HU
    { 786,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDX_H
    { 785,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDX_D
    { 784,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDX_BU
    { 783,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDX_B
    { 782,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDR_W
    { 781,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDR_D
    { 780,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDPTR_W
    { 779,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDPTR_D
    { 778,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDPTE
    { 777,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDL_W
    { 776,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDL_D
    { 775,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDLE_W
    { 774,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDLE_H
    { 773,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDLE_D
    { 772,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDLE_B
    { 771,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDGT_W
    { 770,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDGT_H
    { 769,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDGT_D
    { 768,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // LDGT_B
    { 767,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // LDDIR
    { 766,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0, 0x0ULL },  // JISCR1
    { 765,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0, 0x0ULL },  // JISCR0
    { 764,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // JIRL
    { 763,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IOCSRWR_W
    { 762,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IOCSRWR_H
    { 761,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IOCSRWR_D
    { 760,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IOCSRWR_B
    { 759,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IOCSRRD_W
    { 758,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IOCSRRD_H
    { 757,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IOCSRRD_D
    { 756,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IOCSRRD_B
    { 755,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INVTLB
    { 754,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IDLE
    { 753,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // IBAR
    { 752,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // HVCL
    { 751,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // GTLBFLUSH
    { 750,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // GCSRXCHG
    { 749,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 259,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // GCSRWR
    { 748,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // GCSRRD
    { 747,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FTINT_W_S
    { 746,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 284,	0,	0, 0x0ULL },  // FTINT_W_D
    { 745,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 282,	0,	0, 0x0ULL },  // FTINT_L_S
    { 744,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FTINT_L_D
    { 743,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FTINTRZ_W_S
    { 742,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 284,	0,	0, 0x0ULL },  // FTINTRZ_W_D
    { 741,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 282,	0,	0, 0x0ULL },  // FTINTRZ_L_S
    { 740,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FTINTRZ_L_D
    { 739,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FTINTRP_W_S
    { 738,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 284,	0,	0, 0x0ULL },  // FTINTRP_W_D
    { 737,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 282,	0,	0, 0x0ULL },  // FTINTRP_L_S
    { 736,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FTINTRP_L_D
    { 735,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FTINTRNE_W_S
    { 734,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 284,	0,	0, 0x0ULL },  // FTINTRNE_W_D
    { 733,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 282,	0,	0, 0x0ULL },  // FTINTRNE_L_S
    { 732,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FTINTRNE_L_D
    { 731,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FTINTRM_W_S
    { 730,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 284,	0,	0, 0x0ULL },  // FTINTRM_W_D
    { 729,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 282,	0,	0, 0x0ULL },  // FTINTRM_L_S
    { 728,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FTINTRM_L_D
    { 727,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FSUB_S
    { 726,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 270,	0,	0, 0x0ULL },  // FSUB_D
    { 725,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 292,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FST_S
    { 724,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 289,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FST_D
    { 723,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 286,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FSTX_S
    { 722,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 151,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FSTX_D
    { 721,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 286,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FSTLE_S
    { 720,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 151,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FSTLE_D
    { 719,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 286,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FSTGT_S
    { 718,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 151,	0,	0|(1ULL<<MCID::MayStore), 0x0ULL },  // FSTGT_D
    { 717,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FSQRT_S
    { 716,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FSQRT_D
    { 715,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 307,	0,	0, 0x0ULL },  // FSEL_xS
    { 714,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 303,	0,	0, 0x0ULL },  // FSEL_xD
    { 713,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FSCALEB_S
    { 712,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 270,	0,	0, 0x0ULL },  // FSCALEB_D
    { 711,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FRSQRT_S
    { 710,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FRSQRT_D
    { 709,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FRSQRTE_S
    { 708,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FRSQRTE_D
    { 707,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FRINT_S
    { 706,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FRINT_D
    { 705,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FRECIP_S
    { 704,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FRECIP_D
    { 703,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FRECIPE_S
    { 702,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FRECIPE_D
    { 701,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 299,	0,	0, 0x0ULL },  // FNMSUB_S
    { 700,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 295,	0,	0, 0x0ULL },  // FNMSUB_D
    { 699,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 299,	0,	0, 0x0ULL },  // FNMADD_S
    { 698,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 295,	0,	0, 0x0ULL },  // FNMADD_D
    { 697,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FNEG_S
    { 696,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FNEG_D
    { 695,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FMUL_S
    { 694,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 270,	0,	0, 0x0ULL },  // FMUL_D
    { 693,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 299,	0,	0, 0x0ULL },  // FMSUB_S
    { 692,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 295,	0,	0, 0x0ULL },  // FMSUB_D
    { 691,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FMOV_S
    { 690,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FMOV_D
    { 689,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FMIN_S
    { 688,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 270,	0,	0, 0x0ULL },  // FMIN_D
    { 687,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FMINA_S
    { 686,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 270,	0,	0, 0x0ULL },  // FMINA_D
    { 685,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FMAX_S
    { 684,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 270,	0,	0, 0x0ULL },  // FMAX_D
    { 683,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FMAXA_S
    { 682,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 270,	0,	0, 0x0ULL },  // FMAXA_D
    { 681,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 299,	0,	0, 0x0ULL },  // FMADD_S
    { 680,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 295,	0,	0, 0x0ULL },  // FMADD_D
    { 679,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FLOGB_S
    { 678,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FLOGB_D
    { 677,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 292,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLD_S
    { 676,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 289,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLD_D
    { 675,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 286,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLDX_S
    { 674,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLDX_D
    { 673,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 286,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLDLE_S
    { 672,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLDLE_D
    { 671,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 286,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLDGT_S
    { 670,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad), 0x0ULL },  // FLDGT_D
    { 669,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FFINT_S_W
    { 668,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 284,	0,	0, 0x0ULL },  // FFINT_S_L
    { 667,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 282,	0,	0, 0x0ULL },  // FFINT_D_W
    { 666,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FFINT_D_L
    { 665,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FDIV_S
    { 664,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 270,	0,	0, 0x0ULL },  // FDIV_D
    { 663,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FCVT_UD_D
    { 662,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 284,	0,	0, 0x0ULL },  // FCVT_S_D
    { 661,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FCVT_LD_D
    { 660,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 282,	0,	0, 0x0ULL },  // FCVT_D_S
    { 659,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FCVT_D_LD
    { 658,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FCOPYSIGN_S
    { 657,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 270,	0,	0, 0x0ULL },  // FCOPYSIGN_D
    { 656,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SUN_S
    { 655,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SUN_D
    { 654,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SUNE_S
    { 653,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SUNE_D
    { 652,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SULT_S
    { 651,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SULT_D
    { 650,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SULE_S
    { 649,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SULE_D
    { 648,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SUEQ_S
    { 647,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SUEQ_D
    { 646,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SOR_S
    { 645,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SOR_D
    { 644,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SNE_S
    { 643,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SNE_D
    { 642,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SLT_S
    { 641,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SLT_D
    { 640,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SLE_S
    { 639,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SLE_D
    { 638,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SEQ_S
    { 637,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SEQ_D
    { 636,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_SAF_S
    { 635,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_SAF_D
    { 634,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_CUN_S
    { 633,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_CUN_D
    { 632,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_CUNE_S
    { 631,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_CUNE_D
    { 630,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_CULT_S
    { 629,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_CULT_D
    { 628,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_CULE_S
    { 627,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_CULE_D
    { 626,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_CUEQ_S
    { 625,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_CUEQ_D
    { 624,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_COR_S
    { 623,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_COR_D
    { 622,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_CNE_S
    { 621,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_CNE_D
    { 620,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_CLT_S
    { 619,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_CLT_D
    { 618,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_CLE_S
    { 617,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_CLE_D
    { 616,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_CEQ_S
    { 615,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_CEQ_D
    { 614,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 279,	0,	0, 0x0ULL },  // FCMP_CAF_S
    { 613,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 276,	0,	0, 0x0ULL },  // FCMP_CAF_D
    { 612,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FCLASS_S
    { 611,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FCLASS_D
    { 610,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 273,	0,	0, 0x0ULL },  // FADD_S
    { 609,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 270,	0,	0, 0x0ULL },  // FADD_D
    { 608,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 268,	0,	0, 0x0ULL },  // FABS_S
    { 607,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 266,	0,	0, 0x0ULL },  // FABS_D
    { 606,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // EXT_W_H
    { 605,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // EXT_W_B
    { 604,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ERTN
    { 603,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // DIV_WU
    { 602,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // DIV_W
    { 601,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // DIV_DU
    { 600,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // DIV_D
    { 599,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DBCL
    { 598,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // DBAR
    { 597,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // CTZ_W
    { 596,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // CTZ_D
    { 595,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // CTO_W
    { 594,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // CTO_D
    { 593,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 262,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CSRXCHG
    { 592,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 259,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CSRWR
    { 591,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CSRRD
    { 590,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // CRC_W_W_W
    { 589,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // CRC_W_H_W
    { 588,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // CRC_W_D_W
    { 587,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // CRC_W_B_W
    { 586,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // CRCC_W_W_W
    { 585,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // CRCC_W_H_W
    { 584,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // CRCC_W_D_W
    { 583,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // CRCC_W_B_W
    { 582,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // CPUCFG
    { 581,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // CLZ_W
    { 580,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // CLZ_D
    { 579,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // CLO_W
    { 578,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // CLO_D
    { 577,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 36,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // CACOP
    { 576,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 154,	0,	0, 0x0ULL },  // BYTEPICK_W
    { 575,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 154,	0,	0, 0x0ULL },  // BYTEPICK_D
    { 574,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 255,	0,	0, 0x0ULL },  // BSTRPICK_W
    { 573,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 255,	0,	0, 0x0ULL },  // BSTRPICK_D
    { 572,	5,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 250,	0,	0, 0x0ULL },  // BSTRINS_W
    { 571,	5,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 250,	0,	0, 0x0ULL },  // BSTRINS_D
    { 570,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // BREAK
    { 569,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BNEZ
    { 568,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BNE
    { 567,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BLTU
    { 566,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BLT
    { 565,	1,	0,	4,	0,	0,	1,	LoongArchOpInfoBase + 0,	3,	0|(1ULL<<MCID::Call), 0x0ULL },  // BL
    { 564,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // BITREV_W
    { 563,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // BITREV_D
    { 562,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // BITREV_8B
    { 561,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0, 0x0ULL },  // BITREV_4B
    { 560,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BGEU
    { 559,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BGE
    { 558,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BEQZ
    { 557,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BEQ
    { 556,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 248,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BCNEZ
    { 555,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 248,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // BCEQZ
    { 554,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // B
    { 553,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ASRTLE_D
    { 552,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ASRTGT_D
    { 551,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMXOR_W
    { 550,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMSUB_W
    { 549,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMSRL_W
    { 548,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 245,	0,	0, 0x0ULL },  // ARMSRLI_W
    { 547,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMSRA_W
    { 546,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 245,	0,	0, 0x0ULL },  // ARMSRAI_W
    { 545,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMSLL_W
    { 544,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 245,	0,	0, 0x0ULL },  // ARMSLLI_W
    { 543,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMSBC_W
    { 542,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // ARMRRX_W
    { 541,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMROTR_W
    { 540,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 245,	0,	0, 0x0ULL },  // ARMROTRI_W
    { 539,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMOR_W
    { 538,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // ARMNOT_W
    { 537,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // ARMMTFLAG
    { 536,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // ARMMOV_W
    { 535,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // ARMMOV_D
    { 534,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMMOVE
    { 533,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0, 0x0ULL },  // ARMMFFLAG
    { 532,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMAND_W
    { 531,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMADD_W
    { 530,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ARMADC_W
    { 529,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ANDN
    { 528,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ANDI
    { 527,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // AND
    { 526,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMXOR__DB_W
    { 525,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMXOR__DB_D
    { 524,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMXOR_W
    { 523,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMXOR_D
    { 522,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMSWAP__DB_W
    { 521,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMSWAP__DB_H
    { 520,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMSWAP__DB_D
    { 519,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMSWAP__DB_B
    { 518,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMSWAP_W
    { 517,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMSWAP_H
    { 516,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMSWAP_D
    { 515,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMSWAP_B
    { 514,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMOR__DB_W
    { 513,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMOR__DB_D
    { 512,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMOR_W
    { 511,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMOR_D
    { 510,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMIN__DB_WU
    { 509,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMIN__DB_W
    { 508,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMIN__DB_DU
    { 507,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMIN__DB_D
    { 506,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMIN_WU
    { 505,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMIN_W
    { 504,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMIN_DU
    { 503,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMIN_D
    { 502,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMAX__DB_WU
    { 501,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMAX__DB_W
    { 500,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMAX__DB_DU
    { 499,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMAX__DB_D
    { 498,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMAX_WU
    { 497,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMAX_W
    { 496,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMAX_DU
    { 495,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMMAX_D
    { 494,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 241,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x3ULL },  // AMCAS__DB_W
    { 493,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 241,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x3ULL },  // AMCAS__DB_H
    { 492,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 241,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x3ULL },  // AMCAS__DB_D
    { 491,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 241,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x3ULL },  // AMCAS__DB_B
    { 490,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 241,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x3ULL },  // AMCAS_W
    { 489,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 241,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x3ULL },  // AMCAS_H
    { 488,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 241,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x3ULL },  // AMCAS_D
    { 487,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 241,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x3ULL },  // AMCAS_B
    { 486,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMAND__DB_W
    { 485,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMAND__DB_D
    { 484,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMAND_W
    { 483,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMAND_D
    { 482,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMADD__DB_W
    { 481,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMADD__DB_H
    { 480,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMADD__DB_D
    { 479,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMADD__DB_B
    { 478,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMADD_W
    { 477,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMADD_H
    { 476,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMADD_D
    { 475,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 238,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL },  // AMADD_B
    { 474,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 154,	0,	0, 0x0ULL },  // ALSL_WU
    { 473,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 154,	0,	0, 0x0ULL },  // ALSL_W
    { 472,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 154,	0,	0, 0x0ULL },  // ALSL_D
    { 471,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ADD_W
    { 470,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ADD_D
    { 469,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ADDU16I_D
    { 468,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ADDU12I_W
    { 467,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ADDU12I_D
    { 466,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0, 0x0ULL },  // ADDI_W
    { 465,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // ADDI_D
    { 464,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ADC_W
    { 463,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ADC_H
    { 462,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ADC_D
    { 461,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0, 0x0ULL },  // ADC_B
    { 460,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 236,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // WRFCSR
    { 459,	3,	2,	4,	0,	0,	0,	LoongArchOpInfoBase + 233,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // SplitPairF64Pseudo
    { 458,	6,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 227,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // Select_GPR_Using_CC_GPR
    { 457,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // RDFCSR
    { 456,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 225,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoXVREPLI_W
    { 455,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 225,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoXVREPLI_H
    { 454,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 225,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoXVREPLI_D
    { 453,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 225,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoXVREPLI_B
    { 452,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVMSKNEZ_B
    { 451,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVMSKLTZ_W
    { 450,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVMSKLTZ_H
    { 449,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVMSKLTZ_D
    { 448,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVMSKLTZ_B
    { 447,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVMSKGEZ_B
    { 446,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVMSKEQZ_B
    { 445,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 221,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVINSGR2VR_H
    { 444,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 221,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVINSGR2VR_B
    { 443,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVBZ_W
    { 442,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVBZ_H
    { 441,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVBZ_D
    { 440,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVBZ_B
    { 439,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVBZ
    { 438,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVBNZ_W
    { 437,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVBNZ_H
    { 436,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVBNZ_D
    { 435,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVBNZ_B
    { 434,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoXVBNZ
    { 433,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 217,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoVREPLI_W
    { 432,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 217,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoVREPLI_H
    { 431,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 217,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoVREPLI_D
    { 430,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 217,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoVREPLI_B
    { 429,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVMSKNEZ_B
    { 428,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVMSKLTZ_W
    { 427,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVMSKLTZ_H
    { 426,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVMSKLTZ_D
    { 425,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVMSKLTZ_B
    { 424,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVMSKGEZ_B
    { 423,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVMSKEQZ_B
    { 422,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVBZ_W
    { 421,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVBZ_H
    { 420,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVBZ_D
    { 419,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVBZ_B
    { 418,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVBZ
    { 417,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVBNZ_W
    { 416,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVBNZ_H
    { 415,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVBNZ_D
    { 414,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVBNZ_B
    { 413,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoVBNZ
    { 412,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PseudoUNIMP
    { 411,	1,	0,	4,	0,	1,	0,	LoongArchOpInfoBase + 0,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoTAIL_SMALL
    { 410,	1,	0,	8,	0,	1,	1,	LoongArchOpInfoBase + 0,	10,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoTAIL_MEDIUM
    { 409,	1,	0,	4,	0,	1,	0,	LoongArchOpInfoBase + 0,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoTAIL_LARGE
    { 408,	1,	0,	4,	0,	1,	0,	LoongArchOpInfoBase + 214,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoTAILIndirect
    { 407,	2,	0,	4,	0,	1,	0,	LoongArchOpInfoBase + 34,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoTAIL36
    { 406,	2,	0,	4,	0,	1,	0,	LoongArchOpInfoBase + 34,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoTAIL30
    { 405,	2,	0,	4,	0,	1,	0,	LoongArchOpInfoBase + 34,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoTAIL
    { 404,	3,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 189,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoST_CFR
    { 403,	0,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoRET
    { 402,	7,	2,	44,	0,	0,	0,	LoongArchOpInfoBase + 207,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoMaskedCmpXchg32
    { 401,	6,	2,	36,	0,	0,	0,	LoongArchOpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoMaskedAtomicSwap32
    { 400,	7,	3,	48,	0,	0,	0,	LoongArchOpInfoBase + 200,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoMaskedAtomicLoadUMin32
    { 399,	7,	3,	48,	0,	0,	0,	LoongArchOpInfoBase + 200,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoMaskedAtomicLoadUMax32
    { 398,	6,	2,	36,	0,	0,	0,	LoongArchOpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoMaskedAtomicLoadSub32
    { 397,	6,	2,	36,	0,	0,	0,	LoongArchOpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoMaskedAtomicLoadNand32
    { 396,	8,	3,	56,	0,	0,	0,	LoongArchOpInfoBase + 192,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoMaskedAtomicLoadMin32
    { 395,	8,	3,	56,	0,	0,	0,	LoongArchOpInfoBase + 192,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoMaskedAtomicLoadMax32
    { 394,	6,	2,	36,	0,	0,	0,	LoongArchOpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoMaskedAtomicLoadAdd32
    { 393,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLI_W
    { 392,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLI_D
    { 391,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 189,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // PseudoLD_CFR
    { 390,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLA_TLS_LE
    { 389,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLA_TLS_LD_LARGE
    { 388,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLA_TLS_LD
    { 387,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // PseudoLA_TLS_IE_LARGE
    { 386,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // PseudoLA_TLS_IE
    { 385,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLA_TLS_GD_LARGE
    { 384,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLA_TLS_GD
    { 383,	3,	1,	4,	0,	0,	2,	LoongArchOpInfoBase + 186,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call), 0x0ULL },  // PseudoLA_TLS_DESC_LARGE
    { 382,	2,	1,	4,	0,	0,	1,	LoongArchOpInfoBase + 34,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // PseudoLA_TLS_DESC
    { 381,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLA_PCREL_LARGE
    { 380,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLA_PCREL
    { 379,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // PseudoLA_GOT_LARGE
    { 378,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // PseudoLA_GOT
    { 377,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLA_ABS_LARGE
    { 376,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoLA_ABS
    { 375,	2,	0,	4,	0,	1,	0,	LoongArchOpInfoBase + 34,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoJIRL_TAIL
    { 374,	2,	0,	4,	0,	0,	1,	LoongArchOpInfoBase + 34,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL },  // PseudoJIRL_CALL
    { 373,	3,	1,	4,	0,	1,	1,	LoongArchOpInfoBase + 186,	6,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call), 0x0ULL },  // PseudoDESC_CALL
    { 372,	2,	1,	12,	0,	0,	0,	LoongArchOpInfoBase + 184,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoCopyCFR
    { 371,	6,	2,	36,	0,	0,	0,	LoongArchOpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoCmpXchg64
    { 370,	6,	2,	36,	0,	0,	0,	LoongArchOpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoCmpXchg32
    { 369,	8,	3,	36,	0,	0,	0,	LoongArchOpInfoBase + 170,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoCmpXchg128Acquire
    { 368,	8,	3,	36,	0,	0,	0,	LoongArchOpInfoBase + 170,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoCmpXchg128
    { 367,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoCTPOP_W_LA32
    { 366,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoCTPOP_W
    { 365,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoCTPOP_H_LA32
    { 364,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoCTPOP_H
    { 363,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoCTPOP_D
    { 362,	2,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 168,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // PseudoCTPOP_B
    { 361,	1,	0,	4,	0,	0,	1,	LoongArchOpInfoBase + 0,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL },  // PseudoCALL_SMALL
    { 360,	1,	0,	8,	0,	0,	2,	LoongArchOpInfoBase + 0,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL },  // PseudoCALL_MEDIUM
    { 359,	1,	0,	4,	0,	0,	1,	LoongArchOpInfoBase + 0,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL },  // PseudoCALL_LARGE
    { 358,	1,	0,	4,	0,	0,	1,	LoongArchOpInfoBase + 28,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL },  // PseudoCALLIndirect
    { 357,	1,	0,	4,	0,	0,	1,	LoongArchOpInfoBase + 0,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call), 0x0ULL },  // PseudoCALL36
    { 356,	1,	0,	4,	0,	0,	1,	LoongArchOpInfoBase + 0,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call), 0x0ULL },  // PseudoCALL30
    { 355,	1,	0,	4,	0,	0,	1,	LoongArchOpInfoBase + 0,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call), 0x0ULL },  // PseudoCALL
    { 354,	1,	0,	4,	0,	1,	0,	LoongArchOpInfoBase + 0,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoB_TAIL
    { 353,	2,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 166,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoBRIND
    { 352,	1,	0,	4,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // PseudoBR
    { 351,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicSwap32
    { 350,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicStoreW
    { 349,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 163,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicStoreD
    { 348,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadXor32
    { 347,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadUMin32
    { 346,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadUMax32
    { 345,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadSub32
    { 344,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadOr32
    { 343,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadNand64
    { 342,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadNand32
    { 341,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadMin32
    { 340,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadMax32
    { 339,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadAnd32
    { 338,	5,	2,	24,	0,	0,	0,	LoongArchOpInfoBase + 158,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // PseudoAtomicLoadAdd32
    { 337,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 154,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoAddTPRel_W
    { 336,	4,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 154,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // PseudoAddTPRel_D
    { 335,	1,	0,	4,	0,	1,	1,	LoongArchOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PROBED_STACKALLOC_DYN
    { 334,	1,	0,	4,	0,	1,	1,	LoongArchOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PROBED_STACKALLOC
    { 333,	3,	1,	4,	0,	0,	0,	LoongArchOpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL },  // BuildPairF64Pseudo
    { 332,	2,	0,	4,	0,	1,	1,	LoongArchOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // ADJCALLSTACKUP
    { 331,	2,	0,	4,	0,	1,	1,	LoongArchOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // ADJCALLSTACKDOWN
    { 330,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	LoongArchOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_21712
    { 41,	2,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_21711
    { 40,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // anonymous_21710
    { 31,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	LoongArchOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	LoongArchOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL },  // PHI
  }, {
    /* 0 */
    /* 0 */ LoongArch::R3, LoongArch::R3,
    /* 2 */ LoongArch::R3,
    /* 3 */ LoongArch::R1,
    /* 4 */ LoongArch::R1, LoongArch::R20,
    /* 6 */ LoongArch::R4, LoongArch::R4,
    /* 8 */ LoongArch::R1, LoongArch::R4,
    /* 10 */ LoongArch::R3, LoongArch::R20,
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
    /* 28 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
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
    /* 151 */ { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 154 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 158 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 163 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 166 */ { LoongArch::GPRJRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 168 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 170 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 178 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 184 */ { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 186 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 189 */ { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 192 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 200 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 207 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 214 */ { LoongArch::GPRTRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 215 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 217 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 219 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 221 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 225 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 227 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 233 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 236 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 238 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 241 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 245 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 248 */ { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 250 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 255 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 259 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 262 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::GPRNoR0R1RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 266 */ { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 268 */ { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 270 */ { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 273 */ { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 276 */ { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 279 */ { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 282 */ { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 284 */ { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 286 */ { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 289 */ { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 292 */ { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 295 */ { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 299 */ { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 303 */ { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 307 */ { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 311 */ { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 313 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 315 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FCSRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 317 */ { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 319 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 321 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 323 */ { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 325 */ { LoongArch::FCSRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 327 */ { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 330 */ { LoongArch::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 332 */ { LoongArch::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 334 */ { LoongArch::SCRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 336 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::SCRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 338 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 341 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 344 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 348 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 352 */ { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 353 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 356 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 359 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 363 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 367 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 369 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 371 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 375 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 379 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 382 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 385 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 388 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 390 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 393 */ { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 395 */ { LoongArch::LSX128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 399 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 402 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 405 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 409 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 413 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 417 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 420 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 423 */ { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 426 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 428 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 431 */ { LoongArch::CFRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 433 */ { LoongArch::LASX256RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { LoongArch::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
  }
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char LoongArchInstrNameData[] = {
  /* 0 */ "G_FLOG10\000"
  /* 9 */ "G_FEXP10\000"
  /* 18 */ "PseudoTAIL30\000"
  /* 31 */ "PseudoCALL30\000"
  /* 44 */ "JISCR0\000"
  /* 51 */ "JISCR1\000"
  /* 58 */ "PseudoCTPOP_H_LA32\000"
  /* 77 */ "PseudoCTPOP_W_LA32\000"
  /* 96 */ "PseudoMaskedAtomicLoadSub32\000"
  /* 124 */ "PseudoAtomicLoadSub32\000"
  /* 146 */ "PseudoMaskedAtomicLoadAdd32\000"
  /* 174 */ "PseudoAtomicLoadAdd32\000"
  /* 196 */ "PseudoAtomicLoadAnd32\000"
  /* 218 */ "PseudoMaskedAtomicLoadNand32\000"
  /* 247 */ "PseudoAtomicLoadNand32\000"
  /* 270 */ "PseudoMaskedCmpXchg32\000"
  /* 292 */ "PseudoCmpXchg32\000"
  /* 308 */ "PseudoMaskedAtomicLoadUMin32\000"
  /* 337 */ "PseudoAtomicLoadUMin32\000"
  /* 360 */ "PseudoMaskedAtomicLoadMin32\000"
  /* 388 */ "PseudoAtomicLoadMin32\000"
  /* 410 */ "PseudoMaskedAtomicSwap32\000"
  /* 435 */ "PseudoAtomicSwap32\000"
  /* 454 */ "PseudoAtomicLoadOr32\000"
  /* 475 */ "PseudoAtomicLoadXor32\000"
  /* 497 */ "PseudoMaskedAtomicLoadUMax32\000"
  /* 526 */ "PseudoAtomicLoadUMax32\000"
  /* 549 */ "PseudoMaskedAtomicLoadMax32\000"
  /* 577 */ "PseudoAtomicLoadMax32\000"
  /* 599 */ "G_FLOG2\000"
  /* 607 */ "G_FATAN2\000"
  /* 616 */ "G_FEXP2\000"
  /* 624 */ "MOVFR2GR_S_64\000"
  /* 638 */ "MOVGR2FR_W_64\000"
  /* 652 */ "PseudoAtomicLoadNand64\000"
  /* 675 */ "PseudoCmpXchg64\000"
  /* 691 */ "PseudoTAIL36\000"
  /* 704 */ "PseudoCALL36\000"
  /* 717 */ "PseudoCmpXchg128\000"
  /* 734 */ "G_FMA\000"
  /* 740 */ "G_STRICT_FMA\000"
  /* 753 */ "BITREV_4B\000"
  /* 763 */ "BITREV_8B\000"
  /* 773 */ "INVTLB\000"
  /* 780 */ "G_FSUB\000"
  /* 787 */ "G_STRICT_FSUB\000"
  /* 801 */ "G_ATOMICRMW_FSUB\000"
  /* 818 */ "G_SUB\000"
  /* 824 */ "G_ATOMICRMW_SUB\000"
  /* 840 */ "XVREPLVE0_B\000"
  /* 852 */ "XVADDA_B\000"
  /* 861 */ "X86SRA_B\000"
  /* 870 */ "XVSRA_B\000"
  /* 878 */ "AMADD__DB_B\000"
  /* 890 */ "AMSWAP__DB_B\000"
  /* 903 */ "AMCAS__DB_B\000"
  /* 915 */ "X86SUB_B\000"
  /* 924 */ "XVMSUB_B\000"
  /* 933 */ "XVSSUB_B\000"
  /* 942 */ "XVSUB_B\000"
  /* 950 */ "X86SBC_B\000"
  /* 959 */ "X86ADC_B\000"
  /* 968 */ "X86DEC_B\000"
  /* 977 */ "X86INC_B\000"
  /* 986 */ "X86ADD_B\000"
  /* 995 */ "AMADD_B\000"
  /* 1003 */ "XVMADD_B\000"
  /* 1012 */ "XVSADD_B\000"
  /* 1021 */ "XVADD_B\000"
  /* 1029 */ "LD_B\000"
  /* 1034 */ "X86AND_B\000"
  /* 1043 */ "XVPACKOD_B\000"
  /* 1054 */ "XVPICKOD_B\000"
  /* 1065 */ "XVMOD_B\000"
  /* 1073 */ "IOCSRRD_B\000"
  /* 1083 */ "XVABSD_B\000"
  /* 1092 */ "VEXT2XV_D_B\000"
  /* 1104 */ "LDLE_B\000"
  /* 1111 */ "XVSLE_B\000"
  /* 1119 */ "STLE_B\000"
  /* 1126 */ "XVREPLVE_B\000"
  /* 1137 */ "XVSHUF_B\000"
  /* 1146 */ "XVNEG_B\000"
  /* 1154 */ "XVAVG_B\000"
  /* 1162 */ "XVMUH_B\000"
  /* 1170 */ "XVILVH_B\000"
  /* 1179 */ "XVSUBWOD_H_B\000"
  /* 1192 */ "XVMADDWOD_H_B\000"
  /* 1206 */ "XVADDWOD_H_B\000"
  /* 1219 */ "XVMULWOD_H_B\000"
  /* 1232 */ "XVEXTH_H_B\000"
  /* 1243 */ "XVSLLWIL_H_B\000"
  /* 1256 */ "XVSUBWEV_H_B\000"
  /* 1269 */ "XVMADDWEV_H_B\000"
  /* 1283 */ "XVADDWEV_H_B\000"
  /* 1296 */ "XVMULWEV_H_B\000"
  /* 1309 */ "VEXT2XV_H_B\000"
  /* 1321 */ "XVHSUBW_H_B\000"
  /* 1333 */ "XVHADDW_H_B\000"
  /* 1345 */ "XVSHUF4I_B\000"
  /* 1356 */ "X86SRAI_B\000"
  /* 1366 */ "XVSRAI_B\000"
  /* 1375 */ "XVANDI_B\000"
  /* 1384 */ "XVSLEI_B\000"
  /* 1393 */ "XVREPL128VEI_B\000"
  /* 1408 */ "VREPLVEI_B\000"
  /* 1419 */ "X86RCLI_B\000"
  /* 1429 */ "XVBITSELI_B\000"
  /* 1441 */ "X86SLLI_B\000"
  /* 1451 */ "XVSLLI_B\000"
  /* 1460 */ "PseudoXVREPLI_B\000"
  /* 1476 */ "PseudoVREPLI_B\000"
  /* 1491 */ "X86SRLI_B\000"
  /* 1501 */ "XVSRLI_B\000"
  /* 1510 */ "X86ROTLI_B\000"
  /* 1521 */ "XVMINI_B\000"
  /* 1530 */ "XVFRSTPI_B\000"
  /* 1541 */ "XVSEQI_B\000"
  /* 1550 */ "XVSRARI_B\000"
  /* 1560 */ "X86RCRI_B\000"
  /* 1570 */ "XVBITCLRI_B\000"
  /* 1582 */ "XVSRLRI_B\000"
  /* 1592 */ "XVNORI_B\000"
  /* 1601 */ "XVORI_B\000"
  /* 1609 */ "XVXORI_B\000"
  /* 1618 */ "X86ROTRI_B\000"
  /* 1629 */ "XVROTRI_B\000"
  /* 1639 */ "XVBITSETI_B\000"
  /* 1651 */ "XVSLTI_B\000"
  /* 1660 */ "XVBITREVI_B\000"
  /* 1672 */ "XVMAXI_B\000"
  /* 1681 */ "X86RCL_B\000"
  /* 1690 */ "X86SLL_B\000"
  /* 1699 */ "XVSLL_B\000"
  /* 1707 */ "XVLDREPL_B\000"
  /* 1718 */ "X86SRL_B\000"
  /* 1727 */ "XVSRL_B\000"
  /* 1735 */ "X86ROTL_B\000"
  /* 1745 */ "X86MUL_B\000"
  /* 1754 */ "XVMUL_B\000"
  /* 1762 */ "XVILVL_B\000"
  /* 1771 */ "XVSTELM_B\000"
  /* 1781 */ "XVMIN_B\000"
  /* 1789 */ "XVCLO_B\000"
  /* 1797 */ "AMSWAP_B\000"
  /* 1806 */ "PseudoCTPOP_B\000"
  /* 1820 */ "XVFRSTP_B\000"
  /* 1830 */ "XVSEQ_B\000"
  /* 1838 */ "XVSRAR_B\000"
  /* 1847 */ "X86RCR_B\000"
  /* 1856 */ "VPICKVE2GR_B\000"
  /* 1869 */ "XVAVGR_B\000"
  /* 1878 */ "XVBITCLR_B\000"
  /* 1889 */ "XVSRLR_B\000"
  /* 1898 */ "X86OR_B\000"
  /* 1906 */ "X86XOR_B\000"
  /* 1915 */ "X86ROTR_B\000"
  /* 1925 */ "XVROTR_B\000"
  /* 1934 */ "XVREPLGR2VR_B\000"
  /* 1948 */ "PseudoXVINSGR2VR_B\000"
  /* 1967 */ "IOCSRWR_B\000"
  /* 1977 */ "AMCAS_B\000"
  /* 1985 */ "XVEXTRINS_B\000"
  /* 1997 */ "XVSAT_B\000"
  /* 2005 */ "XVBITSET_B\000"
  /* 2016 */ "LDGT_B\000"
  /* 2023 */ "STGT_B\000"
  /* 2030 */ "XVSLT_B\000"
  /* 2038 */ "XVPCNT_B\000"
  /* 2047 */ "ST_B\000"
  /* 2052 */ "XVMADDWOD_H_BU_B\000"
  /* 2069 */ "XVADDWOD_H_BU_B\000"
  /* 2085 */ "XVMULWOD_H_BU_B\000"
  /* 2101 */ "XVMADDWEV_H_BU_B\000"
  /* 2118 */ "XVADDWEV_H_BU_B\000"
  /* 2134 */ "XVMULWEV_H_BU_B\000"
  /* 2150 */ "XVPACKEV_B\000"
  /* 2161 */ "XVPICKEV_B\000"
  /* 2172 */ "XVBITREV_B\000"
  /* 2183 */ "XVDIV_B\000"
  /* 2191 */ "XVSIGNCOV_B\000"
  /* 2203 */ "EXT_W_B\000"
  /* 2211 */ "VEXT2XV_W_B\000"
  /* 2223 */ "XVMAX_B\000"
  /* 2231 */ "LDX_B\000"
  /* 2237 */ "STX_B\000"
  /* 2243 */ "PseudoXVBZ_B\000"
  /* 2256 */ "PseudoVBZ_B\000"
  /* 2268 */ "PseudoXVMSKGEZ_B\000"
  /* 2285 */ "PseudoVMSKGEZ_B\000"
  /* 2301 */ "PseudoXVMSKNEZ_B\000"
  /* 2318 */ "PseudoVMSKNEZ_B\000"
  /* 2334 */ "XVSETALLNEZ_B\000"
  /* 2348 */ "XVCLZ_B\000"
  /* 2356 */ "PseudoXVBNZ_B\000"
  /* 2370 */ "PseudoVBNZ_B\000"
  /* 2383 */ "XVMSKNZ_B\000"
  /* 2393 */ "PseudoXVMSKEQZ_B\000"
  /* 2410 */ "PseudoVMSKEQZ_B\000"
  /* 2426 */ "XVSETANYEQZ_B\000"
  /* 2440 */ "PseudoXVMSKLTZ_B\000"
  /* 2457 */ "PseudoVMSKLTZ_B\000"
  /* 2473 */ "G_INTRINSIC\000"
  /* 2485 */ "G_FPTRUNC\000"
  /* 2495 */ "G_INTRINSIC_TRUNC\000"
  /* 2513 */ "G_TRUNC\000"
  /* 2521 */ "G_BUILD_VECTOR_TRUNC\000"
  /* 2542 */ "PROBED_STACKALLOC\000"
  /* 2560 */ "G_DYN_STACKALLOC\000"
  /* 2577 */ "PseudoLA_TLS_DESC\000"
  /* 2595 */ "G_FMAD\000"
  /* 2602 */ "G_FPEXTLOAD\000"
  /* 2614 */ "G_INDEXED_SEXTLOAD\000"
  /* 2633 */ "G_SEXTLOAD\000"
  /* 2644 */ "G_INDEXED_ZEXTLOAD\000"
  /* 2663 */ "G_ZEXTLOAD\000"
  /* 2674 */ "G_INDEXED_LOAD\000"
  /* 2689 */ "G_LOAD\000"
  /* 2696 */ "G_VECREDUCE_FADD\000"
  /* 2713 */ "G_FADD\000"
  /* 2720 */ "G_VECREDUCE_SEQ_FADD\000"
  /* 2741 */ "G_STRICT_FADD\000"
  /* 2755 */ "G_ATOMICRMW_FADD\000"
  /* 2772 */ "G_VECREDUCE_ADD\000"
  /* 2788 */ "G_ADD\000"
  /* 2794 */ "G_PTR_ADD\000"
  /* 2804 */ "G_ATOMICRMW_ADD\000"
  /* 2820 */ "PseudoLA_TLS_GD\000"
  /* 2836 */ "PRELD\000"
  /* 2842 */ "XVLD\000"
  /* 2847 */ "FCVT_D_LD\000"
  /* 2857 */ "PseudoLA_TLS_LD\000"
  /* 2873 */ "G_ATOMICRMW_NAND\000"
  /* 2890 */ "G_VECREDUCE_AND\000"
  /* 2906 */ "G_AND\000"
  /* 2912 */ "G_ATOMICRMW_AND\000"
  /* 2928 */ "LIFETIME_END\000"
  /* 2941 */ "PseudoBRIND\000"
  /* 2953 */ "G_BRCOND\000"
  /* 2962 */ "G_ATOMICRMW_USUB_COND\000"
  /* 2984 */ "G_LLROUND\000"
  /* 2994 */ "G_LROUND\000"
  /* 3003 */ "G_INTRINSIC_ROUND\000"
  /* 3021 */ "G_INTRINSIC_FPTRUNC_ROUND\000"
  /* 3047 */ "LOAD_STACK_GUARD\000"
  /* 3064 */ "TLBRD\000"
  /* 3070 */ "GCSRRD\000"
  /* 3077 */ "UD\000"
  /* 3080 */ "XVREPLVE0_D\000"
  /* 3092 */ "XVINSVE0_D\000"
  /* 3103 */ "XVADDA_D\000"
  /* 3112 */ "XVFMINA_D\000"
  /* 3122 */ "X86SRA_D\000"
  /* 3131 */ "XVSRA_D\000"
  /* 3139 */ "XVFMAXA_D\000"
  /* 3149 */ "AMADD__DB_D\000"
  /* 3161 */ "AMAND__DB_D\000"
  /* 3173 */ "AMMIN__DB_D\000"
  /* 3185 */ "AMSWAP__DB_D\000"
  /* 3198 */ "AMOR__DB_D\000"
  /* 3209 */ "AMXOR__DB_D\000"
  /* 3221 */ "AMCAS__DB_D\000"
  /* 3233 */ "AMMAX__DB_D\000"
  /* 3245 */ "FSCALEB_D\000"
  /* 3255 */ "XVFLOGB_D\000"
  /* 3265 */ "X86SUB_D\000"
  /* 3274 */ "XVFSUB_D\000"
  /* 3283 */ "XVFMSUB_D\000"
  /* 3293 */ "XVFNMSUB_D\000"
  /* 3304 */ "XVMSUB_D\000"
  /* 3313 */ "XVSSUB_D\000"
  /* 3322 */ "XVSUB_D\000"
  /* 3330 */ "REVB_D\000"
  /* 3337 */ "X86SBC_D\000"
  /* 3346 */ "X86ADC_D\000"
  /* 3355 */ "X86DEC_D\000"
  /* 3364 */ "X86INC_D\000"
  /* 3373 */ "SC_D\000"
  /* 3378 */ "X86ADD_D\000"
  /* 3387 */ "XVFADD_D\000"
  /* 3396 */ "AMADD_D\000"
  /* 3404 */ "XVFMADD_D\000"
  /* 3414 */ "XVFNMADD_D\000"
  /* 3425 */ "XVMADD_D\000"
  /* 3434 */ "XVSADD_D\000"
  /* 3443 */ "XVADD_D\000"
  /* 3451 */ "FLD_D\000"
  /* 3457 */ "FCVT_LD_D\000"
  /* 3467 */ "X86AND_D\000"
  /* 3476 */ "AMAND_D\000"
  /* 3484 */ "XVPACKOD_D\000"
  /* 3495 */ "XVPICKOD_D\000"
  /* 3506 */ "XVMOD_D\000"
  /* 3514 */ "IOCSRRD_D\000"
  /* 3524 */ "XVABSD_D\000"
  /* 3533 */ "FCVT_UD_D\000"
  /* 3543 */ "XVFCMP_CLE_D\000"
  /* 3556 */ "FLDLE_D\000"
  /* 3564 */ "XVSLE_D\000"
  /* 3572 */ "XVFCMP_SLE_D\000"
  /* 3585 */ "ASRTLE_D\000"
  /* 3594 */ "FSTLE_D\000"
  /* 3602 */ "XVFCMP_CULE_D\000"
  /* 3616 */ "XVFCMP_SULE_D\000"
  /* 3630 */ "RDTIME_D\000"
  /* 3639 */ "XVFCMP_CNE_D\000"
  /* 3652 */ "XVFRINTRNE_D\000"
  /* 3665 */ "XVFCMP_SNE_D\000"
  /* 3678 */ "XVFCMP_CUNE_D\000"
  /* 3692 */ "XVFCMP_SUNE_D\000"
  /* 3706 */ "XVFRECIPE_D\000"
  /* 3718 */ "XVFRSQRTE_D\000"
  /* 3730 */ "XVPICKVE_D\000"
  /* 3741 */ "XVREPLVE_D\000"
  /* 3752 */ "XVFCMP_CAF_D\000"
  /* 3765 */ "XVFCMP_SAF_D\000"
  /* 3778 */ "XVSHUF_D\000"
  /* 3787 */ "FNEG_D\000"
  /* 3794 */ "XVNEG_D\000"
  /* 3802 */ "XVAVG_D\000"
  /* 3810 */ "MULH_D\000"
  /* 3817 */ "XVMUH_D\000"
  /* 3825 */ "REVH_D\000"
  /* 3832 */ "XVILVH_D\000"
  /* 3841 */ "ADDU12I_D\000"
  /* 3851 */ "LU32I_D\000"
  /* 3859 */ "LU52I_D\000"
  /* 3867 */ "XVSHUF4I_D\000"
  /* 3878 */ "ADDU16I_D\000"
  /* 3888 */ "X86SRAI_D\000"
  /* 3898 */ "XVSRAI_D\000"
  /* 3907 */ "ADDI_D\000"
  /* 3914 */ "XVSLEI_D\000"
  /* 3923 */ "XVREPL128VEI_D\000"
  /* 3938 */ "VREPLVEI_D\000"
  /* 3949 */ "X86RCLI_D\000"
  /* 3959 */ "XVHSELI_D\000"
  /* 3969 */ "X86SLLI_D\000"
  /* 3979 */ "XVSLLI_D\000"
  /* 3988 */ "PseudoXVREPLI_D\000"
  /* 4004 */ "PseudoVREPLI_D\000"
  /* 4019 */ "X86SRLI_D\000"
  /* 4029 */ "XVSRLI_D\000"
  /* 4038 */ "X86ROTLI_D\000"
  /* 4049 */ "PseudoLI_D\000"
  /* 4060 */ "XVPERMI_D\000"
  /* 4070 */ "XVMINI_D\000"
  /* 4079 */ "XVSEQI_D\000"
  /* 4088 */ "XVSRARI_D\000"
  /* 4098 */ "X86RCRI_D\000"
  /* 4108 */ "XVBITCLRI_D\000"
  /* 4120 */ "XVSRLRI_D\000"
  /* 4130 */ "X86ROTRI_D\000"
  /* 4141 */ "XVROTRI_D\000"
  /* 4151 */ "XVBITSETI_D\000"
  /* 4163 */ "XVSLTI_D\000"
  /* 4172 */ "XVBITREVI_D\000"
  /* 4184 */ "XVMAXI_D\000"
  /* 4193 */ "BYTEPICK_D\000"
  /* 4204 */ "BSTRPICK_D\000"
  /* 4215 */ "X86RCL_D\000"
  /* 4224 */ "LDL_D\000"
  /* 4230 */ "SCREL_D\000"
  /* 4238 */ "X86SLL_D\000"
  /* 4247 */ "XVSLL_D\000"
  /* 4255 */ "XVLDREPL_D\000"
  /* 4266 */ "X86SRL_D\000"
  /* 4275 */ "XVSRL_D\000"
  /* 4283 */ "ALSL_D\000"
  /* 4290 */ "X86ROTL_D\000"
  /* 4300 */ "STL_D\000"
  /* 4306 */ "X86MUL_D\000"
  /* 4315 */ "XVFMUL_D\000"
  /* 4324 */ "XVMUL_D\000"
  /* 4332 */ "XVILVL_D\000"
  /* 4341 */ "XVFTINTRNE_L_D\000"
  /* 4356 */ "XVFTINTRM_L_D\000"
  /* 4370 */ "XVFTINTRP_L_D\000"
  /* 4384 */ "XVFTINT_L_D\000"
  /* 4396 */ "XVFTINTRZ_L_D\000"
  /* 4410 */ "XVSTELM_D\000"
  /* 4420 */ "XVFRINTRM_D\000"
  /* 4432 */ "FCOPYSIGN_D\000"
  /* 4444 */ "XVFMIN_D\000"
  /* 4453 */ "AMMIN_D\000"
  /* 4461 */ "XVMIN_D\000"
  /* 4469 */ "XVFCMP_CUN_D\000"
  /* 4482 */ "XVFCMP_SUN_D\000"
  /* 4495 */ "XVCLO_D\000"
  /* 4503 */ "CTO_D\000"
  /* 4509 */ "AMSWAP_D\000"
  /* 4518 */ "XVFRECIP_D\000"
  /* 4529 */ "PseudoCTPOP_D\000"
  /* 4543 */ "XVFRINTRP_D\000"
  /* 4555 */ "LLACQ_D\000"
  /* 4563 */ "XVFCMP_CEQ_D\000"
  /* 4576 */ "XVSEQ_D\000"
  /* 4584 */ "XVFCMP_SEQ_D\000"
  /* 4597 */ "XVFCMP_CUEQ_D\000"
  /* 4611 */ "XVFCMP_SUEQ_D\000"
  /* 4625 */ "XVSUBWOD_Q_D\000"
  /* 4638 */ "XVMADDWOD_Q_D\000"
  /* 4652 */ "XVADDWOD_Q_D\000"
  /* 4665 */ "XVMULWOD_Q_D\000"
  /* 4678 */ "XVEXTH_Q_D\000"
  /* 4689 */ "XVEXTL_Q_D\000"
  /* 4700 */ "XVSUBWEV_Q_D\000"
  /* 4713 */ "XVMADDWEV_Q_D\000"
  /* 4727 */ "XVADDWEV_Q_D\000"
  /* 4740 */ "XVMULWEV_Q_D\000"
  /* 4753 */ "XVHSUBW_Q_D\000"
  /* 4765 */ "XVHADDW_Q_D\000"
  /* 4777 */ "XVSRAR_D\000"
  /* 4786 */ "X86RCR_D\000"
  /* 4795 */ "LDR_D\000"
  /* 4801 */ "MOVGR2FR_D\000"
  /* 4812 */ "XVPICKVE2GR_D\000"
  /* 4826 */ "MOVFR2GR_D\000"
  /* 4837 */ "XVAVGR_D\000"
  /* 4846 */ "XVBITCLR_D\000"
  /* 4857 */ "XVSRLR_D\000"
  /* 4866 */ "X86OR_D\000"
  /* 4874 */ "XVFCMP_COR_D\000"
  /* 4887 */ "AMOR_D\000"
  /* 4894 */ "XVFCMP_SOR_D\000"
  /* 4907 */ "X86XOR_D\000"
  /* 4916 */ "AMXOR_D\000"
  /* 4924 */ "X86ROTR_D\000"
  /* 4934 */ "XVROTR_D\000"
  /* 4943 */ "LDPTR_D\000"
  /* 4951 */ "STPTR_D\000"
  /* 4959 */ "STR_D\000"
  /* 4965 */ "XVREPLGR2VR_D\000"
  /* 4979 */ "XVINSGR2VR_D\000"
  /* 4992 */ "IOCSRWR_D\000"
  /* 5002 */ "AMCAS_D\000"
  /* 5010 */ "FABS_D\000"
  /* 5017 */ "BSTRINS_D\000"
  /* 5027 */ "XVEXTRINS_D\000"
  /* 5039 */ "XVFCLASS_D\000"
  /* 5050 */ "XVFCVT_S_D\000"
  /* 5061 */ "XVSAT_D\000"
  /* 5069 */ "XVBITSET_D\000"
  /* 5080 */ "FLDGT_D\000"
  /* 5088 */ "ASRTGT_D\000"
  /* 5097 */ "FSTGT_D\000"
  /* 5105 */ "XVFCMP_CLT_D\000"
  /* 5118 */ "XVSLT_D\000"
  /* 5126 */ "XVFCMP_SLT_D\000"
  /* 5139 */ "XVFCMP_CULT_D\000"
  /* 5153 */ "XVFCMP_SULT_D\000"
  /* 5167 */ "XVPCNT_D\000"
  /* 5176 */ "XVFRINT_D\000"
  /* 5186 */ "XVFSQRT_D\000"
  /* 5196 */ "XVFRSQRT_D\000"
  /* 5207 */ "FST_D\000"
  /* 5213 */ "XVMADDWOD_Q_DU_D\000"
  /* 5230 */ "XVADDWOD_Q_DU_D\000"
  /* 5246 */ "XVMULWOD_Q_DU_D\000"
  /* 5262 */ "XVMADDWEV_Q_DU_D\000"
  /* 5279 */ "XVADDWEV_Q_DU_D\000"
  /* 5295 */ "XVMULWEV_Q_DU_D\000"
  /* 5311 */ "XVFTINT_LU_D\000"
  /* 5324 */ "XVFTINTRZ_LU_D\000"
  /* 5339 */ "XVSSRANI_WU_D\000"
  /* 5353 */ "XVSSRLNI_WU_D\000"
  /* 5367 */ "XVSSRARNI_WU_D\000"
  /* 5382 */ "XVSSRLRNI_WU_D\000"
  /* 5397 */ "XVSSRAN_WU_D\000"
  /* 5410 */ "XVSSRLN_WU_D\000"
  /* 5423 */ "XVSSRARN_WU_D\000"
  /* 5437 */ "XVSSRLRN_WU_D\000"
  /* 5451 */ "XVPACKEV_D\000"
  /* 5462 */ "XVPICKEV_D\000"
  /* 5473 */ "XVBITREV_D\000"
  /* 5484 */ "XVFDIV_D\000"
  /* 5493 */ "XVDIV_D\000"
  /* 5501 */ "XVSIGNCOV_D\000"
  /* 5513 */ "FMOV_D\000"
  /* 5520 */ "ARMMOV_D\000"
  /* 5529 */ "XVFTINTRNE_W_D\000"
  /* 5544 */ "XVSSRANI_W_D\000"
  /* 5557 */ "XVSRANI_W_D\000"
  /* 5569 */ "XVSSRLNI_W_D\000"
  /* 5582 */ "XVSRLNI_W_D\000"
  /* 5594 */ "XVSSRARNI_W_D\000"
  /* 5608 */ "XVSRARNI_W_D\000"
  /* 5621 */ "XVSSRLRNI_W_D\000"
  /* 5635 */ "XVSRLRNI_W_D\000"
  /* 5648 */ "XVFTINTRM_W_D\000"
  /* 5662 */ "XVSSRAN_W_D\000"
  /* 5674 */ "XVSRAN_W_D\000"
  /* 5685 */ "XVSSRLN_W_D\000"
  /* 5697 */ "XVSRLN_W_D\000"
  /* 5708 */ "XVSSRARN_W_D\000"
  /* 5721 */ "XVSRARN_W_D\000"
  /* 5733 */ "XVSSRLRN_W_D\000"
  /* 5746 */ "XVSRLRN_W_D\000"
  /* 5758 */ "XVFTINTRP_W_D\000"
  /* 5772 */ "XVFTINT_W_D\000"
  /* 5784 */ "XVFTINTRZ_W_D\000"
  /* 5798 */ "XVFMAX_D\000"
  /* 5807 */ "AMMAX_D\000"
  /* 5815 */ "XVMAX_D\000"
  /* 5823 */ "FLDX_D\000"
  /* 5830 */ "FSTX_D\000"
  /* 5837 */ "PseudoXVBZ_D\000"
  /* 5850 */ "PseudoVBZ_D\000"
  /* 5862 */ "XVSETALLNEZ_D\000"
  /* 5876 */ "XVCLZ_D\000"
  /* 5884 */ "PseudoXVBNZ_D\000"
  /* 5898 */ "PseudoVBNZ_D\000"
  /* 5911 */ "XVSETANYEQZ_D\000"
  /* 5925 */ "XVFRINTRZ_D\000"
  /* 5937 */ "CTZ_D\000"
  /* 5943 */ "PseudoXVMSKLTZ_D\000"
  /* 5960 */ "PseudoVMSKLTZ_D\000"
  /* 5976 */ "PseudoAddTPRel_D\000"
  /* 5993 */ "PseudoAtomicStoreD\000"
  /* 6012 */ "FSEL_xD\000"
  /* 6020 */ "PSEUDO_PROBE\000"
  /* 6033 */ "G_SSUBE\000"
  /* 6041 */ "G_USUBE\000"
  /* 6049 */ "G_FENCE\000"
  /* 6057 */ "ARITH_FENCE\000"
  /* 6069 */ "REG_SEQUENCE\000"
  /* 6082 */ "G_SADDE\000"
  /* 6090 */ "G_UADDE\000"
  /* 6098 */ "G_GET_FPMODE\000"
  /* 6111 */ "G_RESET_FPMODE\000"
  /* 6126 */ "G_SET_FPMODE\000"
  /* 6139 */ "G_FMINNUM_IEEE\000"
  /* 6154 */ "G_FMAXNUM_IEEE\000"
  /* 6169 */ "BGE\000"
  /* 6173 */ "PseudoLA_TLS_DESC_LARGE\000"
  /* 6197 */ "PseudoLA_TLS_GD_LARGE\000"
  /* 6219 */ "PseudoLA_TLS_LD_LARGE\000"
  /* 6241 */ "PseudoLA_TLS_IE_LARGE\000"
  /* 6263 */ "PseudoLA_PCREL_LARGE\000"
  /* 6284 */ "PseudoTAIL_LARGE\000"
  /* 6301 */ "PseudoCALL_LARGE\000"
  /* 6318 */ "PseudoLA_ABS_LARGE\000"
  /* 6337 */ "PseudoLA_GOT_LARGE\000"
  /* 6356 */ "PseudoLA_TLS_IE\000"
  /* 6372 */ "G_VSCALE\000"
  /* 6381 */ "G_JUMP_TABLE\000"
  /* 6394 */ "IDLE\000"
  /* 6399 */ "BUNDLE\000"
  /* 6406 */ "PseudoLA_TLS_LE\000"
  /* 6422 */ "BNE\000"
  /* 6426 */ "G_MEMSET_INLINE\000"
  /* 6442 */ "G_MEMCPY_INLINE\000"
  /* 6458 */ "RELOC_NONE\000"
  /* 6469 */ "SETX86LOOPNE\000"
  /* 6482 */ "LOCAL_ESCAPE\000"
  /* 6495 */ "SETX86LOOPE\000"
  /* 6507 */ "G_FPTRUNCSTORE\000"
  /* 6522 */ "G_STACKRESTORE\000"
  /* 6537 */ "G_INDEXED_STORE\000"
  /* 6553 */ "G_STORE\000"
  /* 6561 */ "SET_CFR_FALSE\000"
  /* 6575 */ "G_BITREVERSE\000"
  /* 6588 */ "FAKE_USE\000"
  /* 6597 */ "LDPTE\000"
  /* 6603 */ "DBG_VALUE\000"
  /* 6613 */ "G_GLOBAL_VALUE\000"
  /* 6628 */ "G_PTRAUTH_GLOBAL_VALUE\000"
  /* 6651 */ "CONVERGENCECTRL_GLUE\000"
  /* 6672 */ "SET_CFR_TRUE\000"
  /* 6685 */ "G_STACKSAVE\000"
  /* 6697 */ "G_MEMMOVE\000"
  /* 6707 */ "ARMMOVE\000"
  /* 6715 */ "G_FREEZE\000"
  /* 6724 */ "G_FCANONICALIZE\000"
  /* 6740 */ "MOVGR2CF\000"
  /* 6749 */ "G_FMODF\000"
  /* 6757 */ "INIT_UNDEF\000"
  /* 6768 */ "G_IMPLICIT_DEF\000"
  /* 6783 */ "DBG_INSTR_REF\000"
  /* 6797 */ "X86MFFLAG\000"
  /* 6807 */ "ARMMFFLAG\000"
  /* 6817 */ "X86MTFLAG\000"
  /* 6827 */ "ARMMTFLAG\000"
  /* 6837 */ "X86SETTAG\000"
  /* 6847 */ "G_FNEG\000"
  /* 6854 */ "EXTRACT_SUBREG\000"
  /* 6869 */ "INSERT_SUBREG\000"
  /* 6883 */ "G_SEXT_INREG\000"
  /* 6896 */ "SUBREG_TO_REG\000"
  /* 6910 */ "CPUCFG\000"
  /* 6917 */ "G_ATOMIC_CMPXCHG\000"
  /* 6934 */ "GCSRXCHG\000"
  /* 6943 */ "G_ATOMICRMW_XCHG\000"
  /* 6960 */ "G_GET_ROUNDING\000"
  /* 6975 */ "G_SET_ROUNDING\000"
  /* 6990 */ "G_FLOG\000"
  /* 6997 */ "G_VAARG\000"
  /* 7005 */ "PREALLOCATED_ARG\000"
  /* 7022 */ "REVB_2H\000"
  /* 7030 */ "REVB_4H\000"
  /* 7038 */ "TLBSRCH\000"
  /* 7046 */ "G_PREFETCH\000"
  /* 7057 */ "G_SMULH\000"
  /* 7065 */ "G_UMULH\000"
  /* 7073 */ "G_FTANH\000"
  /* 7081 */ "G_FSINH\000"
  /* 7089 */ "G_FCOSH\000"
  /* 7097 */ "GTLBFLUSH\000"
  /* 7107 */ "XVREPLVE0_H\000"
  /* 7119 */ "XVADDA_H\000"
  /* 7128 */ "X86SRA_H\000"
  /* 7137 */ "XVSRA_H\000"
  /* 7145 */ "AMADD__DB_H\000"
  /* 7157 */ "AMSWAP__DB_H\000"
  /* 7170 */ "AMCAS__DB_H\000"
  /* 7182 */ "X86SUB_H\000"
  /* 7191 */ "XVMSUB_H\000"
  /* 7200 */ "XVSSUB_H\000"
  /* 7209 */ "XVSUB_H\000"
  /* 7217 */ "XVSSRANI_B_H\000"
  /* 7230 */ "XVSRANI_B_H\000"
  /* 7242 */ "XVSSRLNI_B_H\000"
  /* 7255 */ "XVSRLNI_B_H\000"
  /* 7267 */ "XVSSRARNI_B_H\000"
  /* 7281 */ "XVSRARNI_B_H\000"
  /* 7294 */ "XVSSRLRNI_B_H\000"
  /* 7308 */ "XVSRLRNI_B_H\000"
  /* 7321 */ "XVSSRAN_B_H\000"
  /* 7333 */ "XVSRAN_B_H\000"
  /* 7344 */ "XVSSRLN_B_H\000"
  /* 7356 */ "XVSRLN_B_H\000"
  /* 7367 */ "XVSSRARN_B_H\000"
  /* 7380 */ "XVSRARN_B_H\000"
  /* 7392 */ "XVSSRLRN_B_H\000"
  /* 7405 */ "XVSRLRN_B_H\000"
  /* 7417 */ "X86SBC_H\000"
  /* 7426 */ "X86ADC_H\000"
  /* 7435 */ "X86DEC_H\000"
  /* 7444 */ "X86INC_H\000"
  /* 7453 */ "X86ADD_H\000"
  /* 7462 */ "AMADD_H\000"
  /* 7470 */ "XVMADD_H\000"
  /* 7479 */ "XVSADD_H\000"
  /* 7488 */ "XVADD_H\000"
  /* 7496 */ "LD_H\000"
  /* 7501 */ "X86AND_H\000"
  /* 7510 */ "XVPACKOD_H\000"
  /* 7521 */ "XVPICKOD_H\000"
  /* 7532 */ "XVMOD_H\000"
  /* 7540 */ "IOCSRRD_H\000"
  /* 7550 */ "XVABSD_H\000"
  /* 7559 */ "VEXT2XV_D_H\000"
  /* 7571 */ "LDLE_H\000"
  /* 7578 */ "XVSLE_H\000"
  /* 7586 */ "STLE_H\000"
  /* 7593 */ "XVREPLVE_H\000"
  /* 7604 */ "XVSHUF_H\000"
  /* 7613 */ "XVNEG_H\000"
  /* 7621 */ "XVAVG_H\000"
  /* 7629 */ "XVMUH_H\000"
  /* 7637 */ "XVILVH_H\000"
  /* 7646 */ "XVSHUF4I_H\000"
  /* 7657 */ "X86SRAI_H\000"
  /* 7667 */ "XVSRAI_H\000"
  /* 7676 */ "XVSLEI_H\000"
  /* 7685 */ "XVREPL128VEI_H\000"
  /* 7700 */ "VREPLVEI_H\000"
  /* 7711 */ "X86RCLI_H\000"
  /* 7721 */ "X86SLLI_H\000"
  /* 7731 */ "XVSLLI_H\000"
  /* 7740 */ "PseudoXVREPLI_H\000"
  /* 7756 */ "PseudoVREPLI_H\000"
  /* 7771 */ "X86SRLI_H\000"
  /* 7781 */ "XVSRLI_H\000"
  /* 7790 */ "X86ROTLI_H\000"
  /* 7801 */ "XVMINI_H\000"
  /* 7810 */ "XVFRSTPI_H\000"
  /* 7821 */ "XVSEQI_H\000"
  /* 7830 */ "XVSRARI_H\000"
  /* 7840 */ "X86RCRI_H\000"
  /* 7850 */ "XVBITCLRI_H\000"
  /* 7862 */ "XVSRLRI_H\000"
  /* 7872 */ "X86ROTRI_H\000"
  /* 7883 */ "XVROTRI_H\000"
  /* 7893 */ "XVBITSETI_H\000"
  /* 7905 */ "XVSLTI_H\000"
  /* 7914 */ "XVBITREVI_H\000"
  /* 7926 */ "XVMAXI_H\000"
  /* 7935 */ "X86RCL_H\000"
  /* 7944 */ "X86SLL_H\000"
  /* 7953 */ "XVSLL_H\000"
  /* 7961 */ "XVLDREPL_H\000"
  /* 7972 */ "X86SRL_H\000"
  /* 7981 */ "XVSRL_H\000"
  /* 7989 */ "X86ROTL_H\000"
  /* 7999 */ "X86MUL_H\000"
  /* 8008 */ "XVMUL_H\000"
  /* 8016 */ "XVILVL_H\000"
  /* 8025 */ "XVSTELM_H\000"
  /* 8035 */ "XVMIN_H\000"
  /* 8043 */ "XVCLO_H\000"
  /* 8051 */ "AMSWAP_H\000"
  /* 8060 */ "PseudoCTPOP_H\000"
  /* 8074 */ "XVFRSTP_H\000"
  /* 8084 */ "XVSEQ_H\000"
  /* 8092 */ "XVSRAR_H\000"
  /* 8101 */ "X86RCR_H\000"
  /* 8110 */ "VPICKVE2GR_H\000"
  /* 8123 */ "XVAVGR_H\000"
  /* 8132 */ "XVBITCLR_H\000"
  /* 8143 */ "XVSRLR_H\000"
  /* 8152 */ "X86OR_H\000"
  /* 8160 */ "X86XOR_H\000"
  /* 8169 */ "X86ROTR_H\000"
  /* 8179 */ "XVROTR_H\000"
  /* 8188 */ "XVREPLGR2VR_H\000"
  /* 8202 */ "PseudoXVINSGR2VR_H\000"
  /* 8221 */ "IOCSRWR_H\000"
  /* 8231 */ "AMCAS_H\000"
  /* 8239 */ "XVEXTRINS_H\000"
  /* 8251 */ "XVFCVTH_S_H\000"
  /* 8263 */ "XVFCVTL_S_H\000"
  /* 8275 */ "XVSAT_H\000"
  /* 8283 */ "XVBITSET_H\000"
  /* 8294 */ "LDGT_H\000"
  /* 8301 */ "STGT_H\000"
  /* 8308 */ "XVSLT_H\000"
  /* 8316 */ "XVPCNT_H\000"
  /* 8325 */ "ST_H\000"
  /* 8330 */ "XVSSRANI_BU_H\000"
  /* 8344 */ "XVSSRLNI_BU_H\000"
  /* 8358 */ "XVSSRARNI_BU_H\000"
  /* 8373 */ "XVSSRLRNI_BU_H\000"
  /* 8388 */ "XVSSRAN_BU_H\000"
  /* 8401 */ "XVSSRLN_BU_H\000"
  /* 8414 */ "XVSSRARN_BU_H\000"
  /* 8428 */ "XVSSRLRN_BU_H\000"
  /* 8442 */ "XVMADDWOD_W_HU_H\000"
  /* 8459 */ "XVADDWOD_W_HU_H\000"
  /* 8475 */ "XVMULWOD_W_HU_H\000"
  /* 8491 */ "XVMADDWEV_W_HU_H\000"
  /* 8508 */ "XVADDWEV_W_HU_H\000"
  /* 8524 */ "XVMULWEV_W_HU_H\000"
  /* 8540 */ "XVPACKEV_H\000"
  /* 8551 */ "XVPICKEV_H\000"
  /* 8562 */ "XVBITREV_H\000"
  /* 8573 */ "XVDIV_H\000"
  /* 8581 */ "XVSIGNCOV_H\000"
  /* 8593 */ "XVSUBWOD_W_H\000"
  /* 8606 */ "XVMADDWOD_W_H\000"
  /* 8620 */ "XVADDWOD_W_H\000"
  /* 8633 */ "XVMULWOD_W_H\000"
  /* 8646 */ "XVEXTH_W_H\000"
  /* 8657 */ "XVSLLWIL_W_H\000"
  /* 8670 */ "EXT_W_H\000"
  /* 8678 */ "XVSUBWEV_W_H\000"
  /* 8691 */ "XVMADDWEV_W_H\000"
  /* 8705 */ "XVADDWEV_W_H\000"
  /* 8718 */ "XVMULWEV_W_H\000"
  /* 8731 */ "VEXT2XV_W_H\000"
  /* 8743 */ "XVHSUBW_W_H\000"
  /* 8755 */ "XVHADDW_W_H\000"
  /* 8767 */ "XVMAX_H\000"
  /* 8775 */ "LDX_H\000"
  /* 8781 */ "STX_H\000"
  /* 8787 */ "PseudoXVBZ_H\000"
  /* 8800 */ "PseudoVBZ_H\000"
  /* 8812 */ "XVSETALLNEZ_H\000"
  /* 8826 */ "XVCLZ_H\000"
  /* 8834 */ "PseudoXVBNZ_H\000"
  /* 8848 */ "PseudoVBNZ_H\000"
  /* 8861 */ "XVSETANYEQZ_H\000"
  /* 8875 */ "PseudoXVMSKLTZ_H\000"
  /* 8892 */ "PseudoVMSKLTZ_H\000"
  /* 8908 */ "PCALAU12I\000"
  /* 8918 */ "PCADDU12I\000"
  /* 8928 */ "PCADDU18I\000"
  /* 8938 */ "PCADDI\000"
  /* 8945 */ "XVLDI\000"
  /* 8951 */ "ANDI\000"
  /* 8956 */ "DBG_PHI\000"
  /* 8964 */ "XORI\000"
  /* 8969 */ "G_FPTOSI\000"
  /* 8978 */ "SLTI\000"
  /* 8983 */ "G_FPTOUI\000"
  /* 8992 */ "SLTUI\000"
  /* 8998 */ "G_FPOWI\000"
  /* 9006 */ "SETX86J\000"
  /* 9014 */ "SETARMJ\000"
  /* 9022 */ "BREAK\000"
  /* 9028 */ "COPY_LANEMASK\000"
  /* 9042 */ "G_PTRMASK\000"
  /* 9052 */ "BL\000"
  /* 9055 */ "DBCL\000"
  /* 9060 */ "HVCL\000"
  /* 9065 */ "GC_LABEL\000"
  /* 9074 */ "DBG_LABEL\000"
  /* 9084 */ "EH_LABEL\000"
  /* 9093 */ "ANNOTATION_LABEL\000"
  /* 9110 */ "ICALL_BRANCH_FUNNEL\000"
  /* 9130 */ "PseudoLA_PCREL\000"
  /* 9145 */ "G_FSHL\000"
  /* 9152 */ "G_SHL\000"
  /* 9158 */ "PseudoB_TAIL\000"
  /* 9171 */ "PseudoJIRL_TAIL\000"
  /* 9187 */ "PseudoTAIL\000"
  /* 9198 */ "G_FCEIL\000"
  /* 9206 */ "G_SAVGCEIL\000"
  /* 9217 */ "G_UAVGCEIL\000"
  /* 9228 */ "SYSCALL\000"
  /* 9236 */ "PseudoDESC_CALL\000"
  /* 9252 */ "PATCHABLE_TAIL_CALL\000"
  /* 9272 */ "PseudoJIRL_CALL\000"
  /* 9288 */ "PATCHABLE_TYPED_EVENT_CALL\000"
  /* 9315 */ "PATCHABLE_EVENT_CALL\000"
  /* 9336 */ "FENTRY_CALL\000"
  /* 9348 */ "PseudoCALL\000"
  /* 9359 */ "PseudoTAIL_SMALL\000"
  /* 9376 */ "PseudoCALL_SMALL\000"
  /* 9393 */ "TLBFILL\000"
  /* 9401 */ "KILL\000"
  /* 9406 */ "G_CONSTANT_POOL\000"
  /* 9422 */ "JIRL\000"
  /* 9427 */ "G_ROTL\000"
  /* 9434 */ "G_VECREDUCE_FMUL\000"
  /* 9451 */ "G_FMUL\000"
  /* 9458 */ "G_VECREDUCE_SEQ_FMUL\000"
  /* 9479 */ "G_STRICT_FMUL\000"
  /* 9493 */ "G_CLMUL\000"
  /* 9501 */ "G_VECREDUCE_MUL\000"
  /* 9517 */ "G_MUL\000"
  /* 9523 */ "XVFFINT_D_L\000"
  /* 9535 */ "XVFFINT_S_L\000"
  /* 9547 */ "G_FREM\000"
  /* 9554 */ "G_STRICT_FREM\000"
  /* 9568 */ "G_SREM\000"
  /* 9575 */ "G_UREM\000"
  /* 9582 */ "G_SDIVREM\000"
  /* 9592 */ "G_UDIVREM\000"
  /* 9602 */ "INLINEASM\000"
  /* 9612 */ "X86CLRTM\000"
  /* 9621 */ "X86SETTM\000"
  /* 9630 */ "PseudoTAIL_MEDIUM\000"
  /* 9648 */ "PseudoCALL_MEDIUM\000"
  /* 9666 */ "G_VECREDUCE_FMINIMUM\000"
  /* 9687 */ "G_FMINIMUM\000"
  /* 9698 */ "G_ATOMICRMW_FMINIMUM\000"
  /* 9719 */ "G_VECREDUCE_FMAXIMUM\000"
  /* 9740 */ "G_FMAXIMUM\000"
  /* 9751 */ "G_ATOMICRMW_FMAXIMUM\000"
  /* 9772 */ "G_FMINIMUMNUM\000"
  /* 9786 */ "G_ATOMICRMW_FMINIMUMNUM\000"
  /* 9810 */ "G_FMAXIMUMNUM\000"
  /* 9824 */ "G_ATOMICRMW_FMAXIMUMNUM\000"
  /* 9848 */ "G_FMINNUM\000"
  /* 9858 */ "G_FMAXNUM\000"
  /* 9868 */ "G_FATAN\000"
  /* 9876 */ "G_FTAN\000"
  /* 9883 */ "ANDN\000"
  /* 9888 */ "G_INTRINSIC_ROUNDEVEN\000"
  /* 9910 */ "G_ASSERT_ALIGN\000"
  /* 9925 */ "G_FCOPYSIGN\000"
  /* 9937 */ "G_VECREDUCE_FMIN\000"
  /* 9954 */ "G_ATOMICRMW_FMIN\000"
  /* 9971 */ "G_VECREDUCE_SMIN\000"
  /* 9988 */ "G_SMIN\000"
  /* 9995 */ "G_VECREDUCE_UMIN\000"
  /* 10012 */ "G_UMIN\000"
  /* 10019 */ "G_ATOMICRMW_UMIN\000"
  /* 10036 */ "G_ATOMICRMW_MIN\000"
  /* 10052 */ "G_FASIN\000"
  /* 10060 */ "G_FSIN\000"
  /* 10067 */ "CFI_INSTRUCTION\000"
  /* 10083 */ "G_CTLZ_ZERO_POISON\000"
  /* 10102 */ "G_CTTZ_ZERO_POISON\000"
  /* 10121 */ "ORN\000"
  /* 10125 */ "ERTN\000"
  /* 10130 */ "ADJCALLSTACKDOWN\000"
  /* 10147 */ "PROBED_STACKALLOC_DYN\000"
  /* 10169 */ "G_SSUBO\000"
  /* 10177 */ "G_USUBO\000"
  /* 10185 */ "G_SADDO\000"
  /* 10193 */ "G_UADDO\000"
  /* 10201 */ "JUMP_TABLE_DEBUG_INFO\000"
  /* 10223 */ "G_SMULO\000"
  /* 10231 */ "G_UMULO\000"
  /* 10239 */ "G_BZERO\000"
  /* 10247 */ "STACKMAP\000"
  /* 10256 */ "G_DEBUGTRAP\000"
  /* 10268 */ "G_UBSANTRAP\000"
  /* 10280 */ "G_TRAP\000"
  /* 10287 */ "G_ATOMICRMW_UDEC_WRAP\000"
  /* 10309 */ "G_ATOMICRMW_UINC_WRAP\000"
  /* 10331 */ "G_BSWAP\000"
  /* 10339 */ "G_SITOFP\000"
  /* 10348 */ "G_UITOFP\000"
  /* 10357 */ "G_FCMP\000"
  /* 10364 */ "G_STRICT_FCMP\000"
  /* 10378 */ "G_ICMP\000"
  /* 10385 */ "G_SCMP\000"
  /* 10392 */ "G_UCMP\000"
  /* 10399 */ "PseudoUNIMP\000"
  /* 10411 */ "CACOP\000"
  /* 10417 */ "CONVERGENCECTRL_LOOP\000"
  /* 10438 */ "G_CTPOP\000"
  /* 10446 */ "X86DECTOP\000"
  /* 10456 */ "X86INCTOP\000"
  /* 10466 */ "X86MFTOP\000"
  /* 10475 */ "X86MTTOP\000"
  /* 10484 */ "PATCHABLE_OP\000"
  /* 10497 */ "FAULTING_OP\000"
  /* 10509 */ "ADJCALLSTACKUP\000"
  /* 10524 */ "PREALLOCATED_SETUP\000"
  /* 10543 */ "G_FLDEXP\000"
  /* 10552 */ "G_STRICT_FLDEXP\000"
  /* 10568 */ "G_FEXP\000"
  /* 10575 */ "G_FFREXP\000"
  /* 10584 */ "BEQ\000"
  /* 10588 */ "XVREPLVE0_Q\000"
  /* 10600 */ "XVSUB_Q\000"
  /* 10608 */ "SC_Q\000"
  /* 10613 */ "XVADD_Q\000"
  /* 10621 */ "XVSSRANI_D_Q\000"
  /* 10634 */ "XVSRANI_D_Q\000"
  /* 10646 */ "XVSSRLNI_D_Q\000"
  /* 10659 */ "XVSRLNI_D_Q\000"
  /* 10671 */ "XVSSRARNI_D_Q\000"
  /* 10685 */ "XVSRARNI_D_Q\000"
  /* 10698 */ "XVSSRLRNI_D_Q\000"
  /* 10712 */ "XVSRLRNI_D_Q\000"
  /* 10725 */ "XVPERMI_Q\000"
  /* 10735 */ "XVSSRANI_DU_Q\000"
  /* 10749 */ "XVSSRLNI_DU_Q\000"
  /* 10763 */ "XVSSRARNI_DU_Q\000"
  /* 10778 */ "XVSSRLRNI_DU_Q\000"
  /* 10793 */ "DBAR\000"
  /* 10798 */ "IBAR\000"
  /* 10803 */ "G_BR\000"
  /* 10808 */ "INLINEASM_BR\000"
  /* 10821 */ "PseudoBR\000"
  /* 10830 */ "MOVGR2SCR\000"
  /* 10840 */ "G_BLOCK_ADDR\000"
  /* 10853 */ "MEMBARRIER\000"
  /* 10864 */ "G_CONSTANT_FOLD_BARRIER\000"
  /* 10888 */ "PATCHABLE_FUNCTION_ENTER\000"
  /* 10913 */ "G_READCYCLECOUNTER\000"
  /* 10932 */ "G_READSTEADYCOUNTER\000"
  /* 10952 */ "G_READ_REGISTER\000"
  /* 10968 */ "G_WRITE_REGISTER\000"
  /* 10985 */ "PseudoLD_CFR\000"
  /* 10998 */ "PseudoST_CFR\000"
  /* 11011 */ "PseudoCopyCFR\000"
  /* 11025 */ "MOVCF2GR\000"
  /* 11034 */ "MOVSCR2GR\000"
  /* 11044 */ "MOVFCSR2GR\000"
  /* 11055 */ "G_ASHR\000"
  /* 11062 */ "G_FSHR\000"
  /* 11069 */ "G_LSHR\000"
  /* 11076 */ "LDDIR\000"
  /* 11082 */ "TLBCLR\000"
  /* 11089 */ "CONVERGENCECTRL_ANCHOR\000"
  /* 11112 */ "NOR\000"
  /* 11116 */ "G_FFLOOR\000"
  /* 11125 */ "G_SAVGFLOOR\000"
  /* 11137 */ "G_UAVGFLOOR\000"
  /* 11149 */ "G_EXTRACT_SUBVECTOR\000"
  /* 11169 */ "G_INSERT_SUBVECTOR\000"
  /* 11188 */ "G_BUILD_VECTOR\000"
  /* 11203 */ "G_SHUFFLE_VECTOR\000"
  /* 11220 */ "G_STEP_VECTOR\000"
  /* 11234 */ "G_SPLAT_VECTOR\000"
  /* 11249 */ "G_VECREDUCE_XOR\000"
  /* 11265 */ "G_XOR\000"
  /* 11271 */ "G_ATOMICRMW_XOR\000"
  /* 11287 */ "G_VECREDUCE_OR\000"
  /* 11302 */ "G_OR\000"
  /* 11307 */ "G_ATOMICRMW_OR\000"
  /* 11322 */ "Select_GPR_Using_CC_GPR\000"
  /* 11346 */ "MOVGR2FCSR\000"
  /* 11357 */ "RDFCSR\000"
  /* 11364 */ "WRFCSR\000"
  /* 11371 */ "G_ROTR\000"
  /* 11378 */ "G_INTTOPTR\000"
  /* 11389 */ "TLBWR\000"
  /* 11395 */ "GCSRWR\000"
  /* 11402 */ "G_FABS\000"
  /* 11409 */ "PseudoLA_ABS\000"
  /* 11422 */ "G_ABS\000"
  /* 11428 */ "G_ABDS\000"
  /* 11435 */ "G_UNMERGE_VALUES\000"
  /* 11452 */ "G_MERGE_VALUES\000"
  /* 11467 */ "G_CTLS\000"
  /* 11474 */ "G_FACOS\000"
  /* 11482 */ "G_FCOS\000"
  /* 11489 */ "G_FSINCOS\000"
  /* 11499 */ "G_STRICT_FCMPS\000"
  /* 11514 */ "G_CONCAT_VECTORS\000"
  /* 11531 */ "COPY_TO_REGCLASS\000"
  /* 11548 */ "G_IS_FPCLASS\000"
  /* 11561 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\000"
  /* 11591 */ "G_VECTOR_COMPRESS\000"
  /* 11609 */ "G_INTRINSIC_W_SIDE_EFFECTS\000"
  /* 11636 */ "G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS\000"
  /* 11674 */ "XVFMINA_S\000"
  /* 11684 */ "XVFMAXA_S\000"
  /* 11694 */ "FSCALEB_S\000"
  /* 11704 */ "XVFLOGB_S\000"
  /* 11714 */ "XVFSUB_S\000"
  /* 11723 */ "XVFMSUB_S\000"
  /* 11733 */ "XVFNMSUB_S\000"
  /* 11744 */ "XVFADD_S\000"
  /* 11753 */ "XVFMADD_S\000"
  /* 11763 */ "XVFNMADD_S\000"
  /* 11774 */ "FLD_S\000"
  /* 11780 */ "XVFCVTH_D_S\000"
  /* 11792 */ "XVFCVTL_D_S\000"
  /* 11804 */ "FCVT_D_S\000"
  /* 11813 */ "XVFCMP_CLE_S\000"
  /* 11826 */ "FLDLE_S\000"
  /* 11834 */ "XVFCMP_SLE_S\000"
  /* 11847 */ "FSTLE_S\000"
  /* 11855 */ "XVFCMP_CULE_S\000"
  /* 11869 */ "XVFCMP_SULE_S\000"
  /* 11883 */ "XVFCMP_CNE_S\000"
  /* 11896 */ "XVFRINTRNE_S\000"
  /* 11909 */ "XVFCMP_SNE_S\000"
  /* 11922 */ "XVFCMP_CUNE_S\000"
  /* 11936 */ "XVFCMP_SUNE_S\000"
  /* 11950 */ "XVFRECIPE_S\000"
  /* 11962 */ "XVFRSQRTE_S\000"
  /* 11974 */ "XVFCMP_CAF_S\000"
  /* 11987 */ "XVFCMP_SAF_S\000"
  /* 12000 */ "FNEG_S\000"
  /* 12007 */ "XVFCVT_H_S\000"
  /* 12018 */ "XVFMUL_S\000"
  /* 12027 */ "FTINTRNE_L_S\000"
  /* 12040 */ "XVFTINTRNEH_L_S\000"
  /* 12056 */ "XVFTINTRMH_L_S\000"
  /* 12071 */ "XVFTINTRPH_L_S\000"
  /* 12086 */ "XVFTINTH_L_S\000"
  /* 12099 */ "XVFTINTRZH_L_S\000"
  /* 12114 */ "XVFTINTRNEL_L_S\000"
  /* 12130 */ "XVFTINTRML_L_S\000"
  /* 12145 */ "XVFTINTRPL_L_S\000"
  /* 12160 */ "XVFTINTL_L_S\000"
  /* 12173 */ "XVFTINTRZL_L_S\000"
  /* 12188 */ "FTINTRM_L_S\000"
  /* 12200 */ "FTINTRP_L_S\000"
  /* 12212 */ "FTINT_L_S\000"
  /* 12222 */ "FTINTRZ_L_S\000"
  /* 12234 */ "XVFRINTRM_S\000"
  /* 12246 */ "FCOPYSIGN_S\000"
  /* 12258 */ "XVFMIN_S\000"
  /* 12267 */ "XVFCMP_CUN_S\000"
  /* 12280 */ "XVFCMP_SUN_S\000"
  /* 12293 */ "XVFRECIP_S\000"
  /* 12304 */ "XVFRINTRP_S\000"
  /* 12316 */ "XVFCMP_CEQ_S\000"
  /* 12329 */ "XVFCMP_SEQ_S\000"
  /* 12342 */ "XVFCMP_CUEQ_S\000"
  /* 12356 */ "XVFCMP_SUEQ_S\000"
  /* 12370 */ "MOVFRH2GR_S\000"
  /* 12382 */ "MOVFR2GR_S\000"
  /* 12393 */ "XVFCMP_COR_S\000"
  /* 12406 */ "XVFCMP_SOR_S\000"
  /* 12419 */ "FABS_S\000"
  /* 12426 */ "XVFCLASS_S\000"
  /* 12437 */ "G_TRUNC_SSAT_S\000"
  /* 12452 */ "FLDGT_S\000"
  /* 12460 */ "FSTGT_S\000"
  /* 12468 */ "XVFCMP_CLT_S\000"
  /* 12481 */ "XVFCMP_SLT_S\000"
  /* 12494 */ "XVFCMP_CULT_S\000"
  /* 12508 */ "XVFCMP_SULT_S\000"
  /* 12522 */ "XVFRINT_S\000"
  /* 12532 */ "XVFSQRT_S\000"
  /* 12542 */ "XVFRSQRT_S\000"
  /* 12553 */ "FST_S\000"
  /* 12559 */ "XVFTINT_WU_S\000"
  /* 12572 */ "XVFTINTRZ_WU_S\000"
  /* 12587 */ "XVFDIV_S\000"
  /* 12596 */ "FMOV_S\000"
  /* 12603 */ "XVFTINTRNE_W_S\000"
  /* 12618 */ "XVFTINTRM_W_S\000"
  /* 12632 */ "XVFTINTRP_W_S\000"
  /* 12646 */ "XVFTINT_W_S\000"
  /* 12658 */ "XVFTINTRZ_W_S\000"
  /* 12672 */ "XVFMAX_S\000"
  /* 12681 */ "FLDX_S\000"
  /* 12688 */ "FSTX_S\000"
  /* 12695 */ "XVFRINTRZ_S\000"
  /* 12707 */ "MOVFR2CF_xS\000"
  /* 12719 */ "FSEL_xS\000"
  /* 12727 */ "MOVCF2FR_xS\000"
  /* 12739 */ "G_SSUBSAT\000"
  /* 12749 */ "G_USUBSAT\000"
  /* 12759 */ "G_SADDSAT\000"
  /* 12769 */ "G_UADDSAT\000"
  /* 12779 */ "G_SSHLSAT\000"
  /* 12789 */ "G_USHLSAT\000"
  /* 12799 */ "G_SMULFIXSAT\000"
  /* 12812 */ "G_UMULFIXSAT\000"
  /* 12825 */ "G_SDIVFIXSAT\000"
  /* 12838 */ "G_UDIVFIXSAT\000"
  /* 12851 */ "G_ATOMICRMW_USUB_SAT\000"
  /* 12872 */ "G_FPTOSI_SAT\000"
  /* 12885 */ "G_FPTOUI_SAT\000"
  /* 12898 */ "G_EXTRACT\000"
  /* 12908 */ "G_SELECT\000"
  /* 12917 */ "G_BRINDIRECT\000"
  /* 12930 */ "PATCHABLE_RET\000"
  /* 12944 */ "PseudoRET\000"
  /* 12954 */ "G_MEMSET\000"
  /* 12963 */ "PATCHABLE_FUNCTION_EXIT\000"
  /* 12987 */ "G_BRJT\000"
  /* 12994 */ "BLT\000"
  /* 12998 */ "G_EXTRACT_VECTOR_ELT\000"
  /* 13019 */ "G_INSERT_VECTOR_ELT\000"
  /* 13039 */ "SLT\000"
  /* 13043 */ "G_FCONSTANT\000"
  /* 13055 */ "G_CONSTANT\000"
  /* 13066 */ "G_INTRINSIC_CONVERGENT\000"
  /* 13089 */ "STATEPOINT\000"
  /* 13100 */ "PATCHPOINT\000"
  /* 13111 */ "G_PTRTOINT\000"
  /* 13122 */ "G_FRINT\000"
  /* 13130 */ "G_INTRINSIC_LLRINT\000"
  /* 13149 */ "G_INTRINSIC_LRINT\000"
  /* 13167 */ "G_FNEARBYINT\000"
  /* 13180 */ "PseudoLA_GOT\000"
  /* 13193 */ "G_VASTART\000"
  /* 13203 */ "LIFETIME_START\000"
  /* 13218 */ "G_INVOKE_REGION_START\000"
  /* 13240 */ "G_INSERT\000"
  /* 13249 */ "G_FSQRT\000"
  /* 13257 */ "G_STRICT_FSQRT\000"
  /* 13272 */ "G_BITCAST\000"
  /* 13282 */ "G_ADDRSPACE_CAST\000"
  /* 13299 */ "DBG_VALUE_LIST\000"
  /* 13314 */ "XVST\000"
  /* 13319 */ "G_FPEXT\000"
  /* 13327 */ "G_SEXT\000"
  /* 13334 */ "G_ASSERT_SEXT\000"
  /* 13348 */ "G_ANYEXT\000"
  /* 13357 */ "G_ZEXT\000"
  /* 13364 */ "G_ASSERT_ZEXT\000"
  /* 13378 */ "XVSSUB_BU\000"
  /* 13388 */ "XVSADD_BU\000"
  /* 13398 */ "LD_BU\000"
  /* 13404 */ "XVMOD_BU\000"
  /* 13413 */ "XVABSD_BU\000"
  /* 13423 */ "XVSLE_BU\000"
  /* 13432 */ "XVAVG_BU\000"
  /* 13441 */ "XVMUH_BU\000"
  /* 13450 */ "XVSUBWOD_H_BU\000"
  /* 13464 */ "XVMADDWOD_H_BU\000"
  /* 13479 */ "XVADDWOD_H_BU\000"
  /* 13493 */ "XVMULWOD_H_BU\000"
  /* 13507 */ "XVSUBWEV_H_BU\000"
  /* 13521 */ "XVMADDWEV_H_BU\000"
  /* 13536 */ "XVADDWEV_H_BU\000"
  /* 13550 */ "XVMULWEV_H_BU\000"
  /* 13564 */ "XVSUBI_BU\000"
  /* 13574 */ "XVADDI_BU\000"
  /* 13584 */ "XVSLEI_BU\000"
  /* 13594 */ "XVMINI_BU\000"
  /* 13604 */ "XVSLTI_BU\000"
  /* 13614 */ "XVMAXI_BU\000"
  /* 13624 */ "X86MUL_BU\000"
  /* 13634 */ "XVMIN_BU\000"
  /* 13643 */ "VPICKVE2GR_BU\000"
  /* 13657 */ "XVAVGR_BU\000"
  /* 13667 */ "XVSAT_BU\000"
  /* 13676 */ "XVSLT_BU\000"
  /* 13685 */ "VEXT2XV_DU_BU\000"
  /* 13699 */ "XVEXTH_HU_BU\000"
  /* 13712 */ "XVSLLWIL_HU_BU\000"
  /* 13727 */ "VEXT2XV_HU_BU\000"
  /* 13741 */ "XVHSUBW_HU_BU\000"
  /* 13755 */ "XVHADDW_HU_BU\000"
  /* 13769 */ "VEXT2XV_WU_BU\000"
  /* 13783 */ "XVDIV_BU\000"
  /* 13792 */ "XVMAX_BU\000"
  /* 13801 */ "LDX_BU\000"
  /* 13808 */ "G_ABDU\000"
  /* 13815 */ "AMMIN__DB_DU\000"
  /* 13828 */ "AMMAX__DB_DU\000"
  /* 13841 */ "X86SUB_DU\000"
  /* 13851 */ "XVSSUB_DU\000"
  /* 13861 */ "X86ADD_DU\000"
  /* 13871 */ "XVSADD_DU\000"
  /* 13881 */ "XVMOD_DU\000"
  /* 13890 */ "XVABSD_DU\000"
  /* 13900 */ "XVSLE_DU\000"
  /* 13909 */ "XVAVG_DU\000"
  /* 13918 */ "MULH_DU\000"
  /* 13926 */ "XVMUH_DU\000"
  /* 13935 */ "XVSUBI_DU\000"
  /* 13945 */ "XVADDI_DU\000"
  /* 13955 */ "XVSLEI_DU\000"
  /* 13965 */ "XVMINI_DU\000"
  /* 13975 */ "XVSLTI_DU\000"
  /* 13985 */ "XVMAXI_DU\000"
  /* 13995 */ "X86MUL_DU\000"
  /* 14005 */ "AMMIN_DU\000"
  /* 14014 */ "XVMIN_DU\000"
  /* 14023 */ "XVSUBWOD_Q_DU\000"
  /* 14037 */ "XVMADDWOD_Q_DU\000"
  /* 14052 */ "XVADDWOD_Q_DU\000"
  /* 14066 */ "XVMULWOD_Q_DU\000"
  /* 14080 */ "XVSUBWEV_Q_DU\000"
  /* 14094 */ "XVMADDWEV_Q_DU\000"
  /* 14109 */ "XVADDWEV_Q_DU\000"
  /* 14123 */ "XVMULWEV_Q_DU\000"
  /* 14137 */ "XVPICKVE2GR_DU\000"
  /* 14152 */ "XVAVGR_DU\000"
  /* 14162 */ "XVSAT_DU\000"
  /* 14171 */ "XVSLT_DU\000"
  /* 14180 */ "XVEXTH_QU_DU\000"
  /* 14193 */ "XVEXTL_QU_DU\000"
  /* 14206 */ "XVHSUBW_QU_DU\000"
  /* 14220 */ "XVHADDW_QU_DU\000"
  /* 14234 */ "XVDIV_DU\000"
  /* 14243 */ "AMMAX_DU\000"
  /* 14252 */ "XVMAX_DU\000"
  /* 14261 */ "BGEU\000"
  /* 14266 */ "XVSSUB_HU\000"
  /* 14276 */ "XVSADD_HU\000"
  /* 14286 */ "LD_HU\000"
  /* 14292 */ "XVMOD_HU\000"
  /* 14301 */ "XVABSD_HU\000"
  /* 14311 */ "XVSLE_HU\000"
  /* 14320 */ "XVAVG_HU\000"
  /* 14329 */ "XVMUH_HU\000"
  /* 14338 */ "XVSUBI_HU\000"
  /* 14348 */ "XVADDI_HU\000"
  /* 14358 */ "XVSLEI_HU\000"
  /* 14368 */ "XVMINI_HU\000"
  /* 14378 */ "XVSLTI_HU\000"
  /* 14388 */ "XVMAXI_HU\000"
  /* 14398 */ "X86MUL_HU\000"
  /* 14408 */ "XVMIN_HU\000"
  /* 14417 */ "VPICKVE2GR_HU\000"
  /* 14431 */ "XVAVGR_HU\000"
  /* 14441 */ "XVSAT_HU\000"
  /* 14450 */ "XVSLT_HU\000"
  /* 14459 */ "VEXT2XV_DU_HU\000"
  /* 14473 */ "XVEXTH_WU_HU\000"
  /* 14486 */ "XVSLLWIL_WU_HU\000"
  /* 14501 */ "VEXT2XV_WU_HU\000"
  /* 14515 */ "XVHSUBW_WU_HU\000"
  /* 14529 */ "XVHADDW_WU_HU\000"
  /* 14543 */ "XVDIV_HU\000"
  /* 14552 */ "XVSUBWOD_W_HU\000"
  /* 14566 */ "XVMADDWOD_W_HU\000"
  /* 14581 */ "XVADDWOD_W_HU\000"
  /* 14595 */ "XVMULWOD_W_HU\000"
  /* 14609 */ "XVSUBWEV_W_HU\000"
  /* 14623 */ "XVMADDWEV_W_HU\000"
  /* 14638 */ "XVADDWEV_W_HU\000"
  /* 14652 */ "XVMULWEV_W_HU\000"
  /* 14666 */ "XVMAX_HU\000"
  /* 14675 */ "LDX_HU\000"
  /* 14682 */ "XVFFINT_D_LU\000"
  /* 14695 */ "BLTU\000"
  /* 14700 */ "SLTU\000"
  /* 14705 */ "AMMIN__DB_WU\000"
  /* 14718 */ "AMMAX__DB_WU\000"
  /* 14731 */ "X86SUB_WU\000"
  /* 14741 */ "XVSSUB_WU\000"
  /* 14751 */ "X86ADD_WU\000"
  /* 14761 */ "XVSADD_WU\000"
  /* 14771 */ "LD_WU\000"
  /* 14777 */ "XVMOD_WU\000"
  /* 14786 */ "XVABSD_WU\000"
  /* 14796 */ "XVSUBWOD_D_WU\000"
  /* 14810 */ "XVMADDWOD_D_WU\000"
  /* 14825 */ "XVADDWOD_D_WU\000"
  /* 14839 */ "XVMULWOD_D_WU\000"
  /* 14853 */ "XVSUBWEV_D_WU\000"
  /* 14867 */ "XVMADDWEV_D_WU\000"
  /* 14882 */ "XVADDWEV_D_WU\000"
  /* 14896 */ "XVMULWEV_D_WU\000"
  /* 14910 */ "MULW_D_WU\000"
  /* 14920 */ "XVSLE_WU\000"
  /* 14929 */ "XVAVG_WU\000"
  /* 14938 */ "MULH_WU\000"
  /* 14946 */ "XVMUH_WU\000"
  /* 14955 */ "XVSUBI_WU\000"
  /* 14965 */ "XVADDI_WU\000"
  /* 14975 */ "XVSLEI_WU\000"
  /* 14985 */ "XVMINI_WU\000"
  /* 14995 */ "XVSLTI_WU\000"
  /* 15005 */ "XVMAXI_WU\000"
  /* 15015 */ "ALSL_WU\000"
  /* 15023 */ "X86MUL_WU\000"
  /* 15033 */ "AMMIN_WU\000"
  /* 15042 */ "XVMIN_WU\000"
  /* 15051 */ "XVPICKVE2GR_WU\000"
  /* 15066 */ "XVAVGR_WU\000"
  /* 15076 */ "XVFFINT_S_WU\000"
  /* 15089 */ "XVSAT_WU\000"
  /* 15098 */ "XVSLT_WU\000"
  /* 15107 */ "XVEXTH_DU_WU\000"
  /* 15120 */ "XVSLLWIL_DU_WU\000"
  /* 15135 */ "VEXT2XV_DU_WU\000"
  /* 15149 */ "XVHSUBW_DU_WU\000"
  /* 15163 */ "XVHADDW_DU_WU\000"
  /* 15177 */ "XVDIV_WU\000"
  /* 15186 */ "AMMAX_WU\000"
  /* 15195 */ "XVMAX_WU\000"
  /* 15204 */ "LDX_WU\000"
  /* 15211 */ "G_TRUNC_SSAT_U\000"
  /* 15226 */ "G_TRUNC_USAT_U\000"
  /* 15241 */ "G_FDIV\000"
  /* 15248 */ "G_STRICT_FDIV\000"
  /* 15262 */ "G_SDIV\000"
  /* 15269 */ "G_UDIV\000"
  /* 15276 */ "G_GET_FPENV\000"
  /* 15288 */ "G_RESET_FPENV\000"
  /* 15302 */ "G_SET_FPENV\000"
  /* 15314 */ "XVAND_V\000"
  /* 15322 */ "XVBITSEL_V\000"
  /* 15333 */ "XVBSLL_V\000"
  /* 15342 */ "XVBSRL_V\000"
  /* 15351 */ "XVANDN_V\000"
  /* 15360 */ "XVORN_V\000"
  /* 15368 */ "XVNOR_V\000"
  /* 15376 */ "XVOR_V\000"
  /* 15383 */ "XVXOR_V\000"
  /* 15391 */ "XVSETNEZ_V\000"
  /* 15402 */ "XVSETEQZ_V\000"
  /* 15413 */ "REVB_2W\000"
  /* 15421 */ "REVH_2W\000"
  /* 15429 */ "G_FPOW\000"
  /* 15436 */ "XVREPLVE0_W\000"
  /* 15448 */ "XVINSVE0_W\000"
  /* 15459 */ "XVADDA_W\000"
  /* 15468 */ "X86SRA_W\000"
  /* 15477 */ "ARMSRA_W\000"
  /* 15486 */ "XVSRA_W\000"
  /* 15494 */ "AMADD__DB_W\000"
  /* 15506 */ "AMAND__DB_W\000"
  /* 15518 */ "AMMIN__DB_W\000"
  /* 15530 */ "AMSWAP__DB_W\000"
  /* 15543 */ "AMOR__DB_W\000"
  /* 15554 */ "AMXOR__DB_W\000"
  /* 15566 */ "AMCAS__DB_W\000"
  /* 15578 */ "AMMAX__DB_W\000"
  /* 15590 */ "X86SUB_W\000"
  /* 15599 */ "ARMSUB_W\000"
  /* 15608 */ "XVMSUB_W\000"
  /* 15617 */ "XVSSUB_W\000"
  /* 15626 */ "XVSUB_W\000"
  /* 15634 */ "CRCC_W_B_W\000"
  /* 15645 */ "CRC_W_B_W\000"
  /* 15655 */ "X86SBC_W\000"
  /* 15664 */ "ARMSBC_W\000"
  /* 15673 */ "X86ADC_W\000"
  /* 15682 */ "ARMADC_W\000"
  /* 15691 */ "X86DEC_W\000"
  /* 15700 */ "X86INC_W\000"
  /* 15709 */ "SC_W\000"
  /* 15714 */ "X86ADD_W\000"
  /* 15723 */ "AMADD_W\000"
  /* 15731 */ "ARMADD_W\000"
  /* 15740 */ "XVMADD_W\000"
  /* 15749 */ "XVSADD_W\000"
  /* 15758 */ "XVADD_W\000"
  /* 15766 */ "LD_W\000"
  /* 15771 */ "X86AND_W\000"
  /* 15780 */ "AMAND_W\000"
  /* 15788 */ "ARMAND_W\000"
  /* 15797 */ "XVPACKOD_W\000"
  /* 15808 */ "XVPICKOD_W\000"
  /* 15819 */ "XVMOD_W\000"
  /* 15827 */ "IOCSRRD_W\000"
  /* 15837 */ "XVABSD_W\000"
  /* 15846 */ "XVSUBWOD_D_W\000"
  /* 15859 */ "XVMADDWOD_D_W\000"
  /* 15873 */ "XVADDWOD_D_W\000"
  /* 15886 */ "XVMULWOD_D_W\000"
  /* 15899 */ "XVFFINTH_D_W\000"
  /* 15912 */ "XVEXTH_D_W\000"
  /* 15923 */ "XVSLLWIL_D_W\000"
  /* 15936 */ "XVFFINTL_D_W\000"
  /* 15949 */ "FFINT_D_W\000"
  /* 15959 */ "XVSUBWEV_D_W\000"
  /* 15972 */ "XVMADDWEV_D_W\000"
  /* 15986 */ "XVADDWEV_D_W\000"
  /* 15999 */ "XVMULWEV_D_W\000"
  /* 16012 */ "VEXT2XV_D_W\000"
  /* 16024 */ "XVHSUBW_D_W\000"
  /* 16036 */ "XVHADDW_D_W\000"
  /* 16048 */ "MULW_D_W\000"
  /* 16057 */ "CRCC_W_D_W\000"
  /* 16068 */ "CRC_W_D_W\000"
  /* 16078 */ "LDLE_W\000"
  /* 16085 */ "XVSLE_W\000"
  /* 16093 */ "STLE_W\000"
  /* 16100 */ "XVPICKVE_W\000"
  /* 16111 */ "XVREPLVE_W\000"
  /* 16122 */ "XVSHUF_W\000"
  /* 16131 */ "XVNEG_W\000"
  /* 16139 */ "XVAVG_W\000"
  /* 16147 */ "RDTIMEH_W\000"
  /* 16157 */ "MULH_W\000"
  /* 16164 */ "MOVGR2FRH_W\000"
  /* 16176 */ "XVMUH_W\000"
  /* 16184 */ "XVILVH_W\000"
  /* 16193 */ "XVSSRANI_H_W\000"
  /* 16206 */ "XVSRANI_H_W\000"
  /* 16218 */ "XVSSRLNI_H_W\000"
  /* 16231 */ "XVSRLNI_H_W\000"
  /* 16243 */ "XVSSRARNI_H_W\000"
  /* 16257 */ "XVSRARNI_H_W\000"
  /* 16270 */ "XVSSRLRNI_H_W\000"
  /* 16284 */ "XVSRLRNI_H_W\000"
  /* 16297 */ "XVSSRAN_H_W\000"
  /* 16309 */ "XVSRAN_H_W\000"
  /* 16320 */ "XVSSRLN_H_W\000"
  /* 16332 */ "XVSRLN_H_W\000"
  /* 16343 */ "XVSSRARN_H_W\000"
  /* 16356 */ "XVSRARN_H_W\000"
  /* 16368 */ "XVSSRLRN_H_W\000"
  /* 16381 */ "XVSRLRN_H_W\000"
  /* 16393 */ "CRCC_W_H_W\000"
  /* 16404 */ "CRC_W_H_W\000"
  /* 16414 */ "ADDU12I_W\000"
  /* 16424 */ "LU12I_W\000"
  /* 16432 */ "XVSHUF4I_W\000"
  /* 16443 */ "X86SRAI_W\000"
  /* 16453 */ "ARMSRAI_W\000"
  /* 16463 */ "XVSRAI_W\000"
  /* 16472 */ "ADDI_W\000"
  /* 16479 */ "XVSLEI_W\000"
  /* 16488 */ "XVREPL128VEI_W\000"
  /* 16503 */ "VREPLVEI_W\000"
  /* 16514 */ "X86RCLI_W\000"
  /* 16524 */ "X86SLLI_W\000"
  /* 16534 */ "ARMSLLI_W\000"
  /* 16544 */ "XVSLLI_W\000"
  /* 16553 */ "PseudoXVREPLI_W\000"
  /* 16569 */ "PseudoVREPLI_W\000"
  /* 16584 */ "X86SRLI_W\000"
  /* 16594 */ "ARMSRLI_W\000"
  /* 16604 */ "XVSRLI_W\000"
  /* 16613 */ "X86ROTLI_W\000"
  /* 16624 */ "PseudoLI_W\000"
  /* 16635 */ "XVPERMI_W\000"
  /* 16645 */ "XVMINI_W\000"
  /* 16654 */ "XVSEQI_W\000"
  /* 16663 */ "XVSRARI_W\000"
  /* 16673 */ "X86RCRI_W\000"
  /* 16683 */ "XVBITCLRI_W\000"
  /* 16695 */ "XVSRLRI_W\000"
  /* 16705 */ "X86ROTRI_W\000"
  /* 16716 */ "ARMROTRI_W\000"
  /* 16727 */ "XVROTRI_W\000"
  /* 16737 */ "XVBITSETI_W\000"
  /* 16749 */ "XVSLTI_W\000"
  /* 16758 */ "XVBITREVI_W\000"
  /* 16770 */ "XVMAXI_W\000"
  /* 16779 */ "BYTEPICK_W\000"
  /* 16790 */ "BSTRPICK_W\000"
  /* 16801 */ "X86RCL_W\000"
  /* 16810 */ "LDL_W\000"
  /* 16816 */ "RDTIMEL_W\000"
  /* 16826 */ "SCREL_W\000"
  /* 16834 */ "X86SLL_W\000"
  /* 16843 */ "ARMSLL_W\000"
  /* 16852 */ "XVSLL_W\000"
  /* 16860 */ "XVLDREPL_W\000"
  /* 16871 */ "X86SRL_W\000"
  /* 16880 */ "ARMSRL_W\000"
  /* 16889 */ "XVSRL_W\000"
  /* 16897 */ "ALSL_W\000"
  /* 16904 */ "X86ROTL_W\000"
  /* 16914 */ "STL_W\000"
  /* 16920 */ "X86MUL_W\000"
  /* 16929 */ "XVMUL_W\000"
  /* 16937 */ "XVILVL_W\000"
  /* 16946 */ "XVSTELM_W\000"
  /* 16956 */ "XVPERM_W\000"
  /* 16965 */ "AMMIN_W\000"
  /* 16973 */ "XVMIN_W\000"
  /* 16981 */ "XVCLO_W\000"
  /* 16989 */ "CTO_W\000"
  /* 16995 */ "AMSWAP_W\000"
  /* 17004 */ "PseudoCTPOP_W\000"
  /* 17018 */ "LLACQ_W\000"
  /* 17026 */ "XVSEQ_W\000"
  /* 17034 */ "XVSRAR_W\000"
  /* 17043 */ "X86RCR_W\000"
  /* 17052 */ "LDR_W\000"
  /* 17058 */ "MOVGR2FR_W\000"
  /* 17069 */ "XVPICKVE2GR_W\000"
  /* 17083 */ "XVAVGR_W\000"
  /* 17092 */ "XVBITCLR_W\000"
  /* 17103 */ "XVSRLR_W\000"
  /* 17112 */ "X86OR_W\000"
  /* 17120 */ "AMOR_W\000"
  /* 17127 */ "ARMOR_W\000"
  /* 17135 */ "X86XOR_W\000"
  /* 17144 */ "AMXOR_W\000"
  /* 17152 */ "ARMXOR_W\000"
  /* 17161 */ "X86ROTR_W\000"
  /* 17171 */ "ARMROTR_W\000"
  /* 17181 */ "XVROTR_W\000"
  /* 17190 */ "LDPTR_W\000"
  /* 17198 */ "STPTR_W\000"
  /* 17206 */ "STR_W\000"
  /* 17212 */ "XVREPLGR2VR_W\000"
  /* 17226 */ "XVINSGR2VR_W\000"
  /* 17239 */ "IOCSRWR_W\000"
  /* 17249 */ "AMCAS_W\000"
  /* 17257 */ "BSTRINS_W\000"
  /* 17267 */ "XVEXTRINS_W\000"
  /* 17279 */ "XVFFINT_S_W\000"
  /* 17291 */ "XVSAT_W\000"
  /* 17299 */ "XVBITSET_W\000"
  /* 17310 */ "LDGT_W\000"
  /* 17317 */ "STGT_W\000"
  /* 17324 */ "XVSLT_W\000"
  /* 17332 */ "XVPCNT_W\000"
  /* 17341 */ "ARMNOT_W\000"
  /* 17350 */ "ST_W\000"
  /* 17355 */ "XVSSRANI_HU_W\000"
  /* 17369 */ "XVSSRLNI_HU_W\000"
  /* 17383 */ "XVSSRARNI_HU_W\000"
  /* 17398 */ "XVSSRLRNI_HU_W\000"
  /* 17413 */ "XVSSRAN_HU_W\000"
  /* 17426 */ "XVSSRLN_HU_W\000"
  /* 17439 */ "XVSSRARN_HU_W\000"
  /* 17453 */ "XVSSRLRN_HU_W\000"
  /* 17467 */ "XVMADDWOD_D_WU_W\000"
  /* 17484 */ "XVADDWOD_D_WU_W\000"
  /* 17500 */ "XVMULWOD_D_WU_W\000"
  /* 17516 */ "XVMADDWEV_D_WU_W\000"
  /* 17533 */ "XVADDWEV_D_WU_W\000"
  /* 17549 */ "XVMULWEV_D_WU_W\000"
  /* 17565 */ "XVPACKEV_W\000"
  /* 17576 */ "XVPICKEV_W\000"
  /* 17587 */ "XVBITREV_W\000"
  /* 17598 */ "XVDIV_W\000"
  /* 17606 */ "XVSIGNCOV_W\000"
  /* 17618 */ "ARMMOV_W\000"
  /* 17627 */ "CRCC_W_W_W\000"
  /* 17638 */ "CRC_W_W_W\000"
  /* 17648 */ "AMMAX_W\000"
  /* 17656 */ "XVMAX_W\000"
  /* 17664 */ "LDX_W\000"
  /* 17670 */ "ARMRRX_W\000"
  /* 17679 */ "STX_W\000"
  /* 17685 */ "PseudoXVBZ_W\000"
  /* 17698 */ "PseudoVBZ_W\000"
  /* 17710 */ "XVSETALLNEZ_W\000"
  /* 17724 */ "XVCLZ_W\000"
  /* 17732 */ "PseudoXVBNZ_W\000"
  /* 17746 */ "PseudoVBNZ_W\000"
  /* 17759 */ "XVSETANYEQZ_W\000"
  /* 17773 */ "CTZ_W\000"
  /* 17779 */ "PseudoXVMSKLTZ_W\000"
  /* 17796 */ "PseudoVMSKLTZ_W\000"
  /* 17812 */ "PseudoAddTPRel_W\000"
  /* 17829 */ "PseudoAtomicStoreW\000"
  /* 17848 */ "G_VECREDUCE_FMAX\000"
  /* 17865 */ "G_ATOMICRMW_FMAX\000"
  /* 17882 */ "G_VECREDUCE_SMAX\000"
  /* 17899 */ "G_SMAX\000"
  /* 17906 */ "G_VECREDUCE_UMAX\000"
  /* 17923 */ "G_UMAX\000"
  /* 17930 */ "G_ATOMICRMW_UMAX\000"
  /* 17947 */ "G_ATOMICRMW_MAX\000"
  /* 17963 */ "PRELDX\000"
  /* 17970 */ "XVLDX\000"
  /* 17976 */ "G_FRAME_INDEX\000"
  /* 17990 */ "G_SBFX\000"
  /* 17997 */ "G_UBFX\000"
  /* 18004 */ "G_SMULFIX\000"
  /* 18014 */ "G_UMULFIX\000"
  /* 18024 */ "G_SDIVFIX\000"
  /* 18034 */ "G_UDIVFIX\000"
  /* 18044 */ "XVSTX\000"
  /* 18050 */ "G_MEMCPY\000"
  /* 18059 */ "COPY\000"
  /* 18064 */ "CONVERGENCECTRL_ENTRY\000"
  /* 18086 */ "PseudoXVBZ\000"
  /* 18097 */ "PseudoVBZ\000"
  /* 18107 */ "BNEZ\000"
  /* 18112 */ "BCNEZ\000"
  /* 18118 */ "MASKNEZ\000"
  /* 18126 */ "G_CTLZ\000"
  /* 18133 */ "PseudoXVBNZ\000"
  /* 18145 */ "PseudoVBNZ\000"
  /* 18156 */ "BEQZ\000"
  /* 18161 */ "BCEQZ\000"
  /* 18167 */ "MASKEQZ\000"
  /* 18175 */ "G_CTTZ\000"
  /* 18182 */ "PseudoCmpXchg128Acquire\000"
  /* 18206 */ "BuildPairF64Pseudo\000"
  /* 18225 */ "SplitPairF64Pseudo\000"
  /* 18244 */ "PseudoTAILIndirect\000"
  /* 18263 */ "PseudoCALLIndirect\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned LoongArchInstrNameIndices[] = {
    8960U, 9602U, 10808U, 10067U, 9084U, 9065U, 9093U, 9401U, 
    6854U, 6869U, 6770U, 6757U, 6896U, 11531U, 6603U, 13299U, 
    6783U, 8956U, 9074U, 6069U, 18059U, 9028U, 6399U, 13203U, 
    2928U, 6020U, 6057U, 10247U, 9336U, 13100U, 3047U, 10524U, 
    7005U, 13089U, 6482U, 10497U, 10484U, 10888U, 12930U, 12963U, 
    9252U, 9315U, 9288U, 9110U, 6588U, 10853U, 10201U, 6458U, 
    18064U, 11089U, 10417U, 6651U, 13334U, 13364U, 9910U, 2788U, 
    818U, 9517U, 15262U, 15269U, 9568U, 9575U, 9582U, 9592U, 
    2906U, 11302U, 11265U, 11428U, 13808U, 11137U, 9217U, 11125U, 
    9206U, 6768U, 8958U, 17976U, 6613U, 6628U, 9406U, 12898U, 
    11435U, 13240U, 11452U, 11188U, 2521U, 11514U, 13111U, 11378U, 
    13272U, 6715U, 10864U, 3021U, 2495U, 3003U, 13149U, 13130U, 
    9888U, 10913U, 10932U, 2689U, 2633U, 2663U, 2602U, 2674U, 
    2614U, 2644U, 6553U, 6507U, 6537U, 11561U, 6917U, 6943U, 
    2804U, 824U, 2912U, 2873U, 11307U, 11271U, 17947U, 10036U, 
    17930U, 10019U, 2755U, 801U, 17865U, 9954U, 9751U, 9698U, 
    9824U, 9786U, 10309U, 10287U, 2962U, 12851U, 6049U, 7046U, 
    2953U, 12917U, 13218U, 2473U, 11609U, 13066U, 11636U, 13348U, 
    2513U, 12437U, 15211U, 15226U, 13055U, 13043U, 13193U, 6997U, 
    13327U, 6883U, 13357U, 9152U, 11069U, 11055U, 9145U, 11062U, 
    11371U, 9427U, 10378U, 10357U, 10385U, 10392U, 12908U, 10193U, 
    6090U, 10177U, 6041U, 10185U, 6082U, 10169U, 6033U, 10231U, 
    10223U, 7065U, 7057U, 12769U, 12759U, 12749U, 12739U, 12789U, 
    12779U, 18004U, 18014U, 12799U, 12812U, 18024U, 18034U, 12825U, 
    12838U, 2713U, 780U, 9451U, 734U, 2595U, 15241U, 9547U, 
    6749U, 15429U, 8998U, 10568U, 616U, 9U, 6990U, 599U, 
    0U, 10543U, 10575U, 6847U, 13319U, 2485U, 8969U, 8983U, 
    10339U, 10348U, 12872U, 12885U, 11402U, 9925U, 11548U, 6724U, 
    9848U, 9858U, 6139U, 6154U, 9687U, 9740U, 9772U, 9810U, 
    15276U, 15302U, 15288U, 6098U, 6126U, 6111U, 6960U, 6975U, 
    2794U, 9042U, 9988U, 17899U, 10012U, 17923U, 11422U, 2994U, 
    2984U, 10803U, 12987U, 6372U, 11169U, 11149U, 13019U, 12998U, 
    11203U, 11234U, 11220U, 11591U, 18175U, 10102U, 18126U, 10083U, 
    11467U, 10438U, 10331U, 6575U, 9493U, 9198U, 11482U, 10060U, 
    11489U, 9876U, 11474U, 10052U, 9868U, 607U, 7089U, 7081U, 
    7073U, 13249U, 11116U, 13122U, 13167U, 13282U, 10840U, 6381U, 
    2560U, 6685U, 6522U, 2741U, 787U, 9479U, 15248U, 9554U, 
    740U, 13257U, 10552U, 10364U, 11499U, 10952U, 10968U, 18050U, 
    6442U, 6697U, 12954U, 10239U, 6426U, 10280U, 10256U, 10268U, 
    2720U, 9458U, 2696U, 9434U, 17848U, 9937U, 9719U, 9666U, 
    2772U, 9501U, 2890U, 11287U, 11249U, 17882U, 9971U, 17906U, 
    9995U, 17990U, 17997U, 10130U, 10509U, 18206U, 2542U, 10147U, 
    5976U, 17812U, 174U, 196U, 577U, 388U, 247U, 652U, 
    454U, 124U, 526U, 337U, 475U, 5993U, 17829U, 435U, 
    10821U, 2941U, 9158U, 9348U, 31U, 704U, 18263U, 6301U, 
    9648U, 9376U, 1806U, 4529U, 8060U, 58U, 17004U, 77U, 
    717U, 18182U, 292U, 675U, 11011U, 9236U, 9272U, 9171U, 
    11409U, 6318U, 13180U, 6337U, 9130U, 6263U, 2577U, 6173U, 
    2820U, 6197U, 6356U, 6241U, 2857U, 6219U, 6406U, 10985U, 
    4049U, 16624U, 146U, 549U, 360U, 218U, 96U, 497U, 
    308U, 410U, 270U, 12944U, 10998U, 9187U, 18U, 691U, 
    18244U, 6284U, 9630U, 9359U, 10399U, 18145U, 2370U, 5898U, 
    8848U, 17746U, 18097U, 2256U, 5850U, 8800U, 17698U, 2410U, 
    2285U, 2457U, 5960U, 8892U, 17796U, 2318U, 1476U, 4004U, 
    7756U, 16569U, 18133U, 2356U, 5884U, 8834U, 17732U, 18086U, 
    2243U, 5837U, 8787U, 17685U, 1948U, 8202U, 2393U, 2268U, 
    2440U, 5943U, 8875U, 17779U, 2301U, 1460U, 3988U, 7740U, 
    16553U, 11357U, 11322U, 18225U, 11364U, 962U, 3349U, 7429U, 
    15676U, 3907U, 16472U, 3841U, 16414U, 3878U, 3381U, 15717U, 
    4283U, 16897U, 15015U, 995U, 3396U, 7462U, 15723U, 878U, 
    3149U, 7145U, 15494U, 3476U, 15780U, 3161U, 15506U, 1977U, 
    5002U, 8231U, 17249U, 903U, 3221U, 7170U, 15566U, 5807U, 
    14243U, 17648U, 15186U, 3233U, 13828U, 15578U, 14718U, 4453U, 
    14005U, 16965U, 15033U, 3173U, 13815U, 15518U, 14705U, 4887U, 
    17120U, 3198U, 15543U, 1797U, 4509U, 8051U, 16995U, 890U, 
    3185U, 7157U, 15530U, 4916U, 17144U, 3209U, 15554U, 2886U, 
    8951U, 9883U, 15682U, 15731U, 15788U, 6807U, 6707U, 5520U, 
    17618U, 6827U, 17341U, 17127U, 16716U, 17171U, 17670U, 15664U, 
    16534U, 16843U, 16453U, 15477U, 16594U, 16880U, 15599U, 17152U, 
    5088U, 3585U, 761U, 18161U, 18112U, 10584U, 18156U, 6169U, 
    14261U, 753U, 763U, 5475U, 17589U, 9052U, 12994U, 14695U, 
    6422U, 18107U, 9022U, 5017U, 17257U, 4204U, 16790U, 4193U, 
    16779U, 10411U, 4497U, 16983U, 5878U, 17726U, 6910U, 15634U, 
    16057U, 16393U, 17627U, 15645U, 16068U, 16404U, 17638U, 3071U, 
    11396U, 6935U, 4503U, 16989U, 5937U, 17773U, 10793U, 9055U, 
    5487U, 14236U, 17600U, 15179U, 10125U, 2203U, 8670U, 5010U, 
    12419U, 3389U, 11746U, 5041U, 12428U, 3754U, 11976U, 4565U, 
    12318U, 3545U, 11815U, 5107U, 12470U, 3641U, 11885U, 4876U, 
    12395U, 4599U, 12344U, 3604U, 11857U, 5141U, 12496U, 3680U, 
    11924U, 4471U, 12269U, 3767U, 11989U, 4586U, 12331U, 3574U, 
    11836U, 5128U, 12483U, 3667U, 11911U, 4896U, 12408U, 4613U, 
    12358U, 3618U, 11871U, 5155U, 12510U, 3694U, 11938U, 4484U, 
    12282U, 4432U, 12246U, 2847U, 11804U, 3457U, 5052U, 3533U, 
    5486U, 12589U, 9525U, 15949U, 9537U, 17281U, 5080U, 12452U, 
    3556U, 11826U, 5823U, 12681U, 3451U, 11774U, 3257U, 11706U, 
    3406U, 11755U, 3141U, 11686U, 5800U, 12674U, 3114U, 11676U, 
    4446U, 12260U, 5513U, 12596U, 3285U, 11725U, 4317U, 12020U, 
    3787U, 12000U, 3416U, 11765U, 3295U, 11735U, 3708U, 11952U, 
    4520U, 12295U, 5178U, 12524U, 3720U, 11964U, 5198U, 12544U, 
    3245U, 11694U, 6012U, 12719U, 5188U, 12534U, 5097U, 12460U, 
    3594U, 11847U, 5830U, 12688U, 5207U, 12553U, 3276U, 11716U, 
    4358U, 12188U, 5650U, 12620U, 4343U, 12027U, 5531U, 12605U, 
    4372U, 12200U, 5760U, 12634U, 4398U, 12222U, 5786U, 12660U, 
    4386U, 12212U, 5774U, 12648U, 3070U, 11395U, 6934U, 7097U, 
    9060U, 10798U, 6394U, 773U, 1073U, 3514U, 7540U, 15827U, 
    1967U, 4992U, 8221U, 17239U, 9422U, 44U, 51U, 11076U, 
    2016U, 5081U, 8294U, 17310U, 1104U, 3557U, 7571U, 16078U, 
    4224U, 16810U, 6597U, 4943U, 17190U, 4795U, 17052U, 2231U, 
    13801U, 5824U, 8775U, 14675U, 17664U, 15204U, 1029U, 13398U, 
    3452U, 7496U, 14286U, 15766U, 14771U, 4555U, 17018U, 4242U, 
    16838U, 16424U, 3851U, 3859U, 18167U, 18118U, 3508U, 13883U, 
    15821U, 14779U, 12727U, 11025U, 11044U, 12707U, 4826U, 12382U, 
    624U, 12370U, 6740U, 11346U, 16164U, 4801U, 17058U, 638U, 
    10830U, 11034U, 3810U, 13918U, 16157U, 14938U, 16048U, 14910U, 
    4309U, 16923U, 11112U, 11109U, 8965U, 10121U, 8938U, 8918U, 
    8928U, 8908U, 2836U, 17963U, 1563U, 4101U, 7843U, 16676U, 
    1850U, 4789U, 8104U, 17046U, 16147U, 16816U, 3630U, 7022U, 
    15413U, 7030U, 3330U, 15421U, 3825U, 1621U, 4133U, 7875U, 
    16708U, 1918U, 4927U, 8172U, 17164U, 953U, 3340U, 7420U, 
    15658U, 4230U, 16826U, 3373U, 10608U, 15709U, 9014U, 9006U, 
    6495U, 6469U, 6561U, 6672U, 3972U, 16527U, 4241U, 16837U, 
    13039U, 8978U, 14700U, 8992U, 3891U, 16446U, 3125U, 15471U, 
    4022U, 16587U, 4269U, 16874U, 2023U, 5098U, 8301U, 17317U, 
    1119U, 3595U, 7586U, 16093U, 4300U, 16914U, 4951U, 17198U, 
    4959U, 17206U, 2237U, 5831U, 8781U, 17679U, 2047U, 5208U, 
    8325U, 17350U, 3268U, 15593U, 9228U, 11082U, 9393U, 7098U, 
    3064U, 7038U, 11389U, 3077U, 1084U, 13414U, 3525U, 13891U, 
    7551U, 14302U, 15838U, 14787U, 853U, 3104U, 7120U, 15460U, 
    13575U, 13946U, 14349U, 14966U, 15987U, 14883U, 17534U, 1284U, 
    13537U, 2119U, 4728U, 14110U, 5280U, 8706U, 14639U, 8509U, 
    15874U, 14826U, 17485U, 1207U, 13480U, 2070U, 4653U, 14053U, 
    5231U, 8621U, 14582U, 8460U, 1022U, 3444U, 7489U, 10614U, 
    15759U, 1376U, 15352U, 15315U, 1870U, 13658U, 4838U, 14153U, 
    8124U, 14432U, 17084U, 15067U, 1155U, 13433U, 3803U, 13910U, 
    7622U, 14321U, 16140U, 14930U, 1571U, 4109U, 7851U, 16684U, 
    1879U, 4847U, 8133U, 17093U, 1661U, 4173U, 7915U, 16759U, 
    2173U, 5474U, 8563U, 17588U, 1430U, 15323U, 1640U, 4152U, 
    7894U, 16738U, 2006U, 5070U, 8284U, 17300U, 15334U, 15343U, 
    1790U, 4496U, 8044U, 16982U, 2349U, 5877U, 8827U, 17725U, 
    2184U, 13784U, 5494U, 14235U, 8574U, 14544U, 17599U, 15178U, 
    13685U, 14459U, 15135U, 1092U, 7559U, 16012U, 13727U, 1309U, 
    13769U, 14501U, 2211U, 8731U, 15108U, 15913U, 13700U, 1233U, 
    14181U, 4679U, 14474U, 8647U, 14194U, 4690U, 1986U, 5028U, 
    8240U, 17268U, 3388U, 11745U, 5040U, 12427U, 3753U, 11975U, 
    4564U, 12317U, 3544U, 11814U, 5106U, 12469U, 3640U, 11884U, 
    4875U, 12394U, 4598U, 12343U, 3603U, 11856U, 5140U, 12495U, 
    3679U, 11923U, 4470U, 12268U, 3766U, 11988U, 4585U, 12330U, 
    3573U, 11835U, 5127U, 12482U, 3666U, 11910U, 4895U, 12407U, 
    4612U, 12357U, 3617U, 11870U, 5154U, 12509U, 3693U, 11937U, 
    4483U, 12281U, 11781U, 8252U, 11793U, 8264U, 12008U, 5051U, 
    5485U, 12588U, 15900U, 15937U, 9524U, 14683U, 9536U, 17280U, 
    15077U, 3256U, 11705U, 3405U, 11754U, 3140U, 11685U, 5799U, 
    12673U, 3113U, 11675U, 4445U, 12259U, 3284U, 11724U, 4316U, 
    12019U, 3415U, 11764U, 3294U, 11734U, 3707U, 11951U, 4519U, 
    12294U, 4421U, 12235U, 3653U, 11897U, 4544U, 12305U, 5926U, 
    12696U, 5177U, 12523U, 3719U, 11963U, 5197U, 12543U, 1531U, 
    7811U, 1821U, 8075U, 5187U, 12533U, 3275U, 11715U, 12087U, 
    12161U, 12057U, 12131U, 4357U, 5649U, 12619U, 12041U, 12115U, 
    4342U, 5530U, 12604U, 12072U, 12146U, 4371U, 5759U, 12633U, 
    12100U, 12174U, 5325U, 4397U, 12573U, 5785U, 12659U, 5312U, 
    4385U, 12560U, 5773U, 12647U, 15164U, 16037U, 13756U, 1334U, 
    14221U, 4766U, 14530U, 8756U, 15150U, 16025U, 13742U, 1322U, 
    14207U, 4754U, 14516U, 8744U, 1171U, 3833U, 7638U, 16185U, 
    1763U, 4333U, 8017U, 16938U, 1955U, 4980U, 8209U, 17227U, 
    2843U, 8946U, 1708U, 4256U, 7962U, 16861U, 17971U, 15973U, 
    14868U, 17517U, 1270U, 13522U, 2102U, 4714U, 14095U, 5263U, 
    8692U, 14624U, 8492U, 15860U, 14811U, 17468U, 1193U, 13465U, 
    2053U, 4639U, 14038U, 5214U, 8607U, 14567U, 8443U, 1004U, 
    3426U, 7471U, 15741U, 1673U, 13615U, 4185U, 13986U, 7927U, 
    14389U, 16771U, 15006U, 2224U, 13793U, 5816U, 14253U, 8768U, 
    14667U, 17657U, 15196U, 1522U, 13595U, 4071U, 13966U, 7802U, 
    14369U, 16646U, 14986U, 1782U, 13635U, 4462U, 14015U, 8036U, 
    14409U, 16974U, 15043U, 1066U, 13405U, 3507U, 13882U, 7533U, 
    14293U, 15820U, 14778U, 2275U, 2447U, 5950U, 8882U, 17786U, 
    2384U, 925U, 3305U, 7192U, 15609U, 1163U, 13442U, 3818U, 
    13927U, 7630U, 14330U, 16177U, 14947U, 16000U, 14897U, 17550U, 
    1297U, 13551U, 2135U, 4741U, 14124U, 5296U, 8719U, 14653U, 
    8525U, 15887U, 14840U, 17501U, 1220U, 13494U, 2086U, 4666U, 
    14067U, 5247U, 8634U, 14596U, 8476U, 1755U, 4325U, 8009U, 
    16930U, 1147U, 3795U, 7614U, 16132U, 1593U, 15369U, 1602U, 
    15361U, 15377U, 2151U, 5452U, 8541U, 17566U, 1044U, 3485U, 
    7511U, 15798U, 2039U, 5168U, 8317U, 17333U, 16636U, 2162U, 
    5463U, 8552U, 17577U, 1055U, 3496U, 7522U, 15809U, 1856U, 
    13643U, 4813U, 14138U, 8110U, 14417U, 17070U, 15052U, 1935U, 
    4966U, 8189U, 17213U, 1408U, 3938U, 7700U, 16503U, 1127U, 
    3742U, 7594U, 16112U, 1630U, 4142U, 7884U, 16728U, 1926U, 
    4935U, 8180U, 17182U, 1013U, 13389U, 3435U, 13872U, 7480U, 
    14277U, 15750U, 14762U, 1998U, 13668U, 5062U, 14163U, 8276U, 
    14442U, 17292U, 15090U, 1542U, 4080U, 7822U, 16655U, 1831U, 
    4577U, 8085U, 17027U, 2335U, 5863U, 8813U, 17711U, 2427U, 
    5912U, 8862U, 17760U, 15403U, 15392U, 1346U, 3868U, 7647U, 
    16433U, 1138U, 3779U, 7605U, 16123U, 2192U, 5502U, 8582U, 
    17607U, 1385U, 13585U, 3915U, 13956U, 7677U, 14359U, 16480U, 
    14976U, 1112U, 13424U, 3565U, 13901U, 7579U, 14312U, 16086U, 
    14921U, 1452U, 3980U, 7732U, 16545U, 15121U, 15924U, 13713U, 
    1244U, 14487U, 8658U, 1700U, 4248U, 7954U, 16853U, 1652U, 
    13605U, 4164U, 13976U, 7906U, 14379U, 16750U, 14996U, 2031U, 
    13677U, 5119U, 14172U, 8309U, 14451U, 17325U, 15099U, 1367U, 
    3899U, 7668U, 16464U, 7231U, 10635U, 16207U, 5558U, 7334U, 
    16310U, 5675U, 1551U, 4089U, 7831U, 16664U, 7282U, 10686U, 
    16258U, 5609U, 7381U, 16357U, 5722U, 1839U, 4778U, 8093U, 
    17035U, 871U, 3132U, 7138U, 15487U, 1502U, 4030U, 7782U, 
    16605U, 7256U, 10660U, 16232U, 5583U, 7357U, 16333U, 5698U, 
    1583U, 4121U, 7863U, 16696U, 7309U, 10713U, 16285U, 5636U, 
    7406U, 16382U, 5747U, 1890U, 4858U, 8144U, 17104U, 1728U, 
    4276U, 7982U, 16890U, 8331U, 7218U, 10736U, 10622U, 17356U, 
    16194U, 5340U, 5545U, 8389U, 7322U, 17414U, 16298U, 5398U, 
    5663U, 8359U, 7268U, 10764U, 10672U, 17384U, 16244U, 5368U, 
    5595U, 8415U, 7368U, 17440U, 16344U, 5424U, 5709U, 8345U, 
    7243U, 10750U, 10647U, 17370U, 16219U, 5354U, 5570U, 8402U, 
    7345U, 17427U, 16321U, 5411U, 5686U, 8374U, 7295U, 10779U, 
    10699U, 17399U, 16271U, 5383U, 5622U, 8429U, 7393U, 17454U, 
    16369U, 5438U, 5734U, 934U, 13379U, 3314U, 13852U, 7201U, 
    14267U, 15618U, 14742U, 13315U, 1772U, 4411U, 8026U, 16947U, 
    18045U, 13565U, 13936U, 14339U, 14956U, 15960U, 14854U, 1257U, 
    13508U, 4701U, 14081U, 8679U, 14610U, 15847U, 14797U, 1180U, 
    13451U, 4626U, 14024U, 8594U, 14553U, 943U, 3323U, 7210U, 
    10601U, 15627U, 1610U, 15384U, 959U, 3346U, 7426U, 15673U, 
    986U, 3378U, 13861U, 7453U, 15714U, 14751U, 1034U, 3467U, 
    7501U, 15771U, 9612U, 10446U, 968U, 3355U, 7435U, 15691U, 
    10456U, 977U, 3364U, 7444U, 15700U, 6797U, 10466U, 6817U, 
    10475U, 1745U, 13624U, 4306U, 13995U, 7999U, 14398U, 16920U, 
    15023U, 1898U, 4866U, 8152U, 17112U, 1419U, 3949U, 7711U, 
    16514U, 1681U, 4215U, 7935U, 16801U, 1560U, 4098U, 7840U, 
    16673U, 1847U, 4786U, 8101U, 17043U, 1510U, 4038U, 7790U, 
    16613U, 1735U, 4290U, 7989U, 16904U, 1618U, 4130U, 7872U, 
    16705U, 1915U, 4924U, 8169U, 17161U, 950U, 3337U, 7417U, 
    15655U, 6837U, 9621U, 1441U, 3969U, 7721U, 16524U, 1690U, 
    4238U, 7944U, 16834U, 1356U, 3888U, 7657U, 16443U, 861U, 
    3122U, 7128U, 15468U, 1491U, 4019U, 7771U, 16584U, 1718U, 
    4266U, 7972U, 16871U, 915U, 3265U, 13841U, 7182U, 15590U, 
    14731U, 1906U, 4907U, 8160U, 17135U, 11261U, 8964U, 1083U, 
    13413U, 3524U, 13890U, 7550U, 14301U, 15837U, 14786U, 852U, 
    3103U, 7119U, 15459U, 13574U, 13945U, 14348U, 14965U, 15986U, 
    14882U, 17533U, 1283U, 13536U, 2118U, 4727U, 14109U, 5279U, 
    8705U, 14638U, 8508U, 15873U, 14825U, 17484U, 1206U, 13479U, 
    2069U, 4652U, 14052U, 5230U, 8620U, 14581U, 8459U, 1021U, 
    3443U, 7488U, 10613U, 15758U, 1375U, 15351U, 15314U, 1869U, 
    13657U, 4837U, 14152U, 8123U, 14431U, 17083U, 15066U, 1154U, 
    13432U, 3802U, 13909U, 7621U, 14320U, 16139U, 14929U, 1570U, 
    4108U, 7850U, 16683U, 1878U, 4846U, 8132U, 17092U, 1660U, 
    4172U, 7914U, 16758U, 2172U, 5473U, 8562U, 17587U, 1429U, 
    15322U, 1639U, 4151U, 7893U, 16737U, 2005U, 5069U, 8283U, 
    17299U, 15333U, 15342U, 1789U, 4495U, 8043U, 16981U, 2348U, 
    5876U, 8826U, 17724U, 2183U, 13783U, 5493U, 14234U, 8573U, 
    14543U, 17598U, 15177U, 15107U, 15912U, 13699U, 1232U, 14180U, 
    4678U, 14473U, 8646U, 14193U, 4689U, 1985U, 5027U, 8239U, 
    17267U, 3387U, 11744U, 5039U, 12426U, 3752U, 11974U, 4563U, 
    12316U, 3543U, 11813U, 5105U, 12468U, 3639U, 11883U, 4874U, 
    12393U, 4597U, 12342U, 3602U, 11855U, 5139U, 12494U, 3678U, 
    11922U, 4469U, 12267U, 3765U, 11987U, 4584U, 12329U, 3572U, 
    11834U, 5126U, 12481U, 3665U, 11909U, 4894U, 12406U, 4611U, 
    12356U, 3616U, 11869U, 5153U, 12508U, 3692U, 11936U, 4482U, 
    12280U, 11780U, 8251U, 11792U, 8263U, 12007U, 5050U, 5484U, 
    12587U, 15899U, 15936U, 9523U, 14682U, 9535U, 17279U, 15076U, 
    3255U, 11704U, 3404U, 11753U, 3139U, 11684U, 5798U, 12672U, 
    3112U, 11674U, 4444U, 12258U, 3283U, 11723U, 4315U, 12018U, 
    3414U, 11763U, 3293U, 11733U, 3706U, 11950U, 4518U, 12293U, 
    4420U, 12234U, 3652U, 11896U, 4543U, 12304U, 5925U, 12695U, 
    5176U, 12522U, 3718U, 11962U, 5196U, 12542U, 1530U, 7810U, 
    1820U, 8074U, 5186U, 12532U, 3274U, 11714U, 12086U, 12160U, 
    12056U, 12130U, 4356U, 5648U, 12618U, 12040U, 12114U, 4341U, 
    5529U, 12603U, 12071U, 12145U, 4370U, 5758U, 12632U, 12099U, 
    12173U, 5324U, 4396U, 12572U, 5784U, 12658U, 5311U, 4384U, 
    12559U, 5772U, 12646U, 15163U, 16036U, 13755U, 1333U, 14220U, 
    4765U, 14529U, 8755U, 3959U, 15149U, 16024U, 13741U, 1321U, 
    14206U, 4753U, 14515U, 8743U, 1170U, 3832U, 7637U, 16184U, 
    1762U, 4332U, 8016U, 16937U, 4979U, 17226U, 3092U, 15448U, 
    2842U, 8945U, 1707U, 4255U, 7961U, 16860U, 17970U, 15972U, 
    14867U, 17516U, 1269U, 13521U, 2101U, 4713U, 14094U, 5262U, 
    8691U, 14623U, 8491U, 15859U, 14810U, 17467U, 1192U, 13464U, 
    2052U, 4638U, 14037U, 5213U, 8606U, 14566U, 8442U, 1003U, 
    3425U, 7470U, 15740U, 1672U, 13614U, 4184U, 13985U, 7926U, 
    14388U, 16770U, 15005U, 2223U, 13792U, 5815U, 14252U, 8767U, 
    14666U, 17656U, 15195U, 1521U, 13594U, 4070U, 13965U, 7801U, 
    14368U, 16645U, 14985U, 1781U, 13634U, 4461U, 14014U, 8035U, 
    14408U, 16973U, 15042U, 1065U, 13404U, 3506U, 13881U, 7532U, 
    14292U, 15819U, 14777U, 2274U, 2446U, 5949U, 8881U, 17785U, 
    2383U, 924U, 3304U, 7191U, 15608U, 1162U, 13441U, 3817U, 
    13926U, 7629U, 14329U, 16176U, 14946U, 15999U, 14896U, 17549U, 
    1296U, 13550U, 2134U, 4740U, 14123U, 5295U, 8718U, 14652U, 
    8524U, 15886U, 14839U, 17500U, 1219U, 13493U, 2085U, 4665U, 
    14066U, 5246U, 8633U, 14595U, 8475U, 1754U, 4324U, 8008U, 
    16929U, 1146U, 3794U, 7613U, 16131U, 1592U, 15368U, 1601U, 
    15360U, 15376U, 2150U, 5451U, 8540U, 17565U, 1043U, 3484U, 
    7510U, 15797U, 2038U, 5167U, 8316U, 17332U, 4060U, 10725U, 
    16635U, 16956U, 2161U, 5462U, 8551U, 17576U, 1054U, 3495U, 
    7521U, 15808U, 4812U, 14137U, 17069U, 15051U, 3730U, 16100U, 
    1393U, 3923U, 7685U, 16488U, 1934U, 4965U, 8188U, 17212U, 
    840U, 3080U, 7107U, 10588U, 15436U, 1126U, 3741U, 7593U, 
    16111U, 1629U, 4141U, 7883U, 16727U, 1925U, 4934U, 8179U, 
    17181U, 1012U, 13388U, 3434U, 13871U, 7479U, 14276U, 15749U, 
    14761U, 1997U, 13667U, 5061U, 14162U, 8275U, 14441U, 17291U, 
    15089U, 1541U, 4079U, 7821U, 16654U, 1830U, 4576U, 8084U, 
    17026U, 2334U, 5862U, 8812U, 17710U, 2426U, 5911U, 8861U, 
    17759U, 15402U, 15391U, 1345U, 3867U, 7646U, 16432U, 1137U, 
    3778U, 7604U, 16122U, 2191U, 5501U, 8581U, 17606U, 1384U, 
    13584U, 3914U, 13955U, 7676U, 14358U, 16479U, 14975U, 1111U, 
    13423U, 3564U, 13900U, 7578U, 14311U, 16085U, 14920U, 1451U, 
    3979U, 7731U, 16544U, 15120U, 15923U, 13712U, 1243U, 14486U, 
    8657U, 1699U, 4247U, 7953U, 16852U, 1651U, 13604U, 4163U, 
    13975U, 7905U, 14378U, 16749U, 14995U, 2030U, 13676U, 5118U, 
    14171U, 8308U, 14450U, 17324U, 15098U, 1366U, 3898U, 7667U, 
    16463U, 7230U, 10634U, 16206U, 5557U, 7333U, 16309U, 5674U, 
    1550U, 4088U, 7830U, 16663U, 7281U, 10685U, 16257U, 5608U, 
    7380U, 16356U, 5721U, 1838U, 4777U, 8092U, 17034U, 870U, 
    3131U, 7137U, 15486U, 1501U, 4029U, 7781U, 16604U, 7255U, 
    10659U, 16231U, 5582U, 7356U, 16332U, 5697U, 1582U, 4120U, 
    7862U, 16695U, 7308U, 10712U, 16284U, 5635U, 7405U, 16381U, 
    5746U, 1889U, 4857U, 8143U, 17103U, 1727U, 4275U, 7981U, 
    16889U, 8330U, 7217U, 10735U, 10621U, 17355U, 16193U, 5339U, 
    5544U, 8388U, 7321U, 17413U, 16297U, 5397U, 5662U, 8358U, 
    7267U, 10763U, 10671U, 17383U, 16243U, 5367U, 5594U, 8414U, 
    7367U, 17439U, 16343U, 5423U, 5708U, 8344U, 7242U, 10749U, 
    10646U, 17369U, 16218U, 5353U, 5569U, 8401U, 7344U, 17426U, 
    16320U, 5410U, 5685U, 8373U, 7294U, 10778U, 10698U, 17398U, 
    16270U, 5382U, 5621U, 8428U, 7392U, 17453U, 16368U, 5437U, 
    5733U, 933U, 13378U, 3313U, 13851U, 7200U, 14266U, 15617U, 
    14741U, 13314U, 1771U, 4410U, 8025U, 16946U, 18044U, 13564U, 
    13935U, 14338U, 14955U, 15959U, 14853U, 1256U, 13507U, 4700U, 
    14080U, 8678U, 14609U, 15846U, 14796U, 1179U, 13450U, 4625U, 
    14023U, 8593U, 14552U, 942U, 3322U, 7209U, 10600U, 15626U, 
    1609U, 15383U, 
};

static inline void InitLoongArchMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(LoongArchDescs.Insts, LoongArchInstrNameIndices, LoongArchInstrNameData, nullptr, nullptr, 2498, nullptr, 0);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct LoongArchGenInstrInfo : public TargetInstrInfo {
  explicit LoongArchGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~LoongArchGenInstrInfo() override = default;
};

} // namespace llvm_ks

namespace llvm_ks::LoongArch {


} // namespace llvm_ks::LoongArch

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

extern const LoongArchInstrTable LoongArchDescs;
extern const unsigned LoongArchInstrNameIndices[];
extern const char LoongArchInstrNameData[];
LoongArchGenInstrInfo::LoongArchGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(LoongArchDescs.Insts, LoongArchInstrNameIndices, LoongArchInstrNameData, nullptr, nullptr, 2498);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace LoongArch_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace LoongArch_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::LoongArch_MC {


} // namespace llvm_ks::LoongArch_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::LoongArch_MC {

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_IsLA64Bit = 4,
  Feature_IsLA32Bit = 3,
  Feature_HasLaGlobalWithPcrelBit = 1,
  Feature_HasLaGlobalWithAbsBit = 0,
  Feature_HasLaLocalWithAbsBit = 2,
};

inline FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) {
  FeatureBitset Features;
  if (FB[LoongArch::Feature64Bit])
    Features.set(Feature_IsLA64Bit);
  if (!FB[LoongArch::Feature64Bit])
    Features.set(Feature_IsLA32Bit);
  if (FB[LoongArch::LaGlobalWithPcrel])
    Features.set(Feature_HasLaGlobalWithPcrelBit);
  if (FB[LoongArch::LaGlobalWithAbs])
    Features.set(Feature_HasLaGlobalWithAbsBit);
  if (FB[LoongArch::LaLocalWithAbs])
    Features.set(Feature_HasLaLocalWithAbsBit);
  return Features;
}

inline FeatureBitset computeRequiredFeatures(unsigned Opcode) {
  enum : uint8_t {
    CEFBS_None,
    CEFBS_IsLA32,
    CEFBS_IsLA64,
  };

  static constexpr FeatureBitset FeatureBitsets[] = {
    {}, // CEFBS_None
    {Feature_IsLA32Bit, },
    {Feature_IsLA64Bit, },
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
    CEFBS_IsLA32, // BuildPairF64Pseudo
    CEFBS_None, // PROBED_STACKALLOC
    CEFBS_None, // PROBED_STACKALLOC_DYN
    CEFBS_IsLA64, // PseudoAddTPRel_D
    CEFBS_IsLA32, // PseudoAddTPRel_W
    CEFBS_None, // PseudoAtomicLoadAdd32
    CEFBS_None, // PseudoAtomicLoadAnd32
    CEFBS_None, // PseudoAtomicLoadMax32
    CEFBS_None, // PseudoAtomicLoadMin32
    CEFBS_None, // PseudoAtomicLoadNand32
    CEFBS_None, // PseudoAtomicLoadNand64
    CEFBS_None, // PseudoAtomicLoadOr32
    CEFBS_None, // PseudoAtomicLoadSub32
    CEFBS_None, // PseudoAtomicLoadUMax32
    CEFBS_None, // PseudoAtomicLoadUMin32
    CEFBS_None, // PseudoAtomicLoadXor32
    CEFBS_IsLA64, // PseudoAtomicStoreD
    CEFBS_None, // PseudoAtomicStoreW
    CEFBS_None, // PseudoAtomicSwap32
    CEFBS_None, // PseudoBR
    CEFBS_None, // PseudoBRIND
    CEFBS_None, // PseudoB_TAIL
    CEFBS_None, // PseudoCALL
    CEFBS_None, // PseudoCALL30
    CEFBS_IsLA64, // PseudoCALL36
    CEFBS_None, // PseudoCALLIndirect
    CEFBS_None, // PseudoCALL_LARGE
    CEFBS_None, // PseudoCALL_MEDIUM
    CEFBS_None, // PseudoCALL_SMALL
    CEFBS_None, // PseudoCTPOP_B
    CEFBS_IsLA64, // PseudoCTPOP_D
    CEFBS_None, // PseudoCTPOP_H
    CEFBS_IsLA32, // PseudoCTPOP_H_LA32
    CEFBS_IsLA64, // PseudoCTPOP_W
    CEFBS_IsLA32, // PseudoCTPOP_W_LA32
    CEFBS_None, // PseudoCmpXchg128
    CEFBS_None, // PseudoCmpXchg128Acquire
    CEFBS_None, // PseudoCmpXchg32
    CEFBS_None, // PseudoCmpXchg64
    CEFBS_None, // PseudoCopyCFR
    CEFBS_None, // PseudoDESC_CALL
    CEFBS_None, // PseudoJIRL_CALL
    CEFBS_None, // PseudoJIRL_TAIL
    CEFBS_None, // PseudoLA_ABS
    CEFBS_None, // PseudoLA_ABS_LARGE
    CEFBS_None, // PseudoLA_GOT
    CEFBS_IsLA64, // PseudoLA_GOT_LARGE
    CEFBS_None, // PseudoLA_PCREL
    CEFBS_IsLA64, // PseudoLA_PCREL_LARGE
    CEFBS_None, // PseudoLA_TLS_DESC
    CEFBS_IsLA64, // PseudoLA_TLS_DESC_LARGE
    CEFBS_None, // PseudoLA_TLS_GD
    CEFBS_IsLA64, // PseudoLA_TLS_GD_LARGE
    CEFBS_None, // PseudoLA_TLS_IE
    CEFBS_IsLA64, // PseudoLA_TLS_IE_LARGE
    CEFBS_None, // PseudoLA_TLS_LD
    CEFBS_IsLA64, // PseudoLA_TLS_LD_LARGE
    CEFBS_None, // PseudoLA_TLS_LE
    CEFBS_None, // PseudoLD_CFR
    CEFBS_IsLA64, // PseudoLI_D
    CEFBS_None, // PseudoLI_W
    CEFBS_None, // PseudoMaskedAtomicLoadAdd32
    CEFBS_None, // PseudoMaskedAtomicLoadMax32
    CEFBS_None, // PseudoMaskedAtomicLoadMin32
    CEFBS_None, // PseudoMaskedAtomicLoadNand32
    CEFBS_None, // PseudoMaskedAtomicLoadSub32
    CEFBS_None, // PseudoMaskedAtomicLoadUMax32
    CEFBS_None, // PseudoMaskedAtomicLoadUMin32
    CEFBS_None, // PseudoMaskedAtomicSwap32
    CEFBS_None, // PseudoMaskedCmpXchg32
    CEFBS_None, // PseudoRET
    CEFBS_None, // PseudoST_CFR
    CEFBS_None, // PseudoTAIL
    CEFBS_None, // PseudoTAIL30
    CEFBS_IsLA64, // PseudoTAIL36
    CEFBS_None, // PseudoTAILIndirect
    CEFBS_None, // PseudoTAIL_LARGE
    CEFBS_None, // PseudoTAIL_MEDIUM
    CEFBS_None, // PseudoTAIL_SMALL
    CEFBS_None, // PseudoUNIMP
    CEFBS_None, // PseudoVBNZ
    CEFBS_None, // PseudoVBNZ_B
    CEFBS_None, // PseudoVBNZ_D
    CEFBS_None, // PseudoVBNZ_H
    CEFBS_None, // PseudoVBNZ_W
    CEFBS_None, // PseudoVBZ
    CEFBS_None, // PseudoVBZ_B
    CEFBS_None, // PseudoVBZ_D
    CEFBS_None, // PseudoVBZ_H
    CEFBS_None, // PseudoVBZ_W
    CEFBS_None, // PseudoVMSKEQZ_B
    CEFBS_None, // PseudoVMSKGEZ_B
    CEFBS_None, // PseudoVMSKLTZ_B
    CEFBS_None, // PseudoVMSKLTZ_D
    CEFBS_None, // PseudoVMSKLTZ_H
    CEFBS_None, // PseudoVMSKLTZ_W
    CEFBS_None, // PseudoVMSKNEZ_B
    CEFBS_None, // PseudoVREPLI_B
    CEFBS_None, // PseudoVREPLI_D
    CEFBS_None, // PseudoVREPLI_H
    CEFBS_None, // PseudoVREPLI_W
    CEFBS_None, // PseudoXVBNZ
    CEFBS_None, // PseudoXVBNZ_B
    CEFBS_None, // PseudoXVBNZ_D
    CEFBS_None, // PseudoXVBNZ_H
    CEFBS_None, // PseudoXVBNZ_W
    CEFBS_None, // PseudoXVBZ
    CEFBS_None, // PseudoXVBZ_B
    CEFBS_None, // PseudoXVBZ_D
    CEFBS_None, // PseudoXVBZ_H
    CEFBS_None, // PseudoXVBZ_W
    CEFBS_None, // PseudoXVINSGR2VR_B
    CEFBS_None, // PseudoXVINSGR2VR_H
    CEFBS_None, // PseudoXVMSKEQZ_B
    CEFBS_None, // PseudoXVMSKGEZ_B
    CEFBS_None, // PseudoXVMSKLTZ_B
    CEFBS_None, // PseudoXVMSKLTZ_D
    CEFBS_None, // PseudoXVMSKLTZ_H
    CEFBS_None, // PseudoXVMSKLTZ_W
    CEFBS_None, // PseudoXVMSKNEZ_B
    CEFBS_None, // PseudoXVREPLI_B
    CEFBS_None, // PseudoXVREPLI_D
    CEFBS_None, // PseudoXVREPLI_H
    CEFBS_None, // PseudoXVREPLI_W
    CEFBS_None, // RDFCSR
    CEFBS_None, // Select_GPR_Using_CC_GPR
    CEFBS_IsLA32, // SplitPairF64Pseudo
    CEFBS_None, // WRFCSR
    CEFBS_None, // ADC_B
    CEFBS_IsLA64, // ADC_D
    CEFBS_None, // ADC_H
    CEFBS_None, // ADC_W
    CEFBS_IsLA64, // ADDI_D
    CEFBS_None, // ADDI_W
    CEFBS_IsLA64, // ADDU12I_D
    CEFBS_None, // ADDU12I_W
    CEFBS_IsLA64, // ADDU16I_D
    CEFBS_IsLA64, // ADD_D
    CEFBS_None, // ADD_W
    CEFBS_IsLA64, // ALSL_D
    CEFBS_None, // ALSL_W
    CEFBS_IsLA64, // ALSL_WU
    CEFBS_IsLA64, // AMADD_B
    CEFBS_IsLA64, // AMADD_D
    CEFBS_IsLA64, // AMADD_H
    CEFBS_IsLA64, // AMADD_W
    CEFBS_IsLA64, // AMADD__DB_B
    CEFBS_IsLA64, // AMADD__DB_D
    CEFBS_IsLA64, // AMADD__DB_H
    CEFBS_IsLA64, // AMADD__DB_W
    CEFBS_IsLA64, // AMAND_D
    CEFBS_IsLA64, // AMAND_W
    CEFBS_IsLA64, // AMAND__DB_D
    CEFBS_IsLA64, // AMAND__DB_W
    CEFBS_IsLA64, // AMCAS_B
    CEFBS_IsLA64, // AMCAS_D
    CEFBS_IsLA64, // AMCAS_H
    CEFBS_IsLA64, // AMCAS_W
    CEFBS_IsLA64, // AMCAS__DB_B
    CEFBS_IsLA64, // AMCAS__DB_D
    CEFBS_IsLA64, // AMCAS__DB_H
    CEFBS_IsLA64, // AMCAS__DB_W
    CEFBS_IsLA64, // AMMAX_D
    CEFBS_IsLA64, // AMMAX_DU
    CEFBS_IsLA64, // AMMAX_W
    CEFBS_IsLA64, // AMMAX_WU
    CEFBS_IsLA64, // AMMAX__DB_D
    CEFBS_IsLA64, // AMMAX__DB_DU
    CEFBS_IsLA64, // AMMAX__DB_W
    CEFBS_IsLA64, // AMMAX__DB_WU
    CEFBS_IsLA64, // AMMIN_D
    CEFBS_IsLA64, // AMMIN_DU
    CEFBS_IsLA64, // AMMIN_W
    CEFBS_IsLA64, // AMMIN_WU
    CEFBS_IsLA64, // AMMIN__DB_D
    CEFBS_IsLA64, // AMMIN__DB_DU
    CEFBS_IsLA64, // AMMIN__DB_W
    CEFBS_IsLA64, // AMMIN__DB_WU
    CEFBS_IsLA64, // AMOR_D
    CEFBS_IsLA64, // AMOR_W
    CEFBS_IsLA64, // AMOR__DB_D
    CEFBS_IsLA64, // AMOR__DB_W
    CEFBS_IsLA64, // AMSWAP_B
    CEFBS_IsLA64, // AMSWAP_D
    CEFBS_IsLA64, // AMSWAP_H
    CEFBS_IsLA64, // AMSWAP_W
    CEFBS_IsLA64, // AMSWAP__DB_B
    CEFBS_IsLA64, // AMSWAP__DB_D
    CEFBS_IsLA64, // AMSWAP__DB_H
    CEFBS_IsLA64, // AMSWAP__DB_W
    CEFBS_IsLA64, // AMXOR_D
    CEFBS_IsLA64, // AMXOR_W
    CEFBS_IsLA64, // AMXOR__DB_D
    CEFBS_IsLA64, // AMXOR__DB_W
    CEFBS_None, // AND
    CEFBS_None, // ANDI
    CEFBS_None, // ANDN
    CEFBS_None, // ARMADC_W
    CEFBS_None, // ARMADD_W
    CEFBS_None, // ARMAND_W
    CEFBS_None, // ARMMFFLAG
    CEFBS_None, // ARMMOVE
    CEFBS_IsLA64, // ARMMOV_D
    CEFBS_None, // ARMMOV_W
    CEFBS_None, // ARMMTFLAG
    CEFBS_None, // ARMNOT_W
    CEFBS_None, // ARMOR_W
    CEFBS_None, // ARMROTRI_W
    CEFBS_None, // ARMROTR_W
    CEFBS_None, // ARMRRX_W
    CEFBS_None, // ARMSBC_W
    CEFBS_None, // ARMSLLI_W
    CEFBS_None, // ARMSLL_W
    CEFBS_None, // ARMSRAI_W
    CEFBS_None, // ARMSRA_W
    CEFBS_None, // ARMSRLI_W
    CEFBS_None, // ARMSRL_W
    CEFBS_None, // ARMSUB_W
    CEFBS_None, // ARMXOR_W
    CEFBS_IsLA64, // ASRTGT_D
    CEFBS_IsLA64, // ASRTLE_D
    CEFBS_None, // B
    CEFBS_None, // BCEQZ
    CEFBS_None, // BCNEZ
    CEFBS_None, // BEQ
    CEFBS_None, // BEQZ
    CEFBS_None, // BGE
    CEFBS_None, // BGEU
    CEFBS_None, // BITREV_4B
    CEFBS_IsLA64, // BITREV_8B
    CEFBS_IsLA64, // BITREV_D
    CEFBS_None, // BITREV_W
    CEFBS_None, // BL
    CEFBS_None, // BLT
    CEFBS_None, // BLTU
    CEFBS_None, // BNE
    CEFBS_None, // BNEZ
    CEFBS_None, // BREAK
    CEFBS_IsLA64, // BSTRINS_D
    CEFBS_None, // BSTRINS_W
    CEFBS_IsLA64, // BSTRPICK_D
    CEFBS_None, // BSTRPICK_W
    CEFBS_IsLA64, // BYTEPICK_D
    CEFBS_None, // BYTEPICK_W
    CEFBS_None, // CACOP
    CEFBS_IsLA64, // CLO_D
    CEFBS_None, // CLO_W
    CEFBS_IsLA64, // CLZ_D
    CEFBS_None, // CLZ_W
    CEFBS_None, // CPUCFG
    CEFBS_IsLA64, // CRCC_W_B_W
    CEFBS_IsLA64, // CRCC_W_D_W
    CEFBS_IsLA64, // CRCC_W_H_W
    CEFBS_IsLA64, // CRCC_W_W_W
    CEFBS_IsLA64, // CRC_W_B_W
    CEFBS_IsLA64, // CRC_W_D_W
    CEFBS_IsLA64, // CRC_W_H_W
    CEFBS_IsLA64, // CRC_W_W_W
    CEFBS_None, // CSRRD
    CEFBS_None, // CSRWR
    CEFBS_None, // CSRXCHG
    CEFBS_IsLA64, // CTO_D
    CEFBS_None, // CTO_W
    CEFBS_IsLA64, // CTZ_D
    CEFBS_None, // CTZ_W
    CEFBS_None, // DBAR
    CEFBS_None, // DBCL
    CEFBS_IsLA64, // DIV_D
    CEFBS_IsLA64, // DIV_DU
    CEFBS_None, // DIV_W
    CEFBS_None, // DIV_WU
    CEFBS_None, // ERTN
    CEFBS_None, // EXT_W_B
    CEFBS_None, // EXT_W_H
    CEFBS_None, // FABS_D
    CEFBS_None, // FABS_S
    CEFBS_None, // FADD_D
    CEFBS_None, // FADD_S
    CEFBS_None, // FCLASS_D
    CEFBS_None, // FCLASS_S
    CEFBS_None, // FCMP_CAF_D
    CEFBS_None, // FCMP_CAF_S
    CEFBS_None, // FCMP_CEQ_D
    CEFBS_None, // FCMP_CEQ_S
    CEFBS_None, // FCMP_CLE_D
    CEFBS_None, // FCMP_CLE_S
    CEFBS_None, // FCMP_CLT_D
    CEFBS_None, // FCMP_CLT_S
    CEFBS_None, // FCMP_CNE_D
    CEFBS_None, // FCMP_CNE_S
    CEFBS_None, // FCMP_COR_D
    CEFBS_None, // FCMP_COR_S
    CEFBS_None, // FCMP_CUEQ_D
    CEFBS_None, // FCMP_CUEQ_S
    CEFBS_None, // FCMP_CULE_D
    CEFBS_None, // FCMP_CULE_S
    CEFBS_None, // FCMP_CULT_D
    CEFBS_None, // FCMP_CULT_S
    CEFBS_None, // FCMP_CUNE_D
    CEFBS_None, // FCMP_CUNE_S
    CEFBS_None, // FCMP_CUN_D
    CEFBS_None, // FCMP_CUN_S
    CEFBS_None, // FCMP_SAF_D
    CEFBS_None, // FCMP_SAF_S
    CEFBS_None, // FCMP_SEQ_D
    CEFBS_None, // FCMP_SEQ_S
    CEFBS_None, // FCMP_SLE_D
    CEFBS_None, // FCMP_SLE_S
    CEFBS_None, // FCMP_SLT_D
    CEFBS_None, // FCMP_SLT_S
    CEFBS_None, // FCMP_SNE_D
    CEFBS_None, // FCMP_SNE_S
    CEFBS_None, // FCMP_SOR_D
    CEFBS_None, // FCMP_SOR_S
    CEFBS_None, // FCMP_SUEQ_D
    CEFBS_None, // FCMP_SUEQ_S
    CEFBS_None, // FCMP_SULE_D
    CEFBS_None, // FCMP_SULE_S
    CEFBS_None, // FCMP_SULT_D
    CEFBS_None, // FCMP_SULT_S
    CEFBS_None, // FCMP_SUNE_D
    CEFBS_None, // FCMP_SUNE_S
    CEFBS_None, // FCMP_SUN_D
    CEFBS_None, // FCMP_SUN_S
    CEFBS_None, // FCOPYSIGN_D
    CEFBS_None, // FCOPYSIGN_S
    CEFBS_None, // FCVT_D_LD
    CEFBS_None, // FCVT_D_S
    CEFBS_None, // FCVT_LD_D
    CEFBS_None, // FCVT_S_D
    CEFBS_None, // FCVT_UD_D
    CEFBS_None, // FDIV_D
    CEFBS_None, // FDIV_S
    CEFBS_None, // FFINT_D_L
    CEFBS_None, // FFINT_D_W
    CEFBS_None, // FFINT_S_L
    CEFBS_None, // FFINT_S_W
    CEFBS_None, // FLDGT_D
    CEFBS_None, // FLDGT_S
    CEFBS_None, // FLDLE_D
    CEFBS_None, // FLDLE_S
    CEFBS_None, // FLDX_D
    CEFBS_None, // FLDX_S
    CEFBS_None, // FLD_D
    CEFBS_None, // FLD_S
    CEFBS_None, // FLOGB_D
    CEFBS_None, // FLOGB_S
    CEFBS_None, // FMADD_D
    CEFBS_None, // FMADD_S
    CEFBS_None, // FMAXA_D
    CEFBS_None, // FMAXA_S
    CEFBS_None, // FMAX_D
    CEFBS_None, // FMAX_S
    CEFBS_None, // FMINA_D
    CEFBS_None, // FMINA_S
    CEFBS_None, // FMIN_D
    CEFBS_None, // FMIN_S
    CEFBS_None, // FMOV_D
    CEFBS_None, // FMOV_S
    CEFBS_None, // FMSUB_D
    CEFBS_None, // FMSUB_S
    CEFBS_None, // FMUL_D
    CEFBS_None, // FMUL_S
    CEFBS_None, // FNEG_D
    CEFBS_None, // FNEG_S
    CEFBS_None, // FNMADD_D
    CEFBS_None, // FNMADD_S
    CEFBS_None, // FNMSUB_D
    CEFBS_None, // FNMSUB_S
    CEFBS_None, // FRECIPE_D
    CEFBS_None, // FRECIPE_S
    CEFBS_None, // FRECIP_D
    CEFBS_None, // FRECIP_S
    CEFBS_None, // FRINT_D
    CEFBS_None, // FRINT_S
    CEFBS_None, // FRSQRTE_D
    CEFBS_None, // FRSQRTE_S
    CEFBS_None, // FRSQRT_D
    CEFBS_None, // FRSQRT_S
    CEFBS_None, // FSCALEB_D
    CEFBS_None, // FSCALEB_S
    CEFBS_None, // FSEL_xD
    CEFBS_None, // FSEL_xS
    CEFBS_None, // FSQRT_D
    CEFBS_None, // FSQRT_S
    CEFBS_None, // FSTGT_D
    CEFBS_None, // FSTGT_S
    CEFBS_None, // FSTLE_D
    CEFBS_None, // FSTLE_S
    CEFBS_None, // FSTX_D
    CEFBS_None, // FSTX_S
    CEFBS_None, // FST_D
    CEFBS_None, // FST_S
    CEFBS_None, // FSUB_D
    CEFBS_None, // FSUB_S
    CEFBS_None, // FTINTRM_L_D
    CEFBS_None, // FTINTRM_L_S
    CEFBS_None, // FTINTRM_W_D
    CEFBS_None, // FTINTRM_W_S
    CEFBS_None, // FTINTRNE_L_D
    CEFBS_None, // FTINTRNE_L_S
    CEFBS_None, // FTINTRNE_W_D
    CEFBS_None, // FTINTRNE_W_S
    CEFBS_None, // FTINTRP_L_D
    CEFBS_None, // FTINTRP_L_S
    CEFBS_None, // FTINTRP_W_D
    CEFBS_None, // FTINTRP_W_S
    CEFBS_None, // FTINTRZ_L_D
    CEFBS_None, // FTINTRZ_L_S
    CEFBS_None, // FTINTRZ_W_D
    CEFBS_None, // FTINTRZ_W_S
    CEFBS_None, // FTINT_L_D
    CEFBS_None, // FTINT_L_S
    CEFBS_None, // FTINT_W_D
    CEFBS_None, // FTINT_W_S
    CEFBS_None, // GCSRRD
    CEFBS_None, // GCSRWR
    CEFBS_None, // GCSRXCHG
    CEFBS_None, // GTLBFLUSH
    CEFBS_None, // HVCL
    CEFBS_None, // IBAR
    CEFBS_None, // IDLE
    CEFBS_None, // INVTLB
    CEFBS_None, // IOCSRRD_B
    CEFBS_IsLA64, // IOCSRRD_D
    CEFBS_None, // IOCSRRD_H
    CEFBS_None, // IOCSRRD_W
    CEFBS_None, // IOCSRWR_B
    CEFBS_IsLA64, // IOCSRWR_D
    CEFBS_None, // IOCSRWR_H
    CEFBS_None, // IOCSRWR_W
    CEFBS_None, // JIRL
    CEFBS_None, // JISCR0
    CEFBS_None, // JISCR1
    CEFBS_None, // LDDIR
    CEFBS_IsLA64, // LDGT_B
    CEFBS_IsLA64, // LDGT_D
    CEFBS_IsLA64, // LDGT_H
    CEFBS_IsLA64, // LDGT_W
    CEFBS_IsLA64, // LDLE_B
    CEFBS_IsLA64, // LDLE_D
    CEFBS_IsLA64, // LDLE_H
    CEFBS_IsLA64, // LDLE_W
    CEFBS_IsLA64, // LDL_D
    CEFBS_None, // LDL_W
    CEFBS_None, // LDPTE
    CEFBS_IsLA64, // LDPTR_D
    CEFBS_IsLA64, // LDPTR_W
    CEFBS_IsLA64, // LDR_D
    CEFBS_None, // LDR_W
    CEFBS_IsLA64, // LDX_B
    CEFBS_IsLA64, // LDX_BU
    CEFBS_IsLA64, // LDX_D
    CEFBS_IsLA64, // LDX_H
    CEFBS_IsLA64, // LDX_HU
    CEFBS_IsLA64, // LDX_W
    CEFBS_IsLA64, // LDX_WU
    CEFBS_None, // LD_B
    CEFBS_None, // LD_BU
    CEFBS_IsLA64, // LD_D
    CEFBS_None, // LD_H
    CEFBS_None, // LD_HU
    CEFBS_None, // LD_W
    CEFBS_IsLA64, // LD_WU
    CEFBS_IsLA64, // LLACQ_D
    CEFBS_IsLA64, // LLACQ_W
    CEFBS_IsLA64, // LL_D
    CEFBS_None, // LL_W
    CEFBS_None, // LU12I_W
    CEFBS_IsLA64, // LU32I_D
    CEFBS_IsLA64, // LU52I_D
    CEFBS_None, // MASKEQZ
    CEFBS_None, // MASKNEZ
    CEFBS_IsLA64, // MOD_D
    CEFBS_IsLA64, // MOD_DU
    CEFBS_None, // MOD_W
    CEFBS_None, // MOD_WU
    CEFBS_None, // MOVCF2FR_xS
    CEFBS_None, // MOVCF2GR
    CEFBS_None, // MOVFCSR2GR
    CEFBS_None, // MOVFR2CF_xS
    CEFBS_IsLA64, // MOVFR2GR_D
    CEFBS_None, // MOVFR2GR_S
    CEFBS_None, // MOVFR2GR_S_64
    CEFBS_None, // MOVFRH2GR_S
    CEFBS_None, // MOVGR2CF
    CEFBS_None, // MOVGR2FCSR
    CEFBS_None, // MOVGR2FRH_W
    CEFBS_IsLA64, // MOVGR2FR_D
    CEFBS_None, // MOVGR2FR_W
    CEFBS_IsLA32, // MOVGR2FR_W_64
    CEFBS_None, // MOVGR2SCR
    CEFBS_None, // MOVSCR2GR
    CEFBS_IsLA64, // MULH_D
    CEFBS_IsLA64, // MULH_DU
    CEFBS_None, // MULH_W
    CEFBS_None, // MULH_WU
    CEFBS_IsLA64, // MULW_D_W
    CEFBS_IsLA64, // MULW_D_WU
    CEFBS_IsLA64, // MUL_D
    CEFBS_None, // MUL_W
    CEFBS_None, // NOR
    CEFBS_None, // OR
    CEFBS_None, // ORI
    CEFBS_None, // ORN
    CEFBS_None, // PCADDI
    CEFBS_None, // PCADDU12I
    CEFBS_IsLA64, // PCADDU18I
    CEFBS_None, // PCALAU12I
    CEFBS_None, // PRELD
    CEFBS_IsLA64, // PRELDX
    CEFBS_None, // RCRI_B
    CEFBS_IsLA64, // RCRI_D
    CEFBS_None, // RCRI_H
    CEFBS_None, // RCRI_W
    CEFBS_None, // RCR_B
    CEFBS_IsLA64, // RCR_D
    CEFBS_None, // RCR_H
    CEFBS_None, // RCR_W
    CEFBS_None, // RDTIMEH_W
    CEFBS_None, // RDTIMEL_W
    CEFBS_IsLA64, // RDTIME_D
    CEFBS_None, // REVB_2H
    CEFBS_IsLA64, // REVB_2W
    CEFBS_IsLA64, // REVB_4H
    CEFBS_IsLA64, // REVB_D
    CEFBS_IsLA64, // REVH_2W
    CEFBS_IsLA64, // REVH_D
    CEFBS_None, // ROTRI_B
    CEFBS_IsLA64, // ROTRI_D
    CEFBS_None, // ROTRI_H
    CEFBS_None, // ROTRI_W
    CEFBS_None, // ROTR_B
    CEFBS_IsLA64, // ROTR_D
    CEFBS_None, // ROTR_H
    CEFBS_None, // ROTR_W
    CEFBS_None, // SBC_B
    CEFBS_IsLA64, // SBC_D
    CEFBS_None, // SBC_H
    CEFBS_None, // SBC_W
    CEFBS_IsLA64, // SCREL_D
    CEFBS_IsLA64, // SCREL_W
    CEFBS_IsLA64, // SC_D
    CEFBS_IsLA64, // SC_Q
    CEFBS_None, // SC_W
    CEFBS_None, // SETARMJ
    CEFBS_None, // SETX86J
    CEFBS_None, // SETX86LOOPE
    CEFBS_None, // SETX86LOOPNE
    CEFBS_None, // SET_CFR_FALSE
    CEFBS_None, // SET_CFR_TRUE
    CEFBS_IsLA64, // SLLI_D
    CEFBS_None, // SLLI_W
    CEFBS_IsLA64, // SLL_D
    CEFBS_None, // SLL_W
    CEFBS_None, // SLT
    CEFBS_None, // SLTI
    CEFBS_None, // SLTU
    CEFBS_None, // SLTUI
    CEFBS_IsLA64, // SRAI_D
    CEFBS_None, // SRAI_W
    CEFBS_IsLA64, // SRA_D
    CEFBS_None, // SRA_W
    CEFBS_IsLA64, // SRLI_D
    CEFBS_None, // SRLI_W
    CEFBS_IsLA64, // SRL_D
    CEFBS_None, // SRL_W
    CEFBS_IsLA64, // STGT_B
    CEFBS_IsLA64, // STGT_D
    CEFBS_IsLA64, // STGT_H
    CEFBS_IsLA64, // STGT_W
    CEFBS_IsLA64, // STLE_B
    CEFBS_IsLA64, // STLE_D
    CEFBS_IsLA64, // STLE_H
    CEFBS_IsLA64, // STLE_W
    CEFBS_IsLA64, // STL_D
    CEFBS_None, // STL_W
    CEFBS_IsLA64, // STPTR_D
    CEFBS_IsLA64, // STPTR_W
    CEFBS_IsLA64, // STR_D
    CEFBS_None, // STR_W
    CEFBS_IsLA64, // STX_B
    CEFBS_IsLA64, // STX_D
    CEFBS_IsLA64, // STX_H
    CEFBS_IsLA64, // STX_W
    CEFBS_None, // ST_B
    CEFBS_IsLA64, // ST_D
    CEFBS_None, // ST_H
    CEFBS_None, // ST_W
    CEFBS_IsLA64, // SUB_D
    CEFBS_None, // SUB_W
    CEFBS_None, // SYSCALL
    CEFBS_None, // TLBCLR
    CEFBS_None, // TLBFILL
    CEFBS_None, // TLBFLUSH
    CEFBS_None, // TLBRD
    CEFBS_None, // TLBSRCH
    CEFBS_None, // TLBWR
    CEFBS_None, // UD
    CEFBS_None, // VABSD_B
    CEFBS_None, // VABSD_BU
    CEFBS_None, // VABSD_D
    CEFBS_None, // VABSD_DU
    CEFBS_None, // VABSD_H
    CEFBS_None, // VABSD_HU
    CEFBS_None, // VABSD_W
    CEFBS_None, // VABSD_WU
    CEFBS_None, // VADDA_B
    CEFBS_None, // VADDA_D
    CEFBS_None, // VADDA_H
    CEFBS_None, // VADDA_W
    CEFBS_None, // VADDI_BU
    CEFBS_None, // VADDI_DU
    CEFBS_None, // VADDI_HU
    CEFBS_None, // VADDI_WU
    CEFBS_None, // VADDWEV_D_W
    CEFBS_None, // VADDWEV_D_WU
    CEFBS_None, // VADDWEV_D_WU_W
    CEFBS_None, // VADDWEV_H_B
    CEFBS_None, // VADDWEV_H_BU
    CEFBS_None, // VADDWEV_H_BU_B
    CEFBS_None, // VADDWEV_Q_D
    CEFBS_None, // VADDWEV_Q_DU
    CEFBS_None, // VADDWEV_Q_DU_D
    CEFBS_None, // VADDWEV_W_H
    CEFBS_None, // VADDWEV_W_HU
    CEFBS_None, // VADDWEV_W_HU_H
    CEFBS_None, // VADDWOD_D_W
    CEFBS_None, // VADDWOD_D_WU
    CEFBS_None, // VADDWOD_D_WU_W
    CEFBS_None, // VADDWOD_H_B
    CEFBS_None, // VADDWOD_H_BU
    CEFBS_None, // VADDWOD_H_BU_B
    CEFBS_None, // VADDWOD_Q_D
    CEFBS_None, // VADDWOD_Q_DU
    CEFBS_None, // VADDWOD_Q_DU_D
    CEFBS_None, // VADDWOD_W_H
    CEFBS_None, // VADDWOD_W_HU
    CEFBS_None, // VADDWOD_W_HU_H
    CEFBS_None, // VADD_B
    CEFBS_None, // VADD_D
    CEFBS_None, // VADD_H
    CEFBS_None, // VADD_Q
    CEFBS_None, // VADD_W
    CEFBS_None, // VANDI_B
    CEFBS_None, // VANDN_V
    CEFBS_None, // VAND_V
    CEFBS_None, // VAVGR_B
    CEFBS_None, // VAVGR_BU
    CEFBS_None, // VAVGR_D
    CEFBS_None, // VAVGR_DU
    CEFBS_None, // VAVGR_H
    CEFBS_None, // VAVGR_HU
    CEFBS_None, // VAVGR_W
    CEFBS_None, // VAVGR_WU
    CEFBS_None, // VAVG_B
    CEFBS_None, // VAVG_BU
    CEFBS_None, // VAVG_D
    CEFBS_None, // VAVG_DU
    CEFBS_None, // VAVG_H
    CEFBS_None, // VAVG_HU
    CEFBS_None, // VAVG_W
    CEFBS_None, // VAVG_WU
    CEFBS_None, // VBITCLRI_B
    CEFBS_None, // VBITCLRI_D
    CEFBS_None, // VBITCLRI_H
    CEFBS_None, // VBITCLRI_W
    CEFBS_None, // VBITCLR_B
    CEFBS_None, // VBITCLR_D
    CEFBS_None, // VBITCLR_H
    CEFBS_None, // VBITCLR_W
    CEFBS_None, // VBITREVI_B
    CEFBS_None, // VBITREVI_D
    CEFBS_None, // VBITREVI_H
    CEFBS_None, // VBITREVI_W
    CEFBS_None, // VBITREV_B
    CEFBS_None, // VBITREV_D
    CEFBS_None, // VBITREV_H
    CEFBS_None, // VBITREV_W
    CEFBS_None, // VBITSELI_B
    CEFBS_None, // VBITSEL_V
    CEFBS_None, // VBITSETI_B
    CEFBS_None, // VBITSETI_D
    CEFBS_None, // VBITSETI_H
    CEFBS_None, // VBITSETI_W
    CEFBS_None, // VBITSET_B
    CEFBS_None, // VBITSET_D
    CEFBS_None, // VBITSET_H
    CEFBS_None, // VBITSET_W
    CEFBS_None, // VBSLL_V
    CEFBS_None, // VBSRL_V
    CEFBS_None, // VCLO_B
    CEFBS_None, // VCLO_D
    CEFBS_None, // VCLO_H
    CEFBS_None, // VCLO_W
    CEFBS_None, // VCLZ_B
    CEFBS_None, // VCLZ_D
    CEFBS_None, // VCLZ_H
    CEFBS_None, // VCLZ_W
    CEFBS_None, // VDIV_B
    CEFBS_None, // VDIV_BU
    CEFBS_None, // VDIV_D
    CEFBS_None, // VDIV_DU
    CEFBS_None, // VDIV_H
    CEFBS_None, // VDIV_HU
    CEFBS_None, // VDIV_W
    CEFBS_None, // VDIV_WU
    CEFBS_None, // VEXT2XV_DU_BU
    CEFBS_None, // VEXT2XV_DU_HU
    CEFBS_None, // VEXT2XV_DU_WU
    CEFBS_None, // VEXT2XV_D_B
    CEFBS_None, // VEXT2XV_D_H
    CEFBS_None, // VEXT2XV_D_W
    CEFBS_None, // VEXT2XV_HU_BU
    CEFBS_None, // VEXT2XV_H_B
    CEFBS_None, // VEXT2XV_WU_BU
    CEFBS_None, // VEXT2XV_WU_HU
    CEFBS_None, // VEXT2XV_W_B
    CEFBS_None, // VEXT2XV_W_H
    CEFBS_None, // VEXTH_DU_WU
    CEFBS_None, // VEXTH_D_W
    CEFBS_None, // VEXTH_HU_BU
    CEFBS_None, // VEXTH_H_B
    CEFBS_None, // VEXTH_QU_DU
    CEFBS_None, // VEXTH_Q_D
    CEFBS_None, // VEXTH_WU_HU
    CEFBS_None, // VEXTH_W_H
    CEFBS_None, // VEXTL_QU_DU
    CEFBS_None, // VEXTL_Q_D
    CEFBS_None, // VEXTRINS_B
    CEFBS_None, // VEXTRINS_D
    CEFBS_None, // VEXTRINS_H
    CEFBS_None, // VEXTRINS_W
    CEFBS_None, // VFADD_D
    CEFBS_None, // VFADD_S
    CEFBS_None, // VFCLASS_D
    CEFBS_None, // VFCLASS_S
    CEFBS_None, // VFCMP_CAF_D
    CEFBS_None, // VFCMP_CAF_S
    CEFBS_None, // VFCMP_CEQ_D
    CEFBS_None, // VFCMP_CEQ_S
    CEFBS_None, // VFCMP_CLE_D
    CEFBS_None, // VFCMP_CLE_S
    CEFBS_None, // VFCMP_CLT_D
    CEFBS_None, // VFCMP_CLT_S
    CEFBS_None, // VFCMP_CNE_D
    CEFBS_None, // VFCMP_CNE_S
    CEFBS_None, // VFCMP_COR_D
    CEFBS_None, // VFCMP_COR_S
    CEFBS_None, // VFCMP_CUEQ_D
    CEFBS_None, // VFCMP_CUEQ_S
    CEFBS_None, // VFCMP_CULE_D
    CEFBS_None, // VFCMP_CULE_S
    CEFBS_None, // VFCMP_CULT_D
    CEFBS_None, // VFCMP_CULT_S
    CEFBS_None, // VFCMP_CUNE_D
    CEFBS_None, // VFCMP_CUNE_S
    CEFBS_None, // VFCMP_CUN_D
    CEFBS_None, // VFCMP_CUN_S
    CEFBS_None, // VFCMP_SAF_D
    CEFBS_None, // VFCMP_SAF_S
    CEFBS_None, // VFCMP_SEQ_D
    CEFBS_None, // VFCMP_SEQ_S
    CEFBS_None, // VFCMP_SLE_D
    CEFBS_None, // VFCMP_SLE_S
    CEFBS_None, // VFCMP_SLT_D
    CEFBS_None, // VFCMP_SLT_S
    CEFBS_None, // VFCMP_SNE_D
    CEFBS_None, // VFCMP_SNE_S
    CEFBS_None, // VFCMP_SOR_D
    CEFBS_None, // VFCMP_SOR_S
    CEFBS_None, // VFCMP_SUEQ_D
    CEFBS_None, // VFCMP_SUEQ_S
    CEFBS_None, // VFCMP_SULE_D
    CEFBS_None, // VFCMP_SULE_S
    CEFBS_None, // VFCMP_SULT_D
    CEFBS_None, // VFCMP_SULT_S
    CEFBS_None, // VFCMP_SUNE_D
    CEFBS_None, // VFCMP_SUNE_S
    CEFBS_None, // VFCMP_SUN_D
    CEFBS_None, // VFCMP_SUN_S
    CEFBS_None, // VFCVTH_D_S
    CEFBS_None, // VFCVTH_S_H
    CEFBS_None, // VFCVTL_D_S
    CEFBS_None, // VFCVTL_S_H
    CEFBS_None, // VFCVT_H_S
    CEFBS_None, // VFCVT_S_D
    CEFBS_None, // VFDIV_D
    CEFBS_None, // VFDIV_S
    CEFBS_None, // VFFINTH_D_W
    CEFBS_None, // VFFINTL_D_W
    CEFBS_None, // VFFINT_D_L
    CEFBS_None, // VFFINT_D_LU
    CEFBS_None, // VFFINT_S_L
    CEFBS_None, // VFFINT_S_W
    CEFBS_None, // VFFINT_S_WU
    CEFBS_None, // VFLOGB_D
    CEFBS_None, // VFLOGB_S
    CEFBS_None, // VFMADD_D
    CEFBS_None, // VFMADD_S
    CEFBS_None, // VFMAXA_D
    CEFBS_None, // VFMAXA_S
    CEFBS_None, // VFMAX_D
    CEFBS_None, // VFMAX_S
    CEFBS_None, // VFMINA_D
    CEFBS_None, // VFMINA_S
    CEFBS_None, // VFMIN_D
    CEFBS_None, // VFMIN_S
    CEFBS_None, // VFMSUB_D
    CEFBS_None, // VFMSUB_S
    CEFBS_None, // VFMUL_D
    CEFBS_None, // VFMUL_S
    CEFBS_None, // VFNMADD_D
    CEFBS_None, // VFNMADD_S
    CEFBS_None, // VFNMSUB_D
    CEFBS_None, // VFNMSUB_S
    CEFBS_None, // VFRECIPE_D
    CEFBS_None, // VFRECIPE_S
    CEFBS_None, // VFRECIP_D
    CEFBS_None, // VFRECIP_S
    CEFBS_None, // VFRINTRM_D
    CEFBS_None, // VFRINTRM_S
    CEFBS_None, // VFRINTRNE_D
    CEFBS_None, // VFRINTRNE_S
    CEFBS_None, // VFRINTRP_D
    CEFBS_None, // VFRINTRP_S
    CEFBS_None, // VFRINTRZ_D
    CEFBS_None, // VFRINTRZ_S
    CEFBS_None, // VFRINT_D
    CEFBS_None, // VFRINT_S
    CEFBS_None, // VFRSQRTE_D
    CEFBS_None, // VFRSQRTE_S
    CEFBS_None, // VFRSQRT_D
    CEFBS_None, // VFRSQRT_S
    CEFBS_None, // VFRSTPI_B
    CEFBS_None, // VFRSTPI_H
    CEFBS_None, // VFRSTP_B
    CEFBS_None, // VFRSTP_H
    CEFBS_None, // VFSQRT_D
    CEFBS_None, // VFSQRT_S
    CEFBS_None, // VFSUB_D
    CEFBS_None, // VFSUB_S
    CEFBS_None, // VFTINTH_L_S
    CEFBS_None, // VFTINTL_L_S
    CEFBS_None, // VFTINTRMH_L_S
    CEFBS_None, // VFTINTRML_L_S
    CEFBS_None, // VFTINTRM_L_D
    CEFBS_None, // VFTINTRM_W_D
    CEFBS_None, // VFTINTRM_W_S
    CEFBS_None, // VFTINTRNEH_L_S
    CEFBS_None, // VFTINTRNEL_L_S
    CEFBS_None, // VFTINTRNE_L_D
    CEFBS_None, // VFTINTRNE_W_D
    CEFBS_None, // VFTINTRNE_W_S
    CEFBS_None, // VFTINTRPH_L_S
    CEFBS_None, // VFTINTRPL_L_S
    CEFBS_None, // VFTINTRP_L_D
    CEFBS_None, // VFTINTRP_W_D
    CEFBS_None, // VFTINTRP_W_S
    CEFBS_None, // VFTINTRZH_L_S
    CEFBS_None, // VFTINTRZL_L_S
    CEFBS_None, // VFTINTRZ_LU_D
    CEFBS_None, // VFTINTRZ_L_D
    CEFBS_None, // VFTINTRZ_WU_S
    CEFBS_None, // VFTINTRZ_W_D
    CEFBS_None, // VFTINTRZ_W_S
    CEFBS_None, // VFTINT_LU_D
    CEFBS_None, // VFTINT_L_D
    CEFBS_None, // VFTINT_WU_S
    CEFBS_None, // VFTINT_W_D
    CEFBS_None, // VFTINT_W_S
    CEFBS_None, // VHADDW_DU_WU
    CEFBS_None, // VHADDW_D_W
    CEFBS_None, // VHADDW_HU_BU
    CEFBS_None, // VHADDW_H_B
    CEFBS_None, // VHADDW_QU_DU
    CEFBS_None, // VHADDW_Q_D
    CEFBS_None, // VHADDW_WU_HU
    CEFBS_None, // VHADDW_W_H
    CEFBS_None, // VHSUBW_DU_WU
    CEFBS_None, // VHSUBW_D_W
    CEFBS_None, // VHSUBW_HU_BU
    CEFBS_None, // VHSUBW_H_B
    CEFBS_None, // VHSUBW_QU_DU
    CEFBS_None, // VHSUBW_Q_D
    CEFBS_None, // VHSUBW_WU_HU
    CEFBS_None, // VHSUBW_W_H
    CEFBS_None, // VILVH_B
    CEFBS_None, // VILVH_D
    CEFBS_None, // VILVH_H
    CEFBS_None, // VILVH_W
    CEFBS_None, // VILVL_B
    CEFBS_None, // VILVL_D
    CEFBS_None, // VILVL_H
    CEFBS_None, // VILVL_W
    CEFBS_None, // VINSGR2VR_B
    CEFBS_None, // VINSGR2VR_D
    CEFBS_None, // VINSGR2VR_H
    CEFBS_None, // VINSGR2VR_W
    CEFBS_None, // VLD
    CEFBS_None, // VLDI
    CEFBS_None, // VLDREPL_B
    CEFBS_None, // VLDREPL_D
    CEFBS_None, // VLDREPL_H
    CEFBS_None, // VLDREPL_W
    CEFBS_None, // VLDX
    CEFBS_None, // VMADDWEV_D_W
    CEFBS_None, // VMADDWEV_D_WU
    CEFBS_None, // VMADDWEV_D_WU_W
    CEFBS_None, // VMADDWEV_H_B
    CEFBS_None, // VMADDWEV_H_BU
    CEFBS_None, // VMADDWEV_H_BU_B
    CEFBS_None, // VMADDWEV_Q_D
    CEFBS_None, // VMADDWEV_Q_DU
    CEFBS_None, // VMADDWEV_Q_DU_D
    CEFBS_None, // VMADDWEV_W_H
    CEFBS_None, // VMADDWEV_W_HU
    CEFBS_None, // VMADDWEV_W_HU_H
    CEFBS_None, // VMADDWOD_D_W
    CEFBS_None, // VMADDWOD_D_WU
    CEFBS_None, // VMADDWOD_D_WU_W
    CEFBS_None, // VMADDWOD_H_B
    CEFBS_None, // VMADDWOD_H_BU
    CEFBS_None, // VMADDWOD_H_BU_B
    CEFBS_None, // VMADDWOD_Q_D
    CEFBS_None, // VMADDWOD_Q_DU
    CEFBS_None, // VMADDWOD_Q_DU_D
    CEFBS_None, // VMADDWOD_W_H
    CEFBS_None, // VMADDWOD_W_HU
    CEFBS_None, // VMADDWOD_W_HU_H
    CEFBS_None, // VMADD_B
    CEFBS_None, // VMADD_D
    CEFBS_None, // VMADD_H
    CEFBS_None, // VMADD_W
    CEFBS_None, // VMAXI_B
    CEFBS_None, // VMAXI_BU
    CEFBS_None, // VMAXI_D
    CEFBS_None, // VMAXI_DU
    CEFBS_None, // VMAXI_H
    CEFBS_None, // VMAXI_HU
    CEFBS_None, // VMAXI_W
    CEFBS_None, // VMAXI_WU
    CEFBS_None, // VMAX_B
    CEFBS_None, // VMAX_BU
    CEFBS_None, // VMAX_D
    CEFBS_None, // VMAX_DU
    CEFBS_None, // VMAX_H
    CEFBS_None, // VMAX_HU
    CEFBS_None, // VMAX_W
    CEFBS_None, // VMAX_WU
    CEFBS_None, // VMINI_B
    CEFBS_None, // VMINI_BU
    CEFBS_None, // VMINI_D
    CEFBS_None, // VMINI_DU
    CEFBS_None, // VMINI_H
    CEFBS_None, // VMINI_HU
    CEFBS_None, // VMINI_W
    CEFBS_None, // VMINI_WU
    CEFBS_None, // VMIN_B
    CEFBS_None, // VMIN_BU
    CEFBS_None, // VMIN_D
    CEFBS_None, // VMIN_DU
    CEFBS_None, // VMIN_H
    CEFBS_None, // VMIN_HU
    CEFBS_None, // VMIN_W
    CEFBS_None, // VMIN_WU
    CEFBS_None, // VMOD_B
    CEFBS_None, // VMOD_BU
    CEFBS_None, // VMOD_D
    CEFBS_None, // VMOD_DU
    CEFBS_None, // VMOD_H
    CEFBS_None, // VMOD_HU
    CEFBS_None, // VMOD_W
    CEFBS_None, // VMOD_WU
    CEFBS_None, // VMSKGEZ_B
    CEFBS_None, // VMSKLTZ_B
    CEFBS_None, // VMSKLTZ_D
    CEFBS_None, // VMSKLTZ_H
    CEFBS_None, // VMSKLTZ_W
    CEFBS_None, // VMSKNZ_B
    CEFBS_None, // VMSUB_B
    CEFBS_None, // VMSUB_D
    CEFBS_None, // VMSUB_H
    CEFBS_None, // VMSUB_W
    CEFBS_None, // VMUH_B
    CEFBS_None, // VMUH_BU
    CEFBS_None, // VMUH_D
    CEFBS_None, // VMUH_DU
    CEFBS_None, // VMUH_H
    CEFBS_None, // VMUH_HU
    CEFBS_None, // VMUH_W
    CEFBS_None, // VMUH_WU
    CEFBS_None, // VMULWEV_D_W
    CEFBS_None, // VMULWEV_D_WU
    CEFBS_None, // VMULWEV_D_WU_W
    CEFBS_None, // VMULWEV_H_B
    CEFBS_None, // VMULWEV_H_BU
    CEFBS_None, // VMULWEV_H_BU_B
    CEFBS_None, // VMULWEV_Q_D
    CEFBS_None, // VMULWEV_Q_DU
    CEFBS_None, // VMULWEV_Q_DU_D
    CEFBS_None, // VMULWEV_W_H
    CEFBS_None, // VMULWEV_W_HU
    CEFBS_None, // VMULWEV_W_HU_H
    CEFBS_None, // VMULWOD_D_W
    CEFBS_None, // VMULWOD_D_WU
    CEFBS_None, // VMULWOD_D_WU_W
    CEFBS_None, // VMULWOD_H_B
    CEFBS_None, // VMULWOD_H_BU
    CEFBS_None, // VMULWOD_H_BU_B
    CEFBS_None, // VMULWOD_Q_D
    CEFBS_None, // VMULWOD_Q_DU
    CEFBS_None, // VMULWOD_Q_DU_D
    CEFBS_None, // VMULWOD_W_H
    CEFBS_None, // VMULWOD_W_HU
    CEFBS_None, // VMULWOD_W_HU_H
    CEFBS_None, // VMUL_B
    CEFBS_None, // VMUL_D
    CEFBS_None, // VMUL_H
    CEFBS_None, // VMUL_W
    CEFBS_None, // VNEG_B
    CEFBS_None, // VNEG_D
    CEFBS_None, // VNEG_H
    CEFBS_None, // VNEG_W
    CEFBS_None, // VNORI_B
    CEFBS_None, // VNOR_V
    CEFBS_None, // VORI_B
    CEFBS_None, // VORN_V
    CEFBS_None, // VOR_V
    CEFBS_None, // VPACKEV_B
    CEFBS_None, // VPACKEV_D
    CEFBS_None, // VPACKEV_H
    CEFBS_None, // VPACKEV_W
    CEFBS_None, // VPACKOD_B
    CEFBS_None, // VPACKOD_D
    CEFBS_None, // VPACKOD_H
    CEFBS_None, // VPACKOD_W
    CEFBS_None, // VPCNT_B
    CEFBS_None, // VPCNT_D
    CEFBS_None, // VPCNT_H
    CEFBS_None, // VPCNT_W
    CEFBS_None, // VPERMI_W
    CEFBS_None, // VPICKEV_B
    CEFBS_None, // VPICKEV_D
    CEFBS_None, // VPICKEV_H
    CEFBS_None, // VPICKEV_W
    CEFBS_None, // VPICKOD_B
    CEFBS_None, // VPICKOD_D
    CEFBS_None, // VPICKOD_H
    CEFBS_None, // VPICKOD_W
    CEFBS_None, // VPICKVE2GR_B
    CEFBS_None, // VPICKVE2GR_BU
    CEFBS_None, // VPICKVE2GR_D
    CEFBS_None, // VPICKVE2GR_DU
    CEFBS_None, // VPICKVE2GR_H
    CEFBS_None, // VPICKVE2GR_HU
    CEFBS_None, // VPICKVE2GR_W
    CEFBS_None, // VPICKVE2GR_WU
    CEFBS_None, // VREPLGR2VR_B
    CEFBS_None, // VREPLGR2VR_D
    CEFBS_None, // VREPLGR2VR_H
    CEFBS_None, // VREPLGR2VR_W
    CEFBS_None, // VREPLVEI_B
    CEFBS_None, // VREPLVEI_D
    CEFBS_None, // VREPLVEI_H
    CEFBS_None, // VREPLVEI_W
    CEFBS_None, // VREPLVE_B
    CEFBS_None, // VREPLVE_D
    CEFBS_None, // VREPLVE_H
    CEFBS_None, // VREPLVE_W
    CEFBS_None, // VROTRI_B
    CEFBS_None, // VROTRI_D
    CEFBS_None, // VROTRI_H
    CEFBS_None, // VROTRI_W
    CEFBS_None, // VROTR_B
    CEFBS_None, // VROTR_D
    CEFBS_None, // VROTR_H
    CEFBS_None, // VROTR_W
    CEFBS_None, // VSADD_B
    CEFBS_None, // VSADD_BU
    CEFBS_None, // VSADD_D
    CEFBS_None, // VSADD_DU
    CEFBS_None, // VSADD_H
    CEFBS_None, // VSADD_HU
    CEFBS_None, // VSADD_W
    CEFBS_None, // VSADD_WU
    CEFBS_None, // VSAT_B
    CEFBS_None, // VSAT_BU
    CEFBS_None, // VSAT_D
    CEFBS_None, // VSAT_DU
    CEFBS_None, // VSAT_H
    CEFBS_None, // VSAT_HU
    CEFBS_None, // VSAT_W
    CEFBS_None, // VSAT_WU
    CEFBS_None, // VSEQI_B
    CEFBS_None, // VSEQI_D
    CEFBS_None, // VSEQI_H
    CEFBS_None, // VSEQI_W
    CEFBS_None, // VSEQ_B
    CEFBS_None, // VSEQ_D
    CEFBS_None, // VSEQ_H
    CEFBS_None, // VSEQ_W
    CEFBS_None, // VSETALLNEZ_B
    CEFBS_None, // VSETALLNEZ_D
    CEFBS_None, // VSETALLNEZ_H
    CEFBS_None, // VSETALLNEZ_W
    CEFBS_None, // VSETANYEQZ_B
    CEFBS_None, // VSETANYEQZ_D
    CEFBS_None, // VSETANYEQZ_H
    CEFBS_None, // VSETANYEQZ_W
    CEFBS_None, // VSETEQZ_V
    CEFBS_None, // VSETNEZ_V
    CEFBS_None, // VSHUF4I_B
    CEFBS_None, // VSHUF4I_D
    CEFBS_None, // VSHUF4I_H
    CEFBS_None, // VSHUF4I_W
    CEFBS_None, // VSHUF_B
    CEFBS_None, // VSHUF_D
    CEFBS_None, // VSHUF_H
    CEFBS_None, // VSHUF_W
    CEFBS_None, // VSIGNCOV_B
    CEFBS_None, // VSIGNCOV_D
    CEFBS_None, // VSIGNCOV_H
    CEFBS_None, // VSIGNCOV_W
    CEFBS_None, // VSLEI_B
    CEFBS_None, // VSLEI_BU
    CEFBS_None, // VSLEI_D
    CEFBS_None, // VSLEI_DU
    CEFBS_None, // VSLEI_H
    CEFBS_None, // VSLEI_HU
    CEFBS_None, // VSLEI_W
    CEFBS_None, // VSLEI_WU
    CEFBS_None, // VSLE_B
    CEFBS_None, // VSLE_BU
    CEFBS_None, // VSLE_D
    CEFBS_None, // VSLE_DU
    CEFBS_None, // VSLE_H
    CEFBS_None, // VSLE_HU
    CEFBS_None, // VSLE_W
    CEFBS_None, // VSLE_WU
    CEFBS_None, // VSLLI_B
    CEFBS_None, // VSLLI_D
    CEFBS_None, // VSLLI_H
    CEFBS_None, // VSLLI_W
    CEFBS_None, // VSLLWIL_DU_WU
    CEFBS_None, // VSLLWIL_D_W
    CEFBS_None, // VSLLWIL_HU_BU
    CEFBS_None, // VSLLWIL_H_B
    CEFBS_None, // VSLLWIL_WU_HU
    CEFBS_None, // VSLLWIL_W_H
    CEFBS_None, // VSLL_B
    CEFBS_None, // VSLL_D
    CEFBS_None, // VSLL_H
    CEFBS_None, // VSLL_W
    CEFBS_None, // VSLTI_B
    CEFBS_None, // VSLTI_BU
    CEFBS_None, // VSLTI_D
    CEFBS_None, // VSLTI_DU
    CEFBS_None, // VSLTI_H
    CEFBS_None, // VSLTI_HU
    CEFBS_None, // VSLTI_W
    CEFBS_None, // VSLTI_WU
    CEFBS_None, // VSLT_B
    CEFBS_None, // VSLT_BU
    CEFBS_None, // VSLT_D
    CEFBS_None, // VSLT_DU
    CEFBS_None, // VSLT_H
    CEFBS_None, // VSLT_HU
    CEFBS_None, // VSLT_W
    CEFBS_None, // VSLT_WU
    CEFBS_None, // VSRAI_B
    CEFBS_None, // VSRAI_D
    CEFBS_None, // VSRAI_H
    CEFBS_None, // VSRAI_W
    CEFBS_None, // VSRANI_B_H
    CEFBS_None, // VSRANI_D_Q
    CEFBS_None, // VSRANI_H_W
    CEFBS_None, // VSRANI_W_D
    CEFBS_None, // VSRAN_B_H
    CEFBS_None, // VSRAN_H_W
    CEFBS_None, // VSRAN_W_D
    CEFBS_None, // VSRARI_B
    CEFBS_None, // VSRARI_D
    CEFBS_None, // VSRARI_H
    CEFBS_None, // VSRARI_W
    CEFBS_None, // VSRARNI_B_H
    CEFBS_None, // VSRARNI_D_Q
    CEFBS_None, // VSRARNI_H_W
    CEFBS_None, // VSRARNI_W_D
    CEFBS_None, // VSRARN_B_H
    CEFBS_None, // VSRARN_H_W
    CEFBS_None, // VSRARN_W_D
    CEFBS_None, // VSRAR_B
    CEFBS_None, // VSRAR_D
    CEFBS_None, // VSRAR_H
    CEFBS_None, // VSRAR_W
    CEFBS_None, // VSRA_B
    CEFBS_None, // VSRA_D
    CEFBS_None, // VSRA_H
    CEFBS_None, // VSRA_W
    CEFBS_None, // VSRLI_B
    CEFBS_None, // VSRLI_D
    CEFBS_None, // VSRLI_H
    CEFBS_None, // VSRLI_W
    CEFBS_None, // VSRLNI_B_H
    CEFBS_None, // VSRLNI_D_Q
    CEFBS_None, // VSRLNI_H_W
    CEFBS_None, // VSRLNI_W_D
    CEFBS_None, // VSRLN_B_H
    CEFBS_None, // VSRLN_H_W
    CEFBS_None, // VSRLN_W_D
    CEFBS_None, // VSRLRI_B
    CEFBS_None, // VSRLRI_D
    CEFBS_None, // VSRLRI_H
    CEFBS_None, // VSRLRI_W
    CEFBS_None, // VSRLRNI_B_H
    CEFBS_None, // VSRLRNI_D_Q
    CEFBS_None, // VSRLRNI_H_W
    CEFBS_None, // VSRLRNI_W_D
    CEFBS_None, // VSRLRN_B_H
    CEFBS_None, // VSRLRN_H_W
    CEFBS_None, // VSRLRN_W_D
    CEFBS_None, // VSRLR_B
    CEFBS_None, // VSRLR_D
    CEFBS_None, // VSRLR_H
    CEFBS_None, // VSRLR_W
    CEFBS_None, // VSRL_B
    CEFBS_None, // VSRL_D
    CEFBS_None, // VSRL_H
    CEFBS_None, // VSRL_W
    CEFBS_None, // VSSRANI_BU_H
    CEFBS_None, // VSSRANI_B_H
    CEFBS_None, // VSSRANI_DU_Q
    CEFBS_None, // VSSRANI_D_Q
    CEFBS_None, // VSSRANI_HU_W
    CEFBS_None, // VSSRANI_H_W
    CEFBS_None, // VSSRANI_WU_D
    CEFBS_None, // VSSRANI_W_D
    CEFBS_None, // VSSRAN_BU_H
    CEFBS_None, // VSSRAN_B_H
    CEFBS_None, // VSSRAN_HU_W
    CEFBS_None, // VSSRAN_H_W
    CEFBS_None, // VSSRAN_WU_D
    CEFBS_None, // VSSRAN_W_D
    CEFBS_None, // VSSRARNI_BU_H
    CEFBS_None, // VSSRARNI_B_H
    CEFBS_None, // VSSRARNI_DU_Q
    CEFBS_None, // VSSRARNI_D_Q
    CEFBS_None, // VSSRARNI_HU_W
    CEFBS_None, // VSSRARNI_H_W
    CEFBS_None, // VSSRARNI_WU_D
    CEFBS_None, // VSSRARNI_W_D
    CEFBS_None, // VSSRARN_BU_H
    CEFBS_None, // VSSRARN_B_H
    CEFBS_None, // VSSRARN_HU_W
    CEFBS_None, // VSSRARN_H_W
    CEFBS_None, // VSSRARN_WU_D
    CEFBS_None, // VSSRARN_W_D
    CEFBS_None, // VSSRLNI_BU_H
    CEFBS_None, // VSSRLNI_B_H
    CEFBS_None, // VSSRLNI_DU_Q
    CEFBS_None, // VSSRLNI_D_Q
    CEFBS_None, // VSSRLNI_HU_W
    CEFBS_None, // VSSRLNI_H_W
    CEFBS_None, // VSSRLNI_WU_D
    CEFBS_None, // VSSRLNI_W_D
    CEFBS_None, // VSSRLN_BU_H
    CEFBS_None, // VSSRLN_B_H
    CEFBS_None, // VSSRLN_HU_W
    CEFBS_None, // VSSRLN_H_W
    CEFBS_None, // VSSRLN_WU_D
    CEFBS_None, // VSSRLN_W_D
    CEFBS_None, // VSSRLRNI_BU_H
    CEFBS_None, // VSSRLRNI_B_H
    CEFBS_None, // VSSRLRNI_DU_Q
    CEFBS_None, // VSSRLRNI_D_Q
    CEFBS_None, // VSSRLRNI_HU_W
    CEFBS_None, // VSSRLRNI_H_W
    CEFBS_None, // VSSRLRNI_WU_D
    CEFBS_None, // VSSRLRNI_W_D
    CEFBS_None, // VSSRLRN_BU_H
    CEFBS_None, // VSSRLRN_B_H
    CEFBS_None, // VSSRLRN_HU_W
    CEFBS_None, // VSSRLRN_H_W
    CEFBS_None, // VSSRLRN_WU_D
    CEFBS_None, // VSSRLRN_W_D
    CEFBS_None, // VSSUB_B
    CEFBS_None, // VSSUB_BU
    CEFBS_None, // VSSUB_D
    CEFBS_None, // VSSUB_DU
    CEFBS_None, // VSSUB_H
    CEFBS_None, // VSSUB_HU
    CEFBS_None, // VSSUB_W
    CEFBS_None, // VSSUB_WU
    CEFBS_None, // VST
    CEFBS_None, // VSTELM_B
    CEFBS_None, // VSTELM_D
    CEFBS_None, // VSTELM_H
    CEFBS_None, // VSTELM_W
    CEFBS_None, // VSTX
    CEFBS_None, // VSUBI_BU
    CEFBS_None, // VSUBI_DU
    CEFBS_None, // VSUBI_HU
    CEFBS_None, // VSUBI_WU
    CEFBS_None, // VSUBWEV_D_W
    CEFBS_None, // VSUBWEV_D_WU
    CEFBS_None, // VSUBWEV_H_B
    CEFBS_None, // VSUBWEV_H_BU
    CEFBS_None, // VSUBWEV_Q_D
    CEFBS_None, // VSUBWEV_Q_DU
    CEFBS_None, // VSUBWEV_W_H
    CEFBS_None, // VSUBWEV_W_HU
    CEFBS_None, // VSUBWOD_D_W
    CEFBS_None, // VSUBWOD_D_WU
    CEFBS_None, // VSUBWOD_H_B
    CEFBS_None, // VSUBWOD_H_BU
    CEFBS_None, // VSUBWOD_Q_D
    CEFBS_None, // VSUBWOD_Q_DU
    CEFBS_None, // VSUBWOD_W_H
    CEFBS_None, // VSUBWOD_W_HU
    CEFBS_None, // VSUB_B
    CEFBS_None, // VSUB_D
    CEFBS_None, // VSUB_H
    CEFBS_None, // VSUB_Q
    CEFBS_None, // VSUB_W
    CEFBS_None, // VXORI_B
    CEFBS_None, // VXOR_V
    CEFBS_None, // X86ADC_B
    CEFBS_IsLA64, // X86ADC_D
    CEFBS_None, // X86ADC_H
    CEFBS_None, // X86ADC_W
    CEFBS_None, // X86ADD_B
    CEFBS_IsLA64, // X86ADD_D
    CEFBS_IsLA64, // X86ADD_DU
    CEFBS_None, // X86ADD_H
    CEFBS_None, // X86ADD_W
    CEFBS_IsLA64, // X86ADD_WU
    CEFBS_None, // X86AND_B
    CEFBS_IsLA64, // X86AND_D
    CEFBS_None, // X86AND_H
    CEFBS_None, // X86AND_W
    CEFBS_None, // X86CLRTM
    CEFBS_None, // X86DECTOP
    CEFBS_None, // X86DEC_B
    CEFBS_IsLA64, // X86DEC_D
    CEFBS_None, // X86DEC_H
    CEFBS_None, // X86DEC_W
    CEFBS_None, // X86INCTOP
    CEFBS_None, // X86INC_B
    CEFBS_IsLA64, // X86INC_D
    CEFBS_None, // X86INC_H
    CEFBS_None, // X86INC_W
    CEFBS_None, // X86MFFLAG
    CEFBS_None, // X86MFTOP
    CEFBS_None, // X86MTFLAG
    CEFBS_None, // X86MTTOP
    CEFBS_None, // X86MUL_B
    CEFBS_None, // X86MUL_BU
    CEFBS_IsLA64, // X86MUL_D
    CEFBS_IsLA64, // X86MUL_DU
    CEFBS_None, // X86MUL_H
    CEFBS_None, // X86MUL_HU
    CEFBS_None, // X86MUL_W
    CEFBS_IsLA64, // X86MUL_WU
    CEFBS_None, // X86OR_B
    CEFBS_IsLA64, // X86OR_D
    CEFBS_None, // X86OR_H
    CEFBS_None, // X86OR_W
    CEFBS_None, // X86RCLI_B
    CEFBS_IsLA64, // X86RCLI_D
    CEFBS_None, // X86RCLI_H
    CEFBS_None, // X86RCLI_W
    CEFBS_None, // X86RCL_B
    CEFBS_IsLA64, // X86RCL_D
    CEFBS_None, // X86RCL_H
    CEFBS_None, // X86RCL_W
    CEFBS_None, // X86RCRI_B
    CEFBS_IsLA64, // X86RCRI_D
    CEFBS_None, // X86RCRI_H
    CEFBS_None, // X86RCRI_W
    CEFBS_None, // X86RCR_B
    CEFBS_IsLA64, // X86RCR_D
    CEFBS_None, // X86RCR_H
    CEFBS_None, // X86RCR_W
    CEFBS_None, // X86ROTLI_B
    CEFBS_IsLA64, // X86ROTLI_D
    CEFBS_None, // X86ROTLI_H
    CEFBS_None, // X86ROTLI_W
    CEFBS_None, // X86ROTL_B
    CEFBS_IsLA64, // X86ROTL_D
    CEFBS_None, // X86ROTL_H
    CEFBS_None, // X86ROTL_W
    CEFBS_None, // X86ROTRI_B
    CEFBS_IsLA64, // X86ROTRI_D
    CEFBS_None, // X86ROTRI_H
    CEFBS_None, // X86ROTRI_W
    CEFBS_None, // X86ROTR_B
    CEFBS_IsLA64, // X86ROTR_D
    CEFBS_None, // X86ROTR_H
    CEFBS_None, // X86ROTR_W
    CEFBS_None, // X86SBC_B
    CEFBS_IsLA64, // X86SBC_D
    CEFBS_None, // X86SBC_H
    CEFBS_None, // X86SBC_W
    CEFBS_None, // X86SETTAG
    CEFBS_None, // X86SETTM
    CEFBS_None, // X86SLLI_B
    CEFBS_IsLA64, // X86SLLI_D
    CEFBS_None, // X86SLLI_H
    CEFBS_None, // X86SLLI_W
    CEFBS_None, // X86SLL_B
    CEFBS_IsLA64, // X86SLL_D
    CEFBS_None, // X86SLL_H
    CEFBS_None, // X86SLL_W
    CEFBS_None, // X86SRAI_B
    CEFBS_IsLA64, // X86SRAI_D
    CEFBS_None, // X86SRAI_H
    CEFBS_None, // X86SRAI_W
    CEFBS_None, // X86SRA_B
    CEFBS_IsLA64, // X86SRA_D
    CEFBS_None, // X86SRA_H
    CEFBS_None, // X86SRA_W
    CEFBS_None, // X86SRLI_B
    CEFBS_IsLA64, // X86SRLI_D
    CEFBS_None, // X86SRLI_H
    CEFBS_None, // X86SRLI_W
    CEFBS_None, // X86SRL_B
    CEFBS_IsLA64, // X86SRL_D
    CEFBS_None, // X86SRL_H
    CEFBS_None, // X86SRL_W
    CEFBS_None, // X86SUB_B
    CEFBS_IsLA64, // X86SUB_D
    CEFBS_IsLA64, // X86SUB_DU
    CEFBS_None, // X86SUB_H
    CEFBS_None, // X86SUB_W
    CEFBS_IsLA64, // X86SUB_WU
    CEFBS_None, // X86XOR_B
    CEFBS_IsLA64, // X86XOR_D
    CEFBS_None, // X86XOR_H
    CEFBS_None, // X86XOR_W
    CEFBS_None, // XOR
    CEFBS_None, // XORI
    CEFBS_None, // XVABSD_B
    CEFBS_None, // XVABSD_BU
    CEFBS_None, // XVABSD_D
    CEFBS_None, // XVABSD_DU
    CEFBS_None, // XVABSD_H
    CEFBS_None, // XVABSD_HU
    CEFBS_None, // XVABSD_W
    CEFBS_None, // XVABSD_WU
    CEFBS_None, // XVADDA_B
    CEFBS_None, // XVADDA_D
    CEFBS_None, // XVADDA_H
    CEFBS_None, // XVADDA_W
    CEFBS_None, // XVADDI_BU
    CEFBS_None, // XVADDI_DU
    CEFBS_None, // XVADDI_HU
    CEFBS_None, // XVADDI_WU
    CEFBS_None, // XVADDWEV_D_W
    CEFBS_None, // XVADDWEV_D_WU
    CEFBS_None, // XVADDWEV_D_WU_W
    CEFBS_None, // XVADDWEV_H_B
    CEFBS_None, // XVADDWEV_H_BU
    CEFBS_None, // XVADDWEV_H_BU_B
    CEFBS_None, // XVADDWEV_Q_D
    CEFBS_None, // XVADDWEV_Q_DU
    CEFBS_None, // XVADDWEV_Q_DU_D
    CEFBS_None, // XVADDWEV_W_H
    CEFBS_None, // XVADDWEV_W_HU
    CEFBS_None, // XVADDWEV_W_HU_H
    CEFBS_None, // XVADDWOD_D_W
    CEFBS_None, // XVADDWOD_D_WU
    CEFBS_None, // XVADDWOD_D_WU_W
    CEFBS_None, // XVADDWOD_H_B
    CEFBS_None, // XVADDWOD_H_BU
    CEFBS_None, // XVADDWOD_H_BU_B
    CEFBS_None, // XVADDWOD_Q_D
    CEFBS_None, // XVADDWOD_Q_DU
    CEFBS_None, // XVADDWOD_Q_DU_D
    CEFBS_None, // XVADDWOD_W_H
    CEFBS_None, // XVADDWOD_W_HU
    CEFBS_None, // XVADDWOD_W_HU_H
    CEFBS_None, // XVADD_B
    CEFBS_None, // XVADD_D
    CEFBS_None, // XVADD_H
    CEFBS_None, // XVADD_Q
    CEFBS_None, // XVADD_W
    CEFBS_None, // XVANDI_B
    CEFBS_None, // XVANDN_V
    CEFBS_None, // XVAND_V
    CEFBS_None, // XVAVGR_B
    CEFBS_None, // XVAVGR_BU
    CEFBS_None, // XVAVGR_D
    CEFBS_None, // XVAVGR_DU
    CEFBS_None, // XVAVGR_H
    CEFBS_None, // XVAVGR_HU
    CEFBS_None, // XVAVGR_W
    CEFBS_None, // XVAVGR_WU
    CEFBS_None, // XVAVG_B
    CEFBS_None, // XVAVG_BU
    CEFBS_None, // XVAVG_D
    CEFBS_None, // XVAVG_DU
    CEFBS_None, // XVAVG_H
    CEFBS_None, // XVAVG_HU
    CEFBS_None, // XVAVG_W
    CEFBS_None, // XVAVG_WU
    CEFBS_None, // XVBITCLRI_B
    CEFBS_None, // XVBITCLRI_D
    CEFBS_None, // XVBITCLRI_H
    CEFBS_None, // XVBITCLRI_W
    CEFBS_None, // XVBITCLR_B
    CEFBS_None, // XVBITCLR_D
    CEFBS_None, // XVBITCLR_H
    CEFBS_None, // XVBITCLR_W
    CEFBS_None, // XVBITREVI_B
    CEFBS_None, // XVBITREVI_D
    CEFBS_None, // XVBITREVI_H
    CEFBS_None, // XVBITREVI_W
    CEFBS_None, // XVBITREV_B
    CEFBS_None, // XVBITREV_D
    CEFBS_None, // XVBITREV_H
    CEFBS_None, // XVBITREV_W
    CEFBS_None, // XVBITSELI_B
    CEFBS_None, // XVBITSEL_V
    CEFBS_None, // XVBITSETI_B
    CEFBS_None, // XVBITSETI_D
    CEFBS_None, // XVBITSETI_H
    CEFBS_None, // XVBITSETI_W
    CEFBS_None, // XVBITSET_B
    CEFBS_None, // XVBITSET_D
    CEFBS_None, // XVBITSET_H
    CEFBS_None, // XVBITSET_W
    CEFBS_None, // XVBSLL_V
    CEFBS_None, // XVBSRL_V
    CEFBS_None, // XVCLO_B
    CEFBS_None, // XVCLO_D
    CEFBS_None, // XVCLO_H
    CEFBS_None, // XVCLO_W
    CEFBS_None, // XVCLZ_B
    CEFBS_None, // XVCLZ_D
    CEFBS_None, // XVCLZ_H
    CEFBS_None, // XVCLZ_W
    CEFBS_None, // XVDIV_B
    CEFBS_None, // XVDIV_BU
    CEFBS_None, // XVDIV_D
    CEFBS_None, // XVDIV_DU
    CEFBS_None, // XVDIV_H
    CEFBS_None, // XVDIV_HU
    CEFBS_None, // XVDIV_W
    CEFBS_None, // XVDIV_WU
    CEFBS_None, // XVEXTH_DU_WU
    CEFBS_None, // XVEXTH_D_W
    CEFBS_None, // XVEXTH_HU_BU
    CEFBS_None, // XVEXTH_H_B
    CEFBS_None, // XVEXTH_QU_DU
    CEFBS_None, // XVEXTH_Q_D
    CEFBS_None, // XVEXTH_WU_HU
    CEFBS_None, // XVEXTH_W_H
    CEFBS_None, // XVEXTL_QU_DU
    CEFBS_None, // XVEXTL_Q_D
    CEFBS_None, // XVEXTRINS_B
    CEFBS_None, // XVEXTRINS_D
    CEFBS_None, // XVEXTRINS_H
    CEFBS_None, // XVEXTRINS_W
    CEFBS_None, // XVFADD_D
    CEFBS_None, // XVFADD_S
    CEFBS_None, // XVFCLASS_D
    CEFBS_None, // XVFCLASS_S
    CEFBS_None, // XVFCMP_CAF_D
    CEFBS_None, // XVFCMP_CAF_S
    CEFBS_None, // XVFCMP_CEQ_D
    CEFBS_None, // XVFCMP_CEQ_S
    CEFBS_None, // XVFCMP_CLE_D
    CEFBS_None, // XVFCMP_CLE_S
    CEFBS_None, // XVFCMP_CLT_D
    CEFBS_None, // XVFCMP_CLT_S
    CEFBS_None, // XVFCMP_CNE_D
    CEFBS_None, // XVFCMP_CNE_S
    CEFBS_None, // XVFCMP_COR_D
    CEFBS_None, // XVFCMP_COR_S
    CEFBS_None, // XVFCMP_CUEQ_D
    CEFBS_None, // XVFCMP_CUEQ_S
    CEFBS_None, // XVFCMP_CULE_D
    CEFBS_None, // XVFCMP_CULE_S
    CEFBS_None, // XVFCMP_CULT_D
    CEFBS_None, // XVFCMP_CULT_S
    CEFBS_None, // XVFCMP_CUNE_D
    CEFBS_None, // XVFCMP_CUNE_S
    CEFBS_None, // XVFCMP_CUN_D
    CEFBS_None, // XVFCMP_CUN_S
    CEFBS_None, // XVFCMP_SAF_D
    CEFBS_None, // XVFCMP_SAF_S
    CEFBS_None, // XVFCMP_SEQ_D
    CEFBS_None, // XVFCMP_SEQ_S
    CEFBS_None, // XVFCMP_SLE_D
    CEFBS_None, // XVFCMP_SLE_S
    CEFBS_None, // XVFCMP_SLT_D
    CEFBS_None, // XVFCMP_SLT_S
    CEFBS_None, // XVFCMP_SNE_D
    CEFBS_None, // XVFCMP_SNE_S
    CEFBS_None, // XVFCMP_SOR_D
    CEFBS_None, // XVFCMP_SOR_S
    CEFBS_None, // XVFCMP_SUEQ_D
    CEFBS_None, // XVFCMP_SUEQ_S
    CEFBS_None, // XVFCMP_SULE_D
    CEFBS_None, // XVFCMP_SULE_S
    CEFBS_None, // XVFCMP_SULT_D
    CEFBS_None, // XVFCMP_SULT_S
    CEFBS_None, // XVFCMP_SUNE_D
    CEFBS_None, // XVFCMP_SUNE_S
    CEFBS_None, // XVFCMP_SUN_D
    CEFBS_None, // XVFCMP_SUN_S
    CEFBS_None, // XVFCVTH_D_S
    CEFBS_None, // XVFCVTH_S_H
    CEFBS_None, // XVFCVTL_D_S
    CEFBS_None, // XVFCVTL_S_H
    CEFBS_None, // XVFCVT_H_S
    CEFBS_None, // XVFCVT_S_D
    CEFBS_None, // XVFDIV_D
    CEFBS_None, // XVFDIV_S
    CEFBS_None, // XVFFINTH_D_W
    CEFBS_None, // XVFFINTL_D_W
    CEFBS_None, // XVFFINT_D_L
    CEFBS_None, // XVFFINT_D_LU
    CEFBS_None, // XVFFINT_S_L
    CEFBS_None, // XVFFINT_S_W
    CEFBS_None, // XVFFINT_S_WU
    CEFBS_None, // XVFLOGB_D
    CEFBS_None, // XVFLOGB_S
    CEFBS_None, // XVFMADD_D
    CEFBS_None, // XVFMADD_S
    CEFBS_None, // XVFMAXA_D
    CEFBS_None, // XVFMAXA_S
    CEFBS_None, // XVFMAX_D
    CEFBS_None, // XVFMAX_S
    CEFBS_None, // XVFMINA_D
    CEFBS_None, // XVFMINA_S
    CEFBS_None, // XVFMIN_D
    CEFBS_None, // XVFMIN_S
    CEFBS_None, // XVFMSUB_D
    CEFBS_None, // XVFMSUB_S
    CEFBS_None, // XVFMUL_D
    CEFBS_None, // XVFMUL_S
    CEFBS_None, // XVFNMADD_D
    CEFBS_None, // XVFNMADD_S
    CEFBS_None, // XVFNMSUB_D
    CEFBS_None, // XVFNMSUB_S
    CEFBS_None, // XVFRECIPE_D
    CEFBS_None, // XVFRECIPE_S
    CEFBS_None, // XVFRECIP_D
    CEFBS_None, // XVFRECIP_S
    CEFBS_None, // XVFRINTRM_D
    CEFBS_None, // XVFRINTRM_S
    CEFBS_None, // XVFRINTRNE_D
    CEFBS_None, // XVFRINTRNE_S
    CEFBS_None, // XVFRINTRP_D
    CEFBS_None, // XVFRINTRP_S
    CEFBS_None, // XVFRINTRZ_D
    CEFBS_None, // XVFRINTRZ_S
    CEFBS_None, // XVFRINT_D
    CEFBS_None, // XVFRINT_S
    CEFBS_None, // XVFRSQRTE_D
    CEFBS_None, // XVFRSQRTE_S
    CEFBS_None, // XVFRSQRT_D
    CEFBS_None, // XVFRSQRT_S
    CEFBS_None, // XVFRSTPI_B
    CEFBS_None, // XVFRSTPI_H
    CEFBS_None, // XVFRSTP_B
    CEFBS_None, // XVFRSTP_H
    CEFBS_None, // XVFSQRT_D
    CEFBS_None, // XVFSQRT_S
    CEFBS_None, // XVFSUB_D
    CEFBS_None, // XVFSUB_S
    CEFBS_None, // XVFTINTH_L_S
    CEFBS_None, // XVFTINTL_L_S
    CEFBS_None, // XVFTINTRMH_L_S
    CEFBS_None, // XVFTINTRML_L_S
    CEFBS_None, // XVFTINTRM_L_D
    CEFBS_None, // XVFTINTRM_W_D
    CEFBS_None, // XVFTINTRM_W_S
    CEFBS_None, // XVFTINTRNEH_L_S
    CEFBS_None, // XVFTINTRNEL_L_S
    CEFBS_None, // XVFTINTRNE_L_D
    CEFBS_None, // XVFTINTRNE_W_D
    CEFBS_None, // XVFTINTRNE_W_S
    CEFBS_None, // XVFTINTRPH_L_S
    CEFBS_None, // XVFTINTRPL_L_S
    CEFBS_None, // XVFTINTRP_L_D
    CEFBS_None, // XVFTINTRP_W_D
    CEFBS_None, // XVFTINTRP_W_S
    CEFBS_None, // XVFTINTRZH_L_S
    CEFBS_None, // XVFTINTRZL_L_S
    CEFBS_None, // XVFTINTRZ_LU_D
    CEFBS_None, // XVFTINTRZ_L_D
    CEFBS_None, // XVFTINTRZ_WU_S
    CEFBS_None, // XVFTINTRZ_W_D
    CEFBS_None, // XVFTINTRZ_W_S
    CEFBS_None, // XVFTINT_LU_D
    CEFBS_None, // XVFTINT_L_D
    CEFBS_None, // XVFTINT_WU_S
    CEFBS_None, // XVFTINT_W_D
    CEFBS_None, // XVFTINT_W_S
    CEFBS_None, // XVHADDW_DU_WU
    CEFBS_None, // XVHADDW_D_W
    CEFBS_None, // XVHADDW_HU_BU
    CEFBS_None, // XVHADDW_H_B
    CEFBS_None, // XVHADDW_QU_DU
    CEFBS_None, // XVHADDW_Q_D
    CEFBS_None, // XVHADDW_WU_HU
    CEFBS_None, // XVHADDW_W_H
    CEFBS_None, // XVHSELI_D
    CEFBS_None, // XVHSUBW_DU_WU
    CEFBS_None, // XVHSUBW_D_W
    CEFBS_None, // XVHSUBW_HU_BU
    CEFBS_None, // XVHSUBW_H_B
    CEFBS_None, // XVHSUBW_QU_DU
    CEFBS_None, // XVHSUBW_Q_D
    CEFBS_None, // XVHSUBW_WU_HU
    CEFBS_None, // XVHSUBW_W_H
    CEFBS_None, // XVILVH_B
    CEFBS_None, // XVILVH_D
    CEFBS_None, // XVILVH_H
    CEFBS_None, // XVILVH_W
    CEFBS_None, // XVILVL_B
    CEFBS_None, // XVILVL_D
    CEFBS_None, // XVILVL_H
    CEFBS_None, // XVILVL_W
    CEFBS_None, // XVINSGR2VR_D
    CEFBS_None, // XVINSGR2VR_W
    CEFBS_None, // XVINSVE0_D
    CEFBS_None, // XVINSVE0_W
    CEFBS_None, // XVLD
    CEFBS_None, // XVLDI
    CEFBS_None, // XVLDREPL_B
    CEFBS_None, // XVLDREPL_D
    CEFBS_None, // XVLDREPL_H
    CEFBS_None, // XVLDREPL_W
    CEFBS_None, // XVLDX
    CEFBS_None, // XVMADDWEV_D_W
    CEFBS_None, // XVMADDWEV_D_WU
    CEFBS_None, // XVMADDWEV_D_WU_W
    CEFBS_None, // XVMADDWEV_H_B
    CEFBS_None, // XVMADDWEV_H_BU
    CEFBS_None, // XVMADDWEV_H_BU_B
    CEFBS_None, // XVMADDWEV_Q_D
    CEFBS_None, // XVMADDWEV_Q_DU
    CEFBS_None, // XVMADDWEV_Q_DU_D
    CEFBS_None, // XVMADDWEV_W_H
    CEFBS_None, // XVMADDWEV_W_HU
    CEFBS_None, // XVMADDWEV_W_HU_H
    CEFBS_None, // XVMADDWOD_D_W
    CEFBS_None, // XVMADDWOD_D_WU
    CEFBS_None, // XVMADDWOD_D_WU_W
    CEFBS_None, // XVMADDWOD_H_B
    CEFBS_None, // XVMADDWOD_H_BU
    CEFBS_None, // XVMADDWOD_H_BU_B
    CEFBS_None, // XVMADDWOD_Q_D
    CEFBS_None, // XVMADDWOD_Q_DU
    CEFBS_None, // XVMADDWOD_Q_DU_D
    CEFBS_None, // XVMADDWOD_W_H
    CEFBS_None, // XVMADDWOD_W_HU
    CEFBS_None, // XVMADDWOD_W_HU_H
    CEFBS_None, // XVMADD_B
    CEFBS_None, // XVMADD_D
    CEFBS_None, // XVMADD_H
    CEFBS_None, // XVMADD_W
    CEFBS_None, // XVMAXI_B
    CEFBS_None, // XVMAXI_BU
    CEFBS_None, // XVMAXI_D
    CEFBS_None, // XVMAXI_DU
    CEFBS_None, // XVMAXI_H
    CEFBS_None, // XVMAXI_HU
    CEFBS_None, // XVMAXI_W
    CEFBS_None, // XVMAXI_WU
    CEFBS_None, // XVMAX_B
    CEFBS_None, // XVMAX_BU
    CEFBS_None, // XVMAX_D
    CEFBS_None, // XVMAX_DU
    CEFBS_None, // XVMAX_H
    CEFBS_None, // XVMAX_HU
    CEFBS_None, // XVMAX_W
    CEFBS_None, // XVMAX_WU
    CEFBS_None, // XVMINI_B
    CEFBS_None, // XVMINI_BU
    CEFBS_None, // XVMINI_D
    CEFBS_None, // XVMINI_DU
    CEFBS_None, // XVMINI_H
    CEFBS_None, // XVMINI_HU
    CEFBS_None, // XVMINI_W
    CEFBS_None, // XVMINI_WU
    CEFBS_None, // XVMIN_B
    CEFBS_None, // XVMIN_BU
    CEFBS_None, // XVMIN_D
    CEFBS_None, // XVMIN_DU
    CEFBS_None, // XVMIN_H
    CEFBS_None, // XVMIN_HU
    CEFBS_None, // XVMIN_W
    CEFBS_None, // XVMIN_WU
    CEFBS_None, // XVMOD_B
    CEFBS_None, // XVMOD_BU
    CEFBS_None, // XVMOD_D
    CEFBS_None, // XVMOD_DU
    CEFBS_None, // XVMOD_H
    CEFBS_None, // XVMOD_HU
    CEFBS_None, // XVMOD_W
    CEFBS_None, // XVMOD_WU
    CEFBS_None, // XVMSKGEZ_B
    CEFBS_None, // XVMSKLTZ_B
    CEFBS_None, // XVMSKLTZ_D
    CEFBS_None, // XVMSKLTZ_H
    CEFBS_None, // XVMSKLTZ_W
    CEFBS_None, // XVMSKNZ_B
    CEFBS_None, // XVMSUB_B
    CEFBS_None, // XVMSUB_D
    CEFBS_None, // XVMSUB_H
    CEFBS_None, // XVMSUB_W
    CEFBS_None, // XVMUH_B
    CEFBS_None, // XVMUH_BU
    CEFBS_None, // XVMUH_D
    CEFBS_None, // XVMUH_DU
    CEFBS_None, // XVMUH_H
    CEFBS_None, // XVMUH_HU
    CEFBS_None, // XVMUH_W
    CEFBS_None, // XVMUH_WU
    CEFBS_None, // XVMULWEV_D_W
    CEFBS_None, // XVMULWEV_D_WU
    CEFBS_None, // XVMULWEV_D_WU_W
    CEFBS_None, // XVMULWEV_H_B
    CEFBS_None, // XVMULWEV_H_BU
    CEFBS_None, // XVMULWEV_H_BU_B
    CEFBS_None, // XVMULWEV_Q_D
    CEFBS_None, // XVMULWEV_Q_DU
    CEFBS_None, // XVMULWEV_Q_DU_D
    CEFBS_None, // XVMULWEV_W_H
    CEFBS_None, // XVMULWEV_W_HU
    CEFBS_None, // XVMULWEV_W_HU_H
    CEFBS_None, // XVMULWOD_D_W
    CEFBS_None, // XVMULWOD_D_WU
    CEFBS_None, // XVMULWOD_D_WU_W
    CEFBS_None, // XVMULWOD_H_B
    CEFBS_None, // XVMULWOD_H_BU
    CEFBS_None, // XVMULWOD_H_BU_B
    CEFBS_None, // XVMULWOD_Q_D
    CEFBS_None, // XVMULWOD_Q_DU
    CEFBS_None, // XVMULWOD_Q_DU_D
    CEFBS_None, // XVMULWOD_W_H
    CEFBS_None, // XVMULWOD_W_HU
    CEFBS_None, // XVMULWOD_W_HU_H
    CEFBS_None, // XVMUL_B
    CEFBS_None, // XVMUL_D
    CEFBS_None, // XVMUL_H
    CEFBS_None, // XVMUL_W
    CEFBS_None, // XVNEG_B
    CEFBS_None, // XVNEG_D
    CEFBS_None, // XVNEG_H
    CEFBS_None, // XVNEG_W
    CEFBS_None, // XVNORI_B
    CEFBS_None, // XVNOR_V
    CEFBS_None, // XVORI_B
    CEFBS_None, // XVORN_V
    CEFBS_None, // XVOR_V
    CEFBS_None, // XVPACKEV_B
    CEFBS_None, // XVPACKEV_D
    CEFBS_None, // XVPACKEV_H
    CEFBS_None, // XVPACKEV_W
    CEFBS_None, // XVPACKOD_B
    CEFBS_None, // XVPACKOD_D
    CEFBS_None, // XVPACKOD_H
    CEFBS_None, // XVPACKOD_W
    CEFBS_None, // XVPCNT_B
    CEFBS_None, // XVPCNT_D
    CEFBS_None, // XVPCNT_H
    CEFBS_None, // XVPCNT_W
    CEFBS_None, // XVPERMI_D
    CEFBS_None, // XVPERMI_Q
    CEFBS_None, // XVPERMI_W
    CEFBS_None, // XVPERM_W
    CEFBS_None, // XVPICKEV_B
    CEFBS_None, // XVPICKEV_D
    CEFBS_None, // XVPICKEV_H
    CEFBS_None, // XVPICKEV_W
    CEFBS_None, // XVPICKOD_B
    CEFBS_None, // XVPICKOD_D
    CEFBS_None, // XVPICKOD_H
    CEFBS_None, // XVPICKOD_W
    CEFBS_None, // XVPICKVE2GR_D
    CEFBS_None, // XVPICKVE2GR_DU
    CEFBS_None, // XVPICKVE2GR_W
    CEFBS_None, // XVPICKVE2GR_WU
    CEFBS_None, // XVPICKVE_D
    CEFBS_None, // XVPICKVE_W
    CEFBS_None, // XVREPL128VEI_B
    CEFBS_None, // XVREPL128VEI_D
    CEFBS_None, // XVREPL128VEI_H
    CEFBS_None, // XVREPL128VEI_W
    CEFBS_None, // XVREPLGR2VR_B
    CEFBS_None, // XVREPLGR2VR_D
    CEFBS_None, // XVREPLGR2VR_H
    CEFBS_None, // XVREPLGR2VR_W
    CEFBS_None, // XVREPLVE0_B
    CEFBS_None, // XVREPLVE0_D
    CEFBS_None, // XVREPLVE0_H
    CEFBS_None, // XVREPLVE0_Q
    CEFBS_None, // XVREPLVE0_W
    CEFBS_None, // XVREPLVE_B
    CEFBS_None, // XVREPLVE_D
    CEFBS_None, // XVREPLVE_H
    CEFBS_None, // XVREPLVE_W
    CEFBS_None, // XVROTRI_B
    CEFBS_None, // XVROTRI_D
    CEFBS_None, // XVROTRI_H
    CEFBS_None, // XVROTRI_W
    CEFBS_None, // XVROTR_B
    CEFBS_None, // XVROTR_D
    CEFBS_None, // XVROTR_H
    CEFBS_None, // XVROTR_W
    CEFBS_None, // XVSADD_B
    CEFBS_None, // XVSADD_BU
    CEFBS_None, // XVSADD_D
    CEFBS_None, // XVSADD_DU
    CEFBS_None, // XVSADD_H
    CEFBS_None, // XVSADD_HU
    CEFBS_None, // XVSADD_W
    CEFBS_None, // XVSADD_WU
    CEFBS_None, // XVSAT_B
    CEFBS_None, // XVSAT_BU
    CEFBS_None, // XVSAT_D
    CEFBS_None, // XVSAT_DU
    CEFBS_None, // XVSAT_H
    CEFBS_None, // XVSAT_HU
    CEFBS_None, // XVSAT_W
    CEFBS_None, // XVSAT_WU
    CEFBS_None, // XVSEQI_B
    CEFBS_None, // XVSEQI_D
    CEFBS_None, // XVSEQI_H
    CEFBS_None, // XVSEQI_W
    CEFBS_None, // XVSEQ_B
    CEFBS_None, // XVSEQ_D
    CEFBS_None, // XVSEQ_H
    CEFBS_None, // XVSEQ_W
    CEFBS_None, // XVSETALLNEZ_B
    CEFBS_None, // XVSETALLNEZ_D
    CEFBS_None, // XVSETALLNEZ_H
    CEFBS_None, // XVSETALLNEZ_W
    CEFBS_None, // XVSETANYEQZ_B
    CEFBS_None, // XVSETANYEQZ_D
    CEFBS_None, // XVSETANYEQZ_H
    CEFBS_None, // XVSETANYEQZ_W
    CEFBS_None, // XVSETEQZ_V
    CEFBS_None, // XVSETNEZ_V
    CEFBS_None, // XVSHUF4I_B
    CEFBS_None, // XVSHUF4I_D
    CEFBS_None, // XVSHUF4I_H
    CEFBS_None, // XVSHUF4I_W
    CEFBS_None, // XVSHUF_B
    CEFBS_None, // XVSHUF_D
    CEFBS_None, // XVSHUF_H
    CEFBS_None, // XVSHUF_W
    CEFBS_None, // XVSIGNCOV_B
    CEFBS_None, // XVSIGNCOV_D
    CEFBS_None, // XVSIGNCOV_H
    CEFBS_None, // XVSIGNCOV_W
    CEFBS_None, // XVSLEI_B
    CEFBS_None, // XVSLEI_BU
    CEFBS_None, // XVSLEI_D
    CEFBS_None, // XVSLEI_DU
    CEFBS_None, // XVSLEI_H
    CEFBS_None, // XVSLEI_HU
    CEFBS_None, // XVSLEI_W
    CEFBS_None, // XVSLEI_WU
    CEFBS_None, // XVSLE_B
    CEFBS_None, // XVSLE_BU
    CEFBS_None, // XVSLE_D
    CEFBS_None, // XVSLE_DU
    CEFBS_None, // XVSLE_H
    CEFBS_None, // XVSLE_HU
    CEFBS_None, // XVSLE_W
    CEFBS_None, // XVSLE_WU
    CEFBS_None, // XVSLLI_B
    CEFBS_None, // XVSLLI_D
    CEFBS_None, // XVSLLI_H
    CEFBS_None, // XVSLLI_W
    CEFBS_None, // XVSLLWIL_DU_WU
    CEFBS_None, // XVSLLWIL_D_W
    CEFBS_None, // XVSLLWIL_HU_BU
    CEFBS_None, // XVSLLWIL_H_B
    CEFBS_None, // XVSLLWIL_WU_HU
    CEFBS_None, // XVSLLWIL_W_H
    CEFBS_None, // XVSLL_B
    CEFBS_None, // XVSLL_D
    CEFBS_None, // XVSLL_H
    CEFBS_None, // XVSLL_W
    CEFBS_None, // XVSLTI_B
    CEFBS_None, // XVSLTI_BU
    CEFBS_None, // XVSLTI_D
    CEFBS_None, // XVSLTI_DU
    CEFBS_None, // XVSLTI_H
    CEFBS_None, // XVSLTI_HU
    CEFBS_None, // XVSLTI_W
    CEFBS_None, // XVSLTI_WU
    CEFBS_None, // XVSLT_B
    CEFBS_None, // XVSLT_BU
    CEFBS_None, // XVSLT_D
    CEFBS_None, // XVSLT_DU
    CEFBS_None, // XVSLT_H
    CEFBS_None, // XVSLT_HU
    CEFBS_None, // XVSLT_W
    CEFBS_None, // XVSLT_WU
    CEFBS_None, // XVSRAI_B
    CEFBS_None, // XVSRAI_D
    CEFBS_None, // XVSRAI_H
    CEFBS_None, // XVSRAI_W
    CEFBS_None, // XVSRANI_B_H
    CEFBS_None, // XVSRANI_D_Q
    CEFBS_None, // XVSRANI_H_W
    CEFBS_None, // XVSRANI_W_D
    CEFBS_None, // XVSRAN_B_H
    CEFBS_None, // XVSRAN_H_W
    CEFBS_None, // XVSRAN_W_D
    CEFBS_None, // XVSRARI_B
    CEFBS_None, // XVSRARI_D
    CEFBS_None, // XVSRARI_H
    CEFBS_None, // XVSRARI_W
    CEFBS_None, // XVSRARNI_B_H
    CEFBS_None, // XVSRARNI_D_Q
    CEFBS_None, // XVSRARNI_H_W
    CEFBS_None, // XVSRARNI_W_D
    CEFBS_None, // XVSRARN_B_H
    CEFBS_None, // XVSRARN_H_W
    CEFBS_None, // XVSRARN_W_D
    CEFBS_None, // XVSRAR_B
    CEFBS_None, // XVSRAR_D
    CEFBS_None, // XVSRAR_H
    CEFBS_None, // XVSRAR_W
    CEFBS_None, // XVSRA_B
    CEFBS_None, // XVSRA_D
    CEFBS_None, // XVSRA_H
    CEFBS_None, // XVSRA_W
    CEFBS_None, // XVSRLI_B
    CEFBS_None, // XVSRLI_D
    CEFBS_None, // XVSRLI_H
    CEFBS_None, // XVSRLI_W
    CEFBS_None, // XVSRLNI_B_H
    CEFBS_None, // XVSRLNI_D_Q
    CEFBS_None, // XVSRLNI_H_W
    CEFBS_None, // XVSRLNI_W_D
    CEFBS_None, // XVSRLN_B_H
    CEFBS_None, // XVSRLN_H_W
    CEFBS_None, // XVSRLN_W_D
    CEFBS_None, // XVSRLRI_B
    CEFBS_None, // XVSRLRI_D
    CEFBS_None, // XVSRLRI_H
    CEFBS_None, // XVSRLRI_W
    CEFBS_None, // XVSRLRNI_B_H
    CEFBS_None, // XVSRLRNI_D_Q
    CEFBS_None, // XVSRLRNI_H_W
    CEFBS_None, // XVSRLRNI_W_D
    CEFBS_None, // XVSRLRN_B_H
    CEFBS_None, // XVSRLRN_H_W
    CEFBS_None, // XVSRLRN_W_D
    CEFBS_None, // XVSRLR_B
    CEFBS_None, // XVSRLR_D
    CEFBS_None, // XVSRLR_H
    CEFBS_None, // XVSRLR_W
    CEFBS_None, // XVSRL_B
    CEFBS_None, // XVSRL_D
    CEFBS_None, // XVSRL_H
    CEFBS_None, // XVSRL_W
    CEFBS_None, // XVSSRANI_BU_H
    CEFBS_None, // XVSSRANI_B_H
    CEFBS_None, // XVSSRANI_DU_Q
    CEFBS_None, // XVSSRANI_D_Q
    CEFBS_None, // XVSSRANI_HU_W
    CEFBS_None, // XVSSRANI_H_W
    CEFBS_None, // XVSSRANI_WU_D
    CEFBS_None, // XVSSRANI_W_D
    CEFBS_None, // XVSSRAN_BU_H
    CEFBS_None, // XVSSRAN_B_H
    CEFBS_None, // XVSSRAN_HU_W
    CEFBS_None, // XVSSRAN_H_W
    CEFBS_None, // XVSSRAN_WU_D
    CEFBS_None, // XVSSRAN_W_D
    CEFBS_None, // XVSSRARNI_BU_H
    CEFBS_None, // XVSSRARNI_B_H
    CEFBS_None, // XVSSRARNI_DU_Q
    CEFBS_None, // XVSSRARNI_D_Q
    CEFBS_None, // XVSSRARNI_HU_W
    CEFBS_None, // XVSSRARNI_H_W
    CEFBS_None, // XVSSRARNI_WU_D
    CEFBS_None, // XVSSRARNI_W_D
    CEFBS_None, // XVSSRARN_BU_H
    CEFBS_None, // XVSSRARN_B_H
    CEFBS_None, // XVSSRARN_HU_W
    CEFBS_None, // XVSSRARN_H_W
    CEFBS_None, // XVSSRARN_WU_D
    CEFBS_None, // XVSSRARN_W_D
    CEFBS_None, // XVSSRLNI_BU_H
    CEFBS_None, // XVSSRLNI_B_H
    CEFBS_None, // XVSSRLNI_DU_Q
    CEFBS_None, // XVSSRLNI_D_Q
    CEFBS_None, // XVSSRLNI_HU_W
    CEFBS_None, // XVSSRLNI_H_W
    CEFBS_None, // XVSSRLNI_WU_D
    CEFBS_None, // XVSSRLNI_W_D
    CEFBS_None, // XVSSRLN_BU_H
    CEFBS_None, // XVSSRLN_B_H
    CEFBS_None, // XVSSRLN_HU_W
    CEFBS_None, // XVSSRLN_H_W
    CEFBS_None, // XVSSRLN_WU_D
    CEFBS_None, // XVSSRLN_W_D
    CEFBS_None, // XVSSRLRNI_BU_H
    CEFBS_None, // XVSSRLRNI_B_H
    CEFBS_None, // XVSSRLRNI_DU_Q
    CEFBS_None, // XVSSRLRNI_D_Q
    CEFBS_None, // XVSSRLRNI_HU_W
    CEFBS_None, // XVSSRLRNI_H_W
    CEFBS_None, // XVSSRLRNI_WU_D
    CEFBS_None, // XVSSRLRNI_W_D
    CEFBS_None, // XVSSRLRN_BU_H
    CEFBS_None, // XVSSRLRN_B_H
    CEFBS_None, // XVSSRLRN_HU_W
    CEFBS_None, // XVSSRLRN_H_W
    CEFBS_None, // XVSSRLRN_WU_D
    CEFBS_None, // XVSSRLRN_W_D
    CEFBS_None, // XVSSUB_B
    CEFBS_None, // XVSSUB_BU
    CEFBS_None, // XVSSUB_D
    CEFBS_None, // XVSSUB_DU
    CEFBS_None, // XVSSUB_H
    CEFBS_None, // XVSSUB_HU
    CEFBS_None, // XVSSUB_W
    CEFBS_None, // XVSSUB_WU
    CEFBS_None, // XVST
    CEFBS_None, // XVSTELM_B
    CEFBS_None, // XVSTELM_D
    CEFBS_None, // XVSTELM_H
    CEFBS_None, // XVSTELM_W
    CEFBS_None, // XVSTX
    CEFBS_None, // XVSUBI_BU
    CEFBS_None, // XVSUBI_DU
    CEFBS_None, // XVSUBI_HU
    CEFBS_None, // XVSUBI_WU
    CEFBS_None, // XVSUBWEV_D_W
    CEFBS_None, // XVSUBWEV_D_WU
    CEFBS_None, // XVSUBWEV_H_B
    CEFBS_None, // XVSUBWEV_H_BU
    CEFBS_None, // XVSUBWEV_Q_D
    CEFBS_None, // XVSUBWEV_Q_DU
    CEFBS_None, // XVSUBWEV_W_H
    CEFBS_None, // XVSUBWEV_W_HU
    CEFBS_None, // XVSUBWOD_D_W
    CEFBS_None, // XVSUBWOD_D_WU
    CEFBS_None, // XVSUBWOD_H_B
    CEFBS_None, // XVSUBWOD_H_BU
    CEFBS_None, // XVSUBWOD_Q_D
    CEFBS_None, // XVSUBWOD_Q_DU
    CEFBS_None, // XVSUBWOD_W_H
    CEFBS_None, // XVSUBWOD_W_HU
    CEFBS_None, // XVSUB_B
    CEFBS_None, // XVSUB_D
    CEFBS_None, // XVSUB_H
    CEFBS_None, // XVSUB_Q
    CEFBS_None, // XVSUB_W
    CEFBS_None, // XVXORI_B
    CEFBS_None, // XVXOR_V
  };

  assert(Opcode < 2498);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::LoongArch_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::LoongArch_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::LoongArch_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::LoongArch_MC {

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_HasLaGlobalWithAbs",
  "Feature_HasLaGlobalWithPcrel",
  "Feature_HasLaLocalWithAbs",
  "Feature_IsLA32",
  "Feature_IsLA64",
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
    Msg << "Attempting to emit " << &LoongArchInstrNameData[LoongArchInstrNameIndices[Opcode]]
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::LoongArch_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

