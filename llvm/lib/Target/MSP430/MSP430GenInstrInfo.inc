/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::MSP430 {

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
    ADD16mc                               = 331, // MSP430InstrInfo.td:499
    ADD16mi                               = 332, // MSP430InstrInfo.td:505
    ADD16mm                               = 333, // MSP430InstrInfo.td:512
    ADD16mn                               = 334, // MSP430InstrInfo.td:518
    ADD16mp                               = 335, // MSP430InstrInfo.td:522
    ADD16mr                               = 336, // MSP430InstrInfo.td:493
    ADD16rc                               = 337, // MSP430InstrInfo.td:480
    ADD16ri                               = 338, // MSP430InstrInfo.td:486
    ADD16rm                               = 339, // MSP430InstrInfo.td:462
    ADD16rn                               = 340, // MSP430InstrInfo.td:467
    ADD16rp                               = 341, // MSP430InstrInfo.td:474
    ADD16rr                               = 342, // MSP430InstrInfo.td:455
    ADD8mc                                = 343, // MSP430InstrInfo.td:496
    ADD8mi                                = 344, // MSP430InstrInfo.td:502
    ADD8mm                                = 345, // MSP430InstrInfo.td:508
    ADD8mn                                = 346, // MSP430InstrInfo.td:516
    ADD8mp                                = 347, // MSP430InstrInfo.td:520
    ADD8mr                                = 348, // MSP430InstrInfo.td:490
    ADD8rc                                = 349, // MSP430InstrInfo.td:477
    ADD8ri                                = 350, // MSP430InstrInfo.td:483
    ADD8rm                                = 351, // MSP430InstrInfo.td:459
    ADD8rn                                = 352, // MSP430InstrInfo.td:465
    ADD8rp                                = 353, // MSP430InstrInfo.td:472
    ADD8rr                                = 354, // MSP430InstrInfo.td:452
    ADDC16mc                              = 355, // MSP430InstrInfo.td:499
    ADDC16mi                              = 356, // MSP430InstrInfo.td:505
    ADDC16mm                              = 357, // MSP430InstrInfo.td:512
    ADDC16mn                              = 358, // MSP430InstrInfo.td:518
    ADDC16mp                              = 359, // MSP430InstrInfo.td:522
    ADDC16mr                              = 360, // MSP430InstrInfo.td:493
    ADDC16rc                              = 361, // MSP430InstrInfo.td:480
    ADDC16ri                              = 362, // MSP430InstrInfo.td:486
    ADDC16rm                              = 363, // MSP430InstrInfo.td:462
    ADDC16rn                              = 364, // MSP430InstrInfo.td:467
    ADDC16rp                              = 365, // MSP430InstrInfo.td:474
    ADDC16rr                              = 366, // MSP430InstrInfo.td:455
    ADDC8mc                               = 367, // MSP430InstrInfo.td:496
    ADDC8mi                               = 368, // MSP430InstrInfo.td:502
    ADDC8mm                               = 369, // MSP430InstrInfo.td:508
    ADDC8mn                               = 370, // MSP430InstrInfo.td:516
    ADDC8mp                               = 371, // MSP430InstrInfo.td:520
    ADDC8mr                               = 372, // MSP430InstrInfo.td:490
    ADDC8rc                               = 373, // MSP430InstrInfo.td:477
    ADDC8ri                               = 374, // MSP430InstrInfo.td:483
    ADDC8rm                               = 375, // MSP430InstrInfo.td:459
    ADDC8rn                               = 376, // MSP430InstrInfo.td:465
    ADDC8rp                               = 377, // MSP430InstrInfo.td:472
    ADDC8rr                               = 378, // MSP430InstrInfo.td:452
    ADDframe                              = 379, // MSP430InstrInfo.td:183
    ADJCALLSTACKDOWN                      = 380, // MSP430InstrInfo.td:174
    ADJCALLSTACKUP                        = 381, // MSP430InstrInfo.td:177
    AND16mc                               = 382, // MSP430InstrInfo.td:499
    AND16mi                               = 383, // MSP430InstrInfo.td:505
    AND16mm                               = 384, // MSP430InstrInfo.td:512
    AND16mn                               = 385, // MSP430InstrInfo.td:518
    AND16mp                               = 386, // MSP430InstrInfo.td:522
    AND16mr                               = 387, // MSP430InstrInfo.td:493
    AND16rc                               = 388, // MSP430InstrInfo.td:480
    AND16ri                               = 389, // MSP430InstrInfo.td:486
    AND16rm                               = 390, // MSP430InstrInfo.td:462
    AND16rn                               = 391, // MSP430InstrInfo.td:467
    AND16rp                               = 392, // MSP430InstrInfo.td:474
    AND16rr                               = 393, // MSP430InstrInfo.td:455
    AND8mc                                = 394, // MSP430InstrInfo.td:496
    AND8mi                                = 395, // MSP430InstrInfo.td:502
    AND8mm                                = 396, // MSP430InstrInfo.td:508
    AND8mn                                = 397, // MSP430InstrInfo.td:516
    AND8mp                                = 398, // MSP430InstrInfo.td:520
    AND8mr                                = 399, // MSP430InstrInfo.td:490
    AND8rc                                = 400, // MSP430InstrInfo.td:477
    AND8ri                                = 401, // MSP430InstrInfo.td:483
    AND8rm                                = 402, // MSP430InstrInfo.td:459
    AND8rn                                = 403, // MSP430InstrInfo.td:465
    AND8rp                                = 404, // MSP430InstrInfo.td:472
    AND8rr                                = 405, // MSP430InstrInfo.td:452
    BIC16mc                               = 406, // MSP430InstrInfo.td:499
    BIC16mi                               = 407, // MSP430InstrInfo.td:505
    BIC16mm                               = 408, // MSP430InstrInfo.td:512
    BIC16mn                               = 409, // MSP430InstrInfo.td:518
    BIC16mp                               = 410, // MSP430InstrInfo.td:522
    BIC16mr                               = 411, // MSP430InstrInfo.td:493
    BIC16rc                               = 412, // MSP430InstrInfo.td:480
    BIC16ri                               = 413, // MSP430InstrInfo.td:486
    BIC16rm                               = 414, // MSP430InstrInfo.td:462
    BIC16rn                               = 415, // MSP430InstrInfo.td:467
    BIC16rp                               = 416, // MSP430InstrInfo.td:474
    BIC16rr                               = 417, // MSP430InstrInfo.td:455
    BIC8mc                                = 418, // MSP430InstrInfo.td:496
    BIC8mi                                = 419, // MSP430InstrInfo.td:502
    BIC8mm                                = 420, // MSP430InstrInfo.td:508
    BIC8mn                                = 421, // MSP430InstrInfo.td:516
    BIC8mp                                = 422, // MSP430InstrInfo.td:520
    BIC8mr                                = 423, // MSP430InstrInfo.td:490
    BIC8rc                                = 424, // MSP430InstrInfo.td:477
    BIC8ri                                = 425, // MSP430InstrInfo.td:483
    BIC8rm                                = 426, // MSP430InstrInfo.td:459
    BIC8rn                                = 427, // MSP430InstrInfo.td:465
    BIC8rp                                = 428, // MSP430InstrInfo.td:472
    BIC8rr                                = 429, // MSP430InstrInfo.td:452
    BIS16mc                               = 430, // MSP430InstrInfo.td:499
    BIS16mi                               = 431, // MSP430InstrInfo.td:505
    BIS16mm                               = 432, // MSP430InstrInfo.td:512
    BIS16mn                               = 433, // MSP430InstrInfo.td:518
    BIS16mp                               = 434, // MSP430InstrInfo.td:522
    BIS16mr                               = 435, // MSP430InstrInfo.td:493
    BIS16rc                               = 436, // MSP430InstrInfo.td:480
    BIS16ri                               = 437, // MSP430InstrInfo.td:486
    BIS16rm                               = 438, // MSP430InstrInfo.td:462
    BIS16rn                               = 439, // MSP430InstrInfo.td:467
    BIS16rp                               = 440, // MSP430InstrInfo.td:474
    BIS16rr                               = 441, // MSP430InstrInfo.td:455
    BIS8mc                                = 442, // MSP430InstrInfo.td:496
    BIS8mi                                = 443, // MSP430InstrInfo.td:502
    BIS8mm                                = 444, // MSP430InstrInfo.td:508
    BIS8mn                                = 445, // MSP430InstrInfo.td:516
    BIS8mp                                = 446, // MSP430InstrInfo.td:520
    BIS8mr                                = 447, // MSP430InstrInfo.td:490
    BIS8rc                                = 448, // MSP430InstrInfo.td:477
    BIS8ri                                = 449, // MSP430InstrInfo.td:483
    BIS8rm                                = 450, // MSP430InstrInfo.td:459
    BIS8rn                                = 451, // MSP430InstrInfo.td:465
    BIS8rp                                = 452, // MSP430InstrInfo.td:472
    BIS8rr                                = 453, // MSP430InstrInfo.td:452
    BIT16mc                               = 454, // MSP430InstrInfo.td:861
    BIT16mi                               = 455, // MSP430InstrInfo.td:870
    BIT16mm                               = 456, // MSP430InstrInfo.td:881
    BIT16mn                               = 457, // MSP430InstrInfo.td:889
    BIT16mp                               = 458, // MSP430InstrInfo.td:894
    BIT16mr                               = 459, // MSP430InstrInfo.td:852
    BIT16rc                               = 460, // MSP430InstrInfo.td:815
    BIT16ri                               = 461, // MSP430InstrInfo.td:824
    BIT16rm                               = 462, // MSP430InstrInfo.td:833
    BIT16rn                               = 463, // MSP430InstrInfo.td:840
    BIT16rp                               = 464, // MSP430InstrInfo.td:845
    BIT16rr                               = 465, // MSP430InstrInfo.td:806
    BIT8mc                                = 466, // MSP430InstrInfo.td:857
    BIT8mi                                = 467, // MSP430InstrInfo.td:866
    BIT8mm                                = 468, // MSP430InstrInfo.td:875
    BIT8mn                                = 469, // MSP430InstrInfo.td:887
    BIT8mp                                = 470, // MSP430InstrInfo.td:892
    BIT8mr                                = 471, // MSP430InstrInfo.td:848
    BIT8rc                                = 472, // MSP430InstrInfo.td:811
    BIT8ri                                = 473, // MSP430InstrInfo.td:820
    BIT8rm                                = 474, // MSP430InstrInfo.td:829
    BIT8rn                                = 475, // MSP430InstrInfo.td:838
    BIT8rp                                = 476, // MSP430InstrInfo.td:843
    BIT8rr                                = 477, // MSP430InstrInfo.td:802
    Bi                                    = 478, // MSP430InstrInfo.td:255
    Bm                                    = 479, // MSP430InstrInfo.td:261
    Br                                    = 480, // MSP430InstrInfo.td:258
    CALLi                                 = 481, // MSP430InstrInfo.td:284
    CALLm                                 = 482, // MSP430InstrInfo.td:290
    CALLn                                 = 483, // MSP430InstrInfo.td:293
    CALLp                                 = 484, // MSP430InstrInfo.td:294
    CALLr                                 = 485, // MSP430InstrInfo.td:287
    CMP16mc                               = 486, // MSP430InstrInfo.td:738
    CMP16mi                               = 487, // MSP430InstrInfo.td:748
    CMP16mm                               = 488, // MSP430InstrInfo.td:785
    CMP16mn                               = 489, // MSP430InstrInfo.td:791
    CMP16mp                               = 490, // MSP430InstrInfo.td:796
    CMP16mr                               = 491, // MSP430InstrInfo.td:777
    CMP16rc                               = 492, // MSP430InstrInfo.td:720
    CMP16ri                               = 493, // MSP430InstrInfo.td:729
    CMP16rm                               = 494, // MSP430InstrInfo.td:758
    CMP16rn                               = 495, // MSP430InstrInfo.td:765
    CMP16rp                               = 496, // MSP430InstrInfo.td:770
    CMP16rr                               = 497, // MSP430InstrInfo.td:711
    CMP8mc                                = 498, // MSP430InstrInfo.td:734
    CMP8mi                                = 499, // MSP430InstrInfo.td:743
    CMP8mm                                = 500, // MSP430InstrInfo.td:781
    CMP8mn                                = 501, // MSP430InstrInfo.td:789
    CMP8mp                                = 502, // MSP430InstrInfo.td:794
    CMP8mr                                = 503, // MSP430InstrInfo.td:773
    CMP8rc                                = 504, // MSP430InstrInfo.td:716
    CMP8ri                                = 505, // MSP430InstrInfo.td:725
    CMP8rm                                = 506, // MSP430InstrInfo.td:754
    CMP8rn                                = 507, // MSP430InstrInfo.td:763
    CMP8rp                                = 508, // MSP430InstrInfo.td:768
    CMP8rr                                = 509, // MSP430InstrInfo.td:707
    DADD16mc                              = 510, // MSP430InstrInfo.td:499
    DADD16mi                              = 511, // MSP430InstrInfo.td:505
    DADD16mm                              = 512, // MSP430InstrInfo.td:512
    DADD16mn                              = 513, // MSP430InstrInfo.td:518
    DADD16mp                              = 514, // MSP430InstrInfo.td:522
    DADD16mr                              = 515, // MSP430InstrInfo.td:493
    DADD16rc                              = 516, // MSP430InstrInfo.td:480
    DADD16ri                              = 517, // MSP430InstrInfo.td:486
    DADD16rm                              = 518, // MSP430InstrInfo.td:462
    DADD16rn                              = 519, // MSP430InstrInfo.td:467
    DADD16rp                              = 520, // MSP430InstrInfo.td:474
    DADD16rr                              = 521, // MSP430InstrInfo.td:455
    DADD8mc                               = 522, // MSP430InstrInfo.td:496
    DADD8mi                               = 523, // MSP430InstrInfo.td:502
    DADD8mm                               = 524, // MSP430InstrInfo.td:508
    DADD8mn                               = 525, // MSP430InstrInfo.td:516
    DADD8mp                               = 526, // MSP430InstrInfo.td:520
    DADD8mr                               = 527, // MSP430InstrInfo.td:490
    DADD8rc                               = 528, // MSP430InstrInfo.td:477
    DADD8ri                               = 529, // MSP430InstrInfo.td:483
    DADD8rm                               = 530, // MSP430InstrInfo.td:459
    DADD8rn                               = 531, // MSP430InstrInfo.td:465
    DADD8rp                               = 532, // MSP430InstrInfo.td:472
    DADD8rr                               = 533, // MSP430InstrInfo.td:452
    JCC                                   = 534, // MSP430InstrInfo.td:269
    JMP                                   = 535, // MSP430InstrInfo.td:248
    MOV16mc                               = 536, // MSP430InstrInfo.td:407
    MOV16mi                               = 537, // MSP430InstrInfo.td:416
    MOV16mm                               = 538, // MSP430InstrInfo.td:434
    MOV16mn                               = 539, // MSP430InstrInfo.td:441
    MOV16mr                               = 540, // MSP430InstrInfo.td:425
    MOV16rc                               = 541, // MSP430InstrInfo.td:335
    MOV16ri                               = 542, // MSP430InstrInfo.td:343
    MOV16rm                               = 543, // MSP430InstrInfo.td:354
    MOV16rn                               = 544, // MSP430InstrInfo.td:362
    MOV16rp                               = 545, // MSP430InstrInfo.td:383
    MOV16rr                               = 546, // MSP430InstrInfo.td:324
    MOV8mc                                = 547, // MSP430InstrInfo.td:403
    MOV8mi                                = 548, // MSP430InstrInfo.td:412
    MOV8mm                                = 549, // MSP430InstrInfo.td:430
    MOV8mn                                = 550, // MSP430InstrInfo.td:439
    MOV8mr                                = 551, // MSP430InstrInfo.td:421
    MOV8rc                                = 552, // MSP430InstrInfo.td:331
    MOV8ri                                = 553, // MSP430InstrInfo.td:339
    MOV8rm                                = 554, // MSP430InstrInfo.td:350
    MOV8rn                                = 555, // MSP430InstrInfo.td:358
    MOV8rp                                = 556, // MSP430InstrInfo.td:380
    MOV8rr                                = 557, // MSP430InstrInfo.td:320
    MOVZX16rm8                            = 558, // MSP430InstrInfo.td:373
    MOVZX16rr8                            = 559, // MSP430InstrInfo.td:369
    POP16r                                = 560, // MSP430InstrInfo.td:302
    PUSH16c                               = 561, // MSP430InstrInfo.td:311
    PUSH16i                               = 562, // MSP430InstrInfo.td:312
    PUSH16r                               = 563, // MSP430InstrInfo.td:310
    PUSH8r                                = 564, // MSP430InstrInfo.td:309
    RET                                   = 565, // MSP430InstrInfo.td:229
    RETI                                  = 566, // MSP430InstrInfo.td:235
    RRA16m                                = 567, // MSP430InstrInfo.td:661
    RRA16n                                = 568, // MSP430InstrInfo.td:667
    RRA16p                                = 569, // MSP430InstrInfo.td:669
    RRA16r                                = 570, // MSP430InstrInfo.td:619
    RRA8m                                 = 571, // MSP430InstrInfo.td:657
    RRA8n                                 = 572, // MSP430InstrInfo.td:666
    RRA8p                                 = 573, // MSP430InstrInfo.td:668
    RRA8r                                 = 574, // MSP430InstrInfo.td:615
    RRC16m                                = 575, // MSP430InstrInfo.td:676
    RRC16n                                = 576, // MSP430InstrInfo.td:682
    RRC16p                                = 577, // MSP430InstrInfo.td:684
    RRC16r                                = 578, // MSP430InstrInfo.td:629
    RRC8m                                 = 579, // MSP430InstrInfo.td:672
    RRC8n                                 = 580, // MSP430InstrInfo.td:681
    RRC8p                                 = 581, // MSP430InstrInfo.td:683
    RRC8r                                 = 582, // MSP430InstrInfo.td:625
    Rrcl16                                = 583, // MSP430InstrInfo.td:219
    Rrcl8                                 = 584, // MSP430InstrInfo.td:217
    SEXT16m                               = 585, // MSP430InstrInfo.td:688
    SEXT16n                               = 586, // MSP430InstrInfo.td:693
    SEXT16p                               = 587, // MSP430InstrInfo.td:694
    SEXT16r                               = 588, // MSP430InstrInfo.td:635
    SUB16mc                               = 589, // MSP430InstrInfo.td:499
    SUB16mi                               = 590, // MSP430InstrInfo.td:505
    SUB16mm                               = 591, // MSP430InstrInfo.td:512
    SUB16mn                               = 592, // MSP430InstrInfo.td:518
    SUB16mp                               = 593, // MSP430InstrInfo.td:522
    SUB16mr                               = 594, // MSP430InstrInfo.td:493
    SUB16rc                               = 595, // MSP430InstrInfo.td:480
    SUB16ri                               = 596, // MSP430InstrInfo.td:486
    SUB16rm                               = 597, // MSP430InstrInfo.td:462
    SUB16rn                               = 598, // MSP430InstrInfo.td:467
    SUB16rp                               = 599, // MSP430InstrInfo.td:474
    SUB16rr                               = 600, // MSP430InstrInfo.td:455
    SUB8mc                                = 601, // MSP430InstrInfo.td:496
    SUB8mi                                = 602, // MSP430InstrInfo.td:502
    SUB8mm                                = 603, // MSP430InstrInfo.td:508
    SUB8mn                                = 604, // MSP430InstrInfo.td:516
    SUB8mp                                = 605, // MSP430InstrInfo.td:520
    SUB8mr                                = 606, // MSP430InstrInfo.td:490
    SUB8rc                                = 607, // MSP430InstrInfo.td:477
    SUB8ri                                = 608, // MSP430InstrInfo.td:483
    SUB8rm                                = 609, // MSP430InstrInfo.td:459
    SUB8rn                                = 610, // MSP430InstrInfo.td:465
    SUB8rp                                = 611, // MSP430InstrInfo.td:472
    SUB8rr                                = 612, // MSP430InstrInfo.td:452
    SUBC16mc                              = 613, // MSP430InstrInfo.td:499
    SUBC16mi                              = 614, // MSP430InstrInfo.td:505
    SUBC16mm                              = 615, // MSP430InstrInfo.td:512
    SUBC16mn                              = 616, // MSP430InstrInfo.td:518
    SUBC16mp                              = 617, // MSP430InstrInfo.td:522
    SUBC16mr                              = 618, // MSP430InstrInfo.td:493
    SUBC16rc                              = 619, // MSP430InstrInfo.td:480
    SUBC16ri                              = 620, // MSP430InstrInfo.td:486
    SUBC16rm                              = 621, // MSP430InstrInfo.td:462
    SUBC16rn                              = 622, // MSP430InstrInfo.td:467
    SUBC16rp                              = 623, // MSP430InstrInfo.td:474
    SUBC16rr                              = 624, // MSP430InstrInfo.td:455
    SUBC8mc                               = 625, // MSP430InstrInfo.td:496
    SUBC8mi                               = 626, // MSP430InstrInfo.td:502
    SUBC8mm                               = 627, // MSP430InstrInfo.td:508
    SUBC8mn                               = 628, // MSP430InstrInfo.td:516
    SUBC8mp                               = 629, // MSP430InstrInfo.td:520
    SUBC8mr                               = 630, // MSP430InstrInfo.td:490
    SUBC8rc                               = 631, // MSP430InstrInfo.td:477
    SUBC8ri                               = 632, // MSP430InstrInfo.td:483
    SUBC8rm                               = 633, // MSP430InstrInfo.td:459
    SUBC8rn                               = 634, // MSP430InstrInfo.td:465
    SUBC8rp                               = 635, // MSP430InstrInfo.td:472
    SUBC8rr                               = 636, // MSP430InstrInfo.td:452
    SWPB16m                               = 637, // MSP430InstrInfo.td:698
    SWPB16n                               = 638, // MSP430InstrInfo.td:702
    SWPB16p                               = 639, // MSP430InstrInfo.td:703
    SWPB16r                               = 640, // MSP430InstrInfo.td:648
    Select16                              = 641, // MSP430InstrInfo.td:193
    Select8                               = 642, // MSP430InstrInfo.td:189
    Shl16                                 = 643, // MSP430InstrInfo.td:202
    Shl8                                  = 644, // MSP430InstrInfo.td:199
    Sra16                                 = 645, // MSP430InstrInfo.td:208
    Sra8                                  = 646, // MSP430InstrInfo.td:205
    Srl16                                 = 647, // MSP430InstrInfo.td:214
    Srl8                                  = 648, // MSP430InstrInfo.td:211
    XOR16mc                               = 649, // MSP430InstrInfo.td:499
    XOR16mi                               = 650, // MSP430InstrInfo.td:505
    XOR16mm                               = 651, // MSP430InstrInfo.td:512
    XOR16mn                               = 652, // MSP430InstrInfo.td:518
    XOR16mp                               = 653, // MSP430InstrInfo.td:522
    XOR16mr                               = 654, // MSP430InstrInfo.td:493
    XOR16rc                               = 655, // MSP430InstrInfo.td:480
    XOR16ri                               = 656, // MSP430InstrInfo.td:486
    XOR16rm                               = 657, // MSP430InstrInfo.td:462
    XOR16rn                               = 658, // MSP430InstrInfo.td:467
    XOR16rp                               = 659, // MSP430InstrInfo.td:474
    XOR16rr                               = 660, // MSP430InstrInfo.td:455
    XOR8mc                                = 661, // MSP430InstrInfo.td:496
    XOR8mi                                = 662, // MSP430InstrInfo.td:502
    XOR8mm                                = 663, // MSP430InstrInfo.td:508
    XOR8mn                                = 664, // MSP430InstrInfo.td:516
    XOR8mp                                = 665, // MSP430InstrInfo.td:520
    XOR8mr                                = 666, // MSP430InstrInfo.td:490
    XOR8rc                                = 667, // MSP430InstrInfo.td:477
    XOR8ri                                = 668, // MSP430InstrInfo.td:483
    XOR8rm                                = 669, // MSP430InstrInfo.td:459
    XOR8rn                                = 670, // MSP430InstrInfo.td:465
    XOR8rp                                = 671, // MSP430InstrInfo.td:472
    XOR8rr                                = 672, // MSP430InstrInfo.td:452
    ZEXT16r                               = 673, // MSP430InstrInfo.td:643
    INSTRUCTION_LIST_END = 674
  };

} // namespace llvm_ks::MSP430

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::MSP430::Sched {

  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };

} // namespace llvm_ks::MSP430::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct MSP430InstrTable {
  MCInstrDesc Insts[674];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[17];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[260];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof MSP430InstrTable::ImplicitOps + sizeof MSP430InstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned MSP430OpInfoBase = (sizeof MSP430InstrTable::ImplicitOps + sizeof MSP430InstrTable::Padding) / sizeof(MCOperandInfo);

extern const MSP430InstrTable MSP430Descs = {
  {
    { 673,	2,	1,	2,	0,	0,	0,	MSP430OpInfoBase + 242,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ZEXT16r
    { 672,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 207,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8rr
    { 671,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 203,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8rp
    { 670,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 200,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8rn
    { 669,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 196,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8rm
    { 668,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 193,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8ri
    { 667,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 190,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8rc
    { 666,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 187,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8mr
    { 665,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8mp
    { 664,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8mn
    { 663,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8mm
    { 662,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8mi
    { 661,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8mc
    { 660,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 184,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16rr
    { 659,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 180,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16rp
    { 658,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 177,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16rn
    { 657,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 173,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16rm
    { 656,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 170,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16ri
    { 655,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 167,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16rc
    { 654,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 164,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16mr
    { 653,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16mp
    { 652,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16mn
    { 651,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16mm
    { 650,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16mi
    { 649,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16mc
    { 648,	3,	1,	0,	0,	0,	1,	MSP430OpInfoBase + 257,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Srl8
    { 647,	3,	1,	0,	0,	0,	1,	MSP430OpInfoBase + 254,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Srl16
    { 646,	3,	1,	0,	0,	0,	1,	MSP430OpInfoBase + 257,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Sra8
    { 645,	3,	1,	0,	0,	0,	1,	MSP430OpInfoBase + 254,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Sra16
    { 644,	3,	1,	0,	0,	0,	1,	MSP430OpInfoBase + 257,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Shl8
    { 643,	3,	1,	0,	0,	0,	1,	MSP430OpInfoBase + 254,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Shl16
    { 642,	4,	1,	0,	0,	1,	0,	MSP430OpInfoBase + 250,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Select8
    { 641,	4,	1,	0,	0,	1,	0,	MSP430OpInfoBase + 246,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Select16
    { 640,	2,	1,	2,	0,	0,	0,	MSP430OpInfoBase + 242,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SWPB16r
    { 639,	1,	0,	2,	0,	0,	0,	MSP430OpInfoBase + 232,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SWPB16p
    { 638,	1,	0,	2,	0,	0,	0,	MSP430OpInfoBase + 232,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SWPB16n
    { 637,	2,	0,	4,	0,	0,	0,	MSP430OpInfoBase + 230,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SWPB16m
    { 636,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 207,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8rr
    { 635,	4,	2,	2,	0,	1,	1,	MSP430OpInfoBase + 203,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8rp
    { 634,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 200,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8rn
    { 633,	4,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 196,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8rm
    { 632,	3,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 193,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8ri
    { 631,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 190,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8rc
    { 630,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 187,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8mr
    { 629,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8mp
    { 628,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8mn
    { 627,	4,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 157,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8mm
    { 626,	3,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 154,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8mi
    { 625,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 151,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC8mc
    { 624,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 184,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16rr
    { 623,	4,	2,	2,	0,	1,	1,	MSP430OpInfoBase + 180,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16rp
    { 622,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 177,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16rn
    { 621,	4,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 173,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16rm
    { 620,	3,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 170,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16ri
    { 619,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 167,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16rc
    { 618,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 164,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16mr
    { 617,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16mp
    { 616,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16mn
    { 615,	4,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 157,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16mm
    { 614,	3,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 154,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16mi
    { 613,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 151,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBC16mc
    { 612,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 207,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8rr
    { 611,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 203,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8rp
    { 610,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 200,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8rn
    { 609,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 196,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8rm
    { 608,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 193,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8ri
    { 607,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 190,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8rc
    { 606,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 187,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8mr
    { 605,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8mp
    { 604,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8mn
    { 603,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8mm
    { 602,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8mi
    { 601,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8mc
    { 600,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 184,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16rr
    { 599,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 180,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16rp
    { 598,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 177,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16rn
    { 597,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 173,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16rm
    { 596,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 170,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16ri
    { 595,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 167,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16rc
    { 594,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 164,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16mr
    { 593,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16mp
    { 592,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16mn
    { 591,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16mm
    { 590,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16mi
    { 589,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16mc
    { 588,	2,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 242,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SEXT16r
    { 587,	1,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 232,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SEXT16p
    { 586,	1,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 232,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SEXT16n
    { 585,	2,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 230,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SEXT16m
    { 584,	2,	1,	0,	0,	0,	1,	MSP430OpInfoBase + 228,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Rrcl8
    { 583,	2,	1,	0,	0,	0,	1,	MSP430OpInfoBase + 217,	0,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Rrcl16
    { 582,	2,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 244,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRC8r
    { 581,	1,	0,	2,	0,	1,	1,	MSP430OpInfoBase + 232,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRC8p
    { 580,	1,	0,	2,	0,	1,	1,	MSP430OpInfoBase + 232,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRC8n
    { 579,	2,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 230,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRC8m
    { 578,	2,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 242,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRC16r
    { 577,	1,	0,	2,	0,	1,	1,	MSP430OpInfoBase + 232,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRC16p
    { 576,	1,	0,	2,	0,	1,	1,	MSP430OpInfoBase + 232,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRC16n
    { 575,	2,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 230,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRC16m
    { 574,	2,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 244,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRA8r
    { 573,	1,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 232,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRA8p
    { 572,	1,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 232,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRA8n
    { 571,	2,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 230,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRA8m
    { 570,	2,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 242,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRA16r
    { 569,	1,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 232,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRA16p
    { 568,	1,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 232,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRA16n
    { 567,	2,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 230,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RRA16m
    { 566,	0,	0,	2,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RETI
    { 565,	0,	0,	2,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET
    { 564,	1,	0,	2,	0,	1,	1,	MSP430OpInfoBase + 241,	15,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PUSH8r
    { 563,	1,	0,	2,	0,	1,	1,	MSP430OpInfoBase + 28,	15,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PUSH16r
    { 562,	1,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 1,	15,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PUSH16i
    { 561,	1,	0,	2,	0,	1,	1,	MSP430OpInfoBase + 0,	15,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PUSH16c
    { 560,	1,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 28,	15,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POP16r
    { 559,	2,	1,	2,	0,	0,	0,	MSP430OpInfoBase + 239,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZX16rr8
    { 558,	3,	1,	4,	0,	0,	0,	MSP430OpInfoBase + 212,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZX16rm8
    { 557,	2,	1,	2,	0,	0,	0,	MSP430OpInfoBase + 228,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8rr
    { 556,	3,	2,	2,	0,	0,	0,	MSP430OpInfoBase + 236,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8rp
    { 555,	2,	1,	2,	0,	0,	0,	MSP430OpInfoBase + 226,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8rn
    { 554,	3,	1,	4,	0,	0,	0,	MSP430OpInfoBase + 223,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8rm
    { 553,	2,	1,	4,	0,	0,	0,	MSP430OpInfoBase + 221,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ri
    { 552,	2,	1,	2,	0,	0,	0,	MSP430OpInfoBase + 219,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8rc
    { 551,	3,	0,	4,	0,	0,	0,	MSP430OpInfoBase + 187,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8mr
    { 550,	3,	0,	4,	0,	0,	0,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8mn
    { 549,	4,	0,	6,	0,	0,	0,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8mm
    { 548,	3,	0,	6,	0,	0,	0,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8mi
    { 547,	3,	0,	4,	0,	0,	0,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8mc
    { 546,	2,	1,	2,	0,	0,	0,	MSP430OpInfoBase + 217,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rr
    { 545,	3,	2,	2,	0,	0,	0,	MSP430OpInfoBase + 233,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rp
    { 544,	2,	1,	2,	0,	0,	0,	MSP430OpInfoBase + 215,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rn
    { 543,	3,	1,	4,	0,	0,	0,	MSP430OpInfoBase + 212,	0,	0|(1ULL<<MCID::FoldableAsLoad)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rm
    { 542,	2,	1,	4,	0,	0,	0,	MSP430OpInfoBase + 210,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ri
    { 541,	2,	1,	2,	0,	0,	0,	MSP430OpInfoBase + 34,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rc
    { 540,	3,	0,	4,	0,	0,	0,	MSP430OpInfoBase + 164,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16mr
    { 539,	3,	0,	4,	0,	0,	0,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16mn
    { 538,	4,	0,	6,	0,	0,	0,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16mm
    { 537,	3,	0,	6,	0,	0,	0,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16mi
    { 536,	3,	0,	4,	0,	0,	0,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16mc
    { 535,	1,	0,	2,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // JMP
    { 534,	2,	0,	2,	0,	1,	0,	MSP430OpInfoBase + 9,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // JCC
    { 533,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 207,	1,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8rr
    { 532,	4,	2,	2,	0,	1,	1,	MSP430OpInfoBase + 203,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8rp
    { 531,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 200,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8rn
    { 530,	4,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 196,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8rm
    { 529,	3,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 193,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8ri
    { 528,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 190,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8rc
    { 527,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 187,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8mr
    { 526,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8mp
    { 525,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8mn
    { 524,	4,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 157,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8mm
    { 523,	3,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 154,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8mi
    { 522,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 151,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD8mc
    { 521,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 184,	1,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16rr
    { 520,	4,	2,	2,	0,	1,	1,	MSP430OpInfoBase + 180,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16rp
    { 519,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 177,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16rn
    { 518,	4,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 173,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16rm
    { 517,	3,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 170,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16ri
    { 516,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 167,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16rc
    { 515,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 164,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16mr
    { 514,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16mp
    { 513,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16mn
    { 512,	4,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 157,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16mm
    { 511,	3,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 154,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16mi
    { 510,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 151,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DADD16mc
    { 509,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 228,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8rr
    { 508,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 226,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8rp
    { 507,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 226,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8rn
    { 506,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 223,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8rm
    { 505,	2,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 221,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8ri
    { 504,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 219,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8rc
    { 503,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 187,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8mr
    { 502,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8mp
    { 501,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8mn
    { 500,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8mm
    { 499,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8mi
    { 498,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8mc
    { 497,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 217,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16rr
    { 496,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 215,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16rp
    { 495,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 215,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16rn
    { 494,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 212,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16rm
    { 493,	2,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 210,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16ri
    { 492,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 34,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16rc
    { 491,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 164,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16mr
    { 490,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16mp
    { 489,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16mn
    { 488,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16mm
    { 487,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16mi
    { 486,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16mc
    { 485,	1,	0,	2,	0,	1,	6,	MSP430OpInfoBase + 28,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLr
    { 484,	1,	0,	2,	0,	1,	6,	MSP430OpInfoBase + 232,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLp
    { 483,	1,	0,	2,	0,	1,	6,	MSP430OpInfoBase + 232,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLn
    { 482,	2,	0,	4,	0,	1,	6,	MSP430OpInfoBase + 230,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLm
    { 481,	1,	0,	4,	0,	1,	6,	MSP430OpInfoBase + 1,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLi
    { 480,	1,	0,	2,	0,	0,	0,	MSP430OpInfoBase + 28,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Br
    { 479,	2,	0,	4,	0,	0,	0,	MSP430OpInfoBase + 230,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bm
    { 478,	1,	0,	4,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bi
    { 477,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 228,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8rr
    { 476,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 226,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8rp
    { 475,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 226,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8rn
    { 474,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 223,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8rm
    { 473,	2,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 221,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8ri
    { 472,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 219,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8rc
    { 471,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 187,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8mr
    { 470,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8mp
    { 469,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8mn
    { 468,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8mm
    { 467,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8mi
    { 466,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT8mc
    { 465,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 217,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16rr
    { 464,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 215,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16rp
    { 463,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 215,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16rn
    { 462,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 212,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16rm
    { 461,	2,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 210,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16ri
    { 460,	2,	0,	2,	0,	0,	1,	MSP430OpInfoBase + 34,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16rc
    { 459,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 164,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16mr
    { 458,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16mp
    { 457,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16mn
    { 456,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16mm
    { 455,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16mi
    { 454,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIT16mc
    { 453,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 207,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8rr
    { 452,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 203,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8rp
    { 451,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 200,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8rn
    { 450,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 196,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8rm
    { 449,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 193,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8ri
    { 448,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 190,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8rc
    { 447,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 187,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8mr
    { 446,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8mp
    { 445,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8mn
    { 444,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8mm
    { 443,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8mi
    { 442,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS8mc
    { 441,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 184,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16rr
    { 440,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 180,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16rp
    { 439,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 177,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16rn
    { 438,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 173,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16rm
    { 437,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 170,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16ri
    { 436,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 167,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16rc
    { 435,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 164,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16mr
    { 434,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16mp
    { 433,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16mn
    { 432,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16mm
    { 431,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16mi
    { 430,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIS16mc
    { 429,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 207,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8rr
    { 428,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 203,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8rp
    { 427,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 200,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8rn
    { 426,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 196,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8rm
    { 425,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 193,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8ri
    { 424,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 190,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8rc
    { 423,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 187,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8mr
    { 422,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8mp
    { 421,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8mn
    { 420,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8mm
    { 419,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8mi
    { 418,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC8mc
    { 417,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 184,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16rr
    { 416,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 180,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16rp
    { 415,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 177,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16rn
    { 414,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 173,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16rm
    { 413,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 170,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16ri
    { 412,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 167,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16rc
    { 411,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 164,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16mr
    { 410,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16mp
    { 409,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16mn
    { 408,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16mm
    { 407,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16mi
    { 406,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BIC16mc
    { 405,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 207,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8rr
    { 404,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 203,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8rp
    { 403,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 200,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8rn
    { 402,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 196,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8rm
    { 401,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 193,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8ri
    { 400,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 190,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8rc
    { 399,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 187,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8mr
    { 398,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8mp
    { 397,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8mn
    { 396,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8mm
    { 395,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8mi
    { 394,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8mc
    { 393,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 184,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16rr
    { 392,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 180,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16rp
    { 391,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 177,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16rn
    { 390,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 173,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16rm
    { 389,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 170,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16ri
    { 388,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 167,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16rc
    { 387,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 164,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16mr
    { 386,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16mp
    { 385,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16mn
    { 384,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16mm
    { 383,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16mi
    { 382,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16mc
    { 381,	2,	0,	0,	0,	1,	2,	MSP430OpInfoBase + 20,	5,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKUP
    { 380,	2,	0,	0,	0,	1,	2,	MSP430OpInfoBase + 20,	5,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKDOWN
    { 379,	3,	1,	0,	0,	1,	1,	MSP430OpInfoBase + 29,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDframe
    { 378,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 207,	1,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8rr
    { 377,	4,	2,	2,	0,	1,	1,	MSP430OpInfoBase + 203,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8rp
    { 376,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 200,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8rn
    { 375,	4,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 196,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8rm
    { 374,	3,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 193,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8ri
    { 373,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 190,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8rc
    { 372,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 187,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8mr
    { 371,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8mp
    { 370,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8mn
    { 369,	4,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 157,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8mm
    { 368,	3,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 154,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8mi
    { 367,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 151,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC8mc
    { 366,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 184,	1,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16rr
    { 365,	4,	2,	2,	0,	1,	1,	MSP430OpInfoBase + 180,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16rp
    { 364,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 177,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16rn
    { 363,	4,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 173,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16rm
    { 362,	3,	1,	4,	0,	1,	1,	MSP430OpInfoBase + 170,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16ri
    { 361,	3,	1,	2,	0,	1,	1,	MSP430OpInfoBase + 167,	1,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16rc
    { 360,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 164,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16mr
    { 359,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16mp
    { 358,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 161,	1,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16mn
    { 357,	4,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 157,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16mm
    { 356,	3,	0,	6,	0,	1,	1,	MSP430OpInfoBase + 154,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16mi
    { 355,	3,	0,	4,	0,	1,	1,	MSP430OpInfoBase + 151,	1,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDC16mc
    { 354,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 207,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8rr
    { 353,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 203,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8rp
    { 352,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 200,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8rn
    { 351,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 196,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8rm
    { 350,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 193,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8ri
    { 349,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 190,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8rc
    { 348,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 187,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8mr
    { 347,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8mp
    { 346,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8mn
    { 345,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8mm
    { 344,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8mi
    { 343,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8mc
    { 342,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 184,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16rr
    { 341,	4,	2,	2,	0,	0,	1,	MSP430OpInfoBase + 180,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16rp
    { 340,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 177,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16rn
    { 339,	4,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 173,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16rm
    { 338,	3,	1,	4,	0,	0,	1,	MSP430OpInfoBase + 170,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16ri
    { 337,	3,	1,	2,	0,	0,	1,	MSP430OpInfoBase + 167,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16rc
    { 336,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 164,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16mr
    { 335,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16mp
    { 334,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 161,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16mn
    { 333,	4,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 157,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16mm
    { 332,	3,	0,	6,	0,	0,	1,	MSP430OpInfoBase + 154,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16mi
    { 331,	3,	0,	4,	0,	0,	1,	MSP430OpInfoBase + 151,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16mc
    { 330,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	MSP430OpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13920
    { 41,	2,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13919
    { 40,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13918
    { 31,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	MSP430OpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	MSP430OpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PHI
  }, {
    /* 0 */
    /* 0 */ MSP430::SR,
    /* 1 */ MSP430::SR, MSP430::SR,
    /* 3 */ MSP430::SP, MSP430::SR,
    /* 5 */ MSP430::SP, MSP430::SP, MSP430::SR,
    /* 8 */ MSP430::SP, MSP430::R11, MSP430::R12, MSP430::R13, MSP430::R14, MSP430::R15, MSP430::SR,
    /* 15 */ MSP430::SP, MSP430::SP,
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
    /* 28 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
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
    /* 151 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 154 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 157 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 161 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 164 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 167 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 170 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 173 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 177 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 180 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, MCOI_TIED_TO(1) },
    /* 184 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 187 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 190 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 193 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 196 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 200 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 203 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, MCOI_TIED_TO(1) },
    /* 207 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 210 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 212 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 215 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 217 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 219 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 221 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 223 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 226 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 228 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 230 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 232 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 233 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, MCOI_TIED_TO(1) },
    /* 236 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_UNKNOWN, MCOI_TIED_TO(1) },
    /* 239 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 241 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 242 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 244 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 246 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 250 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 254 */ { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 257 */ { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { MSP430::GR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
  }
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char MSP430InstrNameData[] = {
  /* 0 */ "G_FLOG10\000"
  /* 9 */ "G_FEXP10\000"
  /* 18 */ "G_FLOG2\000"
  /* 26 */ "G_FATAN2\000"
  /* 35 */ "G_FEXP2\000"
  /* 43 */ "Sra16\000"
  /* 49 */ "Rrcl16\000"
  /* 56 */ "Shl16\000"
  /* 62 */ "Srl16\000"
  /* 68 */ "Select16\000"
  /* 77 */ "Sra8\000"
  /* 82 */ "Rrcl8\000"
  /* 88 */ "Shl8\000"
  /* 93 */ "Srl8\000"
  /* 98 */ "MOVZX16rm8\000"
  /* 109 */ "MOVZX16rr8\000"
  /* 120 */ "Select8\000"
  /* 128 */ "G_FMA\000"
  /* 134 */ "G_STRICT_FMA\000"
  /* 147 */ "G_FSUB\000"
  /* 154 */ "G_STRICT_FSUB\000"
  /* 168 */ "G_ATOMICRMW_FSUB\000"
  /* 185 */ "G_SUB\000"
  /* 191 */ "G_ATOMICRMW_SUB\000"
  /* 207 */ "JCC\000"
  /* 211 */ "G_INTRINSIC\000"
  /* 223 */ "G_FPTRUNC\000"
  /* 233 */ "G_INTRINSIC_TRUNC\000"
  /* 251 */ "G_TRUNC\000"
  /* 259 */ "G_BUILD_VECTOR_TRUNC\000"
  /* 280 */ "G_DYN_STACKALLOC\000"
  /* 297 */ "G_FMAD\000"
  /* 304 */ "G_FPEXTLOAD\000"
  /* 316 */ "G_INDEXED_SEXTLOAD\000"
  /* 335 */ "G_SEXTLOAD\000"
  /* 346 */ "G_INDEXED_ZEXTLOAD\000"
  /* 365 */ "G_ZEXTLOAD\000"
  /* 376 */ "G_INDEXED_LOAD\000"
  /* 391 */ "G_LOAD\000"
  /* 398 */ "G_VECREDUCE_FADD\000"
  /* 415 */ "G_FADD\000"
  /* 422 */ "G_VECREDUCE_SEQ_FADD\000"
  /* 443 */ "G_STRICT_FADD\000"
  /* 457 */ "G_ATOMICRMW_FADD\000"
  /* 474 */ "G_VECREDUCE_ADD\000"
  /* 490 */ "G_ADD\000"
  /* 496 */ "G_PTR_ADD\000"
  /* 506 */ "G_ATOMICRMW_ADD\000"
  /* 522 */ "G_ATOMICRMW_NAND\000"
  /* 539 */ "G_VECREDUCE_AND\000"
  /* 555 */ "G_AND\000"
  /* 561 */ "G_ATOMICRMW_AND\000"
  /* 577 */ "LIFETIME_END\000"
  /* 590 */ "G_BRCOND\000"
  /* 599 */ "G_ATOMICRMW_USUB_COND\000"
  /* 621 */ "G_LLROUND\000"
  /* 631 */ "G_LROUND\000"
  /* 640 */ "G_INTRINSIC_ROUND\000"
  /* 658 */ "G_INTRINSIC_FPTRUNC_ROUND\000"
  /* 684 */ "LOAD_STACK_GUARD\000"
  /* 701 */ "PSEUDO_PROBE\000"
  /* 714 */ "G_SSUBE\000"
  /* 722 */ "G_USUBE\000"
  /* 730 */ "G_FENCE\000"
  /* 738 */ "ARITH_FENCE\000"
  /* 750 */ "REG_SEQUENCE\000"
  /* 763 */ "G_SADDE\000"
  /* 771 */ "G_UADDE\000"
  /* 779 */ "G_GET_FPMODE\000"
  /* 792 */ "G_RESET_FPMODE\000"
  /* 807 */ "G_SET_FPMODE\000"
  /* 820 */ "G_FMINNUM_IEEE\000"
  /* 835 */ "G_FMAXNUM_IEEE\000"
  /* 850 */ "G_VSCALE\000"
  /* 859 */ "G_JUMP_TABLE\000"
  /* 872 */ "BUNDLE\000"
  /* 879 */ "G_MEMSET_INLINE\000"
  /* 895 */ "G_MEMCPY_INLINE\000"
  /* 911 */ "RELOC_NONE\000"
  /* 922 */ "LOCAL_ESCAPE\000"
  /* 935 */ "G_FPTRUNCSTORE\000"
  /* 950 */ "G_STACKRESTORE\000"
  /* 965 */ "G_INDEXED_STORE\000"
  /* 981 */ "G_STORE\000"
  /* 989 */ "G_BITREVERSE\000"
  /* 1002 */ "FAKE_USE\000"
  /* 1011 */ "DBG_VALUE\000"
  /* 1021 */ "G_GLOBAL_VALUE\000"
  /* 1036 */ "G_PTRAUTH_GLOBAL_VALUE\000"
  /* 1059 */ "CONVERGENCECTRL_GLUE\000"
  /* 1080 */ "G_STACKSAVE\000"
  /* 1092 */ "G_MEMMOVE\000"
  /* 1102 */ "G_FREEZE\000"
  /* 1111 */ "G_FCANONICALIZE\000"
  /* 1127 */ "G_FMODF\000"
  /* 1135 */ "INIT_UNDEF\000"
  /* 1146 */ "G_IMPLICIT_DEF\000"
  /* 1161 */ "DBG_INSTR_REF\000"
  /* 1175 */ "G_FNEG\000"
  /* 1182 */ "EXTRACT_SUBREG\000"
  /* 1197 */ "INSERT_SUBREG\000"
  /* 1211 */ "G_SEXT_INREG\000"
  /* 1224 */ "SUBREG_TO_REG\000"
  /* 1238 */ "G_ATOMIC_CMPXCHG\000"
  /* 1255 */ "G_ATOMICRMW_XCHG\000"
  /* 1272 */ "G_GET_ROUNDING\000"
  /* 1287 */ "G_SET_ROUNDING\000"
  /* 1302 */ "G_FLOG\000"
  /* 1309 */ "G_VAARG\000"
  /* 1317 */ "PREALLOCATED_ARG\000"
  /* 1334 */ "G_PREFETCH\000"
  /* 1345 */ "G_SMULH\000"
  /* 1353 */ "G_UMULH\000"
  /* 1361 */ "G_FTANH\000"
  /* 1369 */ "G_FSINH\000"
  /* 1377 */ "G_FCOSH\000"
  /* 1385 */ "DBG_PHI\000"
  /* 1393 */ "G_FPTOSI\000"
  /* 1402 */ "RETI\000"
  /* 1407 */ "G_FPTOUI\000"
  /* 1416 */ "G_FPOWI\000"
  /* 1424 */ "COPY_LANEMASK\000"
  /* 1438 */ "G_PTRMASK\000"
  /* 1448 */ "GC_LABEL\000"
  /* 1457 */ "DBG_LABEL\000"
  /* 1467 */ "EH_LABEL\000"
  /* 1476 */ "ANNOTATION_LABEL\000"
  /* 1493 */ "ICALL_BRANCH_FUNNEL\000"
  /* 1513 */ "G_FSHL\000"
  /* 1520 */ "G_SHL\000"
  /* 1526 */ "G_FCEIL\000"
  /* 1534 */ "G_SAVGCEIL\000"
  /* 1545 */ "G_UAVGCEIL\000"
  /* 1556 */ "PATCHABLE_TAIL_CALL\000"
  /* 1576 */ "PATCHABLE_TYPED_EVENT_CALL\000"
  /* 1603 */ "PATCHABLE_EVENT_CALL\000"
  /* 1624 */ "FENTRY_CALL\000"
  /* 1636 */ "KILL\000"
  /* 1641 */ "G_CONSTANT_POOL\000"
  /* 1657 */ "G_ROTL\000"
  /* 1664 */ "G_VECREDUCE_FMUL\000"
  /* 1681 */ "G_FMUL\000"
  /* 1688 */ "G_VECREDUCE_SEQ_FMUL\000"
  /* 1709 */ "G_STRICT_FMUL\000"
  /* 1723 */ "G_CLMUL\000"
  /* 1731 */ "G_VECREDUCE_MUL\000"
  /* 1747 */ "G_MUL\000"
  /* 1753 */ "G_FREM\000"
  /* 1760 */ "G_STRICT_FREM\000"
  /* 1774 */ "G_SREM\000"
  /* 1781 */ "G_UREM\000"
  /* 1788 */ "G_SDIVREM\000"
  /* 1798 */ "G_UDIVREM\000"
  /* 1808 */ "INLINEASM\000"
  /* 1818 */ "G_VECREDUCE_FMINIMUM\000"
  /* 1839 */ "G_FMINIMUM\000"
  /* 1850 */ "G_ATOMICRMW_FMINIMUM\000"
  /* 1871 */ "G_VECREDUCE_FMAXIMUM\000"
  /* 1892 */ "G_FMAXIMUM\000"
  /* 1903 */ "G_ATOMICRMW_FMAXIMUM\000"
  /* 1924 */ "G_FMINIMUMNUM\000"
  /* 1938 */ "G_ATOMICRMW_FMINIMUMNUM\000"
  /* 1962 */ "G_FMAXIMUMNUM\000"
  /* 1976 */ "G_ATOMICRMW_FMAXIMUMNUM\000"
  /* 2000 */ "G_FMINNUM\000"
  /* 2010 */ "G_FMAXNUM\000"
  /* 2020 */ "G_FATAN\000"
  /* 2028 */ "G_FTAN\000"
  /* 2035 */ "G_INTRINSIC_ROUNDEVEN\000"
  /* 2057 */ "G_ASSERT_ALIGN\000"
  /* 2072 */ "G_FCOPYSIGN\000"
  /* 2084 */ "G_VECREDUCE_FMIN\000"
  /* 2101 */ "G_ATOMICRMW_FMIN\000"
  /* 2118 */ "G_VECREDUCE_SMIN\000"
  /* 2135 */ "G_SMIN\000"
  /* 2142 */ "G_VECREDUCE_UMIN\000"
  /* 2159 */ "G_UMIN\000"
  /* 2166 */ "G_ATOMICRMW_UMIN\000"
  /* 2183 */ "G_ATOMICRMW_MIN\000"
  /* 2199 */ "G_FASIN\000"
  /* 2207 */ "G_FSIN\000"
  /* 2214 */ "CFI_INSTRUCTION\000"
  /* 2230 */ "G_CTLZ_ZERO_POISON\000"
  /* 2249 */ "G_CTTZ_ZERO_POISON\000"
  /* 2268 */ "ADJCALLSTACKDOWN\000"
  /* 2285 */ "G_SSUBO\000"
  /* 2293 */ "G_USUBO\000"
  /* 2301 */ "G_SADDO\000"
  /* 2309 */ "G_UADDO\000"
  /* 2317 */ "JUMP_TABLE_DEBUG_INFO\000"
  /* 2339 */ "G_SMULO\000"
  /* 2347 */ "G_UMULO\000"
  /* 2355 */ "G_BZERO\000"
  /* 2363 */ "STACKMAP\000"
  /* 2372 */ "G_DEBUGTRAP\000"
  /* 2384 */ "G_UBSANTRAP\000"
  /* 2396 */ "G_TRAP\000"
  /* 2403 */ "G_ATOMICRMW_UDEC_WRAP\000"
  /* 2425 */ "G_ATOMICRMW_UINC_WRAP\000"
  /* 2447 */ "G_BSWAP\000"
  /* 2455 */ "G_SITOFP\000"
  /* 2464 */ "G_UITOFP\000"
  /* 2473 */ "G_FCMP\000"
  /* 2480 */ "G_STRICT_FCMP\000"
  /* 2494 */ "G_ICMP\000"
  /* 2501 */ "G_SCMP\000"
  /* 2508 */ "G_UCMP\000"
  /* 2515 */ "JMP\000"
  /* 2519 */ "CONVERGENCECTRL_LOOP\000"
  /* 2540 */ "G_CTPOP\000"
  /* 2548 */ "PATCHABLE_OP\000"
  /* 2561 */ "FAULTING_OP\000"
  /* 2573 */ "ADJCALLSTACKUP\000"
  /* 2588 */ "PREALLOCATED_SETUP\000"
  /* 2607 */ "G_FLDEXP\000"
  /* 2616 */ "G_STRICT_FLDEXP\000"
  /* 2632 */ "G_FEXP\000"
  /* 2639 */ "G_FFREXP\000"
  /* 2648 */ "G_BR\000"
  /* 2653 */ "INLINEASM_BR\000"
  /* 2666 */ "G_BLOCK_ADDR\000"
  /* 2679 */ "MEMBARRIER\000"
  /* 2690 */ "G_CONSTANT_FOLD_BARRIER\000"
  /* 2714 */ "PATCHABLE_FUNCTION_ENTER\000"
  /* 2739 */ "G_READCYCLECOUNTER\000"
  /* 2758 */ "G_READSTEADYCOUNTER\000"
  /* 2778 */ "G_READ_REGISTER\000"
  /* 2794 */ "G_WRITE_REGISTER\000"
  /* 2811 */ "G_ASHR\000"
  /* 2818 */ "G_FSHR\000"
  /* 2825 */ "G_LSHR\000"
  /* 2832 */ "CONVERGENCECTRL_ANCHOR\000"
  /* 2855 */ "G_FFLOOR\000"
  /* 2864 */ "G_SAVGFLOOR\000"
  /* 2876 */ "G_UAVGFLOOR\000"
  /* 2888 */ "G_EXTRACT_SUBVECTOR\000"
  /* 2908 */ "G_INSERT_SUBVECTOR\000"
  /* 2927 */ "G_BUILD_VECTOR\000"
  /* 2942 */ "G_SHUFFLE_VECTOR\000"
  /* 2959 */ "G_STEP_VECTOR\000"
  /* 2973 */ "G_SPLAT_VECTOR\000"
  /* 2988 */ "G_VECREDUCE_XOR\000"
  /* 3004 */ "G_XOR\000"
  /* 3010 */ "G_ATOMICRMW_XOR\000"
  /* 3026 */ "G_VECREDUCE_OR\000"
  /* 3041 */ "G_OR\000"
  /* 3046 */ "G_ATOMICRMW_OR\000"
  /* 3061 */ "G_ROTR\000"
  /* 3068 */ "G_INTTOPTR\000"
  /* 3079 */ "G_FABS\000"
  /* 3086 */ "G_ABS\000"
  /* 3092 */ "G_ABDS\000"
  /* 3099 */ "G_UNMERGE_VALUES\000"
  /* 3116 */ "G_MERGE_VALUES\000"
  /* 3131 */ "G_CTLS\000"
  /* 3138 */ "G_FACOS\000"
  /* 3146 */ "G_FCOS\000"
  /* 3153 */ "G_FSINCOS\000"
  /* 3163 */ "G_STRICT_FCMPS\000"
  /* 3178 */ "G_CONCAT_VECTORS\000"
  /* 3195 */ "COPY_TO_REGCLASS\000"
  /* 3212 */ "G_IS_FPCLASS\000"
  /* 3225 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\000"
  /* 3255 */ "G_VECTOR_COMPRESS\000"
  /* 3273 */ "G_INTRINSIC_W_SIDE_EFFECTS\000"
  /* 3300 */ "G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS\000"
  /* 3338 */ "G_TRUNC_SSAT_S\000"
  /* 3353 */ "G_SSUBSAT\000"
  /* 3363 */ "G_USUBSAT\000"
  /* 3373 */ "G_SADDSAT\000"
  /* 3383 */ "G_UADDSAT\000"
  /* 3393 */ "G_SSHLSAT\000"
  /* 3403 */ "G_USHLSAT\000"
  /* 3413 */ "G_SMULFIXSAT\000"
  /* 3426 */ "G_UMULFIXSAT\000"
  /* 3439 */ "G_SDIVFIXSAT\000"
  /* 3452 */ "G_UDIVFIXSAT\000"
  /* 3465 */ "G_ATOMICRMW_USUB_SAT\000"
  /* 3486 */ "G_FPTOSI_SAT\000"
  /* 3499 */ "G_FPTOUI_SAT\000"
  /* 3512 */ "G_EXTRACT\000"
  /* 3522 */ "G_SELECT\000"
  /* 3531 */ "G_BRINDIRECT\000"
  /* 3544 */ "PATCHABLE_RET\000"
  /* 3558 */ "G_MEMSET\000"
  /* 3567 */ "PATCHABLE_FUNCTION_EXIT\000"
  /* 3591 */ "G_BRJT\000"
  /* 3598 */ "G_EXTRACT_VECTOR_ELT\000"
  /* 3619 */ "G_INSERT_VECTOR_ELT\000"
  /* 3639 */ "G_FCONSTANT\000"
  /* 3651 */ "G_CONSTANT\000"
  /* 3662 */ "G_INTRINSIC_CONVERGENT\000"
  /* 3685 */ "STATEPOINT\000"
  /* 3696 */ "PATCHPOINT\000"
  /* 3707 */ "G_PTRTOINT\000"
  /* 3718 */ "G_FRINT\000"
  /* 3726 */ "G_INTRINSIC_LLRINT\000"
  /* 3745 */ "G_INTRINSIC_LRINT\000"
  /* 3763 */ "G_FNEARBYINT\000"
  /* 3776 */ "G_VASTART\000"
  /* 3786 */ "LIFETIME_START\000"
  /* 3801 */ "G_INVOKE_REGION_START\000"
  /* 3823 */ "G_INSERT\000"
  /* 3832 */ "G_FSQRT\000"
  /* 3840 */ "G_STRICT_FSQRT\000"
  /* 3855 */ "G_BITCAST\000"
  /* 3865 */ "G_ADDRSPACE_CAST\000"
  /* 3882 */ "DBG_VALUE_LIST\000"
  /* 3897 */ "G_FPEXT\000"
  /* 3905 */ "G_SEXT\000"
  /* 3912 */ "G_ASSERT_SEXT\000"
  /* 3926 */ "G_ANYEXT\000"
  /* 3935 */ "G_ZEXT\000"
  /* 3942 */ "G_ASSERT_ZEXT\000"
  /* 3956 */ "G_ABDU\000"
  /* 3963 */ "G_TRUNC_SSAT_U\000"
  /* 3978 */ "G_TRUNC_USAT_U\000"
  /* 3993 */ "G_FDIV\000"
  /* 4000 */ "G_STRICT_FDIV\000"
  /* 4014 */ "G_SDIV\000"
  /* 4021 */ "G_UDIV\000"
  /* 4028 */ "G_GET_FPENV\000"
  /* 4040 */ "G_RESET_FPENV\000"
  /* 4054 */ "G_SET_FPENV\000"
  /* 4066 */ "G_FPOW\000"
  /* 4073 */ "G_VECREDUCE_FMAX\000"
  /* 4090 */ "G_ATOMICRMW_FMAX\000"
  /* 4107 */ "G_VECREDUCE_SMAX\000"
  /* 4124 */ "G_SMAX\000"
  /* 4131 */ "G_VECREDUCE_UMAX\000"
  /* 4148 */ "G_UMAX\000"
  /* 4155 */ "G_ATOMICRMW_UMAX\000"
  /* 4172 */ "G_ATOMICRMW_MAX\000"
  /* 4188 */ "G_FRAME_INDEX\000"
  /* 4202 */ "G_SBFX\000"
  /* 4209 */ "G_UBFX\000"
  /* 4216 */ "G_SMULFIX\000"
  /* 4226 */ "G_UMULFIX\000"
  /* 4236 */ "G_SDIVFIX\000"
  /* 4246 */ "G_UDIVFIX\000"
  /* 4256 */ "G_MEMCPY\000"
  /* 4265 */ "COPY\000"
  /* 4270 */ "CONVERGENCECTRL_ENTRY\000"
  /* 4292 */ "G_CTLZ\000"
  /* 4299 */ "G_CTTZ\000"
  /* 4306 */ "PUSH16c\000"
  /* 4314 */ "SUB16mc\000"
  /* 4322 */ "SUBC16mc\000"
  /* 4331 */ "ADDC16mc\000"
  /* 4340 */ "BIC16mc\000"
  /* 4348 */ "DADD16mc\000"
  /* 4357 */ "AND16mc\000"
  /* 4365 */ "CMP16mc\000"
  /* 4373 */ "XOR16mc\000"
  /* 4381 */ "BIS16mc\000"
  /* 4389 */ "BIT16mc\000"
  /* 4397 */ "MOV16mc\000"
  /* 4405 */ "SUB8mc\000"
  /* 4412 */ "SUBC8mc\000"
  /* 4420 */ "ADDC8mc\000"
  /* 4428 */ "BIC8mc\000"
  /* 4435 */ "DADD8mc\000"
  /* 4443 */ "AND8mc\000"
  /* 4450 */ "CMP8mc\000"
  /* 4457 */ "XOR8mc\000"
  /* 4464 */ "BIS8mc\000"
  /* 4471 */ "BIT8mc\000"
  /* 4478 */ "MOV8mc\000"
  /* 4485 */ "SUB16rc\000"
  /* 4493 */ "SUBC16rc\000"
  /* 4502 */ "ADDC16rc\000"
  /* 4511 */ "BIC16rc\000"
  /* 4519 */ "DADD16rc\000"
  /* 4528 */ "AND16rc\000"
  /* 4536 */ "CMP16rc\000"
  /* 4544 */ "XOR16rc\000"
  /* 4552 */ "BIS16rc\000"
  /* 4560 */ "BIT16rc\000"
  /* 4568 */ "MOV16rc\000"
  /* 4576 */ "SUB8rc\000"
  /* 4583 */ "SUBC8rc\000"
  /* 4591 */ "ADDC8rc\000"
  /* 4599 */ "BIC8rc\000"
  /* 4606 */ "DADD8rc\000"
  /* 4614 */ "AND8rc\000"
  /* 4621 */ "CMP8rc\000"
  /* 4628 */ "XOR8rc\000"
  /* 4635 */ "BIS8rc\000"
  /* 4642 */ "BIT8rc\000"
  /* 4649 */ "MOV8rc\000"
  /* 4656 */ "ADDframe\000"
  /* 4665 */ "PUSH16i\000"
  /* 4673 */ "Bi\000"
  /* 4676 */ "CALLi\000"
  /* 4682 */ "SUB16mi\000"
  /* 4690 */ "SUBC16mi\000"
  /* 4699 */ "ADDC16mi\000"
  /* 4708 */ "BIC16mi\000"
  /* 4716 */ "DADD16mi\000"
  /* 4725 */ "AND16mi\000"
  /* 4733 */ "CMP16mi\000"
  /* 4741 */ "XOR16mi\000"
  /* 4749 */ "BIS16mi\000"
  /* 4757 */ "BIT16mi\000"
  /* 4765 */ "MOV16mi\000"
  /* 4773 */ "SUB8mi\000"
  /* 4780 */ "SUBC8mi\000"
  /* 4788 */ "ADDC8mi\000"
  /* 4796 */ "BIC8mi\000"
  /* 4803 */ "DADD8mi\000"
  /* 4811 */ "AND8mi\000"
  /* 4818 */ "CMP8mi\000"
  /* 4825 */ "XOR8mi\000"
  /* 4832 */ "BIS8mi\000"
  /* 4839 */ "BIT8mi\000"
  /* 4846 */ "MOV8mi\000"
  /* 4853 */ "SUB16ri\000"
  /* 4861 */ "SUBC16ri\000"
  /* 4870 */ "ADDC16ri\000"
  /* 4879 */ "BIC16ri\000"
  /* 4887 */ "DADD16ri\000"
  /* 4896 */ "AND16ri\000"
  /* 4904 */ "CMP16ri\000"
  /* 4912 */ "XOR16ri\000"
  /* 4920 */ "BIS16ri\000"
  /* 4928 */ "BIT16ri\000"
  /* 4936 */ "MOV16ri\000"
  /* 4944 */ "SUB8ri\000"
  /* 4951 */ "SUBC8ri\000"
  /* 4959 */ "ADDC8ri\000"
  /* 4967 */ "BIC8ri\000"
  /* 4974 */ "DADD8ri\000"
  /* 4982 */ "AND8ri\000"
  /* 4989 */ "CMP8ri\000"
  /* 4996 */ "XOR8ri\000"
  /* 5003 */ "BIS8ri\000"
  /* 5010 */ "BIT8ri\000"
  /* 5017 */ "MOV8ri\000"
  /* 5024 */ "RRA16m\000"
  /* 5031 */ "SWPB16m\000"
  /* 5039 */ "RRC16m\000"
  /* 5046 */ "SEXT16m\000"
  /* 5054 */ "RRA8m\000"
  /* 5060 */ "RRC8m\000"
  /* 5066 */ "Bm\000"
  /* 5069 */ "CALLm\000"
  /* 5075 */ "SUB16mm\000"
  /* 5083 */ "SUBC16mm\000"
  /* 5092 */ "ADDC16mm\000"
  /* 5101 */ "BIC16mm\000"
  /* 5109 */ "DADD16mm\000"
  /* 5118 */ "AND16mm\000"
  /* 5126 */ "CMP16mm\000"
  /* 5134 */ "XOR16mm\000"
  /* 5142 */ "BIS16mm\000"
  /* 5150 */ "BIT16mm\000"
  /* 5158 */ "MOV16mm\000"
  /* 5166 */ "SUB8mm\000"
  /* 5173 */ "SUBC8mm\000"
  /* 5181 */ "ADDC8mm\000"
  /* 5189 */ "BIC8mm\000"
  /* 5196 */ "DADD8mm\000"
  /* 5204 */ "AND8mm\000"
  /* 5211 */ "CMP8mm\000"
  /* 5218 */ "XOR8mm\000"
  /* 5225 */ "BIS8mm\000"
  /* 5232 */ "BIT8mm\000"
  /* 5239 */ "MOV8mm\000"
  /* 5246 */ "SUB16rm\000"
  /* 5254 */ "SUBC16rm\000"
  /* 5263 */ "ADDC16rm\000"
  /* 5272 */ "BIC16rm\000"
  /* 5280 */ "DADD16rm\000"
  /* 5289 */ "AND16rm\000"
  /* 5297 */ "CMP16rm\000"
  /* 5305 */ "XOR16rm\000"
  /* 5313 */ "BIS16rm\000"
  /* 5321 */ "BIT16rm\000"
  /* 5329 */ "MOV16rm\000"
  /* 5337 */ "SUB8rm\000"
  /* 5344 */ "SUBC8rm\000"
  /* 5352 */ "ADDC8rm\000"
  /* 5360 */ "BIC8rm\000"
  /* 5367 */ "DADD8rm\000"
  /* 5375 */ "AND8rm\000"
  /* 5382 */ "CMP8rm\000"
  /* 5389 */ "XOR8rm\000"
  /* 5396 */ "BIS8rm\000"
  /* 5403 */ "BIT8rm\000"
  /* 5410 */ "MOV8rm\000"
  /* 5417 */ "RRA16n\000"
  /* 5424 */ "SWPB16n\000"
  /* 5432 */ "RRC16n\000"
  /* 5439 */ "SEXT16n\000"
  /* 5447 */ "RRA8n\000"
  /* 5453 */ "RRC8n\000"
  /* 5459 */ "CALLn\000"
  /* 5465 */ "SUB16mn\000"
  /* 5473 */ "SUBC16mn\000"
  /* 5482 */ "ADDC16mn\000"
  /* 5491 */ "BIC16mn\000"
  /* 5499 */ "DADD16mn\000"
  /* 5508 */ "AND16mn\000"
  /* 5516 */ "CMP16mn\000"
  /* 5524 */ "XOR16mn\000"
  /* 5532 */ "BIS16mn\000"
  /* 5540 */ "BIT16mn\000"
  /* 5548 */ "MOV16mn\000"
  /* 5556 */ "SUB8mn\000"
  /* 5563 */ "SUBC8mn\000"
  /* 5571 */ "ADDC8mn\000"
  /* 5579 */ "BIC8mn\000"
  /* 5586 */ "DADD8mn\000"
  /* 5594 */ "AND8mn\000"
  /* 5601 */ "CMP8mn\000"
  /* 5608 */ "XOR8mn\000"
  /* 5615 */ "BIS8mn\000"
  /* 5622 */ "BIT8mn\000"
  /* 5629 */ "MOV8mn\000"
  /* 5636 */ "SUB16rn\000"
  /* 5644 */ "SUBC16rn\000"
  /* 5653 */ "ADDC16rn\000"
  /* 5662 */ "BIC16rn\000"
  /* 5670 */ "DADD16rn\000"
  /* 5679 */ "AND16rn\000"
  /* 5687 */ "CMP16rn\000"
  /* 5695 */ "XOR16rn\000"
  /* 5703 */ "BIS16rn\000"
  /* 5711 */ "BIT16rn\000"
  /* 5719 */ "MOV16rn\000"
  /* 5727 */ "SUB8rn\000"
  /* 5734 */ "SUBC8rn\000"
  /* 5742 */ "ADDC8rn\000"
  /* 5750 */ "BIC8rn\000"
  /* 5757 */ "DADD8rn\000"
  /* 5765 */ "AND8rn\000"
  /* 5772 */ "CMP8rn\000"
  /* 5779 */ "XOR8rn\000"
  /* 5786 */ "BIS8rn\000"
  /* 5793 */ "BIT8rn\000"
  /* 5800 */ "MOV8rn\000"
  /* 5807 */ "RRA16p\000"
  /* 5814 */ "SWPB16p\000"
  /* 5822 */ "RRC16p\000"
  /* 5829 */ "SEXT16p\000"
  /* 5837 */ "RRA8p\000"
  /* 5843 */ "RRC8p\000"
  /* 5849 */ "CALLp\000"
  /* 5855 */ "SUB16mp\000"
  /* 5863 */ "SUBC16mp\000"
  /* 5872 */ "ADDC16mp\000"
  /* 5881 */ "BIC16mp\000"
  /* 5889 */ "DADD16mp\000"
  /* 5898 */ "AND16mp\000"
  /* 5906 */ "CMP16mp\000"
  /* 5914 */ "XOR16mp\000"
  /* 5922 */ "BIS16mp\000"
  /* 5930 */ "BIT16mp\000"
  /* 5938 */ "SUB8mp\000"
  /* 5945 */ "SUBC8mp\000"
  /* 5953 */ "ADDC8mp\000"
  /* 5961 */ "BIC8mp\000"
  /* 5968 */ "DADD8mp\000"
  /* 5976 */ "AND8mp\000"
  /* 5983 */ "CMP8mp\000"
  /* 5990 */ "XOR8mp\000"
  /* 5997 */ "BIS8mp\000"
  /* 6004 */ "BIT8mp\000"
  /* 6011 */ "SUB16rp\000"
  /* 6019 */ "SUBC16rp\000"
  /* 6028 */ "ADDC16rp\000"
  /* 6037 */ "BIC16rp\000"
  /* 6045 */ "DADD16rp\000"
  /* 6054 */ "AND16rp\000"
  /* 6062 */ "CMP16rp\000"
  /* 6070 */ "XOR16rp\000"
  /* 6078 */ "BIS16rp\000"
  /* 6086 */ "BIT16rp\000"
  /* 6094 */ "MOV16rp\000"
  /* 6102 */ "SUB8rp\000"
  /* 6109 */ "SUBC8rp\000"
  /* 6117 */ "ADDC8rp\000"
  /* 6125 */ "BIC8rp\000"
  /* 6132 */ "DADD8rp\000"
  /* 6140 */ "AND8rp\000"
  /* 6147 */ "CMP8rp\000"
  /* 6154 */ "XOR8rp\000"
  /* 6161 */ "BIS8rp\000"
  /* 6168 */ "BIT8rp\000"
  /* 6175 */ "MOV8rp\000"
  /* 6182 */ "RRA16r\000"
  /* 6189 */ "SWPB16r\000"
  /* 6197 */ "RRC16r\000"
  /* 6204 */ "PUSH16r\000"
  /* 6212 */ "POP16r\000"
  /* 6219 */ "SEXT16r\000"
  /* 6227 */ "ZEXT16r\000"
  /* 6235 */ "RRA8r\000"
  /* 6241 */ "RRC8r\000"
  /* 6247 */ "PUSH8r\000"
  /* 6254 */ "Br\000"
  /* 6257 */ "CALLr\000"
  /* 6263 */ "SUB16mr\000"
  /* 6271 */ "SUBC16mr\000"
  /* 6280 */ "ADDC16mr\000"
  /* 6289 */ "BIC16mr\000"
  /* 6297 */ "DADD16mr\000"
  /* 6306 */ "AND16mr\000"
  /* 6314 */ "CMP16mr\000"
  /* 6322 */ "XOR16mr\000"
  /* 6330 */ "BIS16mr\000"
  /* 6338 */ "BIT16mr\000"
  /* 6346 */ "MOV16mr\000"
  /* 6354 */ "SUB8mr\000"
  /* 6361 */ "SUBC8mr\000"
  /* 6369 */ "ADDC8mr\000"
  /* 6377 */ "BIC8mr\000"
  /* 6384 */ "DADD8mr\000"
  /* 6392 */ "AND8mr\000"
  /* 6399 */ "CMP8mr\000"
  /* 6406 */ "XOR8mr\000"
  /* 6413 */ "BIS8mr\000"
  /* 6420 */ "BIT8mr\000"
  /* 6427 */ "MOV8mr\000"
  /* 6434 */ "SUB16rr\000"
  /* 6442 */ "SUBC16rr\000"
  /* 6451 */ "ADDC16rr\000"
  /* 6460 */ "BIC16rr\000"
  /* 6468 */ "DADD16rr\000"
  /* 6477 */ "AND16rr\000"
  /* 6485 */ "CMP16rr\000"
  /* 6493 */ "XOR16rr\000"
  /* 6501 */ "BIS16rr\000"
  /* 6509 */ "BIT16rr\000"
  /* 6517 */ "MOV16rr\000"
  /* 6525 */ "SUB8rr\000"
  /* 6532 */ "SUBC8rr\000"
  /* 6540 */ "ADDC8rr\000"
  /* 6548 */ "BIC8rr\000"
  /* 6555 */ "DADD8rr\000"
  /* 6563 */ "AND8rr\000"
  /* 6570 */ "CMP8rr\000"
  /* 6577 */ "XOR8rr\000"
  /* 6584 */ "BIS8rr\000"
  /* 6591 */ "BIT8rr\000"
  /* 6598 */ "MOV8rr\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned MSP430InstrNameIndices[] = {
    1389U, 1808U, 2653U, 2214U, 1467U, 1448U, 1476U, 1636U, 
    1182U, 1197U, 1148U, 1135U, 1224U, 3195U, 1011U, 3882U, 
    1161U, 1385U, 1457U, 750U, 4265U, 1424U, 872U, 3786U, 
    577U, 701U, 738U, 2363U, 1624U, 3696U, 684U, 2588U, 
    1317U, 3685U, 922U, 2561U, 2548U, 2714U, 3544U, 3567U, 
    1556U, 1603U, 1576U, 1493U, 1002U, 2679U, 2317U, 911U, 
    4270U, 2832U, 2519U, 1059U, 3912U, 3942U, 2057U, 490U, 
    185U, 1747U, 4014U, 4021U, 1774U, 1781U, 1788U, 1798U, 
    555U, 3041U, 3004U, 3092U, 3956U, 2876U, 1545U, 2864U, 
    1534U, 1146U, 1387U, 4188U, 1021U, 1036U, 1641U, 3512U, 
    3099U, 3823U, 3116U, 2927U, 259U, 3178U, 3707U, 3068U, 
    3855U, 1102U, 2690U, 658U, 233U, 640U, 3745U, 3726U, 
    2035U, 2739U, 2758U, 391U, 335U, 365U, 304U, 376U, 
    316U, 346U, 981U, 935U, 965U, 3225U, 1238U, 1255U, 
    506U, 191U, 561U, 522U, 3046U, 3010U, 4172U, 2183U, 
    4155U, 2166U, 457U, 168U, 4090U, 2101U, 1903U, 1850U, 
    1976U, 1938U, 2425U, 2403U, 599U, 3465U, 730U, 1334U, 
    590U, 3531U, 3801U, 211U, 3273U, 3662U, 3300U, 3926U, 
    251U, 3338U, 3963U, 3978U, 3651U, 3639U, 3776U, 1309U, 
    3905U, 1211U, 3935U, 1520U, 2825U, 2811U, 1513U, 2818U, 
    3061U, 1657U, 2494U, 2473U, 2501U, 2508U, 3522U, 2309U, 
    771U, 2293U, 722U, 2301U, 763U, 2285U, 714U, 2347U, 
    2339U, 1353U, 1345U, 3383U, 3373U, 3363U, 3353U, 3403U, 
    3393U, 4216U, 4226U, 3413U, 3426U, 4236U, 4246U, 3439U, 
    3452U, 415U, 147U, 1681U, 128U, 297U, 3993U, 1753U, 
    1127U, 4066U, 1416U, 2632U, 35U, 9U, 1302U, 18U, 
    0U, 2607U, 2639U, 1175U, 3897U, 223U, 1393U, 1407U, 
    2455U, 2464U, 3486U, 3499U, 3079U, 2072U, 3212U, 1111U, 
    2000U, 2010U, 820U, 835U, 1839U, 1892U, 1924U, 1962U, 
    4028U, 4054U, 4040U, 779U, 807U, 792U, 1272U, 1287U, 
    496U, 1438U, 2135U, 4124U, 2159U, 4148U, 3086U, 631U, 
    621U, 2648U, 3591U, 850U, 2908U, 2888U, 3619U, 3598U, 
    2942U, 2973U, 2959U, 3255U, 4299U, 2249U, 4292U, 2230U, 
    3131U, 2540U, 2447U, 989U, 1723U, 1526U, 3146U, 2207U, 
    3153U, 2028U, 3138U, 2199U, 2020U, 26U, 1377U, 1369U, 
    1361U, 3832U, 2855U, 3718U, 3763U, 3865U, 2666U, 859U, 
    280U, 1080U, 950U, 443U, 154U, 1709U, 4000U, 1760U, 
    134U, 3840U, 2616U, 2480U, 3163U, 2778U, 2794U, 4256U, 
    895U, 1092U, 3558U, 2355U, 879U, 2396U, 2372U, 2384U, 
    422U, 1688U, 398U, 1664U, 4073U, 2084U, 1871U, 1818U, 
    474U, 1731U, 539U, 3026U, 2988U, 4107U, 2118U, 4131U, 
    2142U, 4202U, 4209U, 4349U, 4717U, 5110U, 5500U, 5890U, 
    6298U, 4520U, 4888U, 5281U, 5671U, 6046U, 6469U, 4436U, 
    4804U, 5197U, 5587U, 5969U, 6385U, 4607U, 4975U, 5368U, 
    5758U, 6133U, 6556U, 4331U, 4699U, 5092U, 5482U, 5872U, 
    6280U, 4502U, 4870U, 5263U, 5653U, 6028U, 6451U, 4420U, 
    4788U, 5181U, 5571U, 5953U, 6369U, 4591U, 4959U, 5352U, 
    5742U, 6117U, 6540U, 4656U, 2268U, 2573U, 4357U, 4725U, 
    5118U, 5508U, 5898U, 6306U, 4528U, 4896U, 5289U, 5679U, 
    6054U, 6477U, 4443U, 4811U, 5204U, 5594U, 5976U, 6392U, 
    4614U, 4982U, 5375U, 5765U, 6140U, 6563U, 4340U, 4708U, 
    5101U, 5491U, 5881U, 6289U, 4511U, 4879U, 5272U, 5662U, 
    6037U, 6460U, 4428U, 4796U, 5189U, 5579U, 5961U, 6377U, 
    4599U, 4967U, 5360U, 5750U, 6125U, 6548U, 4381U, 4749U, 
    5142U, 5532U, 5922U, 6330U, 4552U, 4920U, 5313U, 5703U, 
    6078U, 6501U, 4464U, 4832U, 5225U, 5615U, 5997U, 6413U, 
    4635U, 5003U, 5396U, 5786U, 6161U, 6584U, 4389U, 4757U, 
    5150U, 5540U, 5930U, 6338U, 4560U, 4928U, 5321U, 5711U, 
    6086U, 6509U, 4471U, 4839U, 5232U, 5622U, 6004U, 6420U, 
    4642U, 5010U, 5403U, 5793U, 6168U, 6591U, 4673U, 5066U, 
    6254U, 4676U, 5069U, 5459U, 5849U, 6257U, 4365U, 4733U, 
    5126U, 5516U, 5906U, 6314U, 4536U, 4904U, 5297U, 5687U, 
    6062U, 6485U, 4450U, 4818U, 5211U, 5601U, 5983U, 6399U, 
    4621U, 4989U, 5382U, 5772U, 6147U, 6570U, 4348U, 4716U, 
    5109U, 5499U, 5889U, 6297U, 4519U, 4887U, 5280U, 5670U, 
    6045U, 6468U, 4435U, 4803U, 5196U, 5586U, 5968U, 6384U, 
    4606U, 4974U, 5367U, 5757U, 6132U, 6555U, 207U, 2515U, 
    4397U, 4765U, 5158U, 5548U, 6346U, 4568U, 4936U, 5329U, 
    5719U, 6094U, 6517U, 4478U, 4846U, 5239U, 5629U, 6427U, 
    4649U, 5017U, 5410U, 5800U, 6175U, 6598U, 98U, 109U, 
    6212U, 4306U, 4665U, 6204U, 6247U, 3554U, 1402U, 5024U, 
    5417U, 5807U, 6182U, 5054U, 5447U, 5837U, 6235U, 5039U, 
    5432U, 5822U, 6197U, 5060U, 5453U, 5843U, 6241U, 49U, 
    82U, 5046U, 5439U, 5829U, 6219U, 4314U, 4682U, 5075U, 
    5465U, 5855U, 6263U, 4485U, 4853U, 5246U, 5636U, 6011U, 
    6434U, 4405U, 4773U, 5166U, 5556U, 5938U, 6354U, 4576U, 
    4944U, 5337U, 5727U, 6102U, 6525U, 4322U, 4690U, 5083U, 
    5473U, 5863U, 6271U, 4493U, 4861U, 5254U, 5644U, 6019U, 
    6442U, 4412U, 4780U, 5173U, 5563U, 5945U, 6361U, 4583U, 
    4951U, 5344U, 5734U, 6109U, 6532U, 5031U, 5424U, 5814U, 
    6189U, 68U, 120U, 56U, 88U, 43U, 77U, 62U, 
    93U, 4373U, 4741U, 5134U, 5524U, 5914U, 6322U, 4544U, 
    4912U, 5305U, 5695U, 6070U, 6493U, 4457U, 4825U, 5218U, 
    5608U, 5990U, 6406U, 4628U, 4996U, 5389U, 5779U, 6154U, 
    6577U, 6227U, 
};

static inline void InitMSP430MCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(MSP430Descs.Insts, MSP430InstrNameIndices, MSP430InstrNameData, nullptr, nullptr, 674, nullptr, 0);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct MSP430GenInstrInfo : public TargetInstrInfo {
  explicit MSP430GenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~MSP430GenInstrInfo() override = default;
};

} // namespace llvm_ks

namespace llvm_ks::MSP430 {


} // namespace llvm_ks::MSP430

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

extern const MSP430InstrTable MSP430Descs;
extern const unsigned MSP430InstrNameIndices[];
extern const char MSP430InstrNameData[];
MSP430GenInstrInfo::MSP430GenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(MSP430Descs.Insts, MSP430InstrNameIndices, MSP430InstrNameData, nullptr, nullptr, 674);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace MSP430_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace MSP430_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::MSP430_MC {


} // namespace llvm_ks::MSP430_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::MSP430_MC {

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
    CEFBS_None, // ADD16mc
    CEFBS_None, // ADD16mi
    CEFBS_None, // ADD16mm
    CEFBS_None, // ADD16mn
    CEFBS_None, // ADD16mp
    CEFBS_None, // ADD16mr
    CEFBS_None, // ADD16rc
    CEFBS_None, // ADD16ri
    CEFBS_None, // ADD16rm
    CEFBS_None, // ADD16rn
    CEFBS_None, // ADD16rp
    CEFBS_None, // ADD16rr
    CEFBS_None, // ADD8mc
    CEFBS_None, // ADD8mi
    CEFBS_None, // ADD8mm
    CEFBS_None, // ADD8mn
    CEFBS_None, // ADD8mp
    CEFBS_None, // ADD8mr
    CEFBS_None, // ADD8rc
    CEFBS_None, // ADD8ri
    CEFBS_None, // ADD8rm
    CEFBS_None, // ADD8rn
    CEFBS_None, // ADD8rp
    CEFBS_None, // ADD8rr
    CEFBS_None, // ADDC16mc
    CEFBS_None, // ADDC16mi
    CEFBS_None, // ADDC16mm
    CEFBS_None, // ADDC16mn
    CEFBS_None, // ADDC16mp
    CEFBS_None, // ADDC16mr
    CEFBS_None, // ADDC16rc
    CEFBS_None, // ADDC16ri
    CEFBS_None, // ADDC16rm
    CEFBS_None, // ADDC16rn
    CEFBS_None, // ADDC16rp
    CEFBS_None, // ADDC16rr
    CEFBS_None, // ADDC8mc
    CEFBS_None, // ADDC8mi
    CEFBS_None, // ADDC8mm
    CEFBS_None, // ADDC8mn
    CEFBS_None, // ADDC8mp
    CEFBS_None, // ADDC8mr
    CEFBS_None, // ADDC8rc
    CEFBS_None, // ADDC8ri
    CEFBS_None, // ADDC8rm
    CEFBS_None, // ADDC8rn
    CEFBS_None, // ADDC8rp
    CEFBS_None, // ADDC8rr
    CEFBS_None, // ADDframe
    CEFBS_None, // ADJCALLSTACKDOWN
    CEFBS_None, // ADJCALLSTACKUP
    CEFBS_None, // AND16mc
    CEFBS_None, // AND16mi
    CEFBS_None, // AND16mm
    CEFBS_None, // AND16mn
    CEFBS_None, // AND16mp
    CEFBS_None, // AND16mr
    CEFBS_None, // AND16rc
    CEFBS_None, // AND16ri
    CEFBS_None, // AND16rm
    CEFBS_None, // AND16rn
    CEFBS_None, // AND16rp
    CEFBS_None, // AND16rr
    CEFBS_None, // AND8mc
    CEFBS_None, // AND8mi
    CEFBS_None, // AND8mm
    CEFBS_None, // AND8mn
    CEFBS_None, // AND8mp
    CEFBS_None, // AND8mr
    CEFBS_None, // AND8rc
    CEFBS_None, // AND8ri
    CEFBS_None, // AND8rm
    CEFBS_None, // AND8rn
    CEFBS_None, // AND8rp
    CEFBS_None, // AND8rr
    CEFBS_None, // BIC16mc
    CEFBS_None, // BIC16mi
    CEFBS_None, // BIC16mm
    CEFBS_None, // BIC16mn
    CEFBS_None, // BIC16mp
    CEFBS_None, // BIC16mr
    CEFBS_None, // BIC16rc
    CEFBS_None, // BIC16ri
    CEFBS_None, // BIC16rm
    CEFBS_None, // BIC16rn
    CEFBS_None, // BIC16rp
    CEFBS_None, // BIC16rr
    CEFBS_None, // BIC8mc
    CEFBS_None, // BIC8mi
    CEFBS_None, // BIC8mm
    CEFBS_None, // BIC8mn
    CEFBS_None, // BIC8mp
    CEFBS_None, // BIC8mr
    CEFBS_None, // BIC8rc
    CEFBS_None, // BIC8ri
    CEFBS_None, // BIC8rm
    CEFBS_None, // BIC8rn
    CEFBS_None, // BIC8rp
    CEFBS_None, // BIC8rr
    CEFBS_None, // BIS16mc
    CEFBS_None, // BIS16mi
    CEFBS_None, // BIS16mm
    CEFBS_None, // BIS16mn
    CEFBS_None, // BIS16mp
    CEFBS_None, // BIS16mr
    CEFBS_None, // BIS16rc
    CEFBS_None, // BIS16ri
    CEFBS_None, // BIS16rm
    CEFBS_None, // BIS16rn
    CEFBS_None, // BIS16rp
    CEFBS_None, // BIS16rr
    CEFBS_None, // BIS8mc
    CEFBS_None, // BIS8mi
    CEFBS_None, // BIS8mm
    CEFBS_None, // BIS8mn
    CEFBS_None, // BIS8mp
    CEFBS_None, // BIS8mr
    CEFBS_None, // BIS8rc
    CEFBS_None, // BIS8ri
    CEFBS_None, // BIS8rm
    CEFBS_None, // BIS8rn
    CEFBS_None, // BIS8rp
    CEFBS_None, // BIS8rr
    CEFBS_None, // BIT16mc
    CEFBS_None, // BIT16mi
    CEFBS_None, // BIT16mm
    CEFBS_None, // BIT16mn
    CEFBS_None, // BIT16mp
    CEFBS_None, // BIT16mr
    CEFBS_None, // BIT16rc
    CEFBS_None, // BIT16ri
    CEFBS_None, // BIT16rm
    CEFBS_None, // BIT16rn
    CEFBS_None, // BIT16rp
    CEFBS_None, // BIT16rr
    CEFBS_None, // BIT8mc
    CEFBS_None, // BIT8mi
    CEFBS_None, // BIT8mm
    CEFBS_None, // BIT8mn
    CEFBS_None, // BIT8mp
    CEFBS_None, // BIT8mr
    CEFBS_None, // BIT8rc
    CEFBS_None, // BIT8ri
    CEFBS_None, // BIT8rm
    CEFBS_None, // BIT8rn
    CEFBS_None, // BIT8rp
    CEFBS_None, // BIT8rr
    CEFBS_None, // Bi
    CEFBS_None, // Bm
    CEFBS_None, // Br
    CEFBS_None, // CALLi
    CEFBS_None, // CALLm
    CEFBS_None, // CALLn
    CEFBS_None, // CALLp
    CEFBS_None, // CALLr
    CEFBS_None, // CMP16mc
    CEFBS_None, // CMP16mi
    CEFBS_None, // CMP16mm
    CEFBS_None, // CMP16mn
    CEFBS_None, // CMP16mp
    CEFBS_None, // CMP16mr
    CEFBS_None, // CMP16rc
    CEFBS_None, // CMP16ri
    CEFBS_None, // CMP16rm
    CEFBS_None, // CMP16rn
    CEFBS_None, // CMP16rp
    CEFBS_None, // CMP16rr
    CEFBS_None, // CMP8mc
    CEFBS_None, // CMP8mi
    CEFBS_None, // CMP8mm
    CEFBS_None, // CMP8mn
    CEFBS_None, // CMP8mp
    CEFBS_None, // CMP8mr
    CEFBS_None, // CMP8rc
    CEFBS_None, // CMP8ri
    CEFBS_None, // CMP8rm
    CEFBS_None, // CMP8rn
    CEFBS_None, // CMP8rp
    CEFBS_None, // CMP8rr
    CEFBS_None, // DADD16mc
    CEFBS_None, // DADD16mi
    CEFBS_None, // DADD16mm
    CEFBS_None, // DADD16mn
    CEFBS_None, // DADD16mp
    CEFBS_None, // DADD16mr
    CEFBS_None, // DADD16rc
    CEFBS_None, // DADD16ri
    CEFBS_None, // DADD16rm
    CEFBS_None, // DADD16rn
    CEFBS_None, // DADD16rp
    CEFBS_None, // DADD16rr
    CEFBS_None, // DADD8mc
    CEFBS_None, // DADD8mi
    CEFBS_None, // DADD8mm
    CEFBS_None, // DADD8mn
    CEFBS_None, // DADD8mp
    CEFBS_None, // DADD8mr
    CEFBS_None, // DADD8rc
    CEFBS_None, // DADD8ri
    CEFBS_None, // DADD8rm
    CEFBS_None, // DADD8rn
    CEFBS_None, // DADD8rp
    CEFBS_None, // DADD8rr
    CEFBS_None, // JCC
    CEFBS_None, // JMP
    CEFBS_None, // MOV16mc
    CEFBS_None, // MOV16mi
    CEFBS_None, // MOV16mm
    CEFBS_None, // MOV16mn
    CEFBS_None, // MOV16mr
    CEFBS_None, // MOV16rc
    CEFBS_None, // MOV16ri
    CEFBS_None, // MOV16rm
    CEFBS_None, // MOV16rn
    CEFBS_None, // MOV16rp
    CEFBS_None, // MOV16rr
    CEFBS_None, // MOV8mc
    CEFBS_None, // MOV8mi
    CEFBS_None, // MOV8mm
    CEFBS_None, // MOV8mn
    CEFBS_None, // MOV8mr
    CEFBS_None, // MOV8rc
    CEFBS_None, // MOV8ri
    CEFBS_None, // MOV8rm
    CEFBS_None, // MOV8rn
    CEFBS_None, // MOV8rp
    CEFBS_None, // MOV8rr
    CEFBS_None, // MOVZX16rm8
    CEFBS_None, // MOVZX16rr8
    CEFBS_None, // POP16r
    CEFBS_None, // PUSH16c
    CEFBS_None, // PUSH16i
    CEFBS_None, // PUSH16r
    CEFBS_None, // PUSH8r
    CEFBS_None, // RET
    CEFBS_None, // RETI
    CEFBS_None, // RRA16m
    CEFBS_None, // RRA16n
    CEFBS_None, // RRA16p
    CEFBS_None, // RRA16r
    CEFBS_None, // RRA8m
    CEFBS_None, // RRA8n
    CEFBS_None, // RRA8p
    CEFBS_None, // RRA8r
    CEFBS_None, // RRC16m
    CEFBS_None, // RRC16n
    CEFBS_None, // RRC16p
    CEFBS_None, // RRC16r
    CEFBS_None, // RRC8m
    CEFBS_None, // RRC8n
    CEFBS_None, // RRC8p
    CEFBS_None, // RRC8r
    CEFBS_None, // Rrcl16
    CEFBS_None, // Rrcl8
    CEFBS_None, // SEXT16m
    CEFBS_None, // SEXT16n
    CEFBS_None, // SEXT16p
    CEFBS_None, // SEXT16r
    CEFBS_None, // SUB16mc
    CEFBS_None, // SUB16mi
    CEFBS_None, // SUB16mm
    CEFBS_None, // SUB16mn
    CEFBS_None, // SUB16mp
    CEFBS_None, // SUB16mr
    CEFBS_None, // SUB16rc
    CEFBS_None, // SUB16ri
    CEFBS_None, // SUB16rm
    CEFBS_None, // SUB16rn
    CEFBS_None, // SUB16rp
    CEFBS_None, // SUB16rr
    CEFBS_None, // SUB8mc
    CEFBS_None, // SUB8mi
    CEFBS_None, // SUB8mm
    CEFBS_None, // SUB8mn
    CEFBS_None, // SUB8mp
    CEFBS_None, // SUB8mr
    CEFBS_None, // SUB8rc
    CEFBS_None, // SUB8ri
    CEFBS_None, // SUB8rm
    CEFBS_None, // SUB8rn
    CEFBS_None, // SUB8rp
    CEFBS_None, // SUB8rr
    CEFBS_None, // SUBC16mc
    CEFBS_None, // SUBC16mi
    CEFBS_None, // SUBC16mm
    CEFBS_None, // SUBC16mn
    CEFBS_None, // SUBC16mp
    CEFBS_None, // SUBC16mr
    CEFBS_None, // SUBC16rc
    CEFBS_None, // SUBC16ri
    CEFBS_None, // SUBC16rm
    CEFBS_None, // SUBC16rn
    CEFBS_None, // SUBC16rp
    CEFBS_None, // SUBC16rr
    CEFBS_None, // SUBC8mc
    CEFBS_None, // SUBC8mi
    CEFBS_None, // SUBC8mm
    CEFBS_None, // SUBC8mn
    CEFBS_None, // SUBC8mp
    CEFBS_None, // SUBC8mr
    CEFBS_None, // SUBC8rc
    CEFBS_None, // SUBC8ri
    CEFBS_None, // SUBC8rm
    CEFBS_None, // SUBC8rn
    CEFBS_None, // SUBC8rp
    CEFBS_None, // SUBC8rr
    CEFBS_None, // SWPB16m
    CEFBS_None, // SWPB16n
    CEFBS_None, // SWPB16p
    CEFBS_None, // SWPB16r
    CEFBS_None, // Select16
    CEFBS_None, // Select8
    CEFBS_None, // Shl16
    CEFBS_None, // Shl8
    CEFBS_None, // Sra16
    CEFBS_None, // Sra8
    CEFBS_None, // Srl16
    CEFBS_None, // Srl8
    CEFBS_None, // XOR16mc
    CEFBS_None, // XOR16mi
    CEFBS_None, // XOR16mm
    CEFBS_None, // XOR16mn
    CEFBS_None, // XOR16mp
    CEFBS_None, // XOR16mr
    CEFBS_None, // XOR16rc
    CEFBS_None, // XOR16ri
    CEFBS_None, // XOR16rm
    CEFBS_None, // XOR16rn
    CEFBS_None, // XOR16rp
    CEFBS_None, // XOR16rr
    CEFBS_None, // XOR8mc
    CEFBS_None, // XOR8mi
    CEFBS_None, // XOR8mm
    CEFBS_None, // XOR8mn
    CEFBS_None, // XOR8mp
    CEFBS_None, // XOR8mr
    CEFBS_None, // XOR8rc
    CEFBS_None, // XOR8ri
    CEFBS_None, // XOR8rm
    CEFBS_None, // XOR8rn
    CEFBS_None, // XOR8rp
    CEFBS_None, // XOR8rr
    CEFBS_None, // ZEXT16r
  };

  assert(Opcode < 674);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::MSP430_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::MSP430_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::MSP430_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::MSP430_MC {

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
    Msg << "Attempting to emit " << &MSP430InstrNameData[MSP430InstrNameIndices[Opcode]]
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::MSP430_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

