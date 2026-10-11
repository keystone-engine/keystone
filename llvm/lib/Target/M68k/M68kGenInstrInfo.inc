/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::M68k {

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
    ADJCALLSTACKDOWN                      = 331, // M68kInstrCompiler.td:79
    ADJCALLSTACKUP                        = 332, // M68kInstrCompiler.td:83
    CMOV16d                               = 333, // M68kInstrCompiler.td:64
    CMOV32r                               = 334, // M68kInstrCompiler.td:65
    CMOV8d                                = 335, // M68kInstrCompiler.td:63
    MOV8bc                                = 336, // M68kInstrData.td:455
    MOV8cb                                = 337, // M68kInstrData.td:415
    MOV8ce                                = 338, // M68kInstrData.td:415
    MOV8cf                                = 339, // M68kInstrData.td:415
    MOV8cj                                = 340, // M68kInstrData.td:415
    MOV8ck                                = 341, // M68kInstrData.td:415
    MOV8co                                = 342, // M68kInstrData.td:415
    MOV8cp                                = 343, // M68kInstrData.td:415
    MOV8cq                                = 344, // M68kInstrData.td:415
    MOV8ec                                = 345, // M68kInstrData.td:455
    MOV8fc                                = 346, // M68kInstrData.td:455
    MOV8jc                                = 347, // M68kInstrData.td:455
    MOV8oc                                = 348, // M68kInstrData.td:455
    MOV8pc                                = 349, // M68kInstrData.td:455
    MOVI16ri                              = 350, // M68kInstrData.td:613
    MOVI32ri                              = 351, // M68kInstrData.td:614
    MOVI8di                               = 352, // M68kInstrData.td:612
    MOVM16jm_P                            = 353, // M68kInstrData.td:373
    MOVM16mj_P                            = 354, // M68kInstrData.td:380
    MOVM16mp_P                            = 355, // M68kInstrData.td:383
    MOVM16pm_P                            = 356, // M68kInstrData.td:376
    MOVM32jm_P                            = 357, // M68kInstrData.td:374
    MOVM32mj_P                            = 358, // M68kInstrData.td:381
    MOVM32mp_P                            = 359, // M68kInstrData.td:384
    MOVM32pm_P                            = 360, // M68kInstrData.td:377
    MOVSXd16d8                            = 361, // M68kInstrData.td:626
    MOVSXd16f8                            = 362, // M68kInstrData.td:640
    MOVSXd16j8                            = 363, // M68kInstrData.td:632
    MOVSXd16p8                            = 364, // M68kInstrData.td:636
    MOVSXd16q8                            = 365, // M68kInstrData.td:644
    MOVSXd32d16                           = 366, // M68kInstrData.td:628
    MOVSXd32d8                            = 367, // M68kInstrData.td:627
    MOVSXd32f16                           = 368, // M68kInstrData.td:642
    MOVSXd32f8                            = 369, // M68kInstrData.td:641
    MOVSXd32j16                           = 370, // M68kInstrData.td:634
    MOVSXd32j8                            = 371, // M68kInstrData.td:633
    MOVSXd32p16                           = 372, // M68kInstrData.td:638
    MOVSXd32p8                            = 373, // M68kInstrData.td:637
    MOVSXd32q16                           = 374, // M68kInstrData.td:646
    MOVSXd32q8                            = 375, // M68kInstrData.td:645
    MOVXd16d8                             = 376, // M68kInstrData.td:656
    MOVXd32d16                            = 377, // M68kInstrData.td:658
    MOVXd32d8                             = 378, // M68kInstrData.td:657
    MOVZXd16d8                            = 379, // M68kInstrData.td:626
    MOVZXd16f8                            = 380, // M68kInstrData.td:640
    MOVZXd16j8                            = 381, // M68kInstrData.td:632
    MOVZXd16p8                            = 382, // M68kInstrData.td:636
    MOVZXd16q8                            = 383, // M68kInstrData.td:644
    MOVZXd32d16                           = 384, // M68kInstrData.td:628
    MOVZXd32d8                            = 385, // M68kInstrData.td:627
    MOVZXd32f16                           = 386, // M68kInstrData.td:642
    MOVZXd32f8                            = 387, // M68kInstrData.td:641
    MOVZXd32j16                           = 388, // M68kInstrData.td:634
    MOVZXd32j8                            = 389, // M68kInstrData.td:633
    MOVZXd32p16                           = 390, // M68kInstrData.td:638
    MOVZXd32p8                            = 391, // M68kInstrData.td:637
    MOVZXd32q16                           = 392, // M68kInstrData.td:646
    MOVZXd32q8                            = 393, // M68kInstrData.td:645
    POP16d                                = 394, // M68kInstrData.td:586
    POP32r                                = 395, // M68kInstrData.td:587
    POP8d                                 = 396, // M68kInstrData.td:585
    PUSH16d                               = 397, // M68kInstrData.td:579
    PUSH32r                               = 398, // M68kInstrData.td:580
    PUSH8d                                = 399, // M68kInstrData.td:578
    RET                                   = 400, // M68kInstrControl.td:351
    SALLOCA                               = 401, // M68kInstrCompiler.td:125
    SETCS_C16d                            = 402, // M68kInstrControl.td:366
    SETCS_C32d                            = 403, // M68kInstrControl.td:368
    SETCS_C8d                             = 404, // M68kInstrControl.td:364
    TAILJMPj                              = 405, // M68kInstrControl.td:331
    TAILJMPq                              = 406, // M68kInstrControl.td:325
    TCRETURNj                             = 407, // M68kInstrControl.td:330
    TCRETURNq                             = 408, // M68kInstrControl.td:324
    ADD16dd                               = 409, // M68kInstrArithmetic.td:265
    ADD16df                               = 410, // M68kInstrArithmetic.td:218
    ADD16di                               = 411, // M68kInstrArithmetic.td:230
    ADD16dj                               = 412, // M68kInstrArithmetic.td:224
    ADD16dk                               = 413, // M68kInstrArithmetic.td:200
    ADD16dp                               = 414, // M68kInstrArithmetic.td:212
    ADD16dq                               = 415, // M68kInstrArithmetic.td:206
    ADD16dr                               = 416, // M68kInstrArithmetic.td:272
    ADD16fd                               = 417, // M68kInstrArithmetic.td:239
    ADD16fi                               = 418, // M68kInstrArithmetic.td:254
    ADD16jd                               = 419, // M68kInstrArithmetic.td:244
    ADD16ji                               = 420, // M68kInstrArithmetic.td:259
    ADD16pd                               = 421, // M68kInstrArithmetic.td:234
    ADD16pi                               = 422, // M68kInstrArithmetic.td:249
    ADD32ab                               = 423, // M68kInstrArithmetic.td:296
    ADD32af                               = 424, // M68kInstrArithmetic.td:290
    ADD32ai                               = 425, // M68kInstrArithmetic.td:298
    ADD32aj                               = 426, // M68kInstrArithmetic.td:294
    ADD32ak                               = 427, // M68kInstrArithmetic.td:286
    ADD32ap                               = 428, // M68kInstrArithmetic.td:292
    ADD32aq                               = 429, // M68kInstrArithmetic.td:288
    ADD32ar                               = 430, // M68kInstrArithmetic.td:300
    ADD32dd                               = 431, // M68kInstrArithmetic.td:265
    ADD32df                               = 432, // M68kInstrArithmetic.td:218
    ADD32di                               = 433, // M68kInstrArithmetic.td:230
    ADD32dj                               = 434, // M68kInstrArithmetic.td:224
    ADD32dk                               = 435, // M68kInstrArithmetic.td:200
    ADD32dp                               = 436, // M68kInstrArithmetic.td:212
    ADD32dq                               = 437, // M68kInstrArithmetic.td:206
    ADD32dr                               = 438, // M68kInstrArithmetic.td:272
    ADD32fd                               = 439, // M68kInstrArithmetic.td:239
    ADD32fi                               = 440, // M68kInstrArithmetic.td:254
    ADD32jd                               = 441, // M68kInstrArithmetic.td:244
    ADD32ji                               = 442, // M68kInstrArithmetic.td:259
    ADD32pd                               = 443, // M68kInstrArithmetic.td:234
    ADD32pi                               = 444, // M68kInstrArithmetic.td:249
    ADD8dd                                = 445, // M68kInstrArithmetic.td:265
    ADD8df                                = 446, // M68kInstrArithmetic.td:218
    ADD8di                                = 447, // M68kInstrArithmetic.td:230
    ADD8dj                                = 448, // M68kInstrArithmetic.td:224
    ADD8dk                                = 449, // M68kInstrArithmetic.td:200
    ADD8dp                                = 450, // M68kInstrArithmetic.td:212
    ADD8dq                                = 451, // M68kInstrArithmetic.td:206
    ADD8fd                                = 452, // M68kInstrArithmetic.td:239
    ADD8fi                                = 453, // M68kInstrArithmetic.td:254
    ADD8jd                                = 454, // M68kInstrArithmetic.td:244
    ADD8ji                                = 455, // M68kInstrArithmetic.td:259
    ADD8pd                                = 456, // M68kInstrArithmetic.td:234
    ADD8pi                                = 457, // M68kInstrArithmetic.td:249
    ADDX16dd                              = 458, // M68kInstrArithmetic.td:360
    ADDX32dd                              = 459, // M68kInstrArithmetic.td:360
    ADDX8dd                               = 460, // M68kInstrArithmetic.td:360
    AND16dd                               = 461, // M68kInstrArithmetic.td:265
    AND16df                               = 462, // M68kInstrArithmetic.td:218
    AND16di                               = 463, // M68kInstrArithmetic.td:230
    AND16dj                               = 464, // M68kInstrArithmetic.td:224
    AND16dk                               = 465, // M68kInstrArithmetic.td:200
    AND16dp                               = 466, // M68kInstrArithmetic.td:212
    AND16dq                               = 467, // M68kInstrArithmetic.td:206
    AND16dr                               = 468, // M68kInstrArithmetic.td:272
    AND16fd                               = 469, // M68kInstrArithmetic.td:239
    AND16fi                               = 470, // M68kInstrArithmetic.td:254
    AND16jd                               = 471, // M68kInstrArithmetic.td:244
    AND16ji                               = 472, // M68kInstrArithmetic.td:259
    AND16pd                               = 473, // M68kInstrArithmetic.td:234
    AND16pi                               = 474, // M68kInstrArithmetic.td:249
    AND32dd                               = 475, // M68kInstrArithmetic.td:265
    AND32df                               = 476, // M68kInstrArithmetic.td:218
    AND32di                               = 477, // M68kInstrArithmetic.td:230
    AND32dj                               = 478, // M68kInstrArithmetic.td:224
    AND32dk                               = 479, // M68kInstrArithmetic.td:200
    AND32dp                               = 480, // M68kInstrArithmetic.td:212
    AND32dq                               = 481, // M68kInstrArithmetic.td:206
    AND32dr                               = 482, // M68kInstrArithmetic.td:272
    AND32fd                               = 483, // M68kInstrArithmetic.td:239
    AND32fi                               = 484, // M68kInstrArithmetic.td:254
    AND32jd                               = 485, // M68kInstrArithmetic.td:244
    AND32ji                               = 486, // M68kInstrArithmetic.td:259
    AND32pd                               = 487, // M68kInstrArithmetic.td:234
    AND32pi                               = 488, // M68kInstrArithmetic.td:249
    AND8dd                                = 489, // M68kInstrArithmetic.td:265
    AND8df                                = 490, // M68kInstrArithmetic.td:218
    AND8di                                = 491, // M68kInstrArithmetic.td:230
    AND8dj                                = 492, // M68kInstrArithmetic.td:224
    AND8dk                                = 493, // M68kInstrArithmetic.td:200
    AND8dp                                = 494, // M68kInstrArithmetic.td:212
    AND8dq                                = 495, // M68kInstrArithmetic.td:206
    AND8fd                                = 496, // M68kInstrArithmetic.td:239
    AND8fi                                = 497, // M68kInstrArithmetic.td:254
    AND8jd                                = 498, // M68kInstrArithmetic.td:244
    AND8ji                                = 499, // M68kInstrArithmetic.td:259
    AND8pd                                = 500, // M68kInstrArithmetic.td:234
    AND8pi                                = 501, // M68kInstrArithmetic.td:249
    ASR16dd                               = 502, // M68kInstrShiftRotate.td:81
    ASR16di                               = 503, // M68kInstrShiftRotate.td:85
    ASR32dd                               = 504, // M68kInstrShiftRotate.td:82
    ASR32di                               = 505, // M68kInstrShiftRotate.td:86
    ASR8dd                                = 506, // M68kInstrShiftRotate.td:80
    ASR8di                                = 507, // M68kInstrShiftRotate.td:84
    BCHG32dd                              = 508, // M68kInstrBits.td:99
    BCHG32di                              = 509, // M68kInstrBits.td:100
    BCHG8ed                               = 510, // M68kInstrBits.td:107
    BCHG8ei                               = 511, // M68kInstrBits.td:118
    BCHG8fd                               = 512, // M68kInstrBits.td:111
    BCHG8fi                               = 513, // M68kInstrBits.td:122
    BCHG8jd                               = 514, // M68kInstrBits.td:103
    BCHG8ji                               = 515, // M68kInstrBits.td:114
    BCHG8od                               = 516, // M68kInstrBits.td:105
    BCHG8oi                               = 517, // M68kInstrBits.td:116
    BCHG8pd                               = 518, // M68kInstrBits.td:109
    BCHG8pi                               = 519, // M68kInstrBits.td:120
    BCLR32dd                              = 520, // M68kInstrBits.td:99
    BCLR32di                              = 521, // M68kInstrBits.td:100
    BCLR8ed                               = 522, // M68kInstrBits.td:107
    BCLR8ei                               = 523, // M68kInstrBits.td:118
    BCLR8fd                               = 524, // M68kInstrBits.td:111
    BCLR8fi                               = 525, // M68kInstrBits.td:122
    BCLR8jd                               = 526, // M68kInstrBits.td:103
    BCLR8ji                               = 527, // M68kInstrBits.td:114
    BCLR8od                               = 528, // M68kInstrBits.td:105
    BCLR8oi                               = 529, // M68kInstrBits.td:116
    BCLR8pd                               = 530, // M68kInstrBits.td:109
    BCLR8pi                               = 531, // M68kInstrBits.td:120
    BKPT                                  = 532, // M68kInstrControl.td:433
    BRA16                                 = 533, // M68kInstrControl.td:231
    BRA32                                 = 534, // M68kInstrControl.td:234
    BRA8                                  = 535, // M68kInstrControl.td:228
    BSET32dd                              = 536, // M68kInstrBits.td:99
    BSET32di                              = 537, // M68kInstrBits.td:100
    BSET8ed                               = 538, // M68kInstrBits.td:107
    BSET8ei                               = 539, // M68kInstrBits.td:118
    BSET8fd                               = 540, // M68kInstrBits.td:111
    BSET8fi                               = 541, // M68kInstrBits.td:122
    BSET8jd                               = 542, // M68kInstrBits.td:103
    BSET8ji                               = 543, // M68kInstrBits.td:114
    BSET8od                               = 544, // M68kInstrBits.td:105
    BSET8oi                               = 545, // M68kInstrBits.td:116
    BSET8pd                               = 546, // M68kInstrBits.td:109
    BSET8pi                               = 547, // M68kInstrBits.td:120
    BSR16                                 = 548, // M68kInstrControl.td:263
    BSR32                                 = 549, // M68kInstrControl.td:266
    BSR8                                  = 550, // M68kInstrControl.td:260
    BTST32dd                              = 551, // M68kInstrBits.td:99
    BTST32di                              = 552, // M68kInstrBits.td:100
    BTST8ed                               = 553, // M68kInstrBits.td:107
    BTST8ei                               = 554, // M68kInstrBits.td:118
    BTST8fd                               = 555, // M68kInstrBits.td:111
    BTST8fi                               = 556, // M68kInstrBits.td:122
    BTST8jd                               = 557, // M68kInstrBits.td:103
    BTST8ji                               = 558, // M68kInstrBits.td:114
    BTST8kd                               = 559, // M68kInstrBits.td:90
    BTST8ki                               = 560, // M68kInstrBits.td:94
    BTST8od                               = 561, // M68kInstrBits.td:105
    BTST8oi                               = 562, // M68kInstrBits.td:116
    BTST8pd                               = 563, // M68kInstrBits.td:109
    BTST8pi                               = 564, // M68kInstrBits.td:120
    BTST8qd                               = 565, // M68kInstrBits.td:88
    BTST8qi                               = 566, // M68kInstrBits.td:92
    Bcc16                                 = 567, // M68kInstrControl.td:192
    Bcc32                                 = 568, // M68kInstrControl.td:196
    Bcc8                                  = 569, // M68kInstrControl.td:188
    Bcs16                                 = 570, // M68kInstrControl.td:192
    Bcs32                                 = 571, // M68kInstrControl.td:196
    Bcs8                                  = 572, // M68kInstrControl.td:188
    Beq16                                 = 573, // M68kInstrControl.td:192
    Beq32                                 = 574, // M68kInstrControl.td:196
    Beq8                                  = 575, // M68kInstrControl.td:188
    Bge16                                 = 576, // M68kInstrControl.td:192
    Bge32                                 = 577, // M68kInstrControl.td:196
    Bge8                                  = 578, // M68kInstrControl.td:188
    Bgt16                                 = 579, // M68kInstrControl.td:192
    Bgt32                                 = 580, // M68kInstrControl.td:196
    Bgt8                                  = 581, // M68kInstrControl.td:188
    Bhi16                                 = 582, // M68kInstrControl.td:192
    Bhi32                                 = 583, // M68kInstrControl.td:196
    Bhi8                                  = 584, // M68kInstrControl.td:188
    Ble16                                 = 585, // M68kInstrControl.td:192
    Ble32                                 = 586, // M68kInstrControl.td:196
    Ble8                                  = 587, // M68kInstrControl.td:188
    Bls16                                 = 588, // M68kInstrControl.td:192
    Bls32                                 = 589, // M68kInstrControl.td:196
    Bls8                                  = 590, // M68kInstrControl.td:188
    Blt16                                 = 591, // M68kInstrControl.td:192
    Blt32                                 = 592, // M68kInstrControl.td:196
    Blt8                                  = 593, // M68kInstrControl.td:188
    Bmi16                                 = 594, // M68kInstrControl.td:192
    Bmi32                                 = 595, // M68kInstrControl.td:196
    Bmi8                                  = 596, // M68kInstrControl.td:188
    Bne16                                 = 597, // M68kInstrControl.td:192
    Bne32                                 = 598, // M68kInstrControl.td:196
    Bne8                                  = 599, // M68kInstrControl.td:188
    Bpl16                                 = 600, // M68kInstrControl.td:192
    Bpl32                                 = 601, // M68kInstrControl.td:196
    Bpl8                                  = 602, // M68kInstrControl.td:188
    Bvc16                                 = 603, // M68kInstrControl.td:192
    Bvc32                                 = 604, // M68kInstrControl.td:196
    Bvc8                                  = 605, // M68kInstrControl.td:188
    Bvs16                                 = 606, // M68kInstrControl.td:192
    Bvs32                                 = 607, // M68kInstrControl.td:196
    Bvs8                                  = 608, // M68kInstrControl.td:188
    CALLb                                 = 609, // M68kInstrControl.td:299
    CALLf                                 = 610, // M68kInstrControl.td:297
    CALLj                                 = 611, // M68kInstrControl.td:300
    CALLk                                 = 612, // M68kInstrControl.td:294
    CALLl                                 = 613, // M68kInstrControl.td:296
    CALLp                                 = 614, // M68kInstrControl.td:298
    CALLq                                 = 615, // M68kInstrControl.td:295
    CASAL16                               = 616, // M68kInstrAtomics.td:107
    CASAL32                               = 617, // M68kInstrAtomics.td:108
    CASAL8                                = 618, // M68kInstrAtomics.td:106
    CASARI16                              = 619, // M68kInstrAtomics.td:53
    CASARI32                              = 620, // M68kInstrAtomics.td:54
    CASARI8                               = 621, // M68kInstrAtomics.td:52
    CASARID16                             = 622, // M68kInstrAtomics.td:71
    CASARID32                             = 623, // M68kInstrAtomics.td:72
    CASARID8                              = 624, // M68kInstrAtomics.td:70
    CASARII16                             = 625, // M68kInstrAtomics.td:89
    CASARII32                             = 626, // M68kInstrAtomics.td:90
    CASARII8                              = 627, // M68kInstrAtomics.td:88
    CMP16bi                               = 628, // M68kInstrArithmetic.td:508
    CMP16df                               = 629, // M68kInstrArithmetic.td:489
    CMP16di                               = 630, // M68kInstrArithmetic.td:507
    CMP16dj                               = 631, // M68kInstrArithmetic.td:490
    CMP16dk                               = 632, // M68kInstrArithmetic.td:486
    CMP16dp                               = 633, // M68kInstrArithmetic.td:488
    CMP16dq                               = 634, // M68kInstrArithmetic.td:487
    CMP16dr                               = 635, // M68kInstrArithmetic.td:513
    CMP16fi                               = 636, // M68kInstrArithmetic.td:500
    CMP16ji                               = 637, // M68kInstrArithmetic.td:502
    CMP16ki                               = 638, // M68kInstrArithmetic.td:494
    CMP16pi                               = 639, // M68kInstrArithmetic.td:498
    CMP16qi                               = 640, // M68kInstrArithmetic.td:496
    CMP32bi                               = 641, // M68kInstrArithmetic.td:508
    CMP32df                               = 642, // M68kInstrArithmetic.td:489
    CMP32di                               = 643, // M68kInstrArithmetic.td:507
    CMP32dj                               = 644, // M68kInstrArithmetic.td:490
    CMP32dk                               = 645, // M68kInstrArithmetic.td:486
    CMP32dp                               = 646, // M68kInstrArithmetic.td:488
    CMP32dq                               = 647, // M68kInstrArithmetic.td:487
    CMP32dr                               = 648, // M68kInstrArithmetic.td:513
    CMP32fi                               = 649, // M68kInstrArithmetic.td:500
    CMP32ji                               = 650, // M68kInstrArithmetic.td:502
    CMP32ki                               = 651, // M68kInstrArithmetic.td:494
    CMP32pi                               = 652, // M68kInstrArithmetic.td:498
    CMP32qi                               = 653, // M68kInstrArithmetic.td:496
    CMP8bi                                = 654, // M68kInstrArithmetic.td:508
    CMP8dd                                = 655, // M68kInstrArithmetic.td:511
    CMP8df                                = 656, // M68kInstrArithmetic.td:489
    CMP8di                                = 657, // M68kInstrArithmetic.td:507
    CMP8dj                                = 658, // M68kInstrArithmetic.td:490
    CMP8dk                                = 659, // M68kInstrArithmetic.td:486
    CMP8dp                                = 660, // M68kInstrArithmetic.td:488
    CMP8dq                                = 661, // M68kInstrArithmetic.td:487
    CMP8fi                                = 662, // M68kInstrArithmetic.td:500
    CMP8ji                                = 663, // M68kInstrArithmetic.td:502
    CMP8ki                                = 664, // M68kInstrArithmetic.td:494
    CMP8pi                                = 665, // M68kInstrArithmetic.td:498
    CMP8qi                                = 666, // M68kInstrArithmetic.td:496
    EXT16                                 = 667, // M68kInstrArithmetic.td:558
    EXT32                                 = 668, // M68kInstrArithmetic.td:559
    FABS32fp_fp                           = 669, // M68kInstrArithmetic.td:1056
    FABS64fp_fp                           = 670, // M68kInstrArithmetic.td:1056
    FABS80fp_fp                           = 671, // M68kInstrArithmetic.td:1051
    FADD32fp_fp                           = 672, // M68kInstrArithmetic.td:1099
    FADD64fp_fp                           = 673, // M68kInstrArithmetic.td:1099
    FADD80fp_fp                           = 674, // M68kInstrArithmetic.td:1094
    FDABS32fp_fp                          = 675, // M68kInstrArithmetic.td:1056
    FDABS64fp_fp                          = 676, // M68kInstrArithmetic.td:1056
    FDABS80fp_fp                          = 677, // M68kInstrArithmetic.td:1051
    FDADD32fp_fp                          = 678, // M68kInstrArithmetic.td:1099
    FDADD64fp_fp                          = 679, // M68kInstrArithmetic.td:1099
    FDADD80fp_fp                          = 680, // M68kInstrArithmetic.td:1094
    FDDIV32fp_fp                          = 681, // M68kInstrArithmetic.td:1099
    FDDIV64fp_fp                          = 682, // M68kInstrArithmetic.td:1099
    FDDIV80fp_fp                          = 683, // M68kInstrArithmetic.td:1094
    FDIV32fp_fp                           = 684, // M68kInstrArithmetic.td:1099
    FDIV64fp_fp                           = 685, // M68kInstrArithmetic.td:1099
    FDIV80fp_fp                           = 686, // M68kInstrArithmetic.td:1094
    FDMOV32fp_fp                          = 687, // M68kInstrData.td:796
    FDMOV64fp_fp                          = 688, // M68kInstrData.td:796
    FDMOV80fp_fp                          = 689, // M68kInstrData.td:789
    FDMUL32fp_fp                          = 690, // M68kInstrArithmetic.td:1099
    FDMUL64fp_fp                          = 691, // M68kInstrArithmetic.td:1099
    FDMUL80fp_fp                          = 692, // M68kInstrArithmetic.td:1094
    FDNEG32fp_fp                          = 693, // M68kInstrArithmetic.td:1056
    FDNEG64fp_fp                          = 694, // M68kInstrArithmetic.td:1056
    FDNEG80fp_fp                          = 695, // M68kInstrArithmetic.td:1051
    FDSUB32fp_fp                          = 696, // M68kInstrArithmetic.td:1099
    FDSUB64fp_fp                          = 697, // M68kInstrArithmetic.td:1099
    FDSUB80fp_fp                          = 698, // M68kInstrArithmetic.td:1094
    FMOV32fp_fp                           = 699, // M68kInstrData.td:796
    FMOV64fp_fp                           = 700, // M68kInstrData.td:796
    FMOV80fp_fp                           = 701, // M68kInstrData.td:789
    FMOVE32a_fpi                          = 702, // M68kInstrData.td:843
    FMOVE32d_fpcs                         = 703, // M68kInstrData.td:841
    FMOVE32fpcs_d                         = 704, // M68kInstrData.td:840
    FMOVE32fpi_a                          = 705, // M68kInstrData.td:842
    FMUL32fp_fp                           = 706, // M68kInstrArithmetic.td:1099
    FMUL64fp_fp                           = 707, // M68kInstrArithmetic.td:1099
    FMUL80fp_fp                           = 708, // M68kInstrArithmetic.td:1094
    FNEG32fp_fp                           = 709, // M68kInstrArithmetic.td:1056
    FNEG64fp_fp                           = 710, // M68kInstrArithmetic.td:1056
    FNEG80fp_fp                           = 711, // M68kInstrArithmetic.td:1051
    FSABS32fp_fp                          = 712, // M68kInstrArithmetic.td:1056
    FSABS64fp_fp                          = 713, // M68kInstrArithmetic.td:1056
    FSABS80fp_fp                          = 714, // M68kInstrArithmetic.td:1051
    FSADD32fp_fp                          = 715, // M68kInstrArithmetic.td:1099
    FSADD64fp_fp                          = 716, // M68kInstrArithmetic.td:1099
    FSADD80fp_fp                          = 717, // M68kInstrArithmetic.td:1094
    FSDIV32fp_fp                          = 718, // M68kInstrArithmetic.td:1099
    FSDIV64fp_fp                          = 719, // M68kInstrArithmetic.td:1099
    FSDIV80fp_fp                          = 720, // M68kInstrArithmetic.td:1094
    FSMOV32fp_fp                          = 721, // M68kInstrData.td:796
    FSMOV64fp_fp                          = 722, // M68kInstrData.td:796
    FSMOV80fp_fp                          = 723, // M68kInstrData.td:789
    FSMUL32fp_fp                          = 724, // M68kInstrArithmetic.td:1099
    FSMUL64fp_fp                          = 725, // M68kInstrArithmetic.td:1099
    FSMUL80fp_fp                          = 726, // M68kInstrArithmetic.td:1094
    FSNEG32fp_fp                          = 727, // M68kInstrArithmetic.td:1056
    FSNEG64fp_fp                          = 728, // M68kInstrArithmetic.td:1056
    FSNEG80fp_fp                          = 729, // M68kInstrArithmetic.td:1051
    FSSUB32fp_fp                          = 730, // M68kInstrArithmetic.td:1099
    FSSUB64fp_fp                          = 731, // M68kInstrArithmetic.td:1099
    FSSUB80fp_fp                          = 732, // M68kInstrArithmetic.td:1094
    FSUB32fp_fp                           = 733, // M68kInstrArithmetic.td:1099
    FSUB64fp_fp                           = 734, // M68kInstrArithmetic.td:1099
    FSUB80fp_fp                           = 735, // M68kInstrArithmetic.td:1094
    ILLEGAL                               = 736, // M68kInstrControl.td:437
    JMP32j                                = 737, // M68kInstrControl.td:141
    LEA32L                                = 738, // M68kInstrData.td:537
    LEA32b                                = 739, // M68kInstrData.td:537
    LEA32f                                = 740, // M68kInstrData.td:537
    LEA32k                                = 741, // M68kInstrData.td:537
    LEA32l                                = 742, // M68kInstrData.td:537
    LEA32p                                = 743, // M68kInstrData.td:537
    LEA32q                                = 744, // M68kInstrData.td:537
    LINK16                                = 745, // M68kInstrData.td:547
    LINK32                                = 746, // M68kInstrData.td:554
    LSR16dd                               = 747, // M68kInstrShiftRotate.td:81
    LSR16di                               = 748, // M68kInstrShiftRotate.td:85
    LSR32dd                               = 749, // M68kInstrShiftRotate.td:82
    LSR32di                               = 750, // M68kInstrShiftRotate.td:86
    LSR8dd                                = 751, // M68kInstrShiftRotate.td:80
    LSR8di                                = 752, // M68kInstrShiftRotate.td:84
    MOV16aa                               = 753, // M68kInstrData.td:128
    MOV16ab                               = 754, // M68kInstrData.td:202
    MOV16ab_TC                            = 755, // M68kInstrData.td:212
    MOV16ae                               = 756, // M68kInstrData.td:202
    MOV16ae_TC                            = 757, // M68kInstrData.td:212
    MOV16af                               = 758, // M68kInstrData.td:202
    MOV16af_TC                            = 759, // M68kInstrData.td:212
    MOV16ai                               = 760, // M68kInstrData.td:182
    MOV16aj                               = 761, // M68kInstrData.td:202
    MOV16aj_TC                            = 762, // M68kInstrData.td:212
    MOV16ak                               = 763, // M68kInstrData.td:202
    MOV16ak_TC                            = 764, // M68kInstrData.td:212
    MOV16ao                               = 765, // M68kInstrData.td:202
    MOV16ao_TC                            = 766, // M68kInstrData.td:212
    MOV16ap                               = 767, // M68kInstrData.td:202
    MOV16ap_TC                            = 768, // M68kInstrData.td:212
    MOV16aq                               = 769, // M68kInstrData.td:202
    MOV16aq_TC                            = 770, // M68kInstrData.td:212
    MOV16ar                               = 771, // M68kInstrData.td:128
    MOV16ba                               = 772, // M68kInstrData.td:156
    MOV16bb                               = 773, // M68kInstrData.td:247
    MOV16bc                               = 774, // M68kInstrData.td:452
    MOV16bd                               = 775, // M68kInstrData.td:156
    MOV16be                               = 776, // M68kInstrData.td:247
    MOV16bf                               = 777, // M68kInstrData.td:247
    MOV16bi                               = 778, // M68kInstrData.td:165
    MOV16bj                               = 779, // M68kInstrData.td:247
    MOV16bk                               = 780, // M68kInstrData.td:247
    MOV16bo                               = 781, // M68kInstrData.td:247
    MOV16bp                               = 782, // M68kInstrData.td:247
    MOV16bq                               = 783, // M68kInstrData.td:247
    MOV16br                               = 784, // M68kInstrData.td:156
    MOV16bs                               = 785, // M68kInstrData.td:511
    MOV16cb                               = 786, // M68kInstrData.td:413
    MOV16cd                               = 787, // M68kInstrData.td:419
    MOV16ce                               = 788, // M68kInstrData.td:413
    MOV16cf                               = 789, // M68kInstrData.td:413
    MOV16cj                               = 790, // M68kInstrData.td:413
    MOV16ck                               = 791, // M68kInstrData.td:413
    MOV16co                               = 792, // M68kInstrData.td:413
    MOV16cp                               = 793, // M68kInstrData.td:413
    MOV16cq                               = 794, // M68kInstrData.td:413
    MOV16db                               = 795, // M68kInstrData.td:202
    MOV16dc                               = 796, // M68kInstrData.td:460
    MOV16dd                               = 797, // M68kInstrData.td:135
    MOV16de                               = 798, // M68kInstrData.td:202
    MOV16df                               = 799, // M68kInstrData.td:202
    MOV16di                               = 800, // M68kInstrData.td:182
    MOV16dj                               = 801, // M68kInstrData.td:202
    MOV16dk                               = 802, // M68kInstrData.td:202
    MOV16do                               = 803, // M68kInstrData.td:202
    MOV16dp                               = 804, // M68kInstrData.td:202
    MOV16dq                               = 805, // M68kInstrData.td:202
    MOV16ds                               = 806, // M68kInstrData.td:516
    MOV16ea                               = 807, // M68kInstrData.td:156
    MOV16eb                               = 808, // M68kInstrData.td:247
    MOV16ec                               = 809, // M68kInstrData.td:452
    MOV16ed                               = 810, // M68kInstrData.td:156
    MOV16ee                               = 811, // M68kInstrData.td:247
    MOV16ef                               = 812, // M68kInstrData.td:247
    MOV16ei                               = 813, // M68kInstrData.td:165
    MOV16ej                               = 814, // M68kInstrData.td:247
    MOV16ek                               = 815, // M68kInstrData.td:247
    MOV16eo                               = 816, // M68kInstrData.td:247
    MOV16ep                               = 817, // M68kInstrData.td:247
    MOV16eq                               = 818, // M68kInstrData.td:247
    MOV16er                               = 819, // M68kInstrData.td:156
    MOV16es                               = 820, // M68kInstrData.td:511
    MOV16fa                               = 821, // M68kInstrData.td:156
    MOV16fb                               = 822, // M68kInstrData.td:247
    MOV16fc                               = 823, // M68kInstrData.td:452
    MOV16fd                               = 824, // M68kInstrData.td:156
    MOV16fe                               = 825, // M68kInstrData.td:247
    MOV16ff                               = 826, // M68kInstrData.td:247
    MOV16fi                               = 827, // M68kInstrData.td:165
    MOV16fj                               = 828, // M68kInstrData.td:247
    MOV16fk                               = 829, // M68kInstrData.td:247
    MOV16fo                               = 830, // M68kInstrData.td:247
    MOV16fp                               = 831, // M68kInstrData.td:247
    MOV16fq                               = 832, // M68kInstrData.td:247
    MOV16fr                               = 833, // M68kInstrData.td:156
    MOV16fs                               = 834, // M68kInstrData.td:511
    MOV16ja                               = 835, // M68kInstrData.td:156
    MOV16jb                               = 836, // M68kInstrData.td:247
    MOV16jc                               = 837, // M68kInstrData.td:452
    MOV16jd                               = 838, // M68kInstrData.td:156
    MOV16je                               = 839, // M68kInstrData.td:247
    MOV16jf                               = 840, // M68kInstrData.td:247
    MOV16ji                               = 841, // M68kInstrData.td:165
    MOV16jj                               = 842, // M68kInstrData.td:247
    MOV16jk                               = 843, // M68kInstrData.td:247
    MOV16jo                               = 844, // M68kInstrData.td:247
    MOV16jp                               = 845, // M68kInstrData.td:247
    MOV16jq                               = 846, // M68kInstrData.td:247
    MOV16jr                               = 847, // M68kInstrData.td:156
    MOV16js                               = 848, // M68kInstrData.td:511
    MOV16oa                               = 849, // M68kInstrData.td:156
    MOV16ob                               = 850, // M68kInstrData.td:247
    MOV16oc                               = 851, // M68kInstrData.td:452
    MOV16od                               = 852, // M68kInstrData.td:156
    MOV16oe                               = 853, // M68kInstrData.td:247
    MOV16of                               = 854, // M68kInstrData.td:247
    MOV16oi                               = 855, // M68kInstrData.td:165
    MOV16oj                               = 856, // M68kInstrData.td:247
    MOV16ok                               = 857, // M68kInstrData.td:247
    MOV16oo                               = 858, // M68kInstrData.td:247
    MOV16op                               = 859, // M68kInstrData.td:247
    MOV16oq                               = 860, // M68kInstrData.td:247
    MOV16or                               = 861, // M68kInstrData.td:156
    MOV16os                               = 862, // M68kInstrData.td:511
    MOV16pa                               = 863, // M68kInstrData.td:156
    MOV16pb                               = 864, // M68kInstrData.td:247
    MOV16pc                               = 865, // M68kInstrData.td:452
    MOV16pd                               = 866, // M68kInstrData.td:156
    MOV16pe                               = 867, // M68kInstrData.td:247
    MOV16pf                               = 868, // M68kInstrData.td:247
    MOV16pi                               = 869, // M68kInstrData.td:165
    MOV16pj                               = 870, // M68kInstrData.td:247
    MOV16pk                               = 871, // M68kInstrData.td:247
    MOV16po                               = 872, // M68kInstrData.td:247
    MOV16pp                               = 873, // M68kInstrData.td:247
    MOV16pq                               = 874, // M68kInstrData.td:247
    MOV16pr                               = 875, // M68kInstrData.td:156
    MOV16ps                               = 876, // M68kInstrData.td:511
    MOV16ra                               = 877, // M68kInstrData.td:128
    MOV16rb                               = 878, // M68kInstrData.td:202
    MOV16rb_TC                            = 879, // M68kInstrData.td:212
    MOV16re                               = 880, // M68kInstrData.td:202
    MOV16re_TC                            = 881, // M68kInstrData.td:212
    MOV16rf                               = 882, // M68kInstrData.td:202
    MOV16rf_TC                            = 883, // M68kInstrData.td:212
    MOV16ri                               = 884, // M68kInstrData.td:182
    MOV16rj                               = 885, // M68kInstrData.td:202
    MOV16rj_TC                            = 886, // M68kInstrData.td:212
    MOV16rk                               = 887, // M68kInstrData.td:202
    MOV16rk_TC                            = 888, // M68kInstrData.td:212
    MOV16ro                               = 889, // M68kInstrData.td:202
    MOV16ro_TC                            = 890, // M68kInstrData.td:212
    MOV16rp                               = 891, // M68kInstrData.td:202
    MOV16rp_TC                            = 892, // M68kInstrData.td:212
    MOV16rq                               = 893, // M68kInstrData.td:202
    MOV16rq_TC                            = 894, // M68kInstrData.td:212
    MOV16rr                               = 895, // M68kInstrData.td:128
    MOV16sb                               = 896, // M68kInstrData.td:481
    MOV16sd                               = 897, // M68kInstrData.td:485
    MOV16se                               = 898, // M68kInstrData.td:481
    MOV16sf                               = 899, // M68kInstrData.td:481
    MOV16sj                               = 900, // M68kInstrData.td:481
    MOV16sk                               = 901, // M68kInstrData.td:481
    MOV16so                               = 902, // M68kInstrData.td:481
    MOV16sp                               = 903, // M68kInstrData.td:481
    MOV16sq                               = 904, // M68kInstrData.td:481
    MOV32aa                               = 905, // M68kInstrData.td:128
    MOV32ab                               = 906, // M68kInstrData.td:202
    MOV32ab_TC                            = 907, // M68kInstrData.td:212
    MOV32ae                               = 908, // M68kInstrData.td:202
    MOV32ae_TC                            = 909, // M68kInstrData.td:212
    MOV32af                               = 910, // M68kInstrData.td:202
    MOV32af_TC                            = 911, // M68kInstrData.td:212
    MOV32ai                               = 912, // M68kInstrData.td:182
    MOV32aj                               = 913, // M68kInstrData.td:202
    MOV32aj_TC                            = 914, // M68kInstrData.td:212
    MOV32ak                               = 915, // M68kInstrData.td:202
    MOV32ak_TC                            = 916, // M68kInstrData.td:212
    MOV32ao                               = 917, // M68kInstrData.td:202
    MOV32ao_TC                            = 918, // M68kInstrData.td:212
    MOV32ap                               = 919, // M68kInstrData.td:202
    MOV32ap_TC                            = 920, // M68kInstrData.td:212
    MOV32aq                               = 921, // M68kInstrData.td:202
    MOV32aq_TC                            = 922, // M68kInstrData.td:212
    MOV32ar                               = 923, // M68kInstrData.td:128
    MOV32ba                               = 924, // M68kInstrData.td:156
    MOV32bb                               = 925, // M68kInstrData.td:254
    MOV32bd                               = 926, // M68kInstrData.td:156
    MOV32be                               = 927, // M68kInstrData.td:254
    MOV32bf                               = 928, // M68kInstrData.td:254
    MOV32bi                               = 929, // M68kInstrData.td:165
    MOV32bj                               = 930, // M68kInstrData.td:254
    MOV32bk                               = 931, // M68kInstrData.td:254
    MOV32bo                               = 932, // M68kInstrData.td:254
    MOV32bp                               = 933, // M68kInstrData.td:254
    MOV32bq                               = 934, // M68kInstrData.td:254
    MOV32br                               = 935, // M68kInstrData.td:156
    MOV32db                               = 936, // M68kInstrData.td:202
    MOV32dd                               = 937, // M68kInstrData.td:135
    MOV32de                               = 938, // M68kInstrData.td:202
    MOV32df                               = 939, // M68kInstrData.td:202
    MOV32di                               = 940, // M68kInstrData.td:182
    MOV32dj                               = 941, // M68kInstrData.td:202
    MOV32dk                               = 942, // M68kInstrData.td:202
    MOV32do                               = 943, // M68kInstrData.td:202
    MOV32dp                               = 944, // M68kInstrData.td:202
    MOV32dq                               = 945, // M68kInstrData.td:202
    MOV32ea                               = 946, // M68kInstrData.td:156
    MOV32eb                               = 947, // M68kInstrData.td:254
    MOV32ed                               = 948, // M68kInstrData.td:156
    MOV32ee                               = 949, // M68kInstrData.td:254
    MOV32ef                               = 950, // M68kInstrData.td:254
    MOV32ei                               = 951, // M68kInstrData.td:165
    MOV32ej                               = 952, // M68kInstrData.td:254
    MOV32ek                               = 953, // M68kInstrData.td:254
    MOV32eo                               = 954, // M68kInstrData.td:254
    MOV32ep                               = 955, // M68kInstrData.td:254
    MOV32eq                               = 956, // M68kInstrData.td:254
    MOV32er                               = 957, // M68kInstrData.td:156
    MOV32fa                               = 958, // M68kInstrData.td:156
    MOV32fb                               = 959, // M68kInstrData.td:254
    MOV32fd                               = 960, // M68kInstrData.td:156
    MOV32fe                               = 961, // M68kInstrData.td:254
    MOV32ff                               = 962, // M68kInstrData.td:254
    MOV32fi                               = 963, // M68kInstrData.td:165
    MOV32fj                               = 964, // M68kInstrData.td:254
    MOV32fk                               = 965, // M68kInstrData.td:254
    MOV32fo                               = 966, // M68kInstrData.td:254
    MOV32fp                               = 967, // M68kInstrData.td:254
    MOV32fq                               = 968, // M68kInstrData.td:254
    MOV32fr                               = 969, // M68kInstrData.td:156
    MOV32ja                               = 970, // M68kInstrData.td:156
    MOV32jb                               = 971, // M68kInstrData.td:254
    MOV32jd                               = 972, // M68kInstrData.td:156
    MOV32je                               = 973, // M68kInstrData.td:254
    MOV32jf                               = 974, // M68kInstrData.td:254
    MOV32ji                               = 975, // M68kInstrData.td:165
    MOV32jj                               = 976, // M68kInstrData.td:254
    MOV32jk                               = 977, // M68kInstrData.td:254
    MOV32jo                               = 978, // M68kInstrData.td:254
    MOV32jp                               = 979, // M68kInstrData.td:254
    MOV32jq                               = 980, // M68kInstrData.td:254
    MOV32jr                               = 981, // M68kInstrData.td:156
    MOV32oa                               = 982, // M68kInstrData.td:156
    MOV32ob                               = 983, // M68kInstrData.td:254
    MOV32od                               = 984, // M68kInstrData.td:156
    MOV32oe                               = 985, // M68kInstrData.td:254
    MOV32of                               = 986, // M68kInstrData.td:254
    MOV32oi                               = 987, // M68kInstrData.td:165
    MOV32oj                               = 988, // M68kInstrData.td:254
    MOV32ok                               = 989, // M68kInstrData.td:254
    MOV32oo                               = 990, // M68kInstrData.td:254
    MOV32op                               = 991, // M68kInstrData.td:254
    MOV32oq                               = 992, // M68kInstrData.td:254
    MOV32or                               = 993, // M68kInstrData.td:156
    MOV32pa                               = 994, // M68kInstrData.td:156
    MOV32pb                               = 995, // M68kInstrData.td:254
    MOV32pd                               = 996, // M68kInstrData.td:156
    MOV32pe                               = 997, // M68kInstrData.td:254
    MOV32pf                               = 998, // M68kInstrData.td:254
    MOV32pi                               = 999, // M68kInstrData.td:165
    MOV32pj                               = 1000, // M68kInstrData.td:254
    MOV32pk                               = 1001, // M68kInstrData.td:254
    MOV32po                               = 1002, // M68kInstrData.td:254
    MOV32pp                               = 1003, // M68kInstrData.td:254
    MOV32pq                               = 1004, // M68kInstrData.td:254
    MOV32pr                               = 1005, // M68kInstrData.td:156
    MOV32ra                               = 1006, // M68kInstrData.td:128
    MOV32rb                               = 1007, // M68kInstrData.td:202
    MOV32rb_TC                            = 1008, // M68kInstrData.td:212
    MOV32re                               = 1009, // M68kInstrData.td:202
    MOV32re_TC                            = 1010, // M68kInstrData.td:212
    MOV32rf                               = 1011, // M68kInstrData.td:202
    MOV32rf_TC                            = 1012, // M68kInstrData.td:212
    MOV32ri                               = 1013, // M68kInstrData.td:182
    MOV32rj                               = 1014, // M68kInstrData.td:202
    MOV32rj_TC                            = 1015, // M68kInstrData.td:212
    MOV32rk                               = 1016, // M68kInstrData.td:202
    MOV32rk_TC                            = 1017, // M68kInstrData.td:212
    MOV32ro                               = 1018, // M68kInstrData.td:202
    MOV32ro_TC                            = 1019, // M68kInstrData.td:212
    MOV32rp                               = 1020, // M68kInstrData.td:202
    MOV32rp_TC                            = 1021, // M68kInstrData.td:212
    MOV32rq                               = 1022, // M68kInstrData.td:202
    MOV32rq_TC                            = 1023, // M68kInstrData.td:212
    MOV32rr                               = 1024, // M68kInstrData.td:128
    MOV8bb                                = 1025, // M68kInstrData.td:240
    MOV8bd                                = 1026, // M68kInstrData.td:156
    MOV8be                                = 1027, // M68kInstrData.td:240
    MOV8bf                                = 1028, // M68kInstrData.td:240
    MOV8bi                                = 1029, // M68kInstrData.td:165
    MOV8bj                                = 1030, // M68kInstrData.td:240
    MOV8bk                                = 1031, // M68kInstrData.td:240
    MOV8bo                                = 1032, // M68kInstrData.td:240
    MOV8bp                                = 1033, // M68kInstrData.td:240
    MOV8bq                                = 1034, // M68kInstrData.td:240
    MOV8db                                = 1035, // M68kInstrData.td:202
    MOV8dd                                = 1036, // M68kInstrData.td:135
    MOV8de                                = 1037, // M68kInstrData.td:202
    MOV8df                                = 1038, // M68kInstrData.td:202
    MOV8di                                = 1039, // M68kInstrData.td:182
    MOV8dj                                = 1040, // M68kInstrData.td:202
    MOV8dk                                = 1041, // M68kInstrData.td:202
    MOV8do                                = 1042, // M68kInstrData.td:202
    MOV8dp                                = 1043, // M68kInstrData.td:202
    MOV8dq                                = 1044, // M68kInstrData.td:202
    MOV8eb                                = 1045, // M68kInstrData.td:240
    MOV8ed                                = 1046, // M68kInstrData.td:156
    MOV8ee                                = 1047, // M68kInstrData.td:240
    MOV8ef                                = 1048, // M68kInstrData.td:240
    MOV8ei                                = 1049, // M68kInstrData.td:165
    MOV8ej                                = 1050, // M68kInstrData.td:240
    MOV8ek                                = 1051, // M68kInstrData.td:240
    MOV8eo                                = 1052, // M68kInstrData.td:240
    MOV8ep                                = 1053, // M68kInstrData.td:240
    MOV8eq                                = 1054, // M68kInstrData.td:240
    MOV8fb                                = 1055, // M68kInstrData.td:240
    MOV8fd                                = 1056, // M68kInstrData.td:156
    MOV8fe                                = 1057, // M68kInstrData.td:240
    MOV8ff                                = 1058, // M68kInstrData.td:240
    MOV8fi                                = 1059, // M68kInstrData.td:165
    MOV8fj                                = 1060, // M68kInstrData.td:240
    MOV8fk                                = 1061, // M68kInstrData.td:240
    MOV8fo                                = 1062, // M68kInstrData.td:240
    MOV8fp                                = 1063, // M68kInstrData.td:240
    MOV8fq                                = 1064, // M68kInstrData.td:240
    MOV8jb                                = 1065, // M68kInstrData.td:240
    MOV8jd                                = 1066, // M68kInstrData.td:156
    MOV8je                                = 1067, // M68kInstrData.td:240
    MOV8jf                                = 1068, // M68kInstrData.td:240
    MOV8ji                                = 1069, // M68kInstrData.td:165
    MOV8jj                                = 1070, // M68kInstrData.td:240
    MOV8jk                                = 1071, // M68kInstrData.td:240
    MOV8jo                                = 1072, // M68kInstrData.td:240
    MOV8jp                                = 1073, // M68kInstrData.td:240
    MOV8jq                                = 1074, // M68kInstrData.td:240
    MOV8ob                                = 1075, // M68kInstrData.td:240
    MOV8od                                = 1076, // M68kInstrData.td:156
    MOV8oe                                = 1077, // M68kInstrData.td:240
    MOV8of                                = 1078, // M68kInstrData.td:240
    MOV8oi                                = 1079, // M68kInstrData.td:165
    MOV8oj                                = 1080, // M68kInstrData.td:240
    MOV8ok                                = 1081, // M68kInstrData.td:240
    MOV8oo                                = 1082, // M68kInstrData.td:240
    MOV8op                                = 1083, // M68kInstrData.td:240
    MOV8oq                                = 1084, // M68kInstrData.td:240
    MOV8pb                                = 1085, // M68kInstrData.td:240
    MOV8pd                                = 1086, // M68kInstrData.td:156
    MOV8pe                                = 1087, // M68kInstrData.td:240
    MOV8pf                                = 1088, // M68kInstrData.td:240
    MOV8pi                                = 1089, // M68kInstrData.td:165
    MOV8pj                                = 1090, // M68kInstrData.td:240
    MOV8pk                                = 1091, // M68kInstrData.td:240
    MOV8po                                = 1092, // M68kInstrData.td:240
    MOV8pp                                = 1093, // M68kInstrData.td:240
    MOV8pq                                = 1094, // M68kInstrData.td:240
    MOVM16bm                              = 1095, // M68kInstrData.td:337
    MOVM16em                              = 1096, // M68kInstrData.td:337
    MOVM16fm                              = 1097, // M68kInstrData.td:337
    MOVM16jm                              = 1098, // M68kInstrData.td:337
    MOVM16mb                              = 1099, // M68kInstrData.td:355
    MOVM16me                              = 1100, // M68kInstrData.td:355
    MOVM16mf                              = 1101, // M68kInstrData.td:355
    MOVM16mj                              = 1102, // M68kInstrData.td:355
    MOVM16mk                              = 1103, // M68kInstrData.td:355
    MOVM16mo                              = 1104, // M68kInstrData.td:355
    MOVM16mp                              = 1105, // M68kInstrData.td:355
    MOVM16mq                              = 1106, // M68kInstrData.td:355
    MOVM16om                              = 1107, // M68kInstrData.td:337
    MOVM16pm                              = 1108, // M68kInstrData.td:337
    MOVM32bm                              = 1109, // M68kInstrData.td:337
    MOVM32em                              = 1110, // M68kInstrData.td:337
    MOVM32fm                              = 1111, // M68kInstrData.td:337
    MOVM32jm                              = 1112, // M68kInstrData.td:337
    MOVM32mb                              = 1113, // M68kInstrData.td:355
    MOVM32me                              = 1114, // M68kInstrData.td:355
    MOVM32mf                              = 1115, // M68kInstrData.td:355
    MOVM32mj                              = 1116, // M68kInstrData.td:355
    MOVM32mk                              = 1117, // M68kInstrData.td:355
    MOVM32mo                              = 1118, // M68kInstrData.td:355
    MOVM32mp                              = 1119, // M68kInstrData.td:355
    MOVM32mq                              = 1120, // M68kInstrData.td:355
    MOVM32om                              = 1121, // M68kInstrData.td:337
    MOVM32pm                              = 1122, // M68kInstrData.td:337
    MOVQ                                  = 1123, // M68kInstrData.td:287
    NEG16d                                = 1124, // M68kInstrArithmetic.td:829
    NEG32d                                = 1125, // M68kInstrArithmetic.td:829
    NEG8d                                 = 1126, // M68kInstrArithmetic.td:829
    NEGX16d                               = 1127, // M68kInstrArithmetic.td:830
    NEGX32d                               = 1128, // M68kInstrArithmetic.td:830
    NEGX8d                                = 1129, // M68kInstrArithmetic.td:830
    NOP                                   = 1130, // M68kInstrControl.td:46
    NOT16d                                = 1131, // M68kInstrArithmetic.td:831
    NOT32d                                = 1132, // M68kInstrArithmetic.td:831
    NOT8d                                 = 1133, // M68kInstrArithmetic.td:831
    OR16dd                                = 1134, // M68kInstrArithmetic.td:265
    OR16df                                = 1135, // M68kInstrArithmetic.td:218
    OR16di                                = 1136, // M68kInstrArithmetic.td:230
    OR16dj                                = 1137, // M68kInstrArithmetic.td:224
    OR16dk                                = 1138, // M68kInstrArithmetic.td:200
    OR16dp                                = 1139, // M68kInstrArithmetic.td:212
    OR16dq                                = 1140, // M68kInstrArithmetic.td:206
    OR16dr                                = 1141, // M68kInstrArithmetic.td:272
    OR16fd                                = 1142, // M68kInstrArithmetic.td:239
    OR16fi                                = 1143, // M68kInstrArithmetic.td:254
    OR16jd                                = 1144, // M68kInstrArithmetic.td:244
    OR16ji                                = 1145, // M68kInstrArithmetic.td:259
    OR16pd                                = 1146, // M68kInstrArithmetic.td:234
    OR16pi                                = 1147, // M68kInstrArithmetic.td:249
    OR32dd                                = 1148, // M68kInstrArithmetic.td:265
    OR32df                                = 1149, // M68kInstrArithmetic.td:218
    OR32di                                = 1150, // M68kInstrArithmetic.td:230
    OR32dj                                = 1151, // M68kInstrArithmetic.td:224
    OR32dk                                = 1152, // M68kInstrArithmetic.td:200
    OR32dp                                = 1153, // M68kInstrArithmetic.td:212
    OR32dq                                = 1154, // M68kInstrArithmetic.td:206
    OR32dr                                = 1155, // M68kInstrArithmetic.td:272
    OR32fd                                = 1156, // M68kInstrArithmetic.td:239
    OR32fi                                = 1157, // M68kInstrArithmetic.td:254
    OR32jd                                = 1158, // M68kInstrArithmetic.td:244
    OR32ji                                = 1159, // M68kInstrArithmetic.td:259
    OR32pd                                = 1160, // M68kInstrArithmetic.td:234
    OR32pi                                = 1161, // M68kInstrArithmetic.td:249
    OR8dd                                 = 1162, // M68kInstrArithmetic.td:265
    OR8df                                 = 1163, // M68kInstrArithmetic.td:218
    OR8di                                 = 1164, // M68kInstrArithmetic.td:230
    OR8dj                                 = 1165, // M68kInstrArithmetic.td:224
    OR8dk                                 = 1166, // M68kInstrArithmetic.td:200
    OR8dp                                 = 1167, // M68kInstrArithmetic.td:212
    OR8dq                                 = 1168, // M68kInstrArithmetic.td:206
    OR8fd                                 = 1169, // M68kInstrArithmetic.td:239
    OR8fi                                 = 1170, // M68kInstrArithmetic.td:254
    OR8jd                                 = 1171, // M68kInstrArithmetic.td:244
    OR8ji                                 = 1172, // M68kInstrArithmetic.td:259
    OR8pd                                 = 1173, // M68kInstrArithmetic.td:234
    OR8pi                                 = 1174, // M68kInstrArithmetic.td:249
    ROL16dd                               = 1175, // M68kInstrShiftRotate.td:81
    ROL16di                               = 1176, // M68kInstrShiftRotate.td:85
    ROL32dd                               = 1177, // M68kInstrShiftRotate.td:82
    ROL32di                               = 1178, // M68kInstrShiftRotate.td:86
    ROL8dd                                = 1179, // M68kInstrShiftRotate.td:80
    ROL8di                                = 1180, // M68kInstrShiftRotate.td:84
    ROR16dd                               = 1181, // M68kInstrShiftRotate.td:81
    ROR16di                               = 1182, // M68kInstrShiftRotate.td:85
    ROR32dd                               = 1183, // M68kInstrShiftRotate.td:82
    ROR32di                               = 1184, // M68kInstrShiftRotate.td:86
    ROR8dd                                = 1185, // M68kInstrShiftRotate.td:80
    ROR8di                                = 1186, // M68kInstrShiftRotate.td:84
    RTE                                   = 1187, // M68kInstrControl.td:346
    RTS                                   = 1188, // M68kInstrControl.td:342
    SDIVd32d16                            = 1189, // M68kInstrArithmetic.td:627
    SDIVd32d32                            = 1190, // M68kInstrArithmetic.td:636
    SDIVd32i16                            = 1191, // M68kInstrArithmetic.td:630
    SETd8cc                               = 1192, // M68kInstrControl.td:117
    SETd8cs                               = 1193, // M68kInstrControl.td:117
    SETd8eq                               = 1194, // M68kInstrControl.td:117
    SETd8f                                = 1195, // M68kInstrControl.td:117
    SETd8ge                               = 1196, // M68kInstrControl.td:117
    SETd8gt                               = 1197, // M68kInstrControl.td:117
    SETd8hi                               = 1198, // M68kInstrControl.td:117
    SETd8le                               = 1199, // M68kInstrControl.td:117
    SETd8ls                               = 1200, // M68kInstrControl.td:117
    SETd8lt                               = 1201, // M68kInstrControl.td:117
    SETd8mi                               = 1202, // M68kInstrControl.td:117
    SETd8ne                               = 1203, // M68kInstrControl.td:117
    SETd8pl                               = 1204, // M68kInstrControl.td:117
    SETd8t                                = 1205, // M68kInstrControl.td:117
    SETd8vc                               = 1206, // M68kInstrControl.td:117
    SETd8vs                               = 1207, // M68kInstrControl.td:117
    SETj8cc                               = 1208, // M68kInstrControl.td:118
    SETj8cs                               = 1209, // M68kInstrControl.td:118
    SETj8eq                               = 1210, // M68kInstrControl.td:118
    SETj8f                                = 1211, // M68kInstrControl.td:118
    SETj8ge                               = 1212, // M68kInstrControl.td:118
    SETj8gt                               = 1213, // M68kInstrControl.td:118
    SETj8hi                               = 1214, // M68kInstrControl.td:118
    SETj8le                               = 1215, // M68kInstrControl.td:118
    SETj8ls                               = 1216, // M68kInstrControl.td:118
    SETj8lt                               = 1217, // M68kInstrControl.td:118
    SETj8mi                               = 1218, // M68kInstrControl.td:118
    SETj8ne                               = 1219, // M68kInstrControl.td:118
    SETj8pl                               = 1220, // M68kInstrControl.td:118
    SETj8t                                = 1221, // M68kInstrControl.td:118
    SETj8vc                               = 1222, // M68kInstrControl.td:118
    SETj8vs                               = 1223, // M68kInstrControl.td:118
    SETp8cc                               = 1224, // M68kInstrControl.td:119
    SETp8cs                               = 1225, // M68kInstrControl.td:119
    SETp8eq                               = 1226, // M68kInstrControl.td:119
    SETp8f                                = 1227, // M68kInstrControl.td:119
    SETp8ge                               = 1228, // M68kInstrControl.td:119
    SETp8gt                               = 1229, // M68kInstrControl.td:119
    SETp8hi                               = 1230, // M68kInstrControl.td:119
    SETp8le                               = 1231, // M68kInstrControl.td:119
    SETp8ls                               = 1232, // M68kInstrControl.td:119
    SETp8lt                               = 1233, // M68kInstrControl.td:119
    SETp8mi                               = 1234, // M68kInstrControl.td:119
    SETp8ne                               = 1235, // M68kInstrControl.td:119
    SETp8pl                               = 1236, // M68kInstrControl.td:119
    SETp8t                                = 1237, // M68kInstrControl.td:119
    SETp8vc                               = 1238, // M68kInstrControl.td:119
    SETp8vs                               = 1239, // M68kInstrControl.td:119
    SHL16dd                               = 1240, // M68kInstrShiftRotate.td:81
    SHL16di                               = 1241, // M68kInstrShiftRotate.td:85
    SHL32dd                               = 1242, // M68kInstrShiftRotate.td:82
    SHL32di                               = 1243, // M68kInstrShiftRotate.td:86
    SHL8dd                                = 1244, // M68kInstrShiftRotate.td:80
    SHL8di                                = 1245, // M68kInstrShiftRotate.td:84
    SMULd32d16                            = 1246, // M68kInstrArithmetic.td:627
    SMULd32d32                            = 1247, // M68kInstrArithmetic.td:732
    SMULd32i16                            = 1248, // M68kInstrArithmetic.td:630
    SUB16dd                               = 1249, // M68kInstrArithmetic.td:265
    SUB16df                               = 1250, // M68kInstrArithmetic.td:218
    SUB16di                               = 1251, // M68kInstrArithmetic.td:230
    SUB16dj                               = 1252, // M68kInstrArithmetic.td:224
    SUB16dk                               = 1253, // M68kInstrArithmetic.td:200
    SUB16dp                               = 1254, // M68kInstrArithmetic.td:212
    SUB16dq                               = 1255, // M68kInstrArithmetic.td:206
    SUB16dr                               = 1256, // M68kInstrArithmetic.td:272
    SUB16fd                               = 1257, // M68kInstrArithmetic.td:239
    SUB16fi                               = 1258, // M68kInstrArithmetic.td:254
    SUB16jd                               = 1259, // M68kInstrArithmetic.td:244
    SUB16ji                               = 1260, // M68kInstrArithmetic.td:259
    SUB16pd                               = 1261, // M68kInstrArithmetic.td:234
    SUB16pi                               = 1262, // M68kInstrArithmetic.td:249
    SUB32ab                               = 1263, // M68kInstrArithmetic.td:296
    SUB32af                               = 1264, // M68kInstrArithmetic.td:290
    SUB32ai                               = 1265, // M68kInstrArithmetic.td:298
    SUB32aj                               = 1266, // M68kInstrArithmetic.td:294
    SUB32ak                               = 1267, // M68kInstrArithmetic.td:286
    SUB32ap                               = 1268, // M68kInstrArithmetic.td:292
    SUB32aq                               = 1269, // M68kInstrArithmetic.td:288
    SUB32ar                               = 1270, // M68kInstrArithmetic.td:300
    SUB32dd                               = 1271, // M68kInstrArithmetic.td:265
    SUB32df                               = 1272, // M68kInstrArithmetic.td:218
    SUB32di                               = 1273, // M68kInstrArithmetic.td:230
    SUB32dj                               = 1274, // M68kInstrArithmetic.td:224
    SUB32dk                               = 1275, // M68kInstrArithmetic.td:200
    SUB32dp                               = 1276, // M68kInstrArithmetic.td:212
    SUB32dq                               = 1277, // M68kInstrArithmetic.td:206
    SUB32dr                               = 1278, // M68kInstrArithmetic.td:272
    SUB32fd                               = 1279, // M68kInstrArithmetic.td:239
    SUB32fi                               = 1280, // M68kInstrArithmetic.td:254
    SUB32jd                               = 1281, // M68kInstrArithmetic.td:244
    SUB32ji                               = 1282, // M68kInstrArithmetic.td:259
    SUB32pd                               = 1283, // M68kInstrArithmetic.td:234
    SUB32pi                               = 1284, // M68kInstrArithmetic.td:249
    SUB8dd                                = 1285, // M68kInstrArithmetic.td:265
    SUB8df                                = 1286, // M68kInstrArithmetic.td:218
    SUB8di                                = 1287, // M68kInstrArithmetic.td:230
    SUB8dj                                = 1288, // M68kInstrArithmetic.td:224
    SUB8dk                                = 1289, // M68kInstrArithmetic.td:200
    SUB8dp                                = 1290, // M68kInstrArithmetic.td:212
    SUB8dq                                = 1291, // M68kInstrArithmetic.td:206
    SUB8fd                                = 1292, // M68kInstrArithmetic.td:239
    SUB8fi                                = 1293, // M68kInstrArithmetic.td:254
    SUB8jd                                = 1294, // M68kInstrArithmetic.td:244
    SUB8ji                                = 1295, // M68kInstrArithmetic.td:259
    SUB8pd                                = 1296, // M68kInstrArithmetic.td:234
    SUB8pi                                = 1297, // M68kInstrArithmetic.td:249
    SUBX16dd                              = 1298, // M68kInstrArithmetic.td:360
    SUBX32dd                              = 1299, // M68kInstrArithmetic.td:360
    SUBX8dd                               = 1300, // M68kInstrArithmetic.td:360
    TRAP                                  = 1301, // M68kInstrControl.td:425
    TRAPV                                 = 1302, // M68kInstrControl.td:429
    UDIVd32d16                            = 1303, // M68kInstrArithmetic.td:628
    UDIVd32d32                            = 1304, // M68kInstrArithmetic.td:637
    UDIVd32i16                            = 1305, // M68kInstrArithmetic.td:631
    UMULd32d16                            = 1306, // M68kInstrArithmetic.td:628
    UMULd32d32                            = 1307, // M68kInstrArithmetic.td:733
    UMULd32i16                            = 1308, // M68kInstrArithmetic.td:631
    UNLK                                  = 1309, // M68kInstrData.td:562
    XOR16dd                               = 1310, // M68kInstrArithmetic.td:380
    XOR16di                               = 1311, // M68kInstrArithmetic.td:384
    XOR32dd                               = 1312, // M68kInstrArithmetic.td:380
    XOR32di                               = 1313, // M68kInstrArithmetic.td:384
    XOR8dd                                = 1314, // M68kInstrArithmetic.td:380
    XOR8di                                = 1315, // M68kInstrArithmetic.td:384
    INSTRUCTION_LIST_END = 1316
  };

} // namespace llvm_ks::M68k

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::M68k::Sched {

  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };

} // namespace llvm_ks::M68k::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct M68kInstrTable {
  MCInstrDesc Insts[1316];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[13];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[809];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof M68kInstrTable::ImplicitOps + sizeof M68kInstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned M68kOpInfoBase = (sizeof M68kInstrTable::ImplicitOps + sizeof M68kInstrTable::Padding) / sizeof(MCOperandInfo);

extern const M68kInstrTable M68kDescs = {
  {
    { 1315,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 374,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8di
    { 1314,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 366,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR8dd
    { 1313,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR32di
    { 1312,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR32dd
    { 1311,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 263,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16di
    { 1310,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 255,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR16dd
    { 1309,	1,	0,	0,	0,	1,	1,	M68kOpInfoBase + 808,	4,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UNLK
    { 1308,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UMULd32i16
    { 1307,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UMULd32d32
    { 1306,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 805,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UMULd32d16
    { 1305,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UDIVd32i16
    { 1304,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UDIVd32d32
    { 1303,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 805,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UDIVd32d16
    { 1302,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRAPV
    { 1301,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRAP
    { 1300,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 366,	6,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBX8dd
    { 1299,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 329,	6,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBX32dd
    { 1298,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 255,	6,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBX16dd
    { 1297,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8pi
    { 1296,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 397,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8pd
    { 1295,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8ji
    { 1294,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8jd
    { 1293,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8fi
    { 1292,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 391,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8fd
    { 1291,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 388,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8dq
    { 1290,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 384,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8dp
    { 1289,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 380,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8dk
    { 1288,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 377,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8dj
    { 1287,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 374,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8di
    { 1286,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 369,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8df
    { 1285,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 366,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB8dd
    { 1284,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32pi
    { 1283,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 363,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32pd
    { 1282,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32ji
    { 1281,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 361,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32jd
    { 1280,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32fi
    { 1279,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 357,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32fd
    { 1278,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 354,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32dr
    { 1277,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 351,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32dq
    { 1276,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 347,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32dp
    { 1275,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 343,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32dk
    { 1274,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 340,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32dj
    { 1273,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32di
    { 1272,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 332,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32df
    { 1271,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32dd
    { 1270,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 326,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32ar
    { 1269,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 323,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32aq
    { 1268,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 319,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32ap
    { 1267,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 315,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32ak
    { 1266,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 312,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32aj
    { 1265,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 309,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32ai
    { 1264,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 304,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32af
    { 1263,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 301,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB32ab
    { 1262,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16pi
    { 1261,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 295,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16pd
    { 1260,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16ji
    { 1259,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 291,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16jd
    { 1258,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16fi
    { 1257,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 283,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16fd
    { 1256,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 280,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16dr
    { 1255,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 277,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16dq
    { 1254,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 273,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16dp
    { 1253,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 269,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16dk
    { 1252,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 266,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16dj
    { 1251,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 263,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16di
    { 1250,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 258,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16df
    { 1249,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 255,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB16dd
    { 1248,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SMULd32i16
    { 1247,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SMULd32d32
    { 1246,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 805,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SMULd32d16
    { 1245,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 374,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL8di
    { 1244,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 366,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL8dd
    { 1243,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL32di
    { 1242,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL32dd
    { 1241,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 263,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL16di
    { 1240,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 255,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL16dd
    { 1239,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8vs
    { 1238,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8vc
    { 1237,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8t
    { 1236,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8pl
    { 1235,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8ne
    { 1234,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8mi
    { 1233,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8lt
    { 1232,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8ls
    { 1231,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8le
    { 1230,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8hi
    { 1229,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8gt
    { 1228,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8ge
    { 1227,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8f
    { 1226,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8eq
    { 1225,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8cs
    { 1224,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETp8cc
    { 1223,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8vs
    { 1222,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8vc
    { 1221,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8t
    { 1220,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8pl
    { 1219,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8ne
    { 1218,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8mi
    { 1217,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8lt
    { 1216,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8ls
    { 1215,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8le
    { 1214,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8hi
    { 1213,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8gt
    { 1212,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8ge
    { 1211,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8f
    { 1210,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8eq
    { 1209,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8cs
    { 1208,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETj8cc
    { 1207,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8vs
    { 1206,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8vc
    { 1205,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8t
    { 1204,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8pl
    { 1203,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8ne
    { 1202,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8mi
    { 1201,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8lt
    { 1200,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8ls
    { 1199,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8le
    { 1198,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8hi
    { 1197,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8gt
    { 1196,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8ge
    { 1195,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8f
    { 1194,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8eq
    { 1193,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8cs
    { 1192,	1,	1,	0,	0,	1,	0,	M68kOpInfoBase + 246,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETd8cc
    { 1191,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SDIVd32i16
    { 1190,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SDIVd32d32
    { 1189,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 805,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SDIVd32d16
    { 1188,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RTS
    { 1187,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RTE
    { 1186,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 374,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROR8di
    { 1185,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 366,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROR8dd
    { 1184,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROR32di
    { 1183,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROR32dd
    { 1182,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 263,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROR16di
    { 1181,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 255,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROR16dd
    { 1180,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 374,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROL8di
    { 1179,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 366,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROL8dd
    { 1178,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROL32di
    { 1177,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROL32dd
    { 1176,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 263,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROL16di
    { 1175,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 255,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROL16dd
    { 1174,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8pi
    { 1173,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 397,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8pd
    { 1172,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8ji
    { 1171,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8jd
    { 1170,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8fi
    { 1169,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 391,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8fd
    { 1168,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 388,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8dq
    { 1167,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 384,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8dp
    { 1166,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 380,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8dk
    { 1165,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 377,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8dj
    { 1164,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 374,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8di
    { 1163,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 369,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8df
    { 1162,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 366,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR8dd
    { 1161,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32pi
    { 1160,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 363,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32pd
    { 1159,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32ji
    { 1158,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 361,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32jd
    { 1157,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32fi
    { 1156,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 357,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32fd
    { 1155,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 354,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32dr
    { 1154,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 351,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32dq
    { 1153,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 347,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32dp
    { 1152,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 343,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32dk
    { 1151,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 340,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32dj
    { 1150,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32di
    { 1149,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 332,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32df
    { 1148,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR32dd
    { 1147,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16pi
    { 1146,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 295,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16pd
    { 1145,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16ji
    { 1144,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 291,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16jd
    { 1143,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16fi
    { 1142,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 283,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16fd
    { 1141,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 280,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16dr
    { 1140,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 277,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16dq
    { 1139,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 273,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16dp
    { 1138,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 269,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16dk
    { 1137,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 266,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16dj
    { 1136,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 263,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16di
    { 1135,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 258,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16df
    { 1134,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 255,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR16dd
    { 1133,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 803,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOT8d
    { 1132,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 531,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOT32d
    { 1131,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 529,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOT16d
    { 1130,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOP
    { 1129,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 803,	6,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEGX8d
    { 1128,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 531,	6,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEGX32d
    { 1127,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 529,	6,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEGX16d
    { 1126,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 803,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG8d
    { 1125,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 531,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG32d
    { 1124,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 529,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG16d
    { 1123,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 402,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVQ
    { 1122,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 298,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32pm
    { 1121,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 293,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32om
    { 1120,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 502,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32mq
    { 1119,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 499,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32mp
    { 1118,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 494,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32mo
    { 1117,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32mk
    { 1116,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 494,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32mj
    { 1115,	4,	0,	0,	0,	0,	0,	M68kOpInfoBase + 490,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32mf
    { 1114,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 494,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32me
    { 1113,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 481,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32mb
    { 1112,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 293,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32jm
    { 1111,	4,	0,	0,	0,	0,	0,	M68kOpInfoBase + 287,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32fm
    { 1110,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 293,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32em
    { 1109,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 610,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32bm
    { 1108,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 298,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16pm
    { 1107,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 293,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16om
    { 1106,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 502,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16mq
    { 1105,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 499,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16mp
    { 1104,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 494,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16mo
    { 1103,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 496,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16mk
    { 1102,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 494,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16mj
    { 1101,	4,	0,	0,	0,	0,	0,	M68kOpInfoBase + 490,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16mf
    { 1100,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 494,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16me
    { 1099,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 481,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16mb
    { 1098,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 293,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16jm
    { 1097,	4,	0,	0,	0,	0,	0,	M68kOpInfoBase + 287,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16fm
    { 1096,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 293,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16em
    { 1095,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 610,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16bm
    { 1094,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 718,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8pq
    { 1093,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 714,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8pp
    { 1092,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 702,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8po
    { 1091,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 710,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8pk
    { 1090,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 702,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8pj
    { 1089,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8pi
    { 1088,	5,	0,	0,	0,	0,	1,	M68kOpInfoBase + 705,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8pf
    { 1087,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 702,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8pe
    { 1086,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 397,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8pd
    { 1085,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 699,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8pb
    { 1084,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 652,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8oq
    { 1083,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 649,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8op
    { 1082,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8oo
    { 1081,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 646,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ok
    { 1080,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8oj
    { 1079,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8oi
    { 1078,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 642,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8of
    { 1077,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8oe
    { 1076,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8od
    { 1075,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 638,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ob
    { 1074,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 652,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8jq
    { 1073,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 649,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8jp
    { 1072,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8jo
    { 1071,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 646,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8jk
    { 1070,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8jj
    { 1069,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ji
    { 1068,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 642,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8jf
    { 1067,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8je
    { 1066,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8jd
    { 1065,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 638,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8jb
    { 1064,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 684,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8fq
    { 1063,	5,	0,	0,	0,	0,	1,	M68kOpInfoBase + 679,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8fp
    { 1062,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 664,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8fo
    { 1061,	5,	0,	0,	0,	0,	1,	M68kOpInfoBase + 674,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8fk
    { 1060,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 664,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8fj
    { 1059,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8fi
    { 1058,	6,	0,	0,	0,	0,	1,	M68kOpInfoBase + 668,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ff
    { 1057,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 664,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8fe
    { 1056,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 391,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8fd
    { 1055,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 660,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8fb
    { 1054,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 652,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8eq
    { 1053,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 649,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ep
    { 1052,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8eo
    { 1051,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 646,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ek
    { 1050,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ej
    { 1049,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ei
    { 1048,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 642,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ef
    { 1047,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ee
    { 1046,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ed
    { 1045,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 638,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8eb
    { 1044,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 527,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8dq
    { 1043,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 524,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8dp
    { 1042,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 519,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8do
    { 1041,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 521,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8dk
    { 1040,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 519,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8dj
    { 1039,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 194,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8di
    { 1038,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 513,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8df
    { 1037,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 519,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8de
    { 1036,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 511,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8dd
    { 1035,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 801,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8db
    { 1034,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 618,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8bq
    { 1033,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 615,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8bp
    { 1032,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8bo
    { 1031,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 612,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8bk
    { 1030,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8bj
    { 1029,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 610,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8bi
    { 1028,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 606,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8bf
    { 1027,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8be
    { 1026,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 799,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8bd
    { 1025,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 602,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8bb
    { 1024,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 797,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rr
    { 1023,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 795,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rq_TC
    { 1022,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 795,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rq
    { 1021,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 210,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rp_TC
    { 1020,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 210,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rp
    { 1019,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ro_TC
    { 1018,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ro
    { 1017,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 792,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rk_TC
    { 1016,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 792,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rk
    { 1015,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rj_TC
    { 1014,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rj
    { 1013,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 192,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ri
    { 1012,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 788,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rf_TC
    { 1011,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 788,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rf
    { 1010,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32re_TC
    { 1009,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32re
    { 1008,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 786,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rb_TC
    { 1007,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 786,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32rb
    { 1006,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 784,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ra
    { 1005,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 213,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pr
    { 1004,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 718,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pq
    { 1003,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 714,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pp
    { 1002,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 702,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32po
    { 1001,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 710,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pk
    { 1000,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 702,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pj
    { 999,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pi
    { 998,	5,	0,	0,	0,	0,	1,	M68kOpInfoBase + 705,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pf
    { 997,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 702,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pe
    { 996,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 363,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pd
    { 995,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 699,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pb
    { 994,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 781,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32pa
    { 993,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 206,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32or
    { 992,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 652,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32oq
    { 991,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 649,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32op
    { 990,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32oo
    { 989,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 646,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ok
    { 988,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32oj
    { 987,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32oi
    { 986,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 642,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32of
    { 985,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32oe
    { 984,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 361,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32od
    { 983,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 638,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ob
    { 982,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 771,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32oa
    { 981,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 206,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32jr
    { 980,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 652,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32jq
    { 979,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 649,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32jp
    { 978,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32jo
    { 977,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 646,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32jk
    { 976,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32jj
    { 975,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ji
    { 974,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 642,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32jf
    { 973,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32je
    { 972,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 361,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32jd
    { 971,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 638,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32jb
    { 970,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 771,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ja
    { 969,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 777,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fr
    { 968,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 684,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fq
    { 967,	5,	0,	0,	0,	0,	1,	M68kOpInfoBase + 679,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fp
    { 966,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 664,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fo
    { 965,	5,	0,	0,	0,	0,	1,	M68kOpInfoBase + 674,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fk
    { 964,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 664,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fj
    { 963,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fi
    { 962,	6,	0,	0,	0,	0,	1,	M68kOpInfoBase + 668,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ff
    { 961,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 664,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fe
    { 960,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 357,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fd
    { 959,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 660,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fb
    { 958,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 773,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32fa
    { 957,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 206,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32er
    { 956,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 652,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32eq
    { 955,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 649,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ep
    { 954,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32eo
    { 953,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 646,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ek
    { 952,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ej
    { 951,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ei
    { 950,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 642,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ef
    { 949,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ee
    { 948,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 361,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ed
    { 947,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 638,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32eb
    { 946,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 771,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ea
    { 945,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 242,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32dq
    { 944,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32dp
    { 943,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 237,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32do
    { 942,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32dk
    { 941,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 237,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32dj
    { 940,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 402,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32di
    { 939,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32df
    { 938,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 237,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32de
    { 937,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 400,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32dd
    { 936,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 769,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32db
    { 935,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 767,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32br
    { 934,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 618,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32bq
    { 933,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 615,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32bp
    { 932,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32bo
    { 931,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 612,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32bk
    { 930,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32bj
    { 929,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 610,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32bi
    { 928,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 606,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32bf
    { 927,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32be
    { 926,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 765,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32bd
    { 925,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 602,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32bb
    { 924,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 763,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ba
    { 923,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 761,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ar
    { 922,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 576,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32aq_TC
    { 921,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 576,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32aq
    { 920,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 573,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ap_TC
    { 919,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 573,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ap
    { 918,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 757,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ao_TC
    { 917,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 757,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ao
    { 916,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 566,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ak_TC
    { 915,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 566,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ak
    { 914,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 757,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32aj_TC
    { 913,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 757,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32aj
    { 912,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 759,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ai
    { 911,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 562,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32af_TC
    { 910,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 562,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32af
    { 909,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 757,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ae_TC
    { 908,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 757,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ae
    { 907,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 560,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ab_TC
    { 906,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 560,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32ab
    { 905,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 247,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV32aa
    { 904,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 755,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16sq
    { 903,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 752,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16sp
    { 902,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 743,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16so
    { 901,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 749,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16sk
    { 900,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 743,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16sj
    { 899,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 745,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16sf
    { 898,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 743,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16se
    { 897,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 741,	12,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16sd
    { 896,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 739,	12,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16sb
    { 895,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 737,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rr
    { 894,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 735,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rq_TC
    { 893,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 735,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rq
    { 892,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rp_TC
    { 891,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rp
    { 890,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 198,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ro_TC
    { 889,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 198,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ro
    { 888,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 732,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rk_TC
    { 887,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 732,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rk
    { 886,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 198,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rj_TC
    { 885,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 198,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rj
    { 884,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 190,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ri
    { 883,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 728,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rf_TC
    { 882,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 728,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rf
    { 881,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 198,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16re_TC
    { 880,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 198,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16re
    { 879,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 726,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rb_TC
    { 878,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 726,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16rb
    { 877,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 724,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ra
    { 876,	3,	0,	0,	0,	1,	0,	M68kOpInfoBase + 721,	12,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ps
    { 875,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 203,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pr
    { 874,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 718,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pq
    { 873,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 714,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pp
    { 872,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 702,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16po
    { 871,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 710,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pk
    { 870,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 702,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pj
    { 869,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pi
    { 868,	5,	0,	0,	0,	0,	1,	M68kOpInfoBase + 705,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pf
    { 867,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 702,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pe
    { 866,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 295,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pd
    { 865,	3,	0,	0,	0,	1,	0,	M68kOpInfoBase + 187,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pc
    { 864,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 699,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pb
    { 863,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 696,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16pa
    { 862,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 654,	12,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16os
    { 861,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 196,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16or
    { 860,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 652,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16oq
    { 859,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 649,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16op
    { 858,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16oo
    { 857,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 646,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ok
    { 856,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16oj
    { 855,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16oi
    { 854,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 642,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16of
    { 853,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16oe
    { 852,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 291,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16od
    { 851,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 181,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16oc
    { 850,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 638,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ob
    { 849,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 636,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16oa
    { 848,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 654,	12,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16js
    { 847,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 196,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16jr
    { 846,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 652,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16jq
    { 845,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 649,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16jp
    { 844,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16jo
    { 843,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 646,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16jk
    { 842,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16jj
    { 841,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ji
    { 840,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 642,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16jf
    { 839,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16je
    { 838,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 291,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16jd
    { 837,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 181,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16jc
    { 836,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 638,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16jb
    { 835,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 636,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ja
    { 834,	4,	0,	0,	0,	1,	0,	M68kOpInfoBase + 692,	12,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fs
    { 833,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 688,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fr
    { 832,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 684,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fq
    { 831,	5,	0,	0,	0,	0,	1,	M68kOpInfoBase + 679,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fp
    { 830,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 664,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fo
    { 829,	5,	0,	0,	0,	0,	1,	M68kOpInfoBase + 674,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fk
    { 828,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 664,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fj
    { 827,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fi
    { 826,	6,	0,	0,	0,	0,	1,	M68kOpInfoBase + 668,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ff
    { 825,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 664,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fe
    { 824,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 283,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fd
    { 823,	4,	0,	0,	0,	1,	0,	M68kOpInfoBase + 183,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fc
    { 822,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 660,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fb
    { 821,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 656,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16fa
    { 820,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 654,	12,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16es
    { 819,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 196,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16er
    { 818,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 652,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16eq
    { 817,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 649,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ep
    { 816,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16eo
    { 815,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 646,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ek
    { 814,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ej
    { 813,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ei
    { 812,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 642,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ef
    { 811,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 640,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ee
    { 810,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 291,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ed
    { 809,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 181,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ec
    { 808,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 638,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16eb
    { 807,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 636,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ea
    { 806,	2,	1,	0,	0,	1,	0,	M68kOpInfoBase + 634,	12,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ds
    { 805,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16dq
    { 804,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 224,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16dp
    { 803,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 222,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16do
    { 802,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 485,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16dk
    { 801,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 222,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16dj
    { 800,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 632,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16di
    { 799,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 218,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16df
    { 798,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 222,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16de
    { 797,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 630,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16dd
    { 796,	2,	1,	0,	0,	1,	0,	M68kOpInfoBase + 628,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16dc
    { 795,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 626,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16db
    { 794,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 179,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16cq
    { 793,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 176,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16cp
    { 792,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 167,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16co
    { 791,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 173,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ck
    { 790,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 167,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16cj
    { 789,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 169,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16cf
    { 788,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 167,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ce
    { 787,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 624,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16cd
    { 786,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 165,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16cb
    { 785,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 622,	12,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bs
    { 784,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 620,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16br
    { 783,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 618,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bq
    { 782,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 615,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bp
    { 781,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bo
    { 780,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 612,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bk
    { 779,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bj
    { 778,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 610,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bi
    { 777,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 606,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bf
    { 776,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 422,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16be
    { 775,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 604,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bd
    { 774,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 163,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bc
    { 773,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 602,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16bb
    { 772,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 600,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ba
    { 771,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 598,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ar
    { 770,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 596,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16aq_TC
    { 769,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 596,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16aq
    { 768,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 593,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ap_TC
    { 767,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 593,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ap
    { 766,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 584,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ao_TC
    { 765,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 584,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ao
    { 764,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 590,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ak_TC
    { 763,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 590,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ak
    { 762,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 584,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16aj_TC
    { 761,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 584,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16aj
    { 760,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 578,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ai
    { 759,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 586,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16af_TC
    { 758,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 586,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16af
    { 757,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 584,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ae_TC
    { 756,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 584,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ae
    { 755,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 582,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ab_TC
    { 754,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 582,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16ab
    { 753,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 580,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV16aa
    { 752,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 374,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSR8di
    { 751,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 366,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSR8dd
    { 750,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSR32di
    { 749,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSR32dd
    { 748,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 263,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSR16di
    { 747,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 255,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSR16dd
    { 746,	2,	0,	0,	0,	1,	1,	M68kOpInfoBase + 578,	4,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LINK32
    { 745,	2,	0,	0,	0,	1,	1,	M68kOpInfoBase + 578,	4,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LINK16
    { 744,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 576,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LEA32q
    { 743,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 573,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LEA32p
    { 742,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 569,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LEA32l
    { 741,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 566,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LEA32k
    { 740,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 562,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LEA32f
    { 739,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 560,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LEA32b
    { 738,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 556,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LEA32L
    { 737,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 416,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // JMP32j
    { 736,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ILLEGAL
    { 735,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 545,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSUB80fp_fp
    { 734,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 542,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSUB64fp_fp
    { 733,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 539,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSUB32fp_fp
    { 732,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 545,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSSUB80fp_fp
    { 731,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 542,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSSUB64fp_fp
    { 730,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 539,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSSUB32fp_fp
    { 729,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 537,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSNEG80fp_fp
    { 728,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 535,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSNEG64fp_fp
    { 727,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 533,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSNEG32fp_fp
    { 726,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 545,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSMUL80fp_fp
    { 725,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 542,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSMUL64fp_fp
    { 724,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 539,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSMUL32fp_fp
    { 723,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 537,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSMOV80fp_fp
    { 722,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 535,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSMOV64fp_fp
    { 721,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 533,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSMOV32fp_fp
    { 720,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 545,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSDIV80fp_fp
    { 719,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 542,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSDIV64fp_fp
    { 718,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 539,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSDIV32fp_fp
    { 717,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 545,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSADD80fp_fp
    { 716,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 542,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSADD64fp_fp
    { 715,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 539,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSADD32fp_fp
    { 714,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 537,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSABS80fp_fp
    { 713,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 535,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSABS64fp_fp
    { 712,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 533,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FSABS32fp_fp
    { 711,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 537,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FNEG80fp_fp
    { 710,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 535,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FNEG64fp_fp
    { 709,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 533,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FNEG32fp_fp
    { 708,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 545,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMUL80fp_fp
    { 707,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 542,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMUL64fp_fp
    { 706,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 539,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMUL32fp_fp
    { 705,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 554,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMOVE32fpi_a
    { 704,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 552,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMOVE32fpcs_d
    { 703,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 550,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMOVE32d_fpcs
    { 702,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 548,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMOVE32a_fpi
    { 701,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 537,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMOV80fp_fp
    { 700,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 535,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMOV64fp_fp
    { 699,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 533,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMOV32fp_fp
    { 698,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 545,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDSUB80fp_fp
    { 697,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 542,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDSUB64fp_fp
    { 696,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 539,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDSUB32fp_fp
    { 695,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 537,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDNEG80fp_fp
    { 694,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 535,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDNEG64fp_fp
    { 693,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 533,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDNEG32fp_fp
    { 692,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 545,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDMUL80fp_fp
    { 691,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 542,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDMUL64fp_fp
    { 690,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 539,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDMUL32fp_fp
    { 689,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 537,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDMOV80fp_fp
    { 688,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 535,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDMOV64fp_fp
    { 687,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 533,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDMOV32fp_fp
    { 686,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 545,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDIV80fp_fp
    { 685,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 542,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDIV64fp_fp
    { 684,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 539,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDIV32fp_fp
    { 683,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 545,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDDIV80fp_fp
    { 682,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 542,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDDIV64fp_fp
    { 681,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 539,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDDIV32fp_fp
    { 680,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 545,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDADD80fp_fp
    { 679,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 542,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDADD64fp_fp
    { 678,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 539,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDADD32fp_fp
    { 677,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 537,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDABS80fp_fp
    { 676,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 535,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDABS64fp_fp
    { 675,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 533,	11,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FDABS32fp_fp
    { 674,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 545,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FADD80fp_fp
    { 673,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 542,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FADD64fp_fp
    { 672,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 539,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FADD32fp_fp
    { 671,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 537,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FABS80fp_fp
    { 670,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 535,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FABS64fp_fp
    { 669,	2,	1,	0,	0,	1,	1,	M68kOpInfoBase + 533,	9,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FABS32fp_fp
    { 668,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 531,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXT32
    { 667,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 529,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXT16
    { 666,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 502,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8qi
    { 665,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 499,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8pi
    { 664,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 496,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8ki
    { 663,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 494,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8ji
    { 662,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 490,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8fi
    { 661,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 527,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8dq
    { 660,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 524,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8dp
    { 659,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 521,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8dk
    { 658,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 519,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8dj
    { 657,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 517,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8di
    { 656,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 513,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8df
    { 655,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 511,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8dd
    { 654,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 481,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP8bi
    { 653,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 502,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32qi
    { 652,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 499,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32pi
    { 651,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 496,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32ki
    { 650,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 494,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32ji
    { 649,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 490,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32fi
    { 648,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 509,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32dr
    { 647,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 242,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32dq
    { 646,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32dp
    { 645,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32dk
    { 644,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 237,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32dj
    { 643,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 504,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32di
    { 642,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32df
    { 641,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 481,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP32bi
    { 640,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 502,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16qi
    { 639,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 499,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16pi
    { 638,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 496,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16ki
    { 637,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 494,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16ji
    { 636,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 490,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16fi
    { 635,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 488,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16dr
    { 634,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16dq
    { 633,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 224,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16dp
    { 632,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 485,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16dk
    { 631,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 222,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16dj
    { 630,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 483,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16di
    { 629,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 218,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16df
    { 628,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 481,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMP16bi
    { 627,	6,	1,	0,	0,	0,	0,	M68kOpInfoBase + 475,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASARII8
    { 626,	6,	1,	0,	0,	0,	0,	M68kOpInfoBase + 469,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASARII32
    { 625,	6,	1,	0,	0,	0,	0,	M68kOpInfoBase + 463,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASARII16
    { 624,	5,	1,	0,	0,	0,	0,	M68kOpInfoBase + 458,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASARID8
    { 623,	5,	1,	0,	0,	0,	0,	M68kOpInfoBase + 453,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASARID32
    { 622,	5,	1,	0,	0,	0,	0,	M68kOpInfoBase + 448,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASARID16
    { 621,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 444,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASARI8
    { 620,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 440,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASARI32
    { 619,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 436,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASARI16
    { 618,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 432,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASAL8
    { 617,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 428,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASAL32
    { 616,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 424,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CASAL16
    { 615,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLq
    { 614,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 422,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLp
    { 613,	3,	0,	0,	0,	1,	0,	M68kOpInfoBase + 419,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLl
    { 612,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 417,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLk
    { 611,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 416,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLj
    { 610,	3,	0,	0,	0,	1,	0,	M68kOpInfoBase + 413,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLf
    { 609,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 412,	8,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLb
    { 608,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bvs8
    { 607,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bvs32
    { 606,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bvs16
    { 605,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bvc8
    { 604,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bvc32
    { 603,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bvc16
    { 602,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bpl8
    { 601,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bpl32
    { 600,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bpl16
    { 599,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bne8
    { 598,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bne32
    { 597,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bne16
    { 596,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bmi8
    { 595,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bmi32
    { 594,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bmi16
    { 593,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Blt8
    { 592,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Blt32
    { 591,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Blt16
    { 590,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bls8
    { 589,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bls32
    { 588,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bls16
    { 587,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Ble8
    { 586,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Ble32
    { 585,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Ble16
    { 584,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bhi8
    { 583,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bhi32
    { 582,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bhi16
    { 581,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bgt8
    { 580,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bgt32
    { 579,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bgt16
    { 578,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bge8
    { 577,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bge32
    { 576,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bge16
    { 575,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Beq8
    { 574,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Beq32
    { 573,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Beq16
    { 572,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bcs8
    { 571,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bcs32
    { 570,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bcs16
    { 569,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bcc8
    { 568,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bcc32
    { 567,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Bcc16
    { 566,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 253,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8qi
    { 565,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 410,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8qd
    { 564,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8pi
    { 563,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 397,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8pd
    { 562,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8oi
    { 561,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8od
    { 560,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 407,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8ki
    { 559,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 404,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8kd
    { 558,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8ji
    { 557,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8jd
    { 556,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8fi
    { 555,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 391,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8fd
    { 554,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8ei
    { 553,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST8ed
    { 552,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 402,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST32di
    { 551,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 400,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BTST32dd
    { 550,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 250,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSR8
    { 549,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 250,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSR32
    { 548,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 250,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSR16
    { 547,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET8pi
    { 546,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 397,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET8pd
    { 545,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET8oi
    { 544,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET8od
    { 543,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET8ji
    { 542,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET8jd
    { 541,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET8fi
    { 540,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 391,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET8fd
    { 539,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET8ei
    { 538,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET8ed
    { 537,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 402,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET32di
    { 536,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 400,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSET32dd
    { 535,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 250,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRA8
    { 534,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 250,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRA32
    { 533,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 250,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRA16
    { 532,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BKPT
    { 531,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR8pi
    { 530,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 397,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR8pd
    { 529,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR8oi
    { 528,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR8od
    { 527,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR8ji
    { 526,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR8jd
    { 525,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR8fi
    { 524,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 391,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR8fd
    { 523,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR8ei
    { 522,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR8ed
    { 521,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 402,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR32di
    { 520,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 400,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLR32dd
    { 519,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG8pi
    { 518,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 397,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG8pd
    { 517,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG8oi
    { 516,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG8od
    { 515,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG8ji
    { 514,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG8jd
    { 513,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG8fi
    { 512,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 391,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG8fd
    { 511,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG8ei
    { 510,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG8ed
    { 509,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 402,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG32di
    { 508,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 400,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCHG32dd
    { 507,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 374,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASR8di
    { 506,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 366,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASR8dd
    { 505,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASR32di
    { 504,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASR32dd
    { 503,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 263,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASR16di
    { 502,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 255,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASR16dd
    { 501,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8pi
    { 500,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 397,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8pd
    { 499,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8ji
    { 498,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8jd
    { 497,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8fi
    { 496,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 391,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8fd
    { 495,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 388,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8dq
    { 494,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 384,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8dp
    { 493,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 380,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8dk
    { 492,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 377,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8dj
    { 491,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 374,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8di
    { 490,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 369,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8df
    { 489,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 366,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND8dd
    { 488,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32pi
    { 487,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 363,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32pd
    { 486,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32ji
    { 485,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 361,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32jd
    { 484,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32fi
    { 483,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 357,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32fd
    { 482,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 354,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32dr
    { 481,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 351,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32dq
    { 480,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 347,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32dp
    { 479,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 343,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32dk
    { 478,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 340,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32dj
    { 477,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32di
    { 476,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 332,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32df
    { 475,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND32dd
    { 474,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16pi
    { 473,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 295,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16pd
    { 472,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16ji
    { 471,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 291,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16jd
    { 470,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16fi
    { 469,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 283,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16fd
    { 468,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 280,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16dr
    { 467,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 277,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16dq
    { 466,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 273,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16dp
    { 465,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 269,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16dk
    { 464,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 266,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16dj
    { 463,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 263,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16di
    { 462,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 258,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16df
    { 461,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 255,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND16dd
    { 460,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 366,	6,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDX8dd
    { 459,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 329,	6,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDX32dd
    { 458,	3,	1,	0,	0,	1,	1,	M68kOpInfoBase + 255,	6,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDX16dd
    { 457,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8pi
    { 456,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 397,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8pd
    { 455,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8ji
    { 454,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 395,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8jd
    { 453,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8fi
    { 452,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 391,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8fd
    { 451,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 388,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8dq
    { 450,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 384,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8dp
    { 449,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 380,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8dk
    { 448,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 377,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8dj
    { 447,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 374,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8di
    { 446,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 369,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8df
    { 445,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 366,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD8dd
    { 444,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32pi
    { 443,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 363,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32pd
    { 442,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32ji
    { 441,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 361,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32jd
    { 440,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32fi
    { 439,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 357,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32fd
    { 438,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 354,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32dr
    { 437,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 351,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32dq
    { 436,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 347,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32dp
    { 435,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 343,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32dk
    { 434,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 340,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32dj
    { 433,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 337,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32di
    { 432,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 332,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32df
    { 431,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 329,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32dd
    { 430,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 326,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32ar
    { 429,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 323,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32aq
    { 428,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 319,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32ap
    { 427,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 315,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32ak
    { 426,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 312,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32aj
    { 425,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 309,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32ai
    { 424,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 304,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32af
    { 423,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 301,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD32ab
    { 422,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 298,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16pi
    { 421,	3,	0,	0,	0,	0,	1,	M68kOpInfoBase + 295,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16pd
    { 420,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 293,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16ji
    { 419,	2,	0,	0,	0,	0,	1,	M68kOpInfoBase + 291,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16jd
    { 418,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 287,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16fi
    { 417,	4,	0,	0,	0,	0,	1,	M68kOpInfoBase + 283,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16fd
    { 416,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 280,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16dr
    { 415,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 277,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16dq
    { 414,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 273,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16dp
    { 413,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 269,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16dk
    { 412,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 266,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16dj
    { 411,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 263,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16di
    { 410,	5,	1,	0,	0,	0,	1,	M68kOpInfoBase + 258,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16df
    { 409,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 255,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD16dd
    { 408,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 253,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TCRETURNq
    { 407,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 251,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TCRETURNj
    { 406,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 250,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TAILJMPq
    { 405,	1,	0,	0,	0,	1,	0,	M68kOpInfoBase + 249,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TAILJMPj
    { 404,	1,	1,	0,	0,	1,	1,	M68kOpInfoBase + 246,	6,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETCS_C8d
    { 403,	1,	1,	0,	0,	1,	1,	M68kOpInfoBase + 245,	6,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETCS_C32d
    { 402,	1,	1,	0,	0,	1,	1,	M68kOpInfoBase + 244,	6,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SETCS_C16d
    { 401,	2,	1,	0,	0,	1,	2,	M68kOpInfoBase + 247,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SALLOCA
    { 400,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET
    { 399,	1,	0,	0,	0,	1,	1,	M68kOpInfoBase + 246,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PUSH8d
    { 398,	1,	0,	0,	0,	1,	1,	M68kOpInfoBase + 245,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PUSH32r
    { 397,	1,	0,	0,	0,	1,	1,	M68kOpInfoBase + 244,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PUSH16d
    { 396,	1,	1,	0,	0,	1,	1,	M68kOpInfoBase + 246,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POP8d
    { 395,	1,	1,	0,	0,	1,	1,	M68kOpInfoBase + 245,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POP32r
    { 394,	1,	1,	0,	0,	1,	1,	M68kOpInfoBase + 244,	4,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POP16d
    { 393,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 242,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd32q8
    { 392,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 242,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd32q16
    { 391,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 239,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd32p8
    { 390,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 239,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd32p16
    { 389,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 237,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd32j8
    { 388,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 237,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd32j16
    { 387,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 233,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd32f8
    { 386,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 233,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd32f16
    { 385,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 231,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd32d8
    { 384,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 229,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd32d16
    { 383,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 227,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd16q8
    { 382,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 224,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd16p8
    { 381,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 222,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd16j8
    { 380,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 218,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd16f8
    { 379,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 216,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVZXd16d8
    { 378,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 231,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVXd32d8
    { 377,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 229,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVXd32d16
    { 376,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 216,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVXd16d8
    { 375,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 242,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd32q8
    { 374,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 242,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd32q16
    { 373,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 239,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd32p8
    { 372,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 239,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd32p16
    { 371,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 237,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd32j8
    { 370,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 237,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd32j16
    { 369,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 233,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd32f8
    { 368,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 233,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd32f16
    { 367,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 231,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd32d8
    { 366,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 229,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd32d16
    { 365,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 227,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd16q8
    { 364,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 224,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd16p8
    { 363,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 222,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd16j8
    { 362,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 218,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd16f8
    { 361,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 216,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVSXd16d8
    { 360,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 213,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32pm_P
    { 359,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 210,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32mp_P
    { 358,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 208,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32mj_P
    { 357,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 206,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM32jm_P
    { 356,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 203,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16pm_P
    { 355,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 200,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16mp_P
    { 354,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 198,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16mj_P
    { 353,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 196,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVM16jm_P
    { 352,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 194,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVI8di
    { 351,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 192,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVI32ri
    { 350,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 190,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVI16ri
    { 349,	3,	0,	0,	0,	1,	0,	M68kOpInfoBase + 187,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8pc
    { 348,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 181,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8oc
    { 347,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 181,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8jc
    { 346,	4,	0,	0,	0,	1,	0,	M68kOpInfoBase + 183,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8fc
    { 345,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 181,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ec
    { 344,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 179,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8cq
    { 343,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 176,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8cp
    { 342,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 167,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8co
    { 341,	3,	1,	0,	0,	0,	1,	M68kOpInfoBase + 173,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ck
    { 340,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 167,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8cj
    { 339,	4,	1,	0,	0,	0,	1,	M68kOpInfoBase + 169,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8cf
    { 338,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 167,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8ce
    { 337,	2,	1,	0,	0,	0,	1,	M68kOpInfoBase + 165,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8cb
    { 336,	2,	0,	0,	0,	1,	0,	M68kOpInfoBase + 163,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOV8bc
    { 335,	4,	1,	0,	0,	1,	0,	M68kOpInfoBase + 159,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMOV8d
    { 334,	4,	1,	0,	0,	1,	0,	M68kOpInfoBase + 155,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMOV32r
    { 333,	4,	1,	0,	0,	1,	0,	M68kOpInfoBase + 151,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CMOV16d
    { 332,	2,	0,	0,	0,	1,	2,	M68kOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKUP
    { 331,	2,	0,	0,	0,	1,	2,	M68kOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKDOWN
    { 330,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	M68kOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	M68kOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	M68kOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	M68kOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	M68kOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	M68kOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	M68kOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	M68kOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	M68kOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	M68kOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	M68kOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	M68kOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	M68kOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	M68kOpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	M68kOpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	M68kOpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	M68kOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	M68kOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	M68kOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	M68kOpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	M68kOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	M68kOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	M68kOpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14647
    { 41,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14646
    { 40,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14645
    { 31,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	M68kOpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	M68kOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	M68kOpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	0,	0,	0,	M68kOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	0,	0,	0,	M68kOpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	0,	0,	0,	M68kOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	M68kOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	M68kOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PHI
  }, {
    /* 0 */
    /* 0 */ M68k::SP, M68k::SP, M68k::CCR,
    /* 3 */ M68k::CCR,
    /* 4 */ M68k::SP, M68k::SP,
    /* 6 */ M68k::CCR, M68k::CCR,
    /* 8 */ M68k::SP,
    /* 9 */ M68k::FPC, M68k::FPS,
    /* 11 */ M68k::FPS,
    /* 12 */ M68k::SR,
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
    /* 28 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
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
    /* 151 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 155 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 159 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 163 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 165 */ { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 167 */ { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 169 */ { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 173 */ { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 176 */ { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 179 */ { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 181 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 183 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 187 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 190 */ { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 192 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 194 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 196 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 198 */ { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 200 */ { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 203 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 206 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 208 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 210 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 213 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 216 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 218 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 222 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 224 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 227 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 229 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 231 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 233 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 237 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 239 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 242 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 244 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 245 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 246 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 247 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 249 */ { M68k::AR32_TCRegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 250 */ { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 251 */ { M68k::AR32_TCRegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 253 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 255 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 258 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 263 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 266 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 269 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 273 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 277 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 280 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 283 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 287 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 291 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 293 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 295 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 298 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 301 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 304 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 309 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 312 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 315 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 319 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 323 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 326 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 329 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 332 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 337 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 340 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 343 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 347 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 351 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 354 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 357 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 361 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 363 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 366 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 369 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 374 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 377 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 380 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 384 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 388 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 391 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 395 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 397 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 400 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 402 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 404 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 407 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 410 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 412 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 413 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 416 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 417 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 419 */ { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 422 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 424 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 428 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 432 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 436 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 440 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 444 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 448 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 453 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 458 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 463 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 469 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 475 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 481 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 483 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 485 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 488 */ { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 490 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 494 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 496 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 499 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 502 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 504 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 506 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 509 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 511 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 513 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 517 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 519 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 521 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 524 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 527 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 529 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 531 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 533 */ { M68k::FPDR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::FPDR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 535 */ { M68k::FPDR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::FPDR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 537 */ { M68k::FPDR80RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::FPDR80RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 539 */ { M68k::FPDR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::FPDR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::FPDR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 542 */ { M68k::FPDR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::FPDR64RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::FPDR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 545 */ { M68k::FPDR80RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::FPDR80RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::FPDR80RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 548 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::FPICRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 550 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::FPCSCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 552 */ { M68k::FPCSCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 554 */ { M68k::FPICRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 556 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR16RegClassID, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 560 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 562 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 566 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 569 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 573 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 576 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 578 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 580 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 582 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 584 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 586 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 590 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 593 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 596 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 598 */ { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 600 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 602 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 604 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 606 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 610 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 612 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 615 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 618 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 620 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 622 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 624 */ { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 626 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 628 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::CCRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 630 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 632 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 634 */ { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 636 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 638 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 640 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 642 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 646 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 649 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 652 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 654 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 656 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 660 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 664 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 668 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 674 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 679 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 684 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 688 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 692 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 696 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 699 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 702 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 705 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 710 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 714 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 718 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 721 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 724 */ { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 726 */ { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 728 */ { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 732 */ { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 735 */ { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 737 */ { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::XR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 739 */ { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 741 */ { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 743 */ { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 745 */ { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 749 */ { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 752 */ { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 755 */ { M68k::SRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 757 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 759 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 761 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 763 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 765 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 767 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 769 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 771 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 773 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 777 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 781 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 784 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 786 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 788 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::AR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 792 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_PCREL, 0 },
    /* 795 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_PCREL, 0 },
    /* 797 */ { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::XR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 799 */ { -1, 0, MCOI::OPERAND_MEMORY, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 801 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_MEMORY, 0 },
    /* 803 */ { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 805 */ { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { M68k::DR32RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { M68k::DR16RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 808 */ { M68k::AR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
  }
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char M68kInstrNameData[] = {
  /* 0 */ "G_FLOG10\000"
  /* 9 */ "G_FEXP10\000"
  /* 18 */ "BRA32\000"
  /* 24 */ "CASARID32\000"
  /* 34 */ "CASARII32\000"
  /* 44 */ "CASARI32\000"
  /* 53 */ "LINK32\000"
  /* 60 */ "CASAL32\000"
  /* 68 */ "BSR32\000"
  /* 74 */ "EXT32\000"
  /* 80 */ "Bcc32\000"
  /* 86 */ "Bvc32\000"
  /* 92 */ "SMULd32d32\000"
  /* 103 */ "UMULd32d32\000"
  /* 114 */ "SDIVd32d32\000"
  /* 125 */ "UDIVd32d32\000"
  /* 136 */ "Bge32\000"
  /* 142 */ "Ble32\000"
  /* 148 */ "Bne32\000"
  /* 154 */ "Bhi32\000"
  /* 160 */ "Bmi32\000"
  /* 166 */ "Bpl32\000"
  /* 172 */ "Beq32\000"
  /* 178 */ "Bcs32\000"
  /* 184 */ "Bls32\000"
  /* 190 */ "Bvs32\000"
  /* 196 */ "Bgt32\000"
  /* 202 */ "Blt32\000"
  /* 208 */ "G_FLOG2\000"
  /* 216 */ "G_FATAN2\000"
  /* 225 */ "G_FEXP2\000"
  /* 233 */ "BRA16\000"
  /* 239 */ "CASARID16\000"
  /* 249 */ "CASARII16\000"
  /* 259 */ "CASARI16\000"
  /* 268 */ "LINK16\000"
  /* 275 */ "CASAL16\000"
  /* 283 */ "BSR16\000"
  /* 289 */ "EXT16\000"
  /* 295 */ "Bcc16\000"
  /* 301 */ "Bvc16\000"
  /* 307 */ "SMULd32d16\000"
  /* 318 */ "UMULd32d16\000"
  /* 329 */ "SDIVd32d16\000"
  /* 340 */ "UDIVd32d16\000"
  /* 351 */ "MOVSXd32d16\000"
  /* 363 */ "MOVXd32d16\000"
  /* 374 */ "MOVZXd32d16\000"
  /* 386 */ "Bge16\000"
  /* 392 */ "Ble16\000"
  /* 398 */ "Bne16\000"
  /* 404 */ "MOVSXd32f16\000"
  /* 416 */ "MOVZXd32f16\000"
  /* 428 */ "SMULd32i16\000"
  /* 439 */ "UMULd32i16\000"
  /* 450 */ "SDIVd32i16\000"
  /* 461 */ "UDIVd32i16\000"
  /* 472 */ "Bhi16\000"
  /* 478 */ "Bmi16\000"
  /* 484 */ "MOVSXd32j16\000"
  /* 496 */ "MOVZXd32j16\000"
  /* 508 */ "Bpl16\000"
  /* 514 */ "MOVSXd32p16\000"
  /* 526 */ "MOVZXd32p16\000"
  /* 538 */ "MOVSXd32q16\000"
  /* 550 */ "MOVZXd32q16\000"
  /* 562 */ "Beq16\000"
  /* 568 */ "Bcs16\000"
  /* 574 */ "Bls16\000"
  /* 580 */ "Bvs16\000"
  /* 586 */ "Bgt16\000"
  /* 592 */ "Blt16\000"
  /* 598 */ "BRA8\000"
  /* 603 */ "CASARID8\000"
  /* 612 */ "CASARII8\000"
  /* 621 */ "CASARI8\000"
  /* 629 */ "CASAL8\000"
  /* 636 */ "BSR8\000"
  /* 641 */ "Bcc8\000"
  /* 646 */ "Bvc8\000"
  /* 651 */ "MOVSXd32d8\000"
  /* 662 */ "MOVXd32d8\000"
  /* 672 */ "MOVZXd32d8\000"
  /* 683 */ "MOVSXd16d8\000"
  /* 694 */ "MOVXd16d8\000"
  /* 704 */ "MOVZXd16d8\000"
  /* 715 */ "Bge8\000"
  /* 720 */ "Ble8\000"
  /* 725 */ "Bne8\000"
  /* 730 */ "MOVSXd32f8\000"
  /* 741 */ "MOVZXd32f8\000"
  /* 752 */ "MOVSXd16f8\000"
  /* 763 */ "MOVZXd16f8\000"
  /* 774 */ "Bhi8\000"
  /* 779 */ "Bmi8\000"
  /* 784 */ "MOVSXd32j8\000"
  /* 795 */ "MOVZXd32j8\000"
  /* 806 */ "MOVSXd16j8\000"
  /* 817 */ "MOVZXd16j8\000"
  /* 828 */ "Bpl8\000"
  /* 833 */ "MOVSXd32p8\000"
  /* 844 */ "MOVZXd32p8\000"
  /* 855 */ "MOVSXd16p8\000"
  /* 866 */ "MOVZXd16p8\000"
  /* 877 */ "MOVSXd32q8\000"
  /* 888 */ "MOVZXd32q8\000"
  /* 899 */ "MOVSXd16q8\000"
  /* 910 */ "MOVZXd16q8\000"
  /* 921 */ "Beq8\000"
  /* 926 */ "Bcs8\000"
  /* 931 */ "Bls8\000"
  /* 936 */ "Bvs8\000"
  /* 941 */ "Bgt8\000"
  /* 946 */ "Blt8\000"
  /* 951 */ "SALLOCA\000"
  /* 959 */ "G_FMA\000"
  /* 965 */ "G_STRICT_FMA\000"
  /* 978 */ "G_FSUB\000"
  /* 985 */ "G_STRICT_FSUB\000"
  /* 999 */ "G_ATOMICRMW_FSUB\000"
  /* 1016 */ "G_SUB\000"
  /* 1022 */ "G_ATOMICRMW_SUB\000"
  /* 1038 */ "G_INTRINSIC\000"
  /* 1050 */ "G_FPTRUNC\000"
  /* 1060 */ "G_INTRINSIC_TRUNC\000"
  /* 1078 */ "G_TRUNC\000"
  /* 1086 */ "G_BUILD_VECTOR_TRUNC\000"
  /* 1107 */ "G_DYN_STACKALLOC\000"
  /* 1124 */ "MOV32ab_TC\000"
  /* 1135 */ "MOV16ab_TC\000"
  /* 1146 */ "MOV32rb_TC\000"
  /* 1157 */ "MOV16rb_TC\000"
  /* 1168 */ "MOV32ae_TC\000"
  /* 1179 */ "MOV16ae_TC\000"
  /* 1190 */ "MOV32re_TC\000"
  /* 1201 */ "MOV16re_TC\000"
  /* 1212 */ "MOV32af_TC\000"
  /* 1223 */ "MOV16af_TC\000"
  /* 1234 */ "MOV32rf_TC\000"
  /* 1245 */ "MOV16rf_TC\000"
  /* 1256 */ "MOV32aj_TC\000"
  /* 1267 */ "MOV16aj_TC\000"
  /* 1278 */ "MOV32rj_TC\000"
  /* 1289 */ "MOV16rj_TC\000"
  /* 1300 */ "MOV32ak_TC\000"
  /* 1311 */ "MOV16ak_TC\000"
  /* 1322 */ "MOV32rk_TC\000"
  /* 1333 */ "MOV16rk_TC\000"
  /* 1344 */ "MOV32ao_TC\000"
  /* 1355 */ "MOV16ao_TC\000"
  /* 1366 */ "MOV32ro_TC\000"
  /* 1377 */ "MOV16ro_TC\000"
  /* 1388 */ "MOV32ap_TC\000"
  /* 1399 */ "MOV16ap_TC\000"
  /* 1410 */ "MOV32rp_TC\000"
  /* 1421 */ "MOV16rp_TC\000"
  /* 1432 */ "MOV32aq_TC\000"
  /* 1443 */ "MOV16aq_TC\000"
  /* 1454 */ "MOV32rq_TC\000"
  /* 1465 */ "MOV16rq_TC\000"
  /* 1476 */ "G_FMAD\000"
  /* 1483 */ "G_FPEXTLOAD\000"
  /* 1495 */ "G_INDEXED_SEXTLOAD\000"
  /* 1514 */ "G_SEXTLOAD\000"
  /* 1525 */ "G_INDEXED_ZEXTLOAD\000"
  /* 1544 */ "G_ZEXTLOAD\000"
  /* 1555 */ "G_INDEXED_LOAD\000"
  /* 1570 */ "G_LOAD\000"
  /* 1577 */ "G_VECREDUCE_FADD\000"
  /* 1594 */ "G_FADD\000"
  /* 1601 */ "G_VECREDUCE_SEQ_FADD\000"
  /* 1622 */ "G_STRICT_FADD\000"
  /* 1636 */ "G_ATOMICRMW_FADD\000"
  /* 1653 */ "G_VECREDUCE_ADD\000"
  /* 1669 */ "G_ADD\000"
  /* 1675 */ "G_PTR_ADD\000"
  /* 1685 */ "G_ATOMICRMW_ADD\000"
  /* 1701 */ "G_ATOMICRMW_NAND\000"
  /* 1718 */ "G_VECREDUCE_AND\000"
  /* 1734 */ "G_AND\000"
  /* 1740 */ "G_ATOMICRMW_AND\000"
  /* 1756 */ "LIFETIME_END\000"
  /* 1769 */ "G_BRCOND\000"
  /* 1778 */ "G_ATOMICRMW_USUB_COND\000"
  /* 1800 */ "G_LLROUND\000"
  /* 1810 */ "G_LROUND\000"
  /* 1819 */ "G_INTRINSIC_ROUND\000"
  /* 1837 */ "G_INTRINSIC_FPTRUNC_ROUND\000"
  /* 1863 */ "LOAD_STACK_GUARD\000"
  /* 1880 */ "PSEUDO_PROBE\000"
  /* 1893 */ "G_SSUBE\000"
  /* 1901 */ "G_USUBE\000"
  /* 1909 */ "G_FENCE\000"
  /* 1917 */ "ARITH_FENCE\000"
  /* 1929 */ "REG_SEQUENCE\000"
  /* 1942 */ "G_SADDE\000"
  /* 1950 */ "G_UADDE\000"
  /* 1958 */ "G_GET_FPMODE\000"
  /* 1971 */ "G_RESET_FPMODE\000"
  /* 1986 */ "G_SET_FPMODE\000"
  /* 1999 */ "G_FMINNUM_IEEE\000"
  /* 2014 */ "G_FMAXNUM_IEEE\000"
  /* 2029 */ "G_VSCALE\000"
  /* 2038 */ "G_JUMP_TABLE\000"
  /* 2051 */ "BUNDLE\000"
  /* 2058 */ "G_MEMSET_INLINE\000"
  /* 2074 */ "G_MEMCPY_INLINE\000"
  /* 2090 */ "RELOC_NONE\000"
  /* 2101 */ "LOCAL_ESCAPE\000"
  /* 2114 */ "G_FPTRUNCSTORE\000"
  /* 2129 */ "G_STACKRESTORE\000"
  /* 2144 */ "G_INDEXED_STORE\000"
  /* 2160 */ "G_STORE\000"
  /* 2168 */ "G_BITREVERSE\000"
  /* 2181 */ "FAKE_USE\000"
  /* 2190 */ "RTE\000"
  /* 2194 */ "DBG_VALUE\000"
  /* 2204 */ "G_GLOBAL_VALUE\000"
  /* 2219 */ "G_PTRAUTH_GLOBAL_VALUE\000"
  /* 2242 */ "CONVERGENCECTRL_GLUE\000"
  /* 2263 */ "G_STACKSAVE\000"
  /* 2275 */ "G_MEMMOVE\000"
  /* 2285 */ "G_FREEZE\000"
  /* 2294 */ "G_FCANONICALIZE\000"
  /* 2310 */ "G_FMODF\000"
  /* 2318 */ "INIT_UNDEF\000"
  /* 2329 */ "G_IMPLICIT_DEF\000"
  /* 2344 */ "DBG_INSTR_REF\000"
  /* 2358 */ "G_FNEG\000"
  /* 2365 */ "EXTRACT_SUBREG\000"
  /* 2380 */ "INSERT_SUBREG\000"
  /* 2394 */ "G_SEXT_INREG\000"
  /* 2407 */ "SUBREG_TO_REG\000"
  /* 2421 */ "G_ATOMIC_CMPXCHG\000"
  /* 2438 */ "G_ATOMICRMW_XCHG\000"
  /* 2455 */ "G_GET_ROUNDING\000"
  /* 2470 */ "G_SET_ROUNDING\000"
  /* 2485 */ "G_FLOG\000"
  /* 2492 */ "G_VAARG\000"
  /* 2500 */ "PREALLOCATED_ARG\000"
  /* 2517 */ "G_PREFETCH\000"
  /* 2528 */ "G_SMULH\000"
  /* 2536 */ "G_UMULH\000"
  /* 2544 */ "G_FTANH\000"
  /* 2552 */ "G_FSINH\000"
  /* 2560 */ "G_FCOSH\000"
  /* 2568 */ "DBG_PHI\000"
  /* 2576 */ "G_FPTOSI\000"
  /* 2585 */ "G_FPTOUI\000"
  /* 2594 */ "G_FPOWI\000"
  /* 2602 */ "UNLK\000"
  /* 2607 */ "COPY_LANEMASK\000"
  /* 2621 */ "G_PTRMASK\000"
  /* 2631 */ "LEA32L\000"
  /* 2638 */ "ILLEGAL\000"
  /* 2646 */ "GC_LABEL\000"
  /* 2655 */ "DBG_LABEL\000"
  /* 2665 */ "EH_LABEL\000"
  /* 2674 */ "ANNOTATION_LABEL\000"
  /* 2691 */ "ICALL_BRANCH_FUNNEL\000"
  /* 2711 */ "G_FSHL\000"
  /* 2718 */ "G_SHL\000"
  /* 2724 */ "G_FCEIL\000"
  /* 2732 */ "G_SAVGCEIL\000"
  /* 2743 */ "G_UAVGCEIL\000"
  /* 2754 */ "PATCHABLE_TAIL_CALL\000"
  /* 2774 */ "PATCHABLE_TYPED_EVENT_CALL\000"
  /* 2801 */ "PATCHABLE_EVENT_CALL\000"
  /* 2822 */ "FENTRY_CALL\000"
  /* 2834 */ "KILL\000"
  /* 2839 */ "G_CONSTANT_POOL\000"
  /* 2855 */ "G_ROTL\000"
  /* 2862 */ "G_VECREDUCE_FMUL\000"
  /* 2879 */ "G_FMUL\000"
  /* 2886 */ "G_VECREDUCE_SEQ_FMUL\000"
  /* 2907 */ "G_STRICT_FMUL\000"
  /* 2921 */ "G_CLMUL\000"
  /* 2929 */ "G_VECREDUCE_MUL\000"
  /* 2945 */ "G_MUL\000"
  /* 2951 */ "G_FREM\000"
  /* 2958 */ "G_STRICT_FREM\000"
  /* 2972 */ "G_SREM\000"
  /* 2979 */ "G_UREM\000"
  /* 2986 */ "G_SDIVREM\000"
  /* 2996 */ "G_UDIVREM\000"
  /* 3006 */ "INLINEASM\000"
  /* 3016 */ "G_VECREDUCE_FMINIMUM\000"
  /* 3037 */ "G_FMINIMUM\000"
  /* 3048 */ "G_ATOMICRMW_FMINIMUM\000"
  /* 3069 */ "G_VECREDUCE_FMAXIMUM\000"
  /* 3090 */ "G_FMAXIMUM\000"
  /* 3101 */ "G_ATOMICRMW_FMAXIMUM\000"
  /* 3122 */ "G_FMINIMUMNUM\000"
  /* 3136 */ "G_ATOMICRMW_FMINIMUMNUM\000"
  /* 3160 */ "G_FMAXIMUMNUM\000"
  /* 3174 */ "G_ATOMICRMW_FMAXIMUMNUM\000"
  /* 3198 */ "G_FMINNUM\000"
  /* 3208 */ "G_FMAXNUM\000"
  /* 3218 */ "G_FATAN\000"
  /* 3226 */ "G_FTAN\000"
  /* 3233 */ "G_INTRINSIC_ROUNDEVEN\000"
  /* 3255 */ "G_ASSERT_ALIGN\000"
  /* 3270 */ "G_FCOPYSIGN\000"
  /* 3282 */ "G_VECREDUCE_FMIN\000"
  /* 3299 */ "G_ATOMICRMW_FMIN\000"
  /* 3316 */ "G_VECREDUCE_SMIN\000"
  /* 3333 */ "G_SMIN\000"
  /* 3340 */ "G_VECREDUCE_UMIN\000"
  /* 3357 */ "G_UMIN\000"
  /* 3364 */ "G_ATOMICRMW_UMIN\000"
  /* 3381 */ "G_ATOMICRMW_MIN\000"
  /* 3397 */ "G_FASIN\000"
  /* 3405 */ "G_FSIN\000"
  /* 3412 */ "CFI_INSTRUCTION\000"
  /* 3428 */ "G_CTLZ_ZERO_POISON\000"
  /* 3447 */ "G_CTTZ_ZERO_POISON\000"
  /* 3466 */ "ADJCALLSTACKDOWN\000"
  /* 3483 */ "G_SSUBO\000"
  /* 3491 */ "G_USUBO\000"
  /* 3499 */ "G_SADDO\000"
  /* 3507 */ "G_UADDO\000"
  /* 3515 */ "JUMP_TABLE_DEBUG_INFO\000"
  /* 3537 */ "G_SMULO\000"
  /* 3545 */ "G_UMULO\000"
  /* 3553 */ "G_BZERO\000"
  /* 3561 */ "STACKMAP\000"
  /* 3570 */ "G_DEBUGTRAP\000"
  /* 3582 */ "G_UBSANTRAP\000"
  /* 3594 */ "G_TRAP\000"
  /* 3601 */ "G_ATOMICRMW_UDEC_WRAP\000"
  /* 3623 */ "G_ATOMICRMW_UINC_WRAP\000"
  /* 3645 */ "G_BSWAP\000"
  /* 3653 */ "G_SITOFP\000"
  /* 3662 */ "G_UITOFP\000"
  /* 3671 */ "G_FCMP\000"
  /* 3678 */ "G_STRICT_FCMP\000"
  /* 3692 */ "G_ICMP\000"
  /* 3699 */ "G_SCMP\000"
  /* 3706 */ "G_UCMP\000"
  /* 3713 */ "NOP\000"
  /* 3717 */ "CONVERGENCECTRL_LOOP\000"
  /* 3738 */ "G_CTPOP\000"
  /* 3746 */ "PATCHABLE_OP\000"
  /* 3759 */ "FAULTING_OP\000"
  /* 3771 */ "ADJCALLSTACKUP\000"
  /* 3786 */ "PREALLOCATED_SETUP\000"
  /* 3805 */ "G_FLDEXP\000"
  /* 3814 */ "G_STRICT_FLDEXP\000"
  /* 3830 */ "G_FEXP\000"
  /* 3837 */ "G_FFREXP\000"
  /* 3846 */ "MOVM32mj_P\000"
  /* 3857 */ "MOVM16mj_P\000"
  /* 3868 */ "MOVM32jm_P\000"
  /* 3879 */ "MOVM16jm_P\000"
  /* 3890 */ "MOVM32pm_P\000"
  /* 3901 */ "MOVM16pm_P\000"
  /* 3912 */ "MOVM32mp_P\000"
  /* 3923 */ "MOVM16mp_P\000"
  /* 3934 */ "MOVQ\000"
  /* 3939 */ "G_BR\000"
  /* 3944 */ "INLINEASM_BR\000"
  /* 3957 */ "G_BLOCK_ADDR\000"
  /* 3970 */ "MEMBARRIER\000"
  /* 3981 */ "G_CONSTANT_FOLD_BARRIER\000"
  /* 4005 */ "PATCHABLE_FUNCTION_ENTER\000"
  /* 4030 */ "G_READCYCLECOUNTER\000"
  /* 4049 */ "G_READSTEADYCOUNTER\000"
  /* 4069 */ "G_READ_REGISTER\000"
  /* 4085 */ "G_WRITE_REGISTER\000"
  /* 4102 */ "G_ASHR\000"
  /* 4109 */ "G_FSHR\000"
  /* 4116 */ "G_LSHR\000"
  /* 4123 */ "CONVERGENCECTRL_ANCHOR\000"
  /* 4146 */ "G_FFLOOR\000"
  /* 4155 */ "G_SAVGFLOOR\000"
  /* 4167 */ "G_UAVGFLOOR\000"
  /* 4179 */ "G_EXTRACT_SUBVECTOR\000"
  /* 4199 */ "G_INSERT_SUBVECTOR\000"
  /* 4218 */ "G_BUILD_VECTOR\000"
  /* 4233 */ "G_SHUFFLE_VECTOR\000"
  /* 4250 */ "G_STEP_VECTOR\000"
  /* 4264 */ "G_SPLAT_VECTOR\000"
  /* 4279 */ "G_VECREDUCE_XOR\000"
  /* 4295 */ "G_XOR\000"
  /* 4301 */ "G_ATOMICRMW_XOR\000"
  /* 4317 */ "G_VECREDUCE_OR\000"
  /* 4332 */ "G_OR\000"
  /* 4337 */ "G_ATOMICRMW_OR\000"
  /* 4352 */ "G_ROTR\000"
  /* 4359 */ "G_INTTOPTR\000"
  /* 4370 */ "G_FABS\000"
  /* 4377 */ "G_ABS\000"
  /* 4383 */ "G_ABDS\000"
  /* 4390 */ "G_UNMERGE_VALUES\000"
  /* 4407 */ "G_MERGE_VALUES\000"
  /* 4422 */ "G_CTLS\000"
  /* 4429 */ "G_FACOS\000"
  /* 4437 */ "G_FCOS\000"
  /* 4444 */ "G_FSINCOS\000"
  /* 4454 */ "G_STRICT_FCMPS\000"
  /* 4469 */ "G_CONCAT_VECTORS\000"
  /* 4486 */ "COPY_TO_REGCLASS\000"
  /* 4503 */ "G_IS_FPCLASS\000"
  /* 4516 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\000"
  /* 4546 */ "G_VECTOR_COMPRESS\000"
  /* 4564 */ "G_INTRINSIC_W_SIDE_EFFECTS\000"
  /* 4591 */ "G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS\000"
  /* 4629 */ "RTS\000"
  /* 4633 */ "G_TRUNC_SSAT_S\000"
  /* 4648 */ "G_SSUBSAT\000"
  /* 4658 */ "G_USUBSAT\000"
  /* 4668 */ "G_SADDSAT\000"
  /* 4678 */ "G_UADDSAT\000"
  /* 4688 */ "G_SSHLSAT\000"
  /* 4698 */ "G_USHLSAT\000"
  /* 4708 */ "G_SMULFIXSAT\000"
  /* 4721 */ "G_UMULFIXSAT\000"
  /* 4734 */ "G_SDIVFIXSAT\000"
  /* 4747 */ "G_UDIVFIXSAT\000"
  /* 4760 */ "G_ATOMICRMW_USUB_SAT\000"
  /* 4781 */ "G_FPTOSI_SAT\000"
  /* 4794 */ "G_FPTOUI_SAT\000"
  /* 4807 */ "G_EXTRACT\000"
  /* 4817 */ "G_SELECT\000"
  /* 4826 */ "G_BRINDIRECT\000"
  /* 4839 */ "PATCHABLE_RET\000"
  /* 4853 */ "G_MEMSET\000"
  /* 4862 */ "PATCHABLE_FUNCTION_EXIT\000"
  /* 4886 */ "G_BRJT\000"
  /* 4893 */ "G_EXTRACT_VECTOR_ELT\000"
  /* 4914 */ "G_INSERT_VECTOR_ELT\000"
  /* 4934 */ "G_FCONSTANT\000"
  /* 4946 */ "G_CONSTANT\000"
  /* 4957 */ "G_INTRINSIC_CONVERGENT\000"
  /* 4980 */ "STATEPOINT\000"
  /* 4991 */ "PATCHPOINT\000"
  /* 5002 */ "G_PTRTOINT\000"
  /* 5013 */ "G_FRINT\000"
  /* 5021 */ "G_INTRINSIC_LLRINT\000"
  /* 5040 */ "G_INTRINSIC_LRINT\000"
  /* 5058 */ "G_FNEARBYINT\000"
  /* 5071 */ "BKPT\000"
  /* 5076 */ "G_VASTART\000"
  /* 5086 */ "LIFETIME_START\000"
  /* 5101 */ "G_INVOKE_REGION_START\000"
  /* 5123 */ "G_INSERT\000"
  /* 5132 */ "G_FSQRT\000"
  /* 5140 */ "G_STRICT_FSQRT\000"
  /* 5155 */ "G_BITCAST\000"
  /* 5165 */ "G_ADDRSPACE_CAST\000"
  /* 5182 */ "DBG_VALUE_LIST\000"
  /* 5197 */ "G_FPEXT\000"
  /* 5205 */ "G_SEXT\000"
  /* 5212 */ "G_ASSERT_SEXT\000"
  /* 5226 */ "G_ANYEXT\000"
  /* 5235 */ "G_ZEXT\000"
  /* 5242 */ "G_ASSERT_ZEXT\000"
  /* 5256 */ "G_ABDU\000"
  /* 5263 */ "G_TRUNC_SSAT_U\000"
  /* 5278 */ "G_TRUNC_USAT_U\000"
  /* 5293 */ "G_FDIV\000"
  /* 5300 */ "G_STRICT_FDIV\000"
  /* 5314 */ "G_SDIV\000"
  /* 5321 */ "G_UDIV\000"
  /* 5328 */ "G_GET_FPENV\000"
  /* 5340 */ "G_RESET_FPENV\000"
  /* 5354 */ "G_SET_FPENV\000"
  /* 5366 */ "TRAPV\000"
  /* 5372 */ "G_FPOW\000"
  /* 5379 */ "G_VECREDUCE_FMAX\000"
  /* 5396 */ "G_ATOMICRMW_FMAX\000"
  /* 5413 */ "G_VECREDUCE_SMAX\000"
  /* 5430 */ "G_SMAX\000"
  /* 5437 */ "G_VECREDUCE_UMAX\000"
  /* 5454 */ "G_UMAX\000"
  /* 5461 */ "G_ATOMICRMW_UMAX\000"
  /* 5478 */ "G_ATOMICRMW_MAX\000"
  /* 5494 */ "G_FRAME_INDEX\000"
  /* 5508 */ "G_SBFX\000"
  /* 5515 */ "G_UBFX\000"
  /* 5522 */ "G_SMULFIX\000"
  /* 5532 */ "G_UMULFIX\000"
  /* 5542 */ "G_SDIVFIX\000"
  /* 5552 */ "G_UDIVFIX\000"
  /* 5562 */ "G_MEMCPY\000"
  /* 5571 */ "COPY\000"
  /* 5576 */ "CONVERGENCECTRL_ENTRY\000"
  /* 5598 */ "G_CTLZ\000"
  /* 5605 */ "G_CTTZ\000"
  /* 5612 */ "FMOVE32fpi_a\000"
  /* 5625 */ "MOV32aa\000"
  /* 5633 */ "MOV16aa\000"
  /* 5641 */ "MOV32ba\000"
  /* 5649 */ "MOV16ba\000"
  /* 5657 */ "MOV32ea\000"
  /* 5665 */ "MOV16ea\000"
  /* 5673 */ "MOV32fa\000"
  /* 5681 */ "MOV16fa\000"
  /* 5689 */ "MOV32ja\000"
  /* 5697 */ "MOV16ja\000"
  /* 5705 */ "MOV32oa\000"
  /* 5713 */ "MOV16oa\000"
  /* 5721 */ "MOV32pa\000"
  /* 5729 */ "MOV16pa\000"
  /* 5737 */ "MOV32ra\000"
  /* 5745 */ "MOV16ra\000"
  /* 5753 */ "LEA32b\000"
  /* 5760 */ "CALLb\000"
  /* 5766 */ "SUB32ab\000"
  /* 5774 */ "ADD32ab\000"
  /* 5782 */ "MOV32ab\000"
  /* 5790 */ "MOV16ab\000"
  /* 5798 */ "MOV32bb\000"
  /* 5806 */ "MOV16bb\000"
  /* 5814 */ "MOV8bb\000"
  /* 5821 */ "MOV16cb\000"
  /* 5829 */ "MOV8cb\000"
  /* 5836 */ "MOV32db\000"
  /* 5844 */ "MOV16db\000"
  /* 5852 */ "MOV8db\000"
  /* 5859 */ "MOV32eb\000"
  /* 5867 */ "MOV16eb\000"
  /* 5875 */ "MOV8eb\000"
  /* 5882 */ "MOV32fb\000"
  /* 5890 */ "MOV16fb\000"
  /* 5898 */ "MOV8fb\000"
  /* 5905 */ "MOV32jb\000"
  /* 5913 */ "MOV16jb\000"
  /* 5921 */ "MOV8jb\000"
  /* 5928 */ "MOVM32mb\000"
  /* 5937 */ "MOVM16mb\000"
  /* 5946 */ "MOV32ob\000"
  /* 5954 */ "MOV16ob\000"
  /* 5962 */ "MOV8ob\000"
  /* 5969 */ "MOV32pb\000"
  /* 5977 */ "MOV16pb\000"
  /* 5985 */ "MOV8pb\000"
  /* 5992 */ "MOV32rb\000"
  /* 6000 */ "MOV16rb\000"
  /* 6008 */ "MOV16sb\000"
  /* 6016 */ "MOV16bc\000"
  /* 6024 */ "MOV8bc\000"
  /* 6031 */ "SETd8cc\000"
  /* 6039 */ "SETj8cc\000"
  /* 6047 */ "SETp8cc\000"
  /* 6055 */ "MOV16dc\000"
  /* 6063 */ "MOV16ec\000"
  /* 6071 */ "MOV8ec\000"
  /* 6078 */ "MOV16fc\000"
  /* 6086 */ "MOV8fc\000"
  /* 6093 */ "MOV16jc\000"
  /* 6101 */ "MOV8jc\000"
  /* 6108 */ "MOV16oc\000"
  /* 6116 */ "MOV8oc\000"
  /* 6123 */ "MOV16pc\000"
  /* 6131 */ "MOV8pc\000"
  /* 6138 */ "SETd8vc\000"
  /* 6146 */ "SETj8vc\000"
  /* 6154 */ "SETp8vc\000"
  /* 6162 */ "SETCS_C32d\000"
  /* 6173 */ "NEG32d\000"
  /* 6180 */ "NOT32d\000"
  /* 6187 */ "NEGX32d\000"
  /* 6195 */ "SETCS_C16d\000"
  /* 6206 */ "NEG16d\000"
  /* 6213 */ "PUSH16d\000"
  /* 6221 */ "POP16d\000"
  /* 6228 */ "NOT16d\000"
  /* 6235 */ "CMOV16d\000"
  /* 6243 */ "NEGX16d\000"
  /* 6251 */ "SETCS_C8d\000"
  /* 6261 */ "NEG8d\000"
  /* 6267 */ "PUSH8d\000"
  /* 6274 */ "POP8d\000"
  /* 6280 */ "NOT8d\000"
  /* 6286 */ "CMOV8d\000"
  /* 6293 */ "NEGX8d\000"
  /* 6300 */ "FMOVE32fpcs_d\000"
  /* 6314 */ "MOV32bd\000"
  /* 6322 */ "MOV16bd\000"
  /* 6330 */ "MOV8bd\000"
  /* 6337 */ "MOV16cd\000"
  /* 6345 */ "SUB32dd\000"
  /* 6353 */ "ADD32dd\000"
  /* 6361 */ "AND32dd\000"
  /* 6369 */ "BCHG32dd\000"
  /* 6378 */ "SHL32dd\000"
  /* 6386 */ "ROL32dd\000"
  /* 6394 */ "BCLR32dd\000"
  /* 6403 */ "ROR32dd\000"
  /* 6411 */ "XOR32dd\000"
  /* 6419 */ "ASR32dd\000"
  /* 6427 */ "LSR32dd\000"
  /* 6435 */ "BSET32dd\000"
  /* 6444 */ "BTST32dd\000"
  /* 6453 */ "MOV32dd\000"
  /* 6461 */ "SUBX32dd\000"
  /* 6470 */ "ADDX32dd\000"
  /* 6479 */ "SUB16dd\000"
  /* 6487 */ "ADD16dd\000"
  /* 6495 */ "AND16dd\000"
  /* 6503 */ "SHL16dd\000"
  /* 6511 */ "ROL16dd\000"
  /* 6519 */ "ROR16dd\000"
  /* 6527 */ "XOR16dd\000"
  /* 6535 */ "ASR16dd\000"
  /* 6543 */ "LSR16dd\000"
  /* 6551 */ "MOV16dd\000"
  /* 6559 */ "SUBX16dd\000"
  /* 6568 */ "ADDX16dd\000"
  /* 6577 */ "SUB8dd\000"
  /* 6584 */ "ADD8dd\000"
  /* 6591 */ "AND8dd\000"
  /* 6598 */ "SHL8dd\000"
  /* 6605 */ "ROL8dd\000"
  /* 6612 */ "CMP8dd\000"
  /* 6619 */ "ROR8dd\000"
  /* 6626 */ "XOR8dd\000"
  /* 6633 */ "ASR8dd\000"
  /* 6640 */ "LSR8dd\000"
  /* 6647 */ "MOV8dd\000"
  /* 6654 */ "SUBX8dd\000"
  /* 6662 */ "ADDX8dd\000"
  /* 6670 */ "MOV32ed\000"
  /* 6678 */ "MOV16ed\000"
  /* 6686 */ "BCHG8ed\000"
  /* 6694 */ "BCLR8ed\000"
  /* 6702 */ "BSET8ed\000"
  /* 6710 */ "BTST8ed\000"
  /* 6718 */ "MOV8ed\000"
  /* 6725 */ "SUB32fd\000"
  /* 6733 */ "ADD32fd\000"
  /* 6741 */ "AND32fd\000"
  /* 6749 */ "OR32fd\000"
  /* 6756 */ "MOV32fd\000"
  /* 6764 */ "SUB16fd\000"
  /* 6772 */ "ADD16fd\000"
  /* 6780 */ "AND16fd\000"
  /* 6788 */ "OR16fd\000"
  /* 6795 */ "MOV16fd\000"
  /* 6803 */ "SUB8fd\000"
  /* 6810 */ "ADD8fd\000"
  /* 6817 */ "AND8fd\000"
  /* 6824 */ "BCHG8fd\000"
  /* 6832 */ "BCLR8fd\000"
  /* 6840 */ "OR8fd\000"
  /* 6846 */ "BSET8fd\000"
  /* 6854 */ "BTST8fd\000"
  /* 6862 */ "MOV8fd\000"
  /* 6869 */ "SUB32jd\000"
  /* 6877 */ "ADD32jd\000"
  /* 6885 */ "AND32jd\000"
  /* 6893 */ "OR32jd\000"
  /* 6900 */ "MOV32jd\000"
  /* 6908 */ "SUB16jd\000"
  /* 6916 */ "ADD16jd\000"
  /* 6924 */ "AND16jd\000"
  /* 6932 */ "OR16jd\000"
  /* 6939 */ "MOV16jd\000"
  /* 6947 */ "SUB8jd\000"
  /* 6954 */ "ADD8jd\000"
  /* 6961 */ "AND8jd\000"
  /* 6968 */ "BCHG8jd\000"
  /* 6976 */ "BCLR8jd\000"
  /* 6984 */ "OR8jd\000"
  /* 6990 */ "BSET8jd\000"
  /* 6998 */ "BTST8jd\000"
  /* 7006 */ "MOV8jd\000"
  /* 7013 */ "BTST8kd\000"
  /* 7021 */ "MOV32od\000"
  /* 7029 */ "MOV16od\000"
  /* 7037 */ "BCHG8od\000"
  /* 7045 */ "BCLR8od\000"
  /* 7053 */ "BSET8od\000"
  /* 7061 */ "BTST8od\000"
  /* 7069 */ "MOV8od\000"
  /* 7076 */ "SUB32pd\000"
  /* 7084 */ "ADD32pd\000"
  /* 7092 */ "AND32pd\000"
  /* 7100 */ "OR32pd\000"
  /* 7107 */ "MOV32pd\000"
  /* 7115 */ "SUB16pd\000"
  /* 7123 */ "ADD16pd\000"
  /* 7131 */ "AND16pd\000"
  /* 7139 */ "OR16pd\000"
  /* 7146 */ "MOV16pd\000"
  /* 7154 */ "SUB8pd\000"
  /* 7161 */ "ADD8pd\000"
  /* 7168 */ "AND8pd\000"
  /* 7175 */ "BCHG8pd\000"
  /* 7183 */ "BCLR8pd\000"
  /* 7191 */ "OR8pd\000"
  /* 7197 */ "BSET8pd\000"
  /* 7205 */ "BTST8pd\000"
  /* 7213 */ "MOV8pd\000"
  /* 7220 */ "BTST8qd\000"
  /* 7228 */ "MOV16sd\000"
  /* 7236 */ "MOV32ae\000"
  /* 7244 */ "MOV16ae\000"
  /* 7252 */ "MOV32be\000"
  /* 7260 */ "MOV16be\000"
  /* 7268 */ "MOV8be\000"
  /* 7275 */ "MOV16ce\000"
  /* 7283 */ "MOV8ce\000"
  /* 7290 */ "MOV32de\000"
  /* 7298 */ "MOV16de\000"
  /* 7306 */ "MOV8de\000"
  /* 7313 */ "MOV32ee\000"
  /* 7321 */ "MOV16ee\000"
  /* 7329 */ "MOV8ee\000"
  /* 7336 */ "MOV32fe\000"
  /* 7344 */ "MOV16fe\000"
  /* 7352 */ "MOV8fe\000"
  /* 7359 */ "SETd8ge\000"
  /* 7367 */ "SETj8ge\000"
  /* 7375 */ "SETp8ge\000"
  /* 7383 */ "MOV32je\000"
  /* 7391 */ "MOV16je\000"
  /* 7399 */ "MOV8je\000"
  /* 7406 */ "SETd8le\000"
  /* 7414 */ "SETj8le\000"
  /* 7422 */ "SETp8le\000"
  /* 7430 */ "MOVM32me\000"
  /* 7439 */ "MOVM16me\000"
  /* 7448 */ "SETd8ne\000"
  /* 7456 */ "SETj8ne\000"
  /* 7464 */ "SETp8ne\000"
  /* 7472 */ "MOV32oe\000"
  /* 7480 */ "MOV16oe\000"
  /* 7488 */ "MOV8oe\000"
  /* 7495 */ "MOV32pe\000"
  /* 7503 */ "MOV16pe\000"
  /* 7511 */ "MOV8pe\000"
  /* 7518 */ "MOV32re\000"
  /* 7526 */ "MOV16re\000"
  /* 7534 */ "MOV16se\000"
  /* 7542 */ "LEA32f\000"
  /* 7549 */ "SETd8f\000"
  /* 7556 */ "SETj8f\000"
  /* 7563 */ "SETp8f\000"
  /* 7570 */ "CALLf\000"
  /* 7576 */ "SUB32af\000"
  /* 7584 */ "ADD32af\000"
  /* 7592 */ "MOV32af\000"
  /* 7600 */ "MOV16af\000"
  /* 7608 */ "MOV32bf\000"
  /* 7616 */ "MOV16bf\000"
  /* 7624 */ "MOV8bf\000"
  /* 7631 */ "MOV16cf\000"
  /* 7639 */ "MOV8cf\000"
  /* 7646 */ "SUB32df\000"
  /* 7654 */ "ADD32df\000"
  /* 7662 */ "AND32df\000"
  /* 7670 */ "CMP32df\000"
  /* 7678 */ "OR32df\000"
  /* 7685 */ "MOV32df\000"
  /* 7693 */ "SUB16df\000"
  /* 7701 */ "ADD16df\000"
  /* 7709 */ "AND16df\000"
  /* 7717 */ "CMP16df\000"
  /* 7725 */ "OR16df\000"
  /* 7732 */ "MOV16df\000"
  /* 7740 */ "SUB8df\000"
  /* 7747 */ "ADD8df\000"
  /* 7754 */ "AND8df\000"
  /* 7761 */ "CMP8df\000"
  /* 7768 */ "OR8df\000"
  /* 7774 */ "MOV8df\000"
  /* 7781 */ "MOV32ef\000"
  /* 7789 */ "MOV16ef\000"
  /* 7797 */ "MOV8ef\000"
  /* 7804 */ "MOV32ff\000"
  /* 7812 */ "MOV16ff\000"
  /* 7820 */ "MOV8ff\000"
  /* 7827 */ "MOV32jf\000"
  /* 7835 */ "MOV16jf\000"
  /* 7843 */ "MOV8jf\000"
  /* 7850 */ "MOVM32mf\000"
  /* 7859 */ "MOVM16mf\000"
  /* 7868 */ "MOV32of\000"
  /* 7876 */ "MOV16of\000"
  /* 7884 */ "MOV8of\000"
  /* 7891 */ "MOV32pf\000"
  /* 7899 */ "MOV16pf\000"
  /* 7907 */ "MOV8pf\000"
  /* 7914 */ "MOV32rf\000"
  /* 7922 */ "MOV16rf\000"
  /* 7930 */ "MOV16sf\000"
  /* 7938 */ "SUB32ai\000"
  /* 7946 */ "ADD32ai\000"
  /* 7954 */ "MOV32ai\000"
  /* 7962 */ "MOV16ai\000"
  /* 7970 */ "CMP32bi\000"
  /* 7978 */ "MOV32bi\000"
  /* 7986 */ "CMP16bi\000"
  /* 7994 */ "MOV16bi\000"
  /* 8002 */ "CMP8bi\000"
  /* 8009 */ "MOV8bi\000"
  /* 8016 */ "SUB32di\000"
  /* 8024 */ "ADD32di\000"
  /* 8032 */ "AND32di\000"
  /* 8040 */ "BCHG32di\000"
  /* 8049 */ "SHL32di\000"
  /* 8057 */ "ROL32di\000"
  /* 8065 */ "CMP32di\000"
  /* 8073 */ "BCLR32di\000"
  /* 8082 */ "ROR32di\000"
  /* 8090 */ "XOR32di\000"
  /* 8098 */ "ASR32di\000"
  /* 8106 */ "LSR32di\000"
  /* 8114 */ "BSET32di\000"
  /* 8123 */ "BTST32di\000"
  /* 8132 */ "MOV32di\000"
  /* 8140 */ "SUB16di\000"
  /* 8148 */ "ADD16di\000"
  /* 8156 */ "AND16di\000"
  /* 8164 */ "SHL16di\000"
  /* 8172 */ "ROL16di\000"
  /* 8180 */ "CMP16di\000"
  /* 8188 */ "ROR16di\000"
  /* 8196 */ "XOR16di\000"
  /* 8204 */ "ASR16di\000"
  /* 8212 */ "LSR16di\000"
  /* 8220 */ "MOV16di\000"
  /* 8228 */ "SUB8di\000"
  /* 8235 */ "ADD8di\000"
  /* 8242 */ "AND8di\000"
  /* 8249 */ "MOVI8di\000"
  /* 8257 */ "SHL8di\000"
  /* 8264 */ "ROL8di\000"
  /* 8271 */ "CMP8di\000"
  /* 8278 */ "ROR8di\000"
  /* 8285 */ "XOR8di\000"
  /* 8292 */ "ASR8di\000"
  /* 8299 */ "LSR8di\000"
  /* 8306 */ "MOV8di\000"
  /* 8313 */ "MOV32ei\000"
  /* 8321 */ "MOV16ei\000"
  /* 8329 */ "BCHG8ei\000"
  /* 8337 */ "BCLR8ei\000"
  /* 8345 */ "BSET8ei\000"
  /* 8353 */ "BTST8ei\000"
  /* 8361 */ "MOV8ei\000"
  /* 8368 */ "SUB32fi\000"
  /* 8376 */ "ADD32fi\000"
  /* 8384 */ "AND32fi\000"
  /* 8392 */ "CMP32fi\000"
  /* 8400 */ "OR32fi\000"
  /* 8407 */ "MOV32fi\000"
  /* 8415 */ "SUB16fi\000"
  /* 8423 */ "ADD16fi\000"
  /* 8431 */ "AND16fi\000"
  /* 8439 */ "CMP16fi\000"
  /* 8447 */ "OR16fi\000"
  /* 8454 */ "MOV16fi\000"
  /* 8462 */ "SUB8fi\000"
  /* 8469 */ "ADD8fi\000"
  /* 8476 */ "AND8fi\000"
  /* 8483 */ "BCHG8fi\000"
  /* 8491 */ "CMP8fi\000"
  /* 8498 */ "BCLR8fi\000"
  /* 8506 */ "OR8fi\000"
  /* 8512 */ "BSET8fi\000"
  /* 8520 */ "BTST8fi\000"
  /* 8528 */ "MOV8fi\000"
  /* 8535 */ "SETd8hi\000"
  /* 8543 */ "SETj8hi\000"
  /* 8551 */ "SETp8hi\000"
  /* 8559 */ "SUB32ji\000"
  /* 8567 */ "ADD32ji\000"
  /* 8575 */ "AND32ji\000"
  /* 8583 */ "CMP32ji\000"
  /* 8591 */ "OR32ji\000"
  /* 8598 */ "MOV32ji\000"
  /* 8606 */ "SUB16ji\000"
  /* 8614 */ "ADD16ji\000"
  /* 8622 */ "AND16ji\000"
  /* 8630 */ "CMP16ji\000"
  /* 8638 */ "OR16ji\000"
  /* 8645 */ "MOV16ji\000"
  /* 8653 */ "SUB8ji\000"
  /* 8660 */ "ADD8ji\000"
  /* 8667 */ "AND8ji\000"
  /* 8674 */ "BCHG8ji\000"
  /* 8682 */ "CMP8ji\000"
  /* 8689 */ "BCLR8ji\000"
  /* 8697 */ "OR8ji\000"
  /* 8703 */ "BSET8ji\000"
  /* 8711 */ "BTST8ji\000"
  /* 8719 */ "MOV8ji\000"
  /* 8726 */ "CMP32ki\000"
  /* 8734 */ "CMP16ki\000"
  /* 8742 */ "CMP8ki\000"
  /* 8749 */ "BTST8ki\000"
  /* 8757 */ "SETd8mi\000"
  /* 8765 */ "SETj8mi\000"
  /* 8773 */ "SETp8mi\000"
  /* 8781 */ "MOV32oi\000"
  /* 8789 */ "MOV16oi\000"
  /* 8797 */ "BCHG8oi\000"
  /* 8805 */ "BCLR8oi\000"
  /* 8813 */ "BSET8oi\000"
  /* 8821 */ "BTST8oi\000"
  /* 8829 */ "MOV8oi\000"
  /* 8836 */ "SUB32pi\000"
  /* 8844 */ "ADD32pi\000"
  /* 8852 */ "AND32pi\000"
  /* 8860 */ "CMP32pi\000"
  /* 8868 */ "OR32pi\000"
  /* 8875 */ "MOV32pi\000"
  /* 8883 */ "SUB16pi\000"
  /* 8891 */ "ADD16pi\000"
  /* 8899 */ "AND16pi\000"
  /* 8907 */ "CMP16pi\000"
  /* 8915 */ "OR16pi\000"
  /* 8922 */ "MOV16pi\000"
  /* 8930 */ "SUB8pi\000"
  /* 8937 */ "ADD8pi\000"
  /* 8944 */ "AND8pi\000"
  /* 8951 */ "BCHG8pi\000"
  /* 8959 */ "CMP8pi\000"
  /* 8966 */ "BCLR8pi\000"
  /* 8974 */ "OR8pi\000"
  /* 8980 */ "BSET8pi\000"
  /* 8988 */ "BTST8pi\000"
  /* 8996 */ "MOV8pi\000"
  /* 9003 */ "FMOVE32a_fpi\000"
  /* 9016 */ "CMP32qi\000"
  /* 9024 */ "CMP16qi\000"
  /* 9032 */ "CMP8qi\000"
  /* 9039 */ "BTST8qi\000"
  /* 9047 */ "MOVI32ri\000"
  /* 9056 */ "MOV32ri\000"
  /* 9064 */ "MOVI16ri\000"
  /* 9073 */ "MOV16ri\000"
  /* 9081 */ "JMP32j\000"
  /* 9088 */ "CALLj\000"
  /* 9094 */ "TCRETURNj\000"
  /* 9104 */ "TAILJMPj\000"
  /* 9113 */ "SUB32aj\000"
  /* 9121 */ "ADD32aj\000"
  /* 9129 */ "MOV32aj\000"
  /* 9137 */ "MOV16aj\000"
  /* 9145 */ "MOV32bj\000"
  /* 9153 */ "MOV16bj\000"
  /* 9161 */ "MOV8bj\000"
  /* 9168 */ "MOV16cj\000"
  /* 9176 */ "MOV8cj\000"
  /* 9183 */ "SUB32dj\000"
  /* 9191 */ "ADD32dj\000"
  /* 9199 */ "AND32dj\000"
  /* 9207 */ "CMP32dj\000"
  /* 9215 */ "OR32dj\000"
  /* 9222 */ "MOV32dj\000"
  /* 9230 */ "SUB16dj\000"
  /* 9238 */ "ADD16dj\000"
  /* 9246 */ "AND16dj\000"
  /* 9254 */ "CMP16dj\000"
  /* 9262 */ "OR16dj\000"
  /* 9269 */ "MOV16dj\000"
  /* 9277 */ "SUB8dj\000"
  /* 9284 */ "ADD8dj\000"
  /* 9291 */ "AND8dj\000"
  /* 9298 */ "CMP8dj\000"
  /* 9305 */ "OR8dj\000"
  /* 9311 */ "MOV8dj\000"
  /* 9318 */ "MOV32ej\000"
  /* 9326 */ "MOV16ej\000"
  /* 9334 */ "MOV8ej\000"
  /* 9341 */ "MOV32fj\000"
  /* 9349 */ "MOV16fj\000"
  /* 9357 */ "MOV8fj\000"
  /* 9364 */ "MOV32jj\000"
  /* 9372 */ "MOV16jj\000"
  /* 9380 */ "MOV8jj\000"
  /* 9387 */ "MOVM32mj\000"
  /* 9396 */ "MOVM16mj\000"
  /* 9405 */ "MOV32oj\000"
  /* 9413 */ "MOV16oj\000"
  /* 9421 */ "MOV8oj\000"
  /* 9428 */ "MOV32pj\000"
  /* 9436 */ "MOV16pj\000"
  /* 9444 */ "MOV8pj\000"
  /* 9451 */ "MOV32rj\000"
  /* 9459 */ "MOV16rj\000"
  /* 9467 */ "MOV16sj\000"
  /* 9475 */ "LEA32k\000"
  /* 9482 */ "CALLk\000"
  /* 9488 */ "SUB32ak\000"
  /* 9496 */ "ADD32ak\000"
  /* 9504 */ "MOV32ak\000"
  /* 9512 */ "MOV16ak\000"
  /* 9520 */ "MOV32bk\000"
  /* 9528 */ "MOV16bk\000"
  /* 9536 */ "MOV8bk\000"
  /* 9543 */ "MOV16ck\000"
  /* 9551 */ "MOV8ck\000"
  /* 9558 */ "SUB32dk\000"
  /* 9566 */ "ADD32dk\000"
  /* 9574 */ "AND32dk\000"
  /* 9582 */ "CMP32dk\000"
  /* 9590 */ "OR32dk\000"
  /* 9597 */ "MOV32dk\000"
  /* 9605 */ "SUB16dk\000"
  /* 9613 */ "ADD16dk\000"
  /* 9621 */ "AND16dk\000"
  /* 9629 */ "CMP16dk\000"
  /* 9637 */ "OR16dk\000"
  /* 9644 */ "MOV16dk\000"
  /* 9652 */ "SUB8dk\000"
  /* 9659 */ "ADD8dk\000"
  /* 9666 */ "AND8dk\000"
  /* 9673 */ "CMP8dk\000"
  /* 9680 */ "OR8dk\000"
  /* 9686 */ "MOV8dk\000"
  /* 9693 */ "MOV32ek\000"
  /* 9701 */ "MOV16ek\000"
  /* 9709 */ "MOV8ek\000"
  /* 9716 */ "MOV32fk\000"
  /* 9724 */ "MOV16fk\000"
  /* 9732 */ "MOV8fk\000"
  /* 9739 */ "MOV32jk\000"
  /* 9747 */ "MOV16jk\000"
  /* 9755 */ "MOV8jk\000"
  /* 9762 */ "MOVM32mk\000"
  /* 9771 */ "MOVM16mk\000"
  /* 9780 */ "MOV32ok\000"
  /* 9788 */ "MOV16ok\000"
  /* 9796 */ "MOV8ok\000"
  /* 9803 */ "MOV32pk\000"
  /* 9811 */ "MOV16pk\000"
  /* 9819 */ "MOV8pk\000"
  /* 9826 */ "MOV32rk\000"
  /* 9834 */ "MOV16rk\000"
  /* 9842 */ "MOV16sk\000"
  /* 9850 */ "LEA32l\000"
  /* 9857 */ "CALLl\000"
  /* 9863 */ "SETd8pl\000"
  /* 9871 */ "SETj8pl\000"
  /* 9879 */ "SETp8pl\000"
  /* 9887 */ "MOVM32bm\000"
  /* 9896 */ "MOVM16bm\000"
  /* 9905 */ "MOVM32em\000"
  /* 9914 */ "MOVM16em\000"
  /* 9923 */ "MOVM32fm\000"
  /* 9932 */ "MOVM16fm\000"
  /* 9941 */ "MOVM32jm\000"
  /* 9950 */ "MOVM16jm\000"
  /* 9959 */ "MOVM32om\000"
  /* 9968 */ "MOVM16om\000"
  /* 9977 */ "MOVM32pm\000"
  /* 9986 */ "MOVM16pm\000"
  /* 9995 */ "MOV32ao\000"
  /* 10003 */ "MOV16ao\000"
  /* 10011 */ "MOV32bo\000"
  /* 10019 */ "MOV16bo\000"
  /* 10027 */ "MOV8bo\000"
  /* 10034 */ "MOV16co\000"
  /* 10042 */ "MOV8co\000"
  /* 10049 */ "MOV32do\000"
  /* 10057 */ "MOV16do\000"
  /* 10065 */ "MOV8do\000"
  /* 10072 */ "MOV32eo\000"
  /* 10080 */ "MOV16eo\000"
  /* 10088 */ "MOV8eo\000"
  /* 10095 */ "MOV32fo\000"
  /* 10103 */ "MOV16fo\000"
  /* 10111 */ "MOV8fo\000"
  /* 10118 */ "MOV32jo\000"
  /* 10126 */ "MOV16jo\000"
  /* 10134 */ "MOV8jo\000"
  /* 10141 */ "MOVM32mo\000"
  /* 10150 */ "MOVM16mo\000"
  /* 10159 */ "MOV32oo\000"
  /* 10167 */ "MOV16oo\000"
  /* 10175 */ "MOV8oo\000"
  /* 10182 */ "MOV32po\000"
  /* 10190 */ "MOV16po\000"
  /* 10198 */ "MOV8po\000"
  /* 10205 */ "MOV32ro\000"
  /* 10213 */ "MOV16ro\000"
  /* 10221 */ "MOV16so\000"
  /* 10229 */ "LEA32p\000"
  /* 10236 */ "CALLp\000"
  /* 10242 */ "SUB32ap\000"
  /* 10250 */ "ADD32ap\000"
  /* 10258 */ "MOV32ap\000"
  /* 10266 */ "MOV16ap\000"
  /* 10274 */ "MOV32bp\000"
  /* 10282 */ "MOV16bp\000"
  /* 10290 */ "MOV8bp\000"
  /* 10297 */ "MOV16cp\000"
  /* 10305 */ "MOV8cp\000"
  /* 10312 */ "SUB32dp\000"
  /* 10320 */ "ADD32dp\000"
  /* 10328 */ "AND32dp\000"
  /* 10336 */ "CMP32dp\000"
  /* 10344 */ "OR32dp\000"
  /* 10351 */ "MOV32dp\000"
  /* 10359 */ "SUB16dp\000"
  /* 10367 */ "ADD16dp\000"
  /* 10375 */ "AND16dp\000"
  /* 10383 */ "CMP16dp\000"
  /* 10391 */ "OR16dp\000"
  /* 10398 */ "MOV16dp\000"
  /* 10406 */ "SUB8dp\000"
  /* 10413 */ "ADD8dp\000"
  /* 10420 */ "AND8dp\000"
  /* 10427 */ "CMP8dp\000"
  /* 10434 */ "OR8dp\000"
  /* 10440 */ "MOV8dp\000"
  /* 10447 */ "MOV32ep\000"
  /* 10455 */ "MOV16ep\000"
  /* 10463 */ "MOV8ep\000"
  /* 10470 */ "MOV32fp\000"
  /* 10478 */ "MOV16fp\000"
  /* 10486 */ "MOV8fp\000"
  /* 10493 */ "FDSUB80fp_fp\000"
  /* 10506 */ "FSUB80fp_fp\000"
  /* 10518 */ "FSSUB80fp_fp\000"
  /* 10531 */ "FDADD80fp_fp\000"
  /* 10544 */ "FADD80fp_fp\000"
  /* 10556 */ "FSADD80fp_fp\000"
  /* 10569 */ "FDNEG80fp_fp\000"
  /* 10582 */ "FNEG80fp_fp\000"
  /* 10594 */ "FSNEG80fp_fp\000"
  /* 10607 */ "FDMUL80fp_fp\000"
  /* 10620 */ "FMUL80fp_fp\000"
  /* 10632 */ "FSMUL80fp_fp\000"
  /* 10645 */ "FDABS80fp_fp\000"
  /* 10658 */ "FABS80fp_fp\000"
  /* 10670 */ "FSABS80fp_fp\000"
  /* 10683 */ "FDDIV80fp_fp\000"
  /* 10696 */ "FDIV80fp_fp\000"
  /* 10708 */ "FSDIV80fp_fp\000"
  /* 10721 */ "FDMOV80fp_fp\000"
  /* 10734 */ "FMOV80fp_fp\000"
  /* 10746 */ "FSMOV80fp_fp\000"
  /* 10759 */ "FDSUB32fp_fp\000"
  /* 10772 */ "FSUB32fp_fp\000"
  /* 10784 */ "FSSUB32fp_fp\000"
  /* 10797 */ "FDADD32fp_fp\000"
  /* 10810 */ "FADD32fp_fp\000"
  /* 10822 */ "FSADD32fp_fp\000"
  /* 10835 */ "FDNEG32fp_fp\000"
  /* 10848 */ "FNEG32fp_fp\000"
  /* 10860 */ "FSNEG32fp_fp\000"
  /* 10873 */ "FDMUL32fp_fp\000"
  /* 10886 */ "FMUL32fp_fp\000"
  /* 10898 */ "FSMUL32fp_fp\000"
  /* 10911 */ "FDABS32fp_fp\000"
  /* 10924 */ "FABS32fp_fp\000"
  /* 10936 */ "FSABS32fp_fp\000"
  /* 10949 */ "FDDIV32fp_fp\000"
  /* 10962 */ "FDIV32fp_fp\000"
  /* 10974 */ "FSDIV32fp_fp\000"
  /* 10987 */ "FDMOV32fp_fp\000"
  /* 11000 */ "FMOV32fp_fp\000"
  /* 11012 */ "FSMOV32fp_fp\000"
  /* 11025 */ "FDSUB64fp_fp\000"
  /* 11038 */ "FSUB64fp_fp\000"
  /* 11050 */ "FSSUB64fp_fp\000"
  /* 11063 */ "FDADD64fp_fp\000"
  /* 11076 */ "FADD64fp_fp\000"
  /* 11088 */ "FSADD64fp_fp\000"
  /* 11101 */ "FDNEG64fp_fp\000"
  /* 11114 */ "FNEG64fp_fp\000"
  /* 11126 */ "FSNEG64fp_fp\000"
  /* 11139 */ "FDMUL64fp_fp\000"
  /* 11152 */ "FMUL64fp_fp\000"
  /* 11164 */ "FSMUL64fp_fp\000"
  /* 11177 */ "FDABS64fp_fp\000"
  /* 11190 */ "FABS64fp_fp\000"
  /* 11202 */ "FSABS64fp_fp\000"
  /* 11215 */ "FDDIV64fp_fp\000"
  /* 11228 */ "FDIV64fp_fp\000"
  /* 11240 */ "FSDIV64fp_fp\000"
  /* 11253 */ "FDMOV64fp_fp\000"
  /* 11266 */ "FMOV64fp_fp\000"
  /* 11278 */ "FSMOV64fp_fp\000"
  /* 11291 */ "MOV32jp\000"
  /* 11299 */ "MOV16jp\000"
  /* 11307 */ "MOV8jp\000"
  /* 11314 */ "MOVM32mp\000"
  /* 11323 */ "MOVM16mp\000"
  /* 11332 */ "MOV32op\000"
  /* 11340 */ "MOV16op\000"
  /* 11348 */ "MOV8op\000"
  /* 11355 */ "MOV32pp\000"
  /* 11363 */ "MOV16pp\000"
  /* 11371 */ "MOV8pp\000"
  /* 11378 */ "MOV32rp\000"
  /* 11386 */ "MOV16rp\000"
  /* 11394 */ "MOV16sp\000"
  /* 11402 */ "LEA32q\000"
  /* 11409 */ "CALLq\000"
  /* 11415 */ "TCRETURNq\000"
  /* 11425 */ "TAILJMPq\000"
  /* 11434 */ "SUB32aq\000"
  /* 11442 */ "ADD32aq\000"
  /* 11450 */ "MOV32aq\000"
  /* 11458 */ "MOV16aq\000"
  /* 11466 */ "MOV32bq\000"
  /* 11474 */ "MOV16bq\000"
  /* 11482 */ "MOV8bq\000"
  /* 11489 */ "MOV16cq\000"
  /* 11497 */ "MOV8cq\000"
  /* 11504 */ "SUB32dq\000"
  /* 11512 */ "ADD32dq\000"
  /* 11520 */ "AND32dq\000"
  /* 11528 */ "CMP32dq\000"
  /* 11536 */ "OR32dq\000"
  /* 11543 */ "MOV32dq\000"
  /* 11551 */ "SUB16dq\000"
  /* 11559 */ "ADD16dq\000"
  /* 11567 */ "AND16dq\000"
  /* 11575 */ "CMP16dq\000"
  /* 11583 */ "OR16dq\000"
  /* 11590 */ "MOV16dq\000"
  /* 11598 */ "SUB8dq\000"
  /* 11605 */ "ADD8dq\000"
  /* 11612 */ "AND8dq\000"
  /* 11619 */ "CMP8dq\000"
  /* 11626 */ "OR8dq\000"
  /* 11632 */ "MOV8dq\000"
  /* 11639 */ "MOV32eq\000"
  /* 11647 */ "MOV16eq\000"
  /* 11655 */ "MOV8eq\000"
  /* 11662 */ "SETd8eq\000"
  /* 11670 */ "SETj8eq\000"
  /* 11678 */ "SETp8eq\000"
  /* 11686 */ "MOV32fq\000"
  /* 11694 */ "MOV16fq\000"
  /* 11702 */ "MOV8fq\000"
  /* 11709 */ "MOV32jq\000"
  /* 11717 */ "MOV16jq\000"
  /* 11725 */ "MOV8jq\000"
  /* 11732 */ "MOVM32mq\000"
  /* 11741 */ "MOVM16mq\000"
  /* 11750 */ "MOV32oq\000"
  /* 11758 */ "MOV16oq\000"
  /* 11766 */ "MOV8oq\000"
  /* 11773 */ "MOV32pq\000"
  /* 11781 */ "MOV16pq\000"
  /* 11789 */ "MOV8pq\000"
  /* 11796 */ "MOV32rq\000"
  /* 11804 */ "MOV16rq\000"
  /* 11812 */ "MOV16sq\000"
  /* 11820 */ "PUSH32r\000"
  /* 11828 */ "POP32r\000"
  /* 11835 */ "CMOV32r\000"
  /* 11843 */ "SUB32ar\000"
  /* 11851 */ "ADD32ar\000"
  /* 11859 */ "MOV32ar\000"
  /* 11867 */ "MOV16ar\000"
  /* 11875 */ "MOV32br\000"
  /* 11883 */ "MOV16br\000"
  /* 11891 */ "SUB32dr\000"
  /* 11899 */ "ADD32dr\000"
  /* 11907 */ "AND32dr\000"
  /* 11915 */ "CMP32dr\000"
  /* 11923 */ "OR32dr\000"
  /* 11930 */ "SUB16dr\000"
  /* 11938 */ "ADD16dr\000"
  /* 11946 */ "AND16dr\000"
  /* 11954 */ "CMP16dr\000"
  /* 11962 */ "OR16dr\000"
  /* 11969 */ "MOV32er\000"
  /* 11977 */ "MOV16er\000"
  /* 11985 */ "MOV32fr\000"
  /* 11993 */ "MOV16fr\000"
  /* 12001 */ "MOV32jr\000"
  /* 12009 */ "MOV16jr\000"
  /* 12017 */ "MOV32or\000"
  /* 12025 */ "MOV16or\000"
  /* 12033 */ "MOV32pr\000"
  /* 12041 */ "MOV16pr\000"
  /* 12049 */ "MOV32rr\000"
  /* 12057 */ "MOV16rr\000"
  /* 12065 */ "MOV16bs\000"
  /* 12073 */ "SETd8cs\000"
  /* 12081 */ "SETj8cs\000"
  /* 12089 */ "SETp8cs\000"
  /* 12097 */ "FMOVE32d_fpcs\000"
  /* 12111 */ "MOV16ds\000"
  /* 12119 */ "MOV16es\000"
  /* 12127 */ "MOV16fs\000"
  /* 12135 */ "MOV16js\000"
  /* 12143 */ "SETd8ls\000"
  /* 12151 */ "SETj8ls\000"
  /* 12159 */ "SETp8ls\000"
  /* 12167 */ "MOV16os\000"
  /* 12175 */ "MOV16ps\000"
  /* 12183 */ "SETd8vs\000"
  /* 12191 */ "SETj8vs\000"
  /* 12199 */ "SETp8vs\000"
  /* 12207 */ "SETd8t\000"
  /* 12214 */ "SETj8t\000"
  /* 12221 */ "SETp8t\000"
  /* 12228 */ "SETd8gt\000"
  /* 12236 */ "SETj8gt\000"
  /* 12244 */ "SETp8gt\000"
  /* 12252 */ "SETd8lt\000"
  /* 12260 */ "SETj8lt\000"
  /* 12268 */ "SETp8lt\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned M68kInstrNameIndices[] = {
    2572U, 3006U, 3944U, 3412U, 2665U, 2646U, 2674U, 2834U, 
    2365U, 2380U, 2331U, 2318U, 2407U, 4486U, 2194U, 5182U, 
    2344U, 2568U, 2655U, 1929U, 5571U, 2607U, 2051U, 5086U, 
    1756U, 1880U, 1917U, 3561U, 2822U, 4991U, 1863U, 3786U, 
    2500U, 4980U, 2101U, 3759U, 3746U, 4005U, 4839U, 4862U, 
    2754U, 2801U, 2774U, 2691U, 2181U, 3970U, 3515U, 2090U, 
    5576U, 4123U, 3717U, 2242U, 5212U, 5242U, 3255U, 1669U, 
    1016U, 2945U, 5314U, 5321U, 2972U, 2979U, 2986U, 2996U, 
    1734U, 4332U, 4295U, 4383U, 5256U, 4167U, 2743U, 4155U, 
    2732U, 2329U, 2570U, 5494U, 2204U, 2219U, 2839U, 4807U, 
    4390U, 5123U, 4407U, 4218U, 1086U, 4469U, 5002U, 4359U, 
    5155U, 2285U, 3981U, 1837U, 1060U, 1819U, 5040U, 5021U, 
    3233U, 4030U, 4049U, 1570U, 1514U, 1544U, 1483U, 1555U, 
    1495U, 1525U, 2160U, 2114U, 2144U, 4516U, 2421U, 2438U, 
    1685U, 1022U, 1740U, 1701U, 4337U, 4301U, 5478U, 3381U, 
    5461U, 3364U, 1636U, 999U, 5396U, 3299U, 3101U, 3048U, 
    3174U, 3136U, 3623U, 3601U, 1778U, 4760U, 1909U, 2517U, 
    1769U, 4826U, 5101U, 1038U, 4564U, 4957U, 4591U, 5226U, 
    1078U, 4633U, 5263U, 5278U, 4946U, 4934U, 5076U, 2492U, 
    5205U, 2394U, 5235U, 2718U, 4116U, 4102U, 2711U, 4109U, 
    4352U, 2855U, 3692U, 3671U, 3699U, 3706U, 4817U, 3507U, 
    1950U, 3491U, 1901U, 3499U, 1942U, 3483U, 1893U, 3545U, 
    3537U, 2536U, 2528U, 4678U, 4668U, 4658U, 4648U, 4698U, 
    4688U, 5522U, 5532U, 4708U, 4721U, 5542U, 5552U, 4734U, 
    4747U, 1594U, 978U, 2879U, 959U, 1476U, 5293U, 2951U, 
    2310U, 5372U, 2594U, 3830U, 225U, 9U, 2485U, 208U, 
    0U, 3805U, 3837U, 2358U, 5197U, 1050U, 2576U, 2585U, 
    3653U, 3662U, 4781U, 4794U, 4370U, 3270U, 4503U, 2294U, 
    3198U, 3208U, 1999U, 2014U, 3037U, 3090U, 3122U, 3160U, 
    5328U, 5354U, 5340U, 1958U, 1986U, 1971U, 2455U, 2470U, 
    1675U, 2621U, 3333U, 5430U, 3357U, 5454U, 4377U, 1810U, 
    1800U, 3939U, 4886U, 2029U, 4199U, 4179U, 4914U, 4893U, 
    4233U, 4264U, 4250U, 4546U, 5605U, 3447U, 5598U, 3428U, 
    4422U, 3738U, 3645U, 2168U, 2921U, 2724U, 4437U, 3405U, 
    4444U, 3226U, 4429U, 3397U, 3218U, 216U, 2560U, 2552U, 
    2544U, 5132U, 4146U, 5013U, 5058U, 5165U, 3957U, 2038U, 
    1107U, 2263U, 2129U, 1622U, 985U, 2907U, 5300U, 2958U, 
    965U, 5140U, 3814U, 3678U, 4454U, 4069U, 4085U, 5562U, 
    2074U, 2275U, 4853U, 3553U, 2058U, 3594U, 3570U, 3582U, 
    1601U, 2886U, 1577U, 2862U, 5379U, 3282U, 3069U, 3016U, 
    1653U, 2929U, 1718U, 4317U, 4279U, 5413U, 3316U, 5437U, 
    3340U, 5508U, 5515U, 3466U, 3771U, 6235U, 11835U, 6286U, 
    6024U, 5829U, 7283U, 7639U, 9176U, 9551U, 10042U, 10305U, 
    11497U, 6071U, 6086U, 6101U, 6116U, 6131U, 9064U, 9047U, 
    8249U, 3879U, 3857U, 3923U, 3901U, 3868U, 3846U, 3912U, 
    3890U, 683U, 752U, 806U, 855U, 899U, 351U, 651U, 
    404U, 730U, 484U, 784U, 514U, 833U, 538U, 877U, 
    694U, 363U, 662U, 704U, 763U, 817U, 866U, 910U, 
    374U, 672U, 416U, 741U, 496U, 795U, 526U, 844U, 
    550U, 888U, 6221U, 11828U, 6274U, 6213U, 11820U, 6267U, 
    4849U, 951U, 6195U, 6162U, 6251U, 9104U, 11425U, 9094U, 
    11415U, 6487U, 7701U, 8148U, 9238U, 9613U, 10367U, 11559U, 
    11938U, 6772U, 8423U, 6916U, 8614U, 7123U, 8891U, 5774U, 
    7584U, 7946U, 9121U, 9496U, 10250U, 11442U, 11851U, 6353U, 
    7654U, 8024U, 9191U, 9566U, 10320U, 11512U, 11899U, 6733U, 
    8376U, 6877U, 8567U, 7084U, 8844U, 6584U, 7747U, 8235U, 
    9284U, 9659U, 10413U, 11605U, 6810U, 8469U, 6954U, 8660U, 
    7161U, 8937U, 6568U, 6470U, 6662U, 6495U, 7709U, 8156U, 
    9246U, 9621U, 10375U, 11567U, 11946U, 6780U, 8431U, 6924U, 
    8622U, 7131U, 8899U, 6361U, 7662U, 8032U, 9199U, 9574U, 
    10328U, 11520U, 11907U, 6741U, 8384U, 6885U, 8575U, 7092U, 
    8852U, 6591U, 7754U, 8242U, 9291U, 9666U, 10420U, 11612U, 
    6817U, 8476U, 6961U, 8667U, 7168U, 8944U, 6535U, 8204U, 
    6419U, 8098U, 6633U, 8292U, 6369U, 8040U, 6686U, 8329U, 
    6824U, 8483U, 6968U, 8674U, 7037U, 8797U, 7175U, 8951U, 
    6394U, 8073U, 6694U, 8337U, 6832U, 8498U, 6976U, 8689U, 
    7045U, 8805U, 7183U, 8966U, 5071U, 233U, 18U, 598U, 
    6435U, 8114U, 6702U, 8345U, 6846U, 8512U, 6990U, 8703U, 
    7053U, 8813U, 7197U, 8980U, 283U, 68U, 636U, 6444U, 
    8123U, 6710U, 8353U, 6854U, 8520U, 6998U, 8711U, 7013U, 
    8749U, 7061U, 8821U, 7205U, 8988U, 7220U, 9039U, 295U, 
    80U, 641U, 568U, 178U, 926U, 562U, 172U, 921U, 
    386U, 136U, 715U, 586U, 196U, 941U, 472U, 154U, 
    774U, 392U, 142U, 720U, 574U, 184U, 931U, 592U, 
    202U, 946U, 478U, 160U, 779U, 398U, 148U, 725U, 
    508U, 166U, 828U, 301U, 86U, 646U, 580U, 190U, 
    936U, 5760U, 7570U, 9088U, 9482U, 9857U, 10236U, 11409U, 
    275U, 60U, 629U, 259U, 44U, 621U, 239U, 24U, 
    603U, 249U, 34U, 612U, 7986U, 7717U, 8180U, 9254U, 
    9629U, 10383U, 11575U, 11954U, 8439U, 8630U, 8734U, 8907U, 
    9024U, 7970U, 7670U, 8065U, 9207U, 9582U, 10336U, 11528U, 
    11915U, 8392U, 8583U, 8726U, 8860U, 9016U, 8002U, 6612U, 
    7761U, 8271U, 9298U, 9673U, 10427U, 11619U, 8491U, 8682U, 
    8742U, 8959U, 9032U, 289U, 74U, 10924U, 11190U, 10658U, 
    10810U, 11076U, 10544U, 10911U, 11177U, 10645U, 10797U, 11063U, 
    10531U, 10949U, 11215U, 10683U, 10962U, 11228U, 10696U, 10987U, 
    11253U, 10721U, 10873U, 11139U, 10607U, 10835U, 11101U, 10569U, 
    10759U, 11025U, 10493U, 11000U, 11266U, 10734U, 9003U, 12097U, 
    6300U, 5612U, 10886U, 11152U, 10620U, 10848U, 11114U, 10582U, 
    10936U, 11202U, 10670U, 10822U, 11088U, 10556U, 10974U, 11240U, 
    10708U, 11012U, 11278U, 10746U, 10898U, 11164U, 10632U, 10860U, 
    11126U, 10594U, 10784U, 11050U, 10518U, 10772U, 11038U, 10506U, 
    2638U, 9081U, 2631U, 5753U, 7542U, 9475U, 9850U, 10229U, 
    11402U, 268U, 53U, 6543U, 8212U, 6427U, 8106U, 6640U, 
    8299U, 5633U, 5790U, 1135U, 7244U, 1179U, 7600U, 1223U, 
    7962U, 9137U, 1267U, 9512U, 1311U, 10003U, 1355U, 10266U, 
    1399U, 11458U, 1443U, 11867U, 5649U, 5806U, 6016U, 6322U, 
    7260U, 7616U, 7994U, 9153U, 9528U, 10019U, 10282U, 11474U, 
    11883U, 12065U, 5821U, 6337U, 7275U, 7631U, 9168U, 9543U, 
    10034U, 10297U, 11489U, 5844U, 6055U, 6551U, 7298U, 7732U, 
    8220U, 9269U, 9644U, 10057U, 10398U, 11590U, 12111U, 5665U, 
    5867U, 6063U, 6678U, 7321U, 7789U, 8321U, 9326U, 9701U, 
    10080U, 10455U, 11647U, 11977U, 12119U, 5681U, 5890U, 6078U, 
    6795U, 7344U, 7812U, 8454U, 9349U, 9724U, 10103U, 10478U, 
    11694U, 11993U, 12127U, 5697U, 5913U, 6093U, 6939U, 7391U, 
    7835U, 8645U, 9372U, 9747U, 10126U, 11299U, 11717U, 12009U, 
    12135U, 5713U, 5954U, 6108U, 7029U, 7480U, 7876U, 8789U, 
    9413U, 9788U, 10167U, 11340U, 11758U, 12025U, 12167U, 5729U, 
    5977U, 6123U, 7146U, 7503U, 7899U, 8922U, 9436U, 9811U, 
    10190U, 11363U, 11781U, 12041U, 12175U, 5745U, 6000U, 1157U, 
    7526U, 1201U, 7922U, 1245U, 9073U, 9459U, 1289U, 9834U, 
    1333U, 10213U, 1377U, 11386U, 1421U, 11804U, 1465U, 12057U, 
    6008U, 7228U, 7534U, 7930U, 9467U, 9842U, 10221U, 11394U, 
    11812U, 5625U, 5782U, 1124U, 7236U, 1168U, 7592U, 1212U, 
    7954U, 9129U, 1256U, 9504U, 1300U, 9995U, 1344U, 10258U, 
    1388U, 11450U, 1432U, 11859U, 5641U, 5798U, 6314U, 7252U, 
    7608U, 7978U, 9145U, 9520U, 10011U, 10274U, 11466U, 11875U, 
    5836U, 6453U, 7290U, 7685U, 8132U, 9222U, 9597U, 10049U, 
    10351U, 11543U, 5657U, 5859U, 6670U, 7313U, 7781U, 8313U, 
    9318U, 9693U, 10072U, 10447U, 11639U, 11969U, 5673U, 5882U, 
    6756U, 7336U, 7804U, 8407U, 9341U, 9716U, 10095U, 10470U, 
    11686U, 11985U, 5689U, 5905U, 6900U, 7383U, 7827U, 8598U, 
    9364U, 9739U, 10118U, 11291U, 11709U, 12001U, 5705U, 5946U, 
    7021U, 7472U, 7868U, 8781U, 9405U, 9780U, 10159U, 11332U, 
    11750U, 12017U, 5721U, 5969U, 7107U, 7495U, 7891U, 8875U, 
    9428U, 9803U, 10182U, 11355U, 11773U, 12033U, 5737U, 5992U, 
    1146U, 7518U, 1190U, 7914U, 1234U, 9056U, 9451U, 1278U, 
    9826U, 1322U, 10205U, 1366U, 11378U, 1410U, 11796U, 1454U, 
    12049U, 5814U, 6330U, 7268U, 7624U, 8009U, 9161U, 9536U, 
    10027U, 10290U, 11482U, 5852U, 6647U, 7306U, 7774U, 8306U, 
    9311U, 9686U, 10065U, 10440U, 11632U, 5875U, 6718U, 7329U, 
    7797U, 8361U, 9334U, 9709U, 10088U, 10463U, 11655U, 5898U, 
    6862U, 7352U, 7820U, 8528U, 9357U, 9732U, 10111U, 10486U, 
    11702U, 5921U, 7006U, 7399U, 7843U, 8719U, 9380U, 9755U, 
    10134U, 11307U, 11725U, 5962U, 7069U, 7488U, 7884U, 8829U, 
    9421U, 9796U, 10175U, 11348U, 11766U, 5985U, 7213U, 7511U, 
    7907U, 8996U, 9444U, 9819U, 10198U, 11371U, 11789U, 9896U, 
    9914U, 9932U, 9950U, 5937U, 7439U, 7859U, 9396U, 9771U, 
    10150U, 11323U, 11741U, 9968U, 9986U, 9887U, 9905U, 9923U, 
    9941U, 5928U, 7430U, 7850U, 9387U, 9762U, 10141U, 11314U, 
    11732U, 9959U, 9977U, 3934U, 6206U, 6173U, 6261U, 6243U, 
    6187U, 6293U, 3713U, 6228U, 6180U, 6280U, 6520U, 7725U, 
    8189U, 9262U, 9637U, 10391U, 11583U, 11962U, 6788U, 8447U, 
    6932U, 8638U, 7139U, 8915U, 6404U, 7678U, 8083U, 9215U, 
    9590U, 10344U, 11536U, 11923U, 6749U, 8400U, 6893U, 8591U, 
    7100U, 8868U, 6620U, 7768U, 8279U, 9305U, 9680U, 10434U, 
    11626U, 6840U, 8506U, 6984U, 8697U, 7191U, 8974U, 6511U, 
    8172U, 6386U, 8057U, 6605U, 8264U, 6519U, 8188U, 6403U, 
    8082U, 6619U, 8278U, 2190U, 4629U, 329U, 114U, 450U, 
    6031U, 12073U, 11662U, 7549U, 7359U, 12228U, 8535U, 7406U, 
    12143U, 12252U, 8757U, 7448U, 9863U, 12207U, 6138U, 12183U, 
    6039U, 12081U, 11670U, 7556U, 7367U, 12236U, 8543U, 7414U, 
    12151U, 12260U, 8765U, 7456U, 9871U, 12214U, 6146U, 12191U, 
    6047U, 12089U, 11678U, 7563U, 7375U, 12244U, 8551U, 7422U, 
    12159U, 12268U, 8773U, 7464U, 9879U, 12221U, 6154U, 12199U, 
    6503U, 8164U, 6378U, 8049U, 6598U, 8257U, 307U, 92U, 
    428U, 6479U, 7693U, 8140U, 9230U, 9605U, 10359U, 11551U, 
    11930U, 6764U, 8415U, 6908U, 8606U, 7115U, 8883U, 5766U, 
    7576U, 7938U, 9113U, 9488U, 10242U, 11434U, 11843U, 6345U, 
    7646U, 8016U, 9183U, 9558U, 10312U, 11504U, 11891U, 6725U, 
    8368U, 6869U, 8559U, 7076U, 8836U, 6577U, 7740U, 8228U, 
    9277U, 9652U, 10406U, 11598U, 6803U, 8462U, 6947U, 8653U, 
    7154U, 8930U, 6559U, 6461U, 6654U, 3577U, 5366U, 340U, 
    125U, 461U, 318U, 103U, 439U, 2602U, 6527U, 8196U, 
    6411U, 8090U, 6626U, 8285U, 
};

static inline void InitM68kMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(M68kDescs.Insts, M68kInstrNameIndices, M68kInstrNameData, nullptr, nullptr, 1316, nullptr, 0);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct M68kGenInstrInfo : public TargetInstrInfo {
  explicit M68kGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~M68kGenInstrInfo() override = default;
};

} // namespace llvm_ks

namespace llvm_ks::M68k {

constexpr unsigned SUBOP_MxARID8_disp = 0;
constexpr unsigned SUBOP_MxARID8_reg = 1;
constexpr unsigned SUBOP_MxARID8_TC_disp = 0;
constexpr unsigned SUBOP_MxARID8_TC_reg = 1;
constexpr unsigned SUBOP_MxARID16_disp = 0;
constexpr unsigned SUBOP_MxARID16_reg = 1;
constexpr unsigned SUBOP_MxARID16_TC_disp = 0;
constexpr unsigned SUBOP_MxARID16_TC_reg = 1;
constexpr unsigned SUBOP_MxARID32_disp = 0;
constexpr unsigned SUBOP_MxARID32_reg = 1;
constexpr unsigned SUBOP_MxARID32_TC_disp = 0;
constexpr unsigned SUBOP_MxARID32_TC_reg = 1;
constexpr unsigned SUBOP_MxARII8_disp = 0;
constexpr unsigned SUBOP_MxARII8_reg = 1;
constexpr unsigned SUBOP_MxARII8_index = 2;
constexpr unsigned SUBOP_MxARII8_TC_disp = 0;
constexpr unsigned SUBOP_MxARII8_TC_reg = 1;
constexpr unsigned SUBOP_MxARII8_TC_index = 2;
constexpr unsigned SUBOP_MxARII16_disp = 0;
constexpr unsigned SUBOP_MxARII16_reg = 1;
constexpr unsigned SUBOP_MxARII16_index = 2;
constexpr unsigned SUBOP_MxARII16_TC_disp = 0;
constexpr unsigned SUBOP_MxARII16_TC_reg = 1;
constexpr unsigned SUBOP_MxARII16_TC_index = 2;
constexpr unsigned SUBOP_MxARII32_disp = 0;
constexpr unsigned SUBOP_MxARII32_reg = 1;
constexpr unsigned SUBOP_MxARII32_index = 2;
constexpr unsigned SUBOP_MxARII32_TC_disp = 0;
constexpr unsigned SUBOP_MxARII32_TC_reg = 1;
constexpr unsigned SUBOP_MxARII32_TC_index = 2;
constexpr unsigned SUBOP_MxPCI8_disp = 0;
constexpr unsigned SUBOP_MxPCI8_index = 1;
constexpr unsigned SUBOP_MxPCI16_disp = 0;
constexpr unsigned SUBOP_MxPCI16_index = 1;
constexpr unsigned SUBOP_MxPCI32_disp = 0;
constexpr unsigned SUBOP_MxPCI32_index = 1;
constexpr unsigned SUBOP_MxPCIBD16_disp = 0;
constexpr unsigned SUBOP_MxPCIBD16_index = 1;
constexpr unsigned SUBOP_MxPCIBD16_scale = 2;
constexpr unsigned SUBOP_MxPCIBD32_disp = 0;
constexpr unsigned SUBOP_MxPCIBD32_index = 1;
constexpr unsigned SUBOP_MxPCIBD32_scale = 2;

} // namespace llvm_ks::M68k

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

extern const M68kInstrTable M68kDescs;
extern const unsigned M68kInstrNameIndices[];
extern const char M68kInstrNameData[];
M68kGenInstrInfo::M68kGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(M68kDescs.Insts, M68kInstrNameIndices, M68kInstrNameData, nullptr, nullptr, 1316);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_LOGICAL_OPERAND_SIZE_MAP
#undef GET_INSTRINFO_LOGICAL_OPERAND_SIZE_MAP

namespace llvm_ks::M68k {

LLVM_READONLY static unsigned
getLogicalOperandSize(uint32_t Opcode, uint16_t LogicalOpIdx) {
  static const unsigned SizeMap[][4] = {
   {1, 1, 0, 0, }, 
   {1, 1, 1, 1, }, 
   {1, 3, 0, 0, }, 
   {1, 2, 0, 0, }, 
   {3, 1, 0, 0, }, 
   {2, 1, 0, 0, }, 
   {1, 0, 0, 0, }, 
   {1, 1, 1, 0, }, 
   {1, 1, 3, 0, }, 
   {1, 1, 2, 0, }, 
   {3, 0, 0, 0, }, 
   {2, 0, 0, 0, }, 
   {1, 1, 1, 2, }, 
   {1, 1, 1, 3, }, 
   {0, 0, 0, 0, }, 
   {3, 3, 0, 0, }, 
   {3, 2, 0, 0, }, 
   {2, 3, 0, 0, }, 
   {2, 2, 0, 0, }, 
  };
  switch (Opcode) {
  default: return LogicalOpIdx;
  case M68k::ADJCALLSTACKDOWN:
  case M68k::ADJCALLSTACKUP:
  case M68k::MOV8bc:
  case M68k::MOV8cb:
  case M68k::MOV8ce:
  case M68k::MOV8cj:
  case M68k::MOV8co:
  case M68k::MOV8cq:
  case M68k::MOV8ec:
  case M68k::MOV8jc:
  case M68k::MOV8oc:
  case M68k::MOVI16ri:
  case M68k::MOVI32ri:
  case M68k::MOVI8di:
  case M68k::MOVM16jm_P:
  case M68k::MOVM16mj_P:
  case M68k::MOVM32jm_P:
  case M68k::MOVM32mj_P:
  case M68k::MOVSXd16d8:
  case M68k::MOVSXd16j8:
  case M68k::MOVSXd16q8:
  case M68k::MOVSXd32d16:
  case M68k::MOVSXd32d8:
  case M68k::MOVSXd32j16:
  case M68k::MOVSXd32j8:
  case M68k::MOVSXd32q16:
  case M68k::MOVSXd32q8:
  case M68k::MOVXd16d8:
  case M68k::MOVXd32d16:
  case M68k::MOVXd32d8:
  case M68k::MOVZXd16d8:
  case M68k::MOVZXd16j8:
  case M68k::MOVZXd16q8:
  case M68k::MOVZXd32d16:
  case M68k::MOVZXd32d8:
  case M68k::MOVZXd32j16:
  case M68k::MOVZXd32j8:
  case M68k::MOVZXd32q16:
  case M68k::MOVZXd32q8:
  case M68k::SALLOCA:
  case M68k::TCRETURNj:
  case M68k::TCRETURNq:
  case M68k::ADD16jd:
  case M68k::ADD16ji:
  case M68k::ADD32jd:
  case M68k::ADD32ji:
  case M68k::ADD8jd:
  case M68k::ADD8ji:
  case M68k::AND16jd:
  case M68k::AND16ji:
  case M68k::AND32jd:
  case M68k::AND32ji:
  case M68k::AND8jd:
  case M68k::AND8ji:
  case M68k::BCHG32dd:
  case M68k::BCHG32di:
  case M68k::BCHG8ed:
  case M68k::BCHG8ei:
  case M68k::BCHG8jd:
  case M68k::BCHG8ji:
  case M68k::BCHG8od:
  case M68k::BCHG8oi:
  case M68k::BCLR32dd:
  case M68k::BCLR32di:
  case M68k::BCLR8ed:
  case M68k::BCLR8ei:
  case M68k::BCLR8jd:
  case M68k::BCLR8ji:
  case M68k::BCLR8od:
  case M68k::BCLR8oi:
  case M68k::BSET32dd:
  case M68k::BSET32di:
  case M68k::BSET8ed:
  case M68k::BSET8ei:
  case M68k::BSET8jd:
  case M68k::BSET8ji:
  case M68k::BSET8od:
  case M68k::BSET8oi:
  case M68k::BTST32dd:
  case M68k::BTST32di:
  case M68k::BTST8ed:
  case M68k::BTST8ei:
  case M68k::BTST8jd:
  case M68k::BTST8ji:
  case M68k::BTST8od:
  case M68k::BTST8oi:
  case M68k::BTST8qd:
  case M68k::BTST8qi:
  case M68k::CMP16bi:
  case M68k::CMP16di:
  case M68k::CMP16dj:
  case M68k::CMP16dq:
  case M68k::CMP16dr:
  case M68k::CMP16ji:
  case M68k::CMP16qi:
  case M68k::CMP32bi:
  case M68k::CMP32di:
  case M68k::CMP32dj:
  case M68k::CMP32dq:
  case M68k::CMP32dr:
  case M68k::CMP32ji:
  case M68k::CMP32qi:
  case M68k::CMP8bi:
  case M68k::CMP8dd:
  case M68k::CMP8di:
  case M68k::CMP8dj:
  case M68k::CMP8dq:
  case M68k::CMP8ji:
  case M68k::CMP8qi:
  case M68k::EXT16:
  case M68k::EXT32:
  case M68k::FABS32fp_fp:
  case M68k::FABS64fp_fp:
  case M68k::FABS80fp_fp:
  case M68k::FDABS32fp_fp:
  case M68k::FDABS64fp_fp:
  case M68k::FDABS80fp_fp:
  case M68k::FDMOV32fp_fp:
  case M68k::FDMOV64fp_fp:
  case M68k::FDMOV80fp_fp:
  case M68k::FDNEG32fp_fp:
  case M68k::FDNEG64fp_fp:
  case M68k::FDNEG80fp_fp:
  case M68k::FMOV32fp_fp:
  case M68k::FMOV64fp_fp:
  case M68k::FMOV80fp_fp:
  case M68k::FMOVE32a_fpi:
  case M68k::FMOVE32d_fpcs:
  case M68k::FMOVE32fpcs_d:
  case M68k::FMOVE32fpi_a:
  case M68k::FNEG32fp_fp:
  case M68k::FNEG64fp_fp:
  case M68k::FNEG80fp_fp:
  case M68k::FSABS32fp_fp:
  case M68k::FSABS64fp_fp:
  case M68k::FSABS80fp_fp:
  case M68k::FSMOV32fp_fp:
  case M68k::FSMOV64fp_fp:
  case M68k::FSMOV80fp_fp:
  case M68k::FSNEG32fp_fp:
  case M68k::FSNEG64fp_fp:
  case M68k::FSNEG80fp_fp:
  case M68k::LEA32b:
  case M68k::LEA32q:
  case M68k::LINK16:
  case M68k::LINK32:
  case M68k::MOV16aa:
  case M68k::MOV16ab:
  case M68k::MOV16ab_TC:
  case M68k::MOV16ae:
  case M68k::MOV16ae_TC:
  case M68k::MOV16ai:
  case M68k::MOV16aj:
  case M68k::MOV16aj_TC:
  case M68k::MOV16ao:
  case M68k::MOV16ao_TC:
  case M68k::MOV16aq:
  case M68k::MOV16aq_TC:
  case M68k::MOV16ar:
  case M68k::MOV16ba:
  case M68k::MOV16bb:
  case M68k::MOV16bc:
  case M68k::MOV16bd:
  case M68k::MOV16be:
  case M68k::MOV16bi:
  case M68k::MOV16bj:
  case M68k::MOV16bo:
  case M68k::MOV16bq:
  case M68k::MOV16br:
  case M68k::MOV16bs:
  case M68k::MOV16cb:
  case M68k::MOV16cd:
  case M68k::MOV16ce:
  case M68k::MOV16cj:
  case M68k::MOV16co:
  case M68k::MOV16cq:
  case M68k::MOV16db:
  case M68k::MOV16dc:
  case M68k::MOV16dd:
  case M68k::MOV16de:
  case M68k::MOV16di:
  case M68k::MOV16dj:
  case M68k::MOV16do:
  case M68k::MOV16dq:
  case M68k::MOV16ds:
  case M68k::MOV16ea:
  case M68k::MOV16eb:
  case M68k::MOV16ec:
  case M68k::MOV16ed:
  case M68k::MOV16ee:
  case M68k::MOV16ei:
  case M68k::MOV16ej:
  case M68k::MOV16eo:
  case M68k::MOV16eq:
  case M68k::MOV16er:
  case M68k::MOV16es:
  case M68k::MOV16ja:
  case M68k::MOV16jb:
  case M68k::MOV16jc:
  case M68k::MOV16jd:
  case M68k::MOV16je:
  case M68k::MOV16ji:
  case M68k::MOV16jj:
  case M68k::MOV16jo:
  case M68k::MOV16jq:
  case M68k::MOV16jr:
  case M68k::MOV16js:
  case M68k::MOV16oa:
  case M68k::MOV16ob:
  case M68k::MOV16oc:
  case M68k::MOV16od:
  case M68k::MOV16oe:
  case M68k::MOV16oi:
  case M68k::MOV16oj:
  case M68k::MOV16oo:
  case M68k::MOV16oq:
  case M68k::MOV16or:
  case M68k::MOV16os:
  case M68k::MOV16ra:
  case M68k::MOV16rb:
  case M68k::MOV16rb_TC:
  case M68k::MOV16re:
  case M68k::MOV16re_TC:
  case M68k::MOV16ri:
  case M68k::MOV16rj:
  case M68k::MOV16rj_TC:
  case M68k::MOV16ro:
  case M68k::MOV16ro_TC:
  case M68k::MOV16rq:
  case M68k::MOV16rq_TC:
  case M68k::MOV16rr:
  case M68k::MOV16sb:
  case M68k::MOV16sd:
  case M68k::MOV16se:
  case M68k::MOV16sj:
  case M68k::MOV16so:
  case M68k::MOV16sq:
  case M68k::MOV32aa:
  case M68k::MOV32ab:
  case M68k::MOV32ab_TC:
  case M68k::MOV32ae:
  case M68k::MOV32ae_TC:
  case M68k::MOV32ai:
  case M68k::MOV32aj:
  case M68k::MOV32aj_TC:
  case M68k::MOV32ao:
  case M68k::MOV32ao_TC:
  case M68k::MOV32aq:
  case M68k::MOV32aq_TC:
  case M68k::MOV32ar:
  case M68k::MOV32ba:
  case M68k::MOV32bb:
  case M68k::MOV32bd:
  case M68k::MOV32be:
  case M68k::MOV32bi:
  case M68k::MOV32bj:
  case M68k::MOV32bo:
  case M68k::MOV32bq:
  case M68k::MOV32br:
  case M68k::MOV32db:
  case M68k::MOV32dd:
  case M68k::MOV32de:
  case M68k::MOV32di:
  case M68k::MOV32dj:
  case M68k::MOV32do:
  case M68k::MOV32dq:
  case M68k::MOV32ea:
  case M68k::MOV32eb:
  case M68k::MOV32ed:
  case M68k::MOV32ee:
  case M68k::MOV32ei:
  case M68k::MOV32ej:
  case M68k::MOV32eo:
  case M68k::MOV32eq:
  case M68k::MOV32er:
  case M68k::MOV32ja:
  case M68k::MOV32jb:
  case M68k::MOV32jd:
  case M68k::MOV32je:
  case M68k::MOV32ji:
  case M68k::MOV32jj:
  case M68k::MOV32jo:
  case M68k::MOV32jq:
  case M68k::MOV32jr:
  case M68k::MOV32oa:
  case M68k::MOV32ob:
  case M68k::MOV32od:
  case M68k::MOV32oe:
  case M68k::MOV32oi:
  case M68k::MOV32oj:
  case M68k::MOV32oo:
  case M68k::MOV32oq:
  case M68k::MOV32or:
  case M68k::MOV32ra:
  case M68k::MOV32rb:
  case M68k::MOV32rb_TC:
  case M68k::MOV32re:
  case M68k::MOV32re_TC:
  case M68k::MOV32ri:
  case M68k::MOV32rj:
  case M68k::MOV32rj_TC:
  case M68k::MOV32ro:
  case M68k::MOV32ro_TC:
  case M68k::MOV32rq:
  case M68k::MOV32rq_TC:
  case M68k::MOV32rr:
  case M68k::MOV8bb:
  case M68k::MOV8bd:
  case M68k::MOV8be:
  case M68k::MOV8bi:
  case M68k::MOV8bj:
  case M68k::MOV8bo:
  case M68k::MOV8bq:
  case M68k::MOV8db:
  case M68k::MOV8dd:
  case M68k::MOV8de:
  case M68k::MOV8di:
  case M68k::MOV8dj:
  case M68k::MOV8do:
  case M68k::MOV8dq:
  case M68k::MOV8eb:
  case M68k::MOV8ed:
  case M68k::MOV8ee:
  case M68k::MOV8ei:
  case M68k::MOV8ej:
  case M68k::MOV8eo:
  case M68k::MOV8eq:
  case M68k::MOV8jb:
  case M68k::MOV8jd:
  case M68k::MOV8je:
  case M68k::MOV8ji:
  case M68k::MOV8jj:
  case M68k::MOV8jo:
  case M68k::MOV8jq:
  case M68k::MOV8ob:
  case M68k::MOV8od:
  case M68k::MOV8oe:
  case M68k::MOV8oi:
  case M68k::MOV8oj:
  case M68k::MOV8oo:
  case M68k::MOV8oq:
  case M68k::MOVM16bm:
  case M68k::MOVM16em:
  case M68k::MOVM16jm:
  case M68k::MOVM16mb:
  case M68k::MOVM16me:
  case M68k::MOVM16mj:
  case M68k::MOVM16mo:
  case M68k::MOVM16mq:
  case M68k::MOVM16om:
  case M68k::MOVM32bm:
  case M68k::MOVM32em:
  case M68k::MOVM32jm:
  case M68k::MOVM32mb:
  case M68k::MOVM32me:
  case M68k::MOVM32mj:
  case M68k::MOVM32mo:
  case M68k::MOVM32mq:
  case M68k::MOVM32om:
  case M68k::MOVQ:
  case M68k::NEG16d:
  case M68k::NEG32d:
  case M68k::NEG8d:
  case M68k::NEGX16d:
  case M68k::NEGX32d:
  case M68k::NEGX8d:
  case M68k::NOT16d:
  case M68k::NOT32d:
  case M68k::NOT8d:
  case M68k::OR16jd:
  case M68k::OR16ji:
  case M68k::OR32jd:
  case M68k::OR32ji:
  case M68k::OR8jd:
  case M68k::OR8ji:
  case M68k::SUB16jd:
  case M68k::SUB16ji:
  case M68k::SUB32jd:
  case M68k::SUB32ji:
  case M68k::SUB8jd:
  case M68k::SUB8ji:
    return SizeMap[0][LogicalOpIdx];
  case M68k::CMOV16d:
  case M68k::CMOV32r:
  case M68k::CMOV8d:
  case M68k::CASAL16:
  case M68k::CASAL32:
  case M68k::CASAL8:
  case M68k::CASARI16:
  case M68k::CASARI32:
  case M68k::CASARI8:
    return SizeMap[1][LogicalOpIdx];
  case M68k::MOV8cf:
  case M68k::MOVSXd16f8:
  case M68k::MOVSXd32f16:
  case M68k::MOVSXd32f8:
  case M68k::MOVZXd16f8:
  case M68k::MOVZXd32f16:
  case M68k::MOVZXd32f8:
  case M68k::CMP16df:
  case M68k::CMP16fi:
  case M68k::CMP32df:
  case M68k::CMP32fi:
  case M68k::CMP8df:
  case M68k::CMP8fi:
  case M68k::LEA32L:
  case M68k::LEA32f:
  case M68k::LEA32l:
  case M68k::MOV16af:
  case M68k::MOV16af_TC:
  case M68k::MOV16bf:
  case M68k::MOV16cf:
  case M68k::MOV16df:
  case M68k::MOV16ef:
  case M68k::MOV16jf:
  case M68k::MOV16of:
  case M68k::MOV16rf:
  case M68k::MOV16rf_TC:
  case M68k::MOV16sf:
  case M68k::MOV32af:
  case M68k::MOV32af_TC:
  case M68k::MOV32bf:
  case M68k::MOV32df:
  case M68k::MOV32ef:
  case M68k::MOV32jf:
  case M68k::MOV32of:
  case M68k::MOV32rf:
  case M68k::MOV32rf_TC:
  case M68k::MOV8bf:
  case M68k::MOV8df:
  case M68k::MOV8ef:
  case M68k::MOV8jf:
  case M68k::MOV8of:
  case M68k::MOVM16mf:
  case M68k::MOVM32mf:
    return SizeMap[2][LogicalOpIdx];
  case M68k::MOV8ck:
  case M68k::MOV8cp:
  case M68k::MOVM16mp_P:
  case M68k::MOVM32mp_P:
  case M68k::MOVSXd16p8:
  case M68k::MOVSXd32p16:
  case M68k::MOVSXd32p8:
  case M68k::MOVZXd16p8:
  case M68k::MOVZXd32p16:
  case M68k::MOVZXd32p8:
  case M68k::CMP16dk:
  case M68k::CMP16dp:
  case M68k::CMP16ki:
  case M68k::CMP16pi:
  case M68k::CMP32dk:
  case M68k::CMP32dp:
  case M68k::CMP32ki:
  case M68k::CMP32pi:
  case M68k::CMP8dk:
  case M68k::CMP8dp:
  case M68k::CMP8ki:
  case M68k::CMP8pi:
  case M68k::LEA32k:
  case M68k::LEA32p:
  case M68k::MOV16ak:
  case M68k::MOV16ak_TC:
  case M68k::MOV16ap:
  case M68k::MOV16ap_TC:
  case M68k::MOV16bk:
  case M68k::MOV16bp:
  case M68k::MOV16ck:
  case M68k::MOV16cp:
  case M68k::MOV16dk:
  case M68k::MOV16dp:
  case M68k::MOV16ek:
  case M68k::MOV16ep:
  case M68k::MOV16jk:
  case M68k::MOV16jp:
  case M68k::MOV16ok:
  case M68k::MOV16op:
  case M68k::MOV16rk:
  case M68k::MOV16rk_TC:
  case M68k::MOV16rp:
  case M68k::MOV16rp_TC:
  case M68k::MOV16sk:
  case M68k::MOV16sp:
  case M68k::MOV32ak:
  case M68k::MOV32ak_TC:
  case M68k::MOV32ap:
  case M68k::MOV32ap_TC:
  case M68k::MOV32bk:
  case M68k::MOV32bp:
  case M68k::MOV32dk:
  case M68k::MOV32dp:
  case M68k::MOV32ek:
  case M68k::MOV32ep:
  case M68k::MOV32jk:
  case M68k::MOV32jp:
  case M68k::MOV32ok:
  case M68k::MOV32op:
  case M68k::MOV32rk:
  case M68k::MOV32rk_TC:
  case M68k::MOV32rp:
  case M68k::MOV32rp_TC:
  case M68k::MOV8bk:
  case M68k::MOV8bp:
  case M68k::MOV8dk:
  case M68k::MOV8dp:
  case M68k::MOV8ek:
  case M68k::MOV8ep:
  case M68k::MOV8jk:
  case M68k::MOV8jp:
  case M68k::MOV8ok:
  case M68k::MOV8op:
  case M68k::MOVM16mk:
  case M68k::MOVM16mp:
  case M68k::MOVM32mk:
  case M68k::MOVM32mp:
    return SizeMap[3][LogicalOpIdx];
  case M68k::MOV8fc:
  case M68k::ADD16fd:
  case M68k::ADD16fi:
  case M68k::ADD32fd:
  case M68k::ADD32fi:
  case M68k::ADD8fd:
  case M68k::ADD8fi:
  case M68k::AND16fd:
  case M68k::AND16fi:
  case M68k::AND32fd:
  case M68k::AND32fi:
  case M68k::AND8fd:
  case M68k::AND8fi:
  case M68k::BCHG8fd:
  case M68k::BCHG8fi:
  case M68k::BCLR8fd:
  case M68k::BCLR8fi:
  case M68k::BSET8fd:
  case M68k::BSET8fi:
  case M68k::BTST8fd:
  case M68k::BTST8fi:
  case M68k::MOV16fa:
  case M68k::MOV16fb:
  case M68k::MOV16fc:
  case M68k::MOV16fd:
  case M68k::MOV16fe:
  case M68k::MOV16fi:
  case M68k::MOV16fj:
  case M68k::MOV16fo:
  case M68k::MOV16fq:
  case M68k::MOV16fr:
  case M68k::MOV16fs:
  case M68k::MOV32fa:
  case M68k::MOV32fb:
  case M68k::MOV32fd:
  case M68k::MOV32fe:
  case M68k::MOV32fi:
  case M68k::MOV32fj:
  case M68k::MOV32fo:
  case M68k::MOV32fq:
  case M68k::MOV32fr:
  case M68k::MOV8fb:
  case M68k::MOV8fd:
  case M68k::MOV8fe:
  case M68k::MOV8fi:
  case M68k::MOV8fj:
  case M68k::MOV8fo:
  case M68k::MOV8fq:
  case M68k::MOVM16fm:
  case M68k::MOVM32fm:
  case M68k::OR16fd:
  case M68k::OR16fi:
  case M68k::OR32fd:
  case M68k::OR32fi:
  case M68k::OR8fd:
  case M68k::OR8fi:
  case M68k::SUB16fd:
  case M68k::SUB16fi:
  case M68k::SUB32fd:
  case M68k::SUB32fi:
  case M68k::SUB8fd:
  case M68k::SUB8fi:
    return SizeMap[4][LogicalOpIdx];
  case M68k::MOV8pc:
  case M68k::MOVM16pm_P:
  case M68k::MOVM32pm_P:
  case M68k::ADD16pd:
  case M68k::ADD16pi:
  case M68k::ADD32pd:
  case M68k::ADD32pi:
  case M68k::ADD8pd:
  case M68k::ADD8pi:
  case M68k::AND16pd:
  case M68k::AND16pi:
  case M68k::AND32pd:
  case M68k::AND32pi:
  case M68k::AND8pd:
  case M68k::AND8pi:
  case M68k::BCHG8pd:
  case M68k::BCHG8pi:
  case M68k::BCLR8pd:
  case M68k::BCLR8pi:
  case M68k::BSET8pd:
  case M68k::BSET8pi:
  case M68k::BTST8kd:
  case M68k::BTST8ki:
  case M68k::BTST8pd:
  case M68k::BTST8pi:
  case M68k::MOV16pa:
  case M68k::MOV16pb:
  case M68k::MOV16pc:
  case M68k::MOV16pd:
  case M68k::MOV16pe:
  case M68k::MOV16pi:
  case M68k::MOV16pj:
  case M68k::MOV16po:
  case M68k::MOV16pq:
  case M68k::MOV16pr:
  case M68k::MOV16ps:
  case M68k::MOV32pa:
  case M68k::MOV32pb:
  case M68k::MOV32pd:
  case M68k::MOV32pe:
  case M68k::MOV32pi:
  case M68k::MOV32pj:
  case M68k::MOV32po:
  case M68k::MOV32pq:
  case M68k::MOV32pr:
  case M68k::MOV8pb:
  case M68k::MOV8pd:
  case M68k::MOV8pe:
  case M68k::MOV8pi:
  case M68k::MOV8pj:
  case M68k::MOV8po:
  case M68k::MOV8pq:
  case M68k::MOVM16pm:
  case M68k::MOVM32pm:
  case M68k::OR16pd:
  case M68k::OR16pi:
  case M68k::OR32pd:
  case M68k::OR32pi:
  case M68k::OR8pd:
  case M68k::OR8pi:
  case M68k::SUB16pd:
  case M68k::SUB16pi:
  case M68k::SUB32pd:
  case M68k::SUB32pi:
  case M68k::SUB8pd:
  case M68k::SUB8pi:
    return SizeMap[5][LogicalOpIdx];
  case M68k::POP16d:
  case M68k::POP32r:
  case M68k::POP8d:
  case M68k::PUSH16d:
  case M68k::PUSH32r:
  case M68k::PUSH8d:
  case M68k::RET:
  case M68k::SETCS_C16d:
  case M68k::SETCS_C32d:
  case M68k::SETCS_C8d:
  case M68k::TAILJMPj:
  case M68k::TAILJMPq:
  case M68k::BKPT:
  case M68k::BRA16:
  case M68k::BRA32:
  case M68k::BRA8:
  case M68k::BSR16:
  case M68k::BSR32:
  case M68k::BSR8:
  case M68k::Bcc16:
  case M68k::Bcc32:
  case M68k::Bcc8:
  case M68k::Bcs16:
  case M68k::Bcs32:
  case M68k::Bcs8:
  case M68k::Beq16:
  case M68k::Beq32:
  case M68k::Beq8:
  case M68k::Bge16:
  case M68k::Bge32:
  case M68k::Bge8:
  case M68k::Bgt16:
  case M68k::Bgt32:
  case M68k::Bgt8:
  case M68k::Bhi16:
  case M68k::Bhi32:
  case M68k::Bhi8:
  case M68k::Ble16:
  case M68k::Ble32:
  case M68k::Ble8:
  case M68k::Bls16:
  case M68k::Bls32:
  case M68k::Bls8:
  case M68k::Blt16:
  case M68k::Blt32:
  case M68k::Blt8:
  case M68k::Bmi16:
  case M68k::Bmi32:
  case M68k::Bmi8:
  case M68k::Bne16:
  case M68k::Bne32:
  case M68k::Bne8:
  case M68k::Bpl16:
  case M68k::Bpl32:
  case M68k::Bpl8:
  case M68k::Bvc16:
  case M68k::Bvc32:
  case M68k::Bvc8:
  case M68k::Bvs16:
  case M68k::Bvs32:
  case M68k::Bvs8:
  case M68k::CALLb:
  case M68k::CALLj:
  case M68k::CALLq:
  case M68k::JMP32j:
  case M68k::SETd8cc:
  case M68k::SETd8cs:
  case M68k::SETd8eq:
  case M68k::SETd8f:
  case M68k::SETd8ge:
  case M68k::SETd8gt:
  case M68k::SETd8hi:
  case M68k::SETd8le:
  case M68k::SETd8ls:
  case M68k::SETd8lt:
  case M68k::SETd8mi:
  case M68k::SETd8ne:
  case M68k::SETd8pl:
  case M68k::SETd8t:
  case M68k::SETd8vc:
  case M68k::SETd8vs:
  case M68k::SETj8cc:
  case M68k::SETj8cs:
  case M68k::SETj8eq:
  case M68k::SETj8f:
  case M68k::SETj8ge:
  case M68k::SETj8gt:
  case M68k::SETj8hi:
  case M68k::SETj8le:
  case M68k::SETj8ls:
  case M68k::SETj8lt:
  case M68k::SETj8mi:
  case M68k::SETj8ne:
  case M68k::SETj8pl:
  case M68k::SETj8t:
  case M68k::SETj8vc:
  case M68k::SETj8vs:
  case M68k::TRAP:
  case M68k::UNLK:
    return SizeMap[6][LogicalOpIdx];
  case M68k::ADD16dd:
  case M68k::ADD16di:
  case M68k::ADD16dj:
  case M68k::ADD16dq:
  case M68k::ADD16dr:
  case M68k::ADD32ab:
  case M68k::ADD32ai:
  case M68k::ADD32aj:
  case M68k::ADD32aq:
  case M68k::ADD32ar:
  case M68k::ADD32dd:
  case M68k::ADD32di:
  case M68k::ADD32dj:
  case M68k::ADD32dq:
  case M68k::ADD32dr:
  case M68k::ADD8dd:
  case M68k::ADD8di:
  case M68k::ADD8dj:
  case M68k::ADD8dq:
  case M68k::ADDX16dd:
  case M68k::ADDX32dd:
  case M68k::ADDX8dd:
  case M68k::AND16dd:
  case M68k::AND16di:
  case M68k::AND16dj:
  case M68k::AND16dq:
  case M68k::AND16dr:
  case M68k::AND32dd:
  case M68k::AND32di:
  case M68k::AND32dj:
  case M68k::AND32dq:
  case M68k::AND32dr:
  case M68k::AND8dd:
  case M68k::AND8di:
  case M68k::AND8dj:
  case M68k::AND8dq:
  case M68k::ASR16dd:
  case M68k::ASR16di:
  case M68k::ASR32dd:
  case M68k::ASR32di:
  case M68k::ASR8dd:
  case M68k::ASR8di:
  case M68k::FADD32fp_fp:
  case M68k::FADD64fp_fp:
  case M68k::FADD80fp_fp:
  case M68k::FDADD32fp_fp:
  case M68k::FDADD64fp_fp:
  case M68k::FDADD80fp_fp:
  case M68k::FDDIV32fp_fp:
  case M68k::FDDIV64fp_fp:
  case M68k::FDDIV80fp_fp:
  case M68k::FDIV32fp_fp:
  case M68k::FDIV64fp_fp:
  case M68k::FDIV80fp_fp:
  case M68k::FDMUL32fp_fp:
  case M68k::FDMUL64fp_fp:
  case M68k::FDMUL80fp_fp:
  case M68k::FDSUB32fp_fp:
  case M68k::FDSUB64fp_fp:
  case M68k::FDSUB80fp_fp:
  case M68k::FMUL32fp_fp:
  case M68k::FMUL64fp_fp:
  case M68k::FMUL80fp_fp:
  case M68k::FSADD32fp_fp:
  case M68k::FSADD64fp_fp:
  case M68k::FSADD80fp_fp:
  case M68k::FSDIV32fp_fp:
  case M68k::FSDIV64fp_fp:
  case M68k::FSDIV80fp_fp:
  case M68k::FSMUL32fp_fp:
  case M68k::FSMUL64fp_fp:
  case M68k::FSMUL80fp_fp:
  case M68k::FSSUB32fp_fp:
  case M68k::FSSUB64fp_fp:
  case M68k::FSSUB80fp_fp:
  case M68k::FSUB32fp_fp:
  case M68k::FSUB64fp_fp:
  case M68k::FSUB80fp_fp:
  case M68k::LSR16dd:
  case M68k::LSR16di:
  case M68k::LSR32dd:
  case M68k::LSR32di:
  case M68k::LSR8dd:
  case M68k::LSR8di:
  case M68k::OR16dd:
  case M68k::OR16di:
  case M68k::OR16dj:
  case M68k::OR16dq:
  case M68k::OR16dr:
  case M68k::OR32dd:
  case M68k::OR32di:
  case M68k::OR32dj:
  case M68k::OR32dq:
  case M68k::OR32dr:
  case M68k::OR8dd:
  case M68k::OR8di:
  case M68k::OR8dj:
  case M68k::OR8dq:
  case M68k::ROL16dd:
  case M68k::ROL16di:
  case M68k::ROL32dd:
  case M68k::ROL32di:
  case M68k::ROL8dd:
  case M68k::ROL8di:
  case M68k::ROR16dd:
  case M68k::ROR16di:
  case M68k::ROR32dd:
  case M68k::ROR32di:
  case M68k::ROR8dd:
  case M68k::ROR8di:
  case M68k::SDIVd32d16:
  case M68k::SDIVd32d32:
  case M68k::SDIVd32i16:
  case M68k::SHL16dd:
  case M68k::SHL16di:
  case M68k::SHL32dd:
  case M68k::SHL32di:
  case M68k::SHL8dd:
  case M68k::SHL8di:
  case M68k::SMULd32d16:
  case M68k::SMULd32d32:
  case M68k::SMULd32i16:
  case M68k::SUB16dd:
  case M68k::SUB16di:
  case M68k::SUB16dj:
  case M68k::SUB16dq:
  case M68k::SUB16dr:
  case M68k::SUB32ab:
  case M68k::SUB32ai:
  case M68k::SUB32aj:
  case M68k::SUB32aq:
  case M68k::SUB32ar:
  case M68k::SUB32dd:
  case M68k::SUB32di:
  case M68k::SUB32dj:
  case M68k::SUB32dq:
  case M68k::SUB32dr:
  case M68k::SUB8dd:
  case M68k::SUB8di:
  case M68k::SUB8dj:
  case M68k::SUB8dq:
  case M68k::SUBX16dd:
  case M68k::SUBX32dd:
  case M68k::SUBX8dd:
  case M68k::UDIVd32d16:
  case M68k::UDIVd32d32:
  case M68k::UDIVd32i16:
  case M68k::UMULd32d16:
  case M68k::UMULd32d32:
  case M68k::UMULd32i16:
  case M68k::XOR16dd:
  case M68k::XOR16di:
  case M68k::XOR32dd:
  case M68k::XOR32di:
  case M68k::XOR8dd:
  case M68k::XOR8di:
    return SizeMap[7][LogicalOpIdx];
  case M68k::ADD16df:
  case M68k::ADD32af:
  case M68k::ADD32df:
  case M68k::ADD8df:
  case M68k::AND16df:
  case M68k::AND32df:
  case M68k::AND8df:
  case M68k::OR16df:
  case M68k::OR32df:
  case M68k::OR8df:
  case M68k::SUB16df:
  case M68k::SUB32af:
  case M68k::SUB32df:
  case M68k::SUB8df:
    return SizeMap[8][LogicalOpIdx];
  case M68k::ADD16dk:
  case M68k::ADD16dp:
  case M68k::ADD32ak:
  case M68k::ADD32ap:
  case M68k::ADD32dk:
  case M68k::ADD32dp:
  case M68k::ADD8dk:
  case M68k::ADD8dp:
  case M68k::AND16dk:
  case M68k::AND16dp:
  case M68k::AND32dk:
  case M68k::AND32dp:
  case M68k::AND8dk:
  case M68k::AND8dp:
  case M68k::OR16dk:
  case M68k::OR16dp:
  case M68k::OR32dk:
  case M68k::OR32dp:
  case M68k::OR8dk:
  case M68k::OR8dp:
  case M68k::SUB16dk:
  case M68k::SUB16dp:
  case M68k::SUB32ak:
  case M68k::SUB32ap:
  case M68k::SUB32dk:
  case M68k::SUB32dp:
  case M68k::SUB8dk:
  case M68k::SUB8dp:
    return SizeMap[9][LogicalOpIdx];
  case M68k::CALLf:
  case M68k::CALLl:
    return SizeMap[10][LogicalOpIdx];
  case M68k::CALLk:
  case M68k::CALLp:
  case M68k::SETp8cc:
  case M68k::SETp8cs:
  case M68k::SETp8eq:
  case M68k::SETp8f:
  case M68k::SETp8ge:
  case M68k::SETp8gt:
  case M68k::SETp8hi:
  case M68k::SETp8le:
  case M68k::SETp8ls:
  case M68k::SETp8lt:
  case M68k::SETp8mi:
  case M68k::SETp8ne:
  case M68k::SETp8pl:
  case M68k::SETp8t:
  case M68k::SETp8vc:
  case M68k::SETp8vs:
    return SizeMap[11][LogicalOpIdx];
  case M68k::CASARID16:
  case M68k::CASARID32:
  case M68k::CASARID8:
    return SizeMap[12][LogicalOpIdx];
  case M68k::CASARII16:
  case M68k::CASARII32:
  case M68k::CASARII8:
    return SizeMap[13][LogicalOpIdx];
  case M68k::ILLEGAL:
  case M68k::NOP:
  case M68k::RTE:
  case M68k::RTS:
  case M68k::TRAPV:
    return SizeMap[14][LogicalOpIdx];
  case M68k::MOV16ff:
  case M68k::MOV32ff:
  case M68k::MOV8ff:
    return SizeMap[15][LogicalOpIdx];
  case M68k::MOV16fk:
  case M68k::MOV16fp:
  case M68k::MOV32fk:
  case M68k::MOV32fp:
  case M68k::MOV8fk:
  case M68k::MOV8fp:
    return SizeMap[16][LogicalOpIdx];
  case M68k::MOV16pf:
  case M68k::MOV32pf:
  case M68k::MOV8pf:
    return SizeMap[17][LogicalOpIdx];
  case M68k::MOV16pk:
  case M68k::MOV16pp:
  case M68k::MOV32pk:
  case M68k::MOV32pp:
  case M68k::MOV8pk:
  case M68k::MOV8pp:
    return SizeMap[18][LogicalOpIdx];
  }
}
LLVM_READONLY static inline unsigned
getLogicalOperandIdx(uint32_t Opcode, uint16_t LogicalOpIdx) {
  auto S = 0U;
  for (auto i = 0U; i < LogicalOpIdx; ++i)
    S += getLogicalOperandSize(Opcode, i);
  return S;
}

} // namespace llvm_ks::M68k

#endif // GET_INSTRINFO_LOGICAL_OPERAND_SIZE_MAP

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace M68k_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace M68k_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::M68k_MC {


} // namespace llvm_ks::M68k_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::M68k_MC {

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_AtLeastM68000Bit = 0,
  Feature_AtLeastM68010Bit = 1,
  Feature_AtLeastM68020Bit = 2,
  Feature_AtLeastM68040Bit = 3,
  Feature_AtLeastM68060Bit = 4,
  Feature_AtLeastM68881Bit = 5,
  Feature_AtLeastM68882Bit = 6,
};

inline FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) {
  FeatureBitset Features;
  if (FB[M68k::FeatureISA00])
    Features.set(Feature_AtLeastM68000Bit);
  if (FB[M68k::FeatureISA10])
    Features.set(Feature_AtLeastM68010Bit);
  if (FB[M68k::FeatureISA20])
    Features.set(Feature_AtLeastM68020Bit);
  if (FB[M68k::FeatureISA40])
    Features.set(Feature_AtLeastM68040Bit);
  if (FB[M68k::FeatureISA60])
    Features.set(Feature_AtLeastM68060Bit);
  if (FB[M68k::FeatureISA881])
    Features.set(Feature_AtLeastM68881Bit);
  if (FB[M68k::FeatureISA882])
    Features.set(Feature_AtLeastM68882Bit);
  return Features;
}

inline FeatureBitset computeRequiredFeatures(unsigned Opcode) {
  enum : uint8_t {
    CEFBS_None,
    CEFBS_AtLeastM68010,
    CEFBS_AtLeastM68020,
    CEFBS_AtLeastM68040,
    CEFBS_AtLeastM68881,
  };

  static constexpr FeatureBitset FeatureBitsets[] = {
    {}, // CEFBS_None
    {Feature_AtLeastM68010Bit, },
    {Feature_AtLeastM68020Bit, },
    {Feature_AtLeastM68040Bit, },
    {Feature_AtLeastM68881Bit, },
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
    CEFBS_None, // CMOV16d
    CEFBS_None, // CMOV32r
    CEFBS_None, // CMOV8d
    CEFBS_None, // MOV8bc
    CEFBS_None, // MOV8cb
    CEFBS_None, // MOV8ce
    CEFBS_None, // MOV8cf
    CEFBS_None, // MOV8cj
    CEFBS_None, // MOV8ck
    CEFBS_None, // MOV8co
    CEFBS_None, // MOV8cp
    CEFBS_None, // MOV8cq
    CEFBS_None, // MOV8ec
    CEFBS_None, // MOV8fc
    CEFBS_None, // MOV8jc
    CEFBS_None, // MOV8oc
    CEFBS_None, // MOV8pc
    CEFBS_None, // MOVI16ri
    CEFBS_None, // MOVI32ri
    CEFBS_None, // MOVI8di
    CEFBS_None, // MOVM16jm_P
    CEFBS_None, // MOVM16mj_P
    CEFBS_None, // MOVM16mp_P
    CEFBS_None, // MOVM16pm_P
    CEFBS_None, // MOVM32jm_P
    CEFBS_None, // MOVM32mj_P
    CEFBS_None, // MOVM32mp_P
    CEFBS_None, // MOVM32pm_P
    CEFBS_None, // MOVSXd16d8
    CEFBS_None, // MOVSXd16f8
    CEFBS_None, // MOVSXd16j8
    CEFBS_None, // MOVSXd16p8
    CEFBS_None, // MOVSXd16q8
    CEFBS_None, // MOVSXd32d16
    CEFBS_None, // MOVSXd32d8
    CEFBS_None, // MOVSXd32f16
    CEFBS_None, // MOVSXd32f8
    CEFBS_None, // MOVSXd32j16
    CEFBS_None, // MOVSXd32j8
    CEFBS_None, // MOVSXd32p16
    CEFBS_None, // MOVSXd32p8
    CEFBS_None, // MOVSXd32q16
    CEFBS_None, // MOVSXd32q8
    CEFBS_None, // MOVXd16d8
    CEFBS_None, // MOVXd32d16
    CEFBS_None, // MOVXd32d8
    CEFBS_None, // MOVZXd16d8
    CEFBS_None, // MOVZXd16f8
    CEFBS_None, // MOVZXd16j8
    CEFBS_None, // MOVZXd16p8
    CEFBS_None, // MOVZXd16q8
    CEFBS_None, // MOVZXd32d16
    CEFBS_None, // MOVZXd32d8
    CEFBS_None, // MOVZXd32f16
    CEFBS_None, // MOVZXd32f8
    CEFBS_None, // MOVZXd32j16
    CEFBS_None, // MOVZXd32j8
    CEFBS_None, // MOVZXd32p16
    CEFBS_None, // MOVZXd32p8
    CEFBS_None, // MOVZXd32q16
    CEFBS_None, // MOVZXd32q8
    CEFBS_None, // POP16d
    CEFBS_None, // POP32r
    CEFBS_None, // POP8d
    CEFBS_None, // PUSH16d
    CEFBS_None, // PUSH32r
    CEFBS_None, // PUSH8d
    CEFBS_None, // RET
    CEFBS_None, // SALLOCA
    CEFBS_None, // SETCS_C16d
    CEFBS_None, // SETCS_C32d
    CEFBS_None, // SETCS_C8d
    CEFBS_None, // TAILJMPj
    CEFBS_None, // TAILJMPq
    CEFBS_None, // TCRETURNj
    CEFBS_None, // TCRETURNq
    CEFBS_None, // ADD16dd
    CEFBS_None, // ADD16df
    CEFBS_None, // ADD16di
    CEFBS_None, // ADD16dj
    CEFBS_None, // ADD16dk
    CEFBS_None, // ADD16dp
    CEFBS_None, // ADD16dq
    CEFBS_None, // ADD16dr
    CEFBS_None, // ADD16fd
    CEFBS_None, // ADD16fi
    CEFBS_None, // ADD16jd
    CEFBS_None, // ADD16ji
    CEFBS_None, // ADD16pd
    CEFBS_None, // ADD16pi
    CEFBS_None, // ADD32ab
    CEFBS_None, // ADD32af
    CEFBS_None, // ADD32ai
    CEFBS_None, // ADD32aj
    CEFBS_None, // ADD32ak
    CEFBS_None, // ADD32ap
    CEFBS_None, // ADD32aq
    CEFBS_None, // ADD32ar
    CEFBS_None, // ADD32dd
    CEFBS_None, // ADD32df
    CEFBS_None, // ADD32di
    CEFBS_None, // ADD32dj
    CEFBS_None, // ADD32dk
    CEFBS_None, // ADD32dp
    CEFBS_None, // ADD32dq
    CEFBS_None, // ADD32dr
    CEFBS_None, // ADD32fd
    CEFBS_None, // ADD32fi
    CEFBS_None, // ADD32jd
    CEFBS_None, // ADD32ji
    CEFBS_None, // ADD32pd
    CEFBS_None, // ADD32pi
    CEFBS_None, // ADD8dd
    CEFBS_None, // ADD8df
    CEFBS_None, // ADD8di
    CEFBS_None, // ADD8dj
    CEFBS_None, // ADD8dk
    CEFBS_None, // ADD8dp
    CEFBS_None, // ADD8dq
    CEFBS_None, // ADD8fd
    CEFBS_None, // ADD8fi
    CEFBS_None, // ADD8jd
    CEFBS_None, // ADD8ji
    CEFBS_None, // ADD8pd
    CEFBS_None, // ADD8pi
    CEFBS_None, // ADDX16dd
    CEFBS_None, // ADDX32dd
    CEFBS_None, // ADDX8dd
    CEFBS_None, // AND16dd
    CEFBS_None, // AND16df
    CEFBS_None, // AND16di
    CEFBS_None, // AND16dj
    CEFBS_None, // AND16dk
    CEFBS_None, // AND16dp
    CEFBS_None, // AND16dq
    CEFBS_None, // AND16dr
    CEFBS_None, // AND16fd
    CEFBS_None, // AND16fi
    CEFBS_None, // AND16jd
    CEFBS_None, // AND16ji
    CEFBS_None, // AND16pd
    CEFBS_None, // AND16pi
    CEFBS_None, // AND32dd
    CEFBS_None, // AND32df
    CEFBS_None, // AND32di
    CEFBS_None, // AND32dj
    CEFBS_None, // AND32dk
    CEFBS_None, // AND32dp
    CEFBS_None, // AND32dq
    CEFBS_None, // AND32dr
    CEFBS_None, // AND32fd
    CEFBS_None, // AND32fi
    CEFBS_None, // AND32jd
    CEFBS_None, // AND32ji
    CEFBS_None, // AND32pd
    CEFBS_None, // AND32pi
    CEFBS_None, // AND8dd
    CEFBS_None, // AND8df
    CEFBS_None, // AND8di
    CEFBS_None, // AND8dj
    CEFBS_None, // AND8dk
    CEFBS_None, // AND8dp
    CEFBS_None, // AND8dq
    CEFBS_None, // AND8fd
    CEFBS_None, // AND8fi
    CEFBS_None, // AND8jd
    CEFBS_None, // AND8ji
    CEFBS_None, // AND8pd
    CEFBS_None, // AND8pi
    CEFBS_None, // ASR16dd
    CEFBS_None, // ASR16di
    CEFBS_None, // ASR32dd
    CEFBS_None, // ASR32di
    CEFBS_None, // ASR8dd
    CEFBS_None, // ASR8di
    CEFBS_None, // BCHG32dd
    CEFBS_None, // BCHG32di
    CEFBS_None, // BCHG8ed
    CEFBS_None, // BCHG8ei
    CEFBS_None, // BCHG8fd
    CEFBS_None, // BCHG8fi
    CEFBS_None, // BCHG8jd
    CEFBS_None, // BCHG8ji
    CEFBS_None, // BCHG8od
    CEFBS_None, // BCHG8oi
    CEFBS_None, // BCHG8pd
    CEFBS_None, // BCHG8pi
    CEFBS_None, // BCLR32dd
    CEFBS_None, // BCLR32di
    CEFBS_None, // BCLR8ed
    CEFBS_None, // BCLR8ei
    CEFBS_None, // BCLR8fd
    CEFBS_None, // BCLR8fi
    CEFBS_None, // BCLR8jd
    CEFBS_None, // BCLR8ji
    CEFBS_None, // BCLR8od
    CEFBS_None, // BCLR8oi
    CEFBS_None, // BCLR8pd
    CEFBS_None, // BCLR8pi
    CEFBS_None, // BKPT
    CEFBS_None, // BRA16
    CEFBS_AtLeastM68020, // BRA32
    CEFBS_None, // BRA8
    CEFBS_None, // BSET32dd
    CEFBS_None, // BSET32di
    CEFBS_None, // BSET8ed
    CEFBS_None, // BSET8ei
    CEFBS_None, // BSET8fd
    CEFBS_None, // BSET8fi
    CEFBS_None, // BSET8jd
    CEFBS_None, // BSET8ji
    CEFBS_None, // BSET8od
    CEFBS_None, // BSET8oi
    CEFBS_None, // BSET8pd
    CEFBS_None, // BSET8pi
    CEFBS_None, // BSR16
    CEFBS_AtLeastM68020, // BSR32
    CEFBS_None, // BSR8
    CEFBS_None, // BTST32dd
    CEFBS_None, // BTST32di
    CEFBS_None, // BTST8ed
    CEFBS_None, // BTST8ei
    CEFBS_None, // BTST8fd
    CEFBS_None, // BTST8fi
    CEFBS_None, // BTST8jd
    CEFBS_None, // BTST8ji
    CEFBS_None, // BTST8kd
    CEFBS_None, // BTST8ki
    CEFBS_None, // BTST8od
    CEFBS_None, // BTST8oi
    CEFBS_None, // BTST8pd
    CEFBS_None, // BTST8pi
    CEFBS_None, // BTST8qd
    CEFBS_None, // BTST8qi
    CEFBS_None, // Bcc16
    CEFBS_AtLeastM68020, // Bcc32
    CEFBS_None, // Bcc8
    CEFBS_None, // Bcs16
    CEFBS_AtLeastM68020, // Bcs32
    CEFBS_None, // Bcs8
    CEFBS_None, // Beq16
    CEFBS_AtLeastM68020, // Beq32
    CEFBS_None, // Beq8
    CEFBS_None, // Bge16
    CEFBS_AtLeastM68020, // Bge32
    CEFBS_None, // Bge8
    CEFBS_None, // Bgt16
    CEFBS_AtLeastM68020, // Bgt32
    CEFBS_None, // Bgt8
    CEFBS_None, // Bhi16
    CEFBS_AtLeastM68020, // Bhi32
    CEFBS_None, // Bhi8
    CEFBS_None, // Ble16
    CEFBS_AtLeastM68020, // Ble32
    CEFBS_None, // Ble8
    CEFBS_None, // Bls16
    CEFBS_AtLeastM68020, // Bls32
    CEFBS_None, // Bls8
    CEFBS_None, // Blt16
    CEFBS_AtLeastM68020, // Blt32
    CEFBS_None, // Blt8
    CEFBS_None, // Bmi16
    CEFBS_AtLeastM68020, // Bmi32
    CEFBS_None, // Bmi8
    CEFBS_None, // Bne16
    CEFBS_AtLeastM68020, // Bne32
    CEFBS_None, // Bne8
    CEFBS_None, // Bpl16
    CEFBS_AtLeastM68020, // Bpl32
    CEFBS_None, // Bpl8
    CEFBS_None, // Bvc16
    CEFBS_AtLeastM68020, // Bvc32
    CEFBS_None, // Bvc8
    CEFBS_None, // Bvs16
    CEFBS_AtLeastM68020, // Bvs32
    CEFBS_None, // Bvs8
    CEFBS_None, // CALLb
    CEFBS_None, // CALLf
    CEFBS_None, // CALLj
    CEFBS_None, // CALLk
    CEFBS_None, // CALLl
    CEFBS_None, // CALLp
    CEFBS_None, // CALLq
    CEFBS_AtLeastM68020, // CASAL16
    CEFBS_AtLeastM68020, // CASAL32
    CEFBS_AtLeastM68020, // CASAL8
    CEFBS_AtLeastM68020, // CASARI16
    CEFBS_AtLeastM68020, // CASARI32
    CEFBS_AtLeastM68020, // CASARI8
    CEFBS_AtLeastM68020, // CASARID16
    CEFBS_AtLeastM68020, // CASARID32
    CEFBS_AtLeastM68020, // CASARID8
    CEFBS_AtLeastM68020, // CASARII16
    CEFBS_AtLeastM68020, // CASARII32
    CEFBS_AtLeastM68020, // CASARII8
    CEFBS_None, // CMP16bi
    CEFBS_None, // CMP16df
    CEFBS_None, // CMP16di
    CEFBS_None, // CMP16dj
    CEFBS_None, // CMP16dk
    CEFBS_None, // CMP16dp
    CEFBS_None, // CMP16dq
    CEFBS_None, // CMP16dr
    CEFBS_None, // CMP16fi
    CEFBS_None, // CMP16ji
    CEFBS_None, // CMP16ki
    CEFBS_None, // CMP16pi
    CEFBS_None, // CMP16qi
    CEFBS_None, // CMP32bi
    CEFBS_None, // CMP32df
    CEFBS_None, // CMP32di
    CEFBS_None, // CMP32dj
    CEFBS_None, // CMP32dk
    CEFBS_None, // CMP32dp
    CEFBS_None, // CMP32dq
    CEFBS_None, // CMP32dr
    CEFBS_None, // CMP32fi
    CEFBS_None, // CMP32ji
    CEFBS_None, // CMP32ki
    CEFBS_None, // CMP32pi
    CEFBS_None, // CMP32qi
    CEFBS_None, // CMP8bi
    CEFBS_None, // CMP8dd
    CEFBS_None, // CMP8df
    CEFBS_None, // CMP8di
    CEFBS_None, // CMP8dj
    CEFBS_None, // CMP8dk
    CEFBS_None, // CMP8dp
    CEFBS_None, // CMP8dq
    CEFBS_None, // CMP8fi
    CEFBS_None, // CMP8ji
    CEFBS_None, // CMP8ki
    CEFBS_None, // CMP8pi
    CEFBS_None, // CMP8qi
    CEFBS_None, // EXT16
    CEFBS_None, // EXT32
    CEFBS_AtLeastM68881, // FABS32fp_fp
    CEFBS_AtLeastM68881, // FABS64fp_fp
    CEFBS_AtLeastM68881, // FABS80fp_fp
    CEFBS_AtLeastM68881, // FADD32fp_fp
    CEFBS_AtLeastM68881, // FADD64fp_fp
    CEFBS_AtLeastM68881, // FADD80fp_fp
    CEFBS_AtLeastM68040, // FDABS32fp_fp
    CEFBS_AtLeastM68040, // FDABS64fp_fp
    CEFBS_AtLeastM68040, // FDABS80fp_fp
    CEFBS_AtLeastM68040, // FDADD32fp_fp
    CEFBS_AtLeastM68040, // FDADD64fp_fp
    CEFBS_AtLeastM68040, // FDADD80fp_fp
    CEFBS_AtLeastM68040, // FDDIV32fp_fp
    CEFBS_AtLeastM68040, // FDDIV64fp_fp
    CEFBS_AtLeastM68040, // FDDIV80fp_fp
    CEFBS_AtLeastM68881, // FDIV32fp_fp
    CEFBS_AtLeastM68881, // FDIV64fp_fp
    CEFBS_AtLeastM68881, // FDIV80fp_fp
    CEFBS_AtLeastM68040, // FDMOV32fp_fp
    CEFBS_AtLeastM68040, // FDMOV64fp_fp
    CEFBS_AtLeastM68040, // FDMOV80fp_fp
    CEFBS_AtLeastM68040, // FDMUL32fp_fp
    CEFBS_AtLeastM68040, // FDMUL64fp_fp
    CEFBS_AtLeastM68040, // FDMUL80fp_fp
    CEFBS_AtLeastM68040, // FDNEG32fp_fp
    CEFBS_AtLeastM68040, // FDNEG64fp_fp
    CEFBS_AtLeastM68040, // FDNEG80fp_fp
    CEFBS_AtLeastM68040, // FDSUB32fp_fp
    CEFBS_AtLeastM68040, // FDSUB64fp_fp
    CEFBS_AtLeastM68040, // FDSUB80fp_fp
    CEFBS_AtLeastM68881, // FMOV32fp_fp
    CEFBS_AtLeastM68881, // FMOV64fp_fp
    CEFBS_AtLeastM68881, // FMOV80fp_fp
    CEFBS_AtLeastM68881, // FMOVE32a_fpi
    CEFBS_AtLeastM68881, // FMOVE32d_fpcs
    CEFBS_AtLeastM68881, // FMOVE32fpcs_d
    CEFBS_AtLeastM68881, // FMOVE32fpi_a
    CEFBS_AtLeastM68881, // FMUL32fp_fp
    CEFBS_AtLeastM68881, // FMUL64fp_fp
    CEFBS_AtLeastM68881, // FMUL80fp_fp
    CEFBS_AtLeastM68881, // FNEG32fp_fp
    CEFBS_AtLeastM68881, // FNEG64fp_fp
    CEFBS_AtLeastM68881, // FNEG80fp_fp
    CEFBS_AtLeastM68040, // FSABS32fp_fp
    CEFBS_AtLeastM68040, // FSABS64fp_fp
    CEFBS_AtLeastM68040, // FSABS80fp_fp
    CEFBS_AtLeastM68040, // FSADD32fp_fp
    CEFBS_AtLeastM68040, // FSADD64fp_fp
    CEFBS_AtLeastM68040, // FSADD80fp_fp
    CEFBS_AtLeastM68040, // FSDIV32fp_fp
    CEFBS_AtLeastM68040, // FSDIV64fp_fp
    CEFBS_AtLeastM68040, // FSDIV80fp_fp
    CEFBS_AtLeastM68040, // FSMOV32fp_fp
    CEFBS_AtLeastM68040, // FSMOV64fp_fp
    CEFBS_AtLeastM68040, // FSMOV80fp_fp
    CEFBS_AtLeastM68040, // FSMUL32fp_fp
    CEFBS_AtLeastM68040, // FSMUL64fp_fp
    CEFBS_AtLeastM68040, // FSMUL80fp_fp
    CEFBS_AtLeastM68040, // FSNEG32fp_fp
    CEFBS_AtLeastM68040, // FSNEG64fp_fp
    CEFBS_AtLeastM68040, // FSNEG80fp_fp
    CEFBS_AtLeastM68040, // FSSUB32fp_fp
    CEFBS_AtLeastM68040, // FSSUB64fp_fp
    CEFBS_AtLeastM68040, // FSSUB80fp_fp
    CEFBS_AtLeastM68881, // FSUB32fp_fp
    CEFBS_AtLeastM68881, // FSUB64fp_fp
    CEFBS_AtLeastM68881, // FSUB80fp_fp
    CEFBS_None, // ILLEGAL
    CEFBS_None, // JMP32j
    CEFBS_None, // LEA32L
    CEFBS_None, // LEA32b
    CEFBS_None, // LEA32f
    CEFBS_None, // LEA32k
    CEFBS_None, // LEA32l
    CEFBS_None, // LEA32p
    CEFBS_None, // LEA32q
    CEFBS_None, // LINK16
    CEFBS_None, // LINK32
    CEFBS_None, // LSR16dd
    CEFBS_None, // LSR16di
    CEFBS_None, // LSR32dd
    CEFBS_None, // LSR32di
    CEFBS_None, // LSR8dd
    CEFBS_None, // LSR8di
    CEFBS_None, // MOV16aa
    CEFBS_None, // MOV16ab
    CEFBS_None, // MOV16ab_TC
    CEFBS_None, // MOV16ae
    CEFBS_None, // MOV16ae_TC
    CEFBS_None, // MOV16af
    CEFBS_None, // MOV16af_TC
    CEFBS_None, // MOV16ai
    CEFBS_None, // MOV16aj
    CEFBS_None, // MOV16aj_TC
    CEFBS_None, // MOV16ak
    CEFBS_None, // MOV16ak_TC
    CEFBS_None, // MOV16ao
    CEFBS_None, // MOV16ao_TC
    CEFBS_None, // MOV16ap
    CEFBS_None, // MOV16ap_TC
    CEFBS_None, // MOV16aq
    CEFBS_None, // MOV16aq_TC
    CEFBS_None, // MOV16ar
    CEFBS_None, // MOV16ba
    CEFBS_None, // MOV16bb
    CEFBS_AtLeastM68010, // MOV16bc
    CEFBS_None, // MOV16bd
    CEFBS_None, // MOV16be
    CEFBS_None, // MOV16bf
    CEFBS_None, // MOV16bi
    CEFBS_None, // MOV16bj
    CEFBS_None, // MOV16bk
    CEFBS_None, // MOV16bo
    CEFBS_None, // MOV16bp
    CEFBS_None, // MOV16bq
    CEFBS_None, // MOV16br
    CEFBS_None, // MOV16bs
    CEFBS_None, // MOV16cb
    CEFBS_None, // MOV16cd
    CEFBS_None, // MOV16ce
    CEFBS_None, // MOV16cf
    CEFBS_None, // MOV16cj
    CEFBS_None, // MOV16ck
    CEFBS_None, // MOV16co
    CEFBS_None, // MOV16cp
    CEFBS_None, // MOV16cq
    CEFBS_None, // MOV16db
    CEFBS_AtLeastM68010, // MOV16dc
    CEFBS_None, // MOV16dd
    CEFBS_None, // MOV16de
    CEFBS_None, // MOV16df
    CEFBS_None, // MOV16di
    CEFBS_None, // MOV16dj
    CEFBS_None, // MOV16dk
    CEFBS_None, // MOV16do
    CEFBS_None, // MOV16dp
    CEFBS_None, // MOV16dq
    CEFBS_None, // MOV16ds
    CEFBS_None, // MOV16ea
    CEFBS_None, // MOV16eb
    CEFBS_AtLeastM68010, // MOV16ec
    CEFBS_None, // MOV16ed
    CEFBS_None, // MOV16ee
    CEFBS_None, // MOV16ef
    CEFBS_None, // MOV16ei
    CEFBS_None, // MOV16ej
    CEFBS_None, // MOV16ek
    CEFBS_None, // MOV16eo
    CEFBS_None, // MOV16ep
    CEFBS_None, // MOV16eq
    CEFBS_None, // MOV16er
    CEFBS_None, // MOV16es
    CEFBS_None, // MOV16fa
    CEFBS_None, // MOV16fb
    CEFBS_AtLeastM68010, // MOV16fc
    CEFBS_None, // MOV16fd
    CEFBS_None, // MOV16fe
    CEFBS_None, // MOV16ff
    CEFBS_None, // MOV16fi
    CEFBS_None, // MOV16fj
    CEFBS_None, // MOV16fk
    CEFBS_None, // MOV16fo
    CEFBS_None, // MOV16fp
    CEFBS_None, // MOV16fq
    CEFBS_None, // MOV16fr
    CEFBS_None, // MOV16fs
    CEFBS_None, // MOV16ja
    CEFBS_None, // MOV16jb
    CEFBS_AtLeastM68010, // MOV16jc
    CEFBS_None, // MOV16jd
    CEFBS_None, // MOV16je
    CEFBS_None, // MOV16jf
    CEFBS_None, // MOV16ji
    CEFBS_None, // MOV16jj
    CEFBS_None, // MOV16jk
    CEFBS_None, // MOV16jo
    CEFBS_None, // MOV16jp
    CEFBS_None, // MOV16jq
    CEFBS_None, // MOV16jr
    CEFBS_None, // MOV16js
    CEFBS_None, // MOV16oa
    CEFBS_None, // MOV16ob
    CEFBS_AtLeastM68010, // MOV16oc
    CEFBS_None, // MOV16od
    CEFBS_None, // MOV16oe
    CEFBS_None, // MOV16of
    CEFBS_None, // MOV16oi
    CEFBS_None, // MOV16oj
    CEFBS_None, // MOV16ok
    CEFBS_None, // MOV16oo
    CEFBS_None, // MOV16op
    CEFBS_None, // MOV16oq
    CEFBS_None, // MOV16or
    CEFBS_None, // MOV16os
    CEFBS_None, // MOV16pa
    CEFBS_None, // MOV16pb
    CEFBS_AtLeastM68010, // MOV16pc
    CEFBS_None, // MOV16pd
    CEFBS_None, // MOV16pe
    CEFBS_None, // MOV16pf
    CEFBS_None, // MOV16pi
    CEFBS_None, // MOV16pj
    CEFBS_None, // MOV16pk
    CEFBS_None, // MOV16po
    CEFBS_None, // MOV16pp
    CEFBS_None, // MOV16pq
    CEFBS_None, // MOV16pr
    CEFBS_None, // MOV16ps
    CEFBS_None, // MOV16ra
    CEFBS_None, // MOV16rb
    CEFBS_None, // MOV16rb_TC
    CEFBS_None, // MOV16re
    CEFBS_None, // MOV16re_TC
    CEFBS_None, // MOV16rf
    CEFBS_None, // MOV16rf_TC
    CEFBS_None, // MOV16ri
    CEFBS_None, // MOV16rj
    CEFBS_None, // MOV16rj_TC
    CEFBS_None, // MOV16rk
    CEFBS_None, // MOV16rk_TC
    CEFBS_None, // MOV16ro
    CEFBS_None, // MOV16ro_TC
    CEFBS_None, // MOV16rp
    CEFBS_None, // MOV16rp_TC
    CEFBS_None, // MOV16rq
    CEFBS_None, // MOV16rq_TC
    CEFBS_None, // MOV16rr
    CEFBS_None, // MOV16sb
    CEFBS_None, // MOV16sd
    CEFBS_None, // MOV16se
    CEFBS_None, // MOV16sf
    CEFBS_None, // MOV16sj
    CEFBS_None, // MOV16sk
    CEFBS_None, // MOV16so
    CEFBS_None, // MOV16sp
    CEFBS_None, // MOV16sq
    CEFBS_None, // MOV32aa
    CEFBS_None, // MOV32ab
    CEFBS_None, // MOV32ab_TC
    CEFBS_None, // MOV32ae
    CEFBS_None, // MOV32ae_TC
    CEFBS_None, // MOV32af
    CEFBS_None, // MOV32af_TC
    CEFBS_None, // MOV32ai
    CEFBS_None, // MOV32aj
    CEFBS_None, // MOV32aj_TC
    CEFBS_None, // MOV32ak
    CEFBS_None, // MOV32ak_TC
    CEFBS_None, // MOV32ao
    CEFBS_None, // MOV32ao_TC
    CEFBS_None, // MOV32ap
    CEFBS_None, // MOV32ap_TC
    CEFBS_None, // MOV32aq
    CEFBS_None, // MOV32aq_TC
    CEFBS_None, // MOV32ar
    CEFBS_None, // MOV32ba
    CEFBS_None, // MOV32bb
    CEFBS_None, // MOV32bd
    CEFBS_None, // MOV32be
    CEFBS_None, // MOV32bf
    CEFBS_None, // MOV32bi
    CEFBS_None, // MOV32bj
    CEFBS_None, // MOV32bk
    CEFBS_None, // MOV32bo
    CEFBS_None, // MOV32bp
    CEFBS_None, // MOV32bq
    CEFBS_None, // MOV32br
    CEFBS_None, // MOV32db
    CEFBS_None, // MOV32dd
    CEFBS_None, // MOV32de
    CEFBS_None, // MOV32df
    CEFBS_None, // MOV32di
    CEFBS_None, // MOV32dj
    CEFBS_None, // MOV32dk
    CEFBS_None, // MOV32do
    CEFBS_None, // MOV32dp
    CEFBS_None, // MOV32dq
    CEFBS_None, // MOV32ea
    CEFBS_None, // MOV32eb
    CEFBS_None, // MOV32ed
    CEFBS_None, // MOV32ee
    CEFBS_None, // MOV32ef
    CEFBS_None, // MOV32ei
    CEFBS_None, // MOV32ej
    CEFBS_None, // MOV32ek
    CEFBS_None, // MOV32eo
    CEFBS_None, // MOV32ep
    CEFBS_None, // MOV32eq
    CEFBS_None, // MOV32er
    CEFBS_None, // MOV32fa
    CEFBS_None, // MOV32fb
    CEFBS_None, // MOV32fd
    CEFBS_None, // MOV32fe
    CEFBS_None, // MOV32ff
    CEFBS_None, // MOV32fi
    CEFBS_None, // MOV32fj
    CEFBS_None, // MOV32fk
    CEFBS_None, // MOV32fo
    CEFBS_None, // MOV32fp
    CEFBS_None, // MOV32fq
    CEFBS_None, // MOV32fr
    CEFBS_None, // MOV32ja
    CEFBS_None, // MOV32jb
    CEFBS_None, // MOV32jd
    CEFBS_None, // MOV32je
    CEFBS_None, // MOV32jf
    CEFBS_None, // MOV32ji
    CEFBS_None, // MOV32jj
    CEFBS_None, // MOV32jk
    CEFBS_None, // MOV32jo
    CEFBS_None, // MOV32jp
    CEFBS_None, // MOV32jq
    CEFBS_None, // MOV32jr
    CEFBS_None, // MOV32oa
    CEFBS_None, // MOV32ob
    CEFBS_None, // MOV32od
    CEFBS_None, // MOV32oe
    CEFBS_None, // MOV32of
    CEFBS_None, // MOV32oi
    CEFBS_None, // MOV32oj
    CEFBS_None, // MOV32ok
    CEFBS_None, // MOV32oo
    CEFBS_None, // MOV32op
    CEFBS_None, // MOV32oq
    CEFBS_None, // MOV32or
    CEFBS_None, // MOV32pa
    CEFBS_None, // MOV32pb
    CEFBS_None, // MOV32pd
    CEFBS_None, // MOV32pe
    CEFBS_None, // MOV32pf
    CEFBS_None, // MOV32pi
    CEFBS_None, // MOV32pj
    CEFBS_None, // MOV32pk
    CEFBS_None, // MOV32po
    CEFBS_None, // MOV32pp
    CEFBS_None, // MOV32pq
    CEFBS_None, // MOV32pr
    CEFBS_None, // MOV32ra
    CEFBS_None, // MOV32rb
    CEFBS_None, // MOV32rb_TC
    CEFBS_None, // MOV32re
    CEFBS_None, // MOV32re_TC
    CEFBS_None, // MOV32rf
    CEFBS_None, // MOV32rf_TC
    CEFBS_None, // MOV32ri
    CEFBS_None, // MOV32rj
    CEFBS_None, // MOV32rj_TC
    CEFBS_None, // MOV32rk
    CEFBS_None, // MOV32rk_TC
    CEFBS_None, // MOV32ro
    CEFBS_None, // MOV32ro_TC
    CEFBS_None, // MOV32rp
    CEFBS_None, // MOV32rp_TC
    CEFBS_None, // MOV32rq
    CEFBS_None, // MOV32rq_TC
    CEFBS_None, // MOV32rr
    CEFBS_None, // MOV8bb
    CEFBS_None, // MOV8bd
    CEFBS_None, // MOV8be
    CEFBS_None, // MOV8bf
    CEFBS_None, // MOV8bi
    CEFBS_None, // MOV8bj
    CEFBS_None, // MOV8bk
    CEFBS_None, // MOV8bo
    CEFBS_None, // MOV8bp
    CEFBS_None, // MOV8bq
    CEFBS_None, // MOV8db
    CEFBS_None, // MOV8dd
    CEFBS_None, // MOV8de
    CEFBS_None, // MOV8df
    CEFBS_None, // MOV8di
    CEFBS_None, // MOV8dj
    CEFBS_None, // MOV8dk
    CEFBS_None, // MOV8do
    CEFBS_None, // MOV8dp
    CEFBS_None, // MOV8dq
    CEFBS_None, // MOV8eb
    CEFBS_None, // MOV8ed
    CEFBS_None, // MOV8ee
    CEFBS_None, // MOV8ef
    CEFBS_None, // MOV8ei
    CEFBS_None, // MOV8ej
    CEFBS_None, // MOV8ek
    CEFBS_None, // MOV8eo
    CEFBS_None, // MOV8ep
    CEFBS_None, // MOV8eq
    CEFBS_None, // MOV8fb
    CEFBS_None, // MOV8fd
    CEFBS_None, // MOV8fe
    CEFBS_None, // MOV8ff
    CEFBS_None, // MOV8fi
    CEFBS_None, // MOV8fj
    CEFBS_None, // MOV8fk
    CEFBS_None, // MOV8fo
    CEFBS_None, // MOV8fp
    CEFBS_None, // MOV8fq
    CEFBS_None, // MOV8jb
    CEFBS_None, // MOV8jd
    CEFBS_None, // MOV8je
    CEFBS_None, // MOV8jf
    CEFBS_None, // MOV8ji
    CEFBS_None, // MOV8jj
    CEFBS_None, // MOV8jk
    CEFBS_None, // MOV8jo
    CEFBS_None, // MOV8jp
    CEFBS_None, // MOV8jq
    CEFBS_None, // MOV8ob
    CEFBS_None, // MOV8od
    CEFBS_None, // MOV8oe
    CEFBS_None, // MOV8of
    CEFBS_None, // MOV8oi
    CEFBS_None, // MOV8oj
    CEFBS_None, // MOV8ok
    CEFBS_None, // MOV8oo
    CEFBS_None, // MOV8op
    CEFBS_None, // MOV8oq
    CEFBS_None, // MOV8pb
    CEFBS_None, // MOV8pd
    CEFBS_None, // MOV8pe
    CEFBS_None, // MOV8pf
    CEFBS_None, // MOV8pi
    CEFBS_None, // MOV8pj
    CEFBS_None, // MOV8pk
    CEFBS_None, // MOV8po
    CEFBS_None, // MOV8pp
    CEFBS_None, // MOV8pq
    CEFBS_None, // MOVM16bm
    CEFBS_None, // MOVM16em
    CEFBS_None, // MOVM16fm
    CEFBS_None, // MOVM16jm
    CEFBS_None, // MOVM16mb
    CEFBS_None, // MOVM16me
    CEFBS_None, // MOVM16mf
    CEFBS_None, // MOVM16mj
    CEFBS_None, // MOVM16mk
    CEFBS_None, // MOVM16mo
    CEFBS_None, // MOVM16mp
    CEFBS_None, // MOVM16mq
    CEFBS_None, // MOVM16om
    CEFBS_None, // MOVM16pm
    CEFBS_None, // MOVM32bm
    CEFBS_None, // MOVM32em
    CEFBS_None, // MOVM32fm
    CEFBS_None, // MOVM32jm
    CEFBS_None, // MOVM32mb
    CEFBS_None, // MOVM32me
    CEFBS_None, // MOVM32mf
    CEFBS_None, // MOVM32mj
    CEFBS_None, // MOVM32mk
    CEFBS_None, // MOVM32mo
    CEFBS_None, // MOVM32mp
    CEFBS_None, // MOVM32mq
    CEFBS_None, // MOVM32om
    CEFBS_None, // MOVM32pm
    CEFBS_None, // MOVQ
    CEFBS_None, // NEG16d
    CEFBS_None, // NEG32d
    CEFBS_None, // NEG8d
    CEFBS_None, // NEGX16d
    CEFBS_None, // NEGX32d
    CEFBS_None, // NEGX8d
    CEFBS_None, // NOP
    CEFBS_None, // NOT16d
    CEFBS_None, // NOT32d
    CEFBS_None, // NOT8d
    CEFBS_None, // OR16dd
    CEFBS_None, // OR16df
    CEFBS_None, // OR16di
    CEFBS_None, // OR16dj
    CEFBS_None, // OR16dk
    CEFBS_None, // OR16dp
    CEFBS_None, // OR16dq
    CEFBS_None, // OR16dr
    CEFBS_None, // OR16fd
    CEFBS_None, // OR16fi
    CEFBS_None, // OR16jd
    CEFBS_None, // OR16ji
    CEFBS_None, // OR16pd
    CEFBS_None, // OR16pi
    CEFBS_None, // OR32dd
    CEFBS_None, // OR32df
    CEFBS_None, // OR32di
    CEFBS_None, // OR32dj
    CEFBS_None, // OR32dk
    CEFBS_None, // OR32dp
    CEFBS_None, // OR32dq
    CEFBS_None, // OR32dr
    CEFBS_None, // OR32fd
    CEFBS_None, // OR32fi
    CEFBS_None, // OR32jd
    CEFBS_None, // OR32ji
    CEFBS_None, // OR32pd
    CEFBS_None, // OR32pi
    CEFBS_None, // OR8dd
    CEFBS_None, // OR8df
    CEFBS_None, // OR8di
    CEFBS_None, // OR8dj
    CEFBS_None, // OR8dk
    CEFBS_None, // OR8dp
    CEFBS_None, // OR8dq
    CEFBS_None, // OR8fd
    CEFBS_None, // OR8fi
    CEFBS_None, // OR8jd
    CEFBS_None, // OR8ji
    CEFBS_None, // OR8pd
    CEFBS_None, // OR8pi
    CEFBS_None, // ROL16dd
    CEFBS_None, // ROL16di
    CEFBS_None, // ROL32dd
    CEFBS_None, // ROL32di
    CEFBS_None, // ROL8dd
    CEFBS_None, // ROL8di
    CEFBS_None, // ROR16dd
    CEFBS_None, // ROR16di
    CEFBS_None, // ROR32dd
    CEFBS_None, // ROR32di
    CEFBS_None, // ROR8dd
    CEFBS_None, // ROR8di
    CEFBS_None, // RTE
    CEFBS_None, // RTS
    CEFBS_None, // SDIVd32d16
    CEFBS_None, // SDIVd32d32
    CEFBS_None, // SDIVd32i16
    CEFBS_None, // SETd8cc
    CEFBS_None, // SETd8cs
    CEFBS_None, // SETd8eq
    CEFBS_None, // SETd8f
    CEFBS_None, // SETd8ge
    CEFBS_None, // SETd8gt
    CEFBS_None, // SETd8hi
    CEFBS_None, // SETd8le
    CEFBS_None, // SETd8ls
    CEFBS_None, // SETd8lt
    CEFBS_None, // SETd8mi
    CEFBS_None, // SETd8ne
    CEFBS_None, // SETd8pl
    CEFBS_None, // SETd8t
    CEFBS_None, // SETd8vc
    CEFBS_None, // SETd8vs
    CEFBS_None, // SETj8cc
    CEFBS_None, // SETj8cs
    CEFBS_None, // SETj8eq
    CEFBS_None, // SETj8f
    CEFBS_None, // SETj8ge
    CEFBS_None, // SETj8gt
    CEFBS_None, // SETj8hi
    CEFBS_None, // SETj8le
    CEFBS_None, // SETj8ls
    CEFBS_None, // SETj8lt
    CEFBS_None, // SETj8mi
    CEFBS_None, // SETj8ne
    CEFBS_None, // SETj8pl
    CEFBS_None, // SETj8t
    CEFBS_None, // SETj8vc
    CEFBS_None, // SETj8vs
    CEFBS_None, // SETp8cc
    CEFBS_None, // SETp8cs
    CEFBS_None, // SETp8eq
    CEFBS_None, // SETp8f
    CEFBS_None, // SETp8ge
    CEFBS_None, // SETp8gt
    CEFBS_None, // SETp8hi
    CEFBS_None, // SETp8le
    CEFBS_None, // SETp8ls
    CEFBS_None, // SETp8lt
    CEFBS_None, // SETp8mi
    CEFBS_None, // SETp8ne
    CEFBS_None, // SETp8pl
    CEFBS_None, // SETp8t
    CEFBS_None, // SETp8vc
    CEFBS_None, // SETp8vs
    CEFBS_None, // SHL16dd
    CEFBS_None, // SHL16di
    CEFBS_None, // SHL32dd
    CEFBS_None, // SHL32di
    CEFBS_None, // SHL8dd
    CEFBS_None, // SHL8di
    CEFBS_None, // SMULd32d16
    CEFBS_None, // SMULd32d32
    CEFBS_None, // SMULd32i16
    CEFBS_None, // SUB16dd
    CEFBS_None, // SUB16df
    CEFBS_None, // SUB16di
    CEFBS_None, // SUB16dj
    CEFBS_None, // SUB16dk
    CEFBS_None, // SUB16dp
    CEFBS_None, // SUB16dq
    CEFBS_None, // SUB16dr
    CEFBS_None, // SUB16fd
    CEFBS_None, // SUB16fi
    CEFBS_None, // SUB16jd
    CEFBS_None, // SUB16ji
    CEFBS_None, // SUB16pd
    CEFBS_None, // SUB16pi
    CEFBS_None, // SUB32ab
    CEFBS_None, // SUB32af
    CEFBS_None, // SUB32ai
    CEFBS_None, // SUB32aj
    CEFBS_None, // SUB32ak
    CEFBS_None, // SUB32ap
    CEFBS_None, // SUB32aq
    CEFBS_None, // SUB32ar
    CEFBS_None, // SUB32dd
    CEFBS_None, // SUB32df
    CEFBS_None, // SUB32di
    CEFBS_None, // SUB32dj
    CEFBS_None, // SUB32dk
    CEFBS_None, // SUB32dp
    CEFBS_None, // SUB32dq
    CEFBS_None, // SUB32dr
    CEFBS_None, // SUB32fd
    CEFBS_None, // SUB32fi
    CEFBS_None, // SUB32jd
    CEFBS_None, // SUB32ji
    CEFBS_None, // SUB32pd
    CEFBS_None, // SUB32pi
    CEFBS_None, // SUB8dd
    CEFBS_None, // SUB8df
    CEFBS_None, // SUB8di
    CEFBS_None, // SUB8dj
    CEFBS_None, // SUB8dk
    CEFBS_None, // SUB8dp
    CEFBS_None, // SUB8dq
    CEFBS_None, // SUB8fd
    CEFBS_None, // SUB8fi
    CEFBS_None, // SUB8jd
    CEFBS_None, // SUB8ji
    CEFBS_None, // SUB8pd
    CEFBS_None, // SUB8pi
    CEFBS_None, // SUBX16dd
    CEFBS_None, // SUBX32dd
    CEFBS_None, // SUBX8dd
    CEFBS_None, // TRAP
    CEFBS_None, // TRAPV
    CEFBS_None, // UDIVd32d16
    CEFBS_None, // UDIVd32d32
    CEFBS_None, // UDIVd32i16
    CEFBS_None, // UMULd32d16
    CEFBS_None, // UMULd32d32
    CEFBS_None, // UMULd32i16
    CEFBS_None, // UNLK
    CEFBS_None, // XOR16dd
    CEFBS_None, // XOR16di
    CEFBS_None, // XOR32dd
    CEFBS_None, // XOR32di
    CEFBS_None, // XOR8dd
    CEFBS_None, // XOR8di
  };

  assert(Opcode < 1316);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::M68k_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::M68k_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::M68k_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::M68k_MC {

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_AtLeastM68000",
  "Feature_AtLeastM68010",
  "Feature_AtLeastM68020",
  "Feature_AtLeastM68040",
  "Feature_AtLeastM68060",
  "Feature_AtLeastM68881",
  "Feature_AtLeastM68882",
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
    Msg << "Attempting to emit " << &M68kInstrNameData[M68kInstrNameIndices[Opcode]]
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::M68k_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

