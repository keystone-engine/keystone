/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::AVR {

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
    ADCWRdRr                              = 331, // AVRInstrInfo.td:397
    ADDWRdRr                              = 332, // AVRInstrInfo.td:378
    ADJCALLSTACKDOWN                      = 333, // AVRInstrInfo.td:346
    ADJCALLSTACKUP                        = 334, // AVRInstrInfo.td:356
    ANDIWRdK                              = 335, // AVRInstrInfo.td:583
    ANDWRdRr                              = 336, // AVRInstrInfo.td:543
    ASRBNRd                               = 337, // AVRInstrInfo.td:1357
    ASRWLoRd                              = 338, // AVRInstrInfo.td:1364
    ASRWNRd                               = 339, // AVRInstrInfo.td:1353
    ASRWRd                                = 340, // AVRInstrInfo.td:1361
    Asr16                                 = 341, // AVRInstrInfo.td:1625
    Asr32                                 = 342, // AVRInstrInfo.td:1629
    Asr8                                  = 343, // AVRInstrInfo.td:1621
    AtomicFence                           = 344, // AVRInstrInfo.td:1044
    AtomicLoad16                          = 345, // AVRInstrInfo.td:1022
    AtomicLoad8                           = 346, // AVRInstrInfo.td:1021
    AtomicLoadAdd16                       = 347, // AVRInstrInfo.td:1032
    AtomicLoadAdd8                        = 348, // AVRInstrInfo.td:1031
    AtomicLoadAnd16                       = 349, // AVRInstrInfo.td:1036
    AtomicLoadAnd8                        = 350, // AVRInstrInfo.td:1035
    AtomicLoadOr16                        = 351, // AVRInstrInfo.td:1038
    AtomicLoadOr8                         = 352, // AVRInstrInfo.td:1037
    AtomicLoadSub16                       = 353, // AVRInstrInfo.td:1034
    AtomicLoadSub8                        = 354, // AVRInstrInfo.td:1033
    AtomicLoadXor16                       = 355, // AVRInstrInfo.td:1040
    AtomicLoadXor8                        = 356, // AVRInstrInfo.td:1039
    AtomicStore16                         = 357, // AVRInstrInfo.td:1025
    AtomicStore8                          = 358, // AVRInstrInfo.td:1024
    COMWRd                                = 359, // AVRInstrInfo.td:613
    CPCWRdRr                              = 360, // AVRInstrInfo.td:736
    CPWRdRr                               = 361, // AVRInstrInfo.td:721
    CopyZero                              = 362, // AVRInstrInfo.td:1637
    ELPMBRdZ                              = 363, // AVRInstrInfo.td:1221
    ELPMBRdZPi                            = 364, // AVRInstrInfo.td:1233
    ELPMWRdZ                              = 365, // AVRInstrInfo.td:1226
    ELPMWRdZPi                            = 366, // AVRInstrInfo.td:1237
    EORWRdRr                              = 367, // AVRInstrInfo.td:569
    FRMIDX                                = 368, // AVRInstrInfo.td:1530
    INWRdA                                = 369, // AVRInstrInfo.td:1261
    LDDWRdPtrQ                            = 370, // AVRInstrInfo.td:970
    LDDWRdYQ                              = 371, // AVRInstrInfo.td:991
    LDIWRdK                               = 372, // AVRInstrInfo.td:874
    LDSWRdK                               = 373, // AVRInstrInfo.td:894
    LDWRdPtr                              = 374, // AVRInstrInfo.td:917
    LDWRdPtrPd                            = 375, // AVRInstrInfo.td:947
    LDWRdPtrPi                            = 376, // AVRInstrInfo.td:934
    LPMBRdZ                               = 377, // AVRInstrInfo.td:1179
    LPMWRdZ                               = 378, // AVRInstrInfo.td:1183
    LPMWRdZPi                             = 379, // AVRInstrInfo.td:1198
    LSLBNRd                               = 380, // AVRInstrInfo.td:1329
    LSLWHiRd                              = 381, // AVRInstrInfo.td:1322
    LSLWNRd                               = 382, // AVRInstrInfo.td:1325
    LSLWRd                                = 383, // AVRInstrInfo.td:1319
    LSRBNRd                               = 384, // AVRInstrInfo.td:1346
    LSRWLoRd                              = 385, // AVRInstrInfo.td:1339
    LSRWNRd                               = 386, // AVRInstrInfo.td:1342
    LSRWRd                                = 387, // AVRInstrInfo.td:1336
    Lsl16                                 = 388, // AVRInstrInfo.td:1581
    Lsl32                                 = 389, // AVRInstrInfo.td:1585
    Lsl8                                  = 390, // AVRInstrInfo.td:1577
    Lsr16                                 = 391, // AVRInstrInfo.td:1595
    Lsr32                                 = 392, // AVRInstrInfo.td:1599
    Lsr8                                  = 393, // AVRInstrInfo.td:1591
    NEGWRd                                = 394, // AVRInstrInfo.td:625
    ORIWRdK                               = 395, // AVRInstrInfo.td:596
    ORWRdRr                               = 396, // AVRInstrInfo.td:556
    OUTWARr                               = 397, // AVRInstrInfo.td:1270
    POPWRd                                = 398, // AVRInstrInfo.td:1291
    PUSHWRr                               = 399, // AVRInstrInfo.td:1282
    ROLBRdR1                              = 400, // AVRInstrInfo.td:1368
    ROLBRdR17                             = 401, // AVRInstrInfo.td:1373
    ROLWRd                                = 402, // AVRInstrInfo.td:1382
    RORBRd                                = 403, // AVRInstrInfo.td:1377
    RORWRd                                = 404, // AVRInstrInfo.td:1388
    Rol16                                 = 405, // AVRInstrInfo.td:1609
    Rol8                                  = 406, // AVRInstrInfo.td:1605
    Ror16                                 = 407, // AVRInstrInfo.td:1617
    Ror8                                  = 408, // AVRInstrInfo.td:1613
    SBCIWRdK                              = 409, // AVRInstrInfo.td:469
    SBCWRdRr                              = 410, // AVRInstrInfo.td:458
    SEXT                                  = 411, // AVRInstrInfo.td:1522
    SPREAD                                = 412, // AVRInstrInfo.td:1558
    SPWRITE                               = 413, // AVRInstrInfo.td:1561
    STDSPQRr                              = 414, // AVRInstrInfo.td:1545
    STDWPtrQRr                            = 415, // AVRInstrInfo.td:1167
    STDWSPQRr                             = 416, // AVRInstrInfo.td:1552
    STSWKRr                               = 417, // AVRInstrInfo.td:1065
    STWPtrPdRr                            = 418, // AVRInstrInfo.td:1137
    STWPtrPiRr                            = 419, // AVRInstrInfo.td:1112
    STWPtrRr                              = 420, // AVRInstrInfo.td:1088
    SUBIWRdK                              = 421, // AVRInstrInfo.td:438
    SUBWRdRr                              = 422, // AVRInstrInfo.td:425
    Select16                              = 423, // AVRInstrInfo.td:1571
    Select8                               = 424, // AVRInstrInfo.td:1565
    ZEXT                                  = 425, // AVRInstrInfo.td:1525
    ADCRdRr                               = 426, // AVRInstrInfo.td:385
    ADDRdRr                               = 427, // AVRInstrInfo.td:368
    ADIWRdK                               = 428, // AVRInstrInfo.td:403
    ANDIRdK                               = 429, // AVRInstrInfo.td:574
    ANDRdRr                               = 430, // AVRInstrInfo.td:534
    ASRRd                                 = 431, // AVRInstrInfo.td:1350
    BCLRs                                 = 432, // AVRInstrInfo.td:1446
    BLD                                   = 433, // AVRInstrInfo.td:1419
    BRBCsk                                = 434, // AVRInstrInfo.td:775
    BRBSsk                                = 435, // AVRInstrInfo.td:770
    BREAK                                 = 436, // AVRInstrInfo.td:1490
    BREQk                                 = 437, // AVRInstrInfo.td:826
    BRGEk                                 = 438, // AVRInstrInfo.td:844
    BRLOk                                 = 439, // AVRInstrInfo.td:835
    BRLTk                                 = 440, // AVRInstrInfo.td:847
    BRMIk                                 = 441, // AVRInstrInfo.td:838
    BRNEk                                 = 442, // AVRInstrInfo.td:829
    BRPLk                                 = 443, // AVRInstrInfo.td:841
    BRSHk                                 = 444, // AVRInstrInfo.td:832
    BSETs                                 = 445, // AVRInstrInfo.td:1445
    BST                                   = 446, // AVRInstrInfo.td:1416
    CALLk                                 = 447, // AVRInstrInfo.td:688
    CBIAb                                 = 448, // AVRInstrInfo.td:1408
    COMRd                                 = 449, // AVRInstrInfo.td:605
    CPCRdRr                               = 450, // AVRInstrInfo.td:726
    CPIRdK                                = 451, // AVRInstrInfo.td:742
    CPRdRr                                = 452, // AVRInstrInfo.td:712
    CPSE                                  = 453, // AVRInstrInfo.td:709
    DECRd                                 = 454, // AVRInstrInfo.td:483
    DESK                                  = 455, // AVRInstrInfo.td:525
    EICALL                                = 456, // AVRInstrInfo.td:678
    EIJMP                                 = 457, // AVRInstrInfo.td:652
    ELPM                                  = 458, // AVRInstrInfo.td:1207
    ELPMRdZ                               = 459, // AVRInstrInfo.td:1210
    ELPMRdZPi                             = 460, // AVRInstrInfo.td:1215
    EORRdRr                               = 461, // AVRInstrInfo.td:560
    FMUL                                  = 462, // AVRInstrInfo.td:509
    FMULS                                 = 463, // AVRInstrInfo.td:513
    FMULSU                                = 464, // AVRInstrInfo.td:517
    ICALL                                 = 465, // AVRInstrInfo.td:672
    IJMP                                  = 466, // AVRInstrInfo.td:648
    INCRd                                 = 467, // AVRInstrInfo.td:479
    INRdA                                 = 468, // AVRInstrInfo.td:1258
    JMPk                                  = 469, // AVRInstrInfo.td:655
    LACZRd                                = 470, // AVRInstrInfo.td:1304
    LASZRd                                = 471, // AVRInstrInfo.td:1301
    LATZRd                                = 472, // AVRInstrInfo.td:1307
    LDDRdPtrQ                             = 473, // AVRInstrInfo.td:954
    LDIRdK                                = 474, // AVRInstrInfo.td:866
    LDRdPtr                               = 475, // AVRInstrInfo.td:902
    LDRdPtrPd                             = 476, // AVRInstrInfo.td:938
    LDRdPtrPi                             = 477, // AVRInstrInfo.td:926
    LDSRdK                                = 478, // AVRInstrInfo.td:880
    LDSRdKTiny                            = 479, // AVRInstrInfo.td:885
    LPM                                   = 480, // AVRInstrInfo.td:1174
    LPMRdZ                                = 481, // AVRInstrInfo.td:1187
    LPMRdZPi                              = 482, // AVRInstrInfo.td:1194
    LSRRd                                 = 483, // AVRInstrInfo.td:1333
    MOVRdRr                               = 484, // AVRInstrInfo.td:856
    MOVWRdRr                              = 485, // AVRInstrInfo.td:859
    MULRdRr                               = 486, // AVRInstrInfo.td:496
    MULSRdRr                              = 487, // AVRInstrInfo.td:500
    MULSURdRr                             = 488, // AVRInstrInfo.td:505
    NEGRd                                 = 489, // AVRInstrInfo.td:616
    NOP                                   = 490, // AVRInstrInfo.td:1499
    ORIRdK                                = 491, // AVRInstrInfo.td:587
    ORRdRr                                = 492, // AVRInstrInfo.td:547
    OUTARr                                = 493, // AVRInstrInfo.td:1267
    POPRd                                 = 494, // AVRInstrInfo.td:1288
    PUSHRr                                = 495, // AVRInstrInfo.td:1278
    RCALLk                                = 496, // AVRInstrInfo.td:666
    RET                                   = 497, // AVRInstrInfo.td:697
    RETI                                  = 498, // AVRInstrInfo.td:699
    RJMPk                                 = 499, // AVRInstrInfo.td:645
    RORRd                                 = 500, // AVRInstrInfo.td:1385
    SBCIRdK                               = 501, // AVRInstrInfo.td:462
    SBCRdRr                               = 502, // AVRInstrInfo.td:449
    SBIAb                                 = 503, // AVRInstrInfo.td:1403
    SBICAb                                = 504, // AVRInstrInfo.td:759
    SBISAb                                = 505, // AVRInstrInfo.td:762
    SBIWRdK                               = 506, // AVRInstrInfo.td:442
    SBRCRrB                               = 507, // AVRInstrInfo.td:753
    SBRSRrB                               = 508, // AVRInstrInfo.td:756
    SLEEP                                 = 509, // AVRInstrInfo.td:1506
    SPM                                   = 510, // AVRInstrInfo.td:1246
    SPMZPi                                = 511, // AVRInstrInfo.td:1250
    STDPtrQRr                             = 512, // AVRInstrInfo.td:1150
    STPtrPdRr                             = 513, // AVRInstrInfo.td:1123
    STPtrPiRr                             = 514, // AVRInstrInfo.td:1098
    STPtrRr                               = 515, // AVRInstrInfo.td:1073
    STSKRr                                = 516, // AVRInstrInfo.td:1049
    STSKRrTiny                            = 517, // AVRInstrInfo.td:1054
    SUBIRdK                               = 518, // AVRInstrInfo.td:429
    SUBRdRr                               = 519, // AVRInstrInfo.td:415
    SWAPRd                                = 520, // AVRInstrInfo.td:1396
    WDR                                   = 521, // AVRInstrInfo.td:1513
    XCHZRd                                = 522, // AVRInstrInfo.td:1298
    INSTRUCTION_LIST_END = 523
  };

} // namespace llvm_ks::AVR

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::AVR::Sched {

  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };

} // namespace llvm_ks::AVR::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct AVRInstrTable {
  MCInstrDesc Insts[523];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[41];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[312];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof AVRInstrTable::ImplicitOps + sizeof AVRInstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned AVROpInfoBase = (sizeof AVRInstrTable::ImplicitOps + sizeof AVRInstrTable::Padding) / sizeof(MCOperandInfo);

extern const AVRInstrTable AVRDescs = {
  {
    { 522,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 222,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XCHZRd
    { 521,	0,	0,	2,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // WDR
    { 520,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 237,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SWAPRd
    { 519,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 268,	2,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBRdRr
    { 518,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 274,	2,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBIRdK
    { 517,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 310,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STSKRrTiny
    { 516,	2,	0,	4,	0,	0,	0,	AVROpInfoBase + 300,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STSKRr
    { 515,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 188,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STPtrRr
    { 514,	4,	1,	2,	0,	0,	0,	AVROpInfoBase + 306,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STPtrPiRr
    { 513,	4,	1,	2,	0,	0,	0,	AVROpInfoBase + 306,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STPtrPdRr
    { 512,	3,	0,	2,	0,	0,	0,	AVROpInfoBase + 303,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STDPtrQRr
    { 511,	1,	0,	2,	0,	2,	1,	AVROpInfoBase + 302,	38,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPMZPi
    { 510,	0,	0,	2,	0,	1,	0,	AVROpInfoBase + 1,	9,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPM
    { 509,	0,	0,	2,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SLEEP
    { 508,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 282,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SBRSRrB
    { 507,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 282,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SBRCRrB
    { 506,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 271,	2,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SBIWRdK
    { 505,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 32,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SBISAb
    { 504,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 32,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SBICAb
    { 503,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 32,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SBIAb
    { 502,	3,	1,	2,	0,	1,	1,	AVROpInfoBase + 268,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SBCRdRr
    { 501,	3,	1,	2,	0,	1,	1,	AVROpInfoBase + 274,	0,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SBCIRdK
    { 500,	2,	1,	2,	0,	1,	1,	AVROpInfoBase + 237,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RORRd
    { 499,	1,	0,	2,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RJMPk
    { 498,	0,	0,	2,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RETI
    { 497,	0,	0,	2,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET
    { 496,	1,	0,	2,	0,	1,	0,	AVROpInfoBase + 0,	16,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RCALLk
    { 495,	1,	0,	2,	0,	1,	1,	AVROpInfoBase + 192,	10,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PUSHRr
    { 494,	1,	1,	2,	0,	1,	1,	AVROpInfoBase + 192,	10,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POPRd
    { 493,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 300,	0,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OUTARr
    { 492,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 268,	2,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ORRdRr
    { 491,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 274,	2,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ORIRdK
    { 490,	0,	0,	2,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOP
    { 489,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 237,	2,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEGRd
    { 488,	2,	0,	2,	0,	0,	3,	AVROpInfoBase + 288,	35,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULSURdRr
    { 487,	2,	0,	2,	0,	0,	3,	AVROpInfoBase + 298,	35,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULSRdRr
    { 486,	2,	0,	2,	0,	0,	3,	AVROpInfoBase + 284,	35,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MULRdRr
    { 485,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 190,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVWRdRr
    { 484,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 284,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MOVRdRr
    { 483,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 237,	2,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSRRd
    { 482,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 222,	9,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LPMRdZPi
    { 481,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 222,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LPMRdZ
    { 480,	0,	0,	2,	0,	1,	1,	AVROpInfoBase + 1,	33,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LPM
    { 479,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 286,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDSRdKTiny
    { 478,	2,	1,	4,	0,	0,	0,	AVROpInfoBase + 290,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDSRdK
    { 477,	3,	2,	2,	0,	0,	0,	AVROpInfoBase + 295,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDRdPtrPi
    { 476,	3,	2,	2,	0,	0,	0,	AVROpInfoBase + 295,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDRdPtrPd
    { 475,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 178,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDRdPtr
    { 474,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 286,	0,	0|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDIRdK
    { 473,	3,	1,	2,	0,	0,	0,	AVROpInfoBase + 292,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDDRdPtrQ
    { 472,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 222,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LATZRd
    { 471,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 222,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LASZRd
    { 470,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 222,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LACZRd
    { 469,	1,	0,	4,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // JMPk
    { 468,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 290,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INRdA
    { 467,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 237,	2,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INCRd
    { 466,	0,	0,	2,	0,	1,	0,	AVROpInfoBase + 1,	9,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // IJMP
    { 465,	0,	0,	2,	0,	2,	0,	AVROpInfoBase + 1,	6,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ICALL
    { 464,	2,	0,	2,	0,	0,	3,	AVROpInfoBase + 288,	35,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMULSU
    { 463,	2,	0,	2,	0,	0,	3,	AVROpInfoBase + 288,	35,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMULS
    { 462,	2,	0,	2,	0,	0,	3,	AVROpInfoBase + 288,	35,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FMUL
    { 461,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 268,	2,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EORRdRr
    { 460,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 222,	9,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ELPMRdZPi
    { 459,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 222,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ELPMRdZ
    { 458,	0,	0,	2,	0,	1,	1,	AVROpInfoBase + 1,	33,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ELPM
    { 457,	0,	0,	2,	0,	1,	0,	AVROpInfoBase + 1,	9,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EIJMP
    { 456,	0,	0,	2,	0,	2,	0,	AVROpInfoBase + 1,	6,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EICALL
    { 455,	1,	0,	2,	0,	0,	16,	AVROpInfoBase + 1,	17,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DESK
    { 454,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 237,	2,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DECRd
    { 453,	2,	0,	2,	0,	0,	1,	AVROpInfoBase + 284,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CPSE
    { 452,	2,	0,	2,	0,	0,	1,	AVROpInfoBase + 284,	2,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CPRdRr
    { 451,	2,	0,	2,	0,	0,	1,	AVROpInfoBase + 286,	2,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CPIRdK
    { 450,	2,	0,	2,	0,	1,	1,	AVROpInfoBase + 284,	0,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CPCRdRr
    { 449,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 237,	2,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COMRd
    { 448,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 32,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CBIAb
    { 447,	1,	0,	4,	0,	1,	0,	AVROpInfoBase + 0,	16,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALLk
    { 446,	2,	0,	2,	0,	0,	1,	AVROpInfoBase + 282,	2,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BST
    { 445,	1,	0,	2,	0,	0,	1,	AVROpInfoBase + 1,	2,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BSETs
    { 444,	1,	0,	2,	0,	1,	0,	AVROpInfoBase + 0,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRSHk
    { 443,	1,	0,	2,	0,	1,	0,	AVROpInfoBase + 0,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRPLk
    { 442,	1,	0,	2,	0,	1,	0,	AVROpInfoBase + 0,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRNEk
    { 441,	1,	0,	2,	0,	1,	0,	AVROpInfoBase + 0,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRMIk
    { 440,	1,	0,	2,	0,	1,	0,	AVROpInfoBase + 0,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRLTk
    { 439,	1,	0,	2,	0,	1,	0,	AVROpInfoBase + 0,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRLOk
    { 438,	1,	0,	2,	0,	1,	0,	AVROpInfoBase + 0,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRGEk
    { 437,	1,	0,	2,	0,	1,	0,	AVROpInfoBase + 0,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BREQk
    { 436,	0,	0,	2,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BREAK
    { 435,	2,	0,	2,	0,	1,	0,	AVROpInfoBase + 280,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRBSsk
    { 434,	2,	0,	2,	0,	1,	0,	AVROpInfoBase + 280,	2,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BRBCsk
    { 433,	3,	1,	2,	0,	1,	0,	AVROpInfoBase + 277,	2,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BLD
    { 432,	1,	0,	2,	0,	0,	1,	AVROpInfoBase + 1,	2,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BCLRs
    { 431,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 237,	2,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASRRd
    { 430,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 268,	2,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANDRdRr
    { 429,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 274,	2,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANDIRdK
    { 428,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 271,	2,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADIWRdK
    { 427,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 268,	2,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDRdRr
    { 426,	3,	1,	2,	0,	1,	1,	AVROpInfoBase + 268,	0,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADCRdRr
    { 425,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 239,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ZEXT
    { 424,	4,	1,	2,	0,	1,	0,	AVROpInfoBase + 264,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Select8
    { 423,	4,	1,	2,	0,	1,	0,	AVROpInfoBase + 260,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Select16
    { 422,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 151,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBWRdRr
    { 421,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 154,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBIWRdK
    { 420,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STWPtrRr
    { 419,	4,	1,	2,	0,	0,	0,	AVROpInfoBase + 256,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STWPtrPiRr
    { 418,	4,	1,	2,	0,	0,	0,	AVROpInfoBase + 256,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STWPtrPdRr
    { 417,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 254,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STSWKRr
    { 416,	3,	0,	2,	0,	1,	1,	AVROpInfoBase + 251,	10,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STDWSPQRr
    { 415,	3,	0,	2,	0,	0,	0,	AVROpInfoBase + 248,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STDWPtrQRr
    { 414,	3,	0,	2,	0,	1,	1,	AVROpInfoBase + 245,	10,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STDSPQRr
    { 413,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 243,	16,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPWRITE
    { 412,	2,	1,	2,	0,	1,	0,	AVROpInfoBase + 241,	16,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPREAD
    { 411,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 239,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SEXT
    { 410,	3,	1,	2,	0,	1,	1,	AVROpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SBCWRdRr
    { 409,	3,	1,	2,	0,	1,	1,	AVROpInfoBase + 154,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SBCIWRdK
    { 408,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 173,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Ror8
    { 407,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 165,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Ror16
    { 406,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 173,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Rol8
    { 405,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 165,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Rol16
    { 404,	2,	1,	2,	0,	1,	1,	AVROpInfoBase + 160,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RORWRd
    { 403,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 237,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RORBRd
    { 402,	2,	1,	2,	0,	1,	1,	AVROpInfoBase + 160,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROLWRd
    { 401,	2,	1,	2,	0,	1,	1,	AVROpInfoBase + 237,	14,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROLBRdR17
    { 400,	2,	1,	2,	0,	1,	1,	AVROpInfoBase + 237,	12,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROLBRdR1
    { 399,	1,	0,	2,	0,	1,	1,	AVROpInfoBase + 236,	10,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PUSHWRr
    { 398,	1,	1,	2,	0,	1,	1,	AVROpInfoBase + 236,	10,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POPWRd
    { 397,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 234,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OUTWARr
    { 396,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 151,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ORWRdRr
    { 395,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 154,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ORIWRdK
    { 394,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 231,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEGWRd
    { 393,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 173,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Lsr8
    { 392,	5,	2,	2,	0,	0,	1,	AVROpInfoBase + 168,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Lsr32
    { 391,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 165,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Lsr16
    { 390,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 173,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Lsl8
    { 389,	5,	2,	2,	0,	0,	1,	AVROpInfoBase + 168,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Lsl32
    { 388,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 165,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Lsl16
    { 387,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 160,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSRWRd
    { 386,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 228,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSRWNRd
    { 385,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 160,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSRWLoRd
    { 384,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 157,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSRBNRd
    { 383,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 160,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSLWRd
    { 382,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 228,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSLWNRd
    { 381,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 160,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSLWHiRd
    { 380,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 157,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LSLBNRd
    { 379,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 226,	9,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LPMWRdZPi
    { 378,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 224,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LPMWRdZ
    { 377,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 222,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LPMBRdZ
    { 376,	3,	2,	2,	0,	0,	0,	AVROpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDWRdPtrPi
    { 375,	3,	2,	2,	0,	0,	0,	AVROpInfoBase + 219,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDWRdPtrPd
    { 374,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 217,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDWRdPtr
    { 373,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 215,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDSWRdK
    { 372,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 213,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDIWRdK
    { 371,	3,	1,	2,	0,	0,	0,	AVROpInfoBase + 210,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDDWRdYQ
    { 370,	3,	1,	2,	0,	0,	0,	AVROpInfoBase + 207,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LDDWRdPtrQ
    { 369,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 205,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INWRdA
    { 368,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 202,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FRMIDX
    { 367,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 151,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EORWRdRr
    { 366,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 199,	9,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ELPMWRdZPi
    { 365,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 196,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ELPMWRdZ
    { 364,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 193,	9,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ELPMBRdZPi
    { 363,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 193,	8,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ELPMBRdZ
    { 362,	1,	1,	2,	0,	0,	0,	AVROpInfoBase + 192,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CopyZero
    { 361,	2,	0,	2,	0,	0,	1,	AVROpInfoBase + 190,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CPWRdRr
    { 360,	2,	0,	2,	0,	1,	1,	AVROpInfoBase + 190,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CPCWRdRr
    { 359,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 160,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COMWRd
    { 358,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 188,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicStore8
    { 357,	2,	0,	2,	0,	0,	0,	AVROpInfoBase + 186,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicStore16
    { 356,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 183,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoadXor8
    { 355,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 180,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoadXor16
    { 354,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 183,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoadSub8
    { 353,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 180,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoadSub16
    { 352,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 183,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoadOr8
    { 351,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 180,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoadOr16
    { 350,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 183,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoadAnd8
    { 349,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 180,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoadAnd16
    { 348,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 183,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoadAdd8
    { 347,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 180,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoadAdd16
    { 346,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 178,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoad8
    { 345,	2,	1,	2,	0,	0,	0,	AVROpInfoBase + 176,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicLoad16
    { 344,	0,	0,	2,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AtomicFence
    { 343,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 173,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Asr8
    { 342,	5,	2,	2,	0,	0,	1,	AVROpInfoBase + 168,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Asr32
    { 341,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 165,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Asr16
    { 340,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 160,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASRWRd
    { 339,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 162,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASRWNRd
    { 338,	2,	1,	2,	0,	0,	1,	AVROpInfoBase + 160,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASRWLoRd
    { 337,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 157,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ASRBNRd
    { 336,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 151,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANDWRdRr
    { 335,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 154,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANDIWRdK
    { 334,	2,	0,	2,	0,	1,	1,	AVROpInfoBase + 20,	6,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKUP
    { 333,	2,	0,	2,	0,	1,	2,	AVROpInfoBase + 20,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKDOWN
    { 332,	3,	1,	2,	0,	0,	1,	AVROpInfoBase + 151,	2,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADDWRdRr
    { 331,	3,	1,	2,	0,	1,	1,	AVROpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADCWRdRr
    { 330,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	AVROpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	AVROpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	AVROpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	AVROpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	AVROpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	AVROpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	AVROpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	AVROpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	AVROpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	AVROpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	AVROpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	AVROpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	AVROpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	AVROpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	AVROpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	AVROpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	AVROpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	AVROpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	AVROpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	AVROpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	AVROpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	AVROpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	AVROpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	AVROpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	AVROpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	AVROpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	AVROpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	AVROpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	AVROpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14316
    { 41,	2,	0,	0,	0,	0,	0,	AVROpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14315
    { 40,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	AVROpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14314
    { 31,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	AVROpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	AVROpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	AVROpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	0,	0,	0,	AVROpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	0,	0,	0,	AVROpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	0,	0,	0,	AVROpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	AVROpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	AVROpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PHI
  }, {
    /* 0 */
    /* 0 */ AVR::SREG, AVR::SREG,
    /* 2 */ AVR::SREG,
    /* 3 */ AVR::SP, AVR::SP, AVR::SREG,
    /* 6 */ AVR::SP, AVR::R31R30,
    /* 8 */ AVR::R0,
    /* 9 */ AVR::R31R30,
    /* 10 */ AVR::SP, AVR::SP,
    /* 12 */ AVR::R1, AVR::SREG,
    /* 14 */ AVR::R17, AVR::SREG,
    /* 16 */ AVR::SP,
    /* 17 */ AVR::R15, AVR::R14, AVR::R13, AVR::R12, AVR::R11, AVR::R10, AVR::R9, AVR::R8, AVR::R7, AVR::R6, AVR::R5, AVR::R4, AVR::R3, AVR::R2, AVR::R1, AVR::R0,
    /* 33 */ AVR::R31R30, AVR::R0,
    /* 35 */ AVR::R1, AVR::R0, AVR::SREG,
    /* 38 */ AVR::R1, AVR::R0, AVR::R31R30,
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
    /* 28 */ { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
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
    /* 151 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 154 */ { AVR::DLDREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DLDREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 157 */ { AVR::LD8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 160 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 162 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 165 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 168 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 173 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 176 */ { AVR::DREGSNOZRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 178 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 180 */ { AVR::DREGSNOZRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSNOZRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 183 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 186 */ { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSNOZRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 188 */ { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 190 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 192 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 193 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::ZREGRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::LD8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 196 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { AVR::ZREGRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::LD8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 199 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::ZREGRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::LD8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 202 */ { AVR::DLDREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DLDREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 205 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 207 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 210 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 213 */ { AVR::DLDREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 215 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 217 */ { AVR::DREGSNOZRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 219 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) },
    /* 222 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::ZREGRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 224 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { AVR::ZREGRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 226 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::ZREGRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 228 */ { AVR::DLDREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 231 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 234 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 236 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 237 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) },
    /* 239 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 241 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPRSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 243 */ { AVR::GPRSPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 245 */ { AVR::GPRSPRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { AVR::GPR8NOZRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 248 */ { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 251 */ { AVR::GPRSPRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { AVR::DREGSNOZRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 254 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 256 */ { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 260 */ { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::DREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 264 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 268 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 271 */ { AVR::IWREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::IWREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 274 */ { AVR::LD8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::LD8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 277 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 280 */ { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 282 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 284 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 286 */ { AVR::LD8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 288 */ { AVR::LD8loRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::LD8loRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 290 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 292 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 295 */ { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(1) },
    /* 298 */ { AVR::LD8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { AVR::LD8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 300 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 302 */ { AVR::ZREGRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 303 */ { AVR::PTRDISPREGSRegClassID, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 306 */ { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_EARLY_CLOBBER }, { AVR::PTRREGSRegClassID, 0, MCOI::OPERAND_REGISTER, MCOI_TIED_TO(0) }, { AVR::GPR8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 310 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { AVR::LD8RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
  }
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char AVRInstrNameData[] = {
  /* 0 */ "G_FLOG10\000"
  /* 9 */ "G_FEXP10\000"
  /* 18 */ "ROLBRdR1\000"
  /* 27 */ "Lsl32\000"
  /* 33 */ "Asr32\000"
  /* 39 */ "Lsr32\000"
  /* 45 */ "G_FLOG2\000"
  /* 53 */ "G_FATAN2\000"
  /* 62 */ "G_FEXP2\000"
  /* 70 */ "AtomicLoadSub16\000"
  /* 86 */ "AtomicLoad16\000"
  /* 99 */ "AtomicLoadAdd16\000"
  /* 115 */ "AtomicLoadAnd16\000"
  /* 131 */ "AtomicStore16\000"
  /* 145 */ "Rol16\000"
  /* 151 */ "Lsl16\000"
  /* 157 */ "AtomicLoadOr16\000"
  /* 172 */ "Ror16\000"
  /* 178 */ "AtomicLoadXor16\000"
  /* 194 */ "Asr16\000"
  /* 200 */ "Lsr16\000"
  /* 206 */ "Select16\000"
  /* 215 */ "ROLBRdR17\000"
  /* 225 */ "AtomicLoadSub8\000"
  /* 240 */ "AtomicLoad8\000"
  /* 252 */ "AtomicLoadAdd8\000"
  /* 267 */ "AtomicLoadAnd8\000"
  /* 282 */ "AtomicStore8\000"
  /* 295 */ "Rol8\000"
  /* 300 */ "Lsl8\000"
  /* 305 */ "AtomicLoadOr8\000"
  /* 319 */ "Ror8\000"
  /* 324 */ "AtomicLoadXor8\000"
  /* 339 */ "Asr8\000"
  /* 344 */ "Lsr8\000"
  /* 349 */ "Select8\000"
  /* 357 */ "G_FMA\000"
  /* 363 */ "G_STRICT_FMA\000"
  /* 376 */ "INRdA\000"
  /* 382 */ "INWRdA\000"
  /* 389 */ "G_FSUB\000"
  /* 396 */ "G_STRICT_FSUB\000"
  /* 410 */ "G_ATOMICRMW_FSUB\000"
  /* 427 */ "G_SUB\000"
  /* 433 */ "G_ATOMICRMW_SUB\000"
  /* 449 */ "SBRCRrB\000"
  /* 457 */ "SBRSRrB\000"
  /* 465 */ "G_INTRINSIC\000"
  /* 477 */ "G_FPTRUNC\000"
  /* 487 */ "G_INTRINSIC_TRUNC\000"
  /* 505 */ "G_TRUNC\000"
  /* 513 */ "G_BUILD_VECTOR_TRUNC\000"
  /* 534 */ "G_DYN_STACKALLOC\000"
  /* 551 */ "SPREAD\000"
  /* 558 */ "G_FMAD\000"
  /* 565 */ "G_FPEXTLOAD\000"
  /* 577 */ "G_INDEXED_SEXTLOAD\000"
  /* 596 */ "G_SEXTLOAD\000"
  /* 607 */ "G_INDEXED_ZEXTLOAD\000"
  /* 626 */ "G_ZEXTLOAD\000"
  /* 637 */ "G_INDEXED_LOAD\000"
  /* 652 */ "G_LOAD\000"
  /* 659 */ "G_VECREDUCE_FADD\000"
  /* 676 */ "G_FADD\000"
  /* 683 */ "G_VECREDUCE_SEQ_FADD\000"
  /* 704 */ "G_STRICT_FADD\000"
  /* 718 */ "G_ATOMICRMW_FADD\000"
  /* 735 */ "G_VECREDUCE_ADD\000"
  /* 751 */ "G_ADD\000"
  /* 757 */ "G_PTR_ADD\000"
  /* 767 */ "G_ATOMICRMW_ADD\000"
  /* 783 */ "BLD\000"
  /* 787 */ "G_ATOMICRMW_NAND\000"
  /* 804 */ "G_VECREDUCE_AND\000"
  /* 820 */ "G_AND\000"
  /* 826 */ "G_ATOMICRMW_AND\000"
  /* 842 */ "LIFETIME_END\000"
  /* 855 */ "G_BRCOND\000"
  /* 864 */ "G_ATOMICRMW_USUB_COND\000"
  /* 886 */ "G_LLROUND\000"
  /* 896 */ "G_LROUND\000"
  /* 905 */ "G_INTRINSIC_ROUND\000"
  /* 923 */ "G_INTRINSIC_FPTRUNC_ROUND\000"
  /* 949 */ "LOAD_STACK_GUARD\000"
  /* 966 */ "PSEUDO_PROBE\000"
  /* 979 */ "G_SSUBE\000"
  /* 987 */ "G_USUBE\000"
  /* 995 */ "G_FENCE\000"
  /* 1003 */ "ARITH_FENCE\000"
  /* 1015 */ "REG_SEQUENCE\000"
  /* 1028 */ "G_SADDE\000"
  /* 1036 */ "G_UADDE\000"
  /* 1044 */ "G_GET_FPMODE\000"
  /* 1057 */ "G_RESET_FPMODE\000"
  /* 1072 */ "G_SET_FPMODE\000"
  /* 1085 */ "G_FMINNUM_IEEE\000"
  /* 1100 */ "G_FMAXNUM_IEEE\000"
  /* 1115 */ "G_VSCALE\000"
  /* 1124 */ "G_JUMP_TABLE\000"
  /* 1137 */ "BUNDLE\000"
  /* 1144 */ "G_MEMSET_INLINE\000"
  /* 1160 */ "G_MEMCPY_INLINE\000"
  /* 1176 */ "RELOC_NONE\000"
  /* 1187 */ "LOCAL_ESCAPE\000"
  /* 1200 */ "G_FPTRUNCSTORE\000"
  /* 1215 */ "G_STACKRESTORE\000"
  /* 1230 */ "G_INDEXED_STORE\000"
  /* 1246 */ "G_STORE\000"
  /* 1254 */ "CPSE\000"
  /* 1259 */ "G_BITREVERSE\000"
  /* 1272 */ "FAKE_USE\000"
  /* 1281 */ "SPWRITE\000"
  /* 1289 */ "DBG_VALUE\000"
  /* 1299 */ "G_GLOBAL_VALUE\000"
  /* 1314 */ "G_PTRAUTH_GLOBAL_VALUE\000"
  /* 1337 */ "CONVERGENCECTRL_GLUE\000"
  /* 1358 */ "G_STACKSAVE\000"
  /* 1370 */ "G_MEMMOVE\000"
  /* 1380 */ "G_FREEZE\000"
  /* 1389 */ "G_FCANONICALIZE\000"
  /* 1405 */ "G_FMODF\000"
  /* 1413 */ "INIT_UNDEF\000"
  /* 1424 */ "G_IMPLICIT_DEF\000"
  /* 1439 */ "DBG_INSTR_REF\000"
  /* 1453 */ "G_FNEG\000"
  /* 1460 */ "EXTRACT_SUBREG\000"
  /* 1475 */ "INSERT_SUBREG\000"
  /* 1489 */ "G_SEXT_INREG\000"
  /* 1502 */ "SUBREG_TO_REG\000"
  /* 1516 */ "G_ATOMIC_CMPXCHG\000"
  /* 1533 */ "G_ATOMICRMW_XCHG\000"
  /* 1550 */ "G_GET_ROUNDING\000"
  /* 1565 */ "G_SET_ROUNDING\000"
  /* 1580 */ "G_FLOG\000"
  /* 1587 */ "G_VAARG\000"
  /* 1595 */ "PREALLOCATED_ARG\000"
  /* 1612 */ "G_PREFETCH\000"
  /* 1623 */ "G_SMULH\000"
  /* 1631 */ "G_UMULH\000"
  /* 1639 */ "G_FTANH\000"
  /* 1647 */ "G_FSINH\000"
  /* 1655 */ "G_FCOSH\000"
  /* 1663 */ "DBG_PHI\000"
  /* 1671 */ "G_FPTOSI\000"
  /* 1680 */ "RETI\000"
  /* 1685 */ "G_FPTOUI\000"
  /* 1694 */ "G_FPOWI\000"
  /* 1702 */ "BREAK\000"
  /* 1708 */ "COPY_LANEMASK\000"
  /* 1722 */ "G_PTRMASK\000"
  /* 1732 */ "DESK\000"
  /* 1737 */ "SUBIRdK\000"
  /* 1745 */ "SBCIRdK\000"
  /* 1753 */ "LDIRdK\000"
  /* 1760 */ "ANDIRdK\000"
  /* 1768 */ "CPIRdK\000"
  /* 1775 */ "ORIRdK\000"
  /* 1782 */ "LDSRdK\000"
  /* 1789 */ "SBIWRdK\000"
  /* 1797 */ "SUBIWRdK\000"
  /* 1806 */ "SBCIWRdK\000"
  /* 1815 */ "ADIWRdK\000"
  /* 1823 */ "LDIWRdK\000"
  /* 1831 */ "ANDIWRdK\000"
  /* 1840 */ "ORIWRdK\000"
  /* 1848 */ "LDSWRdK\000"
  /* 1856 */ "GC_LABEL\000"
  /* 1865 */ "DBG_LABEL\000"
  /* 1875 */ "EH_LABEL\000"
  /* 1884 */ "ANNOTATION_LABEL\000"
  /* 1901 */ "ICALL_BRANCH_FUNNEL\000"
  /* 1921 */ "G_FSHL\000"
  /* 1928 */ "G_SHL\000"
  /* 1934 */ "G_FCEIL\000"
  /* 1942 */ "G_SAVGCEIL\000"
  /* 1953 */ "G_UAVGCEIL\000"
  /* 1964 */ "EICALL\000"
  /* 1971 */ "PATCHABLE_TAIL_CALL\000"
  /* 1991 */ "PATCHABLE_TYPED_EVENT_CALL\000"
  /* 2018 */ "PATCHABLE_EVENT_CALL\000"
  /* 2039 */ "FENTRY_CALL\000"
  /* 2051 */ "KILL\000"
  /* 2056 */ "G_CONSTANT_POOL\000"
  /* 2072 */ "G_ROTL\000"
  /* 2079 */ "G_VECREDUCE_FMUL\000"
  /* 2096 */ "G_FMUL\000"
  /* 2103 */ "G_VECREDUCE_SEQ_FMUL\000"
  /* 2124 */ "G_STRICT_FMUL\000"
  /* 2138 */ "G_CLMUL\000"
  /* 2146 */ "G_VECREDUCE_MUL\000"
  /* 2162 */ "G_MUL\000"
  /* 2168 */ "G_FREM\000"
  /* 2175 */ "G_STRICT_FREM\000"
  /* 2189 */ "G_SREM\000"
  /* 2196 */ "G_UREM\000"
  /* 2203 */ "G_SDIVREM\000"
  /* 2213 */ "G_UDIVREM\000"
  /* 2223 */ "ELPM\000"
  /* 2228 */ "SPM\000"
  /* 2232 */ "INLINEASM\000"
  /* 2242 */ "G_VECREDUCE_FMINIMUM\000"
  /* 2263 */ "G_FMINIMUM\000"
  /* 2274 */ "G_ATOMICRMW_FMINIMUM\000"
  /* 2295 */ "G_VECREDUCE_FMAXIMUM\000"
  /* 2316 */ "G_FMAXIMUM\000"
  /* 2327 */ "G_ATOMICRMW_FMAXIMUM\000"
  /* 2348 */ "G_FMINIMUMNUM\000"
  /* 2362 */ "G_ATOMICRMW_FMINIMUMNUM\000"
  /* 2386 */ "G_FMAXIMUMNUM\000"
  /* 2400 */ "G_ATOMICRMW_FMAXIMUMNUM\000"
  /* 2424 */ "G_FMINNUM\000"
  /* 2434 */ "G_FMAXNUM\000"
  /* 2444 */ "G_FATAN\000"
  /* 2452 */ "G_FTAN\000"
  /* 2459 */ "G_INTRINSIC_ROUNDEVEN\000"
  /* 2481 */ "G_ASSERT_ALIGN\000"
  /* 2496 */ "G_FCOPYSIGN\000"
  /* 2508 */ "G_VECREDUCE_FMIN\000"
  /* 2525 */ "G_ATOMICRMW_FMIN\000"
  /* 2542 */ "G_VECREDUCE_SMIN\000"
  /* 2559 */ "G_SMIN\000"
  /* 2566 */ "G_VECREDUCE_UMIN\000"
  /* 2583 */ "G_UMIN\000"
  /* 2590 */ "G_ATOMICRMW_UMIN\000"
  /* 2607 */ "G_ATOMICRMW_MIN\000"
  /* 2623 */ "G_FASIN\000"
  /* 2631 */ "G_FSIN\000"
  /* 2638 */ "CFI_INSTRUCTION\000"
  /* 2654 */ "G_CTLZ_ZERO_POISON\000"
  /* 2673 */ "G_CTTZ_ZERO_POISON\000"
  /* 2692 */ "ADJCALLSTACKDOWN\000"
  /* 2709 */ "G_SSUBO\000"
  /* 2717 */ "G_USUBO\000"
  /* 2725 */ "G_SADDO\000"
  /* 2733 */ "G_UADDO\000"
  /* 2741 */ "JUMP_TABLE_DEBUG_INFO\000"
  /* 2763 */ "G_SMULO\000"
  /* 2771 */ "G_UMULO\000"
  /* 2779 */ "G_BZERO\000"
  /* 2787 */ "STACKMAP\000"
  /* 2796 */ "G_DEBUGTRAP\000"
  /* 2808 */ "G_UBSANTRAP\000"
  /* 2820 */ "G_TRAP\000"
  /* 2827 */ "G_ATOMICRMW_UDEC_WRAP\000"
  /* 2849 */ "G_ATOMICRMW_UINC_WRAP\000"
  /* 2871 */ "G_BSWAP\000"
  /* 2879 */ "SLEEP\000"
  /* 2885 */ "G_SITOFP\000"
  /* 2894 */ "G_UITOFP\000"
  /* 2903 */ "G_FCMP\000"
  /* 2910 */ "G_STRICT_FCMP\000"
  /* 2924 */ "G_ICMP\000"
  /* 2931 */ "G_SCMP\000"
  /* 2938 */ "G_UCMP\000"
  /* 2945 */ "EIJMP\000"
  /* 2951 */ "NOP\000"
  /* 2955 */ "CONVERGENCECTRL_LOOP\000"
  /* 2976 */ "G_CTPOP\000"
  /* 2984 */ "PATCHABLE_OP\000"
  /* 2997 */ "FAULTING_OP\000"
  /* 3009 */ "ADJCALLSTACKUP\000"
  /* 3024 */ "PREALLOCATED_SETUP\000"
  /* 3043 */ "G_FLDEXP\000"
  /* 3052 */ "G_STRICT_FLDEXP\000"
  /* 3068 */ "G_FEXP\000"
  /* 3075 */ "G_FFREXP\000"
  /* 3084 */ "LDDWRdYQ\000"
  /* 3093 */ "LDDRdPtrQ\000"
  /* 3103 */ "LDDWRdPtrQ\000"
  /* 3114 */ "G_BR\000"
  /* 3119 */ "INLINEASM_BR\000"
  /* 3132 */ "G_BLOCK_ADDR\000"
  /* 3145 */ "WDR\000"
  /* 3149 */ "MEMBARRIER\000"
  /* 3160 */ "G_CONSTANT_FOLD_BARRIER\000"
  /* 3184 */ "PATCHABLE_FUNCTION_ENTER\000"
  /* 3209 */ "G_READCYCLECOUNTER\000"
  /* 3228 */ "G_READSTEADYCOUNTER\000"
  /* 3248 */ "G_READ_REGISTER\000"
  /* 3264 */ "G_WRITE_REGISTER\000"
  /* 3281 */ "G_ASHR\000"
  /* 3288 */ "G_FSHR\000"
  /* 3295 */ "G_LSHR\000"
  /* 3302 */ "CONVERGENCECTRL_ANCHOR\000"
  /* 3325 */ "G_FFLOOR\000"
  /* 3334 */ "G_SAVGFLOOR\000"
  /* 3346 */ "G_UAVGFLOOR\000"
  /* 3358 */ "G_EXTRACT_SUBVECTOR\000"
  /* 3378 */ "G_INSERT_SUBVECTOR\000"
  /* 3397 */ "G_BUILD_VECTOR\000"
  /* 3412 */ "G_SHUFFLE_VECTOR\000"
  /* 3429 */ "G_STEP_VECTOR\000"
  /* 3443 */ "G_SPLAT_VECTOR\000"
  /* 3458 */ "G_VECREDUCE_XOR\000"
  /* 3474 */ "G_XOR\000"
  /* 3480 */ "G_ATOMICRMW_XOR\000"
  /* 3496 */ "G_VECREDUCE_OR\000"
  /* 3511 */ "G_OR\000"
  /* 3516 */ "G_ATOMICRMW_OR\000"
  /* 3531 */ "G_ROTR\000"
  /* 3538 */ "G_INTTOPTR\000"
  /* 3549 */ "G_FABS\000"
  /* 3556 */ "G_ABS\000"
  /* 3562 */ "G_ABDS\000"
  /* 3569 */ "G_UNMERGE_VALUES\000"
  /* 3586 */ "G_MERGE_VALUES\000"
  /* 3601 */ "G_CTLS\000"
  /* 3608 */ "FMULS\000"
  /* 3614 */ "G_FACOS\000"
  /* 3622 */ "G_FCOS\000"
  /* 3629 */ "G_FSINCOS\000"
  /* 3639 */ "G_STRICT_FCMPS\000"
  /* 3654 */ "G_CONCAT_VECTORS\000"
  /* 3671 */ "COPY_TO_REGCLASS\000"
  /* 3688 */ "G_IS_FPCLASS\000"
  /* 3701 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\000"
  /* 3731 */ "G_VECTOR_COMPRESS\000"
  /* 3749 */ "G_INTRINSIC_W_SIDE_EFFECTS\000"
  /* 3776 */ "G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS\000"
  /* 3814 */ "G_TRUNC_SSAT_S\000"
  /* 3829 */ "G_SSUBSAT\000"
  /* 3839 */ "G_USUBSAT\000"
  /* 3849 */ "G_SADDSAT\000"
  /* 3859 */ "G_UADDSAT\000"
  /* 3869 */ "G_SSHLSAT\000"
  /* 3879 */ "G_USHLSAT\000"
  /* 3889 */ "G_SMULFIXSAT\000"
  /* 3902 */ "G_UMULFIXSAT\000"
  /* 3915 */ "G_SDIVFIXSAT\000"
  /* 3928 */ "G_UDIVFIXSAT\000"
  /* 3941 */ "G_ATOMICRMW_USUB_SAT\000"
  /* 3962 */ "G_FPTOSI_SAT\000"
  /* 3975 */ "G_FPTOUI_SAT\000"
  /* 3988 */ "G_EXTRACT\000"
  /* 3998 */ "G_SELECT\000"
  /* 4007 */ "G_BRINDIRECT\000"
  /* 4020 */ "PATCHABLE_RET\000"
  /* 4034 */ "G_MEMSET\000"
  /* 4043 */ "PATCHABLE_FUNCTION_EXIT\000"
  /* 4067 */ "G_BRJT\000"
  /* 4074 */ "G_EXTRACT_VECTOR_ELT\000"
  /* 4095 */ "G_INSERT_VECTOR_ELT\000"
  /* 4115 */ "G_FCONSTANT\000"
  /* 4127 */ "G_CONSTANT\000"
  /* 4138 */ "G_INTRINSIC_CONVERGENT\000"
  /* 4161 */ "STATEPOINT\000"
  /* 4172 */ "PATCHPOINT\000"
  /* 4183 */ "G_PTRTOINT\000"
  /* 4194 */ "G_FRINT\000"
  /* 4202 */ "G_INTRINSIC_LLRINT\000"
  /* 4221 */ "G_INTRINSIC_LRINT\000"
  /* 4239 */ "G_FNEARBYINT\000"
  /* 4252 */ "G_VASTART\000"
  /* 4262 */ "LIFETIME_START\000"
  /* 4277 */ "G_INVOKE_REGION_START\000"
  /* 4299 */ "G_INSERT\000"
  /* 4308 */ "G_FSQRT\000"
  /* 4316 */ "G_STRICT_FSQRT\000"
  /* 4331 */ "G_BITCAST\000"
  /* 4341 */ "G_ADDRSPACE_CAST\000"
  /* 4358 */ "BST\000"
  /* 4362 */ "DBG_VALUE_LIST\000"
  /* 4377 */ "G_FPEXT\000"
  /* 4385 */ "G_SEXT\000"
  /* 4392 */ "G_ASSERT_SEXT\000"
  /* 4406 */ "G_ANYEXT\000"
  /* 4415 */ "G_ZEXT\000"
  /* 4422 */ "G_ASSERT_ZEXT\000"
  /* 4436 */ "G_ABDU\000"
  /* 4443 */ "FMULSU\000"
  /* 4450 */ "G_TRUNC_SSAT_U\000"
  /* 4465 */ "G_TRUNC_USAT_U\000"
  /* 4480 */ "G_FDIV\000"
  /* 4487 */ "G_STRICT_FDIV\000"
  /* 4501 */ "G_SDIV\000"
  /* 4508 */ "G_UDIV\000"
  /* 4515 */ "G_GET_FPENV\000"
  /* 4527 */ "G_RESET_FPENV\000"
  /* 4541 */ "G_SET_FPENV\000"
  /* 4553 */ "G_FPOW\000"
  /* 4560 */ "G_VECREDUCE_FMAX\000"
  /* 4577 */ "G_ATOMICRMW_FMAX\000"
  /* 4594 */ "G_VECREDUCE_SMAX\000"
  /* 4611 */ "G_SMAX\000"
  /* 4618 */ "G_VECREDUCE_UMAX\000"
  /* 4635 */ "G_UMAX\000"
  /* 4642 */ "G_ATOMICRMW_UMAX\000"
  /* 4659 */ "G_ATOMICRMW_MAX\000"
  /* 4675 */ "FRMIDX\000"
  /* 4682 */ "G_FRAME_INDEX\000"
  /* 4696 */ "G_SBFX\000"
  /* 4703 */ "G_UBFX\000"
  /* 4710 */ "G_SMULFIX\000"
  /* 4720 */ "G_UMULFIX\000"
  /* 4730 */ "G_SDIVFIX\000"
  /* 4740 */ "G_UDIVFIX\000"
  /* 4750 */ "G_MEMCPY\000"
  /* 4759 */ "COPY\000"
  /* 4764 */ "CONVERGENCECTRL_ENTRY\000"
  /* 4786 */ "G_CTLZ\000"
  /* 4793 */ "G_CTTZ\000"
  /* 4800 */ "ELPMBRdZ\000"
  /* 4809 */ "ELPMRdZ\000"
  /* 4817 */ "ELPMWRdZ\000"
  /* 4826 */ "SBICAb\000"
  /* 4833 */ "CBIAb\000"
  /* 4839 */ "SBIAb\000"
  /* 4845 */ "SBISAb\000"
  /* 4852 */ "LDRdPtrPd\000"
  /* 4862 */ "LDWRdPtrPd\000"
  /* 4873 */ "RORBRd\000"
  /* 4880 */ "DECRd\000"
  /* 4886 */ "INCRd\000"
  /* 4892 */ "NEGRd\000"
  /* 4898 */ "COMRd\000"
  /* 4904 */ "LSLBNRd\000"
  /* 4912 */ "ASRBNRd\000"
  /* 4920 */ "LSRBNRd\000"
  /* 4928 */ "LSLWNRd\000"
  /* 4936 */ "ASRWNRd\000"
  /* 4944 */ "LSRWNRd\000"
  /* 4952 */ "SWAPRd\000"
  /* 4959 */ "POPRd\000"
  /* 4965 */ "RORRd\000"
  /* 4971 */ "ASRRd\000"
  /* 4977 */ "LSRRd\000"
  /* 4983 */ "NEGWRd\000"
  /* 4990 */ "ROLWRd\000"
  /* 4997 */ "LSLWRd\000"
  /* 5004 */ "COMWRd\000"
  /* 5011 */ "POPWRd\000"
  /* 5018 */ "RORWRd\000"
  /* 5025 */ "ASRWRd\000"
  /* 5032 */ "LSRWRd\000"
  /* 5039 */ "LACZRd\000"
  /* 5046 */ "XCHZRd\000"
  /* 5053 */ "LASZRd\000"
  /* 5060 */ "LATZRd\000"
  /* 5067 */ "LSLWHiRd\000"
  /* 5076 */ "ASRWLoRd\000"
  /* 5085 */ "LSRWLoRd\000"
  /* 5094 */ "AtomicFence\000"
  /* 5106 */ "SPMZPi\000"
  /* 5113 */ "ELPMBRdZPi\000"
  /* 5124 */ "ELPMRdZPi\000"
  /* 5134 */ "ELPMWRdZPi\000"
  /* 5145 */ "LDRdPtrPi\000"
  /* 5155 */ "LDWRdPtrPi\000"
  /* 5166 */ "BRGEk\000"
  /* 5172 */ "BRNEk\000"
  /* 5178 */ "BRSHk\000"
  /* 5184 */ "BRMIk\000"
  /* 5190 */ "RCALLk\000"
  /* 5197 */ "BRPLk\000"
  /* 5203 */ "BRLOk\000"
  /* 5209 */ "RJMPk\000"
  /* 5215 */ "BREQk\000"
  /* 5221 */ "BRLTk\000"
  /* 5227 */ "BRBCsk\000"
  /* 5234 */ "BRBSsk\000"
  /* 5241 */ "CopyZero\000"
  /* 5250 */ "OUTARr\000"
  /* 5257 */ "OUTWARr\000"
  /* 5265 */ "PUSHRr\000"
  /* 5272 */ "STSKRr\000"
  /* 5279 */ "STSWKRr\000"
  /* 5287 */ "STDSPQRr\000"
  /* 5296 */ "STDWSPQRr\000"
  /* 5306 */ "STDPtrQRr\000"
  /* 5316 */ "STDWPtrQRr\000"
  /* 5327 */ "PUSHWRr\000"
  /* 5335 */ "STPtrPdRr\000"
  /* 5345 */ "STWPtrPdRr\000"
  /* 5356 */ "SUBRdRr\000"
  /* 5364 */ "SBCRdRr\000"
  /* 5372 */ "ADCRdRr\000"
  /* 5380 */ "CPCRdRr\000"
  /* 5388 */ "ADDRdRr\000"
  /* 5396 */ "ANDRdRr\000"
  /* 5404 */ "MULRdRr\000"
  /* 5412 */ "CPRdRr\000"
  /* 5419 */ "EORRdRr\000"
  /* 5427 */ "MULSRdRr\000"
  /* 5436 */ "MULSURdRr\000"
  /* 5446 */ "MOVRdRr\000"
  /* 5454 */ "SUBWRdRr\000"
  /* 5463 */ "SBCWRdRr\000"
  /* 5472 */ "ADCWRdRr\000"
  /* 5481 */ "CPCWRdRr\000"
  /* 5490 */ "ADDWRdRr\000"
  /* 5499 */ "ANDWRdRr\000"
  /* 5508 */ "CPWRdRr\000"
  /* 5516 */ "EORWRdRr\000"
  /* 5525 */ "MOVWRdRr\000"
  /* 5534 */ "STPtrPiRr\000"
  /* 5544 */ "STWPtrPiRr\000"
  /* 5555 */ "STPtrRr\000"
  /* 5563 */ "STWPtrRr\000"
  /* 5572 */ "LDRdPtr\000"
  /* 5580 */ "LDWRdPtr\000"
  /* 5589 */ "BCLRs\000"
  /* 5595 */ "BSETs\000"
  /* 5601 */ "LDSRdKTiny\000"
  /* 5612 */ "STSKRrTiny\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned AVRInstrNameIndices[] = {
    1667U, 2232U, 3119U, 2638U, 1875U, 1856U, 1884U, 2051U, 
    1460U, 1475U, 1426U, 1413U, 1502U, 3671U, 1289U, 4362U, 
    1439U, 1663U, 1865U, 1015U, 4759U, 1708U, 1137U, 4262U, 
    842U, 966U, 1003U, 2787U, 2039U, 4172U, 949U, 3024U, 
    1595U, 4161U, 1187U, 2997U, 2984U, 3184U, 4020U, 4043U, 
    1971U, 2018U, 1991U, 1901U, 1272U, 3149U, 2741U, 1176U, 
    4764U, 3302U, 2955U, 1337U, 4392U, 4422U, 2481U, 751U, 
    427U, 2162U, 4501U, 4508U, 2189U, 2196U, 2203U, 2213U, 
    820U, 3511U, 3474U, 3562U, 4436U, 3346U, 1953U, 3334U, 
    1942U, 1424U, 1665U, 4682U, 1299U, 1314U, 2056U, 3988U, 
    3569U, 4299U, 3586U, 3397U, 513U, 3654U, 4183U, 3538U, 
    4331U, 1380U, 3160U, 923U, 487U, 905U, 4221U, 4202U, 
    2459U, 3209U, 3228U, 652U, 596U, 626U, 565U, 637U, 
    577U, 607U, 1246U, 1200U, 1230U, 3701U, 1516U, 1533U, 
    767U, 433U, 826U, 787U, 3516U, 3480U, 4659U, 2607U, 
    4642U, 2590U, 718U, 410U, 4577U, 2525U, 2327U, 2274U, 
    2400U, 2362U, 2849U, 2827U, 864U, 3941U, 995U, 1612U, 
    855U, 4007U, 4277U, 465U, 3749U, 4138U, 3776U, 4406U, 
    505U, 3814U, 4450U, 4465U, 4127U, 4115U, 4252U, 1587U, 
    4385U, 1489U, 4415U, 1928U, 3295U, 3281U, 1921U, 3288U, 
    3531U, 2072U, 2924U, 2903U, 2931U, 2938U, 3998U, 2733U, 
    1036U, 2717U, 987U, 2725U, 1028U, 2709U, 979U, 2771U, 
    2763U, 1631U, 1623U, 3859U, 3849U, 3839U, 3829U, 3879U, 
    3869U, 4710U, 4720U, 3889U, 3902U, 4730U, 4740U, 3915U, 
    3928U, 676U, 389U, 2096U, 357U, 558U, 4480U, 2168U, 
    1405U, 4553U, 1694U, 3068U, 62U, 9U, 1580U, 45U, 
    0U, 3043U, 3075U, 1453U, 4377U, 477U, 1671U, 1685U, 
    2885U, 2894U, 3962U, 3975U, 3549U, 2496U, 3688U, 1389U, 
    2424U, 2434U, 1085U, 1100U, 2263U, 2316U, 2348U, 2386U, 
    4515U, 4541U, 4527U, 1044U, 1072U, 1057U, 1550U, 1565U, 
    757U, 1722U, 2559U, 4611U, 2583U, 4635U, 3556U, 896U, 
    886U, 3114U, 4067U, 1115U, 3378U, 3358U, 4095U, 4074U, 
    3412U, 3443U, 3429U, 3731U, 4793U, 2673U, 4786U, 2654U, 
    3601U, 2976U, 2871U, 1259U, 2138U, 1934U, 3622U, 2631U, 
    3629U, 2452U, 3614U, 2623U, 2444U, 53U, 1655U, 1647U, 
    1639U, 4308U, 3325U, 4194U, 4239U, 4341U, 3132U, 1124U, 
    534U, 1358U, 1215U, 704U, 396U, 2124U, 4487U, 2175U, 
    363U, 4316U, 3052U, 2910U, 3639U, 3248U, 3264U, 4750U, 
    1160U, 1370U, 4034U, 2779U, 1144U, 2820U, 2796U, 2808U, 
    683U, 2103U, 659U, 2079U, 4560U, 2508U, 2295U, 2242U, 
    735U, 2146U, 804U, 3496U, 3458U, 4594U, 2542U, 4618U, 
    2566U, 4696U, 4703U, 5472U, 5490U, 2692U, 3009U, 1831U, 
    5499U, 4912U, 5076U, 4936U, 5025U, 194U, 33U, 339U, 
    5094U, 86U, 240U, 99U, 252U, 115U, 267U, 157U, 
    305U, 70U, 225U, 178U, 324U, 131U, 282U, 5004U, 
    5481U, 5508U, 5241U, 4800U, 5113U, 4817U, 5134U, 5516U, 
    4675U, 382U, 3103U, 3084U, 1823U, 1848U, 5580U, 4862U, 
    5155U, 4801U, 4818U, 5135U, 4904U, 5067U, 4928U, 4997U, 
    4920U, 5085U, 4944U, 5032U, 151U, 27U, 300U, 200U, 
    39U, 344U, 4983U, 1840U, 5517U, 5257U, 5011U, 5327U, 
    18U, 215U, 4990U, 4873U, 5018U, 145U, 295U, 172U, 
    319U, 1806U, 5463U, 4387U, 551U, 1281U, 5287U, 5316U, 
    5296U, 5279U, 5345U, 5544U, 5563U, 1797U, 5454U, 206U, 
    349U, 4417U, 5372U, 5388U, 1815U, 1760U, 5396U, 4971U, 
    5589U, 783U, 5227U, 5234U, 1702U, 5215U, 5166U, 5203U, 
    5221U, 5184U, 5172U, 5197U, 5178U, 5595U, 4358U, 5191U, 
    4833U, 4898U, 5380U, 1768U, 5412U, 1254U, 4880U, 1732U, 
    1964U, 2945U, 2223U, 4809U, 5124U, 5419U, 2091U, 3608U, 
    4443U, 1965U, 2946U, 4886U, 376U, 5210U, 5039U, 5053U, 
    5060U, 3093U, 1753U, 5572U, 4852U, 5145U, 1782U, 5601U, 
    2224U, 4810U, 5125U, 4977U, 5446U, 5525U, 5404U, 5427U, 
    5436U, 4892U, 2951U, 1775U, 5420U, 5250U, 4959U, 5265U, 
    5190U, 4030U, 1680U, 5209U, 4965U, 1745U, 5364U, 4839U, 
    4826U, 4845U, 1789U, 449U, 457U, 2879U, 2228U, 5106U, 
    5306U, 5335U, 5534U, 5555U, 5272U, 5612U, 1737U, 5356U, 
    4952U, 3145U, 5046U, 
};

static inline void InitAVRMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(AVRDescs.Insts, AVRInstrNameIndices, AVRInstrNameData, nullptr, nullptr, 523, nullptr, 0);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct AVRGenInstrInfo : public TargetInstrInfo {
  explicit AVRGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~AVRGenInstrInfo() override = default;
};

} // namespace llvm_ks

namespace llvm_ks::AVR {


} // namespace llvm_ks::AVR

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

extern const AVRInstrTable AVRDescs;
extern const unsigned AVRInstrNameIndices[];
extern const char AVRInstrNameData[];
AVRGenInstrInfo::AVRGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(AVRDescs.Insts, AVRInstrNameIndices, AVRInstrNameData, nullptr, nullptr, 523);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace AVR_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace AVR_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::AVR_MC {


} // namespace llvm_ks::AVR_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::AVR_MC {

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_HasSRAMBit = 14,
  Feature_HasJMPCALLBit = 7,
  Feature_HasIJMPCALLBit = 6,
  Feature_HasEIJMPCALLBit = 3,
  Feature_HasADDSUBIWBit = 0,
  Feature_HasSmallStackBit = 15,
  Feature_HasMOVWBit = 10,
  Feature_HasLPMBit = 8,
  Feature_HasLPMXBit = 9,
  Feature_HasELPMBit = 4,
  Feature_HasELPMXBit = 5,
  Feature_HasSPMBit = 12,
  Feature_HasSPMXBit = 13,
  Feature_HasDESBit = 2,
  Feature_SupportsRMWBit = 18,
  Feature_SupportsMultiplicationBit = 17,
  Feature_HasBREAKBit = 1,
  Feature_HasTinyEncodingBit = 16,
  Feature_HasNonTinyEncodingBit = 11,
};

inline FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) {
  FeatureBitset Features;
  if (FB[AVR::FeatureSRAM])
    Features.set(Feature_HasSRAMBit);
  if (FB[AVR::FeatureJMPCALL])
    Features.set(Feature_HasJMPCALLBit);
  if (FB[AVR::FeatureIJMPCALL])
    Features.set(Feature_HasIJMPCALLBit);
  if (FB[AVR::FeatureEIJMPCALL])
    Features.set(Feature_HasEIJMPCALLBit);
  if (FB[AVR::FeatureADDSUBIW])
    Features.set(Feature_HasADDSUBIWBit);
  if (FB[AVR::FeatureSmallStack])
    Features.set(Feature_HasSmallStackBit);
  if (FB[AVR::FeatureMOVW])
    Features.set(Feature_HasMOVWBit);
  if (FB[AVR::FeatureLPM])
    Features.set(Feature_HasLPMBit);
  if (FB[AVR::FeatureLPMX])
    Features.set(Feature_HasLPMXBit);
  if (FB[AVR::FeatureELPM])
    Features.set(Feature_HasELPMBit);
  if (FB[AVR::FeatureELPMX])
    Features.set(Feature_HasELPMXBit);
  if (FB[AVR::FeatureSPM])
    Features.set(Feature_HasSPMBit);
  if (FB[AVR::FeatureSPMX])
    Features.set(Feature_HasSPMXBit);
  if (FB[AVR::FeatureDES])
    Features.set(Feature_HasDESBit);
  if (FB[AVR::FeatureRMW])
    Features.set(Feature_SupportsRMWBit);
  if (FB[AVR::FeatureMultiplication])
    Features.set(Feature_SupportsMultiplicationBit);
  if (FB[AVR::FeatureBREAK])
    Features.set(Feature_HasBREAKBit);
  if (FB[AVR::FeatureTinyEncoding])
    Features.set(Feature_HasTinyEncodingBit);
  if (!FB[AVR::FeatureTinyEncoding])
    Features.set(Feature_HasNonTinyEncodingBit);
  return Features;
}

inline FeatureBitset computeRequiredFeatures(unsigned Opcode) {
  enum : uint8_t {
    CEFBS_None,
    CEFBS_HasADDSUBIW,
    CEFBS_HasBREAK,
    CEFBS_HasDES,
    CEFBS_HasEIJMPCALL,
    CEFBS_HasELPM,
    CEFBS_HasELPMX,
    CEFBS_HasIJMPCALL,
    CEFBS_HasJMPCALL,
    CEFBS_HasLPM,
    CEFBS_HasLPMX,
    CEFBS_HasMOVW,
    CEFBS_HasNonTinyEncoding,
    CEFBS_HasSPM,
    CEFBS_HasSPMX,
    CEFBS_HasSRAM,
    CEFBS_HasTinyEncoding,
    CEFBS_SupportsMultiplication,
    CEFBS_SupportsRMW,
    CEFBS_HasSRAM_HasNonTinyEncoding,
    CEFBS_HasSRAM_HasTinyEncoding,
  };

  static constexpr FeatureBitset FeatureBitsets[] = {
    {}, // CEFBS_None
    {Feature_HasADDSUBIWBit, },
    {Feature_HasBREAKBit, },
    {Feature_HasDESBit, },
    {Feature_HasEIJMPCALLBit, },
    {Feature_HasELPMBit, },
    {Feature_HasELPMXBit, },
    {Feature_HasIJMPCALLBit, },
    {Feature_HasJMPCALLBit, },
    {Feature_HasLPMBit, },
    {Feature_HasLPMXBit, },
    {Feature_HasMOVWBit, },
    {Feature_HasNonTinyEncodingBit, },
    {Feature_HasSPMBit, },
    {Feature_HasSPMXBit, },
    {Feature_HasSRAMBit, },
    {Feature_HasTinyEncodingBit, },
    {Feature_SupportsMultiplicationBit, },
    {Feature_SupportsRMWBit, },
    {Feature_HasSRAMBit, Feature_HasNonTinyEncodingBit, },
    {Feature_HasSRAMBit, Feature_HasTinyEncodingBit, },
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
    CEFBS_None, // ADCWRdRr
    CEFBS_None, // ADDWRdRr
    CEFBS_None, // ADJCALLSTACKDOWN
    CEFBS_None, // ADJCALLSTACKUP
    CEFBS_None, // ANDIWRdK
    CEFBS_None, // ANDWRdRr
    CEFBS_None, // ASRBNRd
    CEFBS_None, // ASRWLoRd
    CEFBS_None, // ASRWNRd
    CEFBS_None, // ASRWRd
    CEFBS_None, // Asr16
    CEFBS_None, // Asr32
    CEFBS_None, // Asr8
    CEFBS_None, // AtomicFence
    CEFBS_None, // AtomicLoad16
    CEFBS_None, // AtomicLoad8
    CEFBS_None, // AtomicLoadAdd16
    CEFBS_None, // AtomicLoadAdd8
    CEFBS_None, // AtomicLoadAnd16
    CEFBS_None, // AtomicLoadAnd8
    CEFBS_None, // AtomicLoadOr16
    CEFBS_None, // AtomicLoadOr8
    CEFBS_None, // AtomicLoadSub16
    CEFBS_None, // AtomicLoadSub8
    CEFBS_None, // AtomicLoadXor16
    CEFBS_None, // AtomicLoadXor8
    CEFBS_None, // AtomicStore16
    CEFBS_None, // AtomicStore8
    CEFBS_None, // COMWRd
    CEFBS_None, // CPCWRdRr
    CEFBS_None, // CPWRdRr
    CEFBS_None, // CopyZero
    CEFBS_HasELPM, // ELPMBRdZ
    CEFBS_HasELPMX, // ELPMBRdZPi
    CEFBS_HasELPM, // ELPMWRdZ
    CEFBS_HasELPMX, // ELPMWRdZPi
    CEFBS_None, // EORWRdRr
    CEFBS_None, // FRMIDX
    CEFBS_None, // INWRdA
    CEFBS_HasSRAM, // LDDWRdPtrQ
    CEFBS_HasSRAM, // LDDWRdYQ
    CEFBS_None, // LDIWRdK
    CEFBS_HasSRAM_HasNonTinyEncoding, // LDSWRdK
    CEFBS_HasSRAM, // LDWRdPtr
    CEFBS_HasSRAM, // LDWRdPtrPd
    CEFBS_HasSRAM, // LDWRdPtrPi
    CEFBS_HasLPM, // LPMBRdZ
    CEFBS_HasLPM, // LPMWRdZ
    CEFBS_HasLPMX, // LPMWRdZPi
    CEFBS_None, // LSLBNRd
    CEFBS_None, // LSLWHiRd
    CEFBS_None, // LSLWNRd
    CEFBS_None, // LSLWRd
    CEFBS_None, // LSRBNRd
    CEFBS_None, // LSRWLoRd
    CEFBS_None, // LSRWNRd
    CEFBS_None, // LSRWRd
    CEFBS_None, // Lsl16
    CEFBS_None, // Lsl32
    CEFBS_None, // Lsl8
    CEFBS_None, // Lsr16
    CEFBS_None, // Lsr32
    CEFBS_None, // Lsr8
    CEFBS_None, // NEGWRd
    CEFBS_None, // ORIWRdK
    CEFBS_None, // ORWRdRr
    CEFBS_None, // OUTWARr
    CEFBS_HasSRAM, // POPWRd
    CEFBS_HasSRAM, // PUSHWRr
    CEFBS_HasNonTinyEncoding, // ROLBRdR1
    CEFBS_HasTinyEncoding, // ROLBRdR17
    CEFBS_None, // ROLWRd
    CEFBS_None, // RORBRd
    CEFBS_None, // RORWRd
    CEFBS_None, // Rol16
    CEFBS_None, // Rol8
    CEFBS_None, // Ror16
    CEFBS_None, // Ror8
    CEFBS_None, // SBCIWRdK
    CEFBS_None, // SBCWRdRr
    CEFBS_None, // SEXT
    CEFBS_None, // SPREAD
    CEFBS_None, // SPWRITE
    CEFBS_None, // STDSPQRr
    CEFBS_HasSRAM, // STDWPtrQRr
    CEFBS_None, // STDWSPQRr
    CEFBS_HasSRAM_HasNonTinyEncoding, // STSWKRr
    CEFBS_HasSRAM, // STWPtrPdRr
    CEFBS_HasSRAM, // STWPtrPiRr
    CEFBS_HasSRAM, // STWPtrRr
    CEFBS_None, // SUBIWRdK
    CEFBS_None, // SUBWRdRr
    CEFBS_None, // Select16
    CEFBS_None, // Select8
    CEFBS_None, // ZEXT
    CEFBS_None, // ADCRdRr
    CEFBS_None, // ADDRdRr
    CEFBS_HasADDSUBIW, // ADIWRdK
    CEFBS_None, // ANDIRdK
    CEFBS_None, // ANDRdRr
    CEFBS_None, // ASRRd
    CEFBS_None, // BCLRs
    CEFBS_None, // BLD
    CEFBS_None, // BRBCsk
    CEFBS_None, // BRBSsk
    CEFBS_HasBREAK, // BREAK
    CEFBS_None, // BREQk
    CEFBS_None, // BRGEk
    CEFBS_None, // BRLOk
    CEFBS_None, // BRLTk
    CEFBS_None, // BRMIk
    CEFBS_None, // BRNEk
    CEFBS_None, // BRPLk
    CEFBS_None, // BRSHk
    CEFBS_None, // BSETs
    CEFBS_None, // BST
    CEFBS_HasJMPCALL, // CALLk
    CEFBS_None, // CBIAb
    CEFBS_None, // COMRd
    CEFBS_None, // CPCRdRr
    CEFBS_None, // CPIRdK
    CEFBS_None, // CPRdRr
    CEFBS_None, // CPSE
    CEFBS_None, // DECRd
    CEFBS_HasDES, // DESK
    CEFBS_HasEIJMPCALL, // EICALL
    CEFBS_HasEIJMPCALL, // EIJMP
    CEFBS_HasELPM, // ELPM
    CEFBS_HasELPMX, // ELPMRdZ
    CEFBS_HasELPMX, // ELPMRdZPi
    CEFBS_None, // EORRdRr
    CEFBS_SupportsMultiplication, // FMUL
    CEFBS_SupportsMultiplication, // FMULS
    CEFBS_SupportsMultiplication, // FMULSU
    CEFBS_HasIJMPCALL, // ICALL
    CEFBS_HasIJMPCALL, // IJMP
    CEFBS_None, // INCRd
    CEFBS_None, // INRdA
    CEFBS_HasJMPCALL, // JMPk
    CEFBS_SupportsRMW, // LACZRd
    CEFBS_SupportsRMW, // LASZRd
    CEFBS_SupportsRMW, // LATZRd
    CEFBS_HasSRAM_HasNonTinyEncoding, // LDDRdPtrQ
    CEFBS_None, // LDIRdK
    CEFBS_HasSRAM, // LDRdPtr
    CEFBS_HasSRAM, // LDRdPtrPd
    CEFBS_HasSRAM, // LDRdPtrPi
    CEFBS_HasSRAM_HasNonTinyEncoding, // LDSRdK
    CEFBS_HasSRAM_HasTinyEncoding, // LDSRdKTiny
    CEFBS_HasLPM, // LPM
    CEFBS_HasLPMX, // LPMRdZ
    CEFBS_HasLPMX, // LPMRdZPi
    CEFBS_None, // LSRRd
    CEFBS_None, // MOVRdRr
    CEFBS_HasMOVW, // MOVWRdRr
    CEFBS_SupportsMultiplication, // MULRdRr
    CEFBS_SupportsMultiplication, // MULSRdRr
    CEFBS_SupportsMultiplication, // MULSURdRr
    CEFBS_None, // NEGRd
    CEFBS_None, // NOP
    CEFBS_None, // ORIRdK
    CEFBS_None, // ORRdRr
    CEFBS_None, // OUTARr
    CEFBS_HasSRAM, // POPRd
    CEFBS_HasSRAM, // PUSHRr
    CEFBS_None, // RCALLk
    CEFBS_None, // RET
    CEFBS_None, // RETI
    CEFBS_None, // RJMPk
    CEFBS_None, // RORRd
    CEFBS_None, // SBCIRdK
    CEFBS_None, // SBCRdRr
    CEFBS_None, // SBIAb
    CEFBS_None, // SBICAb
    CEFBS_None, // SBISAb
    CEFBS_HasADDSUBIW, // SBIWRdK
    CEFBS_None, // SBRCRrB
    CEFBS_None, // SBRSRrB
    CEFBS_None, // SLEEP
    CEFBS_HasSPM, // SPM
    CEFBS_HasSPMX, // SPMZPi
    CEFBS_HasSRAM_HasNonTinyEncoding, // STDPtrQRr
    CEFBS_HasSRAM, // STPtrPdRr
    CEFBS_HasSRAM, // STPtrPiRr
    CEFBS_HasSRAM, // STPtrRr
    CEFBS_HasSRAM_HasNonTinyEncoding, // STSKRr
    CEFBS_HasSRAM_HasTinyEncoding, // STSKRrTiny
    CEFBS_None, // SUBIRdK
    CEFBS_None, // SUBRdRr
    CEFBS_None, // SWAPRd
    CEFBS_None, // WDR
    CEFBS_SupportsRMW, // XCHZRd
  };

  assert(Opcode < 523);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::AVR_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::AVR_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::AVR_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::AVR_MC {

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_HasADDSUBIW",
  "Feature_HasBREAK",
  "Feature_HasDES",
  "Feature_HasEIJMPCALL",
  "Feature_HasELPM",
  "Feature_HasELPMX",
  "Feature_HasIJMPCALL",
  "Feature_HasJMPCALL",
  "Feature_HasLPM",
  "Feature_HasLPMX",
  "Feature_HasMOVW",
  "Feature_HasNonTinyEncoding",
  "Feature_HasSPM",
  "Feature_HasSPMX",
  "Feature_HasSRAM",
  "Feature_HasSmallStack",
  "Feature_HasTinyEncoding",
  "Feature_SupportsMultiplication",
  "Feature_SupportsRMW",
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
    Msg << "Attempting to emit " << &AVRInstrNameData[AVRInstrNameIndices[Opcode]]
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::AVR_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

