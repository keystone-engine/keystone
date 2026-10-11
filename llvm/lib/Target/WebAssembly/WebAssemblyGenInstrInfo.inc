/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

namespace llvm_ks::WebAssembly {

  enum {
    PHI                                          = 0, // Target.td:1327
    INLINEASM                                    = 1, // Target.td:1333
    INLINEASM_BR                                 = 2, // Target.td:1339
    CFI_INSTRUCTION                              = 3, // Target.td:1348
    EH_LABEL                                     = 4, // Target.td:1357
    GC_LABEL                                     = 5, // Target.td:1366
    ANNOTATION_LABEL                             = 6, // Target.td:1375
    KILL                                         = 7, // Target.td:1383
    EXTRACT_SUBREG                               = 8, // Target.td:1390
    INSERT_SUBREG                                = 9, // Target.td:1396
    IMPLICIT_DEF                                 = 10, // Target.td:1403
    INIT_UNDEF                                   = 11, // Target.td:1412
    SUBREG_TO_REG                                = 12, // Target.td:1419
    COPY_TO_REGCLASS                             = 13, // Target.td:1425
    DBG_VALUE                                    = 14, // Target.td:1432
    DBG_VALUE_LIST                               = 15, // Target.td:1439
    DBG_INSTR_REF                                = 16, // Target.td:1446
    DBG_PHI                                      = 17, // Target.td:1453
    DBG_LABEL                                    = 18, // Target.td:1460
    REG_SEQUENCE                                 = 19, // Target.td:1467
    COPY                                         = 20, // Target.td:1474
    COPY_LANEMASK                                = 21, // Target.td:1482
    BUNDLE                                       = 22, // Target.td:1489
    LIFETIME_START                               = 23, // Target.td:1495
    LIFETIME_END                                 = 24, // Target.td:1502
    PSEUDO_PROBE                                 = 25, // Target.td:1509
    ARITH_FENCE                                  = 26, // Target.td:1516
    STACKMAP                                     = 27, // Target.td:1525
    FENTRY_CALL                                  = 28, // Target.td:1660
    PATCHPOINT                                   = 29, // Target.td:1533
    LOAD_STACK_GUARD                             = 30, // Target.td:1551
    PREALLOCATED_SETUP                           = 31, // Target.td:1559
    PREALLOCATED_ARG                             = 32, // Target.td:1565
    STATEPOINT                                   = 33, // Target.td:1542
    LOCAL_ESCAPE                                 = 34, // Target.td:1571
    FAULTING_OP                                  = 35, // Target.td:1580
    PATCHABLE_OP                                 = 36, // Target.td:1600
    PATCHABLE_FUNCTION_ENTER                     = 37, // Target.td:1608
    PATCHABLE_RET                                = 38, // Target.td:1615
    PATCHABLE_FUNCTION_EXIT                      = 39, // Target.td:1624
    PATCHABLE_TAIL_CALL                          = 40, // Target.td:1632
    PATCHABLE_EVENT_CALL                         = 41, // Target.td:1640
    PATCHABLE_TYPED_EVENT_CALL                   = 42, // Target.td:1650
    ICALL_BRANCH_FUNNEL                          = 43, // Target.td:1670
    FAKE_USE                                     = 44, // Target.td:1590
    MEMBARRIER                                   = 45, // Target.td:1676
    JUMP_TABLE_DEBUG_INFO                        = 46, // Target.td:1684
    RELOC_NONE                                   = 47, // Target.td:1692
    CONVERGENCECTRL_ENTRY                        = 48, // Target.td:1704
    CONVERGENCECTRL_ANCHOR                       = 49, // Target.td:1700
    CONVERGENCECTRL_LOOP                         = 50, // Target.td:1708
    CONVERGENCECTRL_GLUE                         = 51, // Target.td:1712
    G_ASSERT_SEXT                                = 52, // GenericOpcodes.td:1929
    G_ASSERT_ZEXT                                = 53, // GenericOpcodes.td:1921
    G_ASSERT_ALIGN                               = 54, // GenericOpcodes.td:1936
    G_ADD                                        = 55, // GenericOpcodes.td:308
    G_SUB                                        = 56, // GenericOpcodes.td:316
    G_MUL                                        = 57, // GenericOpcodes.td:324
    G_SDIV                                       = 58, // GenericOpcodes.td:332
    G_UDIV                                       = 59, // GenericOpcodes.td:340
    G_SREM                                       = 60, // GenericOpcodes.td:348
    G_UREM                                       = 61, // GenericOpcodes.td:356
    G_SDIVREM                                    = 62, // GenericOpcodes.td:364
    G_UDIVREM                                    = 63, // GenericOpcodes.td:372
    G_AND                                        = 64, // GenericOpcodes.td:380
    G_OR                                         = 65, // GenericOpcodes.td:388
    G_XOR                                        = 66, // GenericOpcodes.td:396
    G_ABDS                                       = 67, // GenericOpcodes.td:425
    G_ABDU                                       = 68, // GenericOpcodes.td:433
    G_UAVGFLOOR                                  = 69, // GenericOpcodes.td:441
    G_UAVGCEIL                                   = 70, // GenericOpcodes.td:448
    G_SAVGFLOOR                                  = 71, // GenericOpcodes.td:455
    G_SAVGCEIL                                   = 72, // GenericOpcodes.td:462
    G_IMPLICIT_DEF                               = 73, // GenericOpcodes.td:111
    G_PHI                                        = 74, // GenericOpcodes.td:118
    G_FRAME_INDEX                                = 75, // GenericOpcodes.td:125
    G_GLOBAL_VALUE                               = 76, // GenericOpcodes.td:131
    G_PTRAUTH_GLOBAL_VALUE                       = 77, // GenericOpcodes.td:137
    G_CONSTANT_POOL                              = 78, // GenericOpcodes.td:143
    G_EXTRACT                                    = 79, // GenericOpcodes.td:1516
    G_UNMERGE_VALUES                             = 80, // GenericOpcodes.td:1529
    G_INSERT                                     = 81, // GenericOpcodes.td:1538
    G_MERGE_VALUES                               = 82, // GenericOpcodes.td:1548
    G_BUILD_VECTOR                               = 83, // GenericOpcodes.td:1568
    G_BUILD_VECTOR_TRUNC                         = 84, // GenericOpcodes.td:1578
    G_CONCAT_VECTORS                             = 85, // GenericOpcodes.td:1585
    G_PTRTOINT                                   = 86, // GenericOpcodes.td:155
    G_INTTOPTR                                   = 87, // GenericOpcodes.td:149
    G_BITCAST                                    = 88, // GenericOpcodes.td:161
    G_FREEZE                                     = 89, // GenericOpcodes.td:284
    G_CONSTANT_FOLD_BARRIER                      = 90, // GenericOpcodes.td:1943
    G_INTRINSIC_FPTRUNC_ROUND                    = 91, // GenericOpcodes.td:1280
    G_INTRINSIC_TRUNC                            = 92, // GenericOpcodes.td:1286
    G_INTRINSIC_ROUND                            = 93, // GenericOpcodes.td:1292
    G_INTRINSIC_LRINT                            = 94, // GenericOpcodes.td:1298
    G_INTRINSIC_LLRINT                           = 95, // GenericOpcodes.td:1304
    G_INTRINSIC_ROUNDEVEN                        = 96, // GenericOpcodes.td:1310
    G_READCYCLECOUNTER                           = 97, // GenericOpcodes.td:1316
    G_READSTEADYCOUNTER                          = 98, // GenericOpcodes.td:1322
    G_LOAD                                       = 99, // GenericOpcodes.td:1349
    G_SEXTLOAD                                   = 100, // GenericOpcodes.td:1358
    G_ZEXTLOAD                                   = 101, // GenericOpcodes.td:1366
    G_FPEXTLOAD                                  = 102, // GenericOpcodes.td:1375
    G_INDEXED_LOAD                               = 103, // GenericOpcodes.td:1385
    G_INDEXED_SEXTLOAD                           = 104, // GenericOpcodes.td:1394
    G_INDEXED_ZEXTLOAD                           = 105, // GenericOpcodes.td:1402
    G_STORE                                      = 106, // GenericOpcodes.td:1410
    G_FPTRUNCSTORE                               = 107, // GenericOpcodes.td:1420
    G_INDEXED_STORE                              = 108, // GenericOpcodes.td:1428
    G_ATOMIC_CMPXCHG_WITH_SUCCESS                = 109, // GenericOpcodes.td:1439
    G_ATOMIC_CMPXCHG                             = 110, // GenericOpcodes.td:1450
    G_ATOMICRMW_XCHG                             = 111, // GenericOpcodes.td:1470
    G_ATOMICRMW_ADD                              = 112, // GenericOpcodes.td:1471
    G_ATOMICRMW_SUB                              = 113, // GenericOpcodes.td:1472
    G_ATOMICRMW_AND                              = 114, // GenericOpcodes.td:1473
    G_ATOMICRMW_NAND                             = 115, // GenericOpcodes.td:1474
    G_ATOMICRMW_OR                               = 116, // GenericOpcodes.td:1475
    G_ATOMICRMW_XOR                              = 117, // GenericOpcodes.td:1476
    G_ATOMICRMW_MAX                              = 118, // GenericOpcodes.td:1477
    G_ATOMICRMW_MIN                              = 119, // GenericOpcodes.td:1478
    G_ATOMICRMW_UMAX                             = 120, // GenericOpcodes.td:1479
    G_ATOMICRMW_UMIN                             = 121, // GenericOpcodes.td:1480
    G_ATOMICRMW_FADD                             = 122, // GenericOpcodes.td:1481
    G_ATOMICRMW_FSUB                             = 123, // GenericOpcodes.td:1482
    G_ATOMICRMW_FMAX                             = 124, // GenericOpcodes.td:1483
    G_ATOMICRMW_FMIN                             = 125, // GenericOpcodes.td:1484
    G_ATOMICRMW_FMAXIMUM                         = 126, // GenericOpcodes.td:1485
    G_ATOMICRMW_FMINIMUM                         = 127, // GenericOpcodes.td:1486
    G_ATOMICRMW_FMAXIMUMNUM                      = 128, // GenericOpcodes.td:1487
    G_ATOMICRMW_FMINIMUMNUM                      = 129, // GenericOpcodes.td:1488
    G_ATOMICRMW_UINC_WRAP                        = 130, // GenericOpcodes.td:1489
    G_ATOMICRMW_UDEC_WRAP                        = 131, // GenericOpcodes.td:1490
    G_ATOMICRMW_USUB_COND                        = 132, // GenericOpcodes.td:1491
    G_ATOMICRMW_USUB_SAT                         = 133, // GenericOpcodes.td:1492
    G_FENCE                                      = 134, // GenericOpcodes.td:1494
    G_PREFETCH                                   = 135, // GenericOpcodes.td:1501
    G_BRCOND                                     = 136, // GenericOpcodes.td:1641
    G_BRINDIRECT                                 = 137, // GenericOpcodes.td:1650
    G_INVOKE_REGION_START                        = 138, // GenericOpcodes.td:1673
    G_INTRINSIC                                  = 139, // GenericOpcodes.td:1593
    G_INTRINSIC_W_SIDE_EFFECTS                   = 140, // GenericOpcodes.td:1600
    G_INTRINSIC_CONVERGENT                       = 141, // GenericOpcodes.td:1609
    G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS        = 142, // GenericOpcodes.td:1617
    G_ANYEXT                                     = 143, // GenericOpcodes.td:44
    G_TRUNC                                      = 144, // GenericOpcodes.td:83
    G_TRUNC_SSAT_S                               = 145, // GenericOpcodes.td:91
    G_TRUNC_SSAT_U                               = 146, // GenericOpcodes.td:98
    G_TRUNC_USAT_U                               = 147, // GenericOpcodes.td:105
    G_CONSTANT                                   = 148, // GenericOpcodes.td:169
    G_FCONSTANT                                  = 149, // GenericOpcodes.td:177
    G_VASTART                                    = 150, // GenericOpcodes.td:184
    G_VAARG                                      = 151, // GenericOpcodes.td:191
    G_SEXT                                       = 152, // GenericOpcodes.td:52
    G_SEXT_INREG                                 = 153, // GenericOpcodes.td:66
    G_ZEXT                                       = 154, // GenericOpcodes.td:74
    G_SHL                                        = 155, // GenericOpcodes.td:404
    G_LSHR                                       = 156, // GenericOpcodes.td:411
    G_ASHR                                       = 157, // GenericOpcodes.td:418
    G_FSHL                                       = 158, // GenericOpcodes.td:470
    G_FSHR                                       = 159, // GenericOpcodes.td:478
    G_ROTR                                       = 160, // GenericOpcodes.td:485
    G_ROTL                                       = 161, // GenericOpcodes.td:492
    G_ICMP                                       = 162, // GenericOpcodes.td:499
    G_FCMP                                       = 163, // GenericOpcodes.td:506
    G_SCMP                                       = 164, // GenericOpcodes.td:513
    G_UCMP                                       = 165, // GenericOpcodes.td:520
    G_SELECT                                     = 166, // GenericOpcodes.td:527
    G_UADDO                                      = 167, // GenericOpcodes.td:601
    G_UADDE                                      = 168, // GenericOpcodes.td:609
    G_USUBO                                      = 169, // GenericOpcodes.td:631
    G_USUBE                                      = 170, // GenericOpcodes.td:637
    G_SADDO                                      = 171, // GenericOpcodes.td:616
    G_SADDE                                      = 172, // GenericOpcodes.td:624
    G_SSUBO                                      = 173, // GenericOpcodes.td:644
    G_SSUBE                                      = 174, // GenericOpcodes.td:651
    G_UMULO                                      = 175, // GenericOpcodes.td:658
    G_SMULO                                      = 176, // GenericOpcodes.td:666
    G_UMULH                                      = 177, // GenericOpcodes.td:675
    G_SMULH                                      = 178, // GenericOpcodes.td:684
    G_UADDSAT                                    = 179, // GenericOpcodes.td:696
    G_SADDSAT                                    = 180, // GenericOpcodes.td:704
    G_USUBSAT                                    = 181, // GenericOpcodes.td:712
    G_SSUBSAT                                    = 182, // GenericOpcodes.td:720
    G_USHLSAT                                    = 183, // GenericOpcodes.td:728
    G_SSHLSAT                                    = 184, // GenericOpcodes.td:736
    G_SMULFIX                                    = 185, // GenericOpcodes.td:748
    G_UMULFIX                                    = 186, // GenericOpcodes.td:755
    G_SMULFIXSAT                                 = 187, // GenericOpcodes.td:765
    G_UMULFIXSAT                                 = 188, // GenericOpcodes.td:772
    G_SDIVFIX                                    = 189, // GenericOpcodes.td:783
    G_UDIVFIX                                    = 190, // GenericOpcodes.td:790
    G_SDIVFIXSAT                                 = 191, // GenericOpcodes.td:800
    G_UDIVFIXSAT                                 = 192, // GenericOpcodes.td:807
    G_FADD                                       = 193, // GenericOpcodes.td:980
    G_FSUB                                       = 194, // GenericOpcodes.td:988
    G_FMUL                                       = 195, // GenericOpcodes.td:996
    G_FMA                                        = 196, // GenericOpcodes.td:1005
    G_FMAD                                       = 197, // GenericOpcodes.td:1014
    G_FDIV                                       = 198, // GenericOpcodes.td:1022
    G_FREM                                       = 199, // GenericOpcodes.td:1029
    G_FMODF                                      = 200, // GenericOpcodes.td:1036
    G_FPOW                                       = 201, // GenericOpcodes.td:1043
    G_FPOWI                                      = 202, // GenericOpcodes.td:1050
    G_FEXP                                       = 203, // GenericOpcodes.td:1057
    G_FEXP2                                      = 204, // GenericOpcodes.td:1064
    G_FEXP10                                     = 205, // GenericOpcodes.td:1071
    G_FLOG                                       = 206, // GenericOpcodes.td:1078
    G_FLOG2                                      = 207, // GenericOpcodes.td:1085
    G_FLOG10                                     = 208, // GenericOpcodes.td:1092
    G_FLDEXP                                     = 209, // GenericOpcodes.td:1099
    G_FFREXP                                     = 210, // GenericOpcodes.td:1106
    G_FNEG                                       = 211, // GenericOpcodes.td:818
    G_FPEXT                                      = 212, // GenericOpcodes.td:824
    G_FPTRUNC                                    = 213, // GenericOpcodes.td:830
    G_FPTOSI                                     = 214, // GenericOpcodes.td:836
    G_FPTOUI                                     = 215, // GenericOpcodes.td:842
    G_SITOFP                                     = 216, // GenericOpcodes.td:848
    G_UITOFP                                     = 217, // GenericOpcodes.td:854
    G_FPTOSI_SAT                                 = 218, // GenericOpcodes.td:860
    G_FPTOUI_SAT                                 = 219, // GenericOpcodes.td:866
    G_FABS                                       = 220, // GenericOpcodes.td:872
    G_FCOPYSIGN                                  = 221, // GenericOpcodes.td:878
    G_IS_FPCLASS                                 = 222, // GenericOpcodes.td:891
    G_FCANONICALIZE                              = 223, // GenericOpcodes.td:884
    G_FMINNUM                                    = 224, // GenericOpcodes.td:904
    G_FMAXNUM                                    = 225, // GenericOpcodes.td:911
    G_FMINNUM_IEEE                               = 226, // GenericOpcodes.td:929
    G_FMAXNUM_IEEE                               = 227, // GenericOpcodes.td:936
    G_FMINIMUM                                   = 228, // GenericOpcodes.td:946
    G_FMAXIMUM                                   = 229, // GenericOpcodes.td:953
    G_FMINIMUMNUM                                = 230, // GenericOpcodes.td:961
    G_FMAXIMUMNUM                                = 231, // GenericOpcodes.td:968
    G_GET_FPENV                                  = 232, // GenericOpcodes.td:1236
    G_SET_FPENV                                  = 233, // GenericOpcodes.td:1243
    G_RESET_FPENV                                = 234, // GenericOpcodes.td:1250
    G_GET_FPMODE                                 = 235, // GenericOpcodes.td:1257
    G_SET_FPMODE                                 = 236, // GenericOpcodes.td:1264
    G_RESET_FPMODE                               = 237, // GenericOpcodes.td:1271
    G_GET_ROUNDING                               = 238, // GenericOpcodes.td:1328
    G_SET_ROUNDING                               = 239, // GenericOpcodes.td:1334
    G_PTR_ADD                                    = 240, // GenericOpcodes.td:534
    G_PTRMASK                                    = 241, // GenericOpcodes.td:542
    G_SMIN                                       = 242, // GenericOpcodes.td:549
    G_SMAX                                       = 243, // GenericOpcodes.td:557
    G_UMIN                                       = 244, // GenericOpcodes.td:565
    G_UMAX                                       = 245, // GenericOpcodes.td:573
    G_ABS                                        = 246, // GenericOpcodes.td:581
    G_LROUND                                     = 247, // GenericOpcodes.td:291
    G_LLROUND                                    = 248, // GenericOpcodes.td:297
    G_BR                                         = 249, // GenericOpcodes.td:1631
    G_BRJT                                       = 250, // GenericOpcodes.td:1661
    G_VSCALE                                     = 251, // GenericOpcodes.td:1559
    G_INSERT_SUBVECTOR                           = 252, // GenericOpcodes.td:1705
    G_EXTRACT_SUBVECTOR                          = 253, // GenericOpcodes.td:1713
    G_INSERT_VECTOR_ELT                          = 254, // GenericOpcodes.td:1721
    G_EXTRACT_VECTOR_ELT                         = 255, // GenericOpcodes.td:1729
    G_SHUFFLE_VECTOR                             = 256, // GenericOpcodes.td:1740
    G_SPLAT_VECTOR                               = 257, // GenericOpcodes.td:1748
    G_STEP_VECTOR                                = 258, // GenericOpcodes.td:1756
    G_VECTOR_COMPRESS                            = 259, // GenericOpcodes.td:1763
    G_CTTZ                                       = 260, // GenericOpcodes.td:211
    G_CTTZ_ZERO_POISON                           = 261, // GenericOpcodes.td:217
    G_CTLZ                                       = 262, // GenericOpcodes.td:199
    G_CTLZ_ZERO_POISON                           = 263, // GenericOpcodes.td:205
    G_CTLS                                       = 264, // GenericOpcodes.td:223
    G_CTPOP                                      = 265, // GenericOpcodes.td:229
    G_BSWAP                                      = 266, // GenericOpcodes.td:235
    G_BITREVERSE                                 = 267, // GenericOpcodes.td:242
    G_CLMUL                                      = 268, // GenericOpcodes.td:588
    G_FCEIL                                      = 269, // GenericOpcodes.td:1113
    G_FCOS                                       = 270, // GenericOpcodes.td:1120
    G_FSIN                                       = 271, // GenericOpcodes.td:1127
    G_FSINCOS                                    = 272, // GenericOpcodes.td:1134
    G_FTAN                                       = 273, // GenericOpcodes.td:1141
    G_FACOS                                      = 274, // GenericOpcodes.td:1148
    G_FASIN                                      = 275, // GenericOpcodes.td:1155
    G_FATAN                                      = 276, // GenericOpcodes.td:1162
    G_FATAN2                                     = 277, // GenericOpcodes.td:1169
    G_FCOSH                                      = 278, // GenericOpcodes.td:1176
    G_FSINH                                      = 279, // GenericOpcodes.td:1183
    G_FTANH                                      = 280, // GenericOpcodes.td:1190
    G_FSQRT                                      = 281, // GenericOpcodes.td:1200
    G_FFLOOR                                     = 282, // GenericOpcodes.td:1207
    G_FRINT                                      = 283, // GenericOpcodes.td:1214
    G_FNEARBYINT                                 = 284, // GenericOpcodes.td:1221
    G_ADDRSPACE_CAST                             = 285, // GenericOpcodes.td:248
    G_BLOCK_ADDR                                 = 286, // GenericOpcodes.td:254
    G_JUMP_TABLE                                 = 287, // GenericOpcodes.td:260
    G_DYN_STACKALLOC                             = 288, // GenericOpcodes.td:266
    G_STACKSAVE                                  = 289, // GenericOpcodes.td:272
    G_STACKRESTORE                               = 290, // GenericOpcodes.td:278
    G_STRICT_FADD                                = 291, // GenericOpcodes.td:1813
    G_STRICT_FSUB                                = 292, // GenericOpcodes.td:1814
    G_STRICT_FMUL                                = 293, // GenericOpcodes.td:1815
    G_STRICT_FDIV                                = 294, // GenericOpcodes.td:1816
    G_STRICT_FREM                                = 295, // GenericOpcodes.td:1817
    G_STRICT_FMA                                 = 296, // GenericOpcodes.td:1818
    G_STRICT_FSQRT                               = 297, // GenericOpcodes.td:1819
    G_STRICT_FLDEXP                              = 298, // GenericOpcodes.td:1820
    G_STRICT_FCMP                                = 299, // GenericOpcodes.td:1821
    G_STRICT_FCMPS                               = 300, // GenericOpcodes.td:1822
    G_READ_REGISTER                              = 301, // GenericOpcodes.td:1680
    G_WRITE_REGISTER                             = 302, // GenericOpcodes.td:1690
    G_MEMCPY                                     = 303, // GenericOpcodes.td:1828
    G_MEMCPY_INLINE                              = 304, // GenericOpcodes.td:1836
    G_MEMMOVE                                    = 305, // GenericOpcodes.td:1844
    G_MEMSET                                     = 306, // GenericOpcodes.td:1852
    G_BZERO                                      = 307, // GenericOpcodes.td:1859
    G_MEMSET_INLINE                              = 308, // GenericOpcodes.td:1866
    G_TRAP                                       = 309, // GenericOpcodes.td:1876
    G_DEBUGTRAP                                  = 310, // GenericOpcodes.td:1883
    G_UBSANTRAP                                  = 311, // GenericOpcodes.td:1889
    G_VECREDUCE_SEQ_FADD                         = 312, // GenericOpcodes.td:1779
    G_VECREDUCE_SEQ_FMUL                         = 313, // GenericOpcodes.td:1785
    G_VECREDUCE_FADD                             = 314, // GenericOpcodes.td:1791
    G_VECREDUCE_FMUL                             = 315, // GenericOpcodes.td:1792
    G_VECREDUCE_FMAX                             = 316, // GenericOpcodes.td:1794
    G_VECREDUCE_FMIN                             = 317, // GenericOpcodes.td:1795
    G_VECREDUCE_FMAXIMUM                         = 318, // GenericOpcodes.td:1796
    G_VECREDUCE_FMINIMUM                         = 319, // GenericOpcodes.td:1797
    G_VECREDUCE_ADD                              = 320, // GenericOpcodes.td:1799
    G_VECREDUCE_MUL                              = 321, // GenericOpcodes.td:1800
    G_VECREDUCE_AND                              = 322, // GenericOpcodes.td:1801
    G_VECREDUCE_OR                               = 323, // GenericOpcodes.td:1802
    G_VECREDUCE_XOR                              = 324, // GenericOpcodes.td:1803
    G_VECREDUCE_SMAX                             = 325, // GenericOpcodes.td:1804
    G_VECREDUCE_SMIN                             = 326, // GenericOpcodes.td:1805
    G_VECREDUCE_UMAX                             = 327, // GenericOpcodes.td:1806
    G_VECREDUCE_UMIN                             = 328, // GenericOpcodes.td:1807
    G_SBFX                                       = 329, // GenericOpcodes.td:1901
    G_UBFX                                       = 330, // GenericOpcodes.td:1909
    CALL_PARAMS                                  = 331, // WebAssemblyInstrFormats.td:59
    CALL_PARAMS_S                                = 332, // WebAssemblyInstrFormats.td:61
    CALL_RESULTS                                 = 333, // WebAssemblyInstrFormats.td:59
    CALL_RESULTS_S                               = 334, // WebAssemblyInstrFormats.td:61
    CATCHRET                                     = 335, // WebAssemblyInstrFormats.td:59
    CATCHRET_S                                   = 336, // WebAssemblyInstrFormats.td:61
    CLEANUPRET                                   = 337, // WebAssemblyInstrFormats.td:59
    CLEANUPRET_S                                 = 338, // WebAssemblyInstrFormats.td:61
    COMPILER_FENCE                               = 339, // WebAssemblyInstrFormats.td:59
    COMPILER_FENCE_S                             = 340, // WebAssemblyInstrFormats.td:61
    RET_CALL_RESULTS                             = 341, // WebAssemblyInstrFormats.td:59
    RET_CALL_RESULTS_S                           = 342, // WebAssemblyInstrFormats.td:61
    ABS_F16x8                                    = 343, // WebAssemblyInstrFormats.td:59
    ABS_F16x8_S                                  = 344, // WebAssemblyInstrFormats.td:61
    ABS_F32                                      = 345, // WebAssemblyInstrFormats.td:59
    ABS_F32_S                                    = 346, // WebAssemblyInstrFormats.td:61
    ABS_F32x4                                    = 347, // WebAssemblyInstrFormats.td:59
    ABS_F32x4_S                                  = 348, // WebAssemblyInstrFormats.td:61
    ABS_F64                                      = 349, // WebAssemblyInstrFormats.td:59
    ABS_F64_S                                    = 350, // WebAssemblyInstrFormats.td:61
    ABS_F64x2                                    = 351, // WebAssemblyInstrFormats.td:59
    ABS_F64x2_S                                  = 352, // WebAssemblyInstrFormats.td:61
    ABS_I16x8                                    = 353, // WebAssemblyInstrFormats.td:59
    ABS_I16x8_S                                  = 354, // WebAssemblyInstrFormats.td:61
    ABS_I32x4                                    = 355, // WebAssemblyInstrFormats.td:59
    ABS_I32x4_S                                  = 356, // WebAssemblyInstrFormats.td:61
    ABS_I64x2                                    = 357, // WebAssemblyInstrFormats.td:59
    ABS_I64x2_S                                  = 358, // WebAssemblyInstrFormats.td:61
    ABS_I8x16                                    = 359, // WebAssemblyInstrFormats.td:59
    ABS_I8x16_S                                  = 360, // WebAssemblyInstrFormats.td:61
    ADD_F16x8                                    = 361, // WebAssemblyInstrFormats.td:59
    ADD_F16x8_S                                  = 362, // WebAssemblyInstrFormats.td:61
    ADD_F32                                      = 363, // WebAssemblyInstrFormats.td:59
    ADD_F32_S                                    = 364, // WebAssemblyInstrFormats.td:61
    ADD_F32x4                                    = 365, // WebAssemblyInstrFormats.td:59
    ADD_F32x4_S                                  = 366, // WebAssemblyInstrFormats.td:61
    ADD_F64                                      = 367, // WebAssemblyInstrFormats.td:59
    ADD_F64_S                                    = 368, // WebAssemblyInstrFormats.td:61
    ADD_F64x2                                    = 369, // WebAssemblyInstrFormats.td:59
    ADD_F64x2_S                                  = 370, // WebAssemblyInstrFormats.td:61
    ADD_I16x8                                    = 371, // WebAssemblyInstrFormats.td:59
    ADD_I16x8_S                                  = 372, // WebAssemblyInstrFormats.td:61
    ADD_I32                                      = 373, // WebAssemblyInstrFormats.td:59
    ADD_I32_S                                    = 374, // WebAssemblyInstrFormats.td:61
    ADD_I32x4                                    = 375, // WebAssemblyInstrFormats.td:59
    ADD_I32x4_S                                  = 376, // WebAssemblyInstrFormats.td:61
    ADD_I64                                      = 377, // WebAssemblyInstrFormats.td:59
    ADD_I64_S                                    = 378, // WebAssemblyInstrFormats.td:61
    ADD_I64x2                                    = 379, // WebAssemblyInstrFormats.td:59
    ADD_I64x2_S                                  = 380, // WebAssemblyInstrFormats.td:61
    ADD_I8x16                                    = 381, // WebAssemblyInstrFormats.td:59
    ADD_I8x16_S                                  = 382, // WebAssemblyInstrFormats.td:61
    ADD_SAT_S_I16x8                              = 383, // WebAssemblyInstrFormats.td:59
    ADD_SAT_S_I16x8_S                            = 384, // WebAssemblyInstrFormats.td:61
    ADD_SAT_S_I8x16                              = 385, // WebAssemblyInstrFormats.td:59
    ADD_SAT_S_I8x16_S                            = 386, // WebAssemblyInstrFormats.td:61
    ADD_SAT_U_I16x8                              = 387, // WebAssemblyInstrFormats.td:59
    ADD_SAT_U_I16x8_S                            = 388, // WebAssemblyInstrFormats.td:61
    ADD_SAT_U_I8x16                              = 389, // WebAssemblyInstrFormats.td:59
    ADD_SAT_U_I8x16_S                            = 390, // WebAssemblyInstrFormats.td:61
    ADJCALLSTACKDOWN                             = 391, // WebAssemblyInstrFormats.td:59
    ADJCALLSTACKDOWN_S                           = 392, // WebAssemblyInstrFormats.td:61
    ADJCALLSTACKUP                               = 393, // WebAssemblyInstrFormats.td:59
    ADJCALLSTACKUP_S                             = 394, // WebAssemblyInstrFormats.td:61
    ALLTRUE_I16x8                                = 395, // WebAssemblyInstrFormats.td:59
    ALLTRUE_I16x8_S                              = 396, // WebAssemblyInstrFormats.td:61
    ALLTRUE_I32x4                                = 397, // WebAssemblyInstrFormats.td:59
    ALLTRUE_I32x4_S                              = 398, // WebAssemblyInstrFormats.td:61
    ALLTRUE_I64x2                                = 399, // WebAssemblyInstrFormats.td:59
    ALLTRUE_I64x2_S                              = 400, // WebAssemblyInstrFormats.td:61
    ALLTRUE_I8x16                                = 401, // WebAssemblyInstrFormats.td:59
    ALLTRUE_I8x16_S                              = 402, // WebAssemblyInstrFormats.td:61
    AND                                          = 403, // WebAssemblyInstrFormats.td:59
    ANDNOT                                       = 404, // WebAssemblyInstrFormats.td:59
    ANDNOT_S                                     = 405, // WebAssemblyInstrFormats.td:61
    AND_I32                                      = 406, // WebAssemblyInstrFormats.td:59
    AND_I32_S                                    = 407, // WebAssemblyInstrFormats.td:61
    AND_I64                                      = 408, // WebAssemblyInstrFormats.td:59
    AND_I64_S                                    = 409, // WebAssemblyInstrFormats.td:61
    AND_S                                        = 410, // WebAssemblyInstrFormats.td:61
    ANYTRUE                                      = 411, // WebAssemblyInstrFormats.td:59
    ANYTRUE_S                                    = 412, // WebAssemblyInstrFormats.td:61
    ARGUMENT_exnref                              = 413, // WebAssemblyInstrFormats.td:59
    ARGUMENT_exnref_S                            = 414, // WebAssemblyInstrFormats.td:61
    ARGUMENT_externref                           = 415, // WebAssemblyInstrFormats.td:59
    ARGUMENT_externref_S                         = 416, // WebAssemblyInstrFormats.td:61
    ARGUMENT_f32                                 = 417, // WebAssemblyInstrFormats.td:59
    ARGUMENT_f32_S                               = 418, // WebAssemblyInstrFormats.td:61
    ARGUMENT_f64                                 = 419, // WebAssemblyInstrFormats.td:59
    ARGUMENT_f64_S                               = 420, // WebAssemblyInstrFormats.td:61
    ARGUMENT_funcref                             = 421, // WebAssemblyInstrFormats.td:59
    ARGUMENT_funcref_S                           = 422, // WebAssemblyInstrFormats.td:61
    ARGUMENT_i32                                 = 423, // WebAssemblyInstrFormats.td:59
    ARGUMENT_i32_S                               = 424, // WebAssemblyInstrFormats.td:61
    ARGUMENT_i64                                 = 425, // WebAssemblyInstrFormats.td:59
    ARGUMENT_i64_S                               = 426, // WebAssemblyInstrFormats.td:61
    ARGUMENT_v16i8                               = 427, // WebAssemblyInstrFormats.td:59
    ARGUMENT_v16i8_S                             = 428, // WebAssemblyInstrFormats.td:61
    ARGUMENT_v2f64                               = 429, // WebAssemblyInstrFormats.td:59
    ARGUMENT_v2f64_S                             = 430, // WebAssemblyInstrFormats.td:61
    ARGUMENT_v2i64                               = 431, // WebAssemblyInstrFormats.td:59
    ARGUMENT_v2i64_S                             = 432, // WebAssemblyInstrFormats.td:61
    ARGUMENT_v4f32                               = 433, // WebAssemblyInstrFormats.td:59
    ARGUMENT_v4f32_S                             = 434, // WebAssemblyInstrFormats.td:61
    ARGUMENT_v4i32                               = 435, // WebAssemblyInstrFormats.td:59
    ARGUMENT_v4i32_S                             = 436, // WebAssemblyInstrFormats.td:61
    ARGUMENT_v8f16                               = 437, // WebAssemblyInstrFormats.td:59
    ARGUMENT_v8f16_S                             = 438, // WebAssemblyInstrFormats.td:61
    ARGUMENT_v8i16                               = 439, // WebAssemblyInstrFormats.td:59
    ARGUMENT_v8i16_S                             = 440, // WebAssemblyInstrFormats.td:61
    ATOMIC_FENCE                                 = 441, // WebAssemblyInstrFormats.td:59
    ATOMIC_FENCE_S                               = 442, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD16_U_I32_A32                      = 443, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD16_U_I32_A32_S                    = 444, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD16_U_I32_A64                      = 445, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD16_U_I32_A64_S                    = 446, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD16_U_I64_A32                      = 447, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD16_U_I64_A32_S                    = 448, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD16_U_I64_A64                      = 449, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD16_U_I64_A64_S                    = 450, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD32_U_I64_A32                      = 451, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD32_U_I64_A32_S                    = 452, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD32_U_I64_A64                      = 453, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD32_U_I64_A64_S                    = 454, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD8_U_I32_A32                       = 455, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD8_U_I32_A32_S                     = 456, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD8_U_I32_A64                       = 457, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD8_U_I32_A64_S                     = 458, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD8_U_I64_A32                       = 459, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD8_U_I64_A32_S                     = 460, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD8_U_I64_A64                       = 461, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD8_U_I64_A64_S                     = 462, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD_I32_A32                          = 463, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD_I32_A32_S                        = 464, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD_I32_A64                          = 465, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD_I32_A64_S                        = 466, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD_I64_A32                          = 467, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD_I64_A32_S                        = 468, // WebAssemblyInstrFormats.td:61
    ATOMIC_LOAD_I64_A64                          = 469, // WebAssemblyInstrFormats.td:59
    ATOMIC_LOAD_I64_A64_S                        = 470, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_ADD_I32_A32                   = 471, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_ADD_I32_A32_S                 = 472, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_ADD_I32_A64                   = 473, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_ADD_I32_A64_S                 = 474, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_ADD_I64_A32                   = 475, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_ADD_I64_A32_S                 = 476, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_ADD_I64_A64                   = 477, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_ADD_I64_A64_S                 = 478, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_AND_I32_A32                   = 479, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_AND_I32_A32_S                 = 480, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_AND_I32_A64                   = 481, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_AND_I32_A64_S                 = 482, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_AND_I64_A32                   = 483, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_AND_I64_A32_S                 = 484, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_AND_I64_A64                   = 485, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_AND_I64_A64_S                 = 486, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_CMPXCHG_I32_A32               = 487, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_CMPXCHG_I32_A32_S             = 488, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_CMPXCHG_I32_A64               = 489, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_CMPXCHG_I32_A64_S             = 490, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_CMPXCHG_I64_A32               = 491, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_CMPXCHG_I64_A32_S             = 492, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_CMPXCHG_I64_A64               = 493, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_CMPXCHG_I64_A64_S             = 494, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_OR_I32_A32                    = 495, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_OR_I32_A32_S                  = 496, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_OR_I32_A64                    = 497, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_OR_I32_A64_S                  = 498, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_OR_I64_A32                    = 499, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_OR_I64_A32_S                  = 500, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_OR_I64_A64                    = 501, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_OR_I64_A64_S                  = 502, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_SUB_I32_A32                   = 503, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_SUB_I32_A32_S                 = 504, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_SUB_I32_A64                   = 505, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_SUB_I32_A64_S                 = 506, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_SUB_I64_A32                   = 507, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_SUB_I64_A32_S                 = 508, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_SUB_I64_A64                   = 509, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_SUB_I64_A64_S                 = 510, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_XCHG_I32_A32                  = 511, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_XCHG_I32_A32_S                = 512, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_XCHG_I32_A64                  = 513, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_XCHG_I32_A64_S                = 514, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_XCHG_I64_A32                  = 515, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_XCHG_I64_A32_S                = 516, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_XCHG_I64_A64                  = 517, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_XCHG_I64_A64_S                = 518, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_XOR_I32_A32                   = 519, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_XOR_I32_A32_S                 = 520, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_XOR_I32_A64                   = 521, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_XOR_I32_A64_S                 = 522, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_XOR_I64_A32                   = 523, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_XOR_I64_A32_S                 = 524, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW16_U_XOR_I64_A64                   = 525, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW16_U_XOR_I64_A64_S                 = 526, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_ADD_I64_A32                   = 527, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_ADD_I64_A32_S                 = 528, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_ADD_I64_A64                   = 529, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_ADD_I64_A64_S                 = 530, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_AND_I64_A32                   = 531, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_AND_I64_A32_S                 = 532, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_AND_I64_A64                   = 533, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_AND_I64_A64_S                 = 534, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_CMPXCHG_I64_A32               = 535, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_CMPXCHG_I64_A32_S             = 536, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_CMPXCHG_I64_A64               = 537, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_CMPXCHG_I64_A64_S             = 538, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_OR_I64_A32                    = 539, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_OR_I64_A32_S                  = 540, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_OR_I64_A64                    = 541, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_OR_I64_A64_S                  = 542, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_SUB_I64_A32                   = 543, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_SUB_I64_A32_S                 = 544, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_SUB_I64_A64                   = 545, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_SUB_I64_A64_S                 = 546, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_XCHG_I64_A32                  = 547, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_XCHG_I64_A32_S                = 548, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_XCHG_I64_A64                  = 549, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_XCHG_I64_A64_S                = 550, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_XOR_I64_A32                   = 551, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_XOR_I64_A32_S                 = 552, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW32_U_XOR_I64_A64                   = 553, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW32_U_XOR_I64_A64_S                 = 554, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_ADD_I32_A32                    = 555, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_ADD_I32_A32_S                  = 556, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_ADD_I32_A64                    = 557, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_ADD_I32_A64_S                  = 558, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_ADD_I64_A32                    = 559, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_ADD_I64_A32_S                  = 560, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_ADD_I64_A64                    = 561, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_ADD_I64_A64_S                  = 562, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_AND_I32_A32                    = 563, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_AND_I32_A32_S                  = 564, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_AND_I32_A64                    = 565, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_AND_I32_A64_S                  = 566, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_AND_I64_A32                    = 567, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_AND_I64_A32_S                  = 568, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_AND_I64_A64                    = 569, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_AND_I64_A64_S                  = 570, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_CMPXCHG_I32_A32                = 571, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_CMPXCHG_I32_A32_S              = 572, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_CMPXCHG_I32_A64                = 573, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_CMPXCHG_I32_A64_S              = 574, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_CMPXCHG_I64_A32                = 575, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_CMPXCHG_I64_A32_S              = 576, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_CMPXCHG_I64_A64                = 577, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_CMPXCHG_I64_A64_S              = 578, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_OR_I32_A32                     = 579, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_OR_I32_A32_S                   = 580, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_OR_I32_A64                     = 581, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_OR_I32_A64_S                   = 582, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_OR_I64_A32                     = 583, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_OR_I64_A32_S                   = 584, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_OR_I64_A64                     = 585, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_OR_I64_A64_S                   = 586, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_SUB_I32_A32                    = 587, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_SUB_I32_A32_S                  = 588, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_SUB_I32_A64                    = 589, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_SUB_I32_A64_S                  = 590, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_SUB_I64_A32                    = 591, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_SUB_I64_A32_S                  = 592, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_SUB_I64_A64                    = 593, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_SUB_I64_A64_S                  = 594, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_XCHG_I32_A32                   = 595, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_XCHG_I32_A32_S                 = 596, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_XCHG_I32_A64                   = 597, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_XCHG_I32_A64_S                 = 598, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_XCHG_I64_A32                   = 599, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_XCHG_I64_A32_S                 = 600, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_XCHG_I64_A64                   = 601, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_XCHG_I64_A64_S                 = 602, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_XOR_I32_A32                    = 603, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_XOR_I32_A32_S                  = 604, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_XOR_I32_A64                    = 605, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_XOR_I32_A64_S                  = 606, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_XOR_I64_A32                    = 607, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_XOR_I64_A32_S                  = 608, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW8_U_XOR_I64_A64                    = 609, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW8_U_XOR_I64_A64_S                  = 610, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_ADD_I32_A32                       = 611, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_ADD_I32_A32_S                     = 612, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_ADD_I32_A64                       = 613, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_ADD_I32_A64_S                     = 614, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_ADD_I64_A32                       = 615, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_ADD_I64_A32_S                     = 616, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_ADD_I64_A64                       = 617, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_ADD_I64_A64_S                     = 618, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_AND_I32_A32                       = 619, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_AND_I32_A32_S                     = 620, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_AND_I32_A64                       = 621, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_AND_I32_A64_S                     = 622, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_AND_I64_A32                       = 623, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_AND_I64_A32_S                     = 624, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_AND_I64_A64                       = 625, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_AND_I64_A64_S                     = 626, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_CMPXCHG_I32_A32                   = 627, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_CMPXCHG_I32_A32_S                 = 628, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_CMPXCHG_I32_A64                   = 629, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_CMPXCHG_I32_A64_S                 = 630, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_CMPXCHG_I64_A32                   = 631, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_CMPXCHG_I64_A32_S                 = 632, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_CMPXCHG_I64_A64                   = 633, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_CMPXCHG_I64_A64_S                 = 634, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_OR_I32_A32                        = 635, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_OR_I32_A32_S                      = 636, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_OR_I32_A64                        = 637, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_OR_I32_A64_S                      = 638, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_OR_I64_A32                        = 639, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_OR_I64_A32_S                      = 640, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_OR_I64_A64                        = 641, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_OR_I64_A64_S                      = 642, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_SUB_I32_A32                       = 643, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_SUB_I32_A32_S                     = 644, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_SUB_I32_A64                       = 645, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_SUB_I32_A64_S                     = 646, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_SUB_I64_A32                       = 647, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_SUB_I64_A32_S                     = 648, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_SUB_I64_A64                       = 649, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_SUB_I64_A64_S                     = 650, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_XCHG_I32_A32                      = 651, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_XCHG_I32_A32_S                    = 652, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_XCHG_I32_A64                      = 653, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_XCHG_I32_A64_S                    = 654, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_XCHG_I64_A32                      = 655, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_XCHG_I64_A32_S                    = 656, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_XCHG_I64_A64                      = 657, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_XCHG_I64_A64_S                    = 658, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_XOR_I32_A32                       = 659, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_XOR_I32_A32_S                     = 660, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_XOR_I32_A64                       = 661, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_XOR_I32_A64_S                     = 662, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_XOR_I64_A32                       = 663, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_XOR_I64_A32_S                     = 664, // WebAssemblyInstrFormats.td:61
    ATOMIC_RMW_XOR_I64_A64                       = 665, // WebAssemblyInstrFormats.td:59
    ATOMIC_RMW_XOR_I64_A64_S                     = 666, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE16_I32_A32                       = 667, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE16_I32_A32_S                     = 668, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE16_I32_A64                       = 669, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE16_I32_A64_S                     = 670, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE16_I64_A32                       = 671, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE16_I64_A32_S                     = 672, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE16_I64_A64                       = 673, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE16_I64_A64_S                     = 674, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE32_I64_A32                       = 675, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE32_I64_A32_S                     = 676, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE32_I64_A64                       = 677, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE32_I64_A64_S                     = 678, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE8_I32_A32                        = 679, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE8_I32_A32_S                      = 680, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE8_I32_A64                        = 681, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE8_I32_A64_S                      = 682, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE8_I64_A32                        = 683, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE8_I64_A32_S                      = 684, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE8_I64_A64                        = 685, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE8_I64_A64_S                      = 686, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE_I32_A32                         = 687, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE_I32_A32_S                       = 688, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE_I32_A64                         = 689, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE_I32_A64_S                       = 690, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE_I64_A32                         = 691, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE_I64_A32_S                       = 692, // WebAssemblyInstrFormats.td:61
    ATOMIC_STORE_I64_A64                         = 693, // WebAssemblyInstrFormats.td:59
    ATOMIC_STORE_I64_A64_S                       = 694, // WebAssemblyInstrFormats.td:61
    AVGR_U_I16x8                                 = 695, // WebAssemblyInstrFormats.td:59
    AVGR_U_I16x8_S                               = 696, // WebAssemblyInstrFormats.td:61
    AVGR_U_I8x16                                 = 697, // WebAssemblyInstrFormats.td:59
    AVGR_U_I8x16_S                               = 698, // WebAssemblyInstrFormats.td:61
    BITMASK_I16x8                                = 699, // WebAssemblyInstrFormats.td:59
    BITMASK_I16x8_S                              = 700, // WebAssemblyInstrFormats.td:61
    BITMASK_I32x4                                = 701, // WebAssemblyInstrFormats.td:59
    BITMASK_I32x4_S                              = 702, // WebAssemblyInstrFormats.td:61
    BITMASK_I64x2                                = 703, // WebAssemblyInstrFormats.td:59
    BITMASK_I64x2_S                              = 704, // WebAssemblyInstrFormats.td:61
    BITMASK_I8x16                                = 705, // WebAssemblyInstrFormats.td:59
    BITMASK_I8x16_S                              = 706, // WebAssemblyInstrFormats.td:61
    BITSELECT                                    = 707, // WebAssemblyInstrFormats.td:59
    BITSELECT_S                                  = 708, // WebAssemblyInstrFormats.td:61
    BLOCK                                        = 709, // WebAssemblyInstrFormats.td:59
    BLOCK_S                                      = 710, // WebAssemblyInstrFormats.td:61
    BR                                           = 711, // WebAssemblyInstrFormats.td:59
    BR_IF                                        = 712, // WebAssemblyInstrFormats.td:59
    BR_IF_S                                      = 713, // WebAssemblyInstrFormats.td:61
    BR_S                                         = 714, // WebAssemblyInstrFormats.td:61
    BR_TABLE_I32                                 = 715, // WebAssemblyInstrFormats.td:59
    BR_TABLE_I32_S                               = 716, // WebAssemblyInstrFormats.td:61
    BR_TABLE_I64                                 = 717, // WebAssemblyInstrFormats.td:59
    BR_TABLE_I64_S                               = 718, // WebAssemblyInstrFormats.td:61
    BR_UNLESS                                    = 719, // WebAssemblyInstrFormats.td:59
    BR_UNLESS_S                                  = 720, // WebAssemblyInstrFormats.td:61
    CALL                                         = 721, // WebAssemblyInstrFormats.td:59
    CALL_INDIRECT                                = 722, // WebAssemblyInstrFormats.td:59
    CALL_INDIRECT_S                              = 723, // WebAssemblyInstrFormats.td:61
    CALL_REF                                     = 724, // WebAssemblyInstrFormats.td:59
    CALL_REF_S                                   = 725, // WebAssemblyInstrFormats.td:61
    CALL_S                                       = 726, // WebAssemblyInstrFormats.td:61
    CATCH                                        = 727, // WebAssemblyInstrFormats.td:59
    CATCH_ALL                                    = 728, // WebAssemblyInstrFormats.td:59
    CATCH_ALL_LEGACY                             = 729, // WebAssemblyInstrFormats.td:59
    CATCH_ALL_LEGACY_S                           = 730, // WebAssemblyInstrFormats.td:61
    CATCH_ALL_REF                                = 731, // WebAssemblyInstrFormats.td:59
    CATCH_ALL_REF_S                              = 732, // WebAssemblyInstrFormats.td:61
    CATCH_ALL_S                                  = 733, // WebAssemblyInstrFormats.td:61
    CATCH_LEGACY                                 = 734, // WebAssemblyInstrFormats.td:59
    CATCH_LEGACY_S                               = 735, // WebAssemblyInstrFormats.td:61
    CATCH_REF                                    = 736, // WebAssemblyInstrFormats.td:59
    CATCH_REF_S                                  = 737, // WebAssemblyInstrFormats.td:61
    CATCH_S                                      = 738, // WebAssemblyInstrFormats.td:61
    CEIL_F16x8                                   = 739, // WebAssemblyInstrFormats.td:59
    CEIL_F16x8_S                                 = 740, // WebAssemblyInstrFormats.td:61
    CEIL_F32                                     = 741, // WebAssemblyInstrFormats.td:59
    CEIL_F32_S                                   = 742, // WebAssemblyInstrFormats.td:61
    CEIL_F32x4                                   = 743, // WebAssemblyInstrFormats.td:59
    CEIL_F32x4_S                                 = 744, // WebAssemblyInstrFormats.td:61
    CEIL_F64                                     = 745, // WebAssemblyInstrFormats.td:59
    CEIL_F64_S                                   = 746, // WebAssemblyInstrFormats.td:61
    CEIL_F64x2                                   = 747, // WebAssemblyInstrFormats.td:59
    CEIL_F64x2_S                                 = 748, // WebAssemblyInstrFormats.td:61
    CLZ_I32                                      = 749, // WebAssemblyInstrFormats.td:59
    CLZ_I32_S                                    = 750, // WebAssemblyInstrFormats.td:61
    CLZ_I64                                      = 751, // WebAssemblyInstrFormats.td:59
    CLZ_I64_S                                    = 752, // WebAssemblyInstrFormats.td:61
    CONST_F32                                    = 753, // WebAssemblyInstrFormats.td:59
    CONST_F32_S                                  = 754, // WebAssemblyInstrFormats.td:61
    CONST_F64                                    = 755, // WebAssemblyInstrFormats.td:59
    CONST_F64_S                                  = 756, // WebAssemblyInstrFormats.td:61
    CONST_I32                                    = 757, // WebAssemblyInstrFormats.td:59
    CONST_I32_S                                  = 758, // WebAssemblyInstrFormats.td:61
    CONST_I64                                    = 759, // WebAssemblyInstrFormats.td:59
    CONST_I64_S                                  = 760, // WebAssemblyInstrFormats.td:61
    CONST_V128_F32x4                             = 761, // WebAssemblyInstrFormats.td:59
    CONST_V128_F32x4_S                           = 762, // WebAssemblyInstrFormats.td:61
    CONST_V128_F64x2                             = 763, // WebAssemblyInstrFormats.td:59
    CONST_V128_F64x2_S                           = 764, // WebAssemblyInstrFormats.td:61
    CONST_V128_I16x8                             = 765, // WebAssemblyInstrFormats.td:59
    CONST_V128_I16x8_S                           = 766, // WebAssemblyInstrFormats.td:61
    CONST_V128_I32x4                             = 767, // WebAssemblyInstrFormats.td:59
    CONST_V128_I32x4_S                           = 768, // WebAssemblyInstrFormats.td:61
    CONST_V128_I64x2                             = 769, // WebAssemblyInstrFormats.td:59
    CONST_V128_I64x2_S                           = 770, // WebAssemblyInstrFormats.td:61
    CONST_V128_I8x16                             = 771, // WebAssemblyInstrFormats.td:59
    CONST_V128_I8x16_S                           = 772, // WebAssemblyInstrFormats.td:61
    COPYSIGN_F32                                 = 773, // WebAssemblyInstrFormats.td:59
    COPYSIGN_F32_S                               = 774, // WebAssemblyInstrFormats.td:61
    COPYSIGN_F64                                 = 775, // WebAssemblyInstrFormats.td:59
    COPYSIGN_F64_S                               = 776, // WebAssemblyInstrFormats.td:61
    COPY_EXNREF                                  = 777, // WebAssemblyInstrFormats.td:59
    COPY_EXNREF_S                                = 778, // WebAssemblyInstrFormats.td:61
    COPY_EXTERNREF                               = 779, // WebAssemblyInstrFormats.td:59
    COPY_EXTERNREF_S                             = 780, // WebAssemblyInstrFormats.td:61
    COPY_F32                                     = 781, // WebAssemblyInstrFormats.td:59
    COPY_F32_S                                   = 782, // WebAssemblyInstrFormats.td:61
    COPY_F64                                     = 783, // WebAssemblyInstrFormats.td:59
    COPY_F64_S                                   = 784, // WebAssemblyInstrFormats.td:61
    COPY_FUNCREF                                 = 785, // WebAssemblyInstrFormats.td:59
    COPY_FUNCREF_S                               = 786, // WebAssemblyInstrFormats.td:61
    COPY_I32                                     = 787, // WebAssemblyInstrFormats.td:59
    COPY_I32_S                                   = 788, // WebAssemblyInstrFormats.td:61
    COPY_I64                                     = 789, // WebAssemblyInstrFormats.td:59
    COPY_I64_S                                   = 790, // WebAssemblyInstrFormats.td:61
    COPY_V128                                    = 791, // WebAssemblyInstrFormats.td:59
    COPY_V128_S                                  = 792, // WebAssemblyInstrFormats.td:61
    CTZ_I32                                      = 793, // WebAssemblyInstrFormats.td:59
    CTZ_I32_S                                    = 794, // WebAssemblyInstrFormats.td:61
    CTZ_I64                                      = 795, // WebAssemblyInstrFormats.td:59
    CTZ_I64_S                                    = 796, // WebAssemblyInstrFormats.td:61
    DATA_DROP                                    = 797, // WebAssemblyInstrFormats.td:59
    DATA_DROP_S                                  = 798, // WebAssemblyInstrFormats.td:61
    DEBUG_UNREACHABLE                            = 799, // WebAssemblyInstrFormats.td:59
    DEBUG_UNREACHABLE_S                          = 800, // WebAssemblyInstrFormats.td:61
    DELEGATE                                     = 801, // WebAssemblyInstrFormats.td:59
    DELEGATE_S                                   = 802, // WebAssemblyInstrFormats.td:61
    DIV_F16x8                                    = 803, // WebAssemblyInstrFormats.td:59
    DIV_F16x8_S                                  = 804, // WebAssemblyInstrFormats.td:61
    DIV_F32                                      = 805, // WebAssemblyInstrFormats.td:59
    DIV_F32_S                                    = 806, // WebAssemblyInstrFormats.td:61
    DIV_F32x4                                    = 807, // WebAssemblyInstrFormats.td:59
    DIV_F32x4_S                                  = 808, // WebAssemblyInstrFormats.td:61
    DIV_F64                                      = 809, // WebAssemblyInstrFormats.td:59
    DIV_F64_S                                    = 810, // WebAssemblyInstrFormats.td:61
    DIV_F64x2                                    = 811, // WebAssemblyInstrFormats.td:59
    DIV_F64x2_S                                  = 812, // WebAssemblyInstrFormats.td:61
    DIV_S_I32                                    = 813, // WebAssemblyInstrFormats.td:59
    DIV_S_I32_S                                  = 814, // WebAssemblyInstrFormats.td:61
    DIV_S_I64                                    = 815, // WebAssemblyInstrFormats.td:59
    DIV_S_I64_S                                  = 816, // WebAssemblyInstrFormats.td:61
    DIV_U_I32                                    = 817, // WebAssemblyInstrFormats.td:59
    DIV_U_I32_S                                  = 818, // WebAssemblyInstrFormats.td:61
    DIV_U_I64                                    = 819, // WebAssemblyInstrFormats.td:59
    DIV_U_I64_S                                  = 820, // WebAssemblyInstrFormats.td:61
    DOT                                          = 821, // WebAssemblyInstrFormats.td:59
    DOT_S                                        = 822, // WebAssemblyInstrFormats.td:61
    DROP_EXNREF                                  = 823, // WebAssemblyInstrFormats.td:59
    DROP_EXNREF_S                                = 824, // WebAssemblyInstrFormats.td:61
    DROP_EXTERNREF                               = 825, // WebAssemblyInstrFormats.td:59
    DROP_EXTERNREF_S                             = 826, // WebAssemblyInstrFormats.td:61
    DROP_F32                                     = 827, // WebAssemblyInstrFormats.td:59
    DROP_F32_S                                   = 828, // WebAssemblyInstrFormats.td:61
    DROP_F64                                     = 829, // WebAssemblyInstrFormats.td:59
    DROP_F64_S                                   = 830, // WebAssemblyInstrFormats.td:61
    DROP_FUNCREF                                 = 831, // WebAssemblyInstrFormats.td:59
    DROP_FUNCREF_S                               = 832, // WebAssemblyInstrFormats.td:61
    DROP_I32                                     = 833, // WebAssemblyInstrFormats.td:59
    DROP_I32_S                                   = 834, // WebAssemblyInstrFormats.td:61
    DROP_I64                                     = 835, // WebAssemblyInstrFormats.td:59
    DROP_I64_S                                   = 836, // WebAssemblyInstrFormats.td:61
    DROP_V128                                    = 837, // WebAssemblyInstrFormats.td:59
    DROP_V128_S                                  = 838, // WebAssemblyInstrFormats.td:61
    ELSE                                         = 839, // WebAssemblyInstrFormats.td:59
    ELSE_S                                       = 840, // WebAssemblyInstrFormats.td:61
    END                                          = 841, // WebAssemblyInstrFormats.td:59
    END_BLOCK                                    = 842, // WebAssemblyInstrFormats.td:59
    END_BLOCK_S                                  = 843, // WebAssemblyInstrFormats.td:61
    END_FUNCTION                                 = 844, // WebAssemblyInstrFormats.td:59
    END_FUNCTION_S                               = 845, // WebAssemblyInstrFormats.td:61
    END_IF                                       = 846, // WebAssemblyInstrFormats.td:59
    END_IF_S                                     = 847, // WebAssemblyInstrFormats.td:61
    END_LOOP                                     = 848, // WebAssemblyInstrFormats.td:59
    END_LOOP_S                                   = 849, // WebAssemblyInstrFormats.td:61
    END_S                                        = 850, // WebAssemblyInstrFormats.td:61
    END_TRY                                      = 851, // WebAssemblyInstrFormats.td:59
    END_TRY_S                                    = 852, // WebAssemblyInstrFormats.td:61
    END_TRY_TABLE                                = 853, // WebAssemblyInstrFormats.td:59
    END_TRY_TABLE_S                              = 854, // WebAssemblyInstrFormats.td:61
    EQZ_I32                                      = 855, // WebAssemblyInstrFormats.td:59
    EQZ_I32_S                                    = 856, // WebAssemblyInstrFormats.td:61
    EQZ_I64                                      = 857, // WebAssemblyInstrFormats.td:59
    EQZ_I64_S                                    = 858, // WebAssemblyInstrFormats.td:61
    EQ_F16x8                                     = 859, // WebAssemblyInstrFormats.td:59
    EQ_F16x8_S                                   = 860, // WebAssemblyInstrFormats.td:61
    EQ_F32                                       = 861, // WebAssemblyInstrFormats.td:59
    EQ_F32_S                                     = 862, // WebAssemblyInstrFormats.td:61
    EQ_F32x4                                     = 863, // WebAssemblyInstrFormats.td:59
    EQ_F32x4_S                                   = 864, // WebAssemblyInstrFormats.td:61
    EQ_F64                                       = 865, // WebAssemblyInstrFormats.td:59
    EQ_F64_S                                     = 866, // WebAssemblyInstrFormats.td:61
    EQ_F64x2                                     = 867, // WebAssemblyInstrFormats.td:59
    EQ_F64x2_S                                   = 868, // WebAssemblyInstrFormats.td:61
    EQ_I16x8                                     = 869, // WebAssemblyInstrFormats.td:59
    EQ_I16x8_S                                   = 870, // WebAssemblyInstrFormats.td:61
    EQ_I32                                       = 871, // WebAssemblyInstrFormats.td:59
    EQ_I32_S                                     = 872, // WebAssemblyInstrFormats.td:61
    EQ_I32x4                                     = 873, // WebAssemblyInstrFormats.td:59
    EQ_I32x4_S                                   = 874, // WebAssemblyInstrFormats.td:61
    EQ_I64                                       = 875, // WebAssemblyInstrFormats.td:59
    EQ_I64_S                                     = 876, // WebAssemblyInstrFormats.td:61
    EQ_I64x2                                     = 877, // WebAssemblyInstrFormats.td:59
    EQ_I64x2_S                                   = 878, // WebAssemblyInstrFormats.td:61
    EQ_I8x16                                     = 879, // WebAssemblyInstrFormats.td:59
    EQ_I8x16_S                                   = 880, // WebAssemblyInstrFormats.td:61
    EXTMUL_HIGH_S_I16x8                          = 881, // WebAssemblyInstrFormats.td:59
    EXTMUL_HIGH_S_I16x8_S                        = 882, // WebAssemblyInstrFormats.td:61
    EXTMUL_HIGH_S_I32x4                          = 883, // WebAssemblyInstrFormats.td:59
    EXTMUL_HIGH_S_I32x4_S                        = 884, // WebAssemblyInstrFormats.td:61
    EXTMUL_HIGH_S_I64x2                          = 885, // WebAssemblyInstrFormats.td:59
    EXTMUL_HIGH_S_I64x2_S                        = 886, // WebAssemblyInstrFormats.td:61
    EXTMUL_HIGH_U_I16x8                          = 887, // WebAssemblyInstrFormats.td:59
    EXTMUL_HIGH_U_I16x8_S                        = 888, // WebAssemblyInstrFormats.td:61
    EXTMUL_HIGH_U_I32x4                          = 889, // WebAssemblyInstrFormats.td:59
    EXTMUL_HIGH_U_I32x4_S                        = 890, // WebAssemblyInstrFormats.td:61
    EXTMUL_HIGH_U_I64x2                          = 891, // WebAssemblyInstrFormats.td:59
    EXTMUL_HIGH_U_I64x2_S                        = 892, // WebAssemblyInstrFormats.td:61
    EXTMUL_LOW_S_I16x8                           = 893, // WebAssemblyInstrFormats.td:59
    EXTMUL_LOW_S_I16x8_S                         = 894, // WebAssemblyInstrFormats.td:61
    EXTMUL_LOW_S_I32x4                           = 895, // WebAssemblyInstrFormats.td:59
    EXTMUL_LOW_S_I32x4_S                         = 896, // WebAssemblyInstrFormats.td:61
    EXTMUL_LOW_S_I64x2                           = 897, // WebAssemblyInstrFormats.td:59
    EXTMUL_LOW_S_I64x2_S                         = 898, // WebAssemblyInstrFormats.td:61
    EXTMUL_LOW_U_I16x8                           = 899, // WebAssemblyInstrFormats.td:59
    EXTMUL_LOW_U_I16x8_S                         = 900, // WebAssemblyInstrFormats.td:61
    EXTMUL_LOW_U_I32x4                           = 901, // WebAssemblyInstrFormats.td:59
    EXTMUL_LOW_U_I32x4_S                         = 902, // WebAssemblyInstrFormats.td:61
    EXTMUL_LOW_U_I64x2                           = 903, // WebAssemblyInstrFormats.td:59
    EXTMUL_LOW_U_I64x2_S                         = 904, // WebAssemblyInstrFormats.td:61
    EXTRACT_LANE_F16x8                           = 905, // WebAssemblyInstrFormats.td:59
    EXTRACT_LANE_F16x8_S                         = 906, // WebAssemblyInstrFormats.td:61
    EXTRACT_LANE_F32x4                           = 907, // WebAssemblyInstrFormats.td:59
    EXTRACT_LANE_F32x4_S                         = 908, // WebAssemblyInstrFormats.td:61
    EXTRACT_LANE_F64x2                           = 909, // WebAssemblyInstrFormats.td:59
    EXTRACT_LANE_F64x2_S                         = 910, // WebAssemblyInstrFormats.td:61
    EXTRACT_LANE_I16x8_s                         = 911, // WebAssemblyInstrFormats.td:59
    EXTRACT_LANE_I16x8_s_S                       = 912, // WebAssemblyInstrFormats.td:61
    EXTRACT_LANE_I16x8_u                         = 913, // WebAssemblyInstrFormats.td:59
    EXTRACT_LANE_I16x8_u_S                       = 914, // WebAssemblyInstrFormats.td:61
    EXTRACT_LANE_I32x4                           = 915, // WebAssemblyInstrFormats.td:59
    EXTRACT_LANE_I32x4_S                         = 916, // WebAssemblyInstrFormats.td:61
    EXTRACT_LANE_I64x2                           = 917, // WebAssemblyInstrFormats.td:59
    EXTRACT_LANE_I64x2_S                         = 918, // WebAssemblyInstrFormats.td:61
    EXTRACT_LANE_I8x16_s                         = 919, // WebAssemblyInstrFormats.td:59
    EXTRACT_LANE_I8x16_s_S                       = 920, // WebAssemblyInstrFormats.td:61
    EXTRACT_LANE_I8x16_u                         = 921, // WebAssemblyInstrFormats.td:59
    EXTRACT_LANE_I8x16_u_S                       = 922, // WebAssemblyInstrFormats.td:61
    F32_CONVERT_S_I32                            = 923, // WebAssemblyInstrFormats.td:59
    F32_CONVERT_S_I32_S                          = 924, // WebAssemblyInstrFormats.td:61
    F32_CONVERT_S_I64                            = 925, // WebAssemblyInstrFormats.td:59
    F32_CONVERT_S_I64_S                          = 926, // WebAssemblyInstrFormats.td:61
    F32_CONVERT_U_I32                            = 927, // WebAssemblyInstrFormats.td:59
    F32_CONVERT_U_I32_S                          = 928, // WebAssemblyInstrFormats.td:61
    F32_CONVERT_U_I64                            = 929, // WebAssemblyInstrFormats.td:59
    F32_CONVERT_U_I64_S                          = 930, // WebAssemblyInstrFormats.td:61
    F32_DEMOTE_F64                               = 931, // WebAssemblyInstrFormats.td:59
    F32_DEMOTE_F64_S                             = 932, // WebAssemblyInstrFormats.td:61
    F32_REINTERPRET_I32                          = 933, // WebAssemblyInstrFormats.td:59
    F32_REINTERPRET_I32_S                        = 934, // WebAssemblyInstrFormats.td:61
    F64_CONVERT_S_I32                            = 935, // WebAssemblyInstrFormats.td:59
    F64_CONVERT_S_I32_S                          = 936, // WebAssemblyInstrFormats.td:61
    F64_CONVERT_S_I64                            = 937, // WebAssemblyInstrFormats.td:59
    F64_CONVERT_S_I64_S                          = 938, // WebAssemblyInstrFormats.td:61
    F64_CONVERT_U_I32                            = 939, // WebAssemblyInstrFormats.td:59
    F64_CONVERT_U_I32_S                          = 940, // WebAssemblyInstrFormats.td:61
    F64_CONVERT_U_I64                            = 941, // WebAssemblyInstrFormats.td:59
    F64_CONVERT_U_I64_S                          = 942, // WebAssemblyInstrFormats.td:61
    F64_PROMOTE_F32                              = 943, // WebAssemblyInstrFormats.td:59
    F64_PROMOTE_F32_S                            = 944, // WebAssemblyInstrFormats.td:61
    F64_REINTERPRET_I64                          = 945, // WebAssemblyInstrFormats.td:59
    F64_REINTERPRET_I64_S                        = 946, // WebAssemblyInstrFormats.td:61
    FALLTHROUGH_RETURN                           = 947, // WebAssemblyInstrFormats.td:59
    FALLTHROUGH_RETURN_S                         = 948, // WebAssemblyInstrFormats.td:61
    FLOOR_F16x8                                  = 949, // WebAssemblyInstrFormats.td:59
    FLOOR_F16x8_S                                = 950, // WebAssemblyInstrFormats.td:61
    FLOOR_F32                                    = 951, // WebAssemblyInstrFormats.td:59
    FLOOR_F32_S                                  = 952, // WebAssemblyInstrFormats.td:61
    FLOOR_F32x4                                  = 953, // WebAssemblyInstrFormats.td:59
    FLOOR_F32x4_S                                = 954, // WebAssemblyInstrFormats.td:61
    FLOOR_F64                                    = 955, // WebAssemblyInstrFormats.td:59
    FLOOR_F64_S                                  = 956, // WebAssemblyInstrFormats.td:61
    FLOOR_F64x2                                  = 957, // WebAssemblyInstrFormats.td:59
    FLOOR_F64x2_S                                = 958, // WebAssemblyInstrFormats.td:61
    FP_TO_SINT_I32_F32                           = 959, // WebAssemblyInstrFormats.td:59
    FP_TO_SINT_I32_F32_S                         = 960, // WebAssemblyInstrFormats.td:61
    FP_TO_SINT_I32_F64                           = 961, // WebAssemblyInstrFormats.td:59
    FP_TO_SINT_I32_F64_S                         = 962, // WebAssemblyInstrFormats.td:61
    FP_TO_SINT_I64_F32                           = 963, // WebAssemblyInstrFormats.td:59
    FP_TO_SINT_I64_F32_S                         = 964, // WebAssemblyInstrFormats.td:61
    FP_TO_SINT_I64_F64                           = 965, // WebAssemblyInstrFormats.td:59
    FP_TO_SINT_I64_F64_S                         = 966, // WebAssemblyInstrFormats.td:61
    FP_TO_UINT_I32_F32                           = 967, // WebAssemblyInstrFormats.td:59
    FP_TO_UINT_I32_F32_S                         = 968, // WebAssemblyInstrFormats.td:61
    FP_TO_UINT_I32_F64                           = 969, // WebAssemblyInstrFormats.td:59
    FP_TO_UINT_I32_F64_S                         = 970, // WebAssemblyInstrFormats.td:61
    FP_TO_UINT_I64_F32                           = 971, // WebAssemblyInstrFormats.td:59
    FP_TO_UINT_I64_F32_S                         = 972, // WebAssemblyInstrFormats.td:61
    FP_TO_UINT_I64_F64                           = 973, // WebAssemblyInstrFormats.td:59
    FP_TO_UINT_I64_F64_S                         = 974, // WebAssemblyInstrFormats.td:61
    GE_F16x8                                     = 975, // WebAssemblyInstrFormats.td:59
    GE_F16x8_S                                   = 976, // WebAssemblyInstrFormats.td:61
    GE_F32                                       = 977, // WebAssemblyInstrFormats.td:59
    GE_F32_S                                     = 978, // WebAssemblyInstrFormats.td:61
    GE_F32x4                                     = 979, // WebAssemblyInstrFormats.td:59
    GE_F32x4_S                                   = 980, // WebAssemblyInstrFormats.td:61
    GE_F64                                       = 981, // WebAssemblyInstrFormats.td:59
    GE_F64_S                                     = 982, // WebAssemblyInstrFormats.td:61
    GE_F64x2                                     = 983, // WebAssemblyInstrFormats.td:59
    GE_F64x2_S                                   = 984, // WebAssemblyInstrFormats.td:61
    GE_S_I16x8                                   = 985, // WebAssemblyInstrFormats.td:59
    GE_S_I16x8_S                                 = 986, // WebAssemblyInstrFormats.td:61
    GE_S_I32                                     = 987, // WebAssemblyInstrFormats.td:59
    GE_S_I32_S                                   = 988, // WebAssemblyInstrFormats.td:61
    GE_S_I32x4                                   = 989, // WebAssemblyInstrFormats.td:59
    GE_S_I32x4_S                                 = 990, // WebAssemblyInstrFormats.td:61
    GE_S_I64                                     = 991, // WebAssemblyInstrFormats.td:59
    GE_S_I64_S                                   = 992, // WebAssemblyInstrFormats.td:61
    GE_S_I64x2                                   = 993, // WebAssemblyInstrFormats.td:59
    GE_S_I64x2_S                                 = 994, // WebAssemblyInstrFormats.td:61
    GE_S_I8x16                                   = 995, // WebAssemblyInstrFormats.td:59
    GE_S_I8x16_S                                 = 996, // WebAssemblyInstrFormats.td:61
    GE_U_I16x8                                   = 997, // WebAssemblyInstrFormats.td:59
    GE_U_I16x8_S                                 = 998, // WebAssemblyInstrFormats.td:61
    GE_U_I32                                     = 999, // WebAssemblyInstrFormats.td:59
    GE_U_I32_S                                   = 1000, // WebAssemblyInstrFormats.td:61
    GE_U_I32x4                                   = 1001, // WebAssemblyInstrFormats.td:59
    GE_U_I32x4_S                                 = 1002, // WebAssemblyInstrFormats.td:61
    GE_U_I64                                     = 1003, // WebAssemblyInstrFormats.td:59
    GE_U_I64_S                                   = 1004, // WebAssemblyInstrFormats.td:61
    GE_U_I8x16                                   = 1005, // WebAssemblyInstrFormats.td:59
    GE_U_I8x16_S                                 = 1006, // WebAssemblyInstrFormats.td:61
    GLOBAL_GET_EXNREF                            = 1007, // WebAssemblyInstrFormats.td:59
    GLOBAL_GET_EXNREF_S                          = 1008, // WebAssemblyInstrFormats.td:61
    GLOBAL_GET_EXTERNREF                         = 1009, // WebAssemblyInstrFormats.td:59
    GLOBAL_GET_EXTERNREF_S                       = 1010, // WebAssemblyInstrFormats.td:61
    GLOBAL_GET_F32                               = 1011, // WebAssemblyInstrFormats.td:59
    GLOBAL_GET_F32_S                             = 1012, // WebAssemblyInstrFormats.td:61
    GLOBAL_GET_F64                               = 1013, // WebAssemblyInstrFormats.td:59
    GLOBAL_GET_F64_S                             = 1014, // WebAssemblyInstrFormats.td:61
    GLOBAL_GET_FUNCREF                           = 1015, // WebAssemblyInstrFormats.td:59
    GLOBAL_GET_FUNCREF_S                         = 1016, // WebAssemblyInstrFormats.td:61
    GLOBAL_GET_I32                               = 1017, // WebAssemblyInstrFormats.td:59
    GLOBAL_GET_I32_S                             = 1018, // WebAssemblyInstrFormats.td:61
    GLOBAL_GET_I64                               = 1019, // WebAssemblyInstrFormats.td:59
    GLOBAL_GET_I64_S                             = 1020, // WebAssemblyInstrFormats.td:61
    GLOBAL_GET_V128                              = 1021, // WebAssemblyInstrFormats.td:59
    GLOBAL_GET_V128_S                            = 1022, // WebAssemblyInstrFormats.td:61
    GLOBAL_SET_EXNREF                            = 1023, // WebAssemblyInstrFormats.td:59
    GLOBAL_SET_EXNREF_S                          = 1024, // WebAssemblyInstrFormats.td:61
    GLOBAL_SET_EXTERNREF                         = 1025, // WebAssemblyInstrFormats.td:59
    GLOBAL_SET_EXTERNREF_S                       = 1026, // WebAssemblyInstrFormats.td:61
    GLOBAL_SET_F32                               = 1027, // WebAssemblyInstrFormats.td:59
    GLOBAL_SET_F32_S                             = 1028, // WebAssemblyInstrFormats.td:61
    GLOBAL_SET_F64                               = 1029, // WebAssemblyInstrFormats.td:59
    GLOBAL_SET_F64_S                             = 1030, // WebAssemblyInstrFormats.td:61
    GLOBAL_SET_FUNCREF                           = 1031, // WebAssemblyInstrFormats.td:59
    GLOBAL_SET_FUNCREF_S                         = 1032, // WebAssemblyInstrFormats.td:61
    GLOBAL_SET_I32                               = 1033, // WebAssemblyInstrFormats.td:59
    GLOBAL_SET_I32_S                             = 1034, // WebAssemblyInstrFormats.td:61
    GLOBAL_SET_I64                               = 1035, // WebAssemblyInstrFormats.td:59
    GLOBAL_SET_I64_S                             = 1036, // WebAssemblyInstrFormats.td:61
    GLOBAL_SET_V128                              = 1037, // WebAssemblyInstrFormats.td:59
    GLOBAL_SET_V128_S                            = 1038, // WebAssemblyInstrFormats.td:61
    GT_F16x8                                     = 1039, // WebAssemblyInstrFormats.td:59
    GT_F16x8_S                                   = 1040, // WebAssemblyInstrFormats.td:61
    GT_F32                                       = 1041, // WebAssemblyInstrFormats.td:59
    GT_F32_S                                     = 1042, // WebAssemblyInstrFormats.td:61
    GT_F32x4                                     = 1043, // WebAssemblyInstrFormats.td:59
    GT_F32x4_S                                   = 1044, // WebAssemblyInstrFormats.td:61
    GT_F64                                       = 1045, // WebAssemblyInstrFormats.td:59
    GT_F64_S                                     = 1046, // WebAssemblyInstrFormats.td:61
    GT_F64x2                                     = 1047, // WebAssemblyInstrFormats.td:59
    GT_F64x2_S                                   = 1048, // WebAssemblyInstrFormats.td:61
    GT_S_I16x8                                   = 1049, // WebAssemblyInstrFormats.td:59
    GT_S_I16x8_S                                 = 1050, // WebAssemblyInstrFormats.td:61
    GT_S_I32                                     = 1051, // WebAssemblyInstrFormats.td:59
    GT_S_I32_S                                   = 1052, // WebAssemblyInstrFormats.td:61
    GT_S_I32x4                                   = 1053, // WebAssemblyInstrFormats.td:59
    GT_S_I32x4_S                                 = 1054, // WebAssemblyInstrFormats.td:61
    GT_S_I64                                     = 1055, // WebAssemblyInstrFormats.td:59
    GT_S_I64_S                                   = 1056, // WebAssemblyInstrFormats.td:61
    GT_S_I64x2                                   = 1057, // WebAssemblyInstrFormats.td:59
    GT_S_I64x2_S                                 = 1058, // WebAssemblyInstrFormats.td:61
    GT_S_I8x16                                   = 1059, // WebAssemblyInstrFormats.td:59
    GT_S_I8x16_S                                 = 1060, // WebAssemblyInstrFormats.td:61
    GT_U_I16x8                                   = 1061, // WebAssemblyInstrFormats.td:59
    GT_U_I16x8_S                                 = 1062, // WebAssemblyInstrFormats.td:61
    GT_U_I32                                     = 1063, // WebAssemblyInstrFormats.td:59
    GT_U_I32_S                                   = 1064, // WebAssemblyInstrFormats.td:61
    GT_U_I32x4                                   = 1065, // WebAssemblyInstrFormats.td:59
    GT_U_I32x4_S                                 = 1066, // WebAssemblyInstrFormats.td:61
    GT_U_I64                                     = 1067, // WebAssemblyInstrFormats.td:59
    GT_U_I64_S                                   = 1068, // WebAssemblyInstrFormats.td:61
    GT_U_I8x16                                   = 1069, // WebAssemblyInstrFormats.td:59
    GT_U_I8x16_S                                 = 1070, // WebAssemblyInstrFormats.td:61
    I32_EXTEND16_S_I32                           = 1071, // WebAssemblyInstrFormats.td:59
    I32_EXTEND16_S_I32_S                         = 1072, // WebAssemblyInstrFormats.td:61
    I32_EXTEND8_S_I32                            = 1073, // WebAssemblyInstrFormats.td:59
    I32_EXTEND8_S_I32_S                          = 1074, // WebAssemblyInstrFormats.td:61
    I32_REINTERPRET_F32                          = 1075, // WebAssemblyInstrFormats.td:59
    I32_REINTERPRET_F32_S                        = 1076, // WebAssemblyInstrFormats.td:61
    I32_TRUNC_S_F32                              = 1077, // WebAssemblyInstrFormats.td:59
    I32_TRUNC_S_F32_S                            = 1078, // WebAssemblyInstrFormats.td:61
    I32_TRUNC_S_F64                              = 1079, // WebAssemblyInstrFormats.td:59
    I32_TRUNC_S_F64_S                            = 1080, // WebAssemblyInstrFormats.td:61
    I32_TRUNC_S_SAT_F32                          = 1081, // WebAssemblyInstrFormats.td:59
    I32_TRUNC_S_SAT_F32_S                        = 1082, // WebAssemblyInstrFormats.td:61
    I32_TRUNC_S_SAT_F64                          = 1083, // WebAssemblyInstrFormats.td:59
    I32_TRUNC_S_SAT_F64_S                        = 1084, // WebAssemblyInstrFormats.td:61
    I32_TRUNC_U_F32                              = 1085, // WebAssemblyInstrFormats.td:59
    I32_TRUNC_U_F32_S                            = 1086, // WebAssemblyInstrFormats.td:61
    I32_TRUNC_U_F64                              = 1087, // WebAssemblyInstrFormats.td:59
    I32_TRUNC_U_F64_S                            = 1088, // WebAssemblyInstrFormats.td:61
    I32_TRUNC_U_SAT_F32                          = 1089, // WebAssemblyInstrFormats.td:59
    I32_TRUNC_U_SAT_F32_S                        = 1090, // WebAssemblyInstrFormats.td:61
    I32_TRUNC_U_SAT_F64                          = 1091, // WebAssemblyInstrFormats.td:59
    I32_TRUNC_U_SAT_F64_S                        = 1092, // WebAssemblyInstrFormats.td:61
    I32_WRAP_I64                                 = 1093, // WebAssemblyInstrFormats.td:59
    I32_WRAP_I64_S                               = 1094, // WebAssemblyInstrFormats.td:61
    I64_ADD128                                   = 1095, // WebAssemblyInstrFormats.td:59
    I64_ADD128_S                                 = 1096, // WebAssemblyInstrFormats.td:61
    I64_EXTEND16_S_I64                           = 1097, // WebAssemblyInstrFormats.td:59
    I64_EXTEND16_S_I64_S                         = 1098, // WebAssemblyInstrFormats.td:61
    I64_EXTEND32_S_I64                           = 1099, // WebAssemblyInstrFormats.td:59
    I64_EXTEND32_S_I64_S                         = 1100, // WebAssemblyInstrFormats.td:61
    I64_EXTEND8_S_I64                            = 1101, // WebAssemblyInstrFormats.td:59
    I64_EXTEND8_S_I64_S                          = 1102, // WebAssemblyInstrFormats.td:61
    I64_EXTEND_S_I32                             = 1103, // WebAssemblyInstrFormats.td:59
    I64_EXTEND_S_I32_S                           = 1104, // WebAssemblyInstrFormats.td:61
    I64_EXTEND_U_I32                             = 1105, // WebAssemblyInstrFormats.td:59
    I64_EXTEND_U_I32_S                           = 1106, // WebAssemblyInstrFormats.td:61
    I64_MUL_WIDE_S                               = 1107, // WebAssemblyInstrFormats.td:59
    I64_MUL_WIDE_S_S                             = 1108, // WebAssemblyInstrFormats.td:61
    I64_MUL_WIDE_U                               = 1109, // WebAssemblyInstrFormats.td:59
    I64_MUL_WIDE_U_S                             = 1110, // WebAssemblyInstrFormats.td:61
    I64_REINTERPRET_F64                          = 1111, // WebAssemblyInstrFormats.td:59
    I64_REINTERPRET_F64_S                        = 1112, // WebAssemblyInstrFormats.td:61
    I64_SUB128                                   = 1113, // WebAssemblyInstrFormats.td:59
    I64_SUB128_S                                 = 1114, // WebAssemblyInstrFormats.td:61
    I64_TRUNC_S_F32                              = 1115, // WebAssemblyInstrFormats.td:59
    I64_TRUNC_S_F32_S                            = 1116, // WebAssemblyInstrFormats.td:61
    I64_TRUNC_S_F64                              = 1117, // WebAssemblyInstrFormats.td:59
    I64_TRUNC_S_F64_S                            = 1118, // WebAssemblyInstrFormats.td:61
    I64_TRUNC_S_SAT_F32                          = 1119, // WebAssemblyInstrFormats.td:59
    I64_TRUNC_S_SAT_F32_S                        = 1120, // WebAssemblyInstrFormats.td:61
    I64_TRUNC_S_SAT_F64                          = 1121, // WebAssemblyInstrFormats.td:59
    I64_TRUNC_S_SAT_F64_S                        = 1122, // WebAssemblyInstrFormats.td:61
    I64_TRUNC_U_F32                              = 1123, // WebAssemblyInstrFormats.td:59
    I64_TRUNC_U_F32_S                            = 1124, // WebAssemblyInstrFormats.td:61
    I64_TRUNC_U_F64                              = 1125, // WebAssemblyInstrFormats.td:59
    I64_TRUNC_U_F64_S                            = 1126, // WebAssemblyInstrFormats.td:61
    I64_TRUNC_U_SAT_F32                          = 1127, // WebAssemblyInstrFormats.td:59
    I64_TRUNC_U_SAT_F32_S                        = 1128, // WebAssemblyInstrFormats.td:61
    I64_TRUNC_U_SAT_F64                          = 1129, // WebAssemblyInstrFormats.td:59
    I64_TRUNC_U_SAT_F64_S                        = 1130, // WebAssemblyInstrFormats.td:61
    IF                                           = 1131, // WebAssemblyInstrFormats.td:59
    IF_S                                         = 1132, // WebAssemblyInstrFormats.td:61
    LANESELECT_I16x8                             = 1133, // WebAssemblyInstrFormats.td:59
    LANESELECT_I16x8_S                           = 1134, // WebAssemblyInstrFormats.td:61
    LANESELECT_I32x4                             = 1135, // WebAssemblyInstrFormats.td:59
    LANESELECT_I32x4_S                           = 1136, // WebAssemblyInstrFormats.td:61
    LANESELECT_I64x2                             = 1137, // WebAssemblyInstrFormats.td:59
    LANESELECT_I64x2_S                           = 1138, // WebAssemblyInstrFormats.td:61
    LANESELECT_I8x16                             = 1139, // WebAssemblyInstrFormats.td:59
    LANESELECT_I8x16_S                           = 1140, // WebAssemblyInstrFormats.td:61
    LE_F16x8                                     = 1141, // WebAssemblyInstrFormats.td:59
    LE_F16x8_S                                   = 1142, // WebAssemblyInstrFormats.td:61
    LE_F32                                       = 1143, // WebAssemblyInstrFormats.td:59
    LE_F32_S                                     = 1144, // WebAssemblyInstrFormats.td:61
    LE_F32x4                                     = 1145, // WebAssemblyInstrFormats.td:59
    LE_F32x4_S                                   = 1146, // WebAssemblyInstrFormats.td:61
    LE_F64                                       = 1147, // WebAssemblyInstrFormats.td:59
    LE_F64_S                                     = 1148, // WebAssemblyInstrFormats.td:61
    LE_F64x2                                     = 1149, // WebAssemblyInstrFormats.td:59
    LE_F64x2_S                                   = 1150, // WebAssemblyInstrFormats.td:61
    LE_S_I16x8                                   = 1151, // WebAssemblyInstrFormats.td:59
    LE_S_I16x8_S                                 = 1152, // WebAssemblyInstrFormats.td:61
    LE_S_I32                                     = 1153, // WebAssemblyInstrFormats.td:59
    LE_S_I32_S                                   = 1154, // WebAssemblyInstrFormats.td:61
    LE_S_I32x4                                   = 1155, // WebAssemblyInstrFormats.td:59
    LE_S_I32x4_S                                 = 1156, // WebAssemblyInstrFormats.td:61
    LE_S_I64                                     = 1157, // WebAssemblyInstrFormats.td:59
    LE_S_I64_S                                   = 1158, // WebAssemblyInstrFormats.td:61
    LE_S_I64x2                                   = 1159, // WebAssemblyInstrFormats.td:59
    LE_S_I64x2_S                                 = 1160, // WebAssemblyInstrFormats.td:61
    LE_S_I8x16                                   = 1161, // WebAssemblyInstrFormats.td:59
    LE_S_I8x16_S                                 = 1162, // WebAssemblyInstrFormats.td:61
    LE_U_I16x8                                   = 1163, // WebAssemblyInstrFormats.td:59
    LE_U_I16x8_S                                 = 1164, // WebAssemblyInstrFormats.td:61
    LE_U_I32                                     = 1165, // WebAssemblyInstrFormats.td:59
    LE_U_I32_S                                   = 1166, // WebAssemblyInstrFormats.td:61
    LE_U_I32x4                                   = 1167, // WebAssemblyInstrFormats.td:59
    LE_U_I32x4_S                                 = 1168, // WebAssemblyInstrFormats.td:61
    LE_U_I64                                     = 1169, // WebAssemblyInstrFormats.td:59
    LE_U_I64_S                                   = 1170, // WebAssemblyInstrFormats.td:61
    LE_U_I8x16                                   = 1171, // WebAssemblyInstrFormats.td:59
    LE_U_I8x16_S                                 = 1172, // WebAssemblyInstrFormats.td:61
    LOAD16_SPLAT_A32                             = 1173, // WebAssemblyInstrFormats.td:59
    LOAD16_SPLAT_A32_S                           = 1174, // WebAssemblyInstrFormats.td:61
    LOAD16_SPLAT_A64                             = 1175, // WebAssemblyInstrFormats.td:59
    LOAD16_SPLAT_A64_S                           = 1176, // WebAssemblyInstrFormats.td:61
    LOAD16_S_I32_A32                             = 1177, // WebAssemblyInstrFormats.td:59
    LOAD16_S_I32_A32_S                           = 1178, // WebAssemblyInstrFormats.td:61
    LOAD16_S_I32_A64                             = 1179, // WebAssemblyInstrFormats.td:59
    LOAD16_S_I32_A64_S                           = 1180, // WebAssemblyInstrFormats.td:61
    LOAD16_S_I64_A32                             = 1181, // WebAssemblyInstrFormats.td:59
    LOAD16_S_I64_A32_S                           = 1182, // WebAssemblyInstrFormats.td:61
    LOAD16_S_I64_A64                             = 1183, // WebAssemblyInstrFormats.td:59
    LOAD16_S_I64_A64_S                           = 1184, // WebAssemblyInstrFormats.td:61
    LOAD16_U_I32_A32                             = 1185, // WebAssemblyInstrFormats.td:59
    LOAD16_U_I32_A32_S                           = 1186, // WebAssemblyInstrFormats.td:61
    LOAD16_U_I32_A64                             = 1187, // WebAssemblyInstrFormats.td:59
    LOAD16_U_I32_A64_S                           = 1188, // WebAssemblyInstrFormats.td:61
    LOAD16_U_I64_A32                             = 1189, // WebAssemblyInstrFormats.td:59
    LOAD16_U_I64_A32_S                           = 1190, // WebAssemblyInstrFormats.td:61
    LOAD16_U_I64_A64                             = 1191, // WebAssemblyInstrFormats.td:59
    LOAD16_U_I64_A64_S                           = 1192, // WebAssemblyInstrFormats.td:61
    LOAD32_SPLAT_A32                             = 1193, // WebAssemblyInstrFormats.td:59
    LOAD32_SPLAT_A32_S                           = 1194, // WebAssemblyInstrFormats.td:61
    LOAD32_SPLAT_A64                             = 1195, // WebAssemblyInstrFormats.td:59
    LOAD32_SPLAT_A64_S                           = 1196, // WebAssemblyInstrFormats.td:61
    LOAD32_S_I64_A32                             = 1197, // WebAssemblyInstrFormats.td:59
    LOAD32_S_I64_A32_S                           = 1198, // WebAssemblyInstrFormats.td:61
    LOAD32_S_I64_A64                             = 1199, // WebAssemblyInstrFormats.td:59
    LOAD32_S_I64_A64_S                           = 1200, // WebAssemblyInstrFormats.td:61
    LOAD32_U_I64_A32                             = 1201, // WebAssemblyInstrFormats.td:59
    LOAD32_U_I64_A32_S                           = 1202, // WebAssemblyInstrFormats.td:61
    LOAD32_U_I64_A64                             = 1203, // WebAssemblyInstrFormats.td:59
    LOAD32_U_I64_A64_S                           = 1204, // WebAssemblyInstrFormats.td:61
    LOAD64_SPLAT_A32                             = 1205, // WebAssemblyInstrFormats.td:59
    LOAD64_SPLAT_A32_S                           = 1206, // WebAssemblyInstrFormats.td:61
    LOAD64_SPLAT_A64                             = 1207, // WebAssemblyInstrFormats.td:59
    LOAD64_SPLAT_A64_S                           = 1208, // WebAssemblyInstrFormats.td:61
    LOAD8_SPLAT_A32                              = 1209, // WebAssemblyInstrFormats.td:59
    LOAD8_SPLAT_A32_S                            = 1210, // WebAssemblyInstrFormats.td:61
    LOAD8_SPLAT_A64                              = 1211, // WebAssemblyInstrFormats.td:59
    LOAD8_SPLAT_A64_S                            = 1212, // WebAssemblyInstrFormats.td:61
    LOAD8_S_I32_A32                              = 1213, // WebAssemblyInstrFormats.td:59
    LOAD8_S_I32_A32_S                            = 1214, // WebAssemblyInstrFormats.td:61
    LOAD8_S_I32_A64                              = 1215, // WebAssemblyInstrFormats.td:59
    LOAD8_S_I32_A64_S                            = 1216, // WebAssemblyInstrFormats.td:61
    LOAD8_S_I64_A32                              = 1217, // WebAssemblyInstrFormats.td:59
    LOAD8_S_I64_A32_S                            = 1218, // WebAssemblyInstrFormats.td:61
    LOAD8_S_I64_A64                              = 1219, // WebAssemblyInstrFormats.td:59
    LOAD8_S_I64_A64_S                            = 1220, // WebAssemblyInstrFormats.td:61
    LOAD8_U_I32_A32                              = 1221, // WebAssemblyInstrFormats.td:59
    LOAD8_U_I32_A32_S                            = 1222, // WebAssemblyInstrFormats.td:61
    LOAD8_U_I32_A64                              = 1223, // WebAssemblyInstrFormats.td:59
    LOAD8_U_I32_A64_S                            = 1224, // WebAssemblyInstrFormats.td:61
    LOAD8_U_I64_A32                              = 1225, // WebAssemblyInstrFormats.td:59
    LOAD8_U_I64_A32_S                            = 1226, // WebAssemblyInstrFormats.td:61
    LOAD8_U_I64_A64                              = 1227, // WebAssemblyInstrFormats.td:59
    LOAD8_U_I64_A64_S                            = 1228, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_S_I16x8_A32                      = 1229, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_S_I16x8_A32_S                    = 1230, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_S_I16x8_A64                      = 1231, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_S_I16x8_A64_S                    = 1232, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_S_I32x4_A32                      = 1233, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_S_I32x4_A32_S                    = 1234, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_S_I32x4_A64                      = 1235, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_S_I32x4_A64_S                    = 1236, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_S_I64x2_A32                      = 1237, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_S_I64x2_A32_S                    = 1238, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_S_I64x2_A64                      = 1239, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_S_I64x2_A64_S                    = 1240, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_U_I16x8_A32                      = 1241, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_U_I16x8_A32_S                    = 1242, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_U_I16x8_A64                      = 1243, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_U_I16x8_A64_S                    = 1244, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_U_I32x4_A32                      = 1245, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_U_I32x4_A32_S                    = 1246, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_U_I32x4_A64                      = 1247, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_U_I32x4_A64_S                    = 1248, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_U_I64x2_A32                      = 1249, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_U_I64x2_A32_S                    = 1250, // WebAssemblyInstrFormats.td:61
    LOAD_EXTEND_U_I64x2_A64                      = 1251, // WebAssemblyInstrFormats.td:59
    LOAD_EXTEND_U_I64x2_A64_S                    = 1252, // WebAssemblyInstrFormats.td:61
    LOAD_F16_F32_A32                             = 1253, // WebAssemblyInstrFormats.td:59
    LOAD_F16_F32_A32_S                           = 1254, // WebAssemblyInstrFormats.td:61
    LOAD_F16_F32_A64                             = 1255, // WebAssemblyInstrFormats.td:59
    LOAD_F16_F32_A64_S                           = 1256, // WebAssemblyInstrFormats.td:61
    LOAD_F32_A32                                 = 1257, // WebAssemblyInstrFormats.td:59
    LOAD_F32_A32_S                               = 1258, // WebAssemblyInstrFormats.td:61
    LOAD_F32_A64                                 = 1259, // WebAssemblyInstrFormats.td:59
    LOAD_F32_A64_S                               = 1260, // WebAssemblyInstrFormats.td:61
    LOAD_F64_A32                                 = 1261, // WebAssemblyInstrFormats.td:59
    LOAD_F64_A32_S                               = 1262, // WebAssemblyInstrFormats.td:61
    LOAD_F64_A64                                 = 1263, // WebAssemblyInstrFormats.td:59
    LOAD_F64_A64_S                               = 1264, // WebAssemblyInstrFormats.td:61
    LOAD_I32_A32                                 = 1265, // WebAssemblyInstrFormats.td:59
    LOAD_I32_A32_S                               = 1266, // WebAssemblyInstrFormats.td:61
    LOAD_I32_A64                                 = 1267, // WebAssemblyInstrFormats.td:59
    LOAD_I32_A64_S                               = 1268, // WebAssemblyInstrFormats.td:61
    LOAD_I64_A32                                 = 1269, // WebAssemblyInstrFormats.td:59
    LOAD_I64_A32_S                               = 1270, // WebAssemblyInstrFormats.td:61
    LOAD_I64_A64                                 = 1271, // WebAssemblyInstrFormats.td:59
    LOAD_I64_A64_S                               = 1272, // WebAssemblyInstrFormats.td:61
    LOAD_LANE_16_A32                             = 1273, // WebAssemblyInstrFormats.td:59
    LOAD_LANE_16_A32_S                           = 1274, // WebAssemblyInstrFormats.td:61
    LOAD_LANE_16_A64                             = 1275, // WebAssemblyInstrFormats.td:59
    LOAD_LANE_16_A64_S                           = 1276, // WebAssemblyInstrFormats.td:61
    LOAD_LANE_32_A32                             = 1277, // WebAssemblyInstrFormats.td:59
    LOAD_LANE_32_A32_S                           = 1278, // WebAssemblyInstrFormats.td:61
    LOAD_LANE_32_A64                             = 1279, // WebAssemblyInstrFormats.td:59
    LOAD_LANE_32_A64_S                           = 1280, // WebAssemblyInstrFormats.td:61
    LOAD_LANE_64_A32                             = 1281, // WebAssemblyInstrFormats.td:59
    LOAD_LANE_64_A32_S                           = 1282, // WebAssemblyInstrFormats.td:61
    LOAD_LANE_64_A64                             = 1283, // WebAssemblyInstrFormats.td:59
    LOAD_LANE_64_A64_S                           = 1284, // WebAssemblyInstrFormats.td:61
    LOAD_LANE_8_A32                              = 1285, // WebAssemblyInstrFormats.td:59
    LOAD_LANE_8_A32_S                            = 1286, // WebAssemblyInstrFormats.td:61
    LOAD_LANE_8_A64                              = 1287, // WebAssemblyInstrFormats.td:59
    LOAD_LANE_8_A64_S                            = 1288, // WebAssemblyInstrFormats.td:61
    LOAD_V128_A32                                = 1289, // WebAssemblyInstrFormats.td:59
    LOAD_V128_A32_S                              = 1290, // WebAssemblyInstrFormats.td:61
    LOAD_V128_A64                                = 1291, // WebAssemblyInstrFormats.td:59
    LOAD_V128_A64_S                              = 1292, // WebAssemblyInstrFormats.td:61
    LOAD_ZERO_32_A32                             = 1293, // WebAssemblyInstrFormats.td:59
    LOAD_ZERO_32_A32_S                           = 1294, // WebAssemblyInstrFormats.td:61
    LOAD_ZERO_32_A64                             = 1295, // WebAssemblyInstrFormats.td:59
    LOAD_ZERO_32_A64_S                           = 1296, // WebAssemblyInstrFormats.td:61
    LOAD_ZERO_64_A32                             = 1297, // WebAssemblyInstrFormats.td:59
    LOAD_ZERO_64_A32_S                           = 1298, // WebAssemblyInstrFormats.td:61
    LOAD_ZERO_64_A64                             = 1299, // WebAssemblyInstrFormats.td:59
    LOAD_ZERO_64_A64_S                           = 1300, // WebAssemblyInstrFormats.td:61
    LOCAL_GET_EXNREF                             = 1301, // WebAssemblyInstrFormats.td:59
    LOCAL_GET_EXNREF_S                           = 1302, // WebAssemblyInstrFormats.td:61
    LOCAL_GET_EXTERNREF                          = 1303, // WebAssemblyInstrFormats.td:59
    LOCAL_GET_EXTERNREF_S                        = 1304, // WebAssemblyInstrFormats.td:61
    LOCAL_GET_F32                                = 1305, // WebAssemblyInstrFormats.td:59
    LOCAL_GET_F32_S                              = 1306, // WebAssemblyInstrFormats.td:61
    LOCAL_GET_F64                                = 1307, // WebAssemblyInstrFormats.td:59
    LOCAL_GET_F64_S                              = 1308, // WebAssemblyInstrFormats.td:61
    LOCAL_GET_FUNCREF                            = 1309, // WebAssemblyInstrFormats.td:59
    LOCAL_GET_FUNCREF_S                          = 1310, // WebAssemblyInstrFormats.td:61
    LOCAL_GET_I32                                = 1311, // WebAssemblyInstrFormats.td:59
    LOCAL_GET_I32_S                              = 1312, // WebAssemblyInstrFormats.td:61
    LOCAL_GET_I64                                = 1313, // WebAssemblyInstrFormats.td:59
    LOCAL_GET_I64_S                              = 1314, // WebAssemblyInstrFormats.td:61
    LOCAL_GET_V128                               = 1315, // WebAssemblyInstrFormats.td:59
    LOCAL_GET_V128_S                             = 1316, // WebAssemblyInstrFormats.td:61
    LOCAL_SET_EXNREF                             = 1317, // WebAssemblyInstrFormats.td:59
    LOCAL_SET_EXNREF_S                           = 1318, // WebAssemblyInstrFormats.td:61
    LOCAL_SET_EXTERNREF                          = 1319, // WebAssemblyInstrFormats.td:59
    LOCAL_SET_EXTERNREF_S                        = 1320, // WebAssemblyInstrFormats.td:61
    LOCAL_SET_F32                                = 1321, // WebAssemblyInstrFormats.td:59
    LOCAL_SET_F32_S                              = 1322, // WebAssemblyInstrFormats.td:61
    LOCAL_SET_F64                                = 1323, // WebAssemblyInstrFormats.td:59
    LOCAL_SET_F64_S                              = 1324, // WebAssemblyInstrFormats.td:61
    LOCAL_SET_FUNCREF                            = 1325, // WebAssemblyInstrFormats.td:59
    LOCAL_SET_FUNCREF_S                          = 1326, // WebAssemblyInstrFormats.td:61
    LOCAL_SET_I32                                = 1327, // WebAssemblyInstrFormats.td:59
    LOCAL_SET_I32_S                              = 1328, // WebAssemblyInstrFormats.td:61
    LOCAL_SET_I64                                = 1329, // WebAssemblyInstrFormats.td:59
    LOCAL_SET_I64_S                              = 1330, // WebAssemblyInstrFormats.td:61
    LOCAL_SET_V128                               = 1331, // WebAssemblyInstrFormats.td:59
    LOCAL_SET_V128_S                             = 1332, // WebAssemblyInstrFormats.td:61
    LOCAL_TEE_EXNREF                             = 1333, // WebAssemblyInstrFormats.td:59
    LOCAL_TEE_EXNREF_S                           = 1334, // WebAssemblyInstrFormats.td:61
    LOCAL_TEE_EXTERNREF                          = 1335, // WebAssemblyInstrFormats.td:59
    LOCAL_TEE_EXTERNREF_S                        = 1336, // WebAssemblyInstrFormats.td:61
    LOCAL_TEE_F32                                = 1337, // WebAssemblyInstrFormats.td:59
    LOCAL_TEE_F32_S                              = 1338, // WebAssemblyInstrFormats.td:61
    LOCAL_TEE_F64                                = 1339, // WebAssemblyInstrFormats.td:59
    LOCAL_TEE_F64_S                              = 1340, // WebAssemblyInstrFormats.td:61
    LOCAL_TEE_FUNCREF                            = 1341, // WebAssemblyInstrFormats.td:59
    LOCAL_TEE_FUNCREF_S                          = 1342, // WebAssemblyInstrFormats.td:61
    LOCAL_TEE_I32                                = 1343, // WebAssemblyInstrFormats.td:59
    LOCAL_TEE_I32_S                              = 1344, // WebAssemblyInstrFormats.td:61
    LOCAL_TEE_I64                                = 1345, // WebAssemblyInstrFormats.td:59
    LOCAL_TEE_I64_S                              = 1346, // WebAssemblyInstrFormats.td:61
    LOCAL_TEE_V128                               = 1347, // WebAssemblyInstrFormats.td:59
    LOCAL_TEE_V128_S                             = 1348, // WebAssemblyInstrFormats.td:61
    LOOP                                         = 1349, // WebAssemblyInstrFormats.td:59
    LOOP_S                                       = 1350, // WebAssemblyInstrFormats.td:61
    LT_F16x8                                     = 1351, // WebAssemblyInstrFormats.td:59
    LT_F16x8_S                                   = 1352, // WebAssemblyInstrFormats.td:61
    LT_F32                                       = 1353, // WebAssemblyInstrFormats.td:59
    LT_F32_S                                     = 1354, // WebAssemblyInstrFormats.td:61
    LT_F32x4                                     = 1355, // WebAssemblyInstrFormats.td:59
    LT_F32x4_S                                   = 1356, // WebAssemblyInstrFormats.td:61
    LT_F64                                       = 1357, // WebAssemblyInstrFormats.td:59
    LT_F64_S                                     = 1358, // WebAssemblyInstrFormats.td:61
    LT_F64x2                                     = 1359, // WebAssemblyInstrFormats.td:59
    LT_F64x2_S                                   = 1360, // WebAssemblyInstrFormats.td:61
    LT_S_I16x8                                   = 1361, // WebAssemblyInstrFormats.td:59
    LT_S_I16x8_S                                 = 1362, // WebAssemblyInstrFormats.td:61
    LT_S_I32                                     = 1363, // WebAssemblyInstrFormats.td:59
    LT_S_I32_S                                   = 1364, // WebAssemblyInstrFormats.td:61
    LT_S_I32x4                                   = 1365, // WebAssemblyInstrFormats.td:59
    LT_S_I32x4_S                                 = 1366, // WebAssemblyInstrFormats.td:61
    LT_S_I64                                     = 1367, // WebAssemblyInstrFormats.td:59
    LT_S_I64_S                                   = 1368, // WebAssemblyInstrFormats.td:61
    LT_S_I64x2                                   = 1369, // WebAssemblyInstrFormats.td:59
    LT_S_I64x2_S                                 = 1370, // WebAssemblyInstrFormats.td:61
    LT_S_I8x16                                   = 1371, // WebAssemblyInstrFormats.td:59
    LT_S_I8x16_S                                 = 1372, // WebAssemblyInstrFormats.td:61
    LT_U_I16x8                                   = 1373, // WebAssemblyInstrFormats.td:59
    LT_U_I16x8_S                                 = 1374, // WebAssemblyInstrFormats.td:61
    LT_U_I32                                     = 1375, // WebAssemblyInstrFormats.td:59
    LT_U_I32_S                                   = 1376, // WebAssemblyInstrFormats.td:61
    LT_U_I32x4                                   = 1377, // WebAssemblyInstrFormats.td:59
    LT_U_I32x4_S                                 = 1378, // WebAssemblyInstrFormats.td:61
    LT_U_I64                                     = 1379, // WebAssemblyInstrFormats.td:59
    LT_U_I64_S                                   = 1380, // WebAssemblyInstrFormats.td:61
    LT_U_I8x16                                   = 1381, // WebAssemblyInstrFormats.td:59
    LT_U_I8x16_S                                 = 1382, // WebAssemblyInstrFormats.td:61
    MADD_F16x8                                   = 1383, // WebAssemblyInstrFormats.td:59
    MADD_F16x8_S                                 = 1384, // WebAssemblyInstrFormats.td:61
    MADD_F32x4                                   = 1385, // WebAssemblyInstrFormats.td:59
    MADD_F32x4_S                                 = 1386, // WebAssemblyInstrFormats.td:61
    MADD_F64x2                                   = 1387, // WebAssemblyInstrFormats.td:59
    MADD_F64x2_S                                 = 1388, // WebAssemblyInstrFormats.td:61
    MAX_F16x8                                    = 1389, // WebAssemblyInstrFormats.td:59
    MAX_F16x8_S                                  = 1390, // WebAssemblyInstrFormats.td:61
    MAX_F32                                      = 1391, // WebAssemblyInstrFormats.td:59
    MAX_F32_S                                    = 1392, // WebAssemblyInstrFormats.td:61
    MAX_F32x4                                    = 1393, // WebAssemblyInstrFormats.td:59
    MAX_F32x4_S                                  = 1394, // WebAssemblyInstrFormats.td:61
    MAX_F64                                      = 1395, // WebAssemblyInstrFormats.td:59
    MAX_F64_S                                    = 1396, // WebAssemblyInstrFormats.td:61
    MAX_F64x2                                    = 1397, // WebAssemblyInstrFormats.td:59
    MAX_F64x2_S                                  = 1398, // WebAssemblyInstrFormats.td:61
    MAX_S_I16x8                                  = 1399, // WebAssemblyInstrFormats.td:59
    MAX_S_I16x8_S                                = 1400, // WebAssemblyInstrFormats.td:61
    MAX_S_I32x4                                  = 1401, // WebAssemblyInstrFormats.td:59
    MAX_S_I32x4_S                                = 1402, // WebAssemblyInstrFormats.td:61
    MAX_S_I8x16                                  = 1403, // WebAssemblyInstrFormats.td:59
    MAX_S_I8x16_S                                = 1404, // WebAssemblyInstrFormats.td:61
    MAX_U_I16x8                                  = 1405, // WebAssemblyInstrFormats.td:59
    MAX_U_I16x8_S                                = 1406, // WebAssemblyInstrFormats.td:61
    MAX_U_I32x4                                  = 1407, // WebAssemblyInstrFormats.td:59
    MAX_U_I32x4_S                                = 1408, // WebAssemblyInstrFormats.td:61
    MAX_U_I8x16                                  = 1409, // WebAssemblyInstrFormats.td:59
    MAX_U_I8x16_S                                = 1410, // WebAssemblyInstrFormats.td:61
    MEMCPY_A32                                   = 1411, // WebAssemblyInstrFormats.td:59
    MEMCPY_A32_S                                 = 1412, // WebAssemblyInstrFormats.td:61
    MEMCPY_A64                                   = 1413, // WebAssemblyInstrFormats.td:59
    MEMCPY_A64_S                                 = 1414, // WebAssemblyInstrFormats.td:61
    MEMORY_ATOMIC_NOTIFY_A32                     = 1415, // WebAssemblyInstrFormats.td:59
    MEMORY_ATOMIC_NOTIFY_A32_S                   = 1416, // WebAssemblyInstrFormats.td:61
    MEMORY_ATOMIC_NOTIFY_A64                     = 1417, // WebAssemblyInstrFormats.td:59
    MEMORY_ATOMIC_NOTIFY_A64_S                   = 1418, // WebAssemblyInstrFormats.td:61
    MEMORY_ATOMIC_WAIT32_A32                     = 1419, // WebAssemblyInstrFormats.td:59
    MEMORY_ATOMIC_WAIT32_A32_S                   = 1420, // WebAssemblyInstrFormats.td:61
    MEMORY_ATOMIC_WAIT32_A64                     = 1421, // WebAssemblyInstrFormats.td:59
    MEMORY_ATOMIC_WAIT32_A64_S                   = 1422, // WebAssemblyInstrFormats.td:61
    MEMORY_ATOMIC_WAIT64_A32                     = 1423, // WebAssemblyInstrFormats.td:59
    MEMORY_ATOMIC_WAIT64_A32_S                   = 1424, // WebAssemblyInstrFormats.td:61
    MEMORY_ATOMIC_WAIT64_A64                     = 1425, // WebAssemblyInstrFormats.td:59
    MEMORY_ATOMIC_WAIT64_A64_S                   = 1426, // WebAssemblyInstrFormats.td:61
    MEMORY_COPY_A32                              = 1427, // WebAssemblyInstrFormats.td:59
    MEMORY_COPY_A32_S                            = 1428, // WebAssemblyInstrFormats.td:61
    MEMORY_COPY_A64                              = 1429, // WebAssemblyInstrFormats.td:59
    MEMORY_COPY_A64_S                            = 1430, // WebAssemblyInstrFormats.td:61
    MEMORY_FILL_A32                              = 1431, // WebAssemblyInstrFormats.td:59
    MEMORY_FILL_A32_S                            = 1432, // WebAssemblyInstrFormats.td:61
    MEMORY_FILL_A64                              = 1433, // WebAssemblyInstrFormats.td:59
    MEMORY_FILL_A64_S                            = 1434, // WebAssemblyInstrFormats.td:61
    MEMORY_INIT_A32                              = 1435, // WebAssemblyInstrFormats.td:59
    MEMORY_INIT_A32_S                            = 1436, // WebAssemblyInstrFormats.td:61
    MEMORY_INIT_A64                              = 1437, // WebAssemblyInstrFormats.td:59
    MEMORY_INIT_A64_S                            = 1438, // WebAssemblyInstrFormats.td:61
    MEMSET_A32                                   = 1439, // WebAssemblyInstrFormats.td:59
    MEMSET_A32_S                                 = 1440, // WebAssemblyInstrFormats.td:61
    MEMSET_A64                                   = 1441, // WebAssemblyInstrFormats.td:59
    MEMSET_A64_S                                 = 1442, // WebAssemblyInstrFormats.td:61
    MIN_F16x8                                    = 1443, // WebAssemblyInstrFormats.td:59
    MIN_F16x8_S                                  = 1444, // WebAssemblyInstrFormats.td:61
    MIN_F32                                      = 1445, // WebAssemblyInstrFormats.td:59
    MIN_F32_S                                    = 1446, // WebAssemblyInstrFormats.td:61
    MIN_F32x4                                    = 1447, // WebAssemblyInstrFormats.td:59
    MIN_F32x4_S                                  = 1448, // WebAssemblyInstrFormats.td:61
    MIN_F64                                      = 1449, // WebAssemblyInstrFormats.td:59
    MIN_F64_S                                    = 1450, // WebAssemblyInstrFormats.td:61
    MIN_F64x2                                    = 1451, // WebAssemblyInstrFormats.td:59
    MIN_F64x2_S                                  = 1452, // WebAssemblyInstrFormats.td:61
    MIN_S_I16x8                                  = 1453, // WebAssemblyInstrFormats.td:59
    MIN_S_I16x8_S                                = 1454, // WebAssemblyInstrFormats.td:61
    MIN_S_I32x4                                  = 1455, // WebAssemblyInstrFormats.td:59
    MIN_S_I32x4_S                                = 1456, // WebAssemblyInstrFormats.td:61
    MIN_S_I8x16                                  = 1457, // WebAssemblyInstrFormats.td:59
    MIN_S_I8x16_S                                = 1458, // WebAssemblyInstrFormats.td:61
    MIN_U_I16x8                                  = 1459, // WebAssemblyInstrFormats.td:59
    MIN_U_I16x8_S                                = 1460, // WebAssemblyInstrFormats.td:61
    MIN_U_I32x4                                  = 1461, // WebAssemblyInstrFormats.td:59
    MIN_U_I32x4_S                                = 1462, // WebAssemblyInstrFormats.td:61
    MIN_U_I8x16                                  = 1463, // WebAssemblyInstrFormats.td:59
    MIN_U_I8x16_S                                = 1464, // WebAssemblyInstrFormats.td:61
    MUL_F16x8                                    = 1465, // WebAssemblyInstrFormats.td:59
    MUL_F16x8_S                                  = 1466, // WebAssemblyInstrFormats.td:61
    MUL_F32                                      = 1467, // WebAssemblyInstrFormats.td:59
    MUL_F32_S                                    = 1468, // WebAssemblyInstrFormats.td:61
    MUL_F32x4                                    = 1469, // WebAssemblyInstrFormats.td:59
    MUL_F32x4_S                                  = 1470, // WebAssemblyInstrFormats.td:61
    MUL_F64                                      = 1471, // WebAssemblyInstrFormats.td:59
    MUL_F64_S                                    = 1472, // WebAssemblyInstrFormats.td:61
    MUL_F64x2                                    = 1473, // WebAssemblyInstrFormats.td:59
    MUL_F64x2_S                                  = 1474, // WebAssemblyInstrFormats.td:61
    MUL_I16x8                                    = 1475, // WebAssemblyInstrFormats.td:59
    MUL_I16x8_S                                  = 1476, // WebAssemblyInstrFormats.td:61
    MUL_I32                                      = 1477, // WebAssemblyInstrFormats.td:59
    MUL_I32_S                                    = 1478, // WebAssemblyInstrFormats.td:61
    MUL_I32x4                                    = 1479, // WebAssemblyInstrFormats.td:59
    MUL_I32x4_S                                  = 1480, // WebAssemblyInstrFormats.td:61
    MUL_I64                                      = 1481, // WebAssemblyInstrFormats.td:59
    MUL_I64_S                                    = 1482, // WebAssemblyInstrFormats.td:61
    MUL_I64x2                                    = 1483, // WebAssemblyInstrFormats.td:59
    MUL_I64x2_S                                  = 1484, // WebAssemblyInstrFormats.td:61
    NARROW_S_I16x8                               = 1485, // WebAssemblyInstrFormats.td:59
    NARROW_S_I16x8_S                             = 1486, // WebAssemblyInstrFormats.td:61
    NARROW_S_I8x16                               = 1487, // WebAssemblyInstrFormats.td:59
    NARROW_S_I8x16_S                             = 1488, // WebAssemblyInstrFormats.td:61
    NARROW_U_I16x8                               = 1489, // WebAssemblyInstrFormats.td:59
    NARROW_U_I16x8_S                             = 1490, // WebAssemblyInstrFormats.td:61
    NARROW_U_I8x16                               = 1491, // WebAssemblyInstrFormats.td:59
    NARROW_U_I8x16_S                             = 1492, // WebAssemblyInstrFormats.td:61
    NEAREST_F16x8                                = 1493, // WebAssemblyInstrFormats.td:59
    NEAREST_F16x8_S                              = 1494, // WebAssemblyInstrFormats.td:61
    NEAREST_F32                                  = 1495, // WebAssemblyInstrFormats.td:59
    NEAREST_F32_S                                = 1496, // WebAssemblyInstrFormats.td:61
    NEAREST_F32x4                                = 1497, // WebAssemblyInstrFormats.td:59
    NEAREST_F32x4_S                              = 1498, // WebAssemblyInstrFormats.td:61
    NEAREST_F64                                  = 1499, // WebAssemblyInstrFormats.td:59
    NEAREST_F64_S                                = 1500, // WebAssemblyInstrFormats.td:61
    NEAREST_F64x2                                = 1501, // WebAssemblyInstrFormats.td:59
    NEAREST_F64x2_S                              = 1502, // WebAssemblyInstrFormats.td:61
    NEG_F16x8                                    = 1503, // WebAssemblyInstrFormats.td:59
    NEG_F16x8_S                                  = 1504, // WebAssemblyInstrFormats.td:61
    NEG_F32                                      = 1505, // WebAssemblyInstrFormats.td:59
    NEG_F32_S                                    = 1506, // WebAssemblyInstrFormats.td:61
    NEG_F32x4                                    = 1507, // WebAssemblyInstrFormats.td:59
    NEG_F32x4_S                                  = 1508, // WebAssemblyInstrFormats.td:61
    NEG_F64                                      = 1509, // WebAssemblyInstrFormats.td:59
    NEG_F64_S                                    = 1510, // WebAssemblyInstrFormats.td:61
    NEG_F64x2                                    = 1511, // WebAssemblyInstrFormats.td:59
    NEG_F64x2_S                                  = 1512, // WebAssemblyInstrFormats.td:61
    NEG_I16x8                                    = 1513, // WebAssemblyInstrFormats.td:59
    NEG_I16x8_S                                  = 1514, // WebAssemblyInstrFormats.td:61
    NEG_I32x4                                    = 1515, // WebAssemblyInstrFormats.td:59
    NEG_I32x4_S                                  = 1516, // WebAssemblyInstrFormats.td:61
    NEG_I64x2                                    = 1517, // WebAssemblyInstrFormats.td:59
    NEG_I64x2_S                                  = 1518, // WebAssemblyInstrFormats.td:61
    NEG_I8x16                                    = 1519, // WebAssemblyInstrFormats.td:59
    NEG_I8x16_S                                  = 1520, // WebAssemblyInstrFormats.td:61
    NE_F16x8                                     = 1521, // WebAssemblyInstrFormats.td:59
    NE_F16x8_S                                   = 1522, // WebAssemblyInstrFormats.td:61
    NE_F32                                       = 1523, // WebAssemblyInstrFormats.td:59
    NE_F32_S                                     = 1524, // WebAssemblyInstrFormats.td:61
    NE_F32x4                                     = 1525, // WebAssemblyInstrFormats.td:59
    NE_F32x4_S                                   = 1526, // WebAssemblyInstrFormats.td:61
    NE_F64                                       = 1527, // WebAssemblyInstrFormats.td:59
    NE_F64_S                                     = 1528, // WebAssemblyInstrFormats.td:61
    NE_F64x2                                     = 1529, // WebAssemblyInstrFormats.td:59
    NE_F64x2_S                                   = 1530, // WebAssemblyInstrFormats.td:61
    NE_I16x8                                     = 1531, // WebAssemblyInstrFormats.td:59
    NE_I16x8_S                                   = 1532, // WebAssemblyInstrFormats.td:61
    NE_I32                                       = 1533, // WebAssemblyInstrFormats.td:59
    NE_I32_S                                     = 1534, // WebAssemblyInstrFormats.td:61
    NE_I32x4                                     = 1535, // WebAssemblyInstrFormats.td:59
    NE_I32x4_S                                   = 1536, // WebAssemblyInstrFormats.td:61
    NE_I64                                       = 1537, // WebAssemblyInstrFormats.td:59
    NE_I64_S                                     = 1538, // WebAssemblyInstrFormats.td:61
    NE_I64x2                                     = 1539, // WebAssemblyInstrFormats.td:59
    NE_I64x2_S                                   = 1540, // WebAssemblyInstrFormats.td:61
    NE_I8x16                                     = 1541, // WebAssemblyInstrFormats.td:59
    NE_I8x16_S                                   = 1542, // WebAssemblyInstrFormats.td:61
    NMADD_F16x8                                  = 1543, // WebAssemblyInstrFormats.td:59
    NMADD_F16x8_S                                = 1544, // WebAssemblyInstrFormats.td:61
    NMADD_F32x4                                  = 1545, // WebAssemblyInstrFormats.td:59
    NMADD_F32x4_S                                = 1546, // WebAssemblyInstrFormats.td:61
    NMADD_F64x2                                  = 1547, // WebAssemblyInstrFormats.td:59
    NMADD_F64x2_S                                = 1548, // WebAssemblyInstrFormats.td:61
    NOP                                          = 1549, // WebAssemblyInstrFormats.td:59
    NOP_S                                        = 1550, // WebAssemblyInstrFormats.td:61
    NOT                                          = 1551, // WebAssemblyInstrFormats.td:59
    NOT_S                                        = 1552, // WebAssemblyInstrFormats.td:61
    OR                                           = 1553, // WebAssemblyInstrFormats.td:59
    OR_I32                                       = 1554, // WebAssemblyInstrFormats.td:59
    OR_I32_S                                     = 1555, // WebAssemblyInstrFormats.td:61
    OR_I64                                       = 1556, // WebAssemblyInstrFormats.td:59
    OR_I64_S                                     = 1557, // WebAssemblyInstrFormats.td:61
    OR_S                                         = 1558, // WebAssemblyInstrFormats.td:61
    PMAX_F16x8                                   = 1559, // WebAssemblyInstrFormats.td:59
    PMAX_F16x8_S                                 = 1560, // WebAssemblyInstrFormats.td:61
    PMAX_F32x4                                   = 1561, // WebAssemblyInstrFormats.td:59
    PMAX_F32x4_S                                 = 1562, // WebAssemblyInstrFormats.td:61
    PMAX_F64x2                                   = 1563, // WebAssemblyInstrFormats.td:59
    PMAX_F64x2_S                                 = 1564, // WebAssemblyInstrFormats.td:61
    PMIN_F16x8                                   = 1565, // WebAssemblyInstrFormats.td:59
    PMIN_F16x8_S                                 = 1566, // WebAssemblyInstrFormats.td:61
    PMIN_F32x4                                   = 1567, // WebAssemblyInstrFormats.td:59
    PMIN_F32x4_S                                 = 1568, // WebAssemblyInstrFormats.td:61
    PMIN_F64x2                                   = 1569, // WebAssemblyInstrFormats.td:59
    PMIN_F64x2_S                                 = 1570, // WebAssemblyInstrFormats.td:61
    POPCNT_I32                                   = 1571, // WebAssemblyInstrFormats.td:59
    POPCNT_I32_S                                 = 1572, // WebAssemblyInstrFormats.td:61
    POPCNT_I64                                   = 1573, // WebAssemblyInstrFormats.td:59
    POPCNT_I64_S                                 = 1574, // WebAssemblyInstrFormats.td:61
    POPCNT_I8x16                                 = 1575, // WebAssemblyInstrFormats.td:59
    POPCNT_I8x16_S                               = 1576, // WebAssemblyInstrFormats.td:61
    Q15MULR_SAT_S_I16x8                          = 1577, // WebAssemblyInstrFormats.td:59
    Q15MULR_SAT_S_I16x8_S                        = 1578, // WebAssemblyInstrFormats.td:61
    REF_CAST_FUNCREF                             = 1579, // WebAssemblyInstrFormats.td:59
    REF_CAST_FUNCREF_S                           = 1580, // WebAssemblyInstrFormats.td:61
    REF_FUNC                                     = 1581, // WebAssemblyInstrFormats.td:59
    REF_FUNC_S                                   = 1582, // WebAssemblyInstrFormats.td:61
    REF_IS_NULL_EXNREF                           = 1583, // WebAssemblyInstrFormats.td:59
    REF_IS_NULL_EXNREF_S                         = 1584, // WebAssemblyInstrFormats.td:61
    REF_IS_NULL_EXTERNREF                        = 1585, // WebAssemblyInstrFormats.td:59
    REF_IS_NULL_EXTERNREF_S                      = 1586, // WebAssemblyInstrFormats.td:61
    REF_IS_NULL_FUNCREF                          = 1587, // WebAssemblyInstrFormats.td:59
    REF_IS_NULL_FUNCREF_S                        = 1588, // WebAssemblyInstrFormats.td:61
    REF_NULL_EXNREF                              = 1589, // WebAssemblyInstrFormats.td:59
    REF_NULL_EXNREF_S                            = 1590, // WebAssemblyInstrFormats.td:61
    REF_NULL_EXTERNREF                           = 1591, // WebAssemblyInstrFormats.td:59
    REF_NULL_EXTERNREF_S                         = 1592, // WebAssemblyInstrFormats.td:61
    REF_NULL_FUNCREF                             = 1593, // WebAssemblyInstrFormats.td:59
    REF_NULL_FUNCREF_S                           = 1594, // WebAssemblyInstrFormats.td:61
    REF_TEST_FUNCREF                             = 1595, // WebAssemblyInstrFormats.td:59
    REF_TEST_FUNCREF_S                           = 1596, // WebAssemblyInstrFormats.td:61
    RELAXED_DOT                                  = 1597, // WebAssemblyInstrFormats.td:59
    RELAXED_DOT_ADD                              = 1598, // WebAssemblyInstrFormats.td:59
    RELAXED_DOT_ADD_S                            = 1599, // WebAssemblyInstrFormats.td:61
    RELAXED_DOT_BFLOAT                           = 1600, // WebAssemblyInstrFormats.td:59
    RELAXED_DOT_BFLOAT_S                         = 1601, // WebAssemblyInstrFormats.td:61
    RELAXED_DOT_S                                = 1602, // WebAssemblyInstrFormats.td:61
    RELAXED_Q15MULR_S_I16x8                      = 1603, // WebAssemblyInstrFormats.td:59
    RELAXED_Q15MULR_S_I16x8_S                    = 1604, // WebAssemblyInstrFormats.td:61
    RELAXED_SWIZZLE                              = 1605, // WebAssemblyInstrFormats.td:59
    RELAXED_SWIZZLE_S                            = 1606, // WebAssemblyInstrFormats.td:61
    REM_S_I32                                    = 1607, // WebAssemblyInstrFormats.td:59
    REM_S_I32_S                                  = 1608, // WebAssemblyInstrFormats.td:61
    REM_S_I64                                    = 1609, // WebAssemblyInstrFormats.td:59
    REM_S_I64_S                                  = 1610, // WebAssemblyInstrFormats.td:61
    REM_U_I32                                    = 1611, // WebAssemblyInstrFormats.td:59
    REM_U_I32_S                                  = 1612, // WebAssemblyInstrFormats.td:61
    REM_U_I64                                    = 1613, // WebAssemblyInstrFormats.td:59
    REM_U_I64_S                                  = 1614, // WebAssemblyInstrFormats.td:61
    REPLACE_LANE_F16x8                           = 1615, // WebAssemblyInstrFormats.td:59
    REPLACE_LANE_F16x8_S                         = 1616, // WebAssemblyInstrFormats.td:61
    REPLACE_LANE_F32x4                           = 1617, // WebAssemblyInstrFormats.td:59
    REPLACE_LANE_F32x4_S                         = 1618, // WebAssemblyInstrFormats.td:61
    REPLACE_LANE_F64x2                           = 1619, // WebAssemblyInstrFormats.td:59
    REPLACE_LANE_F64x2_S                         = 1620, // WebAssemblyInstrFormats.td:61
    REPLACE_LANE_I16x8                           = 1621, // WebAssemblyInstrFormats.td:59
    REPLACE_LANE_I16x8_S                         = 1622, // WebAssemblyInstrFormats.td:61
    REPLACE_LANE_I32x4                           = 1623, // WebAssemblyInstrFormats.td:59
    REPLACE_LANE_I32x4_S                         = 1624, // WebAssemblyInstrFormats.td:61
    REPLACE_LANE_I64x2                           = 1625, // WebAssemblyInstrFormats.td:59
    REPLACE_LANE_I64x2_S                         = 1626, // WebAssemblyInstrFormats.td:61
    REPLACE_LANE_I8x16                           = 1627, // WebAssemblyInstrFormats.td:59
    REPLACE_LANE_I8x16_S                         = 1628, // WebAssemblyInstrFormats.td:61
    RETHROW                                      = 1629, // WebAssemblyInstrFormats.td:59
    RETHROW_S                                    = 1630, // WebAssemblyInstrFormats.td:61
    RETURN                                       = 1631, // WebAssemblyInstrFormats.td:59
    RETURN_S                                     = 1632, // WebAssemblyInstrFormats.td:61
    RET_CALL                                     = 1633, // WebAssemblyInstrFormats.td:59
    RET_CALL_INDIRECT                            = 1634, // WebAssemblyInstrFormats.td:59
    RET_CALL_INDIRECT_S                          = 1635, // WebAssemblyInstrFormats.td:61
    RET_CALL_REF                                 = 1636, // WebAssemblyInstrFormats.td:59
    RET_CALL_REF_S                               = 1637, // WebAssemblyInstrFormats.td:61
    RET_CALL_S                                   = 1638, // WebAssemblyInstrFormats.td:61
    ROTL_I32                                     = 1639, // WebAssemblyInstrFormats.td:59
    ROTL_I32_S                                   = 1640, // WebAssemblyInstrFormats.td:61
    ROTL_I64                                     = 1641, // WebAssemblyInstrFormats.td:59
    ROTL_I64_S                                   = 1642, // WebAssemblyInstrFormats.td:61
    ROTR_I32                                     = 1643, // WebAssemblyInstrFormats.td:59
    ROTR_I32_S                                   = 1644, // WebAssemblyInstrFormats.td:61
    ROTR_I64                                     = 1645, // WebAssemblyInstrFormats.td:59
    ROTR_I64_S                                   = 1646, // WebAssemblyInstrFormats.td:61
    SELECT_EXNREF                                = 1647, // WebAssemblyInstrFormats.td:59
    SELECT_EXNREF_S                              = 1648, // WebAssemblyInstrFormats.td:61
    SELECT_EXTERNREF                             = 1649, // WebAssemblyInstrFormats.td:59
    SELECT_EXTERNREF_S                           = 1650, // WebAssemblyInstrFormats.td:61
    SELECT_F32                                   = 1651, // WebAssemblyInstrFormats.td:59
    SELECT_F32_S                                 = 1652, // WebAssemblyInstrFormats.td:61
    SELECT_F64                                   = 1653, // WebAssemblyInstrFormats.td:59
    SELECT_F64_S                                 = 1654, // WebAssemblyInstrFormats.td:61
    SELECT_FUNCREF                               = 1655, // WebAssemblyInstrFormats.td:59
    SELECT_FUNCREF_S                             = 1656, // WebAssemblyInstrFormats.td:61
    SELECT_I32                                   = 1657, // WebAssemblyInstrFormats.td:59
    SELECT_I32_S                                 = 1658, // WebAssemblyInstrFormats.td:61
    SELECT_I64                                   = 1659, // WebAssemblyInstrFormats.td:59
    SELECT_I64_S                                 = 1660, // WebAssemblyInstrFormats.td:61
    SELECT_T                                     = 1661, // WebAssemblyInstrFormats.td:59
    SELECT_T_S                                   = 1662, // WebAssemblyInstrFormats.td:61
    SELECT_V128                                  = 1663, // WebAssemblyInstrFormats.td:59
    SELECT_V128_S                                = 1664, // WebAssemblyInstrFormats.td:61
    SHL_I16x8                                    = 1665, // WebAssemblyInstrFormats.td:59
    SHL_I16x8_S                                  = 1666, // WebAssemblyInstrFormats.td:61
    SHL_I32                                      = 1667, // WebAssemblyInstrFormats.td:59
    SHL_I32_S                                    = 1668, // WebAssemblyInstrFormats.td:61
    SHL_I32x4                                    = 1669, // WebAssemblyInstrFormats.td:59
    SHL_I32x4_S                                  = 1670, // WebAssemblyInstrFormats.td:61
    SHL_I64                                      = 1671, // WebAssemblyInstrFormats.td:59
    SHL_I64_S                                    = 1672, // WebAssemblyInstrFormats.td:61
    SHL_I64x2                                    = 1673, // WebAssemblyInstrFormats.td:59
    SHL_I64x2_S                                  = 1674, // WebAssemblyInstrFormats.td:61
    SHL_I8x16                                    = 1675, // WebAssemblyInstrFormats.td:59
    SHL_I8x16_S                                  = 1676, // WebAssemblyInstrFormats.td:61
    SHR_S_I16x8                                  = 1677, // WebAssemblyInstrFormats.td:59
    SHR_S_I16x8_S                                = 1678, // WebAssemblyInstrFormats.td:61
    SHR_S_I32                                    = 1679, // WebAssemblyInstrFormats.td:59
    SHR_S_I32_S                                  = 1680, // WebAssemblyInstrFormats.td:61
    SHR_S_I32x4                                  = 1681, // WebAssemblyInstrFormats.td:59
    SHR_S_I32x4_S                                = 1682, // WebAssemblyInstrFormats.td:61
    SHR_S_I64                                    = 1683, // WebAssemblyInstrFormats.td:59
    SHR_S_I64_S                                  = 1684, // WebAssemblyInstrFormats.td:61
    SHR_S_I64x2                                  = 1685, // WebAssemblyInstrFormats.td:59
    SHR_S_I64x2_S                                = 1686, // WebAssemblyInstrFormats.td:61
    SHR_S_I8x16                                  = 1687, // WebAssemblyInstrFormats.td:59
    SHR_S_I8x16_S                                = 1688, // WebAssemblyInstrFormats.td:61
    SHR_U_I16x8                                  = 1689, // WebAssemblyInstrFormats.td:59
    SHR_U_I16x8_S                                = 1690, // WebAssemblyInstrFormats.td:61
    SHR_U_I32                                    = 1691, // WebAssemblyInstrFormats.td:59
    SHR_U_I32_S                                  = 1692, // WebAssemblyInstrFormats.td:61
    SHR_U_I32x4                                  = 1693, // WebAssemblyInstrFormats.td:59
    SHR_U_I32x4_S                                = 1694, // WebAssemblyInstrFormats.td:61
    SHR_U_I64                                    = 1695, // WebAssemblyInstrFormats.td:59
    SHR_U_I64_S                                  = 1696, // WebAssemblyInstrFormats.td:61
    SHR_U_I64x2                                  = 1697, // WebAssemblyInstrFormats.td:59
    SHR_U_I64x2_S                                = 1698, // WebAssemblyInstrFormats.td:61
    SHR_U_I8x16                                  = 1699, // WebAssemblyInstrFormats.td:59
    SHR_U_I8x16_S                                = 1700, // WebAssemblyInstrFormats.td:61
    SHUFFLE                                      = 1701, // WebAssemblyInstrFormats.td:59
    SHUFFLE_S                                    = 1702, // WebAssemblyInstrFormats.td:61
    SIMD_RELAXED_FMAX_F32x4                      = 1703, // WebAssemblyInstrFormats.td:59
    SIMD_RELAXED_FMAX_F32x4_S                    = 1704, // WebAssemblyInstrFormats.td:61
    SIMD_RELAXED_FMAX_F64x2                      = 1705, // WebAssemblyInstrFormats.td:59
    SIMD_RELAXED_FMAX_F64x2_S                    = 1706, // WebAssemblyInstrFormats.td:61
    SIMD_RELAXED_FMIN_F32x4                      = 1707, // WebAssemblyInstrFormats.td:59
    SIMD_RELAXED_FMIN_F32x4_S                    = 1708, // WebAssemblyInstrFormats.td:61
    SIMD_RELAXED_FMIN_F64x2                      = 1709, // WebAssemblyInstrFormats.td:59
    SIMD_RELAXED_FMIN_F64x2_S                    = 1710, // WebAssemblyInstrFormats.td:61
    SPLAT_F16x8                                  = 1711, // WebAssemblyInstrFormats.td:59
    SPLAT_F16x8_S                                = 1712, // WebAssemblyInstrFormats.td:61
    SPLAT_F32x4                                  = 1713, // WebAssemblyInstrFormats.td:59
    SPLAT_F32x4_S                                = 1714, // WebAssemblyInstrFormats.td:61
    SPLAT_F64x2                                  = 1715, // WebAssemblyInstrFormats.td:59
    SPLAT_F64x2_S                                = 1716, // WebAssemblyInstrFormats.td:61
    SPLAT_I16x8                                  = 1717, // WebAssemblyInstrFormats.td:59
    SPLAT_I16x8_S                                = 1718, // WebAssemblyInstrFormats.td:61
    SPLAT_I32x4                                  = 1719, // WebAssemblyInstrFormats.td:59
    SPLAT_I32x4_S                                = 1720, // WebAssemblyInstrFormats.td:61
    SPLAT_I64x2                                  = 1721, // WebAssemblyInstrFormats.td:59
    SPLAT_I64x2_S                                = 1722, // WebAssemblyInstrFormats.td:61
    SPLAT_I8x16                                  = 1723, // WebAssemblyInstrFormats.td:59
    SPLAT_I8x16_S                                = 1724, // WebAssemblyInstrFormats.td:61
    SQRT_F16x8                                   = 1725, // WebAssemblyInstrFormats.td:59
    SQRT_F16x8_S                                 = 1726, // WebAssemblyInstrFormats.td:61
    SQRT_F32                                     = 1727, // WebAssemblyInstrFormats.td:59
    SQRT_F32_S                                   = 1728, // WebAssemblyInstrFormats.td:61
    SQRT_F32x4                                   = 1729, // WebAssemblyInstrFormats.td:59
    SQRT_F32x4_S                                 = 1730, // WebAssemblyInstrFormats.td:61
    SQRT_F64                                     = 1731, // WebAssemblyInstrFormats.td:59
    SQRT_F64_S                                   = 1732, // WebAssemblyInstrFormats.td:61
    SQRT_F64x2                                   = 1733, // WebAssemblyInstrFormats.td:59
    SQRT_F64x2_S                                 = 1734, // WebAssemblyInstrFormats.td:61
    STORE16_I32_A32                              = 1735, // WebAssemblyInstrFormats.td:59
    STORE16_I32_A32_S                            = 1736, // WebAssemblyInstrFormats.td:61
    STORE16_I32_A64                              = 1737, // WebAssemblyInstrFormats.td:59
    STORE16_I32_A64_S                            = 1738, // WebAssemblyInstrFormats.td:61
    STORE16_I64_A32                              = 1739, // WebAssemblyInstrFormats.td:59
    STORE16_I64_A32_S                            = 1740, // WebAssemblyInstrFormats.td:61
    STORE16_I64_A64                              = 1741, // WebAssemblyInstrFormats.td:59
    STORE16_I64_A64_S                            = 1742, // WebAssemblyInstrFormats.td:61
    STORE32_I64_A32                              = 1743, // WebAssemblyInstrFormats.td:59
    STORE32_I64_A32_S                            = 1744, // WebAssemblyInstrFormats.td:61
    STORE32_I64_A64                              = 1745, // WebAssemblyInstrFormats.td:59
    STORE32_I64_A64_S                            = 1746, // WebAssemblyInstrFormats.td:61
    STORE8_I32_A32                               = 1747, // WebAssemblyInstrFormats.td:59
    STORE8_I32_A32_S                             = 1748, // WebAssemblyInstrFormats.td:61
    STORE8_I32_A64                               = 1749, // WebAssemblyInstrFormats.td:59
    STORE8_I32_A64_S                             = 1750, // WebAssemblyInstrFormats.td:61
    STORE8_I64_A32                               = 1751, // WebAssemblyInstrFormats.td:59
    STORE8_I64_A32_S                             = 1752, // WebAssemblyInstrFormats.td:61
    STORE8_I64_A64                               = 1753, // WebAssemblyInstrFormats.td:59
    STORE8_I64_A64_S                             = 1754, // WebAssemblyInstrFormats.td:61
    STORE_F16_F32_A32                            = 1755, // WebAssemblyInstrFormats.td:59
    STORE_F16_F32_A32_S                          = 1756, // WebAssemblyInstrFormats.td:61
    STORE_F16_F32_A64                            = 1757, // WebAssemblyInstrFormats.td:59
    STORE_F16_F32_A64_S                          = 1758, // WebAssemblyInstrFormats.td:61
    STORE_F32_A32                                = 1759, // WebAssemblyInstrFormats.td:59
    STORE_F32_A32_S                              = 1760, // WebAssemblyInstrFormats.td:61
    STORE_F32_A64                                = 1761, // WebAssemblyInstrFormats.td:59
    STORE_F32_A64_S                              = 1762, // WebAssemblyInstrFormats.td:61
    STORE_F64_A32                                = 1763, // WebAssemblyInstrFormats.td:59
    STORE_F64_A32_S                              = 1764, // WebAssemblyInstrFormats.td:61
    STORE_F64_A64                                = 1765, // WebAssemblyInstrFormats.td:59
    STORE_F64_A64_S                              = 1766, // WebAssemblyInstrFormats.td:61
    STORE_I32_A32                                = 1767, // WebAssemblyInstrFormats.td:59
    STORE_I32_A32_S                              = 1768, // WebAssemblyInstrFormats.td:61
    STORE_I32_A64                                = 1769, // WebAssemblyInstrFormats.td:59
    STORE_I32_A64_S                              = 1770, // WebAssemblyInstrFormats.td:61
    STORE_I64_A32                                = 1771, // WebAssemblyInstrFormats.td:59
    STORE_I64_A32_S                              = 1772, // WebAssemblyInstrFormats.td:61
    STORE_I64_A64                                = 1773, // WebAssemblyInstrFormats.td:59
    STORE_I64_A64_S                              = 1774, // WebAssemblyInstrFormats.td:61
    STORE_LANE_I16x8_A32                         = 1775, // WebAssemblyInstrFormats.td:59
    STORE_LANE_I16x8_A32_S                       = 1776, // WebAssemblyInstrFormats.td:61
    STORE_LANE_I16x8_A64                         = 1777, // WebAssemblyInstrFormats.td:59
    STORE_LANE_I16x8_A64_S                       = 1778, // WebAssemblyInstrFormats.td:61
    STORE_LANE_I32x4_A32                         = 1779, // WebAssemblyInstrFormats.td:59
    STORE_LANE_I32x4_A32_S                       = 1780, // WebAssemblyInstrFormats.td:61
    STORE_LANE_I32x4_A64                         = 1781, // WebAssemblyInstrFormats.td:59
    STORE_LANE_I32x4_A64_S                       = 1782, // WebAssemblyInstrFormats.td:61
    STORE_LANE_I64x2_A32                         = 1783, // WebAssemblyInstrFormats.td:59
    STORE_LANE_I64x2_A32_S                       = 1784, // WebAssemblyInstrFormats.td:61
    STORE_LANE_I64x2_A64                         = 1785, // WebAssemblyInstrFormats.td:59
    STORE_LANE_I64x2_A64_S                       = 1786, // WebAssemblyInstrFormats.td:61
    STORE_LANE_I8x16_A32                         = 1787, // WebAssemblyInstrFormats.td:59
    STORE_LANE_I8x16_A32_S                       = 1788, // WebAssemblyInstrFormats.td:61
    STORE_LANE_I8x16_A64                         = 1789, // WebAssemblyInstrFormats.td:59
    STORE_LANE_I8x16_A64_S                       = 1790, // WebAssemblyInstrFormats.td:61
    STORE_V128_A32                               = 1791, // WebAssemblyInstrFormats.td:59
    STORE_V128_A32_S                             = 1792, // WebAssemblyInstrFormats.td:61
    STORE_V128_A64                               = 1793, // WebAssemblyInstrFormats.td:59
    STORE_V128_A64_S                             = 1794, // WebAssemblyInstrFormats.td:61
    SUB_F16x8                                    = 1795, // WebAssemblyInstrFormats.td:59
    SUB_F16x8_S                                  = 1796, // WebAssemblyInstrFormats.td:61
    SUB_F32                                      = 1797, // WebAssemblyInstrFormats.td:59
    SUB_F32_S                                    = 1798, // WebAssemblyInstrFormats.td:61
    SUB_F32x4                                    = 1799, // WebAssemblyInstrFormats.td:59
    SUB_F32x4_S                                  = 1800, // WebAssemblyInstrFormats.td:61
    SUB_F64                                      = 1801, // WebAssemblyInstrFormats.td:59
    SUB_F64_S                                    = 1802, // WebAssemblyInstrFormats.td:61
    SUB_F64x2                                    = 1803, // WebAssemblyInstrFormats.td:59
    SUB_F64x2_S                                  = 1804, // WebAssemblyInstrFormats.td:61
    SUB_I16x8                                    = 1805, // WebAssemblyInstrFormats.td:59
    SUB_I16x8_S                                  = 1806, // WebAssemblyInstrFormats.td:61
    SUB_I32                                      = 1807, // WebAssemblyInstrFormats.td:59
    SUB_I32_S                                    = 1808, // WebAssemblyInstrFormats.td:61
    SUB_I32x4                                    = 1809, // WebAssemblyInstrFormats.td:59
    SUB_I32x4_S                                  = 1810, // WebAssemblyInstrFormats.td:61
    SUB_I64                                      = 1811, // WebAssemblyInstrFormats.td:59
    SUB_I64_S                                    = 1812, // WebAssemblyInstrFormats.td:61
    SUB_I64x2                                    = 1813, // WebAssemblyInstrFormats.td:59
    SUB_I64x2_S                                  = 1814, // WebAssemblyInstrFormats.td:61
    SUB_I8x16                                    = 1815, // WebAssemblyInstrFormats.td:59
    SUB_I8x16_S                                  = 1816, // WebAssemblyInstrFormats.td:61
    SUB_SAT_S_I16x8                              = 1817, // WebAssemblyInstrFormats.td:59
    SUB_SAT_S_I16x8_S                            = 1818, // WebAssemblyInstrFormats.td:61
    SUB_SAT_S_I8x16                              = 1819, // WebAssemblyInstrFormats.td:59
    SUB_SAT_S_I8x16_S                            = 1820, // WebAssemblyInstrFormats.td:61
    SUB_SAT_U_I16x8                              = 1821, // WebAssemblyInstrFormats.td:59
    SUB_SAT_U_I16x8_S                            = 1822, // WebAssemblyInstrFormats.td:61
    SUB_SAT_U_I8x16                              = 1823, // WebAssemblyInstrFormats.td:59
    SUB_SAT_U_I8x16_S                            = 1824, // WebAssemblyInstrFormats.td:61
    SWIZZLE                                      = 1825, // WebAssemblyInstrFormats.td:59
    SWIZZLE_S                                    = 1826, // WebAssemblyInstrFormats.td:61
    TABLE_COPY                                   = 1827, // WebAssemblyInstrFormats.td:59
    TABLE_COPY_S                                 = 1828, // WebAssemblyInstrFormats.td:61
    TABLE_FILL_EXNREF                            = 1829, // WebAssemblyInstrFormats.td:59
    TABLE_FILL_EXNREF_S                          = 1830, // WebAssemblyInstrFormats.td:61
    TABLE_FILL_EXTERNREF                         = 1831, // WebAssemblyInstrFormats.td:59
    TABLE_FILL_EXTERNREF_S                       = 1832, // WebAssemblyInstrFormats.td:61
    TABLE_FILL_FUNCREF                           = 1833, // WebAssemblyInstrFormats.td:59
    TABLE_FILL_FUNCREF_S                         = 1834, // WebAssemblyInstrFormats.td:61
    TABLE_GET_EXNREF                             = 1835, // WebAssemblyInstrFormats.td:59
    TABLE_GET_EXNREF_S                           = 1836, // WebAssemblyInstrFormats.td:61
    TABLE_GET_EXTERNREF                          = 1837, // WebAssemblyInstrFormats.td:59
    TABLE_GET_EXTERNREF_S                        = 1838, // WebAssemblyInstrFormats.td:61
    TABLE_GET_FUNCREF                            = 1839, // WebAssemblyInstrFormats.td:59
    TABLE_GET_FUNCREF_S                          = 1840, // WebAssemblyInstrFormats.td:61
    TABLE_GROW_EXNREF                            = 1841, // WebAssemblyInstrFormats.td:59
    TABLE_GROW_EXNREF_S                          = 1842, // WebAssemblyInstrFormats.td:61
    TABLE_GROW_EXTERNREF                         = 1843, // WebAssemblyInstrFormats.td:59
    TABLE_GROW_EXTERNREF_S                       = 1844, // WebAssemblyInstrFormats.td:61
    TABLE_GROW_FUNCREF                           = 1845, // WebAssemblyInstrFormats.td:59
    TABLE_GROW_FUNCREF_S                         = 1846, // WebAssemblyInstrFormats.td:61
    TABLE_SET_EXNREF                             = 1847, // WebAssemblyInstrFormats.td:59
    TABLE_SET_EXNREF_S                           = 1848, // WebAssemblyInstrFormats.td:61
    TABLE_SET_EXTERNREF                          = 1849, // WebAssemblyInstrFormats.td:59
    TABLE_SET_EXTERNREF_S                        = 1850, // WebAssemblyInstrFormats.td:61
    TABLE_SET_FUNCREF                            = 1851, // WebAssemblyInstrFormats.td:59
    TABLE_SET_FUNCREF_S                          = 1852, // WebAssemblyInstrFormats.td:61
    TABLE_SIZE                                   = 1853, // WebAssemblyInstrFormats.td:59
    TABLE_SIZE_S                                 = 1854, // WebAssemblyInstrFormats.td:61
    TEE_EXNREF                                   = 1855, // WebAssemblyInstrFormats.td:59
    TEE_EXNREF_S                                 = 1856, // WebAssemblyInstrFormats.td:61
    TEE_EXTERNREF                                = 1857, // WebAssemblyInstrFormats.td:59
    TEE_EXTERNREF_S                              = 1858, // WebAssemblyInstrFormats.td:61
    TEE_F32                                      = 1859, // WebAssemblyInstrFormats.td:59
    TEE_F32_S                                    = 1860, // WebAssemblyInstrFormats.td:61
    TEE_F64                                      = 1861, // WebAssemblyInstrFormats.td:59
    TEE_F64_S                                    = 1862, // WebAssemblyInstrFormats.td:61
    TEE_FUNCREF                                  = 1863, // WebAssemblyInstrFormats.td:59
    TEE_FUNCREF_S                                = 1864, // WebAssemblyInstrFormats.td:61
    TEE_I32                                      = 1865, // WebAssemblyInstrFormats.td:59
    TEE_I32_S                                    = 1866, // WebAssemblyInstrFormats.td:61
    TEE_I64                                      = 1867, // WebAssemblyInstrFormats.td:59
    TEE_I64_S                                    = 1868, // WebAssemblyInstrFormats.td:61
    TEE_V128                                     = 1869, // WebAssemblyInstrFormats.td:59
    TEE_V128_S                                   = 1870, // WebAssemblyInstrFormats.td:61
    THROW                                        = 1871, // WebAssemblyInstrFormats.td:59
    THROW_REF                                    = 1872, // WebAssemblyInstrFormats.td:59
    THROW_REF_S                                  = 1873, // WebAssemblyInstrFormats.td:61
    THROW_S                                      = 1874, // WebAssemblyInstrFormats.td:61
    TRUNC_F16x8                                  = 1875, // WebAssemblyInstrFormats.td:59
    TRUNC_F16x8_S                                = 1876, // WebAssemblyInstrFormats.td:61
    TRUNC_F32                                    = 1877, // WebAssemblyInstrFormats.td:59
    TRUNC_F32_S                                  = 1878, // WebAssemblyInstrFormats.td:61
    TRUNC_F32x4                                  = 1879, // WebAssemblyInstrFormats.td:59
    TRUNC_F32x4_S                                = 1880, // WebAssemblyInstrFormats.td:61
    TRUNC_F64                                    = 1881, // WebAssemblyInstrFormats.td:59
    TRUNC_F64_S                                  = 1882, // WebAssemblyInstrFormats.td:61
    TRUNC_F64x2                                  = 1883, // WebAssemblyInstrFormats.td:59
    TRUNC_F64x2_S                                = 1884, // WebAssemblyInstrFormats.td:61
    TRY                                          = 1885, // WebAssemblyInstrFormats.td:59
    TRY_S                                        = 1886, // WebAssemblyInstrFormats.td:61
    TRY_TABLE                                    = 1887, // WebAssemblyInstrFormats.td:59
    TRY_TABLE_S                                  = 1888, // WebAssemblyInstrFormats.td:61
    UNREACHABLE                                  = 1889, // WebAssemblyInstrFormats.td:59
    UNREACHABLE_S                                = 1890, // WebAssemblyInstrFormats.td:61
    XOR                                          = 1891, // WebAssemblyInstrFormats.td:59
    XOR_I32                                      = 1892, // WebAssemblyInstrFormats.td:59
    XOR_I32_S                                    = 1893, // WebAssemblyInstrFormats.td:61
    XOR_I64                                      = 1894, // WebAssemblyInstrFormats.td:59
    XOR_I64_S                                    = 1895, // WebAssemblyInstrFormats.td:61
    XOR_S                                        = 1896, // WebAssemblyInstrFormats.td:61
    anonymous_14027MEMORY_GROW_A32               = 1897, // WebAssemblyInstrFormats.td:59
    anonymous_14027MEMORY_GROW_A32_S             = 1898, // WebAssemblyInstrFormats.td:61
    anonymous_14027MEMORY_SIZE_A32               = 1899, // WebAssemblyInstrFormats.td:59
    anonymous_14027MEMORY_SIZE_A32_S             = 1900, // WebAssemblyInstrFormats.td:61
    anonymous_14028MEMORY_GROW_A64               = 1901, // WebAssemblyInstrFormats.td:59
    anonymous_14028MEMORY_GROW_A64_S             = 1902, // WebAssemblyInstrFormats.td:61
    anonymous_14028MEMORY_SIZE_A64               = 1903, // WebAssemblyInstrFormats.td:59
    anonymous_14028MEMORY_SIZE_A64_S             = 1904, // WebAssemblyInstrFormats.td:61
    convert_low_s_F64x2                          = 1905, // WebAssemblyInstrFormats.td:59
    convert_low_s_F64x2_S                        = 1906, // WebAssemblyInstrFormats.td:61
    convert_low_u_F64x2                          = 1907, // WebAssemblyInstrFormats.td:59
    convert_low_u_F64x2_S                        = 1908, // WebAssemblyInstrFormats.td:61
    demote_zero_F16x8                            = 1909, // WebAssemblyInstrFormats.td:59
    demote_zero_F16x8_S                          = 1910, // WebAssemblyInstrFormats.td:61
    demote_zero_F32x4                            = 1911, // WebAssemblyInstrFormats.td:59
    demote_zero_F32x4_S                          = 1912, // WebAssemblyInstrFormats.td:61
    extadd_pairwise_s_I16x8                      = 1913, // WebAssemblyInstrFormats.td:59
    extadd_pairwise_s_I16x8_S                    = 1914, // WebAssemblyInstrFormats.td:61
    extadd_pairwise_s_I32x4                      = 1915, // WebAssemblyInstrFormats.td:59
    extadd_pairwise_s_I32x4_S                    = 1916, // WebAssemblyInstrFormats.td:61
    extadd_pairwise_u_I16x8                      = 1917, // WebAssemblyInstrFormats.td:59
    extadd_pairwise_u_I16x8_S                    = 1918, // WebAssemblyInstrFormats.td:61
    extadd_pairwise_u_I32x4                      = 1919, // WebAssemblyInstrFormats.td:59
    extadd_pairwise_u_I32x4_S                    = 1920, // WebAssemblyInstrFormats.td:61
    extend_high_s_I16x8                          = 1921, // WebAssemblyInstrFormats.td:59
    extend_high_s_I16x8_S                        = 1922, // WebAssemblyInstrFormats.td:61
    extend_high_s_I32x4                          = 1923, // WebAssemblyInstrFormats.td:59
    extend_high_s_I32x4_S                        = 1924, // WebAssemblyInstrFormats.td:61
    extend_high_s_I64x2                          = 1925, // WebAssemblyInstrFormats.td:59
    extend_high_s_I64x2_S                        = 1926, // WebAssemblyInstrFormats.td:61
    extend_high_u_I16x8                          = 1927, // WebAssemblyInstrFormats.td:59
    extend_high_u_I16x8_S                        = 1928, // WebAssemblyInstrFormats.td:61
    extend_high_u_I32x4                          = 1929, // WebAssemblyInstrFormats.td:59
    extend_high_u_I32x4_S                        = 1930, // WebAssemblyInstrFormats.td:61
    extend_high_u_I64x2                          = 1931, // WebAssemblyInstrFormats.td:59
    extend_high_u_I64x2_S                        = 1932, // WebAssemblyInstrFormats.td:61
    extend_low_s_I16x8                           = 1933, // WebAssemblyInstrFormats.td:59
    extend_low_s_I16x8_S                         = 1934, // WebAssemblyInstrFormats.td:61
    extend_low_s_I32x4                           = 1935, // WebAssemblyInstrFormats.td:59
    extend_low_s_I32x4_S                         = 1936, // WebAssemblyInstrFormats.td:61
    extend_low_s_I64x2                           = 1937, // WebAssemblyInstrFormats.td:59
    extend_low_s_I64x2_S                         = 1938, // WebAssemblyInstrFormats.td:61
    extend_low_u_I16x8                           = 1939, // WebAssemblyInstrFormats.td:59
    extend_low_u_I16x8_S                         = 1940, // WebAssemblyInstrFormats.td:61
    extend_low_u_I32x4                           = 1941, // WebAssemblyInstrFormats.td:59
    extend_low_u_I32x4_S                         = 1942, // WebAssemblyInstrFormats.td:61
    extend_low_u_I64x2                           = 1943, // WebAssemblyInstrFormats.td:59
    extend_low_u_I64x2_S                         = 1944, // WebAssemblyInstrFormats.td:61
    fp_to_sint_I16x8                             = 1945, // WebAssemblyInstrFormats.td:59
    fp_to_sint_I16x8_S                           = 1946, // WebAssemblyInstrFormats.td:61
    fp_to_sint_I32x4                             = 1947, // WebAssemblyInstrFormats.td:59
    fp_to_sint_I32x4_S                           = 1948, // WebAssemblyInstrFormats.td:61
    fp_to_uint_I16x8                             = 1949, // WebAssemblyInstrFormats.td:59
    fp_to_uint_I16x8_S                           = 1950, // WebAssemblyInstrFormats.td:61
    fp_to_uint_I32x4                             = 1951, // WebAssemblyInstrFormats.td:59
    fp_to_uint_I32x4_S                           = 1952, // WebAssemblyInstrFormats.td:61
    int_wasm_relaxed_trunc_signed_I32x4          = 1953, // WebAssemblyInstrFormats.td:59
    int_wasm_relaxed_trunc_signed_I32x4_S        = 1954, // WebAssemblyInstrFormats.td:61
    int_wasm_relaxed_trunc_signed_zero_I32x4     = 1955, // WebAssemblyInstrFormats.td:59
    int_wasm_relaxed_trunc_signed_zero_I32x4_S   = 1956, // WebAssemblyInstrFormats.td:61
    int_wasm_relaxed_trunc_unsigned_I32x4        = 1957, // WebAssemblyInstrFormats.td:59
    int_wasm_relaxed_trunc_unsigned_I32x4_S      = 1958, // WebAssemblyInstrFormats.td:61
    int_wasm_relaxed_trunc_unsigned_zero_I32x4   = 1959, // WebAssemblyInstrFormats.td:59
    int_wasm_relaxed_trunc_unsigned_zero_I32x4_S = 1960, // WebAssemblyInstrFormats.td:61
    promote_low_F32x4                            = 1961, // WebAssemblyInstrFormats.td:59
    promote_low_F32x4_S                          = 1962, // WebAssemblyInstrFormats.td:61
    promote_low_F64x2                            = 1963, // WebAssemblyInstrFormats.td:59
    promote_low_F64x2_S                          = 1964, // WebAssemblyInstrFormats.td:61
    sint_to_fp_F16x8                             = 1965, // WebAssemblyInstrFormats.td:59
    sint_to_fp_F16x8_S                           = 1966, // WebAssemblyInstrFormats.td:61
    sint_to_fp_F32x4                             = 1967, // WebAssemblyInstrFormats.td:59
    sint_to_fp_F32x4_S                           = 1968, // WebAssemblyInstrFormats.td:61
    trunc_sat_zero_s_I32x4                       = 1969, // WebAssemblyInstrFormats.td:59
    trunc_sat_zero_s_I32x4_S                     = 1970, // WebAssemblyInstrFormats.td:61
    trunc_sat_zero_u_I32x4                       = 1971, // WebAssemblyInstrFormats.td:59
    trunc_sat_zero_u_I32x4_S                     = 1972, // WebAssemblyInstrFormats.td:61
    uint_to_fp_F16x8                             = 1973, // WebAssemblyInstrFormats.td:59
    uint_to_fp_F16x8_S                           = 1974, // WebAssemblyInstrFormats.td:61
    uint_to_fp_F32x4                             = 1975, // WebAssemblyInstrFormats.td:59
    uint_to_fp_F32x4_S                           = 1976, // WebAssemblyInstrFormats.td:61
    INSTRUCTION_LIST_END = 1977
  };
  enum RegClassByHwModeUses : uint16_t {
    wasm_ptr_rc,
  };

} // namespace llvm_ks::WebAssembly

#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM

namespace llvm_ks::WebAssembly::Sched {

  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };

} // namespace llvm_ks::WebAssembly::Sched

#endif // GET_INSTRINFO_SCHED_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

namespace llvm_ks {

struct WebAssemblyInstrTable {
  MCInstrDesc Insts[1977];
  static_assert(alignof(MCInstrDesc) >= alignof(MCPhysReg), "Unwanted padding between Insts and ImplicitOps");
  MCPhysReg ImplicitOps[10];
  char Padding[sizeof(MCOperandInfo) - sizeof ImplicitOps % sizeof(MCOperandInfo)];
  static_assert(alignof(MCInstrDesc) >= alignof(MCOperandInfo), "Unwanted padding between Insts and OperandInfo");
  MCOperandInfo OperandInfo[890];
};
} // namespace llvm_ks

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

namespace llvm_ks {

static_assert((sizeof WebAssemblyInstrTable::ImplicitOps + sizeof WebAssemblyInstrTable::Padding) % sizeof(MCOperandInfo) == 0);
static constexpr unsigned WebAssemblyOpInfoBase = (sizeof WebAssemblyInstrTable::ImplicitOps + sizeof WebAssemblyInstrTable::Padding) / sizeof(MCOperandInfo);

extern const WebAssemblyInstrTable WebAssemblyDescs = {
  {
    { 1976,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // uint_to_fp_F32x4_S
    { 1975,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // uint_to_fp_F32x4
    { 1974,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // uint_to_fp_F16x8_S
    { 1973,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // uint_to_fp_F16x8
    { 1972,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // trunc_sat_zero_u_I32x4_S
    { 1971,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // trunc_sat_zero_u_I32x4
    { 1970,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // trunc_sat_zero_s_I32x4_S
    { 1969,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // trunc_sat_zero_s_I32x4
    { 1968,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // sint_to_fp_F32x4_S
    { 1967,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // sint_to_fp_F32x4
    { 1966,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // sint_to_fp_F16x8_S
    { 1965,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // sint_to_fp_F16x8
    { 1964,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // promote_low_F64x2_S
    { 1963,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // promote_low_F64x2
    { 1962,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // promote_low_F32x4_S
    { 1961,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // promote_low_F32x4
    { 1960,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // int_wasm_relaxed_trunc_unsigned_zero_I32x4_S
    { 1959,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // int_wasm_relaxed_trunc_unsigned_zero_I32x4
    { 1958,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // int_wasm_relaxed_trunc_unsigned_I32x4_S
    { 1957,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // int_wasm_relaxed_trunc_unsigned_I32x4
    { 1956,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // int_wasm_relaxed_trunc_signed_zero_I32x4_S
    { 1955,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // int_wasm_relaxed_trunc_signed_zero_I32x4
    { 1954,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // int_wasm_relaxed_trunc_signed_I32x4_S
    { 1953,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // int_wasm_relaxed_trunc_signed_I32x4
    { 1952,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // fp_to_uint_I32x4_S
    { 1951,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // fp_to_uint_I32x4
    { 1950,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // fp_to_uint_I16x8_S
    { 1949,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // fp_to_uint_I16x8
    { 1948,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // fp_to_sint_I32x4_S
    { 1947,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // fp_to_sint_I32x4
    { 1946,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // fp_to_sint_I16x8_S
    { 1945,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // fp_to_sint_I16x8
    { 1944,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_u_I64x2_S
    { 1943,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_u_I64x2
    { 1942,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_u_I32x4_S
    { 1941,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_u_I32x4
    { 1940,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_u_I16x8_S
    { 1939,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_u_I16x8
    { 1938,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_s_I64x2_S
    { 1937,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_s_I64x2
    { 1936,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_s_I32x4_S
    { 1935,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_s_I32x4
    { 1934,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_s_I16x8_S
    { 1933,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_low_s_I16x8
    { 1932,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_u_I64x2_S
    { 1931,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_u_I64x2
    { 1930,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_u_I32x4_S
    { 1929,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_u_I32x4
    { 1928,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_u_I16x8_S
    { 1927,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_u_I16x8
    { 1926,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_s_I64x2_S
    { 1925,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_s_I64x2
    { 1924,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_s_I32x4_S
    { 1923,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_s_I32x4
    { 1922,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_s_I16x8_S
    { 1921,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extend_high_s_I16x8
    { 1920,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extadd_pairwise_u_I32x4_S
    { 1919,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extadd_pairwise_u_I32x4
    { 1918,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extadd_pairwise_u_I16x8_S
    { 1917,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extadd_pairwise_u_I16x8
    { 1916,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extadd_pairwise_s_I32x4_S
    { 1915,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extadd_pairwise_s_I32x4
    { 1914,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extadd_pairwise_s_I16x8_S
    { 1913,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // extadd_pairwise_s_I16x8
    { 1912,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // demote_zero_F32x4_S
    { 1911,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // demote_zero_F32x4
    { 1910,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // demote_zero_F16x8_S
    { 1909,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // demote_zero_F16x8
    { 1908,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // convert_low_u_F64x2_S
    { 1907,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // convert_low_u_F64x2
    { 1906,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // convert_low_s_F64x2_S
    { 1905,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // convert_low_s_F64x2
    { 1904,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14028MEMORY_SIZE_A64_S
    { 1903,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 190,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14028MEMORY_SIZE_A64
    { 1902,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14028MEMORY_GROW_A64_S
    { 1901,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 887,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14028MEMORY_GROW_A64
    { 1900,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14027MEMORY_SIZE_A32_S
    { 1899,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 188,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14027MEMORY_SIZE_A32
    { 1898,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14027MEMORY_GROW_A32_S
    { 1897,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 884,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14027MEMORY_GROW_A32
    { 1896,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR_S
    { 1895,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR_I64_S
    { 1894,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR_I64
    { 1893,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR_I32_S
    { 1892,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR_I32
    { 1891,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // XOR
    { 1890,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Trap)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UNREACHABLE_S
    { 1889,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Trap)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // UNREACHABLE
    { 1888,	2,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 882,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRY_TABLE_S
    { 1887,	1,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 297,	8,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRY_TABLE
    { 1886,	1,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 297,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRY_S
    { 1885,	1,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 297,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRY
    { 1884,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_F64x2_S
    { 1883,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_F64x2
    { 1882,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_F64_S
    { 1881,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 159,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_F64
    { 1880,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_F32x4_S
    { 1879,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_F32x4
    { 1878,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_F32_S
    { 1877,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 157,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_F32
    { 1876,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_F16x8_S
    { 1875,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TRUNC_F16x8
    { 1874,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 308,	3,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // THROW_S
    { 1873,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // THROW_REF_S
    { 1872,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 309,	3,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // THROW_REF
    { 1871,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 308,	3,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // THROW
    { 1870,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_V128_S
    { 1869,	3,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_V128
    { 1868,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_I64_S
    { 1867,	3,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_I64
    { 1866,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_I32_S
    { 1865,	3,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_I32
    { 1864,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_FUNCREF_S
    { 1863,	3,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 879,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_FUNCREF
    { 1862,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_F64_S
    { 1861,	3,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 167,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_F64
    { 1860,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_F32_S
    { 1859,	3,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 164,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_F32
    { 1858,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_EXTERNREF_S
    { 1857,	3,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 876,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_EXTERNREF
    { 1856,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_EXNREF_S
    { 1855,	3,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 873,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TEE_EXNREF
    { 1854,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_SIZE_S
    { 1853,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 871,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_SIZE
    { 1852,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_SET_FUNCREF_S
    { 1851,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 868,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_SET_FUNCREF
    { 1850,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_SET_EXTERNREF_S
    { 1849,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 865,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_SET_EXTERNREF
    { 1848,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_SET_EXNREF_S
    { 1847,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 862,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_SET_EXNREF
    { 1846,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GROW_FUNCREF_S
    { 1845,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 858,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GROW_FUNCREF
    { 1844,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GROW_EXTERNREF_S
    { 1843,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 854,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GROW_EXTERNREF
    { 1842,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GROW_EXNREF_S
    { 1841,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 850,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GROW_EXNREF
    { 1840,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GET_FUNCREF_S
    { 1839,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 847,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GET_FUNCREF
    { 1838,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GET_EXTERNREF_S
    { 1837,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 844,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GET_EXTERNREF
    { 1836,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GET_EXNREF_S
    { 1835,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 841,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_GET_EXNREF
    { 1834,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_FILL_FUNCREF_S
    { 1833,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 837,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_FILL_FUNCREF
    { 1832,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_FILL_EXTERNREF_S
    { 1831,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 833,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_FILL_EXTERNREF
    { 1830,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 832,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_FILL_EXNREF_S
    { 1829,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 828,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_FILL_EXNREF
    { 1828,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 826,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_COPY_S
    { 1827,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 821,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // TABLE_COPY
    { 1826,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SWIZZLE_S
    { 1825,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SWIZZLE
    { 1824,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_SAT_U_I8x16_S
    { 1823,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_SAT_U_I8x16
    { 1822,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_SAT_U_I16x8_S
    { 1821,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_SAT_U_I16x8
    { 1820,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_SAT_S_I8x16_S
    { 1819,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_SAT_S_I8x16
    { 1818,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_SAT_S_I16x8_S
    { 1817,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_SAT_S_I16x8
    { 1816,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I8x16_S
    { 1815,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I8x16
    { 1814,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I64x2_S
    { 1813,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I64x2
    { 1812,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I64_S
    { 1811,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I64
    { 1810,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I32x4_S
    { 1809,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I32x4
    { 1808,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I32_S
    { 1807,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I32
    { 1806,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I16x8_S
    { 1805,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_I16x8
    { 1804,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_F64x2_S
    { 1803,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_F64x2
    { 1802,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_F64_S
    { 1801,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 167,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_F64
    { 1800,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_F32x4_S
    { 1799,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_F32x4
    { 1798,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_F32_S
    { 1797,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 164,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_F32
    { 1796,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_F16x8_S
    { 1795,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUB_F16x8
    { 1794,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_V128_A64_S
    { 1793,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 817,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_V128_A64
    { 1792,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_V128_A32_S
    { 1791,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 813,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_V128_A32
    { 1790,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 565,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I8x16_A64_S
    { 1789,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 808,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I8x16_A64
    { 1788,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 556,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I8x16_A32_S
    { 1787,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 803,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I8x16_A32
    { 1786,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 565,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I64x2_A64_S
    { 1785,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 808,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I64x2_A64
    { 1784,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 556,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I64x2_A32_S
    { 1783,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 803,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I64x2_A32
    { 1782,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 565,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I32x4_A64_S
    { 1781,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 808,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I32x4_A64
    { 1780,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 556,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I32x4_A32_S
    { 1779,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 803,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I32x4_A32
    { 1778,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 565,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I16x8_A64_S
    { 1777,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 808,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I16x8_A64
    { 1776,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 556,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I16x8_A32_S
    { 1775,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 803,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_LANE_I16x8_A32
    { 1774,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_I64_A64_S
    { 1773,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 783,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_I64_A64
    { 1772,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_I64_A32_S
    { 1771,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 779,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_I64_A32
    { 1770,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_I32_A64_S
    { 1769,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 775,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_I32_A64
    { 1768,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_I32_A32_S
    { 1767,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 771,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_I32_A32
    { 1766,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F64_A64_S
    { 1765,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 799,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F64_A64
    { 1764,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F64_A32_S
    { 1763,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 795,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F64_A32
    { 1762,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F32_A64_S
    { 1761,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 791,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F32_A64
    { 1760,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F32_A32_S
    { 1759,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 787,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F32_A32
    { 1758,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F16_F32_A64_S
    { 1757,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 791,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F16_F32_A64
    { 1756,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F16_F32_A32_S
    { 1755,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 787,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE_F16_F32_A32
    { 1754,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE8_I64_A64_S
    { 1753,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 783,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE8_I64_A64
    { 1752,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE8_I64_A32_S
    { 1751,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 779,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE8_I64_A32
    { 1750,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE8_I32_A64_S
    { 1749,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 775,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE8_I32_A64
    { 1748,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE8_I32_A32_S
    { 1747,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 771,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE8_I32_A32
    { 1746,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE32_I64_A64_S
    { 1745,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 783,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE32_I64_A64
    { 1744,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE32_I64_A32_S
    { 1743,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 779,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE32_I64_A32
    { 1742,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE16_I64_A64_S
    { 1741,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 783,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE16_I64_A64
    { 1740,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE16_I64_A32_S
    { 1739,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 779,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE16_I64_A32
    { 1738,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE16_I32_A64_S
    { 1737,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 775,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE16_I32_A64
    { 1736,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE16_I32_A32_S
    { 1735,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 771,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STORE16_I32_A32
    { 1734,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT_F64x2_S
    { 1733,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT_F64x2
    { 1732,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT_F64_S
    { 1731,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 159,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT_F64
    { 1730,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT_F32x4_S
    { 1729,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT_F32x4
    { 1728,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT_F32_S
    { 1727,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 157,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT_F32
    { 1726,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT_F16x8_S
    { 1725,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SQRT_F16x8
    { 1724,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_I8x16_S
    { 1723,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 767,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_I8x16
    { 1722,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_I64x2_S
    { 1721,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 769,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_I64x2
    { 1720,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_I32x4_S
    { 1719,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 767,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_I32x4
    { 1718,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_I16x8_S
    { 1717,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 767,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_I16x8
    { 1716,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_F64x2_S
    { 1715,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 765,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_F64x2
    { 1714,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_F32x4_S
    { 1713,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 763,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_F32x4
    { 1712,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_F16x8_S
    { 1711,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 763,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SPLAT_F16x8
    { 1710,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SIMD_RELAXED_FMIN_F64x2_S
    { 1709,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SIMD_RELAXED_FMIN_F64x2
    { 1708,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SIMD_RELAXED_FMIN_F32x4_S
    { 1707,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SIMD_RELAXED_FMIN_F32x4
    { 1706,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SIMD_RELAXED_FMAX_F64x2_S
    { 1705,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SIMD_RELAXED_FMAX_F64x2
    { 1704,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SIMD_RELAXED_FMAX_F32x4_S
    { 1703,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SIMD_RELAXED_FMAX_F32x4
    { 1702,	16,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 388,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHUFFLE_S
    { 1701,	19,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 744,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHUFFLE
    { 1700,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I8x16_S
    { 1699,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I8x16
    { 1698,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I64x2_S
    { 1697,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I64x2
    { 1696,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I64_S
    { 1695,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I64
    { 1694,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I32x4_S
    { 1693,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I32x4
    { 1692,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I32_S
    { 1691,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I32
    { 1690,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I16x8_S
    { 1689,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_U_I16x8
    { 1688,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I8x16_S
    { 1687,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I8x16
    { 1686,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I64x2_S
    { 1685,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I64x2
    { 1684,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I64_S
    { 1683,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I64
    { 1682,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I32x4_S
    { 1681,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I32x4
    { 1680,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I32_S
    { 1679,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I32
    { 1678,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I16x8_S
    { 1677,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHR_S_I16x8
    { 1676,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I8x16_S
    { 1675,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I8x16
    { 1674,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I64x2_S
    { 1673,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I64x2
    { 1672,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I64_S
    { 1671,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I64
    { 1670,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I32x4_S
    { 1669,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I32x4
    { 1668,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I32_S
    { 1667,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I32
    { 1666,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I16x8_S
    { 1665,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 741,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SHL_I16x8
    { 1664,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_V128_S
    { 1663,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 737,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_V128
    { 1662,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 736,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_T_S
    { 1661,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 736,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_T
    { 1660,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_I64_S
    { 1659,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 732,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_I64
    { 1658,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_I32_S
    { 1657,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 728,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_I32
    { 1656,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_FUNCREF_S
    { 1655,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 724,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_FUNCREF
    { 1654,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_F64_S
    { 1653,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 720,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_F64
    { 1652,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_F32_S
    { 1651,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 716,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_F32
    { 1650,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_EXTERNREF_S
    { 1649,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 712,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_EXTERNREF
    { 1648,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_EXNREF_S
    { 1647,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 708,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SELECT_EXNREF
    { 1646,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROTR_I64_S
    { 1645,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROTR_I64
    { 1644,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROTR_I32_S
    { 1643,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROTR_I32
    { 1642,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROTL_I64_S
    { 1641,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROTL_I64
    { 1640,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROTL_I32_S
    { 1639,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ROTL_I32
    { 1638,	1,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 151,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET_CALL_S
    { 1637,	1,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 307,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET_CALL_REF_S
    { 1636,	2,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 305,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET_CALL_REF
    { 1635,	2,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 303,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET_CALL_INDIRECT_S
    { 1634,	2,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 303,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET_CALL_INDIRECT
    { 1633,	1,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 151,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RET_CALL
    { 1632,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RETURN_S
    { 1631,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RETURN
    { 1630,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 154,	3,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RETHROW_S
    { 1629,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 154,	3,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RETHROW
    { 1628,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_I8x16_S
    { 1627,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 700,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_I8x16
    { 1626,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_I64x2_S
    { 1625,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 704,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_I64x2
    { 1624,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_I32x4_S
    { 1623,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 700,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_I32x4
    { 1622,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_I16x8_S
    { 1621,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 700,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_I16x8
    { 1620,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_F64x2_S
    { 1619,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 696,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_F64x2
    { 1618,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_F32x4_S
    { 1617,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 692,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_F32x4
    { 1616,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_F16x8_S
    { 1615,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 692,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REPLACE_LANE_F16x8
    { 1614,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REM_U_I64_S
    { 1613,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REM_U_I64
    { 1612,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REM_U_I32_S
    { 1611,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REM_U_I32
    { 1610,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REM_S_I64_S
    { 1609,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REM_S_I64
    { 1608,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REM_S_I32_S
    { 1607,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REM_S_I32
    { 1606,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELAXED_SWIZZLE_S
    { 1605,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELAXED_SWIZZLE
    { 1604,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELAXED_Q15MULR_S_I16x8_S
    { 1603,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELAXED_Q15MULR_S_I16x8
    { 1602,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELAXED_DOT_S
    { 1601,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELAXED_DOT_BFLOAT_S
    { 1600,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELAXED_DOT_BFLOAT
    { 1599,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELAXED_DOT_ADD_S
    { 1598,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELAXED_DOT_ADD
    { 1597,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELAXED_DOT
    { 1596,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 307,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_TEST_FUNCREF_S
    { 1595,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 689,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_TEST_FUNCREF
    { 1594,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_NULL_FUNCREF_S
    { 1593,	1,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 413,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_NULL_FUNCREF
    { 1592,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_NULL_EXTERNREF_S
    { 1591,	1,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 410,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_NULL_EXTERNREF
    { 1590,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_NULL_EXNREF_S
    { 1589,	1,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 309,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_NULL_EXNREF
    { 1588,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_IS_NULL_FUNCREF_S
    { 1587,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 687,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_IS_NULL_FUNCREF
    { 1586,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_IS_NULL_EXTERNREF_S
    { 1585,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 685,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_IS_NULL_EXTERNREF
    { 1584,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_IS_NULL_EXNREF_S
    { 1583,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 683,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_IS_NULL_EXNREF
    { 1582,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 151,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_FUNC_S
    { 1581,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 681,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_FUNC
    { 1580,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 307,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_CAST_FUNCREF_S
    { 1579,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 678,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REF_CAST_FUNCREF
    { 1578,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Q15MULR_SAT_S_I16x8_S
    { 1577,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // Q15MULR_SAT_S_I16x8
    { 1576,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POPCNT_I8x16_S
    { 1575,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POPCNT_I8x16
    { 1574,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POPCNT_I64_S
    { 1573,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 312,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POPCNT_I64
    { 1572,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POPCNT_I32_S
    { 1571,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 310,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // POPCNT_I32
    { 1570,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMIN_F64x2_S
    { 1569,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMIN_F64x2
    { 1568,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMIN_F32x4_S
    { 1567,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMIN_F32x4
    { 1566,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMIN_F16x8_S
    { 1565,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMIN_F16x8
    { 1564,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMAX_F64x2_S
    { 1563,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMAX_F64x2
    { 1562,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMAX_F32x4_S
    { 1561,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMAX_F32x4
    { 1560,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMAX_F16x8_S
    { 1559,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PMAX_F16x8
    { 1558,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR_S
    { 1557,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR_I64_S
    { 1556,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR_I64
    { 1555,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR_I32_S
    { 1554,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR_I32
    { 1553,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // OR
    { 1552,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOT_S
    { 1551,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOT
    { 1550,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOP_S
    { 1549,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NOP
    { 1548,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NMADD_F64x2_S
    { 1547,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NMADD_F64x2
    { 1546,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NMADD_F32x4_S
    { 1545,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NMADD_F32x4
    { 1544,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NMADD_F16x8_S
    { 1543,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NMADD_F16x8
    { 1542,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I8x16_S
    { 1541,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I8x16
    { 1540,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I64x2_S
    { 1539,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I64x2
    { 1538,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I64_S
    { 1537,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 423,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I64
    { 1536,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I32x4_S
    { 1535,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I32x4
    { 1534,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I32_S
    { 1533,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I32
    { 1532,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I16x8_S
    { 1531,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_I16x8
    { 1530,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_F64x2_S
    { 1529,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_F64x2
    { 1528,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_F64_S
    { 1527,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 420,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_F64
    { 1526,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_F32x4_S
    { 1525,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_F32x4
    { 1524,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_F32_S
    { 1523,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 417,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_F32
    { 1522,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_F16x8_S
    { 1521,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NE_F16x8
    { 1520,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_I8x16_S
    { 1519,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_I8x16
    { 1518,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_I64x2_S
    { 1517,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_I64x2
    { 1516,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_I32x4_S
    { 1515,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_I32x4
    { 1514,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_I16x8_S
    { 1513,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_I16x8
    { 1512,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_F64x2_S
    { 1511,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_F64x2
    { 1510,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_F64_S
    { 1509,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 159,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_F64
    { 1508,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_F32x4_S
    { 1507,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_F32x4
    { 1506,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_F32_S
    { 1505,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 157,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_F32
    { 1504,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_F16x8_S
    { 1503,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEG_F16x8
    { 1502,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEAREST_F64x2_S
    { 1501,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEAREST_F64x2
    { 1500,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEAREST_F64_S
    { 1499,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 159,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEAREST_F64
    { 1498,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEAREST_F32x4_S
    { 1497,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEAREST_F32x4
    { 1496,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEAREST_F32_S
    { 1495,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 157,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEAREST_F32
    { 1494,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEAREST_F16x8_S
    { 1493,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NEAREST_F16x8
    { 1492,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NARROW_U_I8x16_S
    { 1491,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NARROW_U_I8x16
    { 1490,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NARROW_U_I16x8_S
    { 1489,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NARROW_U_I16x8
    { 1488,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NARROW_S_I8x16_S
    { 1487,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NARROW_S_I8x16
    { 1486,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NARROW_S_I16x8_S
    { 1485,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // NARROW_S_I16x8
    { 1484,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_I64x2_S
    { 1483,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_I64x2
    { 1482,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_I64_S
    { 1481,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_I64
    { 1480,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_I32x4_S
    { 1479,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_I32x4
    { 1478,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_I32_S
    { 1477,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_I32
    { 1476,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_I16x8_S
    { 1475,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_I16x8
    { 1474,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_F64x2_S
    { 1473,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_F64x2
    { 1472,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_F64_S
    { 1471,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 167,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_F64
    { 1470,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_F32x4_S
    { 1469,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_F32x4
    { 1468,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_F32_S
    { 1467,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 164,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_F32
    { 1466,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_F16x8_S
    { 1465,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MUL_F16x8
    { 1464,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_U_I8x16_S
    { 1463,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_U_I8x16
    { 1462,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_U_I32x4_S
    { 1461,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_U_I32x4
    { 1460,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_U_I16x8_S
    { 1459,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_U_I16x8
    { 1458,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_S_I8x16_S
    { 1457,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_S_I8x16
    { 1456,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_S_I32x4_S
    { 1455,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_S_I32x4
    { 1454,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_S_I16x8_S
    { 1453,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_S_I16x8
    { 1452,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_F64x2_S
    { 1451,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_F64x2
    { 1450,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_F64_S
    { 1449,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 167,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_F64
    { 1448,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_F32x4_S
    { 1447,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_F32x4
    { 1446,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_F32_S
    { 1445,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 164,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_F32
    { 1444,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_F16x8_S
    { 1443,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MIN_F16x8
    { 1442,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 322,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMSET_A64_S
    { 1441,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 669,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMSET_A64
    { 1440,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 322,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMSET_A32_S
    { 1439,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 665,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMSET_A32
    { 1438,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 630,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_INIT_A64_S
    { 1437,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 673,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_INIT_A64
    { 1436,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 630,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_INIT_A32_S
    { 1435,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 625,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_INIT_A32
    { 1434,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 322,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_FILL_A64_S
    { 1433,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 669,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_FILL_A64
    { 1432,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 322,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_FILL_A32_S
    { 1431,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 665,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_FILL_A32
    { 1430,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 630,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_COPY_A64_S
    { 1429,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 632,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_COPY_A64
    { 1428,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 630,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_COPY_A32_S
    { 1427,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 625,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_COPY_A32
    { 1426,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_WAIT64_A64_S
    { 1425,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 658,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_WAIT64_A64
    { 1424,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_WAIT64_A32_S
    { 1423,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 651,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_WAIT64_A32
    { 1422,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_WAIT32_A64_S
    { 1421,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 644,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_WAIT32_A64
    { 1420,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_WAIT32_A32_S
    { 1419,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 637,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_WAIT32_A32
    { 1418,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_NOTIFY_A64_S
    { 1417,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_NOTIFY_A64
    { 1416,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_NOTIFY_A32_S
    { 1415,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMORY_ATOMIC_NOTIFY_A32
    { 1414,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 630,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMCPY_A64_S
    { 1413,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 632,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMCPY_A64
    { 1412,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 630,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMCPY_A32_S
    { 1411,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 625,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMCPY_A32
    { 1410,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_U_I8x16_S
    { 1409,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_U_I8x16
    { 1408,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_U_I32x4_S
    { 1407,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_U_I32x4
    { 1406,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_U_I16x8_S
    { 1405,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_U_I16x8
    { 1404,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_S_I8x16_S
    { 1403,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_S_I8x16
    { 1402,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_S_I32x4_S
    { 1401,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_S_I32x4
    { 1400,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_S_I16x8_S
    { 1399,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_S_I16x8
    { 1398,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_F64x2_S
    { 1397,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_F64x2
    { 1396,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_F64_S
    { 1395,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 167,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_F64
    { 1394,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_F32x4_S
    { 1393,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_F32x4
    { 1392,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_F32_S
    { 1391,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 164,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_F32
    { 1390,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_F16x8_S
    { 1389,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MAX_F16x8
    { 1388,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MADD_F64x2_S
    { 1387,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MADD_F64x2
    { 1386,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MADD_F32x4_S
    { 1385,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MADD_F32x4
    { 1384,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MADD_F16x8_S
    { 1383,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MADD_F16x8
    { 1382,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_U_I8x16_S
    { 1381,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_U_I8x16
    { 1380,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_U_I64_S
    { 1379,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 423,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_U_I64
    { 1378,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_U_I32x4_S
    { 1377,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_U_I32x4
    { 1376,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_U_I32_S
    { 1375,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_U_I32
    { 1374,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_U_I16x8_S
    { 1373,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_U_I16x8
    { 1372,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I8x16_S
    { 1371,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I8x16
    { 1370,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I64x2_S
    { 1369,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I64x2
    { 1368,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I64_S
    { 1367,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 423,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I64
    { 1366,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I32x4_S
    { 1365,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I32x4
    { 1364,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I32_S
    { 1363,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I32
    { 1362,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I16x8_S
    { 1361,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_S_I16x8
    { 1360,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_F64x2_S
    { 1359,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_F64x2
    { 1358,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_F64_S
    { 1357,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 420,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_F64
    { 1356,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_F32x4_S
    { 1355,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_F32x4
    { 1354,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_F32_S
    { 1353,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 417,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_F32
    { 1352,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_F16x8_S
    { 1351,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LT_F16x8
    { 1350,	1,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 297,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOOP_S
    { 1349,	1,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 297,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOOP
    { 1348,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_V128_S
    { 1347,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 622,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_V128
    { 1346,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_I64_S
    { 1345,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 619,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_I64
    { 1344,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_I32_S
    { 1343,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 616,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_I32
    { 1342,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_FUNCREF_S
    { 1341,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 613,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_FUNCREF
    { 1340,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_F64_S
    { 1339,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 610,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_F64
    { 1338,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_F32_S
    { 1337,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 607,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_F32
    { 1336,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_EXTERNREF_S
    { 1335,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 604,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_EXTERNREF
    { 1334,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_EXNREF_S
    { 1333,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 601,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_TEE_EXNREF
    { 1332,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_V128_S
    { 1331,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 599,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_V128
    { 1330,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_I64_S
    { 1329,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 597,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_I64
    { 1328,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_I32_S
    { 1327,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 595,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_I32
    { 1326,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_FUNCREF_S
    { 1325,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 593,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_FUNCREF
    { 1324,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_F64_S
    { 1323,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 591,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_F64
    { 1322,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_F32_S
    { 1321,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 589,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_F32
    { 1320,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_EXTERNREF_S
    { 1319,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 587,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_EXTERNREF
    { 1318,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_EXNREF_S
    { 1317,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 585,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_SET_EXNREF
    { 1316,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_V128_S
    { 1315,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 583,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_V128
    { 1314,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_I64_S
    { 1313,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 581,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_I64
    { 1312,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_I32_S
    { 1311,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 579,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_I32
    { 1310,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_FUNCREF_S
    { 1309,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 577,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_FUNCREF
    { 1308,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_F64_S
    { 1307,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 575,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_F64
    { 1306,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_F32_S
    { 1305,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 573,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_F32
    { 1304,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_EXTERNREF_S
    { 1303,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 571,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_EXTERNREF
    { 1302,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 570,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_EXNREF_S
    { 1301,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 568,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_GET_EXNREF
    { 1300,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_ZERO_64_A64_S
    { 1299,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_ZERO_64_A64
    { 1298,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_ZERO_64_A32_S
    { 1297,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_ZERO_64_A32
    { 1296,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_ZERO_32_A64_S
    { 1295,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_ZERO_32_A64
    { 1294,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_ZERO_32_A32_S
    { 1293,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_ZERO_32_A32
    { 1292,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_V128_A64_S
    { 1291,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_V128_A64
    { 1290,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_V128_A32_S
    { 1289,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_V128_A32
    { 1288,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 565,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_8_A64_S
    { 1287,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 559,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_8_A64
    { 1286,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 556,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_8_A32_S
    { 1285,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 550,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_8_A32
    { 1284,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 565,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_64_A64_S
    { 1283,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 559,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_64_A64
    { 1282,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 556,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_64_A32_S
    { 1281,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 550,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_64_A32
    { 1280,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 565,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_32_A64_S
    { 1279,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 559,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_32_A64
    { 1278,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 556,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_32_A32_S
    { 1277,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 550,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_32_A32
    { 1276,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 565,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_16_A64_S
    { 1275,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 559,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_16_A64
    { 1274,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 556,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_16_A32_S
    { 1273,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 550,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_LANE_16_A32
    { 1272,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_I64_A64_S
    { 1271,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 530,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_I64_A64
    { 1270,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_I64_A32_S
    { 1269,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 526,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_I64_A32
    { 1268,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_I32_A64_S
    { 1267,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 522,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_I32_A64
    { 1266,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_I32_A32_S
    { 1265,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 518,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_I32_A32
    { 1264,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F64_A64_S
    { 1263,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 546,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F64_A64
    { 1262,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F64_A32_S
    { 1261,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 542,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F64_A32
    { 1260,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F32_A64_S
    { 1259,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 538,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F32_A64
    { 1258,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F32_A32_S
    { 1257,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 534,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F32_A32
    { 1256,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F16_F32_A64_S
    { 1255,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 538,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F16_F32_A64
    { 1254,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F16_F32_A32_S
    { 1253,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 534,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_F16_F32_A32
    { 1252,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I64x2_A64_S
    { 1251,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I64x2_A64
    { 1250,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I64x2_A32_S
    { 1249,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I64x2_A32
    { 1248,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I32x4_A64_S
    { 1247,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I32x4_A64
    { 1246,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I32x4_A32_S
    { 1245,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I32x4_A32
    { 1244,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I16x8_A64_S
    { 1243,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I16x8_A64
    { 1242,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I16x8_A32_S
    { 1241,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_U_I16x8_A32
    { 1240,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I64x2_A64_S
    { 1239,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I64x2_A64
    { 1238,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I64x2_A32_S
    { 1237,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I64x2_A32
    { 1236,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I32x4_A64_S
    { 1235,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I32x4_A64
    { 1234,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I32x4_A32_S
    { 1233,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I32x4_A32
    { 1232,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I16x8_A64_S
    { 1231,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I16x8_A64
    { 1230,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I16x8_A32_S
    { 1229,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD_EXTEND_S_I16x8_A32
    { 1228,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_U_I64_A64_S
    { 1227,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 530,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_U_I64_A64
    { 1226,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_U_I64_A32_S
    { 1225,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 526,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_U_I64_A32
    { 1224,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_U_I32_A64_S
    { 1223,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 522,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_U_I32_A64
    { 1222,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_U_I32_A32_S
    { 1221,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 518,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_U_I32_A32
    { 1220,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_S_I64_A64_S
    { 1219,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 530,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_S_I64_A64
    { 1218,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_S_I64_A32_S
    { 1217,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 526,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_S_I64_A32
    { 1216,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_S_I32_A64_S
    { 1215,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 522,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_S_I32_A64
    { 1214,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_S_I32_A32_S
    { 1213,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 518,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_S_I32_A32
    { 1212,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_SPLAT_A64_S
    { 1211,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_SPLAT_A64
    { 1210,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_SPLAT_A32_S
    { 1209,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD8_SPLAT_A32
    { 1208,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD64_SPLAT_A64_S
    { 1207,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD64_SPLAT_A64
    { 1206,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD64_SPLAT_A32_S
    { 1205,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD64_SPLAT_A32
    { 1204,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_U_I64_A64_S
    { 1203,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 530,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_U_I64_A64
    { 1202,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_U_I64_A32_S
    { 1201,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 526,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_U_I64_A32
    { 1200,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_S_I64_A64_S
    { 1199,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 530,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_S_I64_A64
    { 1198,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_S_I64_A32_S
    { 1197,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 526,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_S_I64_A32
    { 1196,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_SPLAT_A64_S
    { 1195,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_SPLAT_A64
    { 1194,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_SPLAT_A32_S
    { 1193,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD32_SPLAT_A32
    { 1192,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_U_I64_A64_S
    { 1191,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 530,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_U_I64_A64
    { 1190,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_U_I64_A32_S
    { 1189,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 526,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_U_I64_A32
    { 1188,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_U_I32_A64_S
    { 1187,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 522,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_U_I32_A64
    { 1186,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_U_I32_A32_S
    { 1185,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 518,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_U_I32_A32
    { 1184,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_S_I64_A64_S
    { 1183,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 530,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_S_I64_A64
    { 1182,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_S_I64_A32_S
    { 1181,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 526,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_S_I64_A32
    { 1180,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_S_I32_A64_S
    { 1179,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 522,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_S_I32_A64
    { 1178,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_S_I32_A32_S
    { 1177,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 518,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_S_I32_A32
    { 1176,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 516,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_SPLAT_A64_S
    { 1175,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 512,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_SPLAT_A64
    { 1174,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 510,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_SPLAT_A32_S
    { 1173,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 506,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOAD16_SPLAT_A32
    { 1172,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_U_I8x16_S
    { 1171,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_U_I8x16
    { 1170,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_U_I64_S
    { 1169,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 423,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_U_I64
    { 1168,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_U_I32x4_S
    { 1167,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_U_I32x4
    { 1166,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_U_I32_S
    { 1165,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_U_I32
    { 1164,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_U_I16x8_S
    { 1163,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_U_I16x8
    { 1162,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I8x16_S
    { 1161,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I8x16
    { 1160,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I64x2_S
    { 1159,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I64x2
    { 1158,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I64_S
    { 1157,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 423,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I64
    { 1156,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I32x4_S
    { 1155,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I32x4
    { 1154,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I32_S
    { 1153,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I32
    { 1152,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I16x8_S
    { 1151,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_S_I16x8
    { 1150,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_F64x2_S
    { 1149,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_F64x2
    { 1148,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_F64_S
    { 1147,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 420,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_F64
    { 1146,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_F32x4_S
    { 1145,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_F32x4
    { 1144,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_F32_S
    { 1143,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 417,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_F32
    { 1142,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_F16x8_S
    { 1141,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LE_F16x8
    { 1140,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LANESELECT_I8x16_S
    { 1139,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LANESELECT_I8x16
    { 1138,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LANESELECT_I64x2_S
    { 1137,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LANESELECT_I64x2
    { 1136,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LANESELECT_I32x4_S
    { 1135,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LANESELECT_I32x4
    { 1134,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LANESELECT_I16x8_S
    { 1133,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LANESELECT_I16x8
    { 1132,	1,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 297,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // IF_S
    { 1131,	2,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 504,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // IF
    { 1130,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_U_SAT_F64_S
    { 1129,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 457,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_U_SAT_F64
    { 1128,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_U_SAT_F32_S
    { 1127,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 455,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_U_SAT_F32
    { 1126,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_U_F64_S
    { 1125,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 457,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_U_F64
    { 1124,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_U_F32_S
    { 1123,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 455,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_U_F32
    { 1122,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_S_SAT_F64_S
    { 1121,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 457,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_S_SAT_F64
    { 1120,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_S_SAT_F32_S
    { 1119,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 455,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_S_SAT_F32
    { 1118,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_S_F64_S
    { 1117,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 457,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_S_F64
    { 1116,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_S_F32_S
    { 1115,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 455,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_TRUNC_S_F32
    { 1114,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_SUB128_S
    { 1113,	6,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 492,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_SUB128
    { 1112,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_REINTERPRET_F64_S
    { 1111,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 457,	3,	0|(1ULL<<MCID::Bitcast)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_REINTERPRET_F64
    { 1110,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_MUL_WIDE_U_S
    { 1109,	4,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 500,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_MUL_WIDE_U
    { 1108,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_MUL_WIDE_S_S
    { 1107,	4,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 500,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_MUL_WIDE_S
    { 1106,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_EXTEND_U_I32_S
    { 1105,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 498,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_EXTEND_U_I32
    { 1104,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_EXTEND_S_I32_S
    { 1103,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 498,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_EXTEND_S_I32
    { 1102,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_EXTEND8_S_I64_S
    { 1101,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 312,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_EXTEND8_S_I64
    { 1100,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_EXTEND32_S_I64_S
    { 1099,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 312,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_EXTEND32_S_I64
    { 1098,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_EXTEND16_S_I64_S
    { 1097,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 312,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_EXTEND16_S_I64
    { 1096,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_ADD128_S
    { 1095,	6,	2,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 492,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I64_ADD128
    { 1094,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_WRAP_I64_S
    { 1093,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 415,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_WRAP_I64
    { 1092,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_U_SAT_F64_S
    { 1091,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 453,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_U_SAT_F64
    { 1090,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_U_SAT_F32_S
    { 1089,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 451,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_U_SAT_F32
    { 1088,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_U_F64_S
    { 1087,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 453,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_U_F64
    { 1086,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_U_F32_S
    { 1085,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 451,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_U_F32
    { 1084,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_S_SAT_F64_S
    { 1083,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 453,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_S_SAT_F64
    { 1082,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_S_SAT_F32_S
    { 1081,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 451,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_S_SAT_F32
    { 1080,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_S_F64_S
    { 1079,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 453,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_S_F64
    { 1078,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_S_F32_S
    { 1077,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 451,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_TRUNC_S_F32
    { 1076,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_REINTERPRET_F32_S
    { 1075,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 451,	3,	0|(1ULL<<MCID::Bitcast)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_REINTERPRET_F32
    { 1074,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_EXTEND8_S_I32_S
    { 1073,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 310,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_EXTEND8_S_I32
    { 1072,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_EXTEND16_S_I32_S
    { 1071,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 310,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // I32_EXTEND16_S_I32
    { 1070,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_U_I8x16_S
    { 1069,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_U_I8x16
    { 1068,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_U_I64_S
    { 1067,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 423,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_U_I64
    { 1066,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_U_I32x4_S
    { 1065,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_U_I32x4
    { 1064,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_U_I32_S
    { 1063,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_U_I32
    { 1062,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_U_I16x8_S
    { 1061,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_U_I16x8
    { 1060,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I8x16_S
    { 1059,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I8x16
    { 1058,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I64x2_S
    { 1057,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I64x2
    { 1056,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I64_S
    { 1055,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 423,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I64
    { 1054,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I32x4_S
    { 1053,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I32x4
    { 1052,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I32_S
    { 1051,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I32
    { 1050,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I16x8_S
    { 1049,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_S_I16x8
    { 1048,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_F64x2_S
    { 1047,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_F64x2
    { 1046,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_F64_S
    { 1045,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 420,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_F64
    { 1044,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_F32x4_S
    { 1043,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_F32x4
    { 1042,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_F32_S
    { 1041,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 417,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_F32
    { 1040,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_F16x8_S
    { 1039,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GT_F16x8
    { 1038,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_V128_S
    { 1037,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 490,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_V128
    { 1036,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_I64_S
    { 1035,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 488,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_I64
    { 1034,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_I32_S
    { 1033,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 486,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_I32
    { 1032,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_FUNCREF_S
    { 1031,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 484,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_FUNCREF
    { 1030,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_F64_S
    { 1029,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 482,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_F64
    { 1028,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_F32_S
    { 1027,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 480,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_F32
    { 1026,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_EXTERNREF_S
    { 1025,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 478,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_EXTERNREF
    { 1024,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_EXNREF_S
    { 1023,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 476,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_SET_EXNREF
    { 1022,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_V128_S
    { 1021,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 474,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_V128
    { 1020,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_I64_S
    { 1019,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 472,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_I64
    { 1018,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_I32_S
    { 1017,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 470,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_I32
    { 1016,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_FUNCREF_S
    { 1015,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 468,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_FUNCREF
    { 1014,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_F64_S
    { 1013,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 466,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_F64
    { 1012,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_F32_S
    { 1011,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 464,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_F32
    { 1010,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_EXTERNREF_S
    { 1009,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 462,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_EXTERNREF
    { 1008,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 461,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_EXNREF_S
    { 1007,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 459,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GLOBAL_GET_EXNREF
    { 1006,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_U_I8x16_S
    { 1005,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_U_I8x16
    { 1004,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_U_I64_S
    { 1003,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 423,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_U_I64
    { 1002,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_U_I32x4_S
    { 1001,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_U_I32x4
    { 1000,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_U_I32_S
    { 999,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_U_I32
    { 998,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_U_I16x8_S
    { 997,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_U_I16x8
    { 996,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I8x16_S
    { 995,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I8x16
    { 994,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I64x2_S
    { 993,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I64x2
    { 992,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I64_S
    { 991,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 423,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I64
    { 990,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I32x4_S
    { 989,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I32x4
    { 988,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I32_S
    { 987,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I32
    { 986,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I16x8_S
    { 985,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_S_I16x8
    { 984,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_F64x2_S
    { 983,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_F64x2
    { 982,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_F64_S
    { 981,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 420,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_F64
    { 980,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_F32x4_S
    { 979,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_F32x4
    { 978,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_F32_S
    { 977,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 417,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_F32
    { 976,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_F16x8_S
    { 975,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GE_F16x8
    { 974,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_UINT_I64_F64_S
    { 973,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 457,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_UINT_I64_F64
    { 972,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_UINT_I64_F32_S
    { 971,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 455,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_UINT_I64_F32
    { 970,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_UINT_I32_F64_S
    { 969,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 453,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_UINT_I32_F64
    { 968,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_UINT_I32_F32_S
    { 967,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 451,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_UINT_I32_F32
    { 966,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_SINT_I64_F64_S
    { 965,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 457,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_SINT_I64_F64
    { 964,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_SINT_I64_F32_S
    { 963,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 455,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_SINT_I64_F32
    { 962,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_SINT_I32_F64_S
    { 961,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 453,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_SINT_I32_F64
    { 960,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_SINT_I32_F32_S
    { 959,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 451,	3,	0|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FP_TO_SINT_I32_F32
    { 958,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_F64x2_S
    { 957,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_F64x2
    { 956,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_F64_S
    { 955,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 159,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_F64
    { 954,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_F32x4_S
    { 953,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_F32x4
    { 952,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_F32_S
    { 951,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 157,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_F32
    { 950,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_F16x8_S
    { 949,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FLOOR_F16x8
    { 948,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FALLTHROUGH_RETURN_S
    { 947,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FALLTHROUGH_RETURN
    { 946,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_REINTERPRET_I64_S
    { 945,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 447,	3,	0|(1ULL<<MCID::Bitcast)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_REINTERPRET_I64
    { 944,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_PROMOTE_F32_S
    { 943,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 449,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_PROMOTE_F32
    { 942,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_CONVERT_U_I64_S
    { 941,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 447,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_CONVERT_U_I64
    { 940,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_CONVERT_U_I32_S
    { 939,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 445,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_CONVERT_U_I32
    { 938,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_CONVERT_S_I64_S
    { 937,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 447,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_CONVERT_S_I64
    { 936,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_CONVERT_S_I32_S
    { 935,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 445,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F64_CONVERT_S_I32
    { 934,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_REINTERPRET_I32_S
    { 933,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 439,	3,	0|(1ULL<<MCID::Bitcast)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_REINTERPRET_I32
    { 932,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_DEMOTE_F64_S
    { 931,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 443,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_DEMOTE_F64
    { 930,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_CONVERT_U_I64_S
    { 929,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 441,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_CONVERT_U_I64
    { 928,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_CONVERT_U_I32_S
    { 927,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 439,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_CONVERT_U_I32
    { 926,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_CONVERT_S_I64_S
    { 925,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 441,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_CONVERT_S_I64
    { 924,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_CONVERT_S_I32_S
    { 923,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 439,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // F32_CONVERT_S_I32
    { 922,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I8x16_u_S
    { 921,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 433,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I8x16_u
    { 920,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I8x16_s_S
    { 919,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 433,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I8x16_s
    { 918,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I64x2_S
    { 917,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 436,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I64x2
    { 916,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I32x4_S
    { 915,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 433,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I32x4
    { 914,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I16x8_u_S
    { 913,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 433,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I16x8_u
    { 912,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I16x8_s_S
    { 911,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 433,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_I16x8_s
    { 910,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_F64x2_S
    { 909,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 430,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_F64x2
    { 908,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_F32x4_S
    { 907,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 426,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_F32x4
    { 906,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 429,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_F16x8_S
    { 905,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 426,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_LANE_F16x8
    { 904,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_U_I64x2_S
    { 903,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_U_I64x2
    { 902,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_U_I32x4_S
    { 901,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_U_I32x4
    { 900,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_U_I16x8_S
    { 899,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_U_I16x8
    { 898,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_S_I64x2_S
    { 897,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_S_I64x2
    { 896,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_S_I32x4_S
    { 895,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_S_I32x4
    { 894,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_S_I16x8_S
    { 893,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_LOW_S_I16x8
    { 892,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_U_I64x2_S
    { 891,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_U_I64x2
    { 890,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_U_I32x4_S
    { 889,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_U_I32x4
    { 888,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_U_I16x8_S
    { 887,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_U_I16x8
    { 886,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_S_I64x2_S
    { 885,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_S_I64x2
    { 884,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_S_I32x4_S
    { 883,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_S_I32x4
    { 882,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_S_I16x8_S
    { 881,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTMUL_HIGH_S_I16x8
    { 880,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I8x16_S
    { 879,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I8x16
    { 878,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I64x2_S
    { 877,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I64x2
    { 876,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I64_S
    { 875,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 423,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I64
    { 874,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I32x4_S
    { 873,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I32x4
    { 872,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I32_S
    { 871,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I32
    { 870,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I16x8_S
    { 869,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_I16x8
    { 868,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_F64x2_S
    { 867,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_F64x2
    { 866,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_F64_S
    { 865,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 420,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_F64
    { 864,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_F32x4_S
    { 863,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_F32x4
    { 862,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_F32_S
    { 861,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 417,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_F32
    { 860,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_F16x8_S
    { 859,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQ_F16x8
    { 858,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQZ_I64_S
    { 857,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 415,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQZ_I64
    { 856,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQZ_I32_S
    { 855,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 310,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EQZ_I32
    { 854,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_TRY_TABLE_S
    { 853,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_TRY_TABLE
    { 852,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_TRY_S
    { 851,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_TRY
    { 850,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_S
    { 849,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_LOOP_S
    { 848,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_LOOP
    { 847,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_IF_S
    { 846,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_IF
    { 845,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_FUNCTION_S
    { 844,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_FUNCTION
    { 843,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_BLOCK_S
    { 842,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END_BLOCK
    { 841,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // END
    { 840,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ELSE_S
    { 839,	0,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 1,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ELSE
    { 838,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_V128_S
    { 837,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 414,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_V128
    { 836,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_I64_S
    { 835,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 302,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_I64
    { 834,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_I32_S
    { 833,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 300,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_I32
    { 832,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_FUNCREF_S
    { 831,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 413,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_FUNCREF
    { 830,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_F64_S
    { 829,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 412,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_F64
    { 828,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_F32_S
    { 827,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 411,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_F32
    { 826,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_EXTERNREF_S
    { 825,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 410,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_EXTERNREF
    { 824,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_EXNREF_S
    { 823,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 309,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DROP_EXNREF
    { 822,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DOT_S
    { 821,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DOT
    { 820,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_U_I64_S
    { 819,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_U_I64
    { 818,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_U_I32_S
    { 817,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_U_I32
    { 816,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_S_I64_S
    { 815,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_S_I64
    { 814,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_S_I32_S
    { 813,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_S_I32
    { 812,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_F64x2_S
    { 811,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_F64x2
    { 810,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_F64_S
    { 809,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 167,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_F64
    { 808,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_F32x4_S
    { 807,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_F32x4
    { 806,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_F32_S
    { 805,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 164,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_F32
    { 804,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_F16x8_S
    { 803,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DIV_F16x8
    { 802,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 154,	3,	0|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DELEGATE_S
    { 801,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 154,	3,	0|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DELEGATE
    { 800,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Trap)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DEBUG_UNREACHABLE_S
    { 799,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Trap)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DEBUG_UNREACHABLE
    { 798,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 322,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DATA_DROP_S
    { 797,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 322,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DATA_DROP
    { 796,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CTZ_I64_S
    { 795,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 312,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CTZ_I64
    { 794,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CTZ_I32_S
    { 793,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 310,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CTZ_I32
    { 792,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_V128_S
    { 791,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_V128
    { 790,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_I64_S
    { 789,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 312,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_I64
    { 788,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_I32_S
    { 787,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 310,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_I32
    { 786,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_FUNCREF_S
    { 785,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 408,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_FUNCREF
    { 784,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_F64_S
    { 783,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 159,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_F64
    { 782,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_F32_S
    { 781,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 157,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_F32
    { 780,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_EXTERNREF_S
    { 779,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 406,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_EXTERNREF
    { 778,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_EXNREF_S
    { 777,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 404,	3,	0|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_EXNREF
    { 776,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPYSIGN_F64_S
    { 775,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 167,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPYSIGN_F64
    { 774,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPYSIGN_F32_S
    { 773,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 164,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPYSIGN_F32
    { 772,	16,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 388,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_I8x16_S
    { 771,	17,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 371,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_I8x16
    { 770,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 369,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_I64x2_S
    { 769,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 366,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_I64x2
    { 768,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 362,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_I32x4_S
    { 767,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 357,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_I32x4
    { 766,	8,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 349,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_I16x8_S
    { 765,	9,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 340,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_I16x8
    { 764,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 338,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_F64x2_S
    { 763,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 335,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_F64x2
    { 762,	4,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 331,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_F32x4_S
    { 761,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 326,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_V128_F32x4
    { 760,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 325,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_I64_S
    { 759,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 323,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_I64
    { 758,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 322,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_I32_S
    { 757,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 320,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_I32
    { 756,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 319,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_F64_S
    { 755,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 317,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_F64
    { 754,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 316,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_F32_S
    { 753,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 314,	3,	0|(1ULL<<MCID::MoveImm)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CONST_F32
    { 752,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CLZ_I64_S
    { 751,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 312,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CLZ_I64
    { 750,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CLZ_I32_S
    { 749,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 310,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CLZ_I32
    { 748,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_F64x2_S
    { 747,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_F64x2
    { 746,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_F64_S
    { 745,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 159,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_F64
    { 744,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_F32x4_S
    { 743,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_F32x4
    { 742,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_F32_S
    { 741,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 157,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_F32
    { 740,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_F16x8_S
    { 739,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CEIL_F16x8
    { 738,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 308,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CATCH_S
    { 737,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 308,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CATCH_REF_S
    { 736,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 308,	3,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CATCH_REF
    { 735,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 308,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CATCH_LEGACY_S
    { 734,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 308,	3,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CATCH_LEGACY
    { 733,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CATCH_ALL_S
    { 732,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CATCH_ALL_REF_S
    { 731,	1,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 309,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CATCH_ALL_REF
    { 730,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CATCH_ALL_LEGACY_S
    { 729,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CATCH_ALL_LEGACY
    { 728,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CATCH_ALL
    { 727,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 308,	3,	0|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CATCH
    { 726,	1,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 151,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CALL_S
    { 725,	1,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 307,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CALL_REF_S
    { 724,	2,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 305,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CALL_REF
    { 723,	2,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 303,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CALL_INDIRECT_S
    { 722,	2,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 303,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CALL_INDIRECT
    { 721,	1,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 151,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CALL
    { 720,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 154,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR_UNLESS_S
    { 719,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 298,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR_UNLESS
    { 718,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 301,	3,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR_TABLE_I64_S
    { 717,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 302,	3,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR_TABLE_I64
    { 716,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 301,	3,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR_TABLE_I32_S
    { 715,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 300,	3,	0|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR_TABLE_I32
    { 714,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 154,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR_S
    { 713,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 154,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR_IF_S
    { 712,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 298,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR_IF
    { 711,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 154,	3,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BR
    { 710,	1,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 297,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BLOCK_S
    { 709,	1,	0,	0,	0,	1,	1,	WebAssemblyOpInfoBase + 297,	8,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BLOCK
    { 708,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BITSELECT_S
    { 707,	4,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 293,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BITSELECT
    { 706,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BITMASK_I8x16_S
    { 705,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 176,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BITMASK_I8x16
    { 704,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BITMASK_I64x2_S
    { 703,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 176,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BITMASK_I64x2
    { 702,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BITMASK_I32x4_S
    { 701,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 176,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BITMASK_I32x4
    { 700,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BITMASK_I16x8_S
    { 699,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 176,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BITMASK_I16x8
    { 698,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AVGR_U_I8x16_S
    { 697,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AVGR_U_I8x16
    { 696,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AVGR_U_I16x8_S
    { 695,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AVGR_U_I16x8
    { 694,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE_I64_A64_S
    { 693,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 288,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE_I64_A64
    { 692,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE_I64_A32_S
    { 691,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 283,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE_I64_A32
    { 690,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE_I32_A64_S
    { 689,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 278,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE_I32_A64
    { 688,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE_I32_A32_S
    { 687,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 273,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE_I32_A32
    { 686,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE8_I64_A64_S
    { 685,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 288,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE8_I64_A64
    { 684,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE8_I64_A32_S
    { 683,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 283,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE8_I64_A32
    { 682,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE8_I32_A64_S
    { 681,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 278,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE8_I32_A64
    { 680,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE8_I32_A32_S
    { 679,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 273,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE8_I32_A32
    { 678,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE32_I64_A64_S
    { 677,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 288,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE32_I64_A64
    { 676,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE32_I64_A32_S
    { 675,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 283,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE32_I64_A32
    { 674,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE16_I64_A64_S
    { 673,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 288,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE16_I64_A64
    { 672,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE16_I64_A32_S
    { 671,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 283,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE16_I64_A32
    { 670,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE16_I32_A64_S
    { 669,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 278,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE16_I32_A64
    { 668,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE16_I32_A32_S
    { 667,	5,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 273,	3,	0|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_STORE16_I32_A32
    { 666,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XOR_I64_A64_S
    { 665,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XOR_I64_A64
    { 664,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XOR_I64_A32_S
    { 663,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XOR_I64_A32
    { 662,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XOR_I32_A64_S
    { 661,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XOR_I32_A64
    { 660,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XOR_I32_A32_S
    { 659,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XOR_I32_A32
    { 658,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XCHG_I64_A64_S
    { 657,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XCHG_I64_A64
    { 656,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XCHG_I64_A32_S
    { 655,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XCHG_I64_A32
    { 654,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XCHG_I32_A64_S
    { 653,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XCHG_I32_A64
    { 652,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XCHG_I32_A32_S
    { 651,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_XCHG_I32_A32
    { 650,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_SUB_I64_A64_S
    { 649,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_SUB_I64_A64
    { 648,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_SUB_I64_A32_S
    { 647,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_SUB_I64_A32
    { 646,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_SUB_I32_A64_S
    { 645,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_SUB_I32_A64
    { 644,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_SUB_I32_A32_S
    { 643,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_SUB_I32_A32
    { 642,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_OR_I64_A64_S
    { 641,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_OR_I64_A64
    { 640,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_OR_I64_A32_S
    { 639,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_OR_I64_A32
    { 638,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_OR_I32_A64_S
    { 637,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_OR_I32_A64
    { 636,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_OR_I32_A32_S
    { 635,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_OR_I32_A32
    { 634,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_CMPXCHG_I64_A64_S
    { 633,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 266,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_CMPXCHG_I64_A64
    { 632,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_CMPXCHG_I64_A32_S
    { 631,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 259,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_CMPXCHG_I64_A32
    { 630,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_CMPXCHG_I32_A64_S
    { 629,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 252,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_CMPXCHG_I32_A64
    { 628,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_CMPXCHG_I32_A32_S
    { 627,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 245,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_CMPXCHG_I32_A32
    { 626,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_AND_I64_A64_S
    { 625,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_AND_I64_A64
    { 624,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_AND_I64_A32_S
    { 623,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_AND_I64_A32
    { 622,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_AND_I32_A64_S
    { 621,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_AND_I32_A64
    { 620,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_AND_I32_A32_S
    { 619,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_AND_I32_A32
    { 618,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_ADD_I64_A64_S
    { 617,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_ADD_I64_A64
    { 616,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_ADD_I64_A32_S
    { 615,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_ADD_I64_A32
    { 614,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_ADD_I32_A64_S
    { 613,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_ADD_I32_A64
    { 612,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_ADD_I32_A32_S
    { 611,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW_ADD_I32_A32
    { 610,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XOR_I64_A64_S
    { 609,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XOR_I64_A64
    { 608,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XOR_I64_A32_S
    { 607,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XOR_I64_A32
    { 606,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XOR_I32_A64_S
    { 605,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XOR_I32_A64
    { 604,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XOR_I32_A32_S
    { 603,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XOR_I32_A32
    { 602,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XCHG_I64_A64_S
    { 601,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XCHG_I64_A64
    { 600,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XCHG_I64_A32_S
    { 599,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XCHG_I64_A32
    { 598,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XCHG_I32_A64_S
    { 597,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XCHG_I32_A64
    { 596,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XCHG_I32_A32_S
    { 595,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_XCHG_I32_A32
    { 594,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_SUB_I64_A64_S
    { 593,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_SUB_I64_A64
    { 592,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_SUB_I64_A32_S
    { 591,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_SUB_I64_A32
    { 590,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_SUB_I32_A64_S
    { 589,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_SUB_I32_A64
    { 588,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_SUB_I32_A32_S
    { 587,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_SUB_I32_A32
    { 586,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_OR_I64_A64_S
    { 585,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_OR_I64_A64
    { 584,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_OR_I64_A32_S
    { 583,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_OR_I64_A32
    { 582,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_OR_I32_A64_S
    { 581,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_OR_I32_A64
    { 580,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_OR_I32_A32_S
    { 579,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_OR_I32_A32
    { 578,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_CMPXCHG_I64_A64_S
    { 577,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 266,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_CMPXCHG_I64_A64
    { 576,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_CMPXCHG_I64_A32_S
    { 575,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 259,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_CMPXCHG_I64_A32
    { 574,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_CMPXCHG_I32_A64_S
    { 573,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 252,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_CMPXCHG_I32_A64
    { 572,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_CMPXCHG_I32_A32_S
    { 571,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 245,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_CMPXCHG_I32_A32
    { 570,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_AND_I64_A64_S
    { 569,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_AND_I64_A64
    { 568,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_AND_I64_A32_S
    { 567,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_AND_I64_A32
    { 566,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_AND_I32_A64_S
    { 565,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_AND_I32_A64
    { 564,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_AND_I32_A32_S
    { 563,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_AND_I32_A32
    { 562,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_ADD_I64_A64_S
    { 561,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_ADD_I64_A64
    { 560,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_ADD_I64_A32_S
    { 559,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_ADD_I64_A32
    { 558,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_ADD_I32_A64_S
    { 557,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_ADD_I32_A64
    { 556,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_ADD_I32_A32_S
    { 555,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW8_U_ADD_I32_A32
    { 554,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_XOR_I64_A64_S
    { 553,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_XOR_I64_A64
    { 552,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_XOR_I64_A32_S
    { 551,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_XOR_I64_A32
    { 550,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_XCHG_I64_A64_S
    { 549,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_XCHG_I64_A64
    { 548,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_XCHG_I64_A32_S
    { 547,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_XCHG_I64_A32
    { 546,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_SUB_I64_A64_S
    { 545,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_SUB_I64_A64
    { 544,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_SUB_I64_A32_S
    { 543,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_SUB_I64_A32
    { 542,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_OR_I64_A64_S
    { 541,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_OR_I64_A64
    { 540,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_OR_I64_A32_S
    { 539,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_OR_I64_A32
    { 538,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_CMPXCHG_I64_A64_S
    { 537,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 266,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_CMPXCHG_I64_A64
    { 536,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_CMPXCHG_I64_A32_S
    { 535,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 259,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_CMPXCHG_I64_A32
    { 534,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_AND_I64_A64_S
    { 533,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_AND_I64_A64
    { 532,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_AND_I64_A32_S
    { 531,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_AND_I64_A32
    { 530,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_ADD_I64_A64_S
    { 529,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_ADD_I64_A64
    { 528,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_ADD_I64_A32_S
    { 527,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW32_U_ADD_I64_A32
    { 526,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XOR_I64_A64_S
    { 525,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XOR_I64_A64
    { 524,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XOR_I64_A32_S
    { 523,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XOR_I64_A32
    { 522,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XOR_I32_A64_S
    { 521,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XOR_I32_A64
    { 520,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XOR_I32_A32_S
    { 519,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XOR_I32_A32
    { 518,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XCHG_I64_A64_S
    { 517,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XCHG_I64_A64
    { 516,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XCHG_I64_A32_S
    { 515,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XCHG_I64_A32
    { 514,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XCHG_I32_A64_S
    { 513,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XCHG_I32_A64
    { 512,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XCHG_I32_A32_S
    { 511,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_XCHG_I32_A32
    { 510,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_SUB_I64_A64_S
    { 509,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_SUB_I64_A64
    { 508,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_SUB_I64_A32_S
    { 507,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_SUB_I64_A32
    { 506,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_SUB_I32_A64_S
    { 505,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_SUB_I32_A64
    { 504,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_SUB_I32_A32_S
    { 503,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_SUB_I32_A32
    { 502,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_OR_I64_A64_S
    { 501,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_OR_I64_A64
    { 500,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_OR_I64_A32_S
    { 499,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_OR_I64_A32
    { 498,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_OR_I32_A64_S
    { 497,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_OR_I32_A64
    { 496,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_OR_I32_A32_S
    { 495,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_OR_I32_A32
    { 494,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_CMPXCHG_I64_A64_S
    { 493,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 266,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_CMPXCHG_I64_A64
    { 492,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_CMPXCHG_I64_A32_S
    { 491,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 259,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_CMPXCHG_I64_A32
    { 490,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_CMPXCHG_I32_A64_S
    { 489,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 252,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_CMPXCHG_I32_A64
    { 488,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_CMPXCHG_I32_A32_S
    { 487,	7,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 245,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_CMPXCHG_I32_A32
    { 486,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_AND_I64_A64_S
    { 485,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_AND_I64_A64
    { 484,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_AND_I64_A32_S
    { 483,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_AND_I64_A32
    { 482,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_AND_I32_A64_S
    { 481,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_AND_I32_A64
    { 480,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_AND_I32_A32_S
    { 479,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_AND_I32_A32
    { 478,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_ADD_I64_A64_S
    { 477,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 239,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_ADD_I64_A64
    { 476,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_ADD_I64_A32_S
    { 475,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 233,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_ADD_I64_A32
    { 474,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_ADD_I32_A64_S
    { 473,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 227,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_ADD_I32_A64
    { 472,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_ADD_I32_A32_S
    { 471,	6,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 221,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_RMW16_U_ADD_I32_A32
    { 470,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD_I64_A64_S
    { 469,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 216,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD_I64_A64
    { 468,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD_I64_A32_S
    { 467,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 211,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD_I64_A32
    { 466,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD_I32_A64_S
    { 465,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 203,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD_I32_A64
    { 464,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD_I32_A32_S
    { 463,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 195,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD_I32_A32
    { 462,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD8_U_I64_A64_S
    { 461,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 216,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD8_U_I64_A64
    { 460,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD8_U_I64_A32_S
    { 459,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 211,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD8_U_I64_A32
    { 458,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD8_U_I32_A64_S
    { 457,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 203,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD8_U_I32_A64
    { 456,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD8_U_I32_A32_S
    { 455,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 195,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD8_U_I32_A32
    { 454,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD32_U_I64_A64_S
    { 453,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 216,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD32_U_I64_A64
    { 452,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD32_U_I64_A32_S
    { 451,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 211,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD32_U_I64_A32
    { 450,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD16_U_I64_A64_S
    { 449,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 216,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD16_U_I64_A64
    { 448,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD16_U_I64_A32_S
    { 447,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 211,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD16_U_I64_A32
    { 446,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 208,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD16_U_I32_A64_S
    { 445,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 203,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD16_U_I32_A64
    { 444,	3,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 200,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD16_U_I32_A32_S
    { 443,	5,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 195,	3,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_LOAD16_U_I32_A32
    { 442,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 194,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_FENCE_S
    { 441,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 194,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ATOMIC_FENCE
    { 440,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v8i16_S
    { 439,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 192,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v8i16
    { 438,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v8f16_S
    { 437,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 192,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v8f16
    { 436,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v4i32_S
    { 435,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 192,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v4i32
    { 434,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v4f32_S
    { 433,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 192,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v4f32
    { 432,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v2i64_S
    { 431,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 192,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v2i64
    { 430,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v2f64_S
    { 429,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 192,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v2f64
    { 428,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v16i8_S
    { 427,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 192,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_v16i8
    { 426,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_i64_S
    { 425,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 190,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_i64
    { 424,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_i32_S
    { 423,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 188,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_i32
    { 422,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_funcref_S
    { 421,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 186,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_funcref
    { 420,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_f64_S
    { 419,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 184,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_f64
    { 418,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_f32_S
    { 417,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 182,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_f32
    { 416,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_externref_S
    { 415,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 180,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_externref
    { 414,	1,	0,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_exnref_S
    { 413,	2,	1,	0,	0,	1,	0,	WebAssemblyOpInfoBase + 178,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARGUMENT_exnref
    { 412,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANYTRUE_S
    { 411,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 176,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANYTRUE
    { 410,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND_S
    { 409,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND_I64_S
    { 408,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND_I64
    { 407,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND_I32_S
    { 406,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND_I32
    { 405,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANDNOT_S
    { 404,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANDNOT
    { 403,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // AND
    { 402,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ALLTRUE_I8x16_S
    { 401,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 176,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ALLTRUE_I8x16
    { 400,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ALLTRUE_I64x2_S
    { 399,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 176,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ALLTRUE_I64x2
    { 398,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ALLTRUE_I32x4_S
    { 397,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 176,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ALLTRUE_I32x4
    { 396,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ALLTRUE_I16x8_S
    { 395,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 176,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ALLTRUE_I16x8
    { 394,	2,	0,	0,	0,	2,	2,	WebAssemblyOpInfoBase + 20,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKUP_S
    { 393,	2,	0,	0,	0,	2,	2,	WebAssemblyOpInfoBase + 20,	4,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKUP
    { 392,	2,	0,	0,	0,	2,	2,	WebAssemblyOpInfoBase + 20,	4,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKDOWN_S
    { 391,	2,	0,	0,	0,	2,	2,	WebAssemblyOpInfoBase + 20,	4,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADJCALLSTACKDOWN
    { 390,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_SAT_U_I8x16_S
    { 389,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_SAT_U_I8x16
    { 388,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_SAT_U_I16x8_S
    { 387,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_SAT_U_I16x8
    { 386,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_SAT_S_I8x16_S
    { 385,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_SAT_S_I8x16
    { 384,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_SAT_S_I16x8_S
    { 383,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_SAT_S_I16x8
    { 382,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I8x16_S
    { 381,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I8x16
    { 380,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I64x2_S
    { 379,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I64x2
    { 378,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I64_S
    { 377,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 173,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I64
    { 376,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I32x4_S
    { 375,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I32x4
    { 374,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I32_S
    { 373,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 170,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I32
    { 372,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I16x8_S
    { 371,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_I16x8
    { 370,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_F64x2_S
    { 369,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_F64x2
    { 368,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_F64_S
    { 367,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 167,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_F64
    { 366,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_F32x4_S
    { 365,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_F32x4
    { 364,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_F32_S
    { 363,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 164,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_F32
    { 362,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_F16x8_S
    { 361,	3,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 161,	3,	0|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ADD_F16x8
    { 360,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_I8x16_S
    { 359,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_I8x16
    { 358,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_I64x2_S
    { 357,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_I64x2
    { 356,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_I32x4_S
    { 355,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_I32x4
    { 354,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_I16x8_S
    { 353,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_I16x8
    { 352,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_F64x2_S
    { 351,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_F64x2
    { 350,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_F64_S
    { 349,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 159,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_F64
    { 348,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_F32x4_S
    { 347,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_F32x4
    { 346,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_F32_S
    { 345,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 157,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_F32
    { 344,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_F16x8_S
    { 343,	2,	1,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 155,	3,	0|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ABS_F16x8
    { 342,	0,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // RET_CALL_RESULTS_S
    { 341,	0,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // RET_CALL_RESULTS
    { 340,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COMPILER_FENCE_S
    { 339,	0,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 1,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COMPILER_FENCE
    { 338,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 154,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::EHScopeReturn)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CLEANUPRET_S
    { 337,	1,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 154,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::EHScopeReturn)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CLEANUPRET
    { 336,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 152,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::EHScopeReturn)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CATCHRET_S
    { 335,	2,	0,	0,	0,	0,	1,	WebAssemblyOpInfoBase + 152,	3,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::EHScopeReturn)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CATCHRET
    { 334,	0,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CALL_RESULTS_S
    { 333,	0,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::VariadicOpsAreDefs), 0x0ULL },  // CALL_RESULTS
    { 332,	1,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALL_PARAMS_S
    { 331,	1,	0,	0,	0,	2,	1,	WebAssemblyOpInfoBase + 151,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CALL_PARAMS
    { 330,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UBFX
    { 329,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 147,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SBFX
    { 328,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_UMIN
    { 327,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_UMAX
    { 326,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SMIN
    { 325,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SMAX
    { 324,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_XOR
    { 323,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_OR
    { 322,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_AND
    { 321,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_MUL
    { 320,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_ADD
    { 319,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMINIMUM
    { 318,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMAXIMUM
    { 317,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMIN
    { 316,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMAX
    { 315,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FMUL
    { 314,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_FADD
    { 313,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SEQ_FMUL
    { 312,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECREDUCE_SEQ_FADD
    { 311,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UBSANTRAP
    { 310,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_DEBUGTRAP
    { 309,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRAP
    { 308,	3,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMSET_INLINE
    { 307,	3,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BZERO
    { 306,	4,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMSET
    { 305,	4,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMMOVE
    { 304,	3,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMCPY_INLINE
    { 303,	4,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 143,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MEMCPY
    { 302,	2,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 141,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_WRITE_REGISTER
    { 301,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_READ_REGISTER
    { 300,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FCMPS
    { 299,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FCMP
    { 298,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FLDEXP
    { 297,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FSQRT
    { 296,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FMA
    { 295,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FREM
    { 294,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FDIV
    { 293,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FMUL
    { 292,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FSUB
    { 291,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayRaiseFPException)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STRICT_FADD
    { 290,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STACKRESTORE
    { 289,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STACKSAVE
    { 288,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_DYN_STACKALLOC
    { 287,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_JUMP_TABLE
    { 286,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BLOCK_ADDR
    { 285,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ADDRSPACE_CAST
    { 284,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FNEARBYINT
    { 283,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FRINT
    { 282,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FFLOOR
    { 281,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSQRT
    { 280,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FTANH
    { 279,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSINH
    { 278,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOSH
    { 277,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FATAN2
    { 276,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FATAN
    { 275,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FASIN
    { 274,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FACOS
    { 273,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FTAN
    { 272,	3,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSINCOS
    { 271,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSIN
    { 270,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOS
    { 269,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCEIL
    { 268,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CLMUL
    { 267,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BITREVERSE
    { 266,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BSWAP
    { 265,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTPOP
    { 264,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLS
    { 263,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLZ_ZERO_POISON
    { 262,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTLZ
    { 261,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTTZ_ZERO_POISON
    { 260,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CTTZ
    { 259,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 137,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VECTOR_COMPRESS
    { 258,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STEP_VECTOR
    { 257,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SPLAT_VECTOR
    { 256,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 133,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SHUFFLE_VECTOR
    { 255,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 130,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT_VECTOR_ELT
    { 254,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 126,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT_VECTOR_ELT
    { 253,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT_SUBVECTOR
    { 252,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT_SUBVECTOR
    { 251,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VSCALE
    { 250,	3,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 123,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRJT
    { 249,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BR
    { 248,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LLROUND
    { 247,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LROUND
    { 246,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABS
    { 245,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMAX
    { 244,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMIN
    { 243,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMAX
    { 242,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMIN
    { 241,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRMASK
    { 240,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTR_ADD
    { 239,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_ROUNDING
    { 238,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_ROUNDING
    { 237,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_RESET_FPMODE
    { 236,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_FPMODE
    { 235,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_FPMODE
    { 234,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_RESET_FPENV
    { 233,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SET_FPENV
    { 232,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GET_FPENV
    { 231,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXIMUMNUM
    { 230,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINIMUMNUM
    { 229,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXIMUM
    { 228,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINIMUM
    { 227,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXNUM_IEEE
    { 226,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINNUM_IEEE
    { 225,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAXNUM
    { 224,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMINNUM
    { 223,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCANONICALIZE
    { 222,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_IS_FPCLASS
    { 221,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCOPYSIGN
    { 220,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FABS
    { 219,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOUI_SAT
    { 218,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOSI_SAT
    { 217,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UITOFP
    { 216,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SITOFP
    { 215,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOUI
    { 214,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTOSI
    { 213,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTRUNC
    { 212,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPEXT
    { 211,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FNEG
    { 210,	3,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FFREXP
    { 209,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLDEXP
    { 208,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG10
    { 207,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG2
    { 206,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FLOG
    { 205,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP10
    { 204,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP2
    { 203,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FEXP
    { 202,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPOWI
    { 201,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPOW
    { 200,	3,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMODF
    { 199,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FREM
    { 198,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FDIV
    { 197,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMAD
    { 196,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMA
    { 195,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FMUL
    { 194,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSUB
    { 193,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FADD
    { 192,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVFIXSAT
    { 191,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVFIXSAT
    { 190,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVFIX
    { 189,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVFIX
    { 188,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULFIXSAT
    { 187,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULFIXSAT
    { 186,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULFIX
    { 185,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 119,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULFIX
    { 184,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSHLSAT
    { 183,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USHLSAT
    { 182,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBSAT
    { 181,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBSAT
    { 180,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDSAT
    { 179,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDSAT
    { 178,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULH
    { 177,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULH
    { 176,	4,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SMULO
    { 175,	4,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UMULO
    { 174,	5,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBE
    { 173,	4,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SSUBO
    { 172,	5,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDE
    { 171,	4,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SADDO
    { 170,	5,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBE
    { 169,	4,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_USUBO
    { 168,	5,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 114,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDE
    { 167,	4,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UADDO
    { 166,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SELECT
    { 165,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UCMP
    { 164,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 111,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SCMP
    { 163,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCMP
    { 162,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 107,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ICMP
    { 161,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ROTL
    { 160,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ROTR
    { 159,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSHR
    { 158,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 103,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FSHL
    { 157,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASHR
    { 156,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LSHR
    { 155,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 100,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SHL
    { 154,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ZEXT
    { 153,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXT_INREG
    { 152,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXT
    { 151,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 97,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VAARG
    { 150,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_VASTART
    { 149,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FCONSTANT
    { 148,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT
    { 147,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_USAT_U
    { 146,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_SSAT_U
    { 145,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC_SSAT_S
    { 144,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_TRUNC
    { 143,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ANYEXT
    { 142,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
    { 141,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // G_INTRINSIC_CONVERGENT
    { 140,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_W_SIDE_EFFECTS
    { 139,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC
    { 138,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INVOKE_REGION_START
    { 137,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRINDIRECT
    { 136,	2,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BRCOND
    { 135,	4,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 93,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PREFETCH
    { 134,	2,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 20,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FENCE
    { 133,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_USUB_SAT
    { 132,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_USUB_COND
    { 131,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UDEC_WRAP
    { 130,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UINC_WRAP
    { 129,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMINIMUMNUM
    { 128,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAXIMUMNUM
    { 127,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMINIMUM
    { 126,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAXIMUM
    { 125,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMIN
    { 124,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FMAX
    { 123,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FSUB
    { 122,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_FADD
    { 121,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UMIN
    { 120,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_UMAX
    { 119,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_MIN
    { 118,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_MAX
    { 117,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_XOR
    { 116,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_OR
    { 115,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_NAND
    { 114,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_AND
    { 113,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_SUB
    { 112,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_ADD
    { 111,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 90,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMICRMW_XCHG
    { 110,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 86,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMIC_CMPXCHG
    { 109,	5,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 81,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ATOMIC_CMPXCHG_WITH_SUCCESS
    { 108,	5,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 76,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_STORE
    { 107,	2,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPTRUNCSTORE
    { 106,	2,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_STORE
    { 105,	5,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_ZEXTLOAD
    { 104,	5,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_SEXTLOAD
    { 103,	5,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 71,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INDEXED_LOAD
    { 102,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FPEXTLOAD
    { 101,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ZEXTLOAD
    { 100,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SEXTLOAD
    { 99,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_LOAD
    { 98,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_READSTEADYCOUNTER
    { 97,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_READCYCLECOUNTER
    { 96,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_ROUNDEVEN
    { 95,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_LLRINT
    { 94,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_LRINT
    { 93,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_ROUND
    { 92,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_TRUNC
    { 91,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 68,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTRINSIC_FPTRUNC_ROUND
    { 90,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT_FOLD_BARRIER
    { 89,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 66,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FREEZE
    { 88,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BITCAST
    { 87,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INTTOPTR
    { 86,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRTOINT
    { 85,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONCAT_VECTORS
    { 84,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BUILD_VECTOR_TRUNC
    { 83,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_BUILD_VECTOR
    { 82,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MERGE_VALUES
    { 81,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 62,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_INSERT
    { 80,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 60,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UNMERGE_VALUES
    { 79,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 57,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_EXTRACT
    { 78,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_CONSTANT_POOL
    { 77,	5,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 52,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PTRAUTH_GLOBAL_VALUE
    { 76,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_GLOBAL_VALUE
    { 75,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 50,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_FRAME_INDEX
    { 74,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_PHI
    { 73,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 49,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_IMPLICIT_DEF
    { 72,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SAVGCEIL
    { 71,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SAVGFLOOR
    { 70,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UAVGCEIL
    { 69,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UAVGFLOOR
    { 68,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABDU
    { 67,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ABDS
    { 66,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_XOR
    { 65,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_OR
    { 64,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_AND
    { 63,	4,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIVREM
    { 62,	4,	2,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 45,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIVREM
    { 61,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UREM
    { 60,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SREM
    { 59,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_UDIV
    { 58,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SDIV
    { 57,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_MUL
    { 56,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_SUB
    { 55,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 42,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ADD
    { 54,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_ALIGN
    { 53,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_ZEXT
    { 52,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 39,	0,	0|(1ULL<<MCID::PreISelOpcode)|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // G_ASSERT_SEXT
    { 51,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_GLUE
    { 50,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_LOOP
    { 49,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ANCHOR
    { 48,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq)|(1ULL<<MCID::Convergent), 0x0ULL },  // CONVERGENCECTRL_ENTRY
    { 47,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // RELOC_NONE
    { 46,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // JUMP_TABLE_DEBUG_INFO
    { 45,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // MEMBARRIER
    { 44,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FAKE_USE
    { 43,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ICALL_BRANCH_FUNNEL
    { 42,	3,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 36,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14872
    { 41,	2,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 34,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14871
    { 40,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_TAIL_CALL
    { 39,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_FUNCTION_EXIT
    { 38,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_RET
    { 37,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_FUNCTION_ENTER
    { 36,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHABLE_OP
    { 35,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FAULTING_OP
    { 34,	2,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 32,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LOCAL_ESCAPE
    { 33,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STATEPOINT
    { 32,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 29,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_14870
    { 31,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PREALLOCATED_SETUP
    { 30,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 28,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // anonymous_13587
    { 29,	6,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 22,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PATCHPOINT
    { 28,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // FENTRY_CALL
    { 27,	2,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 20,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // STACKMAP
    { 26,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 18,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ARITH_FENCE
    { 25,	4,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 14,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PSEUDO_PROBE
    { 24,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LIFETIME_END
    { 23,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // LIFETIME_START
    { 22,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // BUNDLE
    { 21,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 11,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_LANEMASK
    { 20,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY
    { 19,	2,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 9,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // REG_SEQUENCE
    { 18,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_LABEL
    { 17,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_PHI
    { 16,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_INSTR_REF
    { 15,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_VALUE_LIST
    { 14,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // DBG_VALUE
    { 13,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // COPY_TO_REGCLASS
    { 12,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // SUBREG_TO_REG
    { 11,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INIT_UNDEF
    { 10,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // IMPLICIT_DEF
    { 9,	4,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 5,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INSERT_SUBREG
    { 8,	3,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 2,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EXTRACT_SUBREG
    { 7,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // KILL
    { 6,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // ANNOTATION_LABEL
    { 5,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // GC_LABEL
    { 4,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // EH_LABEL
    { 3,	1,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Meta)|(1ULL<<MCID::NotDuplicable)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // CFI_INSTRUCTION
    { 2,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INLINEASM_BR
    { 1,	0,	0,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 1,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // INLINEASM
    { 0,	1,	1,	0,	0,	0,	0,	WebAssemblyOpInfoBase + 0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::ExtraSrcRegAllocReq)|(1ULL<<MCID::ExtraDefRegAllocReq), 0x0ULL },  // PHI
  }, {
    /* 0 */
    /* 0 */ WebAssembly::SP32, WebAssembly::SP64, WebAssembly::ARGUMENTS,
    /* 3 */ WebAssembly::ARGUMENTS,
    /* 4 */ WebAssembly::SP32, WebAssembly::SP64, WebAssembly::SP32, WebAssembly::SP64,
    /* 8 */ WebAssembly::VALUE_STACK, WebAssembly::VALUE_STACK,
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
    /* 28 */ { WebAssembly::wasm_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 },
    /* 29 */ { WebAssembly::wasm_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 32 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 34 */ { WebAssembly::wasm_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
    /* 36 */ { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { WebAssembly::wasm_ptr_rc, 0|(1<<MCOI::LookupRegClassByHwMode), MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 },
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
    /* 151 */ { -1, 0, WebAssembly::OPERAND_FUNCTION32, 0 },
    /* 152 */ { -1, 0, WebAssembly::OPERAND_BASIC_BLOCK, 0 }, { -1, 0, WebAssembly::OPERAND_BASIC_BLOCK, 0 },
    /* 154 */ { -1, 0, WebAssembly::OPERAND_BASIC_BLOCK, 0 },
    /* 155 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 157 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 159 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 161 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 164 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 167 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 170 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 173 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 176 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 178 */ { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 180 */ { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 182 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 184 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 186 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 188 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 190 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 192 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 },
    /* 194 */ { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 },
    /* 195 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 200 */ { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 },
    /* 203 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 208 */ { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 },
    /* 211 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 216 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 221 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 227 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 233 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 239 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 245 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 252 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 259 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 266 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 273 */ { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 278 */ { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 283 */ { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 288 */ { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 293 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 297 */ { -1, 0, WebAssembly::OPERAND_SIGNATURE, 0 },
    /* 298 */ { -1, 0, WebAssembly::OPERAND_BASIC_BLOCK, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 300 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 301 */ { -1, 0, WebAssembly::OPERAND_BRLIST, 0 },
    /* 302 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 303 */ { -1, 0, WebAssembly::OPERAND_TYPEINDEX, 0 }, { -1, 0, WebAssembly::OPERAND_TABLE, 0 },
    /* 305 */ { -1, 0, WebAssembly::OPERAND_TYPEINDEX, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 307 */ { -1, 0, WebAssembly::OPERAND_TYPEINDEX, 0 },
    /* 308 */ { -1, 0, WebAssembly::OPERAND_TAG, 0 },
    /* 309 */ { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 310 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 312 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 314 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_F32IMM, 0 },
    /* 316 */ { -1, 0, WebAssembly::OPERAND_F32IMM, 0 },
    /* 317 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_F64IMM, 0 },
    /* 319 */ { -1, 0, WebAssembly::OPERAND_F64IMM, 0 },
    /* 320 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_I32IMM, 0 },
    /* 322 */ { -1, 0, WebAssembly::OPERAND_I32IMM, 0 },
    /* 323 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_I64IMM, 0 },
    /* 325 */ { -1, 0, WebAssembly::OPERAND_I64IMM, 0 },
    /* 326 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_F32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_F32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_F32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_F32IMM, 0 },
    /* 331 */ { -1, 0, WebAssembly::OPERAND_F32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_F32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_F32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_F32IMM, 0 },
    /* 335 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_F64IMM, 0 }, { -1, 0, WebAssembly::OPERAND_F64IMM, 0 },
    /* 338 */ { -1, 0, WebAssembly::OPERAND_F64IMM, 0 }, { -1, 0, WebAssembly::OPERAND_F64IMM, 0 },
    /* 340 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 },
    /* 349 */ { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I16IMM, 0 },
    /* 357 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I32IMM, 0 },
    /* 362 */ { -1, 0, WebAssembly::OPERAND_VEC_I32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I32IMM, 0 },
    /* 366 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I64IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I64IMM, 0 },
    /* 369 */ { -1, 0, WebAssembly::OPERAND_VEC_I64IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I64IMM, 0 },
    /* 371 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 },
    /* 388 */ { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 },
    /* 404 */ { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 406 */ { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 408 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 410 */ { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 411 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 412 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 413 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 414 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 415 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 417 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 420 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 423 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 426 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 },
    /* 429 */ { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 },
    /* 430 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 },
    /* 433 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 },
    /* 436 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 },
    /* 439 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 441 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 443 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 445 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 447 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 449 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 451 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 453 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 455 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 457 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 459 */ { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 },
    /* 461 */ { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 },
    /* 462 */ { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 },
    /* 464 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 },
    /* 466 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 },
    /* 468 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 },
    /* 470 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 },
    /* 472 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 },
    /* 474 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 },
    /* 476 */ { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 478 */ { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 480 */ { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 482 */ { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 484 */ { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 486 */ { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 488 */ { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 490 */ { -1, 0, WebAssembly::OPERAND_GLOBAL, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 492 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 498 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 500 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 504 */ { -1, 0, WebAssembly::OPERAND_SIGNATURE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 506 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 510 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 },
    /* 512 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 516 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 },
    /* 518 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 522 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 526 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 530 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 534 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 538 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 542 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 546 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 550 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 556 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 },
    /* 559 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 565 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 },
    /* 568 */ { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 },
    /* 570 */ { -1, 0, WebAssembly::OPERAND_LOCAL, 0 },
    /* 571 */ { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 },
    /* 573 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 },
    /* 575 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 },
    /* 577 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 },
    /* 579 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 },
    /* 581 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 },
    /* 583 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 },
    /* 585 */ { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 587 */ { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 589 */ { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 591 */ { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 593 */ { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 595 */ { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 597 */ { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 599 */ { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 601 */ { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 604 */ { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 607 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 610 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 613 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 616 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 619 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 622 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_LOCAL, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 625 */ { -1, 0, WebAssembly::OPERAND_I32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_I32IMM, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 630 */ { -1, 0, WebAssembly::OPERAND_I32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_I32IMM, 0 },
    /* 632 */ { -1, 0, WebAssembly::OPERAND_I32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_I32IMM, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 637 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 644 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 651 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 658 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_MEMORDER, 0 }, { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 665 */ { -1, 0, WebAssembly::OPERAND_I32IMM, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 669 */ { -1, 0, WebAssembly::OPERAND_I32IMM, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 673 */ { -1, 0, WebAssembly::OPERAND_I32IMM, 0 }, { -1, 0, WebAssembly::OPERAND_I32IMM, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 678 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_TYPEINDEX, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 681 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_FUNCTION32, 0 },
    /* 683 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 685 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 687 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 689 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_TYPEINDEX, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 692 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 696 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 700 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 704 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 708 */ { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 712 */ { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 716 */ { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 720 */ { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 724 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 728 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 732 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 736 */ { -1, 0, WebAssembly::OPERAND_VALTYPE_LIST, 0 },
    /* 737 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 741 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 744 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 },
    /* 763 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 765 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 767 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 769 */ { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 771 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 775 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 779 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 783 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 787 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 791 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 795 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 799 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::F64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 803 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 808 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { -1, 0, WebAssembly::OPERAND_VEC_I8IMM, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 813 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET32, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 817 */ { -1, 0, WebAssembly::OPERAND_P2ALIGN, 0 }, { -1, 0, WebAssembly::OPERAND_OFFSET64, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::V128RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 821 */ { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 826 */ { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { -1, 0, WebAssembly::OPERAND_TABLE, 0 },
    /* 828 */ { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 832 */ { -1, 0, WebAssembly::OPERAND_TABLE, 0 },
    /* 833 */ { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 837 */ { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 841 */ { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 844 */ { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 847 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 850 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 854 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 858 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 862 */ { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 865 */ { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 868 */ { -1, 0, WebAssembly::OPERAND_TABLE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 871 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, WebAssembly::OPERAND_TABLE, 0 },
    /* 873 */ { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 876 */ { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::EXTERNREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 879 */ { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { WebAssembly::FUNCREFRegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 882 */ { -1, 0, WebAssembly::OPERAND_SIGNATURE, 0 }, { -1, 0, WebAssembly::OPERAND_CATCH_LIST, 0 },
    /* 884 */ { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { WebAssembly::I32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
    /* 887 */ { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { WebAssembly::I64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 },
  }
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char WebAssemblyInstrNameData[] = {
  /* 0 */ "G_FLOG10\000"
  /* 9 */ "G_FEXP10\000"
  /* 18 */ "LOAD_F16_F32_A32\000"
  /* 35 */ "STORE_F16_F32_A32\000"
  /* 53 */ "LOAD_F32_A32\000"
  /* 66 */ "STORE_F32_A32\000"
  /* 80 */ "ATOMIC_STORE16_I32_A32\000"
  /* 103 */ "ATOMIC_STORE8_I32_A32\000"
  /* 125 */ "ATOMIC_RMW16_U_SUB_I32_A32\000"
  /* 152 */ "ATOMIC_RMW8_U_SUB_I32_A32\000"
  /* 178 */ "ATOMIC_RMW_SUB_I32_A32\000"
  /* 201 */ "ATOMIC_LOAD_I32_A32\000"
  /* 221 */ "ATOMIC_RMW16_U_ADD_I32_A32\000"
  /* 248 */ "ATOMIC_RMW8_U_ADD_I32_A32\000"
  /* 274 */ "ATOMIC_RMW_ADD_I32_A32\000"
  /* 297 */ "ATOMIC_RMW16_U_AND_I32_A32\000"
  /* 324 */ "ATOMIC_RMW8_U_AND_I32_A32\000"
  /* 350 */ "ATOMIC_RMW_AND_I32_A32\000"
  /* 373 */ "ATOMIC_STORE_I32_A32\000"
  /* 394 */ "ATOMIC_RMW16_U_CMPXCHG_I32_A32\000"
  /* 425 */ "ATOMIC_RMW8_U_CMPXCHG_I32_A32\000"
  /* 455 */ "ATOMIC_RMW_CMPXCHG_I32_A32\000"
  /* 482 */ "ATOMIC_RMW16_U_XCHG_I32_A32\000"
  /* 510 */ "ATOMIC_RMW8_U_XCHG_I32_A32\000"
  /* 537 */ "ATOMIC_RMW_XCHG_I32_A32\000"
  /* 561 */ "ATOMIC_RMW16_U_XOR_I32_A32\000"
  /* 588 */ "ATOMIC_RMW8_U_XOR_I32_A32\000"
  /* 614 */ "ATOMIC_RMW_XOR_I32_A32\000"
  /* 637 */ "ATOMIC_RMW16_U_OR_I32_A32\000"
  /* 663 */ "ATOMIC_RMW8_U_OR_I32_A32\000"
  /* 688 */ "ATOMIC_RMW_OR_I32_A32\000"
  /* 710 */ "LOAD16_S_I32_A32\000"
  /* 727 */ "LOAD8_S_I32_A32\000"
  /* 743 */ "ATOMIC_LOAD16_U_I32_A32\000"
  /* 767 */ "ATOMIC_LOAD8_U_I32_A32\000"
  /* 790 */ "MEMORY_ATOMIC_WAIT32_A32\000"
  /* 815 */ "LOAD_LANE_32_A32\000"
  /* 832 */ "LOAD_ZERO_32_A32\000"
  /* 849 */ "STORE_LANE_I64x2_A32\000"
  /* 870 */ "LOAD_EXTEND_S_I64x2_A32\000"
  /* 894 */ "LOAD_EXTEND_U_I64x2_A32\000"
  /* 918 */ "LOAD_F64_A32\000"
  /* 931 */ "STORE_F64_A32\000"
  /* 945 */ "ATOMIC_STORE32_I64_A32\000"
  /* 968 */ "ATOMIC_STORE16_I64_A32\000"
  /* 991 */ "ATOMIC_STORE8_I64_A32\000"
  /* 1013 */ "ATOMIC_RMW32_U_SUB_I64_A32\000"
  /* 1040 */ "ATOMIC_RMW16_U_SUB_I64_A32\000"
  /* 1067 */ "ATOMIC_RMW8_U_SUB_I64_A32\000"
  /* 1093 */ "ATOMIC_RMW_SUB_I64_A32\000"
  /* 1116 */ "ATOMIC_LOAD_I64_A32\000"
  /* 1136 */ "ATOMIC_RMW32_U_ADD_I64_A32\000"
  /* 1163 */ "ATOMIC_RMW16_U_ADD_I64_A32\000"
  /* 1190 */ "ATOMIC_RMW8_U_ADD_I64_A32\000"
  /* 1216 */ "ATOMIC_RMW_ADD_I64_A32\000"
  /* 1239 */ "ATOMIC_RMW32_U_AND_I64_A32\000"
  /* 1266 */ "ATOMIC_RMW16_U_AND_I64_A32\000"
  /* 1293 */ "ATOMIC_RMW8_U_AND_I64_A32\000"
  /* 1319 */ "ATOMIC_RMW_AND_I64_A32\000"
  /* 1342 */ "ATOMIC_STORE_I64_A32\000"
  /* 1363 */ "ATOMIC_RMW32_U_CMPXCHG_I64_A32\000"
  /* 1394 */ "ATOMIC_RMW16_U_CMPXCHG_I64_A32\000"
  /* 1425 */ "ATOMIC_RMW8_U_CMPXCHG_I64_A32\000"
  /* 1455 */ "ATOMIC_RMW_CMPXCHG_I64_A32\000"
  /* 1482 */ "ATOMIC_RMW32_U_XCHG_I64_A32\000"
  /* 1510 */ "ATOMIC_RMW16_U_XCHG_I64_A32\000"
  /* 1538 */ "ATOMIC_RMW8_U_XCHG_I64_A32\000"
  /* 1565 */ "ATOMIC_RMW_XCHG_I64_A32\000"
  /* 1589 */ "ATOMIC_RMW32_U_XOR_I64_A32\000"
  /* 1616 */ "ATOMIC_RMW16_U_XOR_I64_A32\000"
  /* 1643 */ "ATOMIC_RMW8_U_XOR_I64_A32\000"
  /* 1669 */ "ATOMIC_RMW_XOR_I64_A32\000"
  /* 1692 */ "ATOMIC_RMW32_U_OR_I64_A32\000"
  /* 1718 */ "ATOMIC_RMW16_U_OR_I64_A32\000"
  /* 1744 */ "ATOMIC_RMW8_U_OR_I64_A32\000"
  /* 1769 */ "ATOMIC_RMW_OR_I64_A32\000"
  /* 1791 */ "LOAD32_S_I64_A32\000"
  /* 1808 */ "LOAD16_S_I64_A32\000"
  /* 1825 */ "LOAD8_S_I64_A32\000"
  /* 1841 */ "ATOMIC_LOAD32_U_I64_A32\000"
  /* 1865 */ "ATOMIC_LOAD16_U_I64_A32\000"
  /* 1889 */ "ATOMIC_LOAD8_U_I64_A32\000"
  /* 1912 */ "MEMORY_ATOMIC_WAIT64_A32\000"
  /* 1937 */ "LOAD_LANE_64_A32\000"
  /* 1954 */ "LOAD_ZERO_64_A32\000"
  /* 1971 */ "STORE_LANE_I32x4_A32\000"
  /* 1992 */ "LOAD_EXTEND_S_I32x4_A32\000"
  /* 2016 */ "LOAD_EXTEND_U_I32x4_A32\000"
  /* 2040 */ "LOAD_LANE_16_A32\000"
  /* 2057 */ "STORE_LANE_I8x16_A32\000"
  /* 2078 */ "LOAD_V128_A32\000"
  /* 2092 */ "STORE_V128_A32\000"
  /* 2107 */ "LOAD_LANE_8_A32\000"
  /* 2123 */ "STORE_LANE_I16x8_A32\000"
  /* 2144 */ "LOAD_EXTEND_S_I16x8_A32\000"
  /* 2168 */ "LOAD_EXTEND_U_I16x8_A32\000"
  /* 2192 */ "anonymous_14027MEMORY_SIZE_A32\000"
  /* 2223 */ "MEMORY_FILL_A32\000"
  /* 2239 */ "LOAD32_SPLAT_A32\000"
  /* 2256 */ "LOAD64_SPLAT_A32\000"
  /* 2273 */ "LOAD16_SPLAT_A32\000"
  /* 2290 */ "LOAD8_SPLAT_A32\000"
  /* 2306 */ "MEMSET_A32\000"
  /* 2317 */ "MEMORY_INIT_A32\000"
  /* 2333 */ "anonymous_14027MEMORY_GROW_A32\000"
  /* 2364 */ "MEMORY_ATOMIC_NOTIFY_A32\000"
  /* 2389 */ "MEMCPY_A32\000"
  /* 2400 */ "MEMORY_COPY_A32\000"
  /* 2416 */ "FP_TO_SINT_I32_F32\000"
  /* 2435 */ "FP_TO_UINT_I32_F32\000"
  /* 2454 */ "FP_TO_SINT_I64_F32\000"
  /* 2473 */ "FP_TO_UINT_I64_F32\000"
  /* 2492 */ "SUB_F32\000"
  /* 2500 */ "TRUNC_F32\000"
  /* 2510 */ "ADD_F32\000"
  /* 2518 */ "LOCAL_TEE_F32\000"
  /* 2532 */ "GE_F32\000"
  /* 2539 */ "LE_F32\000"
  /* 2546 */ "NE_F32\000"
  /* 2553 */ "F64_PROMOTE_F32\000"
  /* 2569 */ "NEG_F32\000"
  /* 2577 */ "CEIL_F32\000"
  /* 2586 */ "MUL_F32\000"
  /* 2594 */ "COPYSIGN_F32\000"
  /* 2607 */ "MIN_F32\000"
  /* 2615 */ "DROP_F32\000"
  /* 2624 */ "EQ_F32\000"
  /* 2631 */ "FLOOR_F32\000"
  /* 2641 */ "ABS_F32\000"
  /* 2649 */ "I32_TRUNC_S_F32\000"
  /* 2665 */ "I64_TRUNC_S_F32\000"
  /* 2681 */ "I32_TRUNC_S_SAT_F32\000"
  /* 2701 */ "I64_TRUNC_S_SAT_F32\000"
  /* 2721 */ "I32_TRUNC_U_SAT_F32\000"
  /* 2741 */ "I64_TRUNC_U_SAT_F32\000"
  /* 2761 */ "SELECT_F32\000"
  /* 2772 */ "GLOBAL_GET_F32\000"
  /* 2787 */ "LOCAL_GET_F32\000"
  /* 2801 */ "I32_REINTERPRET_F32\000"
  /* 2821 */ "GLOBAL_SET_F32\000"
  /* 2836 */ "LOCAL_SET_F32\000"
  /* 2850 */ "GT_F32\000"
  /* 2857 */ "LT_F32\000"
  /* 2864 */ "SQRT_F32\000"
  /* 2873 */ "NEAREST_F32\000"
  /* 2885 */ "CONST_F32\000"
  /* 2895 */ "I32_TRUNC_U_F32\000"
  /* 2911 */ "I64_TRUNC_U_F32\000"
  /* 2927 */ "DIV_F32\000"
  /* 2935 */ "MAX_F32\000"
  /* 2943 */ "COPY_F32\000"
  /* 2952 */ "SUB_I32\000"
  /* 2960 */ "ADD_I32\000"
  /* 2968 */ "AND_I32\000"
  /* 2976 */ "LOCAL_TEE_I32\000"
  /* 2990 */ "BR_TABLE_I32\000"
  /* 3003 */ "NE_I32\000"
  /* 3010 */ "SHL_I32\000"
  /* 3018 */ "ROTL_I32\000"
  /* 3027 */ "MUL_I32\000"
  /* 3035 */ "DROP_I32\000"
  /* 3044 */ "EQ_I32\000"
  /* 3051 */ "XOR_I32\000"
  /* 3059 */ "ROTR_I32\000"
  /* 3068 */ "I32_EXTEND16_S_I32\000"
  /* 3087 */ "I32_EXTEND8_S_I32\000"
  /* 3105 */ "I64_EXTEND_S_I32\000"
  /* 3122 */ "GE_S_I32\000"
  /* 3131 */ "LE_S_I32\000"
  /* 3140 */ "REM_S_I32\000"
  /* 3150 */ "SHR_S_I32\000"
  /* 3160 */ "GT_S_I32\000"
  /* 3169 */ "LT_S_I32\000"
  /* 3178 */ "F32_CONVERT_S_I32\000"
  /* 3196 */ "F64_CONVERT_S_I32\000"
  /* 3214 */ "DIV_S_I32\000"
  /* 3224 */ "SELECT_I32\000"
  /* 3235 */ "GLOBAL_GET_I32\000"
  /* 3250 */ "LOCAL_GET_I32\000"
  /* 3264 */ "F32_REINTERPRET_I32\000"
  /* 3284 */ "GLOBAL_SET_I32\000"
  /* 3299 */ "LOCAL_SET_I32\000"
  /* 3313 */ "POPCNT_I32\000"
  /* 3324 */ "CONST_I32\000"
  /* 3334 */ "I64_EXTEND_U_I32\000"
  /* 3351 */ "GE_U_I32\000"
  /* 3360 */ "LE_U_I32\000"
  /* 3369 */ "REM_U_I32\000"
  /* 3379 */ "SHR_U_I32\000"
  /* 3389 */ "GT_U_I32\000"
  /* 3398 */ "LT_U_I32\000"
  /* 3407 */ "F32_CONVERT_U_I32\000"
  /* 3425 */ "F64_CONVERT_U_I32\000"
  /* 3443 */ "DIV_U_I32\000"
  /* 3453 */ "COPY_I32\000"
  /* 3462 */ "CLZ_I32\000"
  /* 3470 */ "EQZ_I32\000"
  /* 3478 */ "CTZ_I32\000"
  /* 3486 */ "ARGUMENT_v4f32\000"
  /* 3501 */ "ARGUMENT_f32\000"
  /* 3514 */ "ARGUMENT_v4i32\000"
  /* 3529 */ "ARGUMENT_i32\000"
  /* 3542 */ "G_FLOG2\000"
  /* 3550 */ "G_FATAN2\000"
  /* 3559 */ "G_FEXP2\000"
  /* 3567 */ "CONST_V128_F64x2\000"
  /* 3584 */ "SUB_F64x2\000"
  /* 3594 */ "TRUNC_F64x2\000"
  /* 3606 */ "NMADD_F64x2\000"
  /* 3618 */ "GE_F64x2\000"
  /* 3627 */ "LE_F64x2\000"
  /* 3636 */ "REPLACE_LANE_F64x2\000"
  /* 3655 */ "EXTRACT_LANE_F64x2\000"
  /* 3674 */ "NEG_F64x2\000"
  /* 3684 */ "CEIL_F64x2\000"
  /* 3695 */ "MUL_F64x2\000"
  /* 3705 */ "SIMD_RELAXED_FMIN_F64x2\000"
  /* 3729 */ "PMIN_F64x2\000"
  /* 3740 */ "EQ_F64x2\000"
  /* 3749 */ "FLOOR_F64x2\000"
  /* 3761 */ "ABS_F64x2\000"
  /* 3771 */ "SPLAT_F64x2\000"
  /* 3783 */ "GT_F64x2\000"
  /* 3792 */ "LT_F64x2\000"
  /* 3801 */ "SQRT_F64x2\000"
  /* 3812 */ "NEAREST_F64x2\000"
  /* 3826 */ "DIV_F64x2\000"
  /* 3836 */ "SIMD_RELAXED_FMAX_F64x2\000"
  /* 3860 */ "PMAX_F64x2\000"
  /* 3871 */ "convert_low_s_F64x2\000"
  /* 3891 */ "convert_low_u_F64x2\000"
  /* 3911 */ "promote_low_F64x2\000"
  /* 3929 */ "CONST_V128_I64x2\000"
  /* 3946 */ "SUB_I64x2\000"
  /* 3956 */ "ADD_I64x2\000"
  /* 3966 */ "REPLACE_LANE_I64x2\000"
  /* 3985 */ "EXTRACT_LANE_I64x2\000"
  /* 4004 */ "ALLTRUE_I64x2\000"
  /* 4018 */ "NEG_I64x2\000"
  /* 4028 */ "BITMASK_I64x2\000"
  /* 4042 */ "SHL_I64x2\000"
  /* 4052 */ "MUL_I64x2\000"
  /* 4062 */ "EQ_I64x2\000"
  /* 4071 */ "ABS_I64x2\000"
  /* 4081 */ "GE_S_I64x2\000"
  /* 4092 */ "LE_S_I64x2\000"
  /* 4103 */ "EXTMUL_HIGH_S_I64x2\000"
  /* 4123 */ "SHR_S_I64x2\000"
  /* 4135 */ "GT_S_I64x2\000"
  /* 4146 */ "LT_S_I64x2\000"
  /* 4157 */ "EXTMUL_LOW_S_I64x2\000"
  /* 4176 */ "SPLAT_I64x2\000"
  /* 4188 */ "LANESELECT_I64x2\000"
  /* 4205 */ "EXTMUL_HIGH_U_I64x2\000"
  /* 4225 */ "SHR_U_I64x2\000"
  /* 4237 */ "EXTMUL_LOW_U_I64x2\000"
  /* 4256 */ "extend_high_s_I64x2\000"
  /* 4276 */ "extend_low_s_I64x2\000"
  /* 4295 */ "extend_high_u_I64x2\000"
  /* 4315 */ "extend_low_u_I64x2\000"
  /* 4334 */ "LOAD_F16_F32_A64\000"
  /* 4351 */ "STORE_F16_F32_A64\000"
  /* 4369 */ "LOAD_F32_A64\000"
  /* 4382 */ "STORE_F32_A64\000"
  /* 4396 */ "ATOMIC_STORE16_I32_A64\000"
  /* 4419 */ "ATOMIC_STORE8_I32_A64\000"
  /* 4441 */ "ATOMIC_RMW16_U_SUB_I32_A64\000"
  /* 4468 */ "ATOMIC_RMW8_U_SUB_I32_A64\000"
  /* 4494 */ "ATOMIC_RMW_SUB_I32_A64\000"
  /* 4517 */ "ATOMIC_LOAD_I32_A64\000"
  /* 4537 */ "ATOMIC_RMW16_U_ADD_I32_A64\000"
  /* 4564 */ "ATOMIC_RMW8_U_ADD_I32_A64\000"
  /* 4590 */ "ATOMIC_RMW_ADD_I32_A64\000"
  /* 4613 */ "ATOMIC_RMW16_U_AND_I32_A64\000"
  /* 4640 */ "ATOMIC_RMW8_U_AND_I32_A64\000"
  /* 4666 */ "ATOMIC_RMW_AND_I32_A64\000"
  /* 4689 */ "ATOMIC_STORE_I32_A64\000"
  /* 4710 */ "ATOMIC_RMW16_U_CMPXCHG_I32_A64\000"
  /* 4741 */ "ATOMIC_RMW8_U_CMPXCHG_I32_A64\000"
  /* 4771 */ "ATOMIC_RMW_CMPXCHG_I32_A64\000"
  /* 4798 */ "ATOMIC_RMW16_U_XCHG_I32_A64\000"
  /* 4826 */ "ATOMIC_RMW8_U_XCHG_I32_A64\000"
  /* 4853 */ "ATOMIC_RMW_XCHG_I32_A64\000"
  /* 4877 */ "ATOMIC_RMW16_U_XOR_I32_A64\000"
  /* 4904 */ "ATOMIC_RMW8_U_XOR_I32_A64\000"
  /* 4930 */ "ATOMIC_RMW_XOR_I32_A64\000"
  /* 4953 */ "ATOMIC_RMW16_U_OR_I32_A64\000"
  /* 4979 */ "ATOMIC_RMW8_U_OR_I32_A64\000"
  /* 5004 */ "ATOMIC_RMW_OR_I32_A64\000"
  /* 5026 */ "LOAD16_S_I32_A64\000"
  /* 5043 */ "LOAD8_S_I32_A64\000"
  /* 5059 */ "ATOMIC_LOAD16_U_I32_A64\000"
  /* 5083 */ "ATOMIC_LOAD8_U_I32_A64\000"
  /* 5106 */ "MEMORY_ATOMIC_WAIT32_A64\000"
  /* 5131 */ "LOAD_LANE_32_A64\000"
  /* 5148 */ "LOAD_ZERO_32_A64\000"
  /* 5165 */ "STORE_LANE_I64x2_A64\000"
  /* 5186 */ "LOAD_EXTEND_S_I64x2_A64\000"
  /* 5210 */ "LOAD_EXTEND_U_I64x2_A64\000"
  /* 5234 */ "LOAD_F64_A64\000"
  /* 5247 */ "STORE_F64_A64\000"
  /* 5261 */ "ATOMIC_STORE32_I64_A64\000"
  /* 5284 */ "ATOMIC_STORE16_I64_A64\000"
  /* 5307 */ "ATOMIC_STORE8_I64_A64\000"
  /* 5329 */ "ATOMIC_RMW32_U_SUB_I64_A64\000"
  /* 5356 */ "ATOMIC_RMW16_U_SUB_I64_A64\000"
  /* 5383 */ "ATOMIC_RMW8_U_SUB_I64_A64\000"
  /* 5409 */ "ATOMIC_RMW_SUB_I64_A64\000"
  /* 5432 */ "ATOMIC_LOAD_I64_A64\000"
  /* 5452 */ "ATOMIC_RMW32_U_ADD_I64_A64\000"
  /* 5479 */ "ATOMIC_RMW16_U_ADD_I64_A64\000"
  /* 5506 */ "ATOMIC_RMW8_U_ADD_I64_A64\000"
  /* 5532 */ "ATOMIC_RMW_ADD_I64_A64\000"
  /* 5555 */ "ATOMIC_RMW32_U_AND_I64_A64\000"
  /* 5582 */ "ATOMIC_RMW16_U_AND_I64_A64\000"
  /* 5609 */ "ATOMIC_RMW8_U_AND_I64_A64\000"
  /* 5635 */ "ATOMIC_RMW_AND_I64_A64\000"
  /* 5658 */ "ATOMIC_STORE_I64_A64\000"
  /* 5679 */ "ATOMIC_RMW32_U_CMPXCHG_I64_A64\000"
  /* 5710 */ "ATOMIC_RMW16_U_CMPXCHG_I64_A64\000"
  /* 5741 */ "ATOMIC_RMW8_U_CMPXCHG_I64_A64\000"
  /* 5771 */ "ATOMIC_RMW_CMPXCHG_I64_A64\000"
  /* 5798 */ "ATOMIC_RMW32_U_XCHG_I64_A64\000"
  /* 5826 */ "ATOMIC_RMW16_U_XCHG_I64_A64\000"
  /* 5854 */ "ATOMIC_RMW8_U_XCHG_I64_A64\000"
  /* 5881 */ "ATOMIC_RMW_XCHG_I64_A64\000"
  /* 5905 */ "ATOMIC_RMW32_U_XOR_I64_A64\000"
  /* 5932 */ "ATOMIC_RMW16_U_XOR_I64_A64\000"
  /* 5959 */ "ATOMIC_RMW8_U_XOR_I64_A64\000"
  /* 5985 */ "ATOMIC_RMW_XOR_I64_A64\000"
  /* 6008 */ "ATOMIC_RMW32_U_OR_I64_A64\000"
  /* 6034 */ "ATOMIC_RMW16_U_OR_I64_A64\000"
  /* 6060 */ "ATOMIC_RMW8_U_OR_I64_A64\000"
  /* 6085 */ "ATOMIC_RMW_OR_I64_A64\000"
  /* 6107 */ "LOAD32_S_I64_A64\000"
  /* 6124 */ "LOAD16_S_I64_A64\000"
  /* 6141 */ "LOAD8_S_I64_A64\000"
  /* 6157 */ "ATOMIC_LOAD32_U_I64_A64\000"
  /* 6181 */ "ATOMIC_LOAD16_U_I64_A64\000"
  /* 6205 */ "ATOMIC_LOAD8_U_I64_A64\000"
  /* 6228 */ "MEMORY_ATOMIC_WAIT64_A64\000"
  /* 6253 */ "LOAD_LANE_64_A64\000"
  /* 6270 */ "LOAD_ZERO_64_A64\000"
  /* 6287 */ "STORE_LANE_I32x4_A64\000"
  /* 6308 */ "LOAD_EXTEND_S_I32x4_A64\000"
  /* 6332 */ "LOAD_EXTEND_U_I32x4_A64\000"
  /* 6356 */ "LOAD_LANE_16_A64\000"
  /* 6373 */ "STORE_LANE_I8x16_A64\000"
  /* 6394 */ "LOAD_V128_A64\000"
  /* 6408 */ "STORE_V128_A64\000"
  /* 6423 */ "LOAD_LANE_8_A64\000"
  /* 6439 */ "STORE_LANE_I16x8_A64\000"
  /* 6460 */ "LOAD_EXTEND_S_I16x8_A64\000"
  /* 6484 */ "LOAD_EXTEND_U_I16x8_A64\000"
  /* 6508 */ "anonymous_14028MEMORY_SIZE_A64\000"
  /* 6539 */ "MEMORY_FILL_A64\000"
  /* 6555 */ "LOAD32_SPLAT_A64\000"
  /* 6572 */ "LOAD64_SPLAT_A64\000"
  /* 6589 */ "LOAD16_SPLAT_A64\000"
  /* 6606 */ "LOAD8_SPLAT_A64\000"
  /* 6622 */ "MEMSET_A64\000"
  /* 6633 */ "MEMORY_INIT_A64\000"
  /* 6649 */ "anonymous_14028MEMORY_GROW_A64\000"
  /* 6680 */ "MEMORY_ATOMIC_NOTIFY_A64\000"
  /* 6705 */ "MEMCPY_A64\000"
  /* 6716 */ "MEMORY_COPY_A64\000"
  /* 6732 */ "FP_TO_SINT_I32_F64\000"
  /* 6751 */ "FP_TO_UINT_I32_F64\000"
  /* 6770 */ "FP_TO_SINT_I64_F64\000"
  /* 6789 */ "FP_TO_UINT_I64_F64\000"
  /* 6808 */ "SUB_F64\000"
  /* 6816 */ "TRUNC_F64\000"
  /* 6826 */ "ADD_F64\000"
  /* 6834 */ "LOCAL_TEE_F64\000"
  /* 6848 */ "GE_F64\000"
  /* 6855 */ "LE_F64\000"
  /* 6862 */ "NE_F64\000"
  /* 6869 */ "F32_DEMOTE_F64\000"
  /* 6884 */ "NEG_F64\000"
  /* 6892 */ "CEIL_F64\000"
  /* 6901 */ "MUL_F64\000"
  /* 6909 */ "COPYSIGN_F64\000"
  /* 6922 */ "MIN_F64\000"
  /* 6930 */ "DROP_F64\000"
  /* 6939 */ "EQ_F64\000"
  /* 6946 */ "FLOOR_F64\000"
  /* 6956 */ "ABS_F64\000"
  /* 6964 */ "I32_TRUNC_S_F64\000"
  /* 6980 */ "I64_TRUNC_S_F64\000"
  /* 6996 */ "I32_TRUNC_S_SAT_F64\000"
  /* 7016 */ "I64_TRUNC_S_SAT_F64\000"
  /* 7036 */ "I32_TRUNC_U_SAT_F64\000"
  /* 7056 */ "I64_TRUNC_U_SAT_F64\000"
  /* 7076 */ "SELECT_F64\000"
  /* 7087 */ "GLOBAL_GET_F64\000"
  /* 7102 */ "LOCAL_GET_F64\000"
  /* 7116 */ "I64_REINTERPRET_F64\000"
  /* 7136 */ "GLOBAL_SET_F64\000"
  /* 7151 */ "LOCAL_SET_F64\000"
  /* 7165 */ "GT_F64\000"
  /* 7172 */ "LT_F64\000"
  /* 7179 */ "SQRT_F64\000"
  /* 7188 */ "NEAREST_F64\000"
  /* 7200 */ "CONST_F64\000"
  /* 7210 */ "I32_TRUNC_U_F64\000"
  /* 7226 */ "I64_TRUNC_U_F64\000"
  /* 7242 */ "DIV_F64\000"
  /* 7250 */ "MAX_F64\000"
  /* 7258 */ "COPY_F64\000"
  /* 7267 */ "SUB_I64\000"
  /* 7275 */ "ADD_I64\000"
  /* 7283 */ "AND_I64\000"
  /* 7291 */ "LOCAL_TEE_I64\000"
  /* 7305 */ "BR_TABLE_I64\000"
  /* 7318 */ "NE_I64\000"
  /* 7325 */ "SHL_I64\000"
  /* 7333 */ "ROTL_I64\000"
  /* 7342 */ "MUL_I64\000"
  /* 7350 */ "I32_WRAP_I64\000"
  /* 7363 */ "DROP_I64\000"
  /* 7372 */ "EQ_I64\000"
  /* 7379 */ "XOR_I64\000"
  /* 7387 */ "ROTR_I64\000"
  /* 7396 */ "I64_EXTEND32_S_I64\000"
  /* 7415 */ "I64_EXTEND16_S_I64\000"
  /* 7434 */ "I64_EXTEND8_S_I64\000"
  /* 7452 */ "GE_S_I64\000"
  /* 7461 */ "LE_S_I64\000"
  /* 7470 */ "REM_S_I64\000"
  /* 7480 */ "SHR_S_I64\000"
  /* 7490 */ "GT_S_I64\000"
  /* 7499 */ "LT_S_I64\000"
  /* 7508 */ "F32_CONVERT_S_I64\000"
  /* 7526 */ "F64_CONVERT_S_I64\000"
  /* 7544 */ "DIV_S_I64\000"
  /* 7554 */ "SELECT_I64\000"
  /* 7565 */ "GLOBAL_GET_I64\000"
  /* 7580 */ "LOCAL_GET_I64\000"
  /* 7594 */ "F64_REINTERPRET_I64\000"
  /* 7614 */ "GLOBAL_SET_I64\000"
  /* 7629 */ "LOCAL_SET_I64\000"
  /* 7643 */ "POPCNT_I64\000"
  /* 7654 */ "CONST_I64\000"
  /* 7664 */ "GE_U_I64\000"
  /* 7673 */ "LE_U_I64\000"
  /* 7682 */ "REM_U_I64\000"
  /* 7692 */ "SHR_U_I64\000"
  /* 7702 */ "GT_U_I64\000"
  /* 7711 */ "LT_U_I64\000"
  /* 7720 */ "F32_CONVERT_U_I64\000"
  /* 7738 */ "F64_CONVERT_U_I64\000"
  /* 7756 */ "DIV_U_I64\000"
  /* 7766 */ "COPY_I64\000"
  /* 7775 */ "CLZ_I64\000"
  /* 7783 */ "EQZ_I64\000"
  /* 7791 */ "CTZ_I64\000"
  /* 7799 */ "ARGUMENT_v2f64\000"
  /* 7814 */ "ARGUMENT_f64\000"
  /* 7827 */ "ARGUMENT_v2i64\000"
  /* 7842 */ "ARGUMENT_i64\000"
  /* 7855 */ "CONST_V128_F32x4\000"
  /* 7872 */ "SUB_F32x4\000"
  /* 7882 */ "TRUNC_F32x4\000"
  /* 7894 */ "NMADD_F32x4\000"
  /* 7906 */ "GE_F32x4\000"
  /* 7915 */ "LE_F32x4\000"
  /* 7924 */ "REPLACE_LANE_F32x4\000"
  /* 7943 */ "EXTRACT_LANE_F32x4\000"
  /* 7962 */ "NEG_F32x4\000"
  /* 7972 */ "CEIL_F32x4\000"
  /* 7983 */ "MUL_F32x4\000"
  /* 7993 */ "SIMD_RELAXED_FMIN_F32x4\000"
  /* 8017 */ "PMIN_F32x4\000"
  /* 8028 */ "EQ_F32x4\000"
  /* 8037 */ "FLOOR_F32x4\000"
  /* 8049 */ "ABS_F32x4\000"
  /* 8059 */ "SPLAT_F32x4\000"
  /* 8071 */ "GT_F32x4\000"
  /* 8080 */ "LT_F32x4\000"
  /* 8089 */ "SQRT_F32x4\000"
  /* 8100 */ "NEAREST_F32x4\000"
  /* 8114 */ "DIV_F32x4\000"
  /* 8124 */ "SIMD_RELAXED_FMAX_F32x4\000"
  /* 8148 */ "PMAX_F32x4\000"
  /* 8159 */ "demote_zero_F32x4\000"
  /* 8177 */ "sint_to_fp_F32x4\000"
  /* 8194 */ "uint_to_fp_F32x4\000"
  /* 8211 */ "promote_low_F32x4\000"
  /* 8229 */ "CONST_V128_I32x4\000"
  /* 8246 */ "SUB_I32x4\000"
  /* 8256 */ "ADD_I32x4\000"
  /* 8266 */ "REPLACE_LANE_I32x4\000"
  /* 8285 */ "EXTRACT_LANE_I32x4\000"
  /* 8304 */ "ALLTRUE_I32x4\000"
  /* 8318 */ "NEG_I32x4\000"
  /* 8328 */ "BITMASK_I32x4\000"
  /* 8342 */ "SHL_I32x4\000"
  /* 8352 */ "MUL_I32x4\000"
  /* 8362 */ "EQ_I32x4\000"
  /* 8371 */ "ABS_I32x4\000"
  /* 8381 */ "GE_S_I32x4\000"
  /* 8392 */ "LE_S_I32x4\000"
  /* 8403 */ "EXTMUL_HIGH_S_I32x4\000"
  /* 8423 */ "MIN_S_I32x4\000"
  /* 8435 */ "SHR_S_I32x4\000"
  /* 8447 */ "GT_S_I32x4\000"
  /* 8458 */ "LT_S_I32x4\000"
  /* 8469 */ "EXTMUL_LOW_S_I32x4\000"
  /* 8488 */ "MAX_S_I32x4\000"
  /* 8500 */ "SPLAT_I32x4\000"
  /* 8512 */ "LANESELECT_I32x4\000"
  /* 8529 */ "GE_U_I32x4\000"
  /* 8540 */ "LE_U_I32x4\000"
  /* 8551 */ "EXTMUL_HIGH_U_I32x4\000"
  /* 8571 */ "MIN_U_I32x4\000"
  /* 8583 */ "SHR_U_I32x4\000"
  /* 8595 */ "GT_U_I32x4\000"
  /* 8606 */ "LT_U_I32x4\000"
  /* 8617 */ "EXTMUL_LOW_U_I32x4\000"
  /* 8636 */ "MAX_U_I32x4\000"
  /* 8648 */ "int_wasm_relaxed_trunc_signed_I32x4\000"
  /* 8684 */ "int_wasm_relaxed_trunc_unsigned_I32x4\000"
  /* 8722 */ "int_wasm_relaxed_trunc_signed_zero_I32x4\000"
  /* 8763 */ "int_wasm_relaxed_trunc_unsigned_zero_I32x4\000"
  /* 8806 */ "extadd_pairwise_s_I32x4\000"
  /* 8830 */ "extend_high_s_I32x4\000"
  /* 8850 */ "trunc_sat_zero_s_I32x4\000"
  /* 8873 */ "extend_low_s_I32x4\000"
  /* 8892 */ "fp_to_sint_I32x4\000"
  /* 8909 */ "fp_to_uint_I32x4\000"
  /* 8926 */ "extadd_pairwise_u_I32x4\000"
  /* 8950 */ "extend_high_u_I32x4\000"
  /* 8970 */ "trunc_sat_zero_u_I32x4\000"
  /* 8993 */ "extend_low_u_I32x4\000"
  /* 9012 */ "ARGUMENT_v8f16\000"
  /* 9027 */ "ARGUMENT_v8i16\000"
  /* 9042 */ "CONST_V128_I8x16\000"
  /* 9059 */ "SUB_I8x16\000"
  /* 9069 */ "ADD_I8x16\000"
  /* 9079 */ "REPLACE_LANE_I8x16\000"
  /* 9098 */ "ALLTRUE_I8x16\000"
  /* 9112 */ "NEG_I8x16\000"
  /* 9122 */ "BITMASK_I8x16\000"
  /* 9136 */ "SHL_I8x16\000"
  /* 9146 */ "EQ_I8x16\000"
  /* 9155 */ "ABS_I8x16\000"
  /* 9165 */ "GE_S_I8x16\000"
  /* 9176 */ "LE_S_I8x16\000"
  /* 9187 */ "MIN_S_I8x16\000"
  /* 9199 */ "SHR_S_I8x16\000"
  /* 9211 */ "SUB_SAT_S_I8x16\000"
  /* 9227 */ "ADD_SAT_S_I8x16\000"
  /* 9243 */ "GT_S_I8x16\000"
  /* 9254 */ "LT_S_I8x16\000"
  /* 9265 */ "NARROW_S_I8x16\000"
  /* 9280 */ "MAX_S_I8x16\000"
  /* 9292 */ "SPLAT_I8x16\000"
  /* 9304 */ "LANESELECT_I8x16\000"
  /* 9321 */ "POPCNT_I8x16\000"
  /* 9334 */ "GE_U_I8x16\000"
  /* 9345 */ "LE_U_I8x16\000"
  /* 9356 */ "MIN_U_I8x16\000"
  /* 9368 */ "AVGR_U_I8x16\000"
  /* 9381 */ "SHR_U_I8x16\000"
  /* 9393 */ "SUB_SAT_U_I8x16\000"
  /* 9409 */ "ADD_SAT_U_I8x16\000"
  /* 9425 */ "GT_U_I8x16\000"
  /* 9436 */ "LT_U_I8x16\000"
  /* 9447 */ "NARROW_U_I8x16\000"
  /* 9462 */ "MAX_U_I8x16\000"
  /* 9474 */ "I64_SUB128\000"
  /* 9485 */ "I64_ADD128\000"
  /* 9496 */ "LOCAL_TEE_V128\000"
  /* 9511 */ "DROP_V128\000"
  /* 9521 */ "SELECT_V128\000"
  /* 9533 */ "GLOBAL_GET_V128\000"
  /* 9549 */ "LOCAL_GET_V128\000"
  /* 9564 */ "GLOBAL_SET_V128\000"
  /* 9580 */ "LOCAL_SET_V128\000"
  /* 9595 */ "COPY_V128\000"
  /* 9605 */ "ARGUMENT_v16i8\000"
  /* 9620 */ "SUB_F16x8\000"
  /* 9630 */ "TRUNC_F16x8\000"
  /* 9642 */ "NMADD_F16x8\000"
  /* 9654 */ "GE_F16x8\000"
  /* 9663 */ "LE_F16x8\000"
  /* 9672 */ "REPLACE_LANE_F16x8\000"
  /* 9691 */ "EXTRACT_LANE_F16x8\000"
  /* 9710 */ "NEG_F16x8\000"
  /* 9720 */ "CEIL_F16x8\000"
  /* 9731 */ "MUL_F16x8\000"
  /* 9741 */ "PMIN_F16x8\000"
  /* 9752 */ "EQ_F16x8\000"
  /* 9761 */ "FLOOR_F16x8\000"
  /* 9773 */ "ABS_F16x8\000"
  /* 9783 */ "SPLAT_F16x8\000"
  /* 9795 */ "GT_F16x8\000"
  /* 9804 */ "LT_F16x8\000"
  /* 9813 */ "SQRT_F16x8\000"
  /* 9824 */ "NEAREST_F16x8\000"
  /* 9838 */ "DIV_F16x8\000"
  /* 9848 */ "PMAX_F16x8\000"
  /* 9859 */ "demote_zero_F16x8\000"
  /* 9877 */ "sint_to_fp_F16x8\000"
  /* 9894 */ "uint_to_fp_F16x8\000"
  /* 9911 */ "CONST_V128_I16x8\000"
  /* 9928 */ "SUB_I16x8\000"
  /* 9938 */ "ADD_I16x8\000"
  /* 9948 */ "REPLACE_LANE_I16x8\000"
  /* 9967 */ "ALLTRUE_I16x8\000"
  /* 9981 */ "NEG_I16x8\000"
  /* 9991 */ "BITMASK_I16x8\000"
  /* 10005 */ "SHL_I16x8\000"
  /* 10015 */ "MUL_I16x8\000"
  /* 10025 */ "EQ_I16x8\000"
  /* 10034 */ "ABS_I16x8\000"
  /* 10044 */ "GE_S_I16x8\000"
  /* 10055 */ "LE_S_I16x8\000"
  /* 10066 */ "EXTMUL_HIGH_S_I16x8\000"
  /* 10086 */ "MIN_S_I16x8\000"
  /* 10098 */ "SHR_S_I16x8\000"
  /* 10110 */ "RELAXED_Q15MULR_S_I16x8\000"
  /* 10134 */ "SUB_SAT_S_I16x8\000"
  /* 10150 */ "ADD_SAT_S_I16x8\000"
  /* 10166 */ "Q15MULR_SAT_S_I16x8\000"
  /* 10186 */ "GT_S_I16x8\000"
  /* 10197 */ "LT_S_I16x8\000"
  /* 10208 */ "EXTMUL_LOW_S_I16x8\000"
  /* 10227 */ "NARROW_S_I16x8\000"
  /* 10242 */ "MAX_S_I16x8\000"
  /* 10254 */ "SPLAT_I16x8\000"
  /* 10266 */ "LANESELECT_I16x8\000"
  /* 10283 */ "GE_U_I16x8\000"
  /* 10294 */ "LE_U_I16x8\000"
  /* 10305 */ "EXTMUL_HIGH_U_I16x8\000"
  /* 10325 */ "MIN_U_I16x8\000"
  /* 10337 */ "AVGR_U_I16x8\000"
  /* 10350 */ "SHR_U_I16x8\000"
  /* 10362 */ "SUB_SAT_U_I16x8\000"
  /* 10378 */ "ADD_SAT_U_I16x8\000"
  /* 10394 */ "GT_U_I16x8\000"
  /* 10405 */ "LT_U_I16x8\000"
  /* 10416 */ "EXTMUL_LOW_U_I16x8\000"
  /* 10435 */ "NARROW_U_I16x8\000"
  /* 10450 */ "MAX_U_I16x8\000"
  /* 10462 */ "extadd_pairwise_s_I16x8\000"
  /* 10486 */ "extend_high_s_I16x8\000"
  /* 10506 */ "extend_low_s_I16x8\000"
  /* 10525 */ "fp_to_sint_I16x8\000"
  /* 10542 */ "fp_to_uint_I16x8\000"
  /* 10559 */ "extadd_pairwise_u_I16x8\000"
  /* 10583 */ "extend_high_u_I16x8\000"
  /* 10603 */ "extend_low_u_I16x8\000"
  /* 10622 */ "G_FMA\000"
  /* 10628 */ "G_STRICT_FMA\000"
  /* 10641 */ "G_FSUB\000"
  /* 10648 */ "G_STRICT_FSUB\000"
  /* 10662 */ "G_ATOMICRMW_FSUB\000"
  /* 10679 */ "G_SUB\000"
  /* 10685 */ "G_ATOMICRMW_SUB\000"
  /* 10701 */ "G_INTRINSIC\000"
  /* 10713 */ "REF_FUNC\000"
  /* 10722 */ "G_FPTRUNC\000"
  /* 10732 */ "G_INTRINSIC_TRUNC\000"
  /* 10750 */ "G_TRUNC\000"
  /* 10758 */ "G_BUILD_VECTOR_TRUNC\000"
  /* 10779 */ "G_DYN_STACKALLOC\000"
  /* 10796 */ "G_FMAD\000"
  /* 10803 */ "G_FPEXTLOAD\000"
  /* 10815 */ "G_INDEXED_SEXTLOAD\000"
  /* 10834 */ "G_SEXTLOAD\000"
  /* 10845 */ "G_INDEXED_ZEXTLOAD\000"
  /* 10864 */ "G_ZEXTLOAD\000"
  /* 10875 */ "G_INDEXED_LOAD\000"
  /* 10890 */ "G_LOAD\000"
  /* 10897 */ "G_VECREDUCE_FADD\000"
  /* 10914 */ "G_FADD\000"
  /* 10921 */ "G_VECREDUCE_SEQ_FADD\000"
  /* 10942 */ "G_STRICT_FADD\000"
  /* 10956 */ "G_ATOMICRMW_FADD\000"
  /* 10973 */ "G_VECREDUCE_ADD\000"
  /* 10989 */ "G_ADD\000"
  /* 10995 */ "G_PTR_ADD\000"
  /* 11005 */ "RELAXED_DOT_ADD\000"
  /* 11021 */ "G_ATOMICRMW_ADD\000"
  /* 11037 */ "G_ATOMICRMW_NAND\000"
  /* 11054 */ "G_VECREDUCE_AND\000"
  /* 11070 */ "G_AND\000"
  /* 11076 */ "G_ATOMICRMW_AND\000"
  /* 11092 */ "LIFETIME_END\000"
  /* 11105 */ "G_BRCOND\000"
  /* 11114 */ "G_ATOMICRMW_USUB_COND\000"
  /* 11136 */ "G_LLROUND\000"
  /* 11146 */ "G_LROUND\000"
  /* 11155 */ "G_INTRINSIC_ROUND\000"
  /* 11173 */ "G_INTRINSIC_FPTRUNC_ROUND\000"
  /* 11199 */ "LOAD_STACK_GUARD\000"
  /* 11216 */ "PSEUDO_PROBE\000"
  /* 11229 */ "G_SSUBE\000"
  /* 11237 */ "G_USUBE\000"
  /* 11245 */ "ATOMIC_FENCE\000"
  /* 11258 */ "G_FENCE\000"
  /* 11266 */ "ARITH_FENCE\000"
  /* 11278 */ "COMPILER_FENCE\000"
  /* 11293 */ "REG_SEQUENCE\000"
  /* 11306 */ "G_SADDE\000"
  /* 11314 */ "G_UADDE\000"
  /* 11322 */ "G_GET_FPMODE\000"
  /* 11335 */ "G_RESET_FPMODE\000"
  /* 11350 */ "G_SET_FPMODE\000"
  /* 11363 */ "G_FMINNUM_IEEE\000"
  /* 11378 */ "G_FMAXNUM_IEEE\000"
  /* 11393 */ "G_VSCALE\000"
  /* 11402 */ "DEBUG_UNREACHABLE\000"
  /* 11420 */ "G_JUMP_TABLE\000"
  /* 11433 */ "END_TRY_TABLE\000"
  /* 11447 */ "BUNDLE\000"
  /* 11454 */ "SHUFFLE\000"
  /* 11462 */ "RELAXED_SWIZZLE\000"
  /* 11478 */ "G_MEMSET_INLINE\000"
  /* 11494 */ "G_MEMCPY_INLINE\000"
  /* 11510 */ "RELOC_NONE\000"
  /* 11521 */ "LOCAL_ESCAPE\000"
  /* 11534 */ "G_FPTRUNCSTORE\000"
  /* 11549 */ "G_STACKRESTORE\000"
  /* 11564 */ "G_INDEXED_STORE\000"
  /* 11580 */ "G_STORE\000"
  /* 11588 */ "ELSE\000"
  /* 11593 */ "G_BITREVERSE\000"
  /* 11606 */ "FAKE_USE\000"
  /* 11615 */ "DELEGATE\000"
  /* 11624 */ "DBG_VALUE\000"
  /* 11634 */ "G_GLOBAL_VALUE\000"
  /* 11649 */ "G_PTRAUTH_GLOBAL_VALUE\000"
  /* 11672 */ "CONVERGENCECTRL_GLUE\000"
  /* 11693 */ "ANYTRUE\000"
  /* 11701 */ "G_STACKSAVE\000"
  /* 11713 */ "G_MEMMOVE\000"
  /* 11723 */ "G_FREEZE\000"
  /* 11732 */ "G_FCANONICALIZE\000"
  /* 11748 */ "TABLE_SIZE\000"
  /* 11759 */ "G_FMODF\000"
  /* 11767 */ "INIT_UNDEF\000"
  /* 11778 */ "G_IMPLICIT_DEF\000"
  /* 11793 */ "LOCAL_TEE_FUNCREF\000"
  /* 11811 */ "TABLE_FILL_FUNCREF\000"
  /* 11830 */ "REF_NULL_FUNCREF\000"
  /* 11847 */ "REF_IS_NULL_FUNCREF\000"
  /* 11867 */ "DROP_FUNCREF\000"
  /* 11880 */ "SELECT_FUNCREF\000"
  /* 11895 */ "TABLE_GET_FUNCREF\000"
  /* 11913 */ "GLOBAL_GET_FUNCREF\000"
  /* 11932 */ "LOCAL_GET_FUNCREF\000"
  /* 11950 */ "TABLE_SET_FUNCREF\000"
  /* 11968 */ "GLOBAL_SET_FUNCREF\000"
  /* 11987 */ "LOCAL_SET_FUNCREF\000"
  /* 12005 */ "REF_CAST_FUNCREF\000"
  /* 12022 */ "REF_TEST_FUNCREF\000"
  /* 12039 */ "TABLE_GROW_FUNCREF\000"
  /* 12058 */ "COPY_FUNCREF\000"
  /* 12071 */ "LOCAL_TEE_EXTERNREF\000"
  /* 12091 */ "TABLE_FILL_EXTERNREF\000"
  /* 12112 */ "REF_NULL_EXTERNREF\000"
  /* 12131 */ "REF_IS_NULL_EXTERNREF\000"
  /* 12153 */ "DROP_EXTERNREF\000"
  /* 12168 */ "SELECT_EXTERNREF\000"
  /* 12185 */ "TABLE_GET_EXTERNREF\000"
  /* 12205 */ "GLOBAL_GET_EXTERNREF\000"
  /* 12226 */ "LOCAL_GET_EXTERNREF\000"
  /* 12246 */ "TABLE_SET_EXTERNREF\000"
  /* 12266 */ "GLOBAL_SET_EXTERNREF\000"
  /* 12287 */ "LOCAL_SET_EXTERNREF\000"
  /* 12307 */ "TABLE_GROW_EXTERNREF\000"
  /* 12328 */ "COPY_EXTERNREF\000"
  /* 12343 */ "LOCAL_TEE_EXNREF\000"
  /* 12360 */ "TABLE_FILL_EXNREF\000"
  /* 12378 */ "REF_NULL_EXNREF\000"
  /* 12394 */ "REF_IS_NULL_EXNREF\000"
  /* 12413 */ "DROP_EXNREF\000"
  /* 12425 */ "SELECT_EXNREF\000"
  /* 12439 */ "TABLE_GET_EXNREF\000"
  /* 12456 */ "GLOBAL_GET_EXNREF\000"
  /* 12474 */ "LOCAL_GET_EXNREF\000"
  /* 12491 */ "TABLE_SET_EXNREF\000"
  /* 12508 */ "GLOBAL_SET_EXNREF\000"
  /* 12526 */ "LOCAL_SET_EXNREF\000"
  /* 12543 */ "TABLE_GROW_EXNREF\000"
  /* 12561 */ "COPY_EXNREF\000"
  /* 12573 */ "CATCH_REF\000"
  /* 12583 */ "RET_CALL_REF\000"
  /* 12596 */ "CATCH_ALL_REF\000"
  /* 12610 */ "DBG_INSTR_REF\000"
  /* 12624 */ "THROW_REF\000"
  /* 12634 */ "END_IF\000"
  /* 12641 */ "BR_IF\000"
  /* 12647 */ "G_FNEG\000"
  /* 12654 */ "EXTRACT_SUBREG\000"
  /* 12669 */ "INSERT_SUBREG\000"
  /* 12683 */ "G_SEXT_INREG\000"
  /* 12696 */ "SUBREG_TO_REG\000"
  /* 12710 */ "G_ATOMIC_CMPXCHG\000"
  /* 12727 */ "G_ATOMICRMW_XCHG\000"
  /* 12744 */ "G_GET_ROUNDING\000"
  /* 12759 */ "G_SET_ROUNDING\000"
  /* 12774 */ "G_FLOG\000"
  /* 12781 */ "G_VAARG\000"
  /* 12789 */ "PREALLOCATED_ARG\000"
  /* 12806 */ "CATCH\000"
  /* 12812 */ "G_PREFETCH\000"
  /* 12823 */ "G_SMULH\000"
  /* 12831 */ "G_UMULH\000"
  /* 12839 */ "G_FTANH\000"
  /* 12847 */ "G_FSINH\000"
  /* 12855 */ "G_FCOSH\000"
  /* 12863 */ "DBG_PHI\000"
  /* 12871 */ "G_FPTOSI\000"
  /* 12880 */ "G_FPTOUI\000"
  /* 12889 */ "G_FPOWI\000"
  /* 12897 */ "END_BLOCK\000"
  /* 12907 */ "COPY_LANEMASK\000"
  /* 12921 */ "G_PTRMASK\000"
  /* 12931 */ "GC_LABEL\000"
  /* 12940 */ "DBG_LABEL\000"
  /* 12950 */ "EH_LABEL\000"
  /* 12959 */ "ANNOTATION_LABEL\000"
  /* 12976 */ "ICALL_BRANCH_FUNNEL\000"
  /* 12996 */ "G_FSHL\000"
  /* 13003 */ "G_SHL\000"
  /* 13009 */ "G_FCEIL\000"
  /* 13017 */ "G_SAVGCEIL\000"
  /* 13028 */ "G_UAVGCEIL\000"
  /* 13039 */ "PATCHABLE_TAIL_CALL\000"
  /* 13059 */ "RET_CALL\000"
  /* 13068 */ "PATCHABLE_TYPED_EVENT_CALL\000"
  /* 13095 */ "PATCHABLE_EVENT_CALL\000"
  /* 13116 */ "FENTRY_CALL\000"
  /* 13128 */ "CATCH_ALL\000"
  /* 13138 */ "KILL\000"
  /* 13143 */ "G_CONSTANT_POOL\000"
  /* 13159 */ "G_ROTL\000"
  /* 13166 */ "G_VECREDUCE_FMUL\000"
  /* 13183 */ "G_FMUL\000"
  /* 13190 */ "G_VECREDUCE_SEQ_FMUL\000"
  /* 13211 */ "G_STRICT_FMUL\000"
  /* 13225 */ "G_CLMUL\000"
  /* 13233 */ "G_VECREDUCE_MUL\000"
  /* 13249 */ "G_MUL\000"
  /* 13255 */ "G_FREM\000"
  /* 13262 */ "G_STRICT_FREM\000"
  /* 13276 */ "G_SREM\000"
  /* 13283 */ "G_UREM\000"
  /* 13290 */ "G_SDIVREM\000"
  /* 13300 */ "G_UDIVREM\000"
  /* 13310 */ "INLINEASM\000"
  /* 13320 */ "G_VECREDUCE_FMINIMUM\000"
  /* 13341 */ "G_FMINIMUM\000"
  /* 13352 */ "G_ATOMICRMW_FMINIMUM\000"
  /* 13373 */ "G_VECREDUCE_FMAXIMUM\000"
  /* 13394 */ "G_FMAXIMUM\000"
  /* 13405 */ "G_ATOMICRMW_FMAXIMUM\000"
  /* 13426 */ "G_FMINIMUMNUM\000"
  /* 13440 */ "G_ATOMICRMW_FMINIMUMNUM\000"
  /* 13464 */ "G_FMAXIMUMNUM\000"
  /* 13478 */ "G_ATOMICRMW_FMAXIMUMNUM\000"
  /* 13502 */ "G_FMINNUM\000"
  /* 13512 */ "G_FMAXNUM\000"
  /* 13522 */ "G_FATAN\000"
  /* 13530 */ "G_FTAN\000"
  /* 13537 */ "G_INTRINSIC_ROUNDEVEN\000"
  /* 13559 */ "G_ASSERT_ALIGN\000"
  /* 13574 */ "G_FCOPYSIGN\000"
  /* 13586 */ "G_VECREDUCE_FMIN\000"
  /* 13603 */ "G_ATOMICRMW_FMIN\000"
  /* 13620 */ "G_VECREDUCE_SMIN\000"
  /* 13637 */ "G_SMIN\000"
  /* 13644 */ "G_VECREDUCE_UMIN\000"
  /* 13661 */ "G_UMIN\000"
  /* 13668 */ "G_ATOMICRMW_UMIN\000"
  /* 13685 */ "G_ATOMICRMW_MIN\000"
  /* 13701 */ "G_FASIN\000"
  /* 13709 */ "G_FSIN\000"
  /* 13716 */ "END_FUNCTION\000"
  /* 13729 */ "CFI_INSTRUCTION\000"
  /* 13745 */ "G_CTLZ_ZERO_POISON\000"
  /* 13764 */ "G_CTTZ_ZERO_POISON\000"
  /* 13783 */ "FALLTHROUGH_RETURN\000"
  /* 13802 */ "ADJCALLSTACKDOWN\000"
  /* 13819 */ "G_SSUBO\000"
  /* 13827 */ "G_USUBO\000"
  /* 13835 */ "G_SADDO\000"
  /* 13843 */ "G_UADDO\000"
  /* 13851 */ "JUMP_TABLE_DEBUG_INFO\000"
  /* 13873 */ "G_SMULO\000"
  /* 13881 */ "G_UMULO\000"
  /* 13889 */ "G_BZERO\000"
  /* 13897 */ "STACKMAP\000"
  /* 13906 */ "G_DEBUGTRAP\000"
  /* 13918 */ "G_UBSANTRAP\000"
  /* 13930 */ "G_TRAP\000"
  /* 13937 */ "G_ATOMICRMW_UDEC_WRAP\000"
  /* 13959 */ "G_ATOMICRMW_UINC_WRAP\000"
  /* 13981 */ "G_BSWAP\000"
  /* 13989 */ "G_SITOFP\000"
  /* 13998 */ "G_UITOFP\000"
  /* 14007 */ "G_FCMP\000"
  /* 14014 */ "G_STRICT_FCMP\000"
  /* 14028 */ "G_ICMP\000"
  /* 14035 */ "G_SCMP\000"
  /* 14042 */ "G_UCMP\000"
  /* 14049 */ "NOP\000"
  /* 14053 */ "END_LOOP\000"
  /* 14062 */ "CONVERGENCECTRL_LOOP\000"
  /* 14083 */ "G_CTPOP\000"
  /* 14091 */ "DATA_DROP\000"
  /* 14101 */ "PATCHABLE_OP\000"
  /* 14114 */ "FAULTING_OP\000"
  /* 14126 */ "ADJCALLSTACKUP\000"
  /* 14141 */ "PREALLOCATED_SETUP\000"
  /* 14160 */ "G_FLDEXP\000"
  /* 14169 */ "G_STRICT_FLDEXP\000"
  /* 14185 */ "G_FEXP\000"
  /* 14192 */ "G_FFREXP\000"
  /* 14201 */ "G_BR\000"
  /* 14206 */ "INLINEASM_BR\000"
  /* 14219 */ "G_BLOCK_ADDR\000"
  /* 14232 */ "MEMBARRIER\000"
  /* 14243 */ "G_CONSTANT_FOLD_BARRIER\000"
  /* 14267 */ "PATCHABLE_FUNCTION_ENTER\000"
  /* 14292 */ "G_READCYCLECOUNTER\000"
  /* 14311 */ "G_READSTEADYCOUNTER\000"
  /* 14331 */ "G_READ_REGISTER\000"
  /* 14347 */ "G_WRITE_REGISTER\000"
  /* 14364 */ "G_ASHR\000"
  /* 14371 */ "G_FSHR\000"
  /* 14378 */ "G_LSHR\000"
  /* 14385 */ "CONVERGENCECTRL_ANCHOR\000"
  /* 14408 */ "G_FFLOOR\000"
  /* 14417 */ "G_SAVGFLOOR\000"
  /* 14429 */ "G_UAVGFLOOR\000"
  /* 14441 */ "G_EXTRACT_SUBVECTOR\000"
  /* 14461 */ "G_INSERT_SUBVECTOR\000"
  /* 14480 */ "G_BUILD_VECTOR\000"
  /* 14495 */ "G_SHUFFLE_VECTOR\000"
  /* 14512 */ "G_STEP_VECTOR\000"
  /* 14526 */ "G_SPLAT_VECTOR\000"
  /* 14541 */ "G_VECREDUCE_XOR\000"
  /* 14557 */ "G_XOR\000"
  /* 14563 */ "G_ATOMICRMW_XOR\000"
  /* 14579 */ "G_VECREDUCE_OR\000"
  /* 14594 */ "G_OR\000"
  /* 14599 */ "G_ATOMICRMW_OR\000"
  /* 14614 */ "G_ROTR\000"
  /* 14621 */ "G_INTTOPTR\000"
  /* 14632 */ "G_FABS\000"
  /* 14639 */ "G_ABS\000"
  /* 14645 */ "G_ABDS\000"
  /* 14652 */ "G_UNMERGE_VALUES\000"
  /* 14669 */ "G_MERGE_VALUES\000"
  /* 14684 */ "G_CTLS\000"
  /* 14691 */ "CALL_PARAMS\000"
  /* 14703 */ "G_FACOS\000"
  /* 14711 */ "G_FCOS\000"
  /* 14718 */ "G_FSINCOS\000"
  /* 14728 */ "G_STRICT_FCMPS\000"
  /* 14743 */ "G_CONCAT_VECTORS\000"
  /* 14760 */ "COPY_TO_REGCLASS\000"
  /* 14777 */ "G_IS_FPCLASS\000"
  /* 14790 */ "G_ATOMIC_CMPXCHG_WITH_SUCCESS\000"
  /* 14820 */ "BR_UNLESS\000"
  /* 14830 */ "G_VECTOR_COMPRESS\000"
  /* 14848 */ "G_INTRINSIC_W_SIDE_EFFECTS\000"
  /* 14875 */ "G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS\000"
  /* 14913 */ "RET_CALL_RESULTS\000"
  /* 14930 */ "LOAD_F16_F32_A32_S\000"
  /* 14949 */ "STORE_F16_F32_A32_S\000"
  /* 14969 */ "LOAD_F32_A32_S\000"
  /* 14984 */ "STORE_F32_A32_S\000"
  /* 15000 */ "ATOMIC_STORE16_I32_A32_S\000"
  /* 15025 */ "ATOMIC_STORE8_I32_A32_S\000"
  /* 15049 */ "ATOMIC_RMW16_U_SUB_I32_A32_S\000"
  /* 15078 */ "ATOMIC_RMW8_U_SUB_I32_A32_S\000"
  /* 15106 */ "ATOMIC_RMW_SUB_I32_A32_S\000"
  /* 15131 */ "ATOMIC_LOAD_I32_A32_S\000"
  /* 15153 */ "ATOMIC_RMW16_U_ADD_I32_A32_S\000"
  /* 15182 */ "ATOMIC_RMW8_U_ADD_I32_A32_S\000"
  /* 15210 */ "ATOMIC_RMW_ADD_I32_A32_S\000"
  /* 15235 */ "ATOMIC_RMW16_U_AND_I32_A32_S\000"
  /* 15264 */ "ATOMIC_RMW8_U_AND_I32_A32_S\000"
  /* 15292 */ "ATOMIC_RMW_AND_I32_A32_S\000"
  /* 15317 */ "ATOMIC_STORE_I32_A32_S\000"
  /* 15340 */ "ATOMIC_RMW16_U_CMPXCHG_I32_A32_S\000"
  /* 15373 */ "ATOMIC_RMW8_U_CMPXCHG_I32_A32_S\000"
  /* 15405 */ "ATOMIC_RMW_CMPXCHG_I32_A32_S\000"
  /* 15434 */ "ATOMIC_RMW16_U_XCHG_I32_A32_S\000"
  /* 15464 */ "ATOMIC_RMW8_U_XCHG_I32_A32_S\000"
  /* 15493 */ "ATOMIC_RMW_XCHG_I32_A32_S\000"
  /* 15519 */ "ATOMIC_RMW16_U_XOR_I32_A32_S\000"
  /* 15548 */ "ATOMIC_RMW8_U_XOR_I32_A32_S\000"
  /* 15576 */ "ATOMIC_RMW_XOR_I32_A32_S\000"
  /* 15601 */ "ATOMIC_RMW16_U_OR_I32_A32_S\000"
  /* 15629 */ "ATOMIC_RMW8_U_OR_I32_A32_S\000"
  /* 15656 */ "ATOMIC_RMW_OR_I32_A32_S\000"
  /* 15680 */ "LOAD16_S_I32_A32_S\000"
  /* 15699 */ "LOAD8_S_I32_A32_S\000"
  /* 15717 */ "ATOMIC_LOAD16_U_I32_A32_S\000"
  /* 15743 */ "ATOMIC_LOAD8_U_I32_A32_S\000"
  /* 15768 */ "MEMORY_ATOMIC_WAIT32_A32_S\000"
  /* 15795 */ "LOAD_LANE_32_A32_S\000"
  /* 15814 */ "LOAD_ZERO_32_A32_S\000"
  /* 15833 */ "STORE_LANE_I64x2_A32_S\000"
  /* 15856 */ "LOAD_EXTEND_S_I64x2_A32_S\000"
  /* 15882 */ "LOAD_EXTEND_U_I64x2_A32_S\000"
  /* 15908 */ "LOAD_F64_A32_S\000"
  /* 15923 */ "STORE_F64_A32_S\000"
  /* 15939 */ "ATOMIC_STORE32_I64_A32_S\000"
  /* 15964 */ "ATOMIC_STORE16_I64_A32_S\000"
  /* 15989 */ "ATOMIC_STORE8_I64_A32_S\000"
  /* 16013 */ "ATOMIC_RMW32_U_SUB_I64_A32_S\000"
  /* 16042 */ "ATOMIC_RMW16_U_SUB_I64_A32_S\000"
  /* 16071 */ "ATOMIC_RMW8_U_SUB_I64_A32_S\000"
  /* 16099 */ "ATOMIC_RMW_SUB_I64_A32_S\000"
  /* 16124 */ "ATOMIC_LOAD_I64_A32_S\000"
  /* 16146 */ "ATOMIC_RMW32_U_ADD_I64_A32_S\000"
  /* 16175 */ "ATOMIC_RMW16_U_ADD_I64_A32_S\000"
  /* 16204 */ "ATOMIC_RMW8_U_ADD_I64_A32_S\000"
  /* 16232 */ "ATOMIC_RMW_ADD_I64_A32_S\000"
  /* 16257 */ "ATOMIC_RMW32_U_AND_I64_A32_S\000"
  /* 16286 */ "ATOMIC_RMW16_U_AND_I64_A32_S\000"
  /* 16315 */ "ATOMIC_RMW8_U_AND_I64_A32_S\000"
  /* 16343 */ "ATOMIC_RMW_AND_I64_A32_S\000"
  /* 16368 */ "ATOMIC_STORE_I64_A32_S\000"
  /* 16391 */ "ATOMIC_RMW32_U_CMPXCHG_I64_A32_S\000"
  /* 16424 */ "ATOMIC_RMW16_U_CMPXCHG_I64_A32_S\000"
  /* 16457 */ "ATOMIC_RMW8_U_CMPXCHG_I64_A32_S\000"
  /* 16489 */ "ATOMIC_RMW_CMPXCHG_I64_A32_S\000"
  /* 16518 */ "ATOMIC_RMW32_U_XCHG_I64_A32_S\000"
  /* 16548 */ "ATOMIC_RMW16_U_XCHG_I64_A32_S\000"
  /* 16578 */ "ATOMIC_RMW8_U_XCHG_I64_A32_S\000"
  /* 16607 */ "ATOMIC_RMW_XCHG_I64_A32_S\000"
  /* 16633 */ "ATOMIC_RMW32_U_XOR_I64_A32_S\000"
  /* 16662 */ "ATOMIC_RMW16_U_XOR_I64_A32_S\000"
  /* 16691 */ "ATOMIC_RMW8_U_XOR_I64_A32_S\000"
  /* 16719 */ "ATOMIC_RMW_XOR_I64_A32_S\000"
  /* 16744 */ "ATOMIC_RMW32_U_OR_I64_A32_S\000"
  /* 16772 */ "ATOMIC_RMW16_U_OR_I64_A32_S\000"
  /* 16800 */ "ATOMIC_RMW8_U_OR_I64_A32_S\000"
  /* 16827 */ "ATOMIC_RMW_OR_I64_A32_S\000"
  /* 16851 */ "LOAD32_S_I64_A32_S\000"
  /* 16870 */ "LOAD16_S_I64_A32_S\000"
  /* 16889 */ "LOAD8_S_I64_A32_S\000"
  /* 16907 */ "ATOMIC_LOAD32_U_I64_A32_S\000"
  /* 16933 */ "ATOMIC_LOAD16_U_I64_A32_S\000"
  /* 16959 */ "ATOMIC_LOAD8_U_I64_A32_S\000"
  /* 16984 */ "MEMORY_ATOMIC_WAIT64_A32_S\000"
  /* 17011 */ "LOAD_LANE_64_A32_S\000"
  /* 17030 */ "LOAD_ZERO_64_A32_S\000"
  /* 17049 */ "STORE_LANE_I32x4_A32_S\000"
  /* 17072 */ "LOAD_EXTEND_S_I32x4_A32_S\000"
  /* 17098 */ "LOAD_EXTEND_U_I32x4_A32_S\000"
  /* 17124 */ "LOAD_LANE_16_A32_S\000"
  /* 17143 */ "STORE_LANE_I8x16_A32_S\000"
  /* 17166 */ "LOAD_V128_A32_S\000"
  /* 17182 */ "STORE_V128_A32_S\000"
  /* 17199 */ "LOAD_LANE_8_A32_S\000"
  /* 17217 */ "STORE_LANE_I16x8_A32_S\000"
  /* 17240 */ "LOAD_EXTEND_S_I16x8_A32_S\000"
  /* 17266 */ "LOAD_EXTEND_U_I16x8_A32_S\000"
  /* 17292 */ "anonymous_14027MEMORY_SIZE_A32_S\000"
  /* 17325 */ "MEMORY_FILL_A32_S\000"
  /* 17343 */ "LOAD32_SPLAT_A32_S\000"
  /* 17362 */ "LOAD64_SPLAT_A32_S\000"
  /* 17381 */ "LOAD16_SPLAT_A32_S\000"
  /* 17400 */ "LOAD8_SPLAT_A32_S\000"
  /* 17418 */ "MEMSET_A32_S\000"
  /* 17431 */ "MEMORY_INIT_A32_S\000"
  /* 17449 */ "anonymous_14027MEMORY_GROW_A32_S\000"
  /* 17482 */ "MEMORY_ATOMIC_NOTIFY_A32_S\000"
  /* 17509 */ "MEMCPY_A32_S\000"
  /* 17522 */ "MEMORY_COPY_A32_S\000"
  /* 17540 */ "FP_TO_SINT_I32_F32_S\000"
  /* 17561 */ "FP_TO_UINT_I32_F32_S\000"
  /* 17582 */ "FP_TO_SINT_I64_F32_S\000"
  /* 17603 */ "FP_TO_UINT_I64_F32_S\000"
  /* 17624 */ "SUB_F32_S\000"
  /* 17634 */ "TRUNC_F32_S\000"
  /* 17646 */ "ADD_F32_S\000"
  /* 17656 */ "LOCAL_TEE_F32_S\000"
  /* 17672 */ "GE_F32_S\000"
  /* 17681 */ "LE_F32_S\000"
  /* 17690 */ "NE_F32_S\000"
  /* 17699 */ "F64_PROMOTE_F32_S\000"
  /* 17717 */ "NEG_F32_S\000"
  /* 17727 */ "CEIL_F32_S\000"
  /* 17738 */ "MUL_F32_S\000"
  /* 17748 */ "COPYSIGN_F32_S\000"
  /* 17763 */ "MIN_F32_S\000"
  /* 17773 */ "DROP_F32_S\000"
  /* 17784 */ "EQ_F32_S\000"
  /* 17793 */ "FLOOR_F32_S\000"
  /* 17805 */ "ABS_F32_S\000"
  /* 17815 */ "I32_TRUNC_S_F32_S\000"
  /* 17833 */ "I64_TRUNC_S_F32_S\000"
  /* 17851 */ "I32_TRUNC_S_SAT_F32_S\000"
  /* 17873 */ "I64_TRUNC_S_SAT_F32_S\000"
  /* 17895 */ "I32_TRUNC_U_SAT_F32_S\000"
  /* 17917 */ "I64_TRUNC_U_SAT_F32_S\000"
  /* 17939 */ "SELECT_F32_S\000"
  /* 17952 */ "GLOBAL_GET_F32_S\000"
  /* 17969 */ "LOCAL_GET_F32_S\000"
  /* 17985 */ "I32_REINTERPRET_F32_S\000"
  /* 18007 */ "GLOBAL_SET_F32_S\000"
  /* 18024 */ "LOCAL_SET_F32_S\000"
  /* 18040 */ "GT_F32_S\000"
  /* 18049 */ "LT_F32_S\000"
  /* 18058 */ "SQRT_F32_S\000"
  /* 18069 */ "NEAREST_F32_S\000"
  /* 18083 */ "CONST_F32_S\000"
  /* 18095 */ "I32_TRUNC_U_F32_S\000"
  /* 18113 */ "I64_TRUNC_U_F32_S\000"
  /* 18131 */ "DIV_F32_S\000"
  /* 18141 */ "MAX_F32_S\000"
  /* 18151 */ "COPY_F32_S\000"
  /* 18162 */ "SUB_I32_S\000"
  /* 18172 */ "ADD_I32_S\000"
  /* 18182 */ "AND_I32_S\000"
  /* 18192 */ "LOCAL_TEE_I32_S\000"
  /* 18208 */ "BR_TABLE_I32_S\000"
  /* 18223 */ "NE_I32_S\000"
  /* 18232 */ "SHL_I32_S\000"
  /* 18242 */ "ROTL_I32_S\000"
  /* 18253 */ "MUL_I32_S\000"
  /* 18263 */ "DROP_I32_S\000"
  /* 18274 */ "EQ_I32_S\000"
  /* 18283 */ "XOR_I32_S\000"
  /* 18293 */ "ROTR_I32_S\000"
  /* 18304 */ "I32_EXTEND16_S_I32_S\000"
  /* 18325 */ "I32_EXTEND8_S_I32_S\000"
  /* 18345 */ "I64_EXTEND_S_I32_S\000"
  /* 18364 */ "GE_S_I32_S\000"
  /* 18375 */ "LE_S_I32_S\000"
  /* 18386 */ "REM_S_I32_S\000"
  /* 18398 */ "SHR_S_I32_S\000"
  /* 18410 */ "GT_S_I32_S\000"
  /* 18421 */ "LT_S_I32_S\000"
  /* 18432 */ "F32_CONVERT_S_I32_S\000"
  /* 18452 */ "F64_CONVERT_S_I32_S\000"
  /* 18472 */ "DIV_S_I32_S\000"
  /* 18484 */ "SELECT_I32_S\000"
  /* 18497 */ "GLOBAL_GET_I32_S\000"
  /* 18514 */ "LOCAL_GET_I32_S\000"
  /* 18530 */ "F32_REINTERPRET_I32_S\000"
  /* 18552 */ "GLOBAL_SET_I32_S\000"
  /* 18569 */ "LOCAL_SET_I32_S\000"
  /* 18585 */ "POPCNT_I32_S\000"
  /* 18598 */ "CONST_I32_S\000"
  /* 18610 */ "I64_EXTEND_U_I32_S\000"
  /* 18629 */ "GE_U_I32_S\000"
  /* 18640 */ "LE_U_I32_S\000"
  /* 18651 */ "REM_U_I32_S\000"
  /* 18663 */ "SHR_U_I32_S\000"
  /* 18675 */ "GT_U_I32_S\000"
  /* 18686 */ "LT_U_I32_S\000"
  /* 18697 */ "F32_CONVERT_U_I32_S\000"
  /* 18717 */ "F64_CONVERT_U_I32_S\000"
  /* 18737 */ "DIV_U_I32_S\000"
  /* 18749 */ "COPY_I32_S\000"
  /* 18760 */ "CLZ_I32_S\000"
  /* 18770 */ "EQZ_I32_S\000"
  /* 18780 */ "CTZ_I32_S\000"
  /* 18790 */ "ARGUMENT_v4f32_S\000"
  /* 18807 */ "ARGUMENT_f32_S\000"
  /* 18822 */ "ARGUMENT_v4i32_S\000"
  /* 18839 */ "ARGUMENT_i32_S\000"
  /* 18854 */ "CONST_V128_F64x2_S\000"
  /* 18873 */ "SUB_F64x2_S\000"
  /* 18885 */ "TRUNC_F64x2_S\000"
  /* 18899 */ "NMADD_F64x2_S\000"
  /* 18913 */ "GE_F64x2_S\000"
  /* 18924 */ "LE_F64x2_S\000"
  /* 18935 */ "REPLACE_LANE_F64x2_S\000"
  /* 18956 */ "EXTRACT_LANE_F64x2_S\000"
  /* 18977 */ "NEG_F64x2_S\000"
  /* 18989 */ "CEIL_F64x2_S\000"
  /* 19002 */ "MUL_F64x2_S\000"
  /* 19014 */ "SIMD_RELAXED_FMIN_F64x2_S\000"
  /* 19040 */ "PMIN_F64x2_S\000"
  /* 19053 */ "EQ_F64x2_S\000"
  /* 19064 */ "FLOOR_F64x2_S\000"
  /* 19078 */ "ABS_F64x2_S\000"
  /* 19090 */ "SPLAT_F64x2_S\000"
  /* 19104 */ "GT_F64x2_S\000"
  /* 19115 */ "LT_F64x2_S\000"
  /* 19126 */ "SQRT_F64x2_S\000"
  /* 19139 */ "NEAREST_F64x2_S\000"
  /* 19155 */ "DIV_F64x2_S\000"
  /* 19167 */ "SIMD_RELAXED_FMAX_F64x2_S\000"
  /* 19193 */ "PMAX_F64x2_S\000"
  /* 19206 */ "convert_low_s_F64x2_S\000"
  /* 19228 */ "convert_low_u_F64x2_S\000"
  /* 19250 */ "promote_low_F64x2_S\000"
  /* 19270 */ "CONST_V128_I64x2_S\000"
  /* 19289 */ "SUB_I64x2_S\000"
  /* 19301 */ "ADD_I64x2_S\000"
  /* 19313 */ "REPLACE_LANE_I64x2_S\000"
  /* 19334 */ "EXTRACT_LANE_I64x2_S\000"
  /* 19355 */ "ALLTRUE_I64x2_S\000"
  /* 19371 */ "NEG_I64x2_S\000"
  /* 19383 */ "BITMASK_I64x2_S\000"
  /* 19399 */ "SHL_I64x2_S\000"
  /* 19411 */ "MUL_I64x2_S\000"
  /* 19423 */ "EQ_I64x2_S\000"
  /* 19434 */ "ABS_I64x2_S\000"
  /* 19446 */ "GE_S_I64x2_S\000"
  /* 19459 */ "LE_S_I64x2_S\000"
  /* 19472 */ "EXTMUL_HIGH_S_I64x2_S\000"
  /* 19494 */ "SHR_S_I64x2_S\000"
  /* 19508 */ "GT_S_I64x2_S\000"
  /* 19521 */ "LT_S_I64x2_S\000"
  /* 19534 */ "EXTMUL_LOW_S_I64x2_S\000"
  /* 19555 */ "SPLAT_I64x2_S\000"
  /* 19569 */ "LANESELECT_I64x2_S\000"
  /* 19588 */ "EXTMUL_HIGH_U_I64x2_S\000"
  /* 19610 */ "SHR_U_I64x2_S\000"
  /* 19624 */ "EXTMUL_LOW_U_I64x2_S\000"
  /* 19645 */ "extend_high_s_I64x2_S\000"
  /* 19667 */ "extend_low_s_I64x2_S\000"
  /* 19688 */ "extend_high_u_I64x2_S\000"
  /* 19710 */ "extend_low_u_I64x2_S\000"
  /* 19731 */ "LOAD_F16_F32_A64_S\000"
  /* 19750 */ "STORE_F16_F32_A64_S\000"
  /* 19770 */ "LOAD_F32_A64_S\000"
  /* 19785 */ "STORE_F32_A64_S\000"
  /* 19801 */ "ATOMIC_STORE16_I32_A64_S\000"
  /* 19826 */ "ATOMIC_STORE8_I32_A64_S\000"
  /* 19850 */ "ATOMIC_RMW16_U_SUB_I32_A64_S\000"
  /* 19879 */ "ATOMIC_RMW8_U_SUB_I32_A64_S\000"
  /* 19907 */ "ATOMIC_RMW_SUB_I32_A64_S\000"
  /* 19932 */ "ATOMIC_LOAD_I32_A64_S\000"
  /* 19954 */ "ATOMIC_RMW16_U_ADD_I32_A64_S\000"
  /* 19983 */ "ATOMIC_RMW8_U_ADD_I32_A64_S\000"
  /* 20011 */ "ATOMIC_RMW_ADD_I32_A64_S\000"
  /* 20036 */ "ATOMIC_RMW16_U_AND_I32_A64_S\000"
  /* 20065 */ "ATOMIC_RMW8_U_AND_I32_A64_S\000"
  /* 20093 */ "ATOMIC_RMW_AND_I32_A64_S\000"
  /* 20118 */ "ATOMIC_STORE_I32_A64_S\000"
  /* 20141 */ "ATOMIC_RMW16_U_CMPXCHG_I32_A64_S\000"
  /* 20174 */ "ATOMIC_RMW8_U_CMPXCHG_I32_A64_S\000"
  /* 20206 */ "ATOMIC_RMW_CMPXCHG_I32_A64_S\000"
  /* 20235 */ "ATOMIC_RMW16_U_XCHG_I32_A64_S\000"
  /* 20265 */ "ATOMIC_RMW8_U_XCHG_I32_A64_S\000"
  /* 20294 */ "ATOMIC_RMW_XCHG_I32_A64_S\000"
  /* 20320 */ "ATOMIC_RMW16_U_XOR_I32_A64_S\000"
  /* 20349 */ "ATOMIC_RMW8_U_XOR_I32_A64_S\000"
  /* 20377 */ "ATOMIC_RMW_XOR_I32_A64_S\000"
  /* 20402 */ "ATOMIC_RMW16_U_OR_I32_A64_S\000"
  /* 20430 */ "ATOMIC_RMW8_U_OR_I32_A64_S\000"
  /* 20457 */ "ATOMIC_RMW_OR_I32_A64_S\000"
  /* 20481 */ "LOAD16_S_I32_A64_S\000"
  /* 20500 */ "LOAD8_S_I32_A64_S\000"
  /* 20518 */ "ATOMIC_LOAD16_U_I32_A64_S\000"
  /* 20544 */ "ATOMIC_LOAD8_U_I32_A64_S\000"
  /* 20569 */ "MEMORY_ATOMIC_WAIT32_A64_S\000"
  /* 20596 */ "LOAD_LANE_32_A64_S\000"
  /* 20615 */ "LOAD_ZERO_32_A64_S\000"
  /* 20634 */ "STORE_LANE_I64x2_A64_S\000"
  /* 20657 */ "LOAD_EXTEND_S_I64x2_A64_S\000"
  /* 20683 */ "LOAD_EXTEND_U_I64x2_A64_S\000"
  /* 20709 */ "LOAD_F64_A64_S\000"
  /* 20724 */ "STORE_F64_A64_S\000"
  /* 20740 */ "ATOMIC_STORE32_I64_A64_S\000"
  /* 20765 */ "ATOMIC_STORE16_I64_A64_S\000"
  /* 20790 */ "ATOMIC_STORE8_I64_A64_S\000"
  /* 20814 */ "ATOMIC_RMW32_U_SUB_I64_A64_S\000"
  /* 20843 */ "ATOMIC_RMW16_U_SUB_I64_A64_S\000"
  /* 20872 */ "ATOMIC_RMW8_U_SUB_I64_A64_S\000"
  /* 20900 */ "ATOMIC_RMW_SUB_I64_A64_S\000"
  /* 20925 */ "ATOMIC_LOAD_I64_A64_S\000"
  /* 20947 */ "ATOMIC_RMW32_U_ADD_I64_A64_S\000"
  /* 20976 */ "ATOMIC_RMW16_U_ADD_I64_A64_S\000"
  /* 21005 */ "ATOMIC_RMW8_U_ADD_I64_A64_S\000"
  /* 21033 */ "ATOMIC_RMW_ADD_I64_A64_S\000"
  /* 21058 */ "ATOMIC_RMW32_U_AND_I64_A64_S\000"
  /* 21087 */ "ATOMIC_RMW16_U_AND_I64_A64_S\000"
  /* 21116 */ "ATOMIC_RMW8_U_AND_I64_A64_S\000"
  /* 21144 */ "ATOMIC_RMW_AND_I64_A64_S\000"
  /* 21169 */ "ATOMIC_STORE_I64_A64_S\000"
  /* 21192 */ "ATOMIC_RMW32_U_CMPXCHG_I64_A64_S\000"
  /* 21225 */ "ATOMIC_RMW16_U_CMPXCHG_I64_A64_S\000"
  /* 21258 */ "ATOMIC_RMW8_U_CMPXCHG_I64_A64_S\000"
  /* 21290 */ "ATOMIC_RMW_CMPXCHG_I64_A64_S\000"
  /* 21319 */ "ATOMIC_RMW32_U_XCHG_I64_A64_S\000"
  /* 21349 */ "ATOMIC_RMW16_U_XCHG_I64_A64_S\000"
  /* 21379 */ "ATOMIC_RMW8_U_XCHG_I64_A64_S\000"
  /* 21408 */ "ATOMIC_RMW_XCHG_I64_A64_S\000"
  /* 21434 */ "ATOMIC_RMW32_U_XOR_I64_A64_S\000"
  /* 21463 */ "ATOMIC_RMW16_U_XOR_I64_A64_S\000"
  /* 21492 */ "ATOMIC_RMW8_U_XOR_I64_A64_S\000"
  /* 21520 */ "ATOMIC_RMW_XOR_I64_A64_S\000"
  /* 21545 */ "ATOMIC_RMW32_U_OR_I64_A64_S\000"
  /* 21573 */ "ATOMIC_RMW16_U_OR_I64_A64_S\000"
  /* 21601 */ "ATOMIC_RMW8_U_OR_I64_A64_S\000"
  /* 21628 */ "ATOMIC_RMW_OR_I64_A64_S\000"
  /* 21652 */ "LOAD32_S_I64_A64_S\000"
  /* 21671 */ "LOAD16_S_I64_A64_S\000"
  /* 21690 */ "LOAD8_S_I64_A64_S\000"
  /* 21708 */ "ATOMIC_LOAD32_U_I64_A64_S\000"
  /* 21734 */ "ATOMIC_LOAD16_U_I64_A64_S\000"
  /* 21760 */ "ATOMIC_LOAD8_U_I64_A64_S\000"
  /* 21785 */ "MEMORY_ATOMIC_WAIT64_A64_S\000"
  /* 21812 */ "LOAD_LANE_64_A64_S\000"
  /* 21831 */ "LOAD_ZERO_64_A64_S\000"
  /* 21850 */ "STORE_LANE_I32x4_A64_S\000"
  /* 21873 */ "LOAD_EXTEND_S_I32x4_A64_S\000"
  /* 21899 */ "LOAD_EXTEND_U_I32x4_A64_S\000"
  /* 21925 */ "LOAD_LANE_16_A64_S\000"
  /* 21944 */ "STORE_LANE_I8x16_A64_S\000"
  /* 21967 */ "LOAD_V128_A64_S\000"
  /* 21983 */ "STORE_V128_A64_S\000"
  /* 22000 */ "LOAD_LANE_8_A64_S\000"
  /* 22018 */ "STORE_LANE_I16x8_A64_S\000"
  /* 22041 */ "LOAD_EXTEND_S_I16x8_A64_S\000"
  /* 22067 */ "LOAD_EXTEND_U_I16x8_A64_S\000"
  /* 22093 */ "anonymous_14028MEMORY_SIZE_A64_S\000"
  /* 22126 */ "MEMORY_FILL_A64_S\000"
  /* 22144 */ "LOAD32_SPLAT_A64_S\000"
  /* 22163 */ "LOAD64_SPLAT_A64_S\000"
  /* 22182 */ "LOAD16_SPLAT_A64_S\000"
  /* 22201 */ "LOAD8_SPLAT_A64_S\000"
  /* 22219 */ "MEMSET_A64_S\000"
  /* 22232 */ "MEMORY_INIT_A64_S\000"
  /* 22250 */ "anonymous_14028MEMORY_GROW_A64_S\000"
  /* 22283 */ "MEMORY_ATOMIC_NOTIFY_A64_S\000"
  /* 22310 */ "MEMCPY_A64_S\000"
  /* 22323 */ "MEMORY_COPY_A64_S\000"
  /* 22341 */ "FP_TO_SINT_I32_F64_S\000"
  /* 22362 */ "FP_TO_UINT_I32_F64_S\000"
  /* 22383 */ "FP_TO_SINT_I64_F64_S\000"
  /* 22404 */ "FP_TO_UINT_I64_F64_S\000"
  /* 22425 */ "SUB_F64_S\000"
  /* 22435 */ "TRUNC_F64_S\000"
  /* 22447 */ "ADD_F64_S\000"
  /* 22457 */ "LOCAL_TEE_F64_S\000"
  /* 22473 */ "GE_F64_S\000"
  /* 22482 */ "LE_F64_S\000"
  /* 22491 */ "NE_F64_S\000"
  /* 22500 */ "F32_DEMOTE_F64_S\000"
  /* 22517 */ "NEG_F64_S\000"
  /* 22527 */ "CEIL_F64_S\000"
  /* 22538 */ "MUL_F64_S\000"
  /* 22548 */ "COPYSIGN_F64_S\000"
  /* 22563 */ "MIN_F64_S\000"
  /* 22573 */ "DROP_F64_S\000"
  /* 22584 */ "EQ_F64_S\000"
  /* 22593 */ "FLOOR_F64_S\000"
  /* 22605 */ "ABS_F64_S\000"
  /* 22615 */ "I32_TRUNC_S_F64_S\000"
  /* 22633 */ "I64_TRUNC_S_F64_S\000"
  /* 22651 */ "I32_TRUNC_S_SAT_F64_S\000"
  /* 22673 */ "I64_TRUNC_S_SAT_F64_S\000"
  /* 22695 */ "I32_TRUNC_U_SAT_F64_S\000"
  /* 22717 */ "I64_TRUNC_U_SAT_F64_S\000"
  /* 22739 */ "SELECT_F64_S\000"
  /* 22752 */ "GLOBAL_GET_F64_S\000"
  /* 22769 */ "LOCAL_GET_F64_S\000"
  /* 22785 */ "I64_REINTERPRET_F64_S\000"
  /* 22807 */ "GLOBAL_SET_F64_S\000"
  /* 22824 */ "LOCAL_SET_F64_S\000"
  /* 22840 */ "GT_F64_S\000"
  /* 22849 */ "LT_F64_S\000"
  /* 22858 */ "SQRT_F64_S\000"
  /* 22869 */ "NEAREST_F64_S\000"
  /* 22883 */ "CONST_F64_S\000"
  /* 22895 */ "I32_TRUNC_U_F64_S\000"
  /* 22913 */ "I64_TRUNC_U_F64_S\000"
  /* 22931 */ "DIV_F64_S\000"
  /* 22941 */ "MAX_F64_S\000"
  /* 22951 */ "COPY_F64_S\000"
  /* 22962 */ "SUB_I64_S\000"
  /* 22972 */ "ADD_I64_S\000"
  /* 22982 */ "AND_I64_S\000"
  /* 22992 */ "LOCAL_TEE_I64_S\000"
  /* 23008 */ "BR_TABLE_I64_S\000"
  /* 23023 */ "NE_I64_S\000"
  /* 23032 */ "SHL_I64_S\000"
  /* 23042 */ "ROTL_I64_S\000"
  /* 23053 */ "MUL_I64_S\000"
  /* 23063 */ "I32_WRAP_I64_S\000"
  /* 23078 */ "DROP_I64_S\000"
  /* 23089 */ "EQ_I64_S\000"
  /* 23098 */ "XOR_I64_S\000"
  /* 23108 */ "ROTR_I64_S\000"
  /* 23119 */ "I64_EXTEND32_S_I64_S\000"
  /* 23140 */ "I64_EXTEND16_S_I64_S\000"
  /* 23161 */ "I64_EXTEND8_S_I64_S\000"
  /* 23181 */ "GE_S_I64_S\000"
  /* 23192 */ "LE_S_I64_S\000"
  /* 23203 */ "REM_S_I64_S\000"
  /* 23215 */ "SHR_S_I64_S\000"
  /* 23227 */ "GT_S_I64_S\000"
  /* 23238 */ "LT_S_I64_S\000"
  /* 23249 */ "F32_CONVERT_S_I64_S\000"
  /* 23269 */ "F64_CONVERT_S_I64_S\000"
  /* 23289 */ "DIV_S_I64_S\000"
  /* 23301 */ "SELECT_I64_S\000"
  /* 23314 */ "GLOBAL_GET_I64_S\000"
  /* 23331 */ "LOCAL_GET_I64_S\000"
  /* 23347 */ "F64_REINTERPRET_I64_S\000"
  /* 23369 */ "GLOBAL_SET_I64_S\000"
  /* 23386 */ "LOCAL_SET_I64_S\000"
  /* 23402 */ "POPCNT_I64_S\000"
  /* 23415 */ "CONST_I64_S\000"
  /* 23427 */ "GE_U_I64_S\000"
  /* 23438 */ "LE_U_I64_S\000"
  /* 23449 */ "REM_U_I64_S\000"
  /* 23461 */ "SHR_U_I64_S\000"
  /* 23473 */ "GT_U_I64_S\000"
  /* 23484 */ "LT_U_I64_S\000"
  /* 23495 */ "F32_CONVERT_U_I64_S\000"
  /* 23515 */ "F64_CONVERT_U_I64_S\000"
  /* 23535 */ "DIV_U_I64_S\000"
  /* 23547 */ "COPY_I64_S\000"
  /* 23558 */ "CLZ_I64_S\000"
  /* 23568 */ "EQZ_I64_S\000"
  /* 23578 */ "CTZ_I64_S\000"
  /* 23588 */ "ARGUMENT_v2f64_S\000"
  /* 23605 */ "ARGUMENT_f64_S\000"
  /* 23620 */ "ARGUMENT_v2i64_S\000"
  /* 23637 */ "ARGUMENT_i64_S\000"
  /* 23652 */ "CONST_V128_F32x4_S\000"
  /* 23671 */ "SUB_F32x4_S\000"
  /* 23683 */ "TRUNC_F32x4_S\000"
  /* 23697 */ "NMADD_F32x4_S\000"
  /* 23711 */ "GE_F32x4_S\000"
  /* 23722 */ "LE_F32x4_S\000"
  /* 23733 */ "REPLACE_LANE_F32x4_S\000"
  /* 23754 */ "EXTRACT_LANE_F32x4_S\000"
  /* 23775 */ "NEG_F32x4_S\000"
  /* 23787 */ "CEIL_F32x4_S\000"
  /* 23800 */ "MUL_F32x4_S\000"
  /* 23812 */ "SIMD_RELAXED_FMIN_F32x4_S\000"
  /* 23838 */ "PMIN_F32x4_S\000"
  /* 23851 */ "EQ_F32x4_S\000"
  /* 23862 */ "FLOOR_F32x4_S\000"
  /* 23876 */ "ABS_F32x4_S\000"
  /* 23888 */ "SPLAT_F32x4_S\000"
  /* 23902 */ "GT_F32x4_S\000"
  /* 23913 */ "LT_F32x4_S\000"
  /* 23924 */ "SQRT_F32x4_S\000"
  /* 23937 */ "NEAREST_F32x4_S\000"
  /* 23953 */ "DIV_F32x4_S\000"
  /* 23965 */ "SIMD_RELAXED_FMAX_F32x4_S\000"
  /* 23991 */ "PMAX_F32x4_S\000"
  /* 24004 */ "demote_zero_F32x4_S\000"
  /* 24024 */ "sint_to_fp_F32x4_S\000"
  /* 24043 */ "uint_to_fp_F32x4_S\000"
  /* 24062 */ "promote_low_F32x4_S\000"
  /* 24082 */ "CONST_V128_I32x4_S\000"
  /* 24101 */ "SUB_I32x4_S\000"
  /* 24113 */ "ADD_I32x4_S\000"
  /* 24125 */ "REPLACE_LANE_I32x4_S\000"
  /* 24146 */ "EXTRACT_LANE_I32x4_S\000"
  /* 24167 */ "ALLTRUE_I32x4_S\000"
  /* 24183 */ "NEG_I32x4_S\000"
  /* 24195 */ "BITMASK_I32x4_S\000"
  /* 24211 */ "SHL_I32x4_S\000"
  /* 24223 */ "MUL_I32x4_S\000"
  /* 24235 */ "EQ_I32x4_S\000"
  /* 24246 */ "ABS_I32x4_S\000"
  /* 24258 */ "GE_S_I32x4_S\000"
  /* 24271 */ "LE_S_I32x4_S\000"
  /* 24284 */ "EXTMUL_HIGH_S_I32x4_S\000"
  /* 24306 */ "MIN_S_I32x4_S\000"
  /* 24320 */ "SHR_S_I32x4_S\000"
  /* 24334 */ "GT_S_I32x4_S\000"
  /* 24347 */ "LT_S_I32x4_S\000"
  /* 24360 */ "EXTMUL_LOW_S_I32x4_S\000"
  /* 24381 */ "MAX_S_I32x4_S\000"
  /* 24395 */ "SPLAT_I32x4_S\000"
  /* 24409 */ "LANESELECT_I32x4_S\000"
  /* 24428 */ "GE_U_I32x4_S\000"
  /* 24441 */ "LE_U_I32x4_S\000"
  /* 24454 */ "EXTMUL_HIGH_U_I32x4_S\000"
  /* 24476 */ "MIN_U_I32x4_S\000"
  /* 24490 */ "SHR_U_I32x4_S\000"
  /* 24504 */ "GT_U_I32x4_S\000"
  /* 24517 */ "LT_U_I32x4_S\000"
  /* 24530 */ "EXTMUL_LOW_U_I32x4_S\000"
  /* 24551 */ "MAX_U_I32x4_S\000"
  /* 24565 */ "int_wasm_relaxed_trunc_signed_I32x4_S\000"
  /* 24603 */ "int_wasm_relaxed_trunc_unsigned_I32x4_S\000"
  /* 24643 */ "int_wasm_relaxed_trunc_signed_zero_I32x4_S\000"
  /* 24686 */ "int_wasm_relaxed_trunc_unsigned_zero_I32x4_S\000"
  /* 24731 */ "extadd_pairwise_s_I32x4_S\000"
  /* 24757 */ "extend_high_s_I32x4_S\000"
  /* 24779 */ "trunc_sat_zero_s_I32x4_S\000"
  /* 24804 */ "extend_low_s_I32x4_S\000"
  /* 24825 */ "fp_to_sint_I32x4_S\000"
  /* 24844 */ "fp_to_uint_I32x4_S\000"
  /* 24863 */ "extadd_pairwise_u_I32x4_S\000"
  /* 24889 */ "extend_high_u_I32x4_S\000"
  /* 24911 */ "trunc_sat_zero_u_I32x4_S\000"
  /* 24936 */ "extend_low_u_I32x4_S\000"
  /* 24957 */ "ARGUMENT_v8f16_S\000"
  /* 24974 */ "ARGUMENT_v8i16_S\000"
  /* 24991 */ "CONST_V128_I8x16_S\000"
  /* 25010 */ "SUB_I8x16_S\000"
  /* 25022 */ "ADD_I8x16_S\000"
  /* 25034 */ "REPLACE_LANE_I8x16_S\000"
  /* 25055 */ "ALLTRUE_I8x16_S\000"
  /* 25071 */ "NEG_I8x16_S\000"
  /* 25083 */ "BITMASK_I8x16_S\000"
  /* 25099 */ "SHL_I8x16_S\000"
  /* 25111 */ "EQ_I8x16_S\000"
  /* 25122 */ "ABS_I8x16_S\000"
  /* 25134 */ "GE_S_I8x16_S\000"
  /* 25147 */ "LE_S_I8x16_S\000"
  /* 25160 */ "MIN_S_I8x16_S\000"
  /* 25174 */ "SHR_S_I8x16_S\000"
  /* 25188 */ "SUB_SAT_S_I8x16_S\000"
  /* 25206 */ "ADD_SAT_S_I8x16_S\000"
  /* 25224 */ "GT_S_I8x16_S\000"
  /* 25237 */ "LT_S_I8x16_S\000"
  /* 25250 */ "NARROW_S_I8x16_S\000"
  /* 25267 */ "MAX_S_I8x16_S\000"
  /* 25281 */ "SPLAT_I8x16_S\000"
  /* 25295 */ "LANESELECT_I8x16_S\000"
  /* 25314 */ "POPCNT_I8x16_S\000"
  /* 25329 */ "GE_U_I8x16_S\000"
  /* 25342 */ "LE_U_I8x16_S\000"
  /* 25355 */ "MIN_U_I8x16_S\000"
  /* 25369 */ "AVGR_U_I8x16_S\000"
  /* 25384 */ "SHR_U_I8x16_S\000"
  /* 25398 */ "SUB_SAT_U_I8x16_S\000"
  /* 25416 */ "ADD_SAT_U_I8x16_S\000"
  /* 25434 */ "GT_U_I8x16_S\000"
  /* 25447 */ "LT_U_I8x16_S\000"
  /* 25460 */ "NARROW_U_I8x16_S\000"
  /* 25477 */ "MAX_U_I8x16_S\000"
  /* 25491 */ "I64_SUB128_S\000"
  /* 25504 */ "I64_ADD128_S\000"
  /* 25517 */ "LOCAL_TEE_V128_S\000"
  /* 25534 */ "DROP_V128_S\000"
  /* 25546 */ "SELECT_V128_S\000"
  /* 25560 */ "GLOBAL_GET_V128_S\000"
  /* 25578 */ "LOCAL_GET_V128_S\000"
  /* 25595 */ "GLOBAL_SET_V128_S\000"
  /* 25613 */ "LOCAL_SET_V128_S\000"
  /* 25630 */ "COPY_V128_S\000"
  /* 25642 */ "ARGUMENT_v16i8_S\000"
  /* 25659 */ "SUB_F16x8_S\000"
  /* 25671 */ "TRUNC_F16x8_S\000"
  /* 25685 */ "NMADD_F16x8_S\000"
  /* 25699 */ "GE_F16x8_S\000"
  /* 25710 */ "LE_F16x8_S\000"
  /* 25721 */ "REPLACE_LANE_F16x8_S\000"
  /* 25742 */ "EXTRACT_LANE_F16x8_S\000"
  /* 25763 */ "NEG_F16x8_S\000"
  /* 25775 */ "CEIL_F16x8_S\000"
  /* 25788 */ "MUL_F16x8_S\000"
  /* 25800 */ "PMIN_F16x8_S\000"
  /* 25813 */ "EQ_F16x8_S\000"
  /* 25824 */ "FLOOR_F16x8_S\000"
  /* 25838 */ "ABS_F16x8_S\000"
  /* 25850 */ "SPLAT_F16x8_S\000"
  /* 25864 */ "GT_F16x8_S\000"
  /* 25875 */ "LT_F16x8_S\000"
  /* 25886 */ "SQRT_F16x8_S\000"
  /* 25899 */ "NEAREST_F16x8_S\000"
  /* 25915 */ "DIV_F16x8_S\000"
  /* 25927 */ "PMAX_F16x8_S\000"
  /* 25940 */ "demote_zero_F16x8_S\000"
  /* 25960 */ "sint_to_fp_F16x8_S\000"
  /* 25979 */ "uint_to_fp_F16x8_S\000"
  /* 25998 */ "CONST_V128_I16x8_S\000"
  /* 26017 */ "SUB_I16x8_S\000"
  /* 26029 */ "ADD_I16x8_S\000"
  /* 26041 */ "REPLACE_LANE_I16x8_S\000"
  /* 26062 */ "ALLTRUE_I16x8_S\000"
  /* 26078 */ "NEG_I16x8_S\000"
  /* 26090 */ "BITMASK_I16x8_S\000"
  /* 26106 */ "SHL_I16x8_S\000"
  /* 26118 */ "MUL_I16x8_S\000"
  /* 26130 */ "EQ_I16x8_S\000"
  /* 26141 */ "ABS_I16x8_S\000"
  /* 26153 */ "GE_S_I16x8_S\000"
  /* 26166 */ "LE_S_I16x8_S\000"
  /* 26179 */ "EXTMUL_HIGH_S_I16x8_S\000"
  /* 26201 */ "MIN_S_I16x8_S\000"
  /* 26215 */ "SHR_S_I16x8_S\000"
  /* 26229 */ "RELAXED_Q15MULR_S_I16x8_S\000"
  /* 26255 */ "SUB_SAT_S_I16x8_S\000"
  /* 26273 */ "ADD_SAT_S_I16x8_S\000"
  /* 26291 */ "Q15MULR_SAT_S_I16x8_S\000"
  /* 26313 */ "GT_S_I16x8_S\000"
  /* 26326 */ "LT_S_I16x8_S\000"
  /* 26339 */ "EXTMUL_LOW_S_I16x8_S\000"
  /* 26360 */ "NARROW_S_I16x8_S\000"
  /* 26377 */ "MAX_S_I16x8_S\000"
  /* 26391 */ "SPLAT_I16x8_S\000"
  /* 26405 */ "LANESELECT_I16x8_S\000"
  /* 26424 */ "GE_U_I16x8_S\000"
  /* 26437 */ "LE_U_I16x8_S\000"
  /* 26450 */ "EXTMUL_HIGH_U_I16x8_S\000"
  /* 26472 */ "MIN_U_I16x8_S\000"
  /* 26486 */ "AVGR_U_I16x8_S\000"
  /* 26501 */ "SHR_U_I16x8_S\000"
  /* 26515 */ "SUB_SAT_U_I16x8_S\000"
  /* 26533 */ "ADD_SAT_U_I16x8_S\000"
  /* 26551 */ "GT_U_I16x8_S\000"
  /* 26564 */ "LT_U_I16x8_S\000"
  /* 26577 */ "EXTMUL_LOW_U_I16x8_S\000"
  /* 26598 */ "NARROW_U_I16x8_S\000"
  /* 26615 */ "MAX_U_I16x8_S\000"
  /* 26629 */ "extadd_pairwise_s_I16x8_S\000"
  /* 26655 */ "extend_high_s_I16x8_S\000"
  /* 26677 */ "extend_low_s_I16x8_S\000"
  /* 26698 */ "fp_to_sint_I16x8_S\000"
  /* 26717 */ "fp_to_uint_I16x8_S\000"
  /* 26736 */ "extadd_pairwise_u_I16x8_S\000"
  /* 26762 */ "extend_high_u_I16x8_S\000"
  /* 26784 */ "extend_low_u_I16x8_S\000"
  /* 26805 */ "REF_FUNC_S\000"
  /* 26816 */ "RELAXED_DOT_ADD_S\000"
  /* 26834 */ "AND_S\000"
  /* 26840 */ "END_S\000"
  /* 26846 */ "ATOMIC_FENCE_S\000"
  /* 26861 */ "COMPILER_FENCE_S\000"
  /* 26878 */ "I64_MUL_WIDE_S\000"
  /* 26893 */ "DEBUG_UNREACHABLE_S\000"
  /* 26913 */ "END_TRY_TABLE_S\000"
  /* 26929 */ "SHUFFLE_S\000"
  /* 26939 */ "RELAXED_SWIZZLE_S\000"
  /* 26957 */ "ELSE_S\000"
  /* 26964 */ "DELEGATE_S\000"
  /* 26975 */ "ANYTRUE_S\000"
  /* 26985 */ "TABLE_SIZE_S\000"
  /* 26998 */ "LOCAL_TEE_FUNCREF_S\000"
  /* 27018 */ "TABLE_FILL_FUNCREF_S\000"
  /* 27039 */ "REF_NULL_FUNCREF_S\000"
  /* 27058 */ "REF_IS_NULL_FUNCREF_S\000"
  /* 27080 */ "DROP_FUNCREF_S\000"
  /* 27095 */ "SELECT_FUNCREF_S\000"
  /* 27112 */ "TABLE_GET_FUNCREF_S\000"
  /* 27132 */ "GLOBAL_GET_FUNCREF_S\000"
  /* 27153 */ "LOCAL_GET_FUNCREF_S\000"
  /* 27173 */ "TABLE_SET_FUNCREF_S\000"
  /* 27193 */ "GLOBAL_SET_FUNCREF_S\000"
  /* 27214 */ "LOCAL_SET_FUNCREF_S\000"
  /* 27234 */ "REF_CAST_FUNCREF_S\000"
  /* 27253 */ "REF_TEST_FUNCREF_S\000"
  /* 27272 */ "TABLE_GROW_FUNCREF_S\000"
  /* 27293 */ "COPY_FUNCREF_S\000"
  /* 27308 */ "LOCAL_TEE_EXTERNREF_S\000"
  /* 27330 */ "TABLE_FILL_EXTERNREF_S\000"
  /* 27353 */ "REF_NULL_EXTERNREF_S\000"
  /* 27374 */ "REF_IS_NULL_EXTERNREF_S\000"
  /* 27398 */ "DROP_EXTERNREF_S\000"
  /* 27415 */ "SELECT_EXTERNREF_S\000"
  /* 27434 */ "TABLE_GET_EXTERNREF_S\000"
  /* 27456 */ "GLOBAL_GET_EXTERNREF_S\000"
  /* 27479 */ "LOCAL_GET_EXTERNREF_S\000"
  /* 27501 */ "TABLE_SET_EXTERNREF_S\000"
  /* 27523 */ "GLOBAL_SET_EXTERNREF_S\000"
  /* 27546 */ "LOCAL_SET_EXTERNREF_S\000"
  /* 27568 */ "TABLE_GROW_EXTERNREF_S\000"
  /* 27591 */ "COPY_EXTERNREF_S\000"
  /* 27608 */ "LOCAL_TEE_EXNREF_S\000"
  /* 27627 */ "TABLE_FILL_EXNREF_S\000"
  /* 27647 */ "REF_NULL_EXNREF_S\000"
  /* 27665 */ "REF_IS_NULL_EXNREF_S\000"
  /* 27686 */ "DROP_EXNREF_S\000"
  /* 27700 */ "SELECT_EXNREF_S\000"
  /* 27716 */ "TABLE_GET_EXNREF_S\000"
  /* 27735 */ "GLOBAL_GET_EXNREF_S\000"
  /* 27755 */ "LOCAL_GET_EXNREF_S\000"
  /* 27774 */ "TABLE_SET_EXNREF_S\000"
  /* 27793 */ "GLOBAL_SET_EXNREF_S\000"
  /* 27813 */ "LOCAL_SET_EXNREF_S\000"
  /* 27832 */ "TABLE_GROW_EXNREF_S\000"
  /* 27852 */ "COPY_EXNREF_S\000"
  /* 27866 */ "CATCH_REF_S\000"
  /* 27878 */ "RET_CALL_REF_S\000"
  /* 27893 */ "CATCH_ALL_REF_S\000"
  /* 27909 */ "THROW_REF_S\000"
  /* 27921 */ "END_IF_S\000"
  /* 27930 */ "BR_IF_S\000"
  /* 27938 */ "CATCH_S\000"
  /* 27946 */ "END_BLOCK_S\000"
  /* 27958 */ "RET_CALL_S\000"
  /* 27969 */ "CATCH_ALL_S\000"
  /* 27981 */ "END_FUNCTION_S\000"
  /* 27996 */ "FALLTHROUGH_RETURN_S\000"
  /* 28017 */ "ADJCALLSTACKDOWN_S\000"
  /* 28036 */ "NOP_S\000"
  /* 28042 */ "END_LOOP_S\000"
  /* 28053 */ "DATA_DROP_S\000"
  /* 28065 */ "ADJCALLSTACKUP_S\000"
  /* 28082 */ "BR_S\000"
  /* 28087 */ "XOR_S\000"
  /* 28093 */ "CALL_PARAMS_S\000"
  /* 28107 */ "BR_UNLESS_S\000"
  /* 28119 */ "RET_CALL_RESULTS_S\000"
  /* 28138 */ "I64_MUL_WIDE_S_S\000"
  /* 28155 */ "RELAXED_DOT_BFLOAT_S\000"
  /* 28176 */ "G_TRUNC_SSAT_S\000"
  /* 28191 */ "BITSELECT_S\000"
  /* 28203 */ "RET_CALL_INDIRECT_S\000"
  /* 28223 */ "CATCHRET_S\000"
  /* 28234 */ "CLEANUPRET_S\000"
  /* 28247 */ "RELAXED_DOT_S\000"
  /* 28261 */ "ANDNOT_S\000"
  /* 28270 */ "SELECT_T_S\000"
  /* 28281 */ "I64_MUL_WIDE_U_S\000"
  /* 28298 */ "RETHROW_S\000"
  /* 28308 */ "CATCH_LEGACY_S\000"
  /* 28323 */ "CATCH_ALL_LEGACY_S\000"
  /* 28342 */ "TABLE_COPY_S\000"
  /* 28355 */ "END_TRY_S\000"
  /* 28365 */ "ARGUMENT_funcref_S\000"
  /* 28384 */ "ARGUMENT_externref_S\000"
  /* 28405 */ "ARGUMENT_exnref_S\000"
  /* 28423 */ "EXTRACT_LANE_I8x16_s_S\000"
  /* 28446 */ "EXTRACT_LANE_I16x8_s_S\000"
  /* 28469 */ "EXTRACT_LANE_I8x16_u_S\000"
  /* 28492 */ "EXTRACT_LANE_I16x8_u_S\000"
  /* 28515 */ "RELAXED_DOT_BFLOAT\000"
  /* 28534 */ "G_SSUBSAT\000"
  /* 28544 */ "G_USUBSAT\000"
  /* 28554 */ "G_SADDSAT\000"
  /* 28564 */ "G_UADDSAT\000"
  /* 28574 */ "G_SSHLSAT\000"
  /* 28584 */ "G_USHLSAT\000"
  /* 28594 */ "G_SMULFIXSAT\000"
  /* 28607 */ "G_UMULFIXSAT\000"
  /* 28620 */ "G_SDIVFIXSAT\000"
  /* 28633 */ "G_UDIVFIXSAT\000"
  /* 28646 */ "G_ATOMICRMW_USUB_SAT\000"
  /* 28667 */ "G_FPTOSI_SAT\000"
  /* 28680 */ "G_FPTOUI_SAT\000"
  /* 28693 */ "G_EXTRACT\000"
  /* 28703 */ "BITSELECT\000"
  /* 28713 */ "G_SELECT\000"
  /* 28722 */ "G_BRINDIRECT\000"
  /* 28735 */ "RET_CALL_INDIRECT\000"
  /* 28753 */ "CATCHRET\000"
  /* 28762 */ "CLEANUPRET\000"
  /* 28773 */ "PATCHABLE_RET\000"
  /* 28787 */ "G_MEMSET\000"
  /* 28796 */ "PATCHABLE_FUNCTION_EXIT\000"
  /* 28820 */ "G_BRJT\000"
  /* 28827 */ "G_EXTRACT_VECTOR_ELT\000"
  /* 28848 */ "G_INSERT_VECTOR_ELT\000"
  /* 28868 */ "G_FCONSTANT\000"
  /* 28880 */ "G_CONSTANT\000"
  /* 28891 */ "G_INTRINSIC_CONVERGENT\000"
  /* 28914 */ "STATEPOINT\000"
  /* 28925 */ "PATCHPOINT\000"
  /* 28936 */ "G_PTRTOINT\000"
  /* 28947 */ "G_FRINT\000"
  /* 28955 */ "G_INTRINSIC_LLRINT\000"
  /* 28974 */ "G_INTRINSIC_LRINT\000"
  /* 28992 */ "G_FNEARBYINT\000"
  /* 29005 */ "RELAXED_DOT\000"
  /* 29017 */ "ANDNOT\000"
  /* 29024 */ "G_VASTART\000"
  /* 29034 */ "LIFETIME_START\000"
  /* 29049 */ "G_INVOKE_REGION_START\000"
  /* 29071 */ "G_INSERT\000"
  /* 29080 */ "G_FSQRT\000"
  /* 29088 */ "G_STRICT_FSQRT\000"
  /* 29103 */ "G_BITCAST\000"
  /* 29113 */ "G_ADDRSPACE_CAST\000"
  /* 29130 */ "DBG_VALUE_LIST\000"
  /* 29145 */ "G_FPEXT\000"
  /* 29153 */ "G_SEXT\000"
  /* 29160 */ "G_ASSERT_SEXT\000"
  /* 29174 */ "G_ANYEXT\000"
  /* 29183 */ "G_ZEXT\000"
  /* 29190 */ "G_ASSERT_ZEXT\000"
  /* 29204 */ "SELECT_T\000"
  /* 29213 */ "G_ABDU\000"
  /* 29220 */ "I64_MUL_WIDE_U\000"
  /* 29235 */ "G_TRUNC_SSAT_U\000"
  /* 29250 */ "G_TRUNC_USAT_U\000"
  /* 29265 */ "G_FDIV\000"
  /* 29272 */ "G_STRICT_FDIV\000"
  /* 29286 */ "G_SDIV\000"
  /* 29293 */ "G_UDIV\000"
  /* 29300 */ "G_GET_FPENV\000"
  /* 29312 */ "G_RESET_FPENV\000"
  /* 29326 */ "G_SET_FPENV\000"
  /* 29338 */ "G_FPOW\000"
  /* 29345 */ "RETHROW\000"
  /* 29353 */ "G_VECREDUCE_FMAX\000"
  /* 29370 */ "G_ATOMICRMW_FMAX\000"
  /* 29387 */ "G_VECREDUCE_SMAX\000"
  /* 29404 */ "G_SMAX\000"
  /* 29411 */ "G_VECREDUCE_UMAX\000"
  /* 29428 */ "G_UMAX\000"
  /* 29435 */ "G_ATOMICRMW_UMAX\000"
  /* 29452 */ "G_ATOMICRMW_MAX\000"
  /* 29468 */ "G_FRAME_INDEX\000"
  /* 29482 */ "G_SBFX\000"
  /* 29489 */ "G_UBFX\000"
  /* 29496 */ "G_SMULFIX\000"
  /* 29506 */ "G_UMULFIX\000"
  /* 29516 */ "G_SDIVFIX\000"
  /* 29526 */ "G_UDIVFIX\000"
  /* 29536 */ "CATCH_LEGACY\000"
  /* 29549 */ "CATCH_ALL_LEGACY\000"
  /* 29566 */ "G_MEMCPY\000"
  /* 29575 */ "TABLE_COPY\000"
  /* 29586 */ "CONVERGENCECTRL_ENTRY\000"
  /* 29608 */ "END_TRY\000"
  /* 29616 */ "G_CTLZ\000"
  /* 29623 */ "G_CTTZ\000"
  /* 29630 */ "ARGUMENT_funcref\000"
  /* 29647 */ "ARGUMENT_externref\000"
  /* 29666 */ "ARGUMENT_exnref\000"
  /* 29682 */ "EXTRACT_LANE_I8x16_s\000"
  /* 29703 */ "EXTRACT_LANE_I16x8_s\000"
  /* 29724 */ "EXTRACT_LANE_I8x16_u\000"
  /* 29745 */ "EXTRACT_LANE_I16x8_u\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const unsigned WebAssemblyInstrNameIndices[] = {
    12867U, 13310U, 14206U, 13729U, 12950U, 12931U, 12959U, 13138U, 
    12654U, 12669U, 11780U, 11767U, 12696U, 14760U, 11624U, 29130U, 
    12610U, 12863U, 12940U, 11293U, 29581U, 12907U, 11447U, 29034U, 
    11092U, 11216U, 11266U, 13897U, 13116U, 28925U, 11199U, 14141U, 
    12789U, 28914U, 11521U, 14114U, 14101U, 14267U, 28773U, 28796U, 
    13039U, 13095U, 13068U, 12976U, 11606U, 14232U, 13851U, 11510U, 
    29586U, 14385U, 14062U, 11672U, 29160U, 29190U, 13559U, 10989U, 
    10679U, 13249U, 29286U, 29293U, 13276U, 13283U, 13290U, 13300U, 
    11070U, 14594U, 14557U, 14645U, 29213U, 14429U, 13028U, 14417U, 
    13017U, 11778U, 12865U, 29468U, 11634U, 11649U, 13143U, 28693U, 
    14652U, 29071U, 14669U, 14480U, 10758U, 14743U, 28936U, 14621U, 
    29103U, 11723U, 14243U, 11173U, 10732U, 11155U, 28974U, 28955U, 
    13537U, 14292U, 14311U, 10890U, 10834U, 10864U, 10803U, 10875U, 
    10815U, 10845U, 11580U, 11534U, 11564U, 14790U, 12710U, 12727U, 
    11021U, 10685U, 11076U, 11037U, 14599U, 14563U, 29452U, 13685U, 
    29435U, 13668U, 10956U, 10662U, 29370U, 13603U, 13405U, 13352U, 
    13478U, 13440U, 13959U, 13937U, 11114U, 28646U, 11258U, 12812U, 
    11105U, 28722U, 29049U, 10701U, 14848U, 28891U, 14875U, 29174U, 
    10750U, 28176U, 29235U, 29250U, 28880U, 28868U, 29024U, 12781U, 
    29153U, 12683U, 29183U, 13003U, 14378U, 14364U, 12996U, 14371U, 
    14614U, 13159U, 14028U, 14007U, 14035U, 14042U, 28713U, 13843U, 
    11314U, 13827U, 11237U, 13835U, 11306U, 13819U, 11229U, 13881U, 
    13873U, 12831U, 12823U, 28564U, 28554U, 28544U, 28534U, 28584U, 
    28574U, 29496U, 29506U, 28594U, 28607U, 29516U, 29526U, 28620U, 
    28633U, 10914U, 10641U, 13183U, 10622U, 10796U, 29265U, 13255U, 
    11759U, 29338U, 12889U, 14185U, 3559U, 9U, 12774U, 3542U, 
    0U, 14160U, 14192U, 12647U, 29145U, 10722U, 12871U, 12880U, 
    13989U, 13998U, 28667U, 28680U, 14632U, 13574U, 14777U, 11732U, 
    13502U, 13512U, 11363U, 11378U, 13341U, 13394U, 13426U, 13464U, 
    29300U, 29326U, 29312U, 11322U, 11350U, 11335U, 12744U, 12759U, 
    10995U, 12921U, 13637U, 29404U, 13661U, 29428U, 14639U, 11146U, 
    11136U, 14201U, 28820U, 11393U, 14461U, 14441U, 28848U, 28827U, 
    14495U, 14526U, 14512U, 14830U, 29623U, 13764U, 29616U, 13745U, 
    14684U, 14083U, 13981U, 11593U, 13225U, 13009U, 14711U, 13709U, 
    14718U, 13530U, 14703U, 13701U, 13522U, 3550U, 12855U, 12847U, 
    12839U, 29080U, 14408U, 28947U, 28992U, 29113U, 14219U, 11420U, 
    10779U, 11701U, 11549U, 10942U, 10648U, 13211U, 29272U, 13262U, 
    10628U, 29088U, 14169U, 14014U, 14728U, 14331U, 14347U, 29566U, 
    11494U, 11713U, 28787U, 13889U, 11478U, 13930U, 13906U, 13918U, 
    10921U, 13190U, 10897U, 13166U, 29353U, 13586U, 13373U, 13320U, 
    10973U, 13233U, 11054U, 14579U, 14541U, 29387U, 13620U, 29411U, 
    13644U, 29482U, 29489U, 14691U, 28093U, 14917U, 28123U, 28753U, 
    28223U, 28762U, 28234U, 11278U, 26861U, 14913U, 28119U, 9773U, 
    25838U, 2641U, 17805U, 8049U, 23876U, 6956U, 22605U, 3761U, 
    19078U, 10034U, 26141U, 8371U, 24246U, 4071U, 19434U, 9155U, 
    25122U, 9644U, 25687U, 2510U, 17646U, 7896U, 23699U, 6826U, 
    22447U, 3608U, 18901U, 9938U, 26029U, 2960U, 18172U, 8256U, 
    24113U, 7275U, 22972U, 3956U, 19301U, 9069U, 25022U, 10150U, 
    26273U, 9227U, 25206U, 10378U, 26533U, 9409U, 25416U, 13802U, 
    28017U, 14126U, 28065U, 9967U, 26062U, 8304U, 24167U, 4004U, 
    19355U, 9098U, 25055U, 11050U, 29017U, 28261U, 2968U, 18182U, 
    7283U, 22982U, 26834U, 11693U, 26975U, 29666U, 28405U, 29647U, 
    28384U, 3501U, 18807U, 7814U, 23605U, 29630U, 28365U, 3529U, 
    18839U, 7842U, 23637U, 9605U, 25642U, 7799U, 23588U, 7827U, 
    23620U, 3486U, 18790U, 3514U, 18822U, 9012U, 24957U, 9027U, 
    24974U, 11245U, 26846U, 743U, 15717U, 5059U, 20518U, 1865U, 
    16933U, 6181U, 21734U, 1841U, 16907U, 6157U, 21708U, 767U, 
    15743U, 5083U, 20544U, 1889U, 16959U, 6205U, 21760U, 201U, 
    15131U, 4517U, 19932U, 1116U, 16124U, 5432U, 20925U, 221U, 
    15153U, 4537U, 19954U, 1163U, 16175U, 5479U, 20976U, 297U, 
    15235U, 4613U, 20036U, 1266U, 16286U, 5582U, 21087U, 394U, 
    15340U, 4710U, 20141U, 1394U, 16424U, 5710U, 21225U, 637U, 
    15601U, 4953U, 20402U, 1718U, 16772U, 6034U, 21573U, 125U, 
    15049U, 4441U, 19850U, 1040U, 16042U, 5356U, 20843U, 482U, 
    15434U, 4798U, 20235U, 1510U, 16548U, 5826U, 21349U, 561U, 
    15519U, 4877U, 20320U, 1616U, 16662U, 5932U, 21463U, 1136U, 
    16146U, 5452U, 20947U, 1239U, 16257U, 5555U, 21058U, 1363U, 
    16391U, 5679U, 21192U, 1692U, 16744U, 6008U, 21545U, 1013U, 
    16013U, 5329U, 20814U, 1482U, 16518U, 5798U, 21319U, 1589U, 
    16633U, 5905U, 21434U, 248U, 15182U, 4564U, 19983U, 1190U, 
    16204U, 5506U, 21005U, 324U, 15264U, 4640U, 20065U, 1293U, 
    16315U, 5609U, 21116U, 425U, 15373U, 4741U, 20174U, 1425U, 
    16457U, 5741U, 21258U, 663U, 15629U, 4979U, 20430U, 1744U, 
    16800U, 6060U, 21601U, 152U, 15078U, 4468U, 19879U, 1067U, 
    16071U, 5383U, 20872U, 510U, 15464U, 4826U, 20265U, 1538U, 
    16578U, 5854U, 21379U, 588U, 15548U, 4904U, 20349U, 1643U, 
    16691U, 5959U, 21492U, 274U, 15210U, 4590U, 20011U, 1216U, 
    16232U, 5532U, 21033U, 350U, 15292U, 4666U, 20093U, 1319U, 
    16343U, 5635U, 21144U, 455U, 15405U, 4771U, 20206U, 1455U, 
    16489U, 5771U, 21290U, 688U, 15656U, 5004U, 20457U, 1769U, 
    16827U, 6085U, 21628U, 178U, 15106U, 4494U, 19907U, 1093U, 
    16099U, 5409U, 20900U, 537U, 15493U, 4853U, 20294U, 1565U, 
    16607U, 5881U, 21408U, 614U, 15576U, 4930U, 20377U, 1669U, 
    16719U, 5985U, 21520U, 80U, 15000U, 4396U, 19801U, 968U, 
    15964U, 5284U, 20765U, 945U, 15939U, 5261U, 20740U, 103U, 
    15025U, 4419U, 19826U, 991U, 15989U, 5307U, 20790U, 373U, 
    15317U, 4689U, 20118U, 1342U, 16368U, 5658U, 21169U, 10337U, 
    26486U, 9368U, 25369U, 9991U, 26090U, 8328U, 24195U, 4028U, 
    19383U, 9122U, 25083U, 28703U, 28191U, 12901U, 27950U, 14203U, 
    12641U, 27930U, 28082U, 2990U, 18208U, 7305U, 23008U, 14820U, 
    28107U, 13054U, 28739U, 28207U, 12587U, 27882U, 27962U, 12806U, 
    13128U, 29549U, 28323U, 12596U, 27893U, 27969U, 29536U, 28308U, 
    12573U, 27866U, 27938U, 9720U, 25775U, 2577U, 17727U, 7972U, 
    23787U, 6892U, 22527U, 3684U, 18989U, 3462U, 18760U, 7775U, 
    23558U, 2885U, 18083U, 7200U, 22883U, 3324U, 18598U, 7654U, 
    23415U, 7855U, 23652U, 3567U, 18854U, 9911U, 25998U, 8229U, 
    24082U, 3929U, 19270U, 9042U, 24991U, 2594U, 17748U, 6909U, 
    22548U, 12561U, 27852U, 12328U, 27591U, 2943U, 18151U, 7258U, 
    22951U, 12058U, 27293U, 3453U, 18749U, 7766U, 23547U, 9595U, 
    25630U, 3478U, 18780U, 7791U, 23578U, 14091U, 28053U, 11402U, 
    26893U, 11615U, 26964U, 9838U, 25915U, 2927U, 18131U, 8114U, 
    23953U, 7242U, 22931U, 3826U, 19155U, 3214U, 18472U, 7544U, 
    23289U, 3443U, 18737U, 7756U, 23535U, 29013U, 28255U, 12413U, 
    27686U, 12153U, 27398U, 2615U, 17773U, 6930U, 22573U, 11867U, 
    27080U, 3035U, 18263U, 7363U, 23078U, 9511U, 25534U, 11588U, 
    26957U, 11101U, 12897U, 27946U, 13716U, 27981U, 12634U, 27921U, 
    14053U, 28042U, 26840U, 29608U, 28355U, 11433U, 26913U, 3470U, 
    18770U, 7783U, 23568U, 9752U, 25813U, 2624U, 17784U, 8028U, 
    23851U, 6939U, 22584U, 3740U, 19053U, 10025U, 26130U, 3044U, 
    18274U, 8362U, 24235U, 7372U, 23089U, 4062U, 19423U, 9146U, 
    25111U, 10066U, 26179U, 8403U, 24284U, 4103U, 19472U, 10305U, 
    26450U, 8551U, 24454U, 4205U, 19588U, 10208U, 26339U, 8469U, 
    24360U, 4157U, 19534U, 10416U, 26577U, 8617U, 24530U, 4237U, 
    19624U, 9691U, 25742U, 7943U, 23754U, 3655U, 18956U, 29703U, 
    28446U, 29745U, 28492U, 8285U, 24146U, 3985U, 19334U, 29682U, 
    28423U, 29724U, 28469U, 3178U, 18432U, 7508U, 23249U, 3407U, 
    18697U, 7720U, 23495U, 6869U, 22500U, 3264U, 18530U, 3196U, 
    18452U, 7526U, 23269U, 3425U, 18717U, 7738U, 23515U, 2553U, 
    17699U, 7594U, 23347U, 13783U, 27996U, 9761U, 25824U, 2631U, 
    17793U, 8037U, 23862U, 6946U, 22593U, 3749U, 19064U, 2416U, 
    17540U, 6732U, 22341U, 2454U, 17582U, 6770U, 22383U, 2435U, 
    17561U, 6751U, 22362U, 2473U, 17603U, 6789U, 22404U, 9654U, 
    25699U, 2532U, 17672U, 7906U, 23711U, 6848U, 22473U, 3618U, 
    18913U, 10044U, 26153U, 3122U, 18364U, 8381U, 24258U, 7452U, 
    23181U, 4081U, 19446U, 9165U, 25134U, 10283U, 26424U, 3351U, 
    18629U, 8529U, 24428U, 7664U, 23427U, 9334U, 25329U, 12456U, 
    27735U, 12205U, 27456U, 2772U, 17952U, 7087U, 22752U, 11913U, 
    27132U, 3235U, 18497U, 7565U, 23314U, 9533U, 25560U, 12508U, 
    27793U, 12266U, 27523U, 2821U, 18007U, 7136U, 22807U, 11968U, 
    27193U, 3284U, 18552U, 7614U, 23369U, 9564U, 25595U, 9795U, 
    25864U, 2850U, 18040U, 8071U, 23902U, 7165U, 22840U, 3783U, 
    19104U, 10186U, 26313U, 3160U, 18410U, 8447U, 24334U, 7490U, 
    23227U, 4135U, 19508U, 9243U, 25224U, 10394U, 26551U, 3389U, 
    18675U, 8595U, 24504U, 7702U, 23473U, 9425U, 25434U, 3068U, 
    18304U, 3087U, 18325U, 2801U, 17985U, 2649U, 17815U, 6964U, 
    22615U, 2681U, 17851U, 6996U, 22651U, 2895U, 18095U, 7210U, 
    22895U, 2721U, 17895U, 7036U, 22695U, 7350U, 23063U, 9485U, 
    25504U, 7415U, 23140U, 7396U, 23119U, 7434U, 23161U, 3105U, 
    18345U, 3334U, 18610U, 26878U, 28138U, 29220U, 28281U, 7116U, 
    22785U, 9474U, 25491U, 2665U, 17833U, 6980U, 22633U, 2701U, 
    17873U, 7016U, 22673U, 2911U, 18113U, 7226U, 22913U, 2741U, 
    17917U, 7056U, 22717U, 12638U, 27925U, 10266U, 26405U, 8512U, 
    24409U, 4188U, 19569U, 9304U, 25295U, 9663U, 25710U, 2539U, 
    17681U, 7915U, 23722U, 6855U, 22482U, 3627U, 18924U, 10055U, 
    26166U, 3131U, 18375U, 8392U, 24271U, 7461U, 23192U, 4092U, 
    19459U, 9176U, 25147U, 10294U, 26437U, 3360U, 18640U, 8540U, 
    24441U, 7673U, 23438U, 9345U, 25342U, 2273U, 17381U, 6589U, 
    22182U, 710U, 15680U, 5026U, 20481U, 1808U, 16870U, 6124U, 
    21671U, 750U, 15724U, 5066U, 20525U, 1872U, 16940U, 6188U, 
    21741U, 2239U, 17343U, 6555U, 22144U, 1791U, 16851U, 6107U, 
    21652U, 1848U, 16914U, 6164U, 21715U, 2256U, 17362U, 6572U, 
    22163U, 2290U, 17400U, 6606U, 22201U, 727U, 15699U, 5043U, 
    20500U, 1825U, 16889U, 6141U, 21690U, 774U, 15750U, 5090U, 
    20551U, 1896U, 16966U, 6212U, 21767U, 2144U, 17240U, 6460U, 
    22041U, 1992U, 17072U, 6308U, 21873U, 870U, 15856U, 5186U, 
    20657U, 2168U, 17266U, 6484U, 22067U, 2016U, 17098U, 6332U, 
    21899U, 894U, 15882U, 5210U, 20683U, 18U, 14930U, 4334U, 
    19731U, 53U, 14969U, 4369U, 19770U, 918U, 15908U, 5234U, 
    20709U, 208U, 15138U, 4524U, 19939U, 1123U, 16131U, 5439U, 
    20932U, 2040U, 17124U, 6356U, 21925U, 815U, 15795U, 5131U, 
    20596U, 1937U, 17011U, 6253U, 21812U, 2107U, 17199U, 6423U, 
    22000U, 2078U, 17166U, 6394U, 21967U, 832U, 15814U, 5148U, 
    20615U, 1954U, 17030U, 6270U, 21831U, 12474U, 27755U, 12226U, 
    27479U, 2787U, 17969U, 7102U, 22769U, 11932U, 27153U, 3250U, 
    18514U, 7580U, 23331U, 9549U, 25578U, 12526U, 27813U, 12287U, 
    27546U, 2836U, 18024U, 7151U, 22824U, 11987U, 27214U, 3299U, 
    18569U, 7629U, 23386U, 9580U, 25613U, 12343U, 27608U, 12071U, 
    27308U, 2518U, 17656U, 6834U, 22457U, 11793U, 26998U, 2976U, 
    18192U, 7291U, 22992U, 9496U, 25517U, 14057U, 28046U, 9804U, 
    25875U, 2857U, 18049U, 8080U, 23913U, 7172U, 22849U, 3792U, 
    19115U, 10197U, 26326U, 3169U, 18421U, 8458U, 24347U, 7499U, 
    23238U, 4146U, 19521U, 9254U, 25237U, 10405U, 26564U, 3398U, 
    18686U, 8606U, 24517U, 7711U, 23484U, 9436U, 25447U, 9643U, 
    25686U, 7895U, 23698U, 3607U, 18900U, 9849U, 25928U, 2935U, 
    18141U, 8138U, 23979U, 7250U, 22941U, 3850U, 19181U, 10242U, 
    26377U, 8488U, 24381U, 9280U, 25267U, 10450U, 26615U, 8636U, 
    24551U, 9462U, 25477U, 2389U, 17509U, 6705U, 22310U, 2364U, 
    17482U, 6680U, 22283U, 790U, 15768U, 5106U, 20569U, 1912U, 
    16984U, 6228U, 21785U, 2400U, 17522U, 6716U, 22323U, 2223U, 
    17325U, 6539U, 22126U, 2317U, 17431U, 6633U, 22232U, 2306U, 
    17418U, 6622U, 22219U, 9742U, 25801U, 2607U, 17763U, 8007U, 
    23826U, 6922U, 22563U, 3719U, 19028U, 10086U, 26201U, 8423U, 
    24306U, 9187U, 25160U, 10325U, 26472U, 8571U, 24476U, 9356U, 
    25355U, 9731U, 25788U, 2586U, 17738U, 7983U, 23800U, 6901U, 
    22538U, 3695U, 19002U, 10015U, 26118U, 3027U, 18253U, 8352U, 
    24223U, 7342U, 23053U, 4052U, 19411U, 10227U, 26360U, 9265U, 
    25250U, 10435U, 26598U, 9447U, 25460U, 9824U, 25899U, 2873U, 
    18069U, 8100U, 23937U, 7188U, 22869U, 3812U, 19139U, 9710U, 
    25763U, 2569U, 17717U, 7962U, 23775U, 6884U, 22517U, 3674U, 
    18977U, 9981U, 26078U, 8318U, 24183U, 4018U, 19371U, 9112U, 
    25071U, 9682U, 25731U, 2546U, 17690U, 7934U, 23743U, 6862U, 
    22491U, 3646U, 18945U, 9958U, 26051U, 3003U, 18223U, 8276U, 
    24135U, 7318U, 23023U, 3976U, 19323U, 9089U, 25044U, 9642U, 
    25685U, 7894U, 23697U, 3606U, 18899U, 14049U, 28036U, 29020U, 
    28264U, 14405U, 3052U, 18284U, 7380U, 23099U, 28088U, 9848U, 
    25927U, 8148U, 23991U, 3860U, 19193U, 9741U, 25800U, 8017U, 
    23838U, 3729U, 19040U, 3313U, 18585U, 7643U, 23402U, 9321U, 
    25314U, 10166U, 26291U, 12005U, 27234U, 10713U, 26805U, 12394U, 
    27665U, 12131U, 27374U, 11847U, 27058U, 12378U, 27647U, 12112U, 
    27353U, 11830U, 27039U, 12022U, 27253U, 29005U, 11005U, 26816U, 
    28515U, 28155U, 28247U, 10110U, 26229U, 11462U, 26939U, 3140U, 
    18386U, 7470U, 23203U, 3369U, 18651U, 7682U, 23449U, 9672U, 
    25721U, 7924U, 23733U, 3636U, 18935U, 9948U, 26041U, 8266U, 
    24125U, 3966U, 19313U, 9079U, 25034U, 29345U, 28298U, 13795U, 
    28008U, 13059U, 28735U, 28203U, 12583U, 27878U, 27958U, 3018U, 
    18242U, 7333U, 23042U, 3059U, 18293U, 7387U, 23108U, 12425U, 
    27700U, 12168U, 27415U, 2761U, 17939U, 7076U, 22739U, 11880U, 
    27095U, 3224U, 18484U, 7554U, 23301U, 29204U, 28270U, 9521U, 
    25546U, 10005U, 26106U, 3010U, 18232U, 8342U, 24211U, 7325U, 
    23032U, 4042U, 19399U, 9136U, 25099U, 10098U, 26215U, 3150U, 
    18398U, 8435U, 24320U, 7480U, 23215U, 4123U, 19494U, 9199U, 
    25174U, 10350U, 26501U, 3379U, 18663U, 8583U, 24490U, 7692U, 
    23461U, 4225U, 19610U, 9381U, 25384U, 11454U, 26929U, 8124U, 
    23965U, 3836U, 19167U, 7993U, 23812U, 3705U, 19014U, 9783U, 
    25850U, 8059U, 23888U, 3771U, 19090U, 10254U, 26391U, 8500U, 
    24395U, 4176U, 19555U, 9292U, 25281U, 9813U, 25886U, 2864U, 
    18058U, 8089U, 23924U, 7179U, 22858U, 3801U, 19126U, 87U, 
    15007U, 4403U, 19808U, 975U, 15971U, 5291U, 20772U, 952U, 
    15946U, 5268U, 20747U, 110U, 15032U, 4426U, 19833U, 998U, 
    15996U, 5314U, 20797U, 35U, 14949U, 4351U, 19750U, 66U, 
    14984U, 4382U, 19785U, 931U, 15923U, 5247U, 20724U, 380U, 
    15324U, 4696U, 20125U, 1349U, 16375U, 5665U, 21176U, 2123U, 
    17217U, 6439U, 22018U, 1971U, 17049U, 6287U, 21850U, 849U, 
    15833U, 5165U, 20634U, 2057U, 17143U, 6373U, 21944U, 2092U, 
    17182U, 6408U, 21983U, 9620U, 25659U, 2492U, 17624U, 7872U, 
    23671U, 6808U, 22425U, 3584U, 18873U, 9928U, 26017U, 2952U, 
    18162U, 8246U, 24101U, 7267U, 22962U, 3946U, 19289U, 9059U, 
    25010U, 10134U, 26255U, 9211U, 25188U, 10362U, 26515U, 9393U, 
    25398U, 11470U, 26947U, 29575U, 28342U, 12360U, 27627U, 12091U, 
    27330U, 11811U, 27018U, 12439U, 27716U, 12185U, 27434U, 11895U, 
    27112U, 12543U, 27832U, 12307U, 27568U, 12039U, 27272U, 12491U, 
    27774U, 12246U, 27501U, 11950U, 27173U, 11748U, 26985U, 12349U, 
    27614U, 12077U, 27314U, 2524U, 17662U, 6840U, 22463U, 11799U, 
    27004U, 2982U, 18198U, 7297U, 22998U, 9502U, 25523U, 29347U, 
    12624U, 27909U, 28300U, 9630U, 25671U, 2500U, 17634U, 7882U, 
    23683U, 6816U, 22435U, 3594U, 18885U, 29604U, 28359U, 11437U, 
    26917U, 11408U, 26899U, 14553U, 3051U, 18283U, 7379U, 23098U, 
    28087U, 2333U, 17449U, 2192U, 17292U, 6649U, 22250U, 6508U, 
    22093U, 3871U, 19206U, 3891U, 19228U, 9859U, 25940U, 8159U, 
    24004U, 10462U, 26629U, 8806U, 24731U, 10559U, 26736U, 8926U, 
    24863U, 10486U, 26655U, 8830U, 24757U, 4256U, 19645U, 10583U, 
    26762U, 8950U, 24889U, 4295U, 19688U, 10506U, 26677U, 8873U, 
    24804U, 4276U, 19667U, 10603U, 26784U, 8993U, 24936U, 4315U, 
    19710U, 10525U, 26698U, 8892U, 24825U, 10542U, 26717U, 8909U, 
    24844U, 8648U, 24565U, 8722U, 24643U, 8684U, 24603U, 8763U, 
    24686U, 8211U, 24062U, 3911U, 19250U, 9877U, 25960U, 8177U, 
    24024U, 8850U, 24779U, 8970U, 24911U, 9894U, 25979U, 8194U, 
    24043U, 
};

extern const int16_t WebAssemblyRegClassByHwModeTables[2][1] = {
  { // DefaultMode
    WebAssembly::I32RegClassID, // wasm_ptr_rc
  },
  { // WASM64
    WebAssembly::I64RegClassID, // wasm_ptr_rc
  },
};

static inline void InitWebAssemblyMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(WebAssemblyDescs.Insts, WebAssemblyInstrNameIndices, WebAssemblyInstrNameData, nullptr, nullptr, 1977, &WebAssemblyRegClassByHwModeTables[0][0], 1);
}


} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER

namespace llvm_ks {

struct WebAssemblyGenInstrInfo : public TargetInstrInfo {
  explicit WebAssemblyGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode = ~0u, unsigned CFDestroyOpcode = ~0u, unsigned CatchRetOpcode = ~0u, unsigned ReturnOpcode = ~0u);
  ~WebAssemblyGenInstrInfo() override = default;
};
extern const int16_t WebAssemblyRegClassByHwModeTables[2][1];

} // namespace llvm_ks

namespace llvm_ks::WebAssembly {


} // namespace llvm_ks::WebAssembly

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

extern const WebAssemblyInstrTable WebAssemblyDescs;
extern const unsigned WebAssemblyInstrNameIndices[];
extern const char WebAssemblyInstrNameData[];
WebAssemblyGenInstrInfo::WebAssemblyGenInstrInfo(const TargetSubtargetInfo &STI, const TargetRegisterInfo &TRI, unsigned CFSetupOpcode, unsigned CFDestroyOpcode, unsigned CatchRetOpcode, unsigned ReturnOpcode)
  : TargetInstrInfo(TRI, CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode, WebAssemblyRegClassByHwModeTables[STI.getHwMode(MCSubtargetInfo::HwMode_RegInfo)]) {
  InitMCInstrInfo(WebAssemblyDescs.Insts, WebAssemblyInstrNameIndices, WebAssemblyInstrNameData, nullptr, nullptr, 1977, &WebAssemblyRegClassByHwModeTables[0][0], 1);
}

} // namespace llvm_ks

#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_OPERAND_ENUM
#undef GET_INSTRINFO_OPERAND_ENUM

namespace llvm_ks::WebAssembly {

enum class OpName : uint8_t {
  dst = 0,
  order = 1,
  p2align = 2,
  off = 3,
  addr = 4,
  val = 5,
  exp = 6,
  new_ = 7,
  idx = 8,
  vec = 9,
  count = 10,
  timeout = 11,
  NUM_OPERAND_NAMES = 12,
}; // enum class OpName

LLVM_READONLY int16_t getNamedOperandIdx(uint32_t Opcode, OpName Name);
LLVM_READONLY OpName getOperandIdxName(uint32_t Opcode, int16_t Idx);

} // namespace llvm_ks::WebAssembly

#endif // GET_INSTRINFO_OPERAND_ENUM

#ifdef GET_INSTRINFO_NAMED_OPS
#undef GET_INSTRINFO_NAMED_OPS

namespace llvm_ks::WebAssembly {

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
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 2, 1,
    2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1,
    2, 1, 2, 1, 2, 1, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 4, 2, 4, 2, 4, 2, 4, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 4, 2, 4, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 4, 2, 4, 2, 4,
    2, 4, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 4, 2, 4, 2, 4, 2, 4, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 5, 2, 5, 2, 5,
    2, 5, 2, 5, 2, 5, 2, 5, 2, 5, 2, 5, 2, 5, 2, 5,
    2, 5, 2, 5, 2, 5, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6,
    7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6,
    7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6,
    7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6,
    7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6,
    7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6, 7, 6,
    7, 6, 7, 6, 7, 6, 7, 6, 7, 8, 9, 8, 9, 8, 9, 8,
    9, 8, 9, 8, 9, 8, 9, 8, 9, 6, 7, 6, 7, 6, 7, 6,
    7, 6, 7, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 10, 2, 10, 2, 11, 2, 11, 2, 11,
    2, 11, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
    0, 0, 0, 0, 0, 0, 0, 12, 7, 12, 7, 12, 7, 12, 7, 12,
    7, 12, 7, 12, 7, 12, 7, 12, 7, 12, 7, 12, 7, 12, 7, 12,
    7, 12, 7, 12, 7, 12, 7, 12, 7, 12, 7, 12, 7, 12, 7, 13,
    9, 13, 9, 13, 9, 13, 9, 13, 9, 13, 9, 13, 9, 13, 9, 14,
    7, 14, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
    0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  return InstructionIndex[Opcode];
}
LLVM_READONLY int16_t getNamedOperandIdx(uint32_t Opcode, OpName Name) {
  assert(Name != OpName::NUM_OPERAND_NAMES);
  static constexpr int8_t OperandMap[][12] = {
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, 1, 2, 3, 4, -1, -1, -1, -1, -1, -1, -1, },
    {-1, 0, 1, 2, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, 1, 2, 3, 4, 5, -1, -1, -1, -1, -1, -1, },
    {0, 1, 2, 3, 4, -1, 5, 6, -1, -1, -1, -1, },
    {-1, 0, 1, 2, 3, 4, -1, -1, -1, -1, -1, -1, },
    {0, -1, 1, 2, 3, -1, -1, -1, -1, -1, -1, -1, },
    {-1, -1, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, },
    {0, -1, 1, 2, 4, -1, -1, -1, 3, 5, -1, -1, },
    {-1, -1, 0, 1, -1, -1, -1, -1, 2, -1, -1, -1, },
    {0, 1, 2, 3, 4, -1, -1, -1, -1, -1, 5, -1, },
    {0, 1, 2, 3, 4, -1, 5, -1, -1, -1, -1, 6, },
    {-1, -1, 0, 1, 2, 3, -1, -1, -1, -1, -1, -1, },
    {-1, -1, 0, 1, 3, -1, -1, -1, 2, 4, -1, -1, },
    {-1, -1, 0, 1, 2, -1, -1, -1, -1, 3, -1, -1, },
  };
  unsigned InstrIdx = getInstructionIndexForOpLookup(Opcode);
  return OperandMap[InstrIdx][(unsigned)Name];
}
LLVM_READONLY OpName getOperandIdxName(uint32_t Opcode, int16_t Idx) {
  assert(Idx >= 0 && Idx < 7);
  static constexpr OpName OperandMap[][7] = {
    {OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::order, OpName::p2align, OpName::off, OpName::addr, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::order, OpName::p2align, OpName::off, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::order, OpName::p2align, OpName::off, OpName::addr, OpName::val, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::order, OpName::p2align, OpName::off, OpName::addr, OpName::exp, OpName::new_, },
    {OpName::order, OpName::p2align, OpName::off, OpName::addr, OpName::val, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::p2align, OpName::off, OpName::addr, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::p2align, OpName::off, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::p2align, OpName::off, OpName::idx, OpName::addr, OpName::vec, OpName::NUM_OPERAND_NAMES, },
    {OpName::p2align, OpName::off, OpName::idx, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::order, OpName::p2align, OpName::off, OpName::addr, OpName::count, OpName::NUM_OPERAND_NAMES, },
    {OpName::dst, OpName::order, OpName::p2align, OpName::off, OpName::addr, OpName::exp, OpName::timeout, },
    {OpName::p2align, OpName::off, OpName::addr, OpName::val, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::p2align, OpName::off, OpName::idx, OpName::addr, OpName::vec, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
    {OpName::p2align, OpName::off, OpName::addr, OpName::vec, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, OpName::NUM_OPERAND_NAMES, },
  };
  unsigned InstrIdx = getInstructionIndexForOpLookup(Opcode);
  return OperandMap[InstrIdx][(unsigned)Idx];
}

} // namespace llvm_ks::WebAssembly

#endif // GET_INSTRINFO_NAMED_OPS

#ifdef GET_INSTRINFO_MC_HELPER_DECLS
#undef GET_INSTRINFO_MC_HELPER_DECLS

namespace llvm_ks {

class MCInst;
class FeatureBitset;

namespace WebAssembly_MC {

void verifyInstructionPredicates(unsigned Opcode, const FeatureBitset &Features);

} // namespace WebAssembly_MC

} // namespace llvm_ks

#endif // GET_INSTRINFO_MC_HELPER_DECLS

#ifdef GET_INSTRINFO_MC_HELPERS
#undef GET_INSTRINFO_MC_HELPERS

namespace llvm_ks::WebAssembly_MC {


} // namespace llvm_ks::WebAssembly_MC

#endif // GET_INSTRINFO_MC_HELPERS

#if (defined(ENABLE_INSTR_PREDICATE_VERIFIER) && !defined(NDEBUG)) ||\
    defined(GET_AVAILABLE_OPCODE_CHECKER)
#define GET_COMPUTE_FEATURES
#endif
#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

namespace llvm_ks::WebAssembly_MC {

// Bits for subtarget features that participate in instruction matching.
enum SubtargetFeatureBits : uint8_t {
  Feature_HasAtomicsBit = 0,
  Feature_HasBulkMemoryBit = 1,
  Feature_HasBulkMemoryOptBit = 2,
  Feature_HasCallIndirectOverlongBit = 3,
  Feature_HasExceptionHandlingBit = 4,
  Feature_HasExtendedConstBit = 5,
  Feature_HasFP16Bit = 6,
  Feature_HasGCBit = 7,
  Feature_HasMultiMemoryBit = 8,
  Feature_HasMultivalueBit = 9,
  Feature_HasMutableGlobalsBit = 10,
  Feature_HasNontrappingFPToIntBit = 11,
  Feature_NotHasNontrappingFPToIntBit = 19,
  Feature_HasReferenceTypesBit = 12,
  Feature_HasRelaxedAtomicsBit = 13,
  Feature_HasRelaxedSIMDBit = 14,
  Feature_HasSignExtBit = 16,
  Feature_HasSIMD128Bit = 15,
  Feature_HasTailCallBit = 17,
  Feature_HasWideArithmeticBit = 18,
};

inline FeatureBitset computeAvailableFeatures(const FeatureBitset &FB) {
  FeatureBitset Features;
  if (FB[WebAssembly::FeatureAtomics])
    Features.set(Feature_HasAtomicsBit);
  if (FB[WebAssembly::FeatureBulkMemory])
    Features.set(Feature_HasBulkMemoryBit);
  if (FB[WebAssembly::FeatureBulkMemoryOpt])
    Features.set(Feature_HasBulkMemoryOptBit);
  if (FB[WebAssembly::FeatureCallIndirectOverlong])
    Features.set(Feature_HasCallIndirectOverlongBit);
  if (FB[WebAssembly::FeatureExceptionHandling])
    Features.set(Feature_HasExceptionHandlingBit);
  if (FB[WebAssembly::FeatureExtendedConst])
    Features.set(Feature_HasExtendedConstBit);
  if (FB[WebAssembly::FeatureFP16])
    Features.set(Feature_HasFP16Bit);
  if (FB[WebAssembly::FeatureGC])
    Features.set(Feature_HasGCBit);
  if (FB[WebAssembly::FeatureMultiMemory])
    Features.set(Feature_HasMultiMemoryBit);
  if (FB[WebAssembly::FeatureMultivalue])
    Features.set(Feature_HasMultivalueBit);
  if (FB[WebAssembly::FeatureMutableGlobals])
    Features.set(Feature_HasMutableGlobalsBit);
  if (FB[WebAssembly::FeatureNontrappingFPToInt])
    Features.set(Feature_HasNontrappingFPToIntBit);
  if (!FB[WebAssembly::FeatureNontrappingFPToInt])
    Features.set(Feature_NotHasNontrappingFPToIntBit);
  if (FB[WebAssembly::FeatureReferenceTypes])
    Features.set(Feature_HasReferenceTypesBit);
  if (FB[WebAssembly::FeatureRelaxedAtomics])
    Features.set(Feature_HasRelaxedAtomicsBit);
  if (FB[WebAssembly::FeatureRelaxedSIMD])
    Features.set(Feature_HasRelaxedSIMDBit);
  if (FB[WebAssembly::FeatureSignExt])
    Features.set(Feature_HasSignExtBit);
  if (FB[WebAssembly::FeatureSIMD128] || FB[WebAssembly::FeatureRelaxedSIMD])
    Features.set(Feature_HasSIMD128Bit);
  if (FB[WebAssembly::FeatureTailCall])
    Features.set(Feature_HasTailCallBit);
  if (FB[WebAssembly::FeatureWideArithmetic])
    Features.set(Feature_HasWideArithmeticBit);
  return Features;
}

inline FeatureBitset computeRequiredFeatures(unsigned Opcode) {
  enum : uint8_t {
    CEFBS_None,
    CEFBS_HasAtomics,
    CEFBS_HasBulkMemoryOpt,
    CEFBS_HasExceptionHandling,
    CEFBS_HasFP16,
    CEFBS_HasGC,
    CEFBS_HasNontrappingFPToInt,
    CEFBS_HasReferenceTypes,
    CEFBS_HasRelaxedSIMD,
    CEFBS_HasSIMD128,
    CEFBS_HasSignExt,
    CEFBS_HasTailCall,
    CEFBS_HasWideArithmetic,
    CEFBS_NotHasNontrappingFPToInt,
    CEFBS_HasReferenceTypes_HasExceptionHandling,
    CEFBS_HasSIMD128_HasFP16,
    CEFBS_HasSIMD128_HasRelaxedSIMD,
    CEFBS_HasTailCall_HasGC,
  };

  static constexpr FeatureBitset FeatureBitsets[] = {
    {}, // CEFBS_None
    {Feature_HasAtomicsBit, },
    {Feature_HasBulkMemoryOptBit, },
    {Feature_HasExceptionHandlingBit, },
    {Feature_HasFP16Bit, },
    {Feature_HasGCBit, },
    {Feature_HasNontrappingFPToIntBit, },
    {Feature_HasReferenceTypesBit, },
    {Feature_HasRelaxedSIMDBit, },
    {Feature_HasSIMD128Bit, },
    {Feature_HasSignExtBit, },
    {Feature_HasTailCallBit, },
    {Feature_HasWideArithmeticBit, },
    {Feature_NotHasNontrappingFPToIntBit, },
    {Feature_HasReferenceTypesBit, Feature_HasExceptionHandlingBit, },
    {Feature_HasSIMD128Bit, Feature_HasFP16Bit, },
    {Feature_HasSIMD128Bit, Feature_HasRelaxedSIMDBit, },
    {Feature_HasTailCallBit, Feature_HasGCBit, },
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
    CEFBS_None, // CALL_PARAMS
    CEFBS_None, // CALL_PARAMS_S
    CEFBS_None, // CALL_RESULTS
    CEFBS_None, // CALL_RESULTS_S
    CEFBS_HasExceptionHandling, // CATCHRET
    CEFBS_HasExceptionHandling, // CATCHRET_S
    CEFBS_HasExceptionHandling, // CLEANUPRET
    CEFBS_HasExceptionHandling, // CLEANUPRET_S
    CEFBS_HasAtomics, // COMPILER_FENCE
    CEFBS_HasAtomics, // COMPILER_FENCE_S
    CEFBS_None, // RET_CALL_RESULTS
    CEFBS_None, // RET_CALL_RESULTS_S
    CEFBS_HasSIMD128_HasFP16, // ABS_F16x8
    CEFBS_HasSIMD128_HasFP16, // ABS_F16x8_S
    CEFBS_None, // ABS_F32
    CEFBS_None, // ABS_F32_S
    CEFBS_HasSIMD128, // ABS_F32x4
    CEFBS_HasSIMD128, // ABS_F32x4_S
    CEFBS_None, // ABS_F64
    CEFBS_None, // ABS_F64_S
    CEFBS_HasSIMD128, // ABS_F64x2
    CEFBS_HasSIMD128, // ABS_F64x2_S
    CEFBS_HasSIMD128, // ABS_I16x8
    CEFBS_HasSIMD128, // ABS_I16x8_S
    CEFBS_HasSIMD128, // ABS_I32x4
    CEFBS_HasSIMD128, // ABS_I32x4_S
    CEFBS_HasSIMD128, // ABS_I64x2
    CEFBS_HasSIMD128, // ABS_I64x2_S
    CEFBS_HasSIMD128, // ABS_I8x16
    CEFBS_HasSIMD128, // ABS_I8x16_S
    CEFBS_HasSIMD128_HasFP16, // ADD_F16x8
    CEFBS_HasSIMD128_HasFP16, // ADD_F16x8_S
    CEFBS_None, // ADD_F32
    CEFBS_None, // ADD_F32_S
    CEFBS_HasSIMD128, // ADD_F32x4
    CEFBS_HasSIMD128, // ADD_F32x4_S
    CEFBS_None, // ADD_F64
    CEFBS_None, // ADD_F64_S
    CEFBS_HasSIMD128, // ADD_F64x2
    CEFBS_HasSIMD128, // ADD_F64x2_S
    CEFBS_HasSIMD128, // ADD_I16x8
    CEFBS_HasSIMD128, // ADD_I16x8_S
    CEFBS_None, // ADD_I32
    CEFBS_None, // ADD_I32_S
    CEFBS_HasSIMD128, // ADD_I32x4
    CEFBS_HasSIMD128, // ADD_I32x4_S
    CEFBS_None, // ADD_I64
    CEFBS_None, // ADD_I64_S
    CEFBS_HasSIMD128, // ADD_I64x2
    CEFBS_HasSIMD128, // ADD_I64x2_S
    CEFBS_HasSIMD128, // ADD_I8x16
    CEFBS_HasSIMD128, // ADD_I8x16_S
    CEFBS_HasSIMD128, // ADD_SAT_S_I16x8
    CEFBS_HasSIMD128, // ADD_SAT_S_I16x8_S
    CEFBS_HasSIMD128, // ADD_SAT_S_I8x16
    CEFBS_HasSIMD128, // ADD_SAT_S_I8x16_S
    CEFBS_HasSIMD128, // ADD_SAT_U_I16x8
    CEFBS_HasSIMD128, // ADD_SAT_U_I16x8_S
    CEFBS_HasSIMD128, // ADD_SAT_U_I8x16
    CEFBS_HasSIMD128, // ADD_SAT_U_I8x16_S
    CEFBS_None, // ADJCALLSTACKDOWN
    CEFBS_None, // ADJCALLSTACKDOWN_S
    CEFBS_None, // ADJCALLSTACKUP
    CEFBS_None, // ADJCALLSTACKUP_S
    CEFBS_HasSIMD128, // ALLTRUE_I16x8
    CEFBS_HasSIMD128, // ALLTRUE_I16x8_S
    CEFBS_HasSIMD128, // ALLTRUE_I32x4
    CEFBS_HasSIMD128, // ALLTRUE_I32x4_S
    CEFBS_HasSIMD128, // ALLTRUE_I64x2
    CEFBS_HasSIMD128, // ALLTRUE_I64x2_S
    CEFBS_HasSIMD128, // ALLTRUE_I8x16
    CEFBS_HasSIMD128, // ALLTRUE_I8x16_S
    CEFBS_HasSIMD128, // AND
    CEFBS_HasSIMD128, // ANDNOT
    CEFBS_HasSIMD128, // ANDNOT_S
    CEFBS_None, // AND_I32
    CEFBS_None, // AND_I32_S
    CEFBS_None, // AND_I64
    CEFBS_None, // AND_I64_S
    CEFBS_HasSIMD128, // AND_S
    CEFBS_HasSIMD128, // ANYTRUE
    CEFBS_HasSIMD128, // ANYTRUE_S
    CEFBS_None, // ARGUMENT_exnref
    CEFBS_None, // ARGUMENT_exnref_S
    CEFBS_None, // ARGUMENT_externref
    CEFBS_None, // ARGUMENT_externref_S
    CEFBS_None, // ARGUMENT_f32
    CEFBS_None, // ARGUMENT_f32_S
    CEFBS_None, // ARGUMENT_f64
    CEFBS_None, // ARGUMENT_f64_S
    CEFBS_None, // ARGUMENT_funcref
    CEFBS_None, // ARGUMENT_funcref_S
    CEFBS_None, // ARGUMENT_i32
    CEFBS_None, // ARGUMENT_i32_S
    CEFBS_None, // ARGUMENT_i64
    CEFBS_None, // ARGUMENT_i64_S
    CEFBS_None, // ARGUMENT_v16i8
    CEFBS_None, // ARGUMENT_v16i8_S
    CEFBS_None, // ARGUMENT_v2f64
    CEFBS_None, // ARGUMENT_v2f64_S
    CEFBS_None, // ARGUMENT_v2i64
    CEFBS_None, // ARGUMENT_v2i64_S
    CEFBS_None, // ARGUMENT_v4f32
    CEFBS_None, // ARGUMENT_v4f32_S
    CEFBS_None, // ARGUMENT_v4i32
    CEFBS_None, // ARGUMENT_v4i32_S
    CEFBS_None, // ARGUMENT_v8f16
    CEFBS_None, // ARGUMENT_v8f16_S
    CEFBS_None, // ARGUMENT_v8i16
    CEFBS_None, // ARGUMENT_v8i16_S
    CEFBS_HasAtomics, // ATOMIC_FENCE
    CEFBS_HasAtomics, // ATOMIC_FENCE_S
    CEFBS_HasAtomics, // ATOMIC_LOAD16_U_I32_A32
    CEFBS_HasAtomics, // ATOMIC_LOAD16_U_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_LOAD16_U_I32_A64
    CEFBS_HasAtomics, // ATOMIC_LOAD16_U_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_LOAD16_U_I64_A32
    CEFBS_HasAtomics, // ATOMIC_LOAD16_U_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_LOAD16_U_I64_A64
    CEFBS_HasAtomics, // ATOMIC_LOAD16_U_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_LOAD32_U_I64_A32
    CEFBS_HasAtomics, // ATOMIC_LOAD32_U_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_LOAD32_U_I64_A64
    CEFBS_HasAtomics, // ATOMIC_LOAD32_U_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_LOAD8_U_I32_A32
    CEFBS_HasAtomics, // ATOMIC_LOAD8_U_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_LOAD8_U_I32_A64
    CEFBS_HasAtomics, // ATOMIC_LOAD8_U_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_LOAD8_U_I64_A32
    CEFBS_HasAtomics, // ATOMIC_LOAD8_U_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_LOAD8_U_I64_A64
    CEFBS_HasAtomics, // ATOMIC_LOAD8_U_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_LOAD_I32_A32
    CEFBS_HasAtomics, // ATOMIC_LOAD_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_LOAD_I32_A64
    CEFBS_HasAtomics, // ATOMIC_LOAD_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_LOAD_I64_A32
    CEFBS_HasAtomics, // ATOMIC_LOAD_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_LOAD_I64_A64
    CEFBS_HasAtomics, // ATOMIC_LOAD_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_ADD_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_ADD_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_ADD_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_ADD_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_ADD_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_ADD_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_ADD_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_ADD_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_AND_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_AND_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_AND_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_AND_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_AND_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_AND_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_AND_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_AND_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_CMPXCHG_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_CMPXCHG_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_CMPXCHG_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_CMPXCHG_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_CMPXCHG_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_CMPXCHG_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_CMPXCHG_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_CMPXCHG_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_OR_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_OR_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_OR_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_OR_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_OR_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_OR_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_OR_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_OR_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_SUB_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_SUB_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_SUB_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_SUB_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_SUB_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_SUB_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_SUB_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_SUB_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XCHG_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XCHG_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XCHG_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XCHG_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XCHG_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XCHG_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XCHG_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XCHG_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XOR_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XOR_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XOR_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XOR_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XOR_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XOR_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XOR_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW16_U_XOR_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_ADD_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_ADD_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_ADD_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_ADD_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_AND_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_AND_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_AND_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_AND_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_CMPXCHG_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_CMPXCHG_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_CMPXCHG_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_CMPXCHG_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_OR_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_OR_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_OR_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_OR_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_SUB_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_SUB_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_SUB_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_SUB_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_XCHG_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_XCHG_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_XCHG_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_XCHG_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_XOR_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_XOR_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_XOR_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW32_U_XOR_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_ADD_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_ADD_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_ADD_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_ADD_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_ADD_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_ADD_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_ADD_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_ADD_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_AND_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_AND_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_AND_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_AND_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_AND_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_AND_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_AND_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_AND_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_CMPXCHG_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_CMPXCHG_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_CMPXCHG_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_CMPXCHG_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_CMPXCHG_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_CMPXCHG_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_CMPXCHG_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_CMPXCHG_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_OR_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_OR_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_OR_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_OR_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_OR_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_OR_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_OR_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_OR_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_SUB_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_SUB_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_SUB_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_SUB_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_SUB_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_SUB_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_SUB_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_SUB_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XCHG_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XCHG_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XCHG_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XCHG_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XCHG_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XCHG_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XCHG_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XCHG_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XOR_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XOR_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XOR_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XOR_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XOR_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XOR_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XOR_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW8_U_XOR_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_ADD_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_ADD_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_ADD_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_ADD_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_ADD_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_ADD_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_ADD_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_ADD_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_AND_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_AND_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_AND_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_AND_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_AND_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_AND_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_AND_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_AND_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_CMPXCHG_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_CMPXCHG_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_CMPXCHG_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_CMPXCHG_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_CMPXCHG_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_CMPXCHG_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_CMPXCHG_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_CMPXCHG_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_OR_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_OR_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_OR_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_OR_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_OR_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_OR_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_OR_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_OR_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_SUB_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_SUB_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_SUB_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_SUB_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_SUB_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_SUB_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_SUB_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_SUB_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_XCHG_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_XCHG_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_XCHG_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_XCHG_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_XCHG_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_XCHG_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_XCHG_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_XCHG_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_XOR_I32_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_XOR_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_XOR_I32_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_XOR_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_RMW_XOR_I64_A32
    CEFBS_HasAtomics, // ATOMIC_RMW_XOR_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_RMW_XOR_I64_A64
    CEFBS_HasAtomics, // ATOMIC_RMW_XOR_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_STORE16_I32_A32
    CEFBS_HasAtomics, // ATOMIC_STORE16_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_STORE16_I32_A64
    CEFBS_HasAtomics, // ATOMIC_STORE16_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_STORE16_I64_A32
    CEFBS_HasAtomics, // ATOMIC_STORE16_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_STORE16_I64_A64
    CEFBS_HasAtomics, // ATOMIC_STORE16_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_STORE32_I64_A32
    CEFBS_HasAtomics, // ATOMIC_STORE32_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_STORE32_I64_A64
    CEFBS_HasAtomics, // ATOMIC_STORE32_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_STORE8_I32_A32
    CEFBS_HasAtomics, // ATOMIC_STORE8_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_STORE8_I32_A64
    CEFBS_HasAtomics, // ATOMIC_STORE8_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_STORE8_I64_A32
    CEFBS_HasAtomics, // ATOMIC_STORE8_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_STORE8_I64_A64
    CEFBS_HasAtomics, // ATOMIC_STORE8_I64_A64_S
    CEFBS_HasAtomics, // ATOMIC_STORE_I32_A32
    CEFBS_HasAtomics, // ATOMIC_STORE_I32_A32_S
    CEFBS_HasAtomics, // ATOMIC_STORE_I32_A64
    CEFBS_HasAtomics, // ATOMIC_STORE_I32_A64_S
    CEFBS_HasAtomics, // ATOMIC_STORE_I64_A32
    CEFBS_HasAtomics, // ATOMIC_STORE_I64_A32_S
    CEFBS_HasAtomics, // ATOMIC_STORE_I64_A64
    CEFBS_HasAtomics, // ATOMIC_STORE_I64_A64_S
    CEFBS_HasSIMD128, // AVGR_U_I16x8
    CEFBS_HasSIMD128, // AVGR_U_I16x8_S
    CEFBS_HasSIMD128, // AVGR_U_I8x16
    CEFBS_HasSIMD128, // AVGR_U_I8x16_S
    CEFBS_HasSIMD128, // BITMASK_I16x8
    CEFBS_HasSIMD128, // BITMASK_I16x8_S
    CEFBS_HasSIMD128, // BITMASK_I32x4
    CEFBS_HasSIMD128, // BITMASK_I32x4_S
    CEFBS_HasSIMD128, // BITMASK_I64x2
    CEFBS_HasSIMD128, // BITMASK_I64x2_S
    CEFBS_HasSIMD128, // BITMASK_I8x16
    CEFBS_HasSIMD128, // BITMASK_I8x16_S
    CEFBS_HasSIMD128, // BITSELECT
    CEFBS_HasSIMD128, // BITSELECT_S
    CEFBS_None, // BLOCK
    CEFBS_None, // BLOCK_S
    CEFBS_None, // BR
    CEFBS_None, // BR_IF
    CEFBS_None, // BR_IF_S
    CEFBS_None, // BR_S
    CEFBS_None, // BR_TABLE_I32
    CEFBS_None, // BR_TABLE_I32_S
    CEFBS_None, // BR_TABLE_I64
    CEFBS_None, // BR_TABLE_I64_S
    CEFBS_None, // BR_UNLESS
    CEFBS_None, // BR_UNLESS_S
    CEFBS_None, // CALL
    CEFBS_None, // CALL_INDIRECT
    CEFBS_None, // CALL_INDIRECT_S
    CEFBS_HasGC, // CALL_REF
    CEFBS_HasGC, // CALL_REF_S
    CEFBS_None, // CALL_S
    CEFBS_HasExceptionHandling, // CATCH
    CEFBS_HasExceptionHandling, // CATCH_ALL
    CEFBS_HasExceptionHandling, // CATCH_ALL_LEGACY
    CEFBS_HasExceptionHandling, // CATCH_ALL_LEGACY_S
    CEFBS_HasExceptionHandling, // CATCH_ALL_REF
    CEFBS_HasExceptionHandling, // CATCH_ALL_REF_S
    CEFBS_HasExceptionHandling, // CATCH_ALL_S
    CEFBS_HasExceptionHandling, // CATCH_LEGACY
    CEFBS_HasExceptionHandling, // CATCH_LEGACY_S
    CEFBS_HasExceptionHandling, // CATCH_REF
    CEFBS_HasExceptionHandling, // CATCH_REF_S
    CEFBS_HasExceptionHandling, // CATCH_S
    CEFBS_HasSIMD128_HasFP16, // CEIL_F16x8
    CEFBS_HasSIMD128_HasFP16, // CEIL_F16x8_S
    CEFBS_None, // CEIL_F32
    CEFBS_None, // CEIL_F32_S
    CEFBS_HasSIMD128, // CEIL_F32x4
    CEFBS_HasSIMD128, // CEIL_F32x4_S
    CEFBS_None, // CEIL_F64
    CEFBS_None, // CEIL_F64_S
    CEFBS_HasSIMD128, // CEIL_F64x2
    CEFBS_HasSIMD128, // CEIL_F64x2_S
    CEFBS_None, // CLZ_I32
    CEFBS_None, // CLZ_I32_S
    CEFBS_None, // CLZ_I64
    CEFBS_None, // CLZ_I64_S
    CEFBS_None, // CONST_F32
    CEFBS_None, // CONST_F32_S
    CEFBS_None, // CONST_F64
    CEFBS_None, // CONST_F64_S
    CEFBS_None, // CONST_I32
    CEFBS_None, // CONST_I32_S
    CEFBS_None, // CONST_I64
    CEFBS_None, // CONST_I64_S
    CEFBS_HasSIMD128, // CONST_V128_F32x4
    CEFBS_HasSIMD128, // CONST_V128_F32x4_S
    CEFBS_HasSIMD128, // CONST_V128_F64x2
    CEFBS_HasSIMD128, // CONST_V128_F64x2_S
    CEFBS_HasSIMD128, // CONST_V128_I16x8
    CEFBS_HasSIMD128, // CONST_V128_I16x8_S
    CEFBS_HasSIMD128, // CONST_V128_I32x4
    CEFBS_HasSIMD128, // CONST_V128_I32x4_S
    CEFBS_HasSIMD128, // CONST_V128_I64x2
    CEFBS_HasSIMD128, // CONST_V128_I64x2_S
    CEFBS_HasSIMD128, // CONST_V128_I8x16
    CEFBS_HasSIMD128, // CONST_V128_I8x16_S
    CEFBS_None, // COPYSIGN_F32
    CEFBS_None, // COPYSIGN_F32_S
    CEFBS_None, // COPYSIGN_F64
    CEFBS_None, // COPYSIGN_F64_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // COPY_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // COPY_EXNREF_S
    CEFBS_HasReferenceTypes, // COPY_EXTERNREF
    CEFBS_HasReferenceTypes, // COPY_EXTERNREF_S
    CEFBS_None, // COPY_F32
    CEFBS_None, // COPY_F32_S
    CEFBS_None, // COPY_F64
    CEFBS_None, // COPY_F64_S
    CEFBS_HasReferenceTypes, // COPY_FUNCREF
    CEFBS_HasReferenceTypes, // COPY_FUNCREF_S
    CEFBS_None, // COPY_I32
    CEFBS_None, // COPY_I32_S
    CEFBS_None, // COPY_I64
    CEFBS_None, // COPY_I64_S
    CEFBS_HasSIMD128, // COPY_V128
    CEFBS_HasSIMD128, // COPY_V128_S
    CEFBS_None, // CTZ_I32
    CEFBS_None, // CTZ_I32_S
    CEFBS_None, // CTZ_I64
    CEFBS_None, // CTZ_I64_S
    CEFBS_HasBulkMemoryOpt, // DATA_DROP
    CEFBS_HasBulkMemoryOpt, // DATA_DROP_S
    CEFBS_None, // DEBUG_UNREACHABLE
    CEFBS_None, // DEBUG_UNREACHABLE_S
    CEFBS_HasExceptionHandling, // DELEGATE
    CEFBS_HasExceptionHandling, // DELEGATE_S
    CEFBS_HasSIMD128_HasFP16, // DIV_F16x8
    CEFBS_HasSIMD128_HasFP16, // DIV_F16x8_S
    CEFBS_None, // DIV_F32
    CEFBS_None, // DIV_F32_S
    CEFBS_HasSIMD128, // DIV_F32x4
    CEFBS_HasSIMD128, // DIV_F32x4_S
    CEFBS_None, // DIV_F64
    CEFBS_None, // DIV_F64_S
    CEFBS_HasSIMD128, // DIV_F64x2
    CEFBS_HasSIMD128, // DIV_F64x2_S
    CEFBS_None, // DIV_S_I32
    CEFBS_None, // DIV_S_I32_S
    CEFBS_None, // DIV_S_I64
    CEFBS_None, // DIV_S_I64_S
    CEFBS_None, // DIV_U_I32
    CEFBS_None, // DIV_U_I32_S
    CEFBS_None, // DIV_U_I64
    CEFBS_None, // DIV_U_I64_S
    CEFBS_HasSIMD128, // DOT
    CEFBS_HasSIMD128, // DOT_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // DROP_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // DROP_EXNREF_S
    CEFBS_HasReferenceTypes, // DROP_EXTERNREF
    CEFBS_HasReferenceTypes, // DROP_EXTERNREF_S
    CEFBS_None, // DROP_F32
    CEFBS_None, // DROP_F32_S
    CEFBS_None, // DROP_F64
    CEFBS_None, // DROP_F64_S
    CEFBS_HasReferenceTypes, // DROP_FUNCREF
    CEFBS_HasReferenceTypes, // DROP_FUNCREF_S
    CEFBS_None, // DROP_I32
    CEFBS_None, // DROP_I32_S
    CEFBS_None, // DROP_I64
    CEFBS_None, // DROP_I64_S
    CEFBS_HasSIMD128, // DROP_V128
    CEFBS_HasSIMD128, // DROP_V128_S
    CEFBS_None, // ELSE
    CEFBS_None, // ELSE_S
    CEFBS_None, // END
    CEFBS_None, // END_BLOCK
    CEFBS_None, // END_BLOCK_S
    CEFBS_None, // END_FUNCTION
    CEFBS_None, // END_FUNCTION_S
    CEFBS_None, // END_IF
    CEFBS_None, // END_IF_S
    CEFBS_None, // END_LOOP
    CEFBS_None, // END_LOOP_S
    CEFBS_None, // END_S
    CEFBS_HasExceptionHandling, // END_TRY
    CEFBS_HasExceptionHandling, // END_TRY_S
    CEFBS_HasExceptionHandling, // END_TRY_TABLE
    CEFBS_HasExceptionHandling, // END_TRY_TABLE_S
    CEFBS_None, // EQZ_I32
    CEFBS_None, // EQZ_I32_S
    CEFBS_None, // EQZ_I64
    CEFBS_None, // EQZ_I64_S
    CEFBS_HasSIMD128_HasFP16, // EQ_F16x8
    CEFBS_HasSIMD128_HasFP16, // EQ_F16x8_S
    CEFBS_None, // EQ_F32
    CEFBS_None, // EQ_F32_S
    CEFBS_HasSIMD128, // EQ_F32x4
    CEFBS_HasSIMD128, // EQ_F32x4_S
    CEFBS_None, // EQ_F64
    CEFBS_None, // EQ_F64_S
    CEFBS_HasSIMD128, // EQ_F64x2
    CEFBS_HasSIMD128, // EQ_F64x2_S
    CEFBS_HasSIMD128, // EQ_I16x8
    CEFBS_HasSIMD128, // EQ_I16x8_S
    CEFBS_None, // EQ_I32
    CEFBS_None, // EQ_I32_S
    CEFBS_HasSIMD128, // EQ_I32x4
    CEFBS_HasSIMD128, // EQ_I32x4_S
    CEFBS_None, // EQ_I64
    CEFBS_None, // EQ_I64_S
    CEFBS_HasSIMD128, // EQ_I64x2
    CEFBS_HasSIMD128, // EQ_I64x2_S
    CEFBS_HasSIMD128, // EQ_I8x16
    CEFBS_HasSIMD128, // EQ_I8x16_S
    CEFBS_HasSIMD128, // EXTMUL_HIGH_S_I16x8
    CEFBS_HasSIMD128, // EXTMUL_HIGH_S_I16x8_S
    CEFBS_HasSIMD128, // EXTMUL_HIGH_S_I32x4
    CEFBS_HasSIMD128, // EXTMUL_HIGH_S_I32x4_S
    CEFBS_HasSIMD128, // EXTMUL_HIGH_S_I64x2
    CEFBS_HasSIMD128, // EXTMUL_HIGH_S_I64x2_S
    CEFBS_HasSIMD128, // EXTMUL_HIGH_U_I16x8
    CEFBS_HasSIMD128, // EXTMUL_HIGH_U_I16x8_S
    CEFBS_HasSIMD128, // EXTMUL_HIGH_U_I32x4
    CEFBS_HasSIMD128, // EXTMUL_HIGH_U_I32x4_S
    CEFBS_HasSIMD128, // EXTMUL_HIGH_U_I64x2
    CEFBS_HasSIMD128, // EXTMUL_HIGH_U_I64x2_S
    CEFBS_HasSIMD128, // EXTMUL_LOW_S_I16x8
    CEFBS_HasSIMD128, // EXTMUL_LOW_S_I16x8_S
    CEFBS_HasSIMD128, // EXTMUL_LOW_S_I32x4
    CEFBS_HasSIMD128, // EXTMUL_LOW_S_I32x4_S
    CEFBS_HasSIMD128, // EXTMUL_LOW_S_I64x2
    CEFBS_HasSIMD128, // EXTMUL_LOW_S_I64x2_S
    CEFBS_HasSIMD128, // EXTMUL_LOW_U_I16x8
    CEFBS_HasSIMD128, // EXTMUL_LOW_U_I16x8_S
    CEFBS_HasSIMD128, // EXTMUL_LOW_U_I32x4
    CEFBS_HasSIMD128, // EXTMUL_LOW_U_I32x4_S
    CEFBS_HasSIMD128, // EXTMUL_LOW_U_I64x2
    CEFBS_HasSIMD128, // EXTMUL_LOW_U_I64x2_S
    CEFBS_HasFP16, // EXTRACT_LANE_F16x8
    CEFBS_HasFP16, // EXTRACT_LANE_F16x8_S
    CEFBS_HasSIMD128, // EXTRACT_LANE_F32x4
    CEFBS_HasSIMD128, // EXTRACT_LANE_F32x4_S
    CEFBS_HasSIMD128, // EXTRACT_LANE_F64x2
    CEFBS_HasSIMD128, // EXTRACT_LANE_F64x2_S
    CEFBS_HasSIMD128, // EXTRACT_LANE_I16x8_s
    CEFBS_HasSIMD128, // EXTRACT_LANE_I16x8_s_S
    CEFBS_HasSIMD128, // EXTRACT_LANE_I16x8_u
    CEFBS_HasSIMD128, // EXTRACT_LANE_I16x8_u_S
    CEFBS_HasSIMD128, // EXTRACT_LANE_I32x4
    CEFBS_HasSIMD128, // EXTRACT_LANE_I32x4_S
    CEFBS_HasSIMD128, // EXTRACT_LANE_I64x2
    CEFBS_HasSIMD128, // EXTRACT_LANE_I64x2_S
    CEFBS_HasSIMD128, // EXTRACT_LANE_I8x16_s
    CEFBS_HasSIMD128, // EXTRACT_LANE_I8x16_s_S
    CEFBS_HasSIMD128, // EXTRACT_LANE_I8x16_u
    CEFBS_HasSIMD128, // EXTRACT_LANE_I8x16_u_S
    CEFBS_None, // F32_CONVERT_S_I32
    CEFBS_None, // F32_CONVERT_S_I32_S
    CEFBS_None, // F32_CONVERT_S_I64
    CEFBS_None, // F32_CONVERT_S_I64_S
    CEFBS_None, // F32_CONVERT_U_I32
    CEFBS_None, // F32_CONVERT_U_I32_S
    CEFBS_None, // F32_CONVERT_U_I64
    CEFBS_None, // F32_CONVERT_U_I64_S
    CEFBS_None, // F32_DEMOTE_F64
    CEFBS_None, // F32_DEMOTE_F64_S
    CEFBS_None, // F32_REINTERPRET_I32
    CEFBS_None, // F32_REINTERPRET_I32_S
    CEFBS_None, // F64_CONVERT_S_I32
    CEFBS_None, // F64_CONVERT_S_I32_S
    CEFBS_None, // F64_CONVERT_S_I64
    CEFBS_None, // F64_CONVERT_S_I64_S
    CEFBS_None, // F64_CONVERT_U_I32
    CEFBS_None, // F64_CONVERT_U_I32_S
    CEFBS_None, // F64_CONVERT_U_I64
    CEFBS_None, // F64_CONVERT_U_I64_S
    CEFBS_None, // F64_PROMOTE_F32
    CEFBS_None, // F64_PROMOTE_F32_S
    CEFBS_None, // F64_REINTERPRET_I64
    CEFBS_None, // F64_REINTERPRET_I64_S
    CEFBS_None, // FALLTHROUGH_RETURN
    CEFBS_None, // FALLTHROUGH_RETURN_S
    CEFBS_HasSIMD128_HasFP16, // FLOOR_F16x8
    CEFBS_HasSIMD128_HasFP16, // FLOOR_F16x8_S
    CEFBS_None, // FLOOR_F32
    CEFBS_None, // FLOOR_F32_S
    CEFBS_HasSIMD128, // FLOOR_F32x4
    CEFBS_HasSIMD128, // FLOOR_F32x4_S
    CEFBS_None, // FLOOR_F64
    CEFBS_None, // FLOOR_F64_S
    CEFBS_HasSIMD128, // FLOOR_F64x2
    CEFBS_HasSIMD128, // FLOOR_F64x2_S
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_SINT_I32_F32
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_SINT_I32_F32_S
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_SINT_I32_F64
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_SINT_I32_F64_S
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_SINT_I64_F32
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_SINT_I64_F32_S
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_SINT_I64_F64
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_SINT_I64_F64_S
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_UINT_I32_F32
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_UINT_I32_F32_S
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_UINT_I32_F64
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_UINT_I32_F64_S
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_UINT_I64_F32
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_UINT_I64_F32_S
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_UINT_I64_F64
    CEFBS_NotHasNontrappingFPToInt, // FP_TO_UINT_I64_F64_S
    CEFBS_HasSIMD128_HasFP16, // GE_F16x8
    CEFBS_HasSIMD128_HasFP16, // GE_F16x8_S
    CEFBS_None, // GE_F32
    CEFBS_None, // GE_F32_S
    CEFBS_HasSIMD128, // GE_F32x4
    CEFBS_HasSIMD128, // GE_F32x4_S
    CEFBS_None, // GE_F64
    CEFBS_None, // GE_F64_S
    CEFBS_HasSIMD128, // GE_F64x2
    CEFBS_HasSIMD128, // GE_F64x2_S
    CEFBS_HasSIMD128, // GE_S_I16x8
    CEFBS_HasSIMD128, // GE_S_I16x8_S
    CEFBS_None, // GE_S_I32
    CEFBS_None, // GE_S_I32_S
    CEFBS_HasSIMD128, // GE_S_I32x4
    CEFBS_HasSIMD128, // GE_S_I32x4_S
    CEFBS_None, // GE_S_I64
    CEFBS_None, // GE_S_I64_S
    CEFBS_HasSIMD128, // GE_S_I64x2
    CEFBS_HasSIMD128, // GE_S_I64x2_S
    CEFBS_HasSIMD128, // GE_S_I8x16
    CEFBS_HasSIMD128, // GE_S_I8x16_S
    CEFBS_HasSIMD128, // GE_U_I16x8
    CEFBS_HasSIMD128, // GE_U_I16x8_S
    CEFBS_None, // GE_U_I32
    CEFBS_None, // GE_U_I32_S
    CEFBS_HasSIMD128, // GE_U_I32x4
    CEFBS_HasSIMD128, // GE_U_I32x4_S
    CEFBS_None, // GE_U_I64
    CEFBS_None, // GE_U_I64_S
    CEFBS_HasSIMD128, // GE_U_I8x16
    CEFBS_HasSIMD128, // GE_U_I8x16_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // GLOBAL_GET_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // GLOBAL_GET_EXNREF_S
    CEFBS_HasReferenceTypes, // GLOBAL_GET_EXTERNREF
    CEFBS_HasReferenceTypes, // GLOBAL_GET_EXTERNREF_S
    CEFBS_None, // GLOBAL_GET_F32
    CEFBS_None, // GLOBAL_GET_F32_S
    CEFBS_None, // GLOBAL_GET_F64
    CEFBS_None, // GLOBAL_GET_F64_S
    CEFBS_HasReferenceTypes, // GLOBAL_GET_FUNCREF
    CEFBS_HasReferenceTypes, // GLOBAL_GET_FUNCREF_S
    CEFBS_None, // GLOBAL_GET_I32
    CEFBS_None, // GLOBAL_GET_I32_S
    CEFBS_None, // GLOBAL_GET_I64
    CEFBS_None, // GLOBAL_GET_I64_S
    CEFBS_HasSIMD128, // GLOBAL_GET_V128
    CEFBS_HasSIMD128, // GLOBAL_GET_V128_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // GLOBAL_SET_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // GLOBAL_SET_EXNREF_S
    CEFBS_HasReferenceTypes, // GLOBAL_SET_EXTERNREF
    CEFBS_HasReferenceTypes, // GLOBAL_SET_EXTERNREF_S
    CEFBS_None, // GLOBAL_SET_F32
    CEFBS_None, // GLOBAL_SET_F32_S
    CEFBS_None, // GLOBAL_SET_F64
    CEFBS_None, // GLOBAL_SET_F64_S
    CEFBS_HasReferenceTypes, // GLOBAL_SET_FUNCREF
    CEFBS_HasReferenceTypes, // GLOBAL_SET_FUNCREF_S
    CEFBS_None, // GLOBAL_SET_I32
    CEFBS_None, // GLOBAL_SET_I32_S
    CEFBS_None, // GLOBAL_SET_I64
    CEFBS_None, // GLOBAL_SET_I64_S
    CEFBS_HasSIMD128, // GLOBAL_SET_V128
    CEFBS_HasSIMD128, // GLOBAL_SET_V128_S
    CEFBS_HasSIMD128_HasFP16, // GT_F16x8
    CEFBS_HasSIMD128_HasFP16, // GT_F16x8_S
    CEFBS_None, // GT_F32
    CEFBS_None, // GT_F32_S
    CEFBS_HasSIMD128, // GT_F32x4
    CEFBS_HasSIMD128, // GT_F32x4_S
    CEFBS_None, // GT_F64
    CEFBS_None, // GT_F64_S
    CEFBS_HasSIMD128, // GT_F64x2
    CEFBS_HasSIMD128, // GT_F64x2_S
    CEFBS_HasSIMD128, // GT_S_I16x8
    CEFBS_HasSIMD128, // GT_S_I16x8_S
    CEFBS_None, // GT_S_I32
    CEFBS_None, // GT_S_I32_S
    CEFBS_HasSIMD128, // GT_S_I32x4
    CEFBS_HasSIMD128, // GT_S_I32x4_S
    CEFBS_None, // GT_S_I64
    CEFBS_None, // GT_S_I64_S
    CEFBS_HasSIMD128, // GT_S_I64x2
    CEFBS_HasSIMD128, // GT_S_I64x2_S
    CEFBS_HasSIMD128, // GT_S_I8x16
    CEFBS_HasSIMD128, // GT_S_I8x16_S
    CEFBS_HasSIMD128, // GT_U_I16x8
    CEFBS_HasSIMD128, // GT_U_I16x8_S
    CEFBS_None, // GT_U_I32
    CEFBS_None, // GT_U_I32_S
    CEFBS_HasSIMD128, // GT_U_I32x4
    CEFBS_HasSIMD128, // GT_U_I32x4_S
    CEFBS_None, // GT_U_I64
    CEFBS_None, // GT_U_I64_S
    CEFBS_HasSIMD128, // GT_U_I8x16
    CEFBS_HasSIMD128, // GT_U_I8x16_S
    CEFBS_HasSignExt, // I32_EXTEND16_S_I32
    CEFBS_HasSignExt, // I32_EXTEND16_S_I32_S
    CEFBS_HasSignExt, // I32_EXTEND8_S_I32
    CEFBS_HasSignExt, // I32_EXTEND8_S_I32_S
    CEFBS_None, // I32_REINTERPRET_F32
    CEFBS_None, // I32_REINTERPRET_F32_S
    CEFBS_None, // I32_TRUNC_S_F32
    CEFBS_None, // I32_TRUNC_S_F32_S
    CEFBS_None, // I32_TRUNC_S_F64
    CEFBS_None, // I32_TRUNC_S_F64_S
    CEFBS_HasNontrappingFPToInt, // I32_TRUNC_S_SAT_F32
    CEFBS_HasNontrappingFPToInt, // I32_TRUNC_S_SAT_F32_S
    CEFBS_HasNontrappingFPToInt, // I32_TRUNC_S_SAT_F64
    CEFBS_HasNontrappingFPToInt, // I32_TRUNC_S_SAT_F64_S
    CEFBS_None, // I32_TRUNC_U_F32
    CEFBS_None, // I32_TRUNC_U_F32_S
    CEFBS_None, // I32_TRUNC_U_F64
    CEFBS_None, // I32_TRUNC_U_F64_S
    CEFBS_HasNontrappingFPToInt, // I32_TRUNC_U_SAT_F32
    CEFBS_HasNontrappingFPToInt, // I32_TRUNC_U_SAT_F32_S
    CEFBS_HasNontrappingFPToInt, // I32_TRUNC_U_SAT_F64
    CEFBS_HasNontrappingFPToInt, // I32_TRUNC_U_SAT_F64_S
    CEFBS_None, // I32_WRAP_I64
    CEFBS_None, // I32_WRAP_I64_S
    CEFBS_HasWideArithmetic, // I64_ADD128
    CEFBS_HasWideArithmetic, // I64_ADD128_S
    CEFBS_HasSignExt, // I64_EXTEND16_S_I64
    CEFBS_HasSignExt, // I64_EXTEND16_S_I64_S
    CEFBS_HasSignExt, // I64_EXTEND32_S_I64
    CEFBS_HasSignExt, // I64_EXTEND32_S_I64_S
    CEFBS_HasSignExt, // I64_EXTEND8_S_I64
    CEFBS_HasSignExt, // I64_EXTEND8_S_I64_S
    CEFBS_None, // I64_EXTEND_S_I32
    CEFBS_None, // I64_EXTEND_S_I32_S
    CEFBS_None, // I64_EXTEND_U_I32
    CEFBS_None, // I64_EXTEND_U_I32_S
    CEFBS_HasWideArithmetic, // I64_MUL_WIDE_S
    CEFBS_HasWideArithmetic, // I64_MUL_WIDE_S_S
    CEFBS_HasWideArithmetic, // I64_MUL_WIDE_U
    CEFBS_HasWideArithmetic, // I64_MUL_WIDE_U_S
    CEFBS_None, // I64_REINTERPRET_F64
    CEFBS_None, // I64_REINTERPRET_F64_S
    CEFBS_HasWideArithmetic, // I64_SUB128
    CEFBS_HasWideArithmetic, // I64_SUB128_S
    CEFBS_None, // I64_TRUNC_S_F32
    CEFBS_None, // I64_TRUNC_S_F32_S
    CEFBS_None, // I64_TRUNC_S_F64
    CEFBS_None, // I64_TRUNC_S_F64_S
    CEFBS_HasNontrappingFPToInt, // I64_TRUNC_S_SAT_F32
    CEFBS_HasNontrappingFPToInt, // I64_TRUNC_S_SAT_F32_S
    CEFBS_HasNontrappingFPToInt, // I64_TRUNC_S_SAT_F64
    CEFBS_HasNontrappingFPToInt, // I64_TRUNC_S_SAT_F64_S
    CEFBS_None, // I64_TRUNC_U_F32
    CEFBS_None, // I64_TRUNC_U_F32_S
    CEFBS_None, // I64_TRUNC_U_F64
    CEFBS_None, // I64_TRUNC_U_F64_S
    CEFBS_HasNontrappingFPToInt, // I64_TRUNC_U_SAT_F32
    CEFBS_HasNontrappingFPToInt, // I64_TRUNC_U_SAT_F32_S
    CEFBS_HasNontrappingFPToInt, // I64_TRUNC_U_SAT_F64
    CEFBS_HasNontrappingFPToInt, // I64_TRUNC_U_SAT_F64_S
    CEFBS_None, // IF
    CEFBS_None, // IF_S
    CEFBS_HasRelaxedSIMD, // LANESELECT_I16x8
    CEFBS_HasRelaxedSIMD, // LANESELECT_I16x8_S
    CEFBS_HasRelaxedSIMD, // LANESELECT_I32x4
    CEFBS_HasRelaxedSIMD, // LANESELECT_I32x4_S
    CEFBS_HasRelaxedSIMD, // LANESELECT_I64x2
    CEFBS_HasRelaxedSIMD, // LANESELECT_I64x2_S
    CEFBS_HasRelaxedSIMD, // LANESELECT_I8x16
    CEFBS_HasRelaxedSIMD, // LANESELECT_I8x16_S
    CEFBS_HasSIMD128_HasFP16, // LE_F16x8
    CEFBS_HasSIMD128_HasFP16, // LE_F16x8_S
    CEFBS_None, // LE_F32
    CEFBS_None, // LE_F32_S
    CEFBS_HasSIMD128, // LE_F32x4
    CEFBS_HasSIMD128, // LE_F32x4_S
    CEFBS_None, // LE_F64
    CEFBS_None, // LE_F64_S
    CEFBS_HasSIMD128, // LE_F64x2
    CEFBS_HasSIMD128, // LE_F64x2_S
    CEFBS_HasSIMD128, // LE_S_I16x8
    CEFBS_HasSIMD128, // LE_S_I16x8_S
    CEFBS_None, // LE_S_I32
    CEFBS_None, // LE_S_I32_S
    CEFBS_HasSIMD128, // LE_S_I32x4
    CEFBS_HasSIMD128, // LE_S_I32x4_S
    CEFBS_None, // LE_S_I64
    CEFBS_None, // LE_S_I64_S
    CEFBS_HasSIMD128, // LE_S_I64x2
    CEFBS_HasSIMD128, // LE_S_I64x2_S
    CEFBS_HasSIMD128, // LE_S_I8x16
    CEFBS_HasSIMD128, // LE_S_I8x16_S
    CEFBS_HasSIMD128, // LE_U_I16x8
    CEFBS_HasSIMD128, // LE_U_I16x8_S
    CEFBS_None, // LE_U_I32
    CEFBS_None, // LE_U_I32_S
    CEFBS_HasSIMD128, // LE_U_I32x4
    CEFBS_HasSIMD128, // LE_U_I32x4_S
    CEFBS_None, // LE_U_I64
    CEFBS_None, // LE_U_I64_S
    CEFBS_HasSIMD128, // LE_U_I8x16
    CEFBS_HasSIMD128, // LE_U_I8x16_S
    CEFBS_HasSIMD128, // LOAD16_SPLAT_A32
    CEFBS_HasSIMD128, // LOAD16_SPLAT_A32_S
    CEFBS_HasSIMD128, // LOAD16_SPLAT_A64
    CEFBS_HasSIMD128, // LOAD16_SPLAT_A64_S
    CEFBS_None, // LOAD16_S_I32_A32
    CEFBS_None, // LOAD16_S_I32_A32_S
    CEFBS_None, // LOAD16_S_I32_A64
    CEFBS_None, // LOAD16_S_I32_A64_S
    CEFBS_None, // LOAD16_S_I64_A32
    CEFBS_None, // LOAD16_S_I64_A32_S
    CEFBS_None, // LOAD16_S_I64_A64
    CEFBS_None, // LOAD16_S_I64_A64_S
    CEFBS_None, // LOAD16_U_I32_A32
    CEFBS_None, // LOAD16_U_I32_A32_S
    CEFBS_None, // LOAD16_U_I32_A64
    CEFBS_None, // LOAD16_U_I32_A64_S
    CEFBS_None, // LOAD16_U_I64_A32
    CEFBS_None, // LOAD16_U_I64_A32_S
    CEFBS_None, // LOAD16_U_I64_A64
    CEFBS_None, // LOAD16_U_I64_A64_S
    CEFBS_HasSIMD128, // LOAD32_SPLAT_A32
    CEFBS_HasSIMD128, // LOAD32_SPLAT_A32_S
    CEFBS_HasSIMD128, // LOAD32_SPLAT_A64
    CEFBS_HasSIMD128, // LOAD32_SPLAT_A64_S
    CEFBS_None, // LOAD32_S_I64_A32
    CEFBS_None, // LOAD32_S_I64_A32_S
    CEFBS_None, // LOAD32_S_I64_A64
    CEFBS_None, // LOAD32_S_I64_A64_S
    CEFBS_None, // LOAD32_U_I64_A32
    CEFBS_None, // LOAD32_U_I64_A32_S
    CEFBS_None, // LOAD32_U_I64_A64
    CEFBS_None, // LOAD32_U_I64_A64_S
    CEFBS_HasSIMD128, // LOAD64_SPLAT_A32
    CEFBS_HasSIMD128, // LOAD64_SPLAT_A32_S
    CEFBS_HasSIMD128, // LOAD64_SPLAT_A64
    CEFBS_HasSIMD128, // LOAD64_SPLAT_A64_S
    CEFBS_HasSIMD128, // LOAD8_SPLAT_A32
    CEFBS_HasSIMD128, // LOAD8_SPLAT_A32_S
    CEFBS_HasSIMD128, // LOAD8_SPLAT_A64
    CEFBS_HasSIMD128, // LOAD8_SPLAT_A64_S
    CEFBS_None, // LOAD8_S_I32_A32
    CEFBS_None, // LOAD8_S_I32_A32_S
    CEFBS_None, // LOAD8_S_I32_A64
    CEFBS_None, // LOAD8_S_I32_A64_S
    CEFBS_None, // LOAD8_S_I64_A32
    CEFBS_None, // LOAD8_S_I64_A32_S
    CEFBS_None, // LOAD8_S_I64_A64
    CEFBS_None, // LOAD8_S_I64_A64_S
    CEFBS_None, // LOAD8_U_I32_A32
    CEFBS_None, // LOAD8_U_I32_A32_S
    CEFBS_None, // LOAD8_U_I32_A64
    CEFBS_None, // LOAD8_U_I32_A64_S
    CEFBS_None, // LOAD8_U_I64_A32
    CEFBS_None, // LOAD8_U_I64_A32_S
    CEFBS_None, // LOAD8_U_I64_A64
    CEFBS_None, // LOAD8_U_I64_A64_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I16x8_A32
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I16x8_A32_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I16x8_A64
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I16x8_A64_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I32x4_A32
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I32x4_A32_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I32x4_A64
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I32x4_A64_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I64x2_A32
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I64x2_A32_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I64x2_A64
    CEFBS_HasSIMD128, // LOAD_EXTEND_S_I64x2_A64_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I16x8_A32
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I16x8_A32_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I16x8_A64
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I16x8_A64_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I32x4_A32
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I32x4_A32_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I32x4_A64
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I32x4_A64_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I64x2_A32
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I64x2_A32_S
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I64x2_A64
    CEFBS_HasSIMD128, // LOAD_EXTEND_U_I64x2_A64_S
    CEFBS_HasFP16, // LOAD_F16_F32_A32
    CEFBS_HasFP16, // LOAD_F16_F32_A32_S
    CEFBS_HasFP16, // LOAD_F16_F32_A64
    CEFBS_HasFP16, // LOAD_F16_F32_A64_S
    CEFBS_None, // LOAD_F32_A32
    CEFBS_None, // LOAD_F32_A32_S
    CEFBS_None, // LOAD_F32_A64
    CEFBS_None, // LOAD_F32_A64_S
    CEFBS_None, // LOAD_F64_A32
    CEFBS_None, // LOAD_F64_A32_S
    CEFBS_None, // LOAD_F64_A64
    CEFBS_None, // LOAD_F64_A64_S
    CEFBS_None, // LOAD_I32_A32
    CEFBS_None, // LOAD_I32_A32_S
    CEFBS_None, // LOAD_I32_A64
    CEFBS_None, // LOAD_I32_A64_S
    CEFBS_None, // LOAD_I64_A32
    CEFBS_None, // LOAD_I64_A32_S
    CEFBS_None, // LOAD_I64_A64
    CEFBS_None, // LOAD_I64_A64_S
    CEFBS_HasSIMD128, // LOAD_LANE_16_A32
    CEFBS_HasSIMD128, // LOAD_LANE_16_A32_S
    CEFBS_HasSIMD128, // LOAD_LANE_16_A64
    CEFBS_HasSIMD128, // LOAD_LANE_16_A64_S
    CEFBS_HasSIMD128, // LOAD_LANE_32_A32
    CEFBS_HasSIMD128, // LOAD_LANE_32_A32_S
    CEFBS_HasSIMD128, // LOAD_LANE_32_A64
    CEFBS_HasSIMD128, // LOAD_LANE_32_A64_S
    CEFBS_HasSIMD128, // LOAD_LANE_64_A32
    CEFBS_HasSIMD128, // LOAD_LANE_64_A32_S
    CEFBS_HasSIMD128, // LOAD_LANE_64_A64
    CEFBS_HasSIMD128, // LOAD_LANE_64_A64_S
    CEFBS_HasSIMD128, // LOAD_LANE_8_A32
    CEFBS_HasSIMD128, // LOAD_LANE_8_A32_S
    CEFBS_HasSIMD128, // LOAD_LANE_8_A64
    CEFBS_HasSIMD128, // LOAD_LANE_8_A64_S
    CEFBS_HasSIMD128, // LOAD_V128_A32
    CEFBS_HasSIMD128, // LOAD_V128_A32_S
    CEFBS_HasSIMD128, // LOAD_V128_A64
    CEFBS_HasSIMD128, // LOAD_V128_A64_S
    CEFBS_HasSIMD128, // LOAD_ZERO_32_A32
    CEFBS_HasSIMD128, // LOAD_ZERO_32_A32_S
    CEFBS_HasSIMD128, // LOAD_ZERO_32_A64
    CEFBS_HasSIMD128, // LOAD_ZERO_32_A64_S
    CEFBS_HasSIMD128, // LOAD_ZERO_64_A32
    CEFBS_HasSIMD128, // LOAD_ZERO_64_A32_S
    CEFBS_HasSIMD128, // LOAD_ZERO_64_A64
    CEFBS_HasSIMD128, // LOAD_ZERO_64_A64_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // LOCAL_GET_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // LOCAL_GET_EXNREF_S
    CEFBS_HasReferenceTypes, // LOCAL_GET_EXTERNREF
    CEFBS_HasReferenceTypes, // LOCAL_GET_EXTERNREF_S
    CEFBS_None, // LOCAL_GET_F32
    CEFBS_None, // LOCAL_GET_F32_S
    CEFBS_None, // LOCAL_GET_F64
    CEFBS_None, // LOCAL_GET_F64_S
    CEFBS_HasReferenceTypes, // LOCAL_GET_FUNCREF
    CEFBS_HasReferenceTypes, // LOCAL_GET_FUNCREF_S
    CEFBS_None, // LOCAL_GET_I32
    CEFBS_None, // LOCAL_GET_I32_S
    CEFBS_None, // LOCAL_GET_I64
    CEFBS_None, // LOCAL_GET_I64_S
    CEFBS_HasSIMD128, // LOCAL_GET_V128
    CEFBS_HasSIMD128, // LOCAL_GET_V128_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // LOCAL_SET_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // LOCAL_SET_EXNREF_S
    CEFBS_HasReferenceTypes, // LOCAL_SET_EXTERNREF
    CEFBS_HasReferenceTypes, // LOCAL_SET_EXTERNREF_S
    CEFBS_None, // LOCAL_SET_F32
    CEFBS_None, // LOCAL_SET_F32_S
    CEFBS_None, // LOCAL_SET_F64
    CEFBS_None, // LOCAL_SET_F64_S
    CEFBS_HasReferenceTypes, // LOCAL_SET_FUNCREF
    CEFBS_HasReferenceTypes, // LOCAL_SET_FUNCREF_S
    CEFBS_None, // LOCAL_SET_I32
    CEFBS_None, // LOCAL_SET_I32_S
    CEFBS_None, // LOCAL_SET_I64
    CEFBS_None, // LOCAL_SET_I64_S
    CEFBS_HasSIMD128, // LOCAL_SET_V128
    CEFBS_HasSIMD128, // LOCAL_SET_V128_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // LOCAL_TEE_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // LOCAL_TEE_EXNREF_S
    CEFBS_HasReferenceTypes, // LOCAL_TEE_EXTERNREF
    CEFBS_HasReferenceTypes, // LOCAL_TEE_EXTERNREF_S
    CEFBS_None, // LOCAL_TEE_F32
    CEFBS_None, // LOCAL_TEE_F32_S
    CEFBS_None, // LOCAL_TEE_F64
    CEFBS_None, // LOCAL_TEE_F64_S
    CEFBS_HasReferenceTypes, // LOCAL_TEE_FUNCREF
    CEFBS_HasReferenceTypes, // LOCAL_TEE_FUNCREF_S
    CEFBS_None, // LOCAL_TEE_I32
    CEFBS_None, // LOCAL_TEE_I32_S
    CEFBS_None, // LOCAL_TEE_I64
    CEFBS_None, // LOCAL_TEE_I64_S
    CEFBS_HasSIMD128, // LOCAL_TEE_V128
    CEFBS_HasSIMD128, // LOCAL_TEE_V128_S
    CEFBS_None, // LOOP
    CEFBS_None, // LOOP_S
    CEFBS_HasSIMD128_HasFP16, // LT_F16x8
    CEFBS_HasSIMD128_HasFP16, // LT_F16x8_S
    CEFBS_None, // LT_F32
    CEFBS_None, // LT_F32_S
    CEFBS_HasSIMD128, // LT_F32x4
    CEFBS_HasSIMD128, // LT_F32x4_S
    CEFBS_None, // LT_F64
    CEFBS_None, // LT_F64_S
    CEFBS_HasSIMD128, // LT_F64x2
    CEFBS_HasSIMD128, // LT_F64x2_S
    CEFBS_HasSIMD128, // LT_S_I16x8
    CEFBS_HasSIMD128, // LT_S_I16x8_S
    CEFBS_None, // LT_S_I32
    CEFBS_None, // LT_S_I32_S
    CEFBS_HasSIMD128, // LT_S_I32x4
    CEFBS_HasSIMD128, // LT_S_I32x4_S
    CEFBS_None, // LT_S_I64
    CEFBS_None, // LT_S_I64_S
    CEFBS_HasSIMD128, // LT_S_I64x2
    CEFBS_HasSIMD128, // LT_S_I64x2_S
    CEFBS_HasSIMD128, // LT_S_I8x16
    CEFBS_HasSIMD128, // LT_S_I8x16_S
    CEFBS_HasSIMD128, // LT_U_I16x8
    CEFBS_HasSIMD128, // LT_U_I16x8_S
    CEFBS_None, // LT_U_I32
    CEFBS_None, // LT_U_I32_S
    CEFBS_HasSIMD128, // LT_U_I32x4
    CEFBS_HasSIMD128, // LT_U_I32x4_S
    CEFBS_None, // LT_U_I64
    CEFBS_None, // LT_U_I64_S
    CEFBS_HasSIMD128, // LT_U_I8x16
    CEFBS_HasSIMD128, // LT_U_I8x16_S
    CEFBS_HasSIMD128_HasFP16, // MADD_F16x8
    CEFBS_HasSIMD128_HasFP16, // MADD_F16x8_S
    CEFBS_HasSIMD128_HasRelaxedSIMD, // MADD_F32x4
    CEFBS_HasSIMD128_HasRelaxedSIMD, // MADD_F32x4_S
    CEFBS_HasSIMD128_HasRelaxedSIMD, // MADD_F64x2
    CEFBS_HasSIMD128_HasRelaxedSIMD, // MADD_F64x2_S
    CEFBS_HasSIMD128_HasFP16, // MAX_F16x8
    CEFBS_HasSIMD128_HasFP16, // MAX_F16x8_S
    CEFBS_None, // MAX_F32
    CEFBS_None, // MAX_F32_S
    CEFBS_HasSIMD128, // MAX_F32x4
    CEFBS_HasSIMD128, // MAX_F32x4_S
    CEFBS_None, // MAX_F64
    CEFBS_None, // MAX_F64_S
    CEFBS_HasSIMD128, // MAX_F64x2
    CEFBS_HasSIMD128, // MAX_F64x2_S
    CEFBS_HasSIMD128, // MAX_S_I16x8
    CEFBS_HasSIMD128, // MAX_S_I16x8_S
    CEFBS_HasSIMD128, // MAX_S_I32x4
    CEFBS_HasSIMD128, // MAX_S_I32x4_S
    CEFBS_HasSIMD128, // MAX_S_I8x16
    CEFBS_HasSIMD128, // MAX_S_I8x16_S
    CEFBS_HasSIMD128, // MAX_U_I16x8
    CEFBS_HasSIMD128, // MAX_U_I16x8_S
    CEFBS_HasSIMD128, // MAX_U_I32x4
    CEFBS_HasSIMD128, // MAX_U_I32x4_S
    CEFBS_HasSIMD128, // MAX_U_I8x16
    CEFBS_HasSIMD128, // MAX_U_I8x16_S
    CEFBS_HasBulkMemoryOpt, // MEMCPY_A32
    CEFBS_HasBulkMemoryOpt, // MEMCPY_A32_S
    CEFBS_HasBulkMemoryOpt, // MEMCPY_A64
    CEFBS_HasBulkMemoryOpt, // MEMCPY_A64_S
    CEFBS_HasAtomics, // MEMORY_ATOMIC_NOTIFY_A32
    CEFBS_HasAtomics, // MEMORY_ATOMIC_NOTIFY_A32_S
    CEFBS_HasAtomics, // MEMORY_ATOMIC_NOTIFY_A64
    CEFBS_HasAtomics, // MEMORY_ATOMIC_NOTIFY_A64_S
    CEFBS_HasAtomics, // MEMORY_ATOMIC_WAIT32_A32
    CEFBS_HasAtomics, // MEMORY_ATOMIC_WAIT32_A32_S
    CEFBS_HasAtomics, // MEMORY_ATOMIC_WAIT32_A64
    CEFBS_HasAtomics, // MEMORY_ATOMIC_WAIT32_A64_S
    CEFBS_HasAtomics, // MEMORY_ATOMIC_WAIT64_A32
    CEFBS_HasAtomics, // MEMORY_ATOMIC_WAIT64_A32_S
    CEFBS_HasAtomics, // MEMORY_ATOMIC_WAIT64_A64
    CEFBS_HasAtomics, // MEMORY_ATOMIC_WAIT64_A64_S
    CEFBS_HasBulkMemoryOpt, // MEMORY_COPY_A32
    CEFBS_HasBulkMemoryOpt, // MEMORY_COPY_A32_S
    CEFBS_HasBulkMemoryOpt, // MEMORY_COPY_A64
    CEFBS_HasBulkMemoryOpt, // MEMORY_COPY_A64_S
    CEFBS_HasBulkMemoryOpt, // MEMORY_FILL_A32
    CEFBS_HasBulkMemoryOpt, // MEMORY_FILL_A32_S
    CEFBS_HasBulkMemoryOpt, // MEMORY_FILL_A64
    CEFBS_HasBulkMemoryOpt, // MEMORY_FILL_A64_S
    CEFBS_HasBulkMemoryOpt, // MEMORY_INIT_A32
    CEFBS_HasBulkMemoryOpt, // MEMORY_INIT_A32_S
    CEFBS_HasBulkMemoryOpt, // MEMORY_INIT_A64
    CEFBS_HasBulkMemoryOpt, // MEMORY_INIT_A64_S
    CEFBS_HasBulkMemoryOpt, // MEMSET_A32
    CEFBS_HasBulkMemoryOpt, // MEMSET_A32_S
    CEFBS_HasBulkMemoryOpt, // MEMSET_A64
    CEFBS_HasBulkMemoryOpt, // MEMSET_A64_S
    CEFBS_HasSIMD128_HasFP16, // MIN_F16x8
    CEFBS_HasSIMD128_HasFP16, // MIN_F16x8_S
    CEFBS_None, // MIN_F32
    CEFBS_None, // MIN_F32_S
    CEFBS_HasSIMD128, // MIN_F32x4
    CEFBS_HasSIMD128, // MIN_F32x4_S
    CEFBS_None, // MIN_F64
    CEFBS_None, // MIN_F64_S
    CEFBS_HasSIMD128, // MIN_F64x2
    CEFBS_HasSIMD128, // MIN_F64x2_S
    CEFBS_HasSIMD128, // MIN_S_I16x8
    CEFBS_HasSIMD128, // MIN_S_I16x8_S
    CEFBS_HasSIMD128, // MIN_S_I32x4
    CEFBS_HasSIMD128, // MIN_S_I32x4_S
    CEFBS_HasSIMD128, // MIN_S_I8x16
    CEFBS_HasSIMD128, // MIN_S_I8x16_S
    CEFBS_HasSIMD128, // MIN_U_I16x8
    CEFBS_HasSIMD128, // MIN_U_I16x8_S
    CEFBS_HasSIMD128, // MIN_U_I32x4
    CEFBS_HasSIMD128, // MIN_U_I32x4_S
    CEFBS_HasSIMD128, // MIN_U_I8x16
    CEFBS_HasSIMD128, // MIN_U_I8x16_S
    CEFBS_HasSIMD128_HasFP16, // MUL_F16x8
    CEFBS_HasSIMD128_HasFP16, // MUL_F16x8_S
    CEFBS_None, // MUL_F32
    CEFBS_None, // MUL_F32_S
    CEFBS_HasSIMD128, // MUL_F32x4
    CEFBS_HasSIMD128, // MUL_F32x4_S
    CEFBS_None, // MUL_F64
    CEFBS_None, // MUL_F64_S
    CEFBS_HasSIMD128, // MUL_F64x2
    CEFBS_HasSIMD128, // MUL_F64x2_S
    CEFBS_HasSIMD128, // MUL_I16x8
    CEFBS_HasSIMD128, // MUL_I16x8_S
    CEFBS_None, // MUL_I32
    CEFBS_None, // MUL_I32_S
    CEFBS_HasSIMD128, // MUL_I32x4
    CEFBS_HasSIMD128, // MUL_I32x4_S
    CEFBS_None, // MUL_I64
    CEFBS_None, // MUL_I64_S
    CEFBS_HasSIMD128, // MUL_I64x2
    CEFBS_HasSIMD128, // MUL_I64x2_S
    CEFBS_HasSIMD128, // NARROW_S_I16x8
    CEFBS_HasSIMD128, // NARROW_S_I16x8_S
    CEFBS_HasSIMD128, // NARROW_S_I8x16
    CEFBS_HasSIMD128, // NARROW_S_I8x16_S
    CEFBS_HasSIMD128, // NARROW_U_I16x8
    CEFBS_HasSIMD128, // NARROW_U_I16x8_S
    CEFBS_HasSIMD128, // NARROW_U_I8x16
    CEFBS_HasSIMD128, // NARROW_U_I8x16_S
    CEFBS_HasSIMD128_HasFP16, // NEAREST_F16x8
    CEFBS_HasSIMD128_HasFP16, // NEAREST_F16x8_S
    CEFBS_None, // NEAREST_F32
    CEFBS_None, // NEAREST_F32_S
    CEFBS_HasSIMD128, // NEAREST_F32x4
    CEFBS_HasSIMD128, // NEAREST_F32x4_S
    CEFBS_None, // NEAREST_F64
    CEFBS_None, // NEAREST_F64_S
    CEFBS_HasSIMD128, // NEAREST_F64x2
    CEFBS_HasSIMD128, // NEAREST_F64x2_S
    CEFBS_HasSIMD128_HasFP16, // NEG_F16x8
    CEFBS_HasSIMD128_HasFP16, // NEG_F16x8_S
    CEFBS_None, // NEG_F32
    CEFBS_None, // NEG_F32_S
    CEFBS_HasSIMD128, // NEG_F32x4
    CEFBS_HasSIMD128, // NEG_F32x4_S
    CEFBS_None, // NEG_F64
    CEFBS_None, // NEG_F64_S
    CEFBS_HasSIMD128, // NEG_F64x2
    CEFBS_HasSIMD128, // NEG_F64x2_S
    CEFBS_HasSIMD128, // NEG_I16x8
    CEFBS_HasSIMD128, // NEG_I16x8_S
    CEFBS_HasSIMD128, // NEG_I32x4
    CEFBS_HasSIMD128, // NEG_I32x4_S
    CEFBS_HasSIMD128, // NEG_I64x2
    CEFBS_HasSIMD128, // NEG_I64x2_S
    CEFBS_HasSIMD128, // NEG_I8x16
    CEFBS_HasSIMD128, // NEG_I8x16_S
    CEFBS_HasSIMD128_HasFP16, // NE_F16x8
    CEFBS_HasSIMD128_HasFP16, // NE_F16x8_S
    CEFBS_None, // NE_F32
    CEFBS_None, // NE_F32_S
    CEFBS_HasSIMD128, // NE_F32x4
    CEFBS_HasSIMD128, // NE_F32x4_S
    CEFBS_None, // NE_F64
    CEFBS_None, // NE_F64_S
    CEFBS_HasSIMD128, // NE_F64x2
    CEFBS_HasSIMD128, // NE_F64x2_S
    CEFBS_HasSIMD128, // NE_I16x8
    CEFBS_HasSIMD128, // NE_I16x8_S
    CEFBS_None, // NE_I32
    CEFBS_None, // NE_I32_S
    CEFBS_HasSIMD128, // NE_I32x4
    CEFBS_HasSIMD128, // NE_I32x4_S
    CEFBS_None, // NE_I64
    CEFBS_None, // NE_I64_S
    CEFBS_HasSIMD128, // NE_I64x2
    CEFBS_HasSIMD128, // NE_I64x2_S
    CEFBS_HasSIMD128, // NE_I8x16
    CEFBS_HasSIMD128, // NE_I8x16_S
    CEFBS_HasSIMD128_HasFP16, // NMADD_F16x8
    CEFBS_HasSIMD128_HasFP16, // NMADD_F16x8_S
    CEFBS_HasSIMD128_HasRelaxedSIMD, // NMADD_F32x4
    CEFBS_HasSIMD128_HasRelaxedSIMD, // NMADD_F32x4_S
    CEFBS_HasSIMD128_HasRelaxedSIMD, // NMADD_F64x2
    CEFBS_HasSIMD128_HasRelaxedSIMD, // NMADD_F64x2_S
    CEFBS_None, // NOP
    CEFBS_None, // NOP_S
    CEFBS_HasSIMD128, // NOT
    CEFBS_HasSIMD128, // NOT_S
    CEFBS_HasSIMD128, // OR
    CEFBS_None, // OR_I32
    CEFBS_None, // OR_I32_S
    CEFBS_None, // OR_I64
    CEFBS_None, // OR_I64_S
    CEFBS_HasSIMD128, // OR_S
    CEFBS_HasSIMD128_HasFP16, // PMAX_F16x8
    CEFBS_HasSIMD128_HasFP16, // PMAX_F16x8_S
    CEFBS_HasSIMD128, // PMAX_F32x4
    CEFBS_HasSIMD128, // PMAX_F32x4_S
    CEFBS_HasSIMD128, // PMAX_F64x2
    CEFBS_HasSIMD128, // PMAX_F64x2_S
    CEFBS_HasSIMD128_HasFP16, // PMIN_F16x8
    CEFBS_HasSIMD128_HasFP16, // PMIN_F16x8_S
    CEFBS_HasSIMD128, // PMIN_F32x4
    CEFBS_HasSIMD128, // PMIN_F32x4_S
    CEFBS_HasSIMD128, // PMIN_F64x2
    CEFBS_HasSIMD128, // PMIN_F64x2_S
    CEFBS_None, // POPCNT_I32
    CEFBS_None, // POPCNT_I32_S
    CEFBS_None, // POPCNT_I64
    CEFBS_None, // POPCNT_I64_S
    CEFBS_HasSIMD128, // POPCNT_I8x16
    CEFBS_HasSIMD128, // POPCNT_I8x16_S
    CEFBS_HasSIMD128, // Q15MULR_SAT_S_I16x8
    CEFBS_HasSIMD128, // Q15MULR_SAT_S_I16x8_S
    CEFBS_HasGC, // REF_CAST_FUNCREF
    CEFBS_HasGC, // REF_CAST_FUNCREF_S
    CEFBS_HasReferenceTypes, // REF_FUNC
    CEFBS_HasReferenceTypes, // REF_FUNC_S
    CEFBS_HasReferenceTypes, // REF_IS_NULL_EXNREF
    CEFBS_HasReferenceTypes, // REF_IS_NULL_EXNREF_S
    CEFBS_HasReferenceTypes, // REF_IS_NULL_EXTERNREF
    CEFBS_HasReferenceTypes, // REF_IS_NULL_EXTERNREF_S
    CEFBS_HasReferenceTypes, // REF_IS_NULL_FUNCREF
    CEFBS_HasReferenceTypes, // REF_IS_NULL_FUNCREF_S
    CEFBS_HasReferenceTypes, // REF_NULL_EXNREF
    CEFBS_HasReferenceTypes, // REF_NULL_EXNREF_S
    CEFBS_HasReferenceTypes, // REF_NULL_EXTERNREF
    CEFBS_HasReferenceTypes, // REF_NULL_EXTERNREF_S
    CEFBS_HasReferenceTypes, // REF_NULL_FUNCREF
    CEFBS_HasReferenceTypes, // REF_NULL_FUNCREF_S
    CEFBS_HasGC, // REF_TEST_FUNCREF
    CEFBS_HasGC, // REF_TEST_FUNCREF_S
    CEFBS_HasRelaxedSIMD, // RELAXED_DOT
    CEFBS_HasRelaxedSIMD, // RELAXED_DOT_ADD
    CEFBS_HasRelaxedSIMD, // RELAXED_DOT_ADD_S
    CEFBS_HasRelaxedSIMD, // RELAXED_DOT_BFLOAT
    CEFBS_HasRelaxedSIMD, // RELAXED_DOT_BFLOAT_S
    CEFBS_HasRelaxedSIMD, // RELAXED_DOT_S
    CEFBS_HasRelaxedSIMD, // RELAXED_Q15MULR_S_I16x8
    CEFBS_HasRelaxedSIMD, // RELAXED_Q15MULR_S_I16x8_S
    CEFBS_HasRelaxedSIMD, // RELAXED_SWIZZLE
    CEFBS_HasRelaxedSIMD, // RELAXED_SWIZZLE_S
    CEFBS_None, // REM_S_I32
    CEFBS_None, // REM_S_I32_S
    CEFBS_None, // REM_S_I64
    CEFBS_None, // REM_S_I64_S
    CEFBS_None, // REM_U_I32
    CEFBS_None, // REM_U_I32_S
    CEFBS_None, // REM_U_I64
    CEFBS_None, // REM_U_I64_S
    CEFBS_HasFP16, // REPLACE_LANE_F16x8
    CEFBS_HasFP16, // REPLACE_LANE_F16x8_S
    CEFBS_HasSIMD128, // REPLACE_LANE_F32x4
    CEFBS_HasSIMD128, // REPLACE_LANE_F32x4_S
    CEFBS_HasSIMD128, // REPLACE_LANE_F64x2
    CEFBS_HasSIMD128, // REPLACE_LANE_F64x2_S
    CEFBS_HasSIMD128, // REPLACE_LANE_I16x8
    CEFBS_HasSIMD128, // REPLACE_LANE_I16x8_S
    CEFBS_HasSIMD128, // REPLACE_LANE_I32x4
    CEFBS_HasSIMD128, // REPLACE_LANE_I32x4_S
    CEFBS_HasSIMD128, // REPLACE_LANE_I64x2
    CEFBS_HasSIMD128, // REPLACE_LANE_I64x2_S
    CEFBS_HasSIMD128, // REPLACE_LANE_I8x16
    CEFBS_HasSIMD128, // REPLACE_LANE_I8x16_S
    CEFBS_HasExceptionHandling, // RETHROW
    CEFBS_HasExceptionHandling, // RETHROW_S
    CEFBS_None, // RETURN
    CEFBS_None, // RETURN_S
    CEFBS_HasTailCall, // RET_CALL
    CEFBS_HasTailCall, // RET_CALL_INDIRECT
    CEFBS_HasTailCall, // RET_CALL_INDIRECT_S
    CEFBS_HasTailCall_HasGC, // RET_CALL_REF
    CEFBS_HasTailCall_HasGC, // RET_CALL_REF_S
    CEFBS_HasTailCall, // RET_CALL_S
    CEFBS_None, // ROTL_I32
    CEFBS_None, // ROTL_I32_S
    CEFBS_None, // ROTL_I64
    CEFBS_None, // ROTL_I64_S
    CEFBS_None, // ROTR_I32
    CEFBS_None, // ROTR_I32_S
    CEFBS_None, // ROTR_I64
    CEFBS_None, // ROTR_I64_S
    CEFBS_HasReferenceTypes, // SELECT_EXNREF
    CEFBS_HasReferenceTypes, // SELECT_EXNREF_S
    CEFBS_HasReferenceTypes, // SELECT_EXTERNREF
    CEFBS_HasReferenceTypes, // SELECT_EXTERNREF_S
    CEFBS_None, // SELECT_F32
    CEFBS_None, // SELECT_F32_S
    CEFBS_None, // SELECT_F64
    CEFBS_None, // SELECT_F64_S
    CEFBS_HasReferenceTypes, // SELECT_FUNCREF
    CEFBS_HasReferenceTypes, // SELECT_FUNCREF_S
    CEFBS_None, // SELECT_I32
    CEFBS_None, // SELECT_I32_S
    CEFBS_None, // SELECT_I64
    CEFBS_None, // SELECT_I64_S
    CEFBS_HasReferenceTypes, // SELECT_T
    CEFBS_HasReferenceTypes, // SELECT_T_S
    CEFBS_None, // SELECT_V128
    CEFBS_None, // SELECT_V128_S
    CEFBS_HasSIMD128, // SHL_I16x8
    CEFBS_HasSIMD128, // SHL_I16x8_S
    CEFBS_None, // SHL_I32
    CEFBS_None, // SHL_I32_S
    CEFBS_HasSIMD128, // SHL_I32x4
    CEFBS_HasSIMD128, // SHL_I32x4_S
    CEFBS_None, // SHL_I64
    CEFBS_None, // SHL_I64_S
    CEFBS_HasSIMD128, // SHL_I64x2
    CEFBS_HasSIMD128, // SHL_I64x2_S
    CEFBS_HasSIMD128, // SHL_I8x16
    CEFBS_HasSIMD128, // SHL_I8x16_S
    CEFBS_HasSIMD128, // SHR_S_I16x8
    CEFBS_HasSIMD128, // SHR_S_I16x8_S
    CEFBS_None, // SHR_S_I32
    CEFBS_None, // SHR_S_I32_S
    CEFBS_HasSIMD128, // SHR_S_I32x4
    CEFBS_HasSIMD128, // SHR_S_I32x4_S
    CEFBS_None, // SHR_S_I64
    CEFBS_None, // SHR_S_I64_S
    CEFBS_HasSIMD128, // SHR_S_I64x2
    CEFBS_HasSIMD128, // SHR_S_I64x2_S
    CEFBS_HasSIMD128, // SHR_S_I8x16
    CEFBS_HasSIMD128, // SHR_S_I8x16_S
    CEFBS_HasSIMD128, // SHR_U_I16x8
    CEFBS_HasSIMD128, // SHR_U_I16x8_S
    CEFBS_None, // SHR_U_I32
    CEFBS_None, // SHR_U_I32_S
    CEFBS_HasSIMD128, // SHR_U_I32x4
    CEFBS_HasSIMD128, // SHR_U_I32x4_S
    CEFBS_None, // SHR_U_I64
    CEFBS_None, // SHR_U_I64_S
    CEFBS_HasSIMD128, // SHR_U_I64x2
    CEFBS_HasSIMD128, // SHR_U_I64x2_S
    CEFBS_HasSIMD128, // SHR_U_I8x16
    CEFBS_HasSIMD128, // SHR_U_I8x16_S
    CEFBS_HasSIMD128, // SHUFFLE
    CEFBS_HasSIMD128, // SHUFFLE_S
    CEFBS_HasRelaxedSIMD, // SIMD_RELAXED_FMAX_F32x4
    CEFBS_HasRelaxedSIMD, // SIMD_RELAXED_FMAX_F32x4_S
    CEFBS_HasRelaxedSIMD, // SIMD_RELAXED_FMAX_F64x2
    CEFBS_HasRelaxedSIMD, // SIMD_RELAXED_FMAX_F64x2_S
    CEFBS_HasRelaxedSIMD, // SIMD_RELAXED_FMIN_F32x4
    CEFBS_HasRelaxedSIMD, // SIMD_RELAXED_FMIN_F32x4_S
    CEFBS_HasRelaxedSIMD, // SIMD_RELAXED_FMIN_F64x2
    CEFBS_HasRelaxedSIMD, // SIMD_RELAXED_FMIN_F64x2_S
    CEFBS_HasFP16, // SPLAT_F16x8
    CEFBS_HasFP16, // SPLAT_F16x8_S
    CEFBS_HasSIMD128, // SPLAT_F32x4
    CEFBS_HasSIMD128, // SPLAT_F32x4_S
    CEFBS_HasSIMD128, // SPLAT_F64x2
    CEFBS_HasSIMD128, // SPLAT_F64x2_S
    CEFBS_HasSIMD128, // SPLAT_I16x8
    CEFBS_HasSIMD128, // SPLAT_I16x8_S
    CEFBS_HasSIMD128, // SPLAT_I32x4
    CEFBS_HasSIMD128, // SPLAT_I32x4_S
    CEFBS_HasSIMD128, // SPLAT_I64x2
    CEFBS_HasSIMD128, // SPLAT_I64x2_S
    CEFBS_HasSIMD128, // SPLAT_I8x16
    CEFBS_HasSIMD128, // SPLAT_I8x16_S
    CEFBS_HasSIMD128_HasFP16, // SQRT_F16x8
    CEFBS_HasSIMD128_HasFP16, // SQRT_F16x8_S
    CEFBS_None, // SQRT_F32
    CEFBS_None, // SQRT_F32_S
    CEFBS_HasSIMD128, // SQRT_F32x4
    CEFBS_HasSIMD128, // SQRT_F32x4_S
    CEFBS_None, // SQRT_F64
    CEFBS_None, // SQRT_F64_S
    CEFBS_HasSIMD128, // SQRT_F64x2
    CEFBS_HasSIMD128, // SQRT_F64x2_S
    CEFBS_None, // STORE16_I32_A32
    CEFBS_None, // STORE16_I32_A32_S
    CEFBS_None, // STORE16_I32_A64
    CEFBS_None, // STORE16_I32_A64_S
    CEFBS_None, // STORE16_I64_A32
    CEFBS_None, // STORE16_I64_A32_S
    CEFBS_None, // STORE16_I64_A64
    CEFBS_None, // STORE16_I64_A64_S
    CEFBS_None, // STORE32_I64_A32
    CEFBS_None, // STORE32_I64_A32_S
    CEFBS_None, // STORE32_I64_A64
    CEFBS_None, // STORE32_I64_A64_S
    CEFBS_None, // STORE8_I32_A32
    CEFBS_None, // STORE8_I32_A32_S
    CEFBS_None, // STORE8_I32_A64
    CEFBS_None, // STORE8_I32_A64_S
    CEFBS_None, // STORE8_I64_A32
    CEFBS_None, // STORE8_I64_A32_S
    CEFBS_None, // STORE8_I64_A64
    CEFBS_None, // STORE8_I64_A64_S
    CEFBS_HasFP16, // STORE_F16_F32_A32
    CEFBS_HasFP16, // STORE_F16_F32_A32_S
    CEFBS_HasFP16, // STORE_F16_F32_A64
    CEFBS_HasFP16, // STORE_F16_F32_A64_S
    CEFBS_None, // STORE_F32_A32
    CEFBS_None, // STORE_F32_A32_S
    CEFBS_None, // STORE_F32_A64
    CEFBS_None, // STORE_F32_A64_S
    CEFBS_None, // STORE_F64_A32
    CEFBS_None, // STORE_F64_A32_S
    CEFBS_None, // STORE_F64_A64
    CEFBS_None, // STORE_F64_A64_S
    CEFBS_None, // STORE_I32_A32
    CEFBS_None, // STORE_I32_A32_S
    CEFBS_None, // STORE_I32_A64
    CEFBS_None, // STORE_I32_A64_S
    CEFBS_None, // STORE_I64_A32
    CEFBS_None, // STORE_I64_A32_S
    CEFBS_None, // STORE_I64_A64
    CEFBS_None, // STORE_I64_A64_S
    CEFBS_HasSIMD128, // STORE_LANE_I16x8_A32
    CEFBS_HasSIMD128, // STORE_LANE_I16x8_A32_S
    CEFBS_HasSIMD128, // STORE_LANE_I16x8_A64
    CEFBS_HasSIMD128, // STORE_LANE_I16x8_A64_S
    CEFBS_HasSIMD128, // STORE_LANE_I32x4_A32
    CEFBS_HasSIMD128, // STORE_LANE_I32x4_A32_S
    CEFBS_HasSIMD128, // STORE_LANE_I32x4_A64
    CEFBS_HasSIMD128, // STORE_LANE_I32x4_A64_S
    CEFBS_HasSIMD128, // STORE_LANE_I64x2_A32
    CEFBS_HasSIMD128, // STORE_LANE_I64x2_A32_S
    CEFBS_HasSIMD128, // STORE_LANE_I64x2_A64
    CEFBS_HasSIMD128, // STORE_LANE_I64x2_A64_S
    CEFBS_HasSIMD128, // STORE_LANE_I8x16_A32
    CEFBS_HasSIMD128, // STORE_LANE_I8x16_A32_S
    CEFBS_HasSIMD128, // STORE_LANE_I8x16_A64
    CEFBS_HasSIMD128, // STORE_LANE_I8x16_A64_S
    CEFBS_HasSIMD128, // STORE_V128_A32
    CEFBS_HasSIMD128, // STORE_V128_A32_S
    CEFBS_HasSIMD128, // STORE_V128_A64
    CEFBS_HasSIMD128, // STORE_V128_A64_S
    CEFBS_HasSIMD128_HasFP16, // SUB_F16x8
    CEFBS_HasSIMD128_HasFP16, // SUB_F16x8_S
    CEFBS_None, // SUB_F32
    CEFBS_None, // SUB_F32_S
    CEFBS_HasSIMD128, // SUB_F32x4
    CEFBS_HasSIMD128, // SUB_F32x4_S
    CEFBS_None, // SUB_F64
    CEFBS_None, // SUB_F64_S
    CEFBS_HasSIMD128, // SUB_F64x2
    CEFBS_HasSIMD128, // SUB_F64x2_S
    CEFBS_HasSIMD128, // SUB_I16x8
    CEFBS_HasSIMD128, // SUB_I16x8_S
    CEFBS_None, // SUB_I32
    CEFBS_None, // SUB_I32_S
    CEFBS_HasSIMD128, // SUB_I32x4
    CEFBS_HasSIMD128, // SUB_I32x4_S
    CEFBS_None, // SUB_I64
    CEFBS_None, // SUB_I64_S
    CEFBS_HasSIMD128, // SUB_I64x2
    CEFBS_HasSIMD128, // SUB_I64x2_S
    CEFBS_HasSIMD128, // SUB_I8x16
    CEFBS_HasSIMD128, // SUB_I8x16_S
    CEFBS_HasSIMD128, // SUB_SAT_S_I16x8
    CEFBS_HasSIMD128, // SUB_SAT_S_I16x8_S
    CEFBS_HasSIMD128, // SUB_SAT_S_I8x16
    CEFBS_HasSIMD128, // SUB_SAT_S_I8x16_S
    CEFBS_HasSIMD128, // SUB_SAT_U_I16x8
    CEFBS_HasSIMD128, // SUB_SAT_U_I16x8_S
    CEFBS_HasSIMD128, // SUB_SAT_U_I8x16
    CEFBS_HasSIMD128, // SUB_SAT_U_I8x16_S
    CEFBS_HasSIMD128, // SWIZZLE
    CEFBS_HasSIMD128, // SWIZZLE_S
    CEFBS_HasReferenceTypes, // TABLE_COPY
    CEFBS_HasReferenceTypes, // TABLE_COPY_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // TABLE_FILL_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // TABLE_FILL_EXNREF_S
    CEFBS_HasReferenceTypes, // TABLE_FILL_EXTERNREF
    CEFBS_HasReferenceTypes, // TABLE_FILL_EXTERNREF_S
    CEFBS_HasReferenceTypes, // TABLE_FILL_FUNCREF
    CEFBS_HasReferenceTypes, // TABLE_FILL_FUNCREF_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // TABLE_GET_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // TABLE_GET_EXNREF_S
    CEFBS_HasReferenceTypes, // TABLE_GET_EXTERNREF
    CEFBS_HasReferenceTypes, // TABLE_GET_EXTERNREF_S
    CEFBS_HasReferenceTypes, // TABLE_GET_FUNCREF
    CEFBS_HasReferenceTypes, // TABLE_GET_FUNCREF_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // TABLE_GROW_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // TABLE_GROW_EXNREF_S
    CEFBS_HasReferenceTypes, // TABLE_GROW_EXTERNREF
    CEFBS_HasReferenceTypes, // TABLE_GROW_EXTERNREF_S
    CEFBS_HasReferenceTypes, // TABLE_GROW_FUNCREF
    CEFBS_HasReferenceTypes, // TABLE_GROW_FUNCREF_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // TABLE_SET_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // TABLE_SET_EXNREF_S
    CEFBS_HasReferenceTypes, // TABLE_SET_EXTERNREF
    CEFBS_HasReferenceTypes, // TABLE_SET_EXTERNREF_S
    CEFBS_HasReferenceTypes, // TABLE_SET_FUNCREF
    CEFBS_HasReferenceTypes, // TABLE_SET_FUNCREF_S
    CEFBS_HasReferenceTypes, // TABLE_SIZE
    CEFBS_HasReferenceTypes, // TABLE_SIZE_S
    CEFBS_HasReferenceTypes_HasExceptionHandling, // TEE_EXNREF
    CEFBS_HasReferenceTypes_HasExceptionHandling, // TEE_EXNREF_S
    CEFBS_HasReferenceTypes, // TEE_EXTERNREF
    CEFBS_HasReferenceTypes, // TEE_EXTERNREF_S
    CEFBS_None, // TEE_F32
    CEFBS_None, // TEE_F32_S
    CEFBS_None, // TEE_F64
    CEFBS_None, // TEE_F64_S
    CEFBS_HasReferenceTypes, // TEE_FUNCREF
    CEFBS_HasReferenceTypes, // TEE_FUNCREF_S
    CEFBS_None, // TEE_I32
    CEFBS_None, // TEE_I32_S
    CEFBS_None, // TEE_I64
    CEFBS_None, // TEE_I64_S
    CEFBS_HasSIMD128, // TEE_V128
    CEFBS_HasSIMD128, // TEE_V128_S
    CEFBS_HasExceptionHandling, // THROW
    CEFBS_HasExceptionHandling, // THROW_REF
    CEFBS_HasExceptionHandling, // THROW_REF_S
    CEFBS_HasExceptionHandling, // THROW_S
    CEFBS_HasSIMD128_HasFP16, // TRUNC_F16x8
    CEFBS_HasSIMD128_HasFP16, // TRUNC_F16x8_S
    CEFBS_None, // TRUNC_F32
    CEFBS_None, // TRUNC_F32_S
    CEFBS_HasSIMD128, // TRUNC_F32x4
    CEFBS_HasSIMD128, // TRUNC_F32x4_S
    CEFBS_None, // TRUNC_F64
    CEFBS_None, // TRUNC_F64_S
    CEFBS_HasSIMD128, // TRUNC_F64x2
    CEFBS_HasSIMD128, // TRUNC_F64x2_S
    CEFBS_HasExceptionHandling, // TRY
    CEFBS_HasExceptionHandling, // TRY_S
    CEFBS_HasExceptionHandling, // TRY_TABLE
    CEFBS_HasExceptionHandling, // TRY_TABLE_S
    CEFBS_None, // UNREACHABLE
    CEFBS_None, // UNREACHABLE_S
    CEFBS_HasSIMD128, // XOR
    CEFBS_None, // XOR_I32
    CEFBS_None, // XOR_I32_S
    CEFBS_None, // XOR_I64
    CEFBS_None, // XOR_I64_S
    CEFBS_HasSIMD128, // XOR_S
    CEFBS_None, // anonymous_14027MEMORY_GROW_A32
    CEFBS_None, // anonymous_14027MEMORY_GROW_A32_S
    CEFBS_None, // anonymous_14027MEMORY_SIZE_A32
    CEFBS_None, // anonymous_14027MEMORY_SIZE_A32_S
    CEFBS_None, // anonymous_14028MEMORY_GROW_A64
    CEFBS_None, // anonymous_14028MEMORY_GROW_A64_S
    CEFBS_None, // anonymous_14028MEMORY_SIZE_A64
    CEFBS_None, // anonymous_14028MEMORY_SIZE_A64_S
    CEFBS_HasSIMD128, // convert_low_s_F64x2
    CEFBS_HasSIMD128, // convert_low_s_F64x2_S
    CEFBS_HasSIMD128, // convert_low_u_F64x2
    CEFBS_HasSIMD128, // convert_low_u_F64x2_S
    CEFBS_HasSIMD128_HasFP16, // demote_zero_F16x8
    CEFBS_HasSIMD128_HasFP16, // demote_zero_F16x8_S
    CEFBS_HasSIMD128, // demote_zero_F32x4
    CEFBS_HasSIMD128, // demote_zero_F32x4_S
    CEFBS_HasSIMD128, // extadd_pairwise_s_I16x8
    CEFBS_HasSIMD128, // extadd_pairwise_s_I16x8_S
    CEFBS_HasSIMD128, // extadd_pairwise_s_I32x4
    CEFBS_HasSIMD128, // extadd_pairwise_s_I32x4_S
    CEFBS_HasSIMD128, // extadd_pairwise_u_I16x8
    CEFBS_HasSIMD128, // extadd_pairwise_u_I16x8_S
    CEFBS_HasSIMD128, // extadd_pairwise_u_I32x4
    CEFBS_HasSIMD128, // extadd_pairwise_u_I32x4_S
    CEFBS_HasSIMD128, // extend_high_s_I16x8
    CEFBS_HasSIMD128, // extend_high_s_I16x8_S
    CEFBS_HasSIMD128, // extend_high_s_I32x4
    CEFBS_HasSIMD128, // extend_high_s_I32x4_S
    CEFBS_HasSIMD128, // extend_high_s_I64x2
    CEFBS_HasSIMD128, // extend_high_s_I64x2_S
    CEFBS_HasSIMD128, // extend_high_u_I16x8
    CEFBS_HasSIMD128, // extend_high_u_I16x8_S
    CEFBS_HasSIMD128, // extend_high_u_I32x4
    CEFBS_HasSIMD128, // extend_high_u_I32x4_S
    CEFBS_HasSIMD128, // extend_high_u_I64x2
    CEFBS_HasSIMD128, // extend_high_u_I64x2_S
    CEFBS_HasSIMD128, // extend_low_s_I16x8
    CEFBS_HasSIMD128, // extend_low_s_I16x8_S
    CEFBS_HasSIMD128, // extend_low_s_I32x4
    CEFBS_HasSIMD128, // extend_low_s_I32x4_S
    CEFBS_HasSIMD128, // extend_low_s_I64x2
    CEFBS_HasSIMD128, // extend_low_s_I64x2_S
    CEFBS_HasSIMD128, // extend_low_u_I16x8
    CEFBS_HasSIMD128, // extend_low_u_I16x8_S
    CEFBS_HasSIMD128, // extend_low_u_I32x4
    CEFBS_HasSIMD128, // extend_low_u_I32x4_S
    CEFBS_HasSIMD128, // extend_low_u_I64x2
    CEFBS_HasSIMD128, // extend_low_u_I64x2_S
    CEFBS_HasSIMD128_HasFP16, // fp_to_sint_I16x8
    CEFBS_HasSIMD128_HasFP16, // fp_to_sint_I16x8_S
    CEFBS_HasSIMD128, // fp_to_sint_I32x4
    CEFBS_HasSIMD128, // fp_to_sint_I32x4_S
    CEFBS_HasSIMD128_HasFP16, // fp_to_uint_I16x8
    CEFBS_HasSIMD128_HasFP16, // fp_to_uint_I16x8_S
    CEFBS_HasSIMD128, // fp_to_uint_I32x4
    CEFBS_HasSIMD128, // fp_to_uint_I32x4_S
    CEFBS_HasRelaxedSIMD, // int_wasm_relaxed_trunc_signed_I32x4
    CEFBS_HasRelaxedSIMD, // int_wasm_relaxed_trunc_signed_I32x4_S
    CEFBS_HasRelaxedSIMD, // int_wasm_relaxed_trunc_signed_zero_I32x4
    CEFBS_HasRelaxedSIMD, // int_wasm_relaxed_trunc_signed_zero_I32x4_S
    CEFBS_HasRelaxedSIMD, // int_wasm_relaxed_trunc_unsigned_I32x4
    CEFBS_HasRelaxedSIMD, // int_wasm_relaxed_trunc_unsigned_I32x4_S
    CEFBS_HasRelaxedSIMD, // int_wasm_relaxed_trunc_unsigned_zero_I32x4
    CEFBS_HasRelaxedSIMD, // int_wasm_relaxed_trunc_unsigned_zero_I32x4_S
    CEFBS_HasSIMD128_HasFP16, // promote_low_F32x4
    CEFBS_HasSIMD128_HasFP16, // promote_low_F32x4_S
    CEFBS_HasSIMD128, // promote_low_F64x2
    CEFBS_HasSIMD128, // promote_low_F64x2_S
    CEFBS_HasSIMD128_HasFP16, // sint_to_fp_F16x8
    CEFBS_HasSIMD128_HasFP16, // sint_to_fp_F16x8_S
    CEFBS_HasSIMD128, // sint_to_fp_F32x4
    CEFBS_HasSIMD128, // sint_to_fp_F32x4_S
    CEFBS_HasSIMD128, // trunc_sat_zero_s_I32x4
    CEFBS_HasSIMD128, // trunc_sat_zero_s_I32x4_S
    CEFBS_HasSIMD128, // trunc_sat_zero_u_I32x4
    CEFBS_HasSIMD128, // trunc_sat_zero_u_I32x4_S
    CEFBS_HasSIMD128_HasFP16, // uint_to_fp_F16x8
    CEFBS_HasSIMD128_HasFP16, // uint_to_fp_F16x8_S
    CEFBS_HasSIMD128, // uint_to_fp_F32x4
    CEFBS_HasSIMD128, // uint_to_fp_F32x4_S
  };

  assert(Opcode < 1977);
  return FeatureBitsets[RequiredFeaturesRefs[Opcode]];
}


} // namespace llvm_ks::WebAssembly_MC

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

namespace llvm_ks::WebAssembly_MC {

bool isOpcodeAvailable(unsigned Opcode, const FeatureBitset &Features) {
  FeatureBitset AvailableFeatures = computeAvailableFeatures(Features);
  FeatureBitset RequiredFeatures = computeRequiredFeatures(Opcode);
  FeatureBitset MissingFeatures =
      (AvailableFeatures & RequiredFeatures) ^
      RequiredFeatures;
  return !MissingFeatures.any();
}

} // namespace llvm_ks::WebAssembly_MC

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef ENABLE_INSTR_PREDICATE_VERIFIER
#undef ENABLE_INSTR_PREDICATE_VERIFIER

#include <sstream>

namespace llvm_ks::WebAssembly_MC {

#ifndef NDEBUG
static const char *SubtargetFeatureNames[] = {
  "Feature_HasAtomics",
  "Feature_HasBulkMemory",
  "Feature_HasBulkMemoryOpt",
  "Feature_HasCallIndirectOverlong",
  "Feature_HasExceptionHandling",
  "Feature_HasExtendedConst",
  "Feature_HasFP16",
  "Feature_HasGC",
  "Feature_HasMultiMemory",
  "Feature_HasMultivalue",
  "Feature_HasMutableGlobals",
  "Feature_HasNontrappingFPToInt",
  "Feature_HasReferenceTypes",
  "Feature_HasRelaxedAtomics",
  "Feature_HasRelaxedSIMD",
  "Feature_HasSIMD128",
  "Feature_HasSignExt",
  "Feature_HasTailCall",
  "Feature_HasWideArithmetic",
  "Feature_NotHasNontrappingFPToInt",
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
    Msg << "Attempting to emit " << &WebAssemblyInstrNameData[WebAssemblyInstrNameIndices[Opcode]]
        << " instruction but the ";
    for (unsigned i = 0, e = MissingFeatures.size(); i != e; ++i)
      if (MissingFeatures.test(i))
        Msg << SubtargetFeatureNames[i] << " ";
    Msg << "predicate(s) are not met";
    report_fatal_error(Msg.str().c_str());
  }
#endif // NDEBUG
}

} // namespace llvm_ks::WebAssembly_MC

#endif // ENABLE_INSTR_PREDICATE_VERIFIER

#ifdef GET_INSTRMAP_INFO
#undef GET_INSTRMAP_INFO

namespace llvm_ks::WebAssembly {

enum IsWasm64 {
  IsWasm64_1
};

enum StackBased {
  StackBased_0,
  StackBased_1
};

// getRegisterOpcode
LLVM_READONLY
int32_t getRegisterOpcode(uint32_t Opcode) {
  using namespace WebAssembly;
  static constexpr uint32_t Table[][2] = {
    { CALL_PARAMS_S, CALL_PARAMS },
    { CALL_RESULTS_S, CALL_RESULTS },
    { CATCHRET_S, CATCHRET },
    { CLEANUPRET_S, CLEANUPRET },
    { COMPILER_FENCE_S, COMPILER_FENCE },
    { RET_CALL_RESULTS_S, RET_CALL_RESULTS },
    { ABS_F16x8_S, ABS_F16x8 },
    { ABS_F32_S, ABS_F32 },
    { ABS_F32x4_S, ABS_F32x4 },
    { ABS_F64_S, ABS_F64 },
    { ABS_F64x2_S, ABS_F64x2 },
    { ABS_I16x8_S, ABS_I16x8 },
    { ABS_I32x4_S, ABS_I32x4 },
    { ABS_I64x2_S, ABS_I64x2 },
    { ABS_I8x16_S, ABS_I8x16 },
    { ADD_F16x8_S, ADD_F16x8 },
    { ADD_F32_S, ADD_F32 },
    { ADD_F32x4_S, ADD_F32x4 },
    { ADD_F64_S, ADD_F64 },
    { ADD_F64x2_S, ADD_F64x2 },
    { ADD_I16x8_S, ADD_I16x8 },
    { ADD_I32_S, ADD_I32 },
    { ADD_I32x4_S, ADD_I32x4 },
    { ADD_I64_S, ADD_I64 },
    { ADD_I64x2_S, ADD_I64x2 },
    { ADD_I8x16_S, ADD_I8x16 },
    { ADD_SAT_S_I16x8_S, ADD_SAT_S_I16x8 },
    { ADD_SAT_S_I8x16_S, ADD_SAT_S_I8x16 },
    { ADD_SAT_U_I16x8_S, ADD_SAT_U_I16x8 },
    { ADD_SAT_U_I8x16_S, ADD_SAT_U_I8x16 },
    { ADJCALLSTACKDOWN_S, ADJCALLSTACKDOWN },
    { ADJCALLSTACKUP_S, ADJCALLSTACKUP },
    { ALLTRUE_I16x8_S, ALLTRUE_I16x8 },
    { ALLTRUE_I32x4_S, ALLTRUE_I32x4 },
    { ALLTRUE_I64x2_S, ALLTRUE_I64x2 },
    { ALLTRUE_I8x16_S, ALLTRUE_I8x16 },
    { ANDNOT_S, ANDNOT },
    { AND_I32_S, AND_I32 },
    { AND_I64_S, AND_I64 },
    { AND_S, AND },
    { ANYTRUE_S, ANYTRUE },
    { ARGUMENT_exnref_S, ARGUMENT_exnref },
    { ARGUMENT_externref_S, ARGUMENT_externref },
    { ARGUMENT_f32_S, ARGUMENT_f32 },
    { ARGUMENT_f64_S, ARGUMENT_f64 },
    { ARGUMENT_funcref_S, ARGUMENT_funcref },
    { ARGUMENT_i32_S, ARGUMENT_i32 },
    { ARGUMENT_i64_S, ARGUMENT_i64 },
    { ARGUMENT_v16i8_S, ARGUMENT_v16i8 },
    { ARGUMENT_v2f64_S, ARGUMENT_v2f64 },
    { ARGUMENT_v2i64_S, ARGUMENT_v2i64 },
    { ARGUMENT_v4f32_S, ARGUMENT_v4f32 },
    { ARGUMENT_v4i32_S, ARGUMENT_v4i32 },
    { ARGUMENT_v8f16_S, ARGUMENT_v8f16 },
    { ARGUMENT_v8i16_S, ARGUMENT_v8i16 },
    { ATOMIC_FENCE_S, ATOMIC_FENCE },
    { ATOMIC_LOAD16_U_I32_A32_S, ATOMIC_LOAD16_U_I32_A32 },
    { ATOMIC_LOAD16_U_I32_A64_S, ATOMIC_LOAD16_U_I32_A64 },
    { ATOMIC_LOAD16_U_I64_A32_S, ATOMIC_LOAD16_U_I64_A32 },
    { ATOMIC_LOAD16_U_I64_A64_S, ATOMIC_LOAD16_U_I64_A64 },
    { ATOMIC_LOAD32_U_I64_A32_S, ATOMIC_LOAD32_U_I64_A32 },
    { ATOMIC_LOAD32_U_I64_A64_S, ATOMIC_LOAD32_U_I64_A64 },
    { ATOMIC_LOAD8_U_I32_A32_S, ATOMIC_LOAD8_U_I32_A32 },
    { ATOMIC_LOAD8_U_I32_A64_S, ATOMIC_LOAD8_U_I32_A64 },
    { ATOMIC_LOAD8_U_I64_A32_S, ATOMIC_LOAD8_U_I64_A32 },
    { ATOMIC_LOAD8_U_I64_A64_S, ATOMIC_LOAD8_U_I64_A64 },
    { ATOMIC_LOAD_I32_A32_S, ATOMIC_LOAD_I32_A32 },
    { ATOMIC_LOAD_I32_A64_S, ATOMIC_LOAD_I32_A64 },
    { ATOMIC_LOAD_I64_A32_S, ATOMIC_LOAD_I64_A32 },
    { ATOMIC_LOAD_I64_A64_S, ATOMIC_LOAD_I64_A64 },
    { ATOMIC_RMW16_U_ADD_I32_A32_S, ATOMIC_RMW16_U_ADD_I32_A32 },
    { ATOMIC_RMW16_U_ADD_I32_A64_S, ATOMIC_RMW16_U_ADD_I32_A64 },
    { ATOMIC_RMW16_U_ADD_I64_A32_S, ATOMIC_RMW16_U_ADD_I64_A32 },
    { ATOMIC_RMW16_U_ADD_I64_A64_S, ATOMIC_RMW16_U_ADD_I64_A64 },
    { ATOMIC_RMW16_U_AND_I32_A32_S, ATOMIC_RMW16_U_AND_I32_A32 },
    { ATOMIC_RMW16_U_AND_I32_A64_S, ATOMIC_RMW16_U_AND_I32_A64 },
    { ATOMIC_RMW16_U_AND_I64_A32_S, ATOMIC_RMW16_U_AND_I64_A32 },
    { ATOMIC_RMW16_U_AND_I64_A64_S, ATOMIC_RMW16_U_AND_I64_A64 },
    { ATOMIC_RMW16_U_CMPXCHG_I32_A32_S, ATOMIC_RMW16_U_CMPXCHG_I32_A32 },
    { ATOMIC_RMW16_U_CMPXCHG_I32_A64_S, ATOMIC_RMW16_U_CMPXCHG_I32_A64 },
    { ATOMIC_RMW16_U_CMPXCHG_I64_A32_S, ATOMIC_RMW16_U_CMPXCHG_I64_A32 },
    { ATOMIC_RMW16_U_CMPXCHG_I64_A64_S, ATOMIC_RMW16_U_CMPXCHG_I64_A64 },
    { ATOMIC_RMW16_U_OR_I32_A32_S, ATOMIC_RMW16_U_OR_I32_A32 },
    { ATOMIC_RMW16_U_OR_I32_A64_S, ATOMIC_RMW16_U_OR_I32_A64 },
    { ATOMIC_RMW16_U_OR_I64_A32_S, ATOMIC_RMW16_U_OR_I64_A32 },
    { ATOMIC_RMW16_U_OR_I64_A64_S, ATOMIC_RMW16_U_OR_I64_A64 },
    { ATOMIC_RMW16_U_SUB_I32_A32_S, ATOMIC_RMW16_U_SUB_I32_A32 },
    { ATOMIC_RMW16_U_SUB_I32_A64_S, ATOMIC_RMW16_U_SUB_I32_A64 },
    { ATOMIC_RMW16_U_SUB_I64_A32_S, ATOMIC_RMW16_U_SUB_I64_A32 },
    { ATOMIC_RMW16_U_SUB_I64_A64_S, ATOMIC_RMW16_U_SUB_I64_A64 },
    { ATOMIC_RMW16_U_XCHG_I32_A32_S, ATOMIC_RMW16_U_XCHG_I32_A32 },
    { ATOMIC_RMW16_U_XCHG_I32_A64_S, ATOMIC_RMW16_U_XCHG_I32_A64 },
    { ATOMIC_RMW16_U_XCHG_I64_A32_S, ATOMIC_RMW16_U_XCHG_I64_A32 },
    { ATOMIC_RMW16_U_XCHG_I64_A64_S, ATOMIC_RMW16_U_XCHG_I64_A64 },
    { ATOMIC_RMW16_U_XOR_I32_A32_S, ATOMIC_RMW16_U_XOR_I32_A32 },
    { ATOMIC_RMW16_U_XOR_I32_A64_S, ATOMIC_RMW16_U_XOR_I32_A64 },
    { ATOMIC_RMW16_U_XOR_I64_A32_S, ATOMIC_RMW16_U_XOR_I64_A32 },
    { ATOMIC_RMW16_U_XOR_I64_A64_S, ATOMIC_RMW16_U_XOR_I64_A64 },
    { ATOMIC_RMW32_U_ADD_I64_A32_S, ATOMIC_RMW32_U_ADD_I64_A32 },
    { ATOMIC_RMW32_U_ADD_I64_A64_S, ATOMIC_RMW32_U_ADD_I64_A64 },
    { ATOMIC_RMW32_U_AND_I64_A32_S, ATOMIC_RMW32_U_AND_I64_A32 },
    { ATOMIC_RMW32_U_AND_I64_A64_S, ATOMIC_RMW32_U_AND_I64_A64 },
    { ATOMIC_RMW32_U_CMPXCHG_I64_A32_S, ATOMIC_RMW32_U_CMPXCHG_I64_A32 },
    { ATOMIC_RMW32_U_CMPXCHG_I64_A64_S, ATOMIC_RMW32_U_CMPXCHG_I64_A64 },
    { ATOMIC_RMW32_U_OR_I64_A32_S, ATOMIC_RMW32_U_OR_I64_A32 },
    { ATOMIC_RMW32_U_OR_I64_A64_S, ATOMIC_RMW32_U_OR_I64_A64 },
    { ATOMIC_RMW32_U_SUB_I64_A32_S, ATOMIC_RMW32_U_SUB_I64_A32 },
    { ATOMIC_RMW32_U_SUB_I64_A64_S, ATOMIC_RMW32_U_SUB_I64_A64 },
    { ATOMIC_RMW32_U_XCHG_I64_A32_S, ATOMIC_RMW32_U_XCHG_I64_A32 },
    { ATOMIC_RMW32_U_XCHG_I64_A64_S, ATOMIC_RMW32_U_XCHG_I64_A64 },
    { ATOMIC_RMW32_U_XOR_I64_A32_S, ATOMIC_RMW32_U_XOR_I64_A32 },
    { ATOMIC_RMW32_U_XOR_I64_A64_S, ATOMIC_RMW32_U_XOR_I64_A64 },
    { ATOMIC_RMW8_U_ADD_I32_A32_S, ATOMIC_RMW8_U_ADD_I32_A32 },
    { ATOMIC_RMW8_U_ADD_I32_A64_S, ATOMIC_RMW8_U_ADD_I32_A64 },
    { ATOMIC_RMW8_U_ADD_I64_A32_S, ATOMIC_RMW8_U_ADD_I64_A32 },
    { ATOMIC_RMW8_U_ADD_I64_A64_S, ATOMIC_RMW8_U_ADD_I64_A64 },
    { ATOMIC_RMW8_U_AND_I32_A32_S, ATOMIC_RMW8_U_AND_I32_A32 },
    { ATOMIC_RMW8_U_AND_I32_A64_S, ATOMIC_RMW8_U_AND_I32_A64 },
    { ATOMIC_RMW8_U_AND_I64_A32_S, ATOMIC_RMW8_U_AND_I64_A32 },
    { ATOMIC_RMW8_U_AND_I64_A64_S, ATOMIC_RMW8_U_AND_I64_A64 },
    { ATOMIC_RMW8_U_CMPXCHG_I32_A32_S, ATOMIC_RMW8_U_CMPXCHG_I32_A32 },
    { ATOMIC_RMW8_U_CMPXCHG_I32_A64_S, ATOMIC_RMW8_U_CMPXCHG_I32_A64 },
    { ATOMIC_RMW8_U_CMPXCHG_I64_A32_S, ATOMIC_RMW8_U_CMPXCHG_I64_A32 },
    { ATOMIC_RMW8_U_CMPXCHG_I64_A64_S, ATOMIC_RMW8_U_CMPXCHG_I64_A64 },
    { ATOMIC_RMW8_U_OR_I32_A32_S, ATOMIC_RMW8_U_OR_I32_A32 },
    { ATOMIC_RMW8_U_OR_I32_A64_S, ATOMIC_RMW8_U_OR_I32_A64 },
    { ATOMIC_RMW8_U_OR_I64_A32_S, ATOMIC_RMW8_U_OR_I64_A32 },
    { ATOMIC_RMW8_U_OR_I64_A64_S, ATOMIC_RMW8_U_OR_I64_A64 },
    { ATOMIC_RMW8_U_SUB_I32_A32_S, ATOMIC_RMW8_U_SUB_I32_A32 },
    { ATOMIC_RMW8_U_SUB_I32_A64_S, ATOMIC_RMW8_U_SUB_I32_A64 },
    { ATOMIC_RMW8_U_SUB_I64_A32_S, ATOMIC_RMW8_U_SUB_I64_A32 },
    { ATOMIC_RMW8_U_SUB_I64_A64_S, ATOMIC_RMW8_U_SUB_I64_A64 },
    { ATOMIC_RMW8_U_XCHG_I32_A32_S, ATOMIC_RMW8_U_XCHG_I32_A32 },
    { ATOMIC_RMW8_U_XCHG_I32_A64_S, ATOMIC_RMW8_U_XCHG_I32_A64 },
    { ATOMIC_RMW8_U_XCHG_I64_A32_S, ATOMIC_RMW8_U_XCHG_I64_A32 },
    { ATOMIC_RMW8_U_XCHG_I64_A64_S, ATOMIC_RMW8_U_XCHG_I64_A64 },
    { ATOMIC_RMW8_U_XOR_I32_A32_S, ATOMIC_RMW8_U_XOR_I32_A32 },
    { ATOMIC_RMW8_U_XOR_I32_A64_S, ATOMIC_RMW8_U_XOR_I32_A64 },
    { ATOMIC_RMW8_U_XOR_I64_A32_S, ATOMIC_RMW8_U_XOR_I64_A32 },
    { ATOMIC_RMW8_U_XOR_I64_A64_S, ATOMIC_RMW8_U_XOR_I64_A64 },
    { ATOMIC_RMW_ADD_I32_A32_S, ATOMIC_RMW_ADD_I32_A32 },
    { ATOMIC_RMW_ADD_I32_A64_S, ATOMIC_RMW_ADD_I32_A64 },
    { ATOMIC_RMW_ADD_I64_A32_S, ATOMIC_RMW_ADD_I64_A32 },
    { ATOMIC_RMW_ADD_I64_A64_S, ATOMIC_RMW_ADD_I64_A64 },
    { ATOMIC_RMW_AND_I32_A32_S, ATOMIC_RMW_AND_I32_A32 },
    { ATOMIC_RMW_AND_I32_A64_S, ATOMIC_RMW_AND_I32_A64 },
    { ATOMIC_RMW_AND_I64_A32_S, ATOMIC_RMW_AND_I64_A32 },
    { ATOMIC_RMW_AND_I64_A64_S, ATOMIC_RMW_AND_I64_A64 },
    { ATOMIC_RMW_CMPXCHG_I32_A32_S, ATOMIC_RMW_CMPXCHG_I32_A32 },
    { ATOMIC_RMW_CMPXCHG_I32_A64_S, ATOMIC_RMW_CMPXCHG_I32_A64 },
    { ATOMIC_RMW_CMPXCHG_I64_A32_S, ATOMIC_RMW_CMPXCHG_I64_A32 },
    { ATOMIC_RMW_CMPXCHG_I64_A64_S, ATOMIC_RMW_CMPXCHG_I64_A64 },
    { ATOMIC_RMW_OR_I32_A32_S, ATOMIC_RMW_OR_I32_A32 },
    { ATOMIC_RMW_OR_I32_A64_S, ATOMIC_RMW_OR_I32_A64 },
    { ATOMIC_RMW_OR_I64_A32_S, ATOMIC_RMW_OR_I64_A32 },
    { ATOMIC_RMW_OR_I64_A64_S, ATOMIC_RMW_OR_I64_A64 },
    { ATOMIC_RMW_SUB_I32_A32_S, ATOMIC_RMW_SUB_I32_A32 },
    { ATOMIC_RMW_SUB_I32_A64_S, ATOMIC_RMW_SUB_I32_A64 },
    { ATOMIC_RMW_SUB_I64_A32_S, ATOMIC_RMW_SUB_I64_A32 },
    { ATOMIC_RMW_SUB_I64_A64_S, ATOMIC_RMW_SUB_I64_A64 },
    { ATOMIC_RMW_XCHG_I32_A32_S, ATOMIC_RMW_XCHG_I32_A32 },
    { ATOMIC_RMW_XCHG_I32_A64_S, ATOMIC_RMW_XCHG_I32_A64 },
    { ATOMIC_RMW_XCHG_I64_A32_S, ATOMIC_RMW_XCHG_I64_A32 },
    { ATOMIC_RMW_XCHG_I64_A64_S, ATOMIC_RMW_XCHG_I64_A64 },
    { ATOMIC_RMW_XOR_I32_A32_S, ATOMIC_RMW_XOR_I32_A32 },
    { ATOMIC_RMW_XOR_I32_A64_S, ATOMIC_RMW_XOR_I32_A64 },
    { ATOMIC_RMW_XOR_I64_A32_S, ATOMIC_RMW_XOR_I64_A32 },
    { ATOMIC_RMW_XOR_I64_A64_S, ATOMIC_RMW_XOR_I64_A64 },
    { ATOMIC_STORE16_I32_A32_S, ATOMIC_STORE16_I32_A32 },
    { ATOMIC_STORE16_I32_A64_S, ATOMIC_STORE16_I32_A64 },
    { ATOMIC_STORE16_I64_A32_S, ATOMIC_STORE16_I64_A32 },
    { ATOMIC_STORE16_I64_A64_S, ATOMIC_STORE16_I64_A64 },
    { ATOMIC_STORE32_I64_A32_S, ATOMIC_STORE32_I64_A32 },
    { ATOMIC_STORE32_I64_A64_S, ATOMIC_STORE32_I64_A64 },
    { ATOMIC_STORE8_I32_A32_S, ATOMIC_STORE8_I32_A32 },
    { ATOMIC_STORE8_I32_A64_S, ATOMIC_STORE8_I32_A64 },
    { ATOMIC_STORE8_I64_A32_S, ATOMIC_STORE8_I64_A32 },
    { ATOMIC_STORE8_I64_A64_S, ATOMIC_STORE8_I64_A64 },
    { ATOMIC_STORE_I32_A32_S, ATOMIC_STORE_I32_A32 },
    { ATOMIC_STORE_I32_A64_S, ATOMIC_STORE_I32_A64 },
    { ATOMIC_STORE_I64_A32_S, ATOMIC_STORE_I64_A32 },
    { ATOMIC_STORE_I64_A64_S, ATOMIC_STORE_I64_A64 },
    { AVGR_U_I16x8_S, AVGR_U_I16x8 },
    { AVGR_U_I8x16_S, AVGR_U_I8x16 },
    { BITMASK_I16x8_S, BITMASK_I16x8 },
    { BITMASK_I32x4_S, BITMASK_I32x4 },
    { BITMASK_I64x2_S, BITMASK_I64x2 },
    { BITMASK_I8x16_S, BITMASK_I8x16 },
    { BITSELECT_S, BITSELECT },
    { BLOCK_S, BLOCK },
    { BR_IF_S, BR_IF },
    { BR_S, BR },
    { BR_TABLE_I32_S, BR_TABLE_I32 },
    { BR_TABLE_I64_S, BR_TABLE_I64 },
    { BR_UNLESS_S, BR_UNLESS },
    { CALL_INDIRECT_S, CALL_INDIRECT },
    { CALL_REF_S, CALL_REF },
    { CALL_S, CALL },
    { CATCH_ALL_LEGACY_S, CATCH_ALL_LEGACY },
    { CATCH_ALL_REF_S, CATCH_ALL_REF },
    { CATCH_ALL_S, CATCH_ALL },
    { CATCH_LEGACY_S, CATCH_LEGACY },
    { CATCH_REF_S, CATCH_REF },
    { CATCH_S, CATCH },
    { CEIL_F16x8_S, CEIL_F16x8 },
    { CEIL_F32_S, CEIL_F32 },
    { CEIL_F32x4_S, CEIL_F32x4 },
    { CEIL_F64_S, CEIL_F64 },
    { CEIL_F64x2_S, CEIL_F64x2 },
    { CLZ_I32_S, CLZ_I32 },
    { CLZ_I64_S, CLZ_I64 },
    { CONST_F32_S, CONST_F32 },
    { CONST_F64_S, CONST_F64 },
    { CONST_I32_S, CONST_I32 },
    { CONST_I64_S, CONST_I64 },
    { CONST_V128_F32x4_S, CONST_V128_F32x4 },
    { CONST_V128_F64x2_S, CONST_V128_F64x2 },
    { CONST_V128_I16x8_S, CONST_V128_I16x8 },
    { CONST_V128_I32x4_S, CONST_V128_I32x4 },
    { CONST_V128_I64x2_S, CONST_V128_I64x2 },
    { CONST_V128_I8x16_S, CONST_V128_I8x16 },
    { COPYSIGN_F32_S, COPYSIGN_F32 },
    { COPYSIGN_F64_S, COPYSIGN_F64 },
    { COPY_EXNREF_S, COPY_EXNREF },
    { COPY_EXTERNREF_S, COPY_EXTERNREF },
    { COPY_F32_S, COPY_F32 },
    { COPY_F64_S, COPY_F64 },
    { COPY_FUNCREF_S, COPY_FUNCREF },
    { COPY_I32_S, COPY_I32 },
    { COPY_I64_S, COPY_I64 },
    { COPY_V128_S, COPY_V128 },
    { CTZ_I32_S, CTZ_I32 },
    { CTZ_I64_S, CTZ_I64 },
    { DATA_DROP_S, DATA_DROP },
    { DEBUG_UNREACHABLE_S, DEBUG_UNREACHABLE },
    { DELEGATE_S, DELEGATE },
    { DIV_F16x8_S, DIV_F16x8 },
    { DIV_F32_S, DIV_F32 },
    { DIV_F32x4_S, DIV_F32x4 },
    { DIV_F64_S, DIV_F64 },
    { DIV_F64x2_S, DIV_F64x2 },
    { DIV_S_I32_S, DIV_S_I32 },
    { DIV_S_I64_S, DIV_S_I64 },
    { DIV_U_I32_S, DIV_U_I32 },
    { DIV_U_I64_S, DIV_U_I64 },
    { DOT_S, DOT },
    { DROP_EXNREF_S, DROP_EXNREF },
    { DROP_EXTERNREF_S, DROP_EXTERNREF },
    { DROP_F32_S, DROP_F32 },
    { DROP_F64_S, DROP_F64 },
    { DROP_FUNCREF_S, DROP_FUNCREF },
    { DROP_I32_S, DROP_I32 },
    { DROP_I64_S, DROP_I64 },
    { DROP_V128_S, DROP_V128 },
    { ELSE_S, ELSE },
    { END_BLOCK_S, END_BLOCK },
    { END_FUNCTION_S, END_FUNCTION },
    { END_IF_S, END_IF },
    { END_LOOP_S, END_LOOP },
    { END_S, END },
    { END_TRY_S, END_TRY },
    { END_TRY_TABLE_S, END_TRY_TABLE },
    { EQZ_I32_S, EQZ_I32 },
    { EQZ_I64_S, EQZ_I64 },
    { EQ_F16x8_S, EQ_F16x8 },
    { EQ_F32_S, EQ_F32 },
    { EQ_F32x4_S, EQ_F32x4 },
    { EQ_F64_S, EQ_F64 },
    { EQ_F64x2_S, EQ_F64x2 },
    { EQ_I16x8_S, EQ_I16x8 },
    { EQ_I32_S, EQ_I32 },
    { EQ_I32x4_S, EQ_I32x4 },
    { EQ_I64_S, EQ_I64 },
    { EQ_I64x2_S, EQ_I64x2 },
    { EQ_I8x16_S, EQ_I8x16 },
    { EXTMUL_HIGH_S_I16x8_S, EXTMUL_HIGH_S_I16x8 },
    { EXTMUL_HIGH_S_I32x4_S, EXTMUL_HIGH_S_I32x4 },
    { EXTMUL_HIGH_S_I64x2_S, EXTMUL_HIGH_S_I64x2 },
    { EXTMUL_HIGH_U_I16x8_S, EXTMUL_HIGH_U_I16x8 },
    { EXTMUL_HIGH_U_I32x4_S, EXTMUL_HIGH_U_I32x4 },
    { EXTMUL_HIGH_U_I64x2_S, EXTMUL_HIGH_U_I64x2 },
    { EXTMUL_LOW_S_I16x8_S, EXTMUL_LOW_S_I16x8 },
    { EXTMUL_LOW_S_I32x4_S, EXTMUL_LOW_S_I32x4 },
    { EXTMUL_LOW_S_I64x2_S, EXTMUL_LOW_S_I64x2 },
    { EXTMUL_LOW_U_I16x8_S, EXTMUL_LOW_U_I16x8 },
    { EXTMUL_LOW_U_I32x4_S, EXTMUL_LOW_U_I32x4 },
    { EXTMUL_LOW_U_I64x2_S, EXTMUL_LOW_U_I64x2 },
    { EXTRACT_LANE_F16x8_S, EXTRACT_LANE_F16x8 },
    { EXTRACT_LANE_F32x4_S, EXTRACT_LANE_F32x4 },
    { EXTRACT_LANE_F64x2_S, EXTRACT_LANE_F64x2 },
    { EXTRACT_LANE_I16x8_s_S, EXTRACT_LANE_I16x8_s },
    { EXTRACT_LANE_I16x8_u_S, EXTRACT_LANE_I16x8_u },
    { EXTRACT_LANE_I32x4_S, EXTRACT_LANE_I32x4 },
    { EXTRACT_LANE_I64x2_S, EXTRACT_LANE_I64x2 },
    { EXTRACT_LANE_I8x16_s_S, EXTRACT_LANE_I8x16_s },
    { EXTRACT_LANE_I8x16_u_S, EXTRACT_LANE_I8x16_u },
    { F32_CONVERT_S_I32_S, F32_CONVERT_S_I32 },
    { F32_CONVERT_S_I64_S, F32_CONVERT_S_I64 },
    { F32_CONVERT_U_I32_S, F32_CONVERT_U_I32 },
    { F32_CONVERT_U_I64_S, F32_CONVERT_U_I64 },
    { F32_DEMOTE_F64_S, F32_DEMOTE_F64 },
    { F32_REINTERPRET_I32_S, F32_REINTERPRET_I32 },
    { F64_CONVERT_S_I32_S, F64_CONVERT_S_I32 },
    { F64_CONVERT_S_I64_S, F64_CONVERT_S_I64 },
    { F64_CONVERT_U_I32_S, F64_CONVERT_U_I32 },
    { F64_CONVERT_U_I64_S, F64_CONVERT_U_I64 },
    { F64_PROMOTE_F32_S, F64_PROMOTE_F32 },
    { F64_REINTERPRET_I64_S, F64_REINTERPRET_I64 },
    { FALLTHROUGH_RETURN_S, FALLTHROUGH_RETURN },
    { FLOOR_F16x8_S, FLOOR_F16x8 },
    { FLOOR_F32_S, FLOOR_F32 },
    { FLOOR_F32x4_S, FLOOR_F32x4 },
    { FLOOR_F64_S, FLOOR_F64 },
    { FLOOR_F64x2_S, FLOOR_F64x2 },
    { FP_TO_SINT_I32_F32_S, FP_TO_SINT_I32_F32 },
    { FP_TO_SINT_I32_F64_S, FP_TO_SINT_I32_F64 },
    { FP_TO_SINT_I64_F32_S, FP_TO_SINT_I64_F32 },
    { FP_TO_SINT_I64_F64_S, FP_TO_SINT_I64_F64 },
    { FP_TO_UINT_I32_F32_S, FP_TO_UINT_I32_F32 },
    { FP_TO_UINT_I32_F64_S, FP_TO_UINT_I32_F64 },
    { FP_TO_UINT_I64_F32_S, FP_TO_UINT_I64_F32 },
    { FP_TO_UINT_I64_F64_S, FP_TO_UINT_I64_F64 },
    { GE_F16x8_S, GE_F16x8 },
    { GE_F32_S, GE_F32 },
    { GE_F32x4_S, GE_F32x4 },
    { GE_F64_S, GE_F64 },
    { GE_F64x2_S, GE_F64x2 },
    { GE_S_I16x8_S, GE_S_I16x8 },
    { GE_S_I32_S, GE_S_I32 },
    { GE_S_I32x4_S, GE_S_I32x4 },
    { GE_S_I64_S, GE_S_I64 },
    { GE_S_I64x2_S, GE_S_I64x2 },
    { GE_S_I8x16_S, GE_S_I8x16 },
    { GE_U_I16x8_S, GE_U_I16x8 },
    { GE_U_I32_S, GE_U_I32 },
    { GE_U_I32x4_S, GE_U_I32x4 },
    { GE_U_I64_S, GE_U_I64 },
    { GE_U_I8x16_S, GE_U_I8x16 },
    { GLOBAL_GET_EXNREF_S, GLOBAL_GET_EXNREF },
    { GLOBAL_GET_EXTERNREF_S, GLOBAL_GET_EXTERNREF },
    { GLOBAL_GET_F32_S, GLOBAL_GET_F32 },
    { GLOBAL_GET_F64_S, GLOBAL_GET_F64 },
    { GLOBAL_GET_FUNCREF_S, GLOBAL_GET_FUNCREF },
    { GLOBAL_GET_I32_S, GLOBAL_GET_I32 },
    { GLOBAL_GET_I64_S, GLOBAL_GET_I64 },
    { GLOBAL_GET_V128_S, GLOBAL_GET_V128 },
    { GLOBAL_SET_EXNREF_S, GLOBAL_SET_EXNREF },
    { GLOBAL_SET_EXTERNREF_S, GLOBAL_SET_EXTERNREF },
    { GLOBAL_SET_F32_S, GLOBAL_SET_F32 },
    { GLOBAL_SET_F64_S, GLOBAL_SET_F64 },
    { GLOBAL_SET_FUNCREF_S, GLOBAL_SET_FUNCREF },
    { GLOBAL_SET_I32_S, GLOBAL_SET_I32 },
    { GLOBAL_SET_I64_S, GLOBAL_SET_I64 },
    { GLOBAL_SET_V128_S, GLOBAL_SET_V128 },
    { GT_F16x8_S, GT_F16x8 },
    { GT_F32_S, GT_F32 },
    { GT_F32x4_S, GT_F32x4 },
    { GT_F64_S, GT_F64 },
    { GT_F64x2_S, GT_F64x2 },
    { GT_S_I16x8_S, GT_S_I16x8 },
    { GT_S_I32_S, GT_S_I32 },
    { GT_S_I32x4_S, GT_S_I32x4 },
    { GT_S_I64_S, GT_S_I64 },
    { GT_S_I64x2_S, GT_S_I64x2 },
    { GT_S_I8x16_S, GT_S_I8x16 },
    { GT_U_I16x8_S, GT_U_I16x8 },
    { GT_U_I32_S, GT_U_I32 },
    { GT_U_I32x4_S, GT_U_I32x4 },
    { GT_U_I64_S, GT_U_I64 },
    { GT_U_I8x16_S, GT_U_I8x16 },
    { I32_EXTEND16_S_I32_S, I32_EXTEND16_S_I32 },
    { I32_EXTEND8_S_I32_S, I32_EXTEND8_S_I32 },
    { I32_REINTERPRET_F32_S, I32_REINTERPRET_F32 },
    { I32_TRUNC_S_F32_S, I32_TRUNC_S_F32 },
    { I32_TRUNC_S_F64_S, I32_TRUNC_S_F64 },
    { I32_TRUNC_S_SAT_F32_S, I32_TRUNC_S_SAT_F32 },
    { I32_TRUNC_S_SAT_F64_S, I32_TRUNC_S_SAT_F64 },
    { I32_TRUNC_U_F32_S, I32_TRUNC_U_F32 },
    { I32_TRUNC_U_F64_S, I32_TRUNC_U_F64 },
    { I32_TRUNC_U_SAT_F32_S, I32_TRUNC_U_SAT_F32 },
    { I32_TRUNC_U_SAT_F64_S, I32_TRUNC_U_SAT_F64 },
    { I32_WRAP_I64_S, I32_WRAP_I64 },
    { I64_ADD128_S, I64_ADD128 },
    { I64_EXTEND16_S_I64_S, I64_EXTEND16_S_I64 },
    { I64_EXTEND32_S_I64_S, I64_EXTEND32_S_I64 },
    { I64_EXTEND8_S_I64_S, I64_EXTEND8_S_I64 },
    { I64_EXTEND_S_I32_S, I64_EXTEND_S_I32 },
    { I64_EXTEND_U_I32_S, I64_EXTEND_U_I32 },
    { I64_MUL_WIDE_S_S, I64_MUL_WIDE_S },
    { I64_MUL_WIDE_U_S, I64_MUL_WIDE_U },
    { I64_REINTERPRET_F64_S, I64_REINTERPRET_F64 },
    { I64_SUB128_S, I64_SUB128 },
    { I64_TRUNC_S_F32_S, I64_TRUNC_S_F32 },
    { I64_TRUNC_S_F64_S, I64_TRUNC_S_F64 },
    { I64_TRUNC_S_SAT_F32_S, I64_TRUNC_S_SAT_F32 },
    { I64_TRUNC_S_SAT_F64_S, I64_TRUNC_S_SAT_F64 },
    { I64_TRUNC_U_F32_S, I64_TRUNC_U_F32 },
    { I64_TRUNC_U_F64_S, I64_TRUNC_U_F64 },
    { I64_TRUNC_U_SAT_F32_S, I64_TRUNC_U_SAT_F32 },
    { I64_TRUNC_U_SAT_F64_S, I64_TRUNC_U_SAT_F64 },
    { IF_S, IF },
    { LANESELECT_I16x8_S, LANESELECT_I16x8 },
    { LANESELECT_I32x4_S, LANESELECT_I32x4 },
    { LANESELECT_I64x2_S, LANESELECT_I64x2 },
    { LANESELECT_I8x16_S, LANESELECT_I8x16 },
    { LE_F16x8_S, LE_F16x8 },
    { LE_F32_S, LE_F32 },
    { LE_F32x4_S, LE_F32x4 },
    { LE_F64_S, LE_F64 },
    { LE_F64x2_S, LE_F64x2 },
    { LE_S_I16x8_S, LE_S_I16x8 },
    { LE_S_I32_S, LE_S_I32 },
    { LE_S_I32x4_S, LE_S_I32x4 },
    { LE_S_I64_S, LE_S_I64 },
    { LE_S_I64x2_S, LE_S_I64x2 },
    { LE_S_I8x16_S, LE_S_I8x16 },
    { LE_U_I16x8_S, LE_U_I16x8 },
    { LE_U_I32_S, LE_U_I32 },
    { LE_U_I32x4_S, LE_U_I32x4 },
    { LE_U_I64_S, LE_U_I64 },
    { LE_U_I8x16_S, LE_U_I8x16 },
    { LOAD16_SPLAT_A32_S, LOAD16_SPLAT_A32 },
    { LOAD16_SPLAT_A64_S, LOAD16_SPLAT_A64 },
    { LOAD16_S_I32_A32_S, LOAD16_S_I32_A32 },
    { LOAD16_S_I32_A64_S, LOAD16_S_I32_A64 },
    { LOAD16_S_I64_A32_S, LOAD16_S_I64_A32 },
    { LOAD16_S_I64_A64_S, LOAD16_S_I64_A64 },
    { LOAD16_U_I32_A32_S, LOAD16_U_I32_A32 },
    { LOAD16_U_I32_A64_S, LOAD16_U_I32_A64 },
    { LOAD16_U_I64_A32_S, LOAD16_U_I64_A32 },
    { LOAD16_U_I64_A64_S, LOAD16_U_I64_A64 },
    { LOAD32_SPLAT_A32_S, LOAD32_SPLAT_A32 },
    { LOAD32_SPLAT_A64_S, LOAD32_SPLAT_A64 },
    { LOAD32_S_I64_A32_S, LOAD32_S_I64_A32 },
    { LOAD32_S_I64_A64_S, LOAD32_S_I64_A64 },
    { LOAD32_U_I64_A32_S, LOAD32_U_I64_A32 },
    { LOAD32_U_I64_A64_S, LOAD32_U_I64_A64 },
    { LOAD64_SPLAT_A32_S, LOAD64_SPLAT_A32 },
    { LOAD64_SPLAT_A64_S, LOAD64_SPLAT_A64 },
    { LOAD8_SPLAT_A32_S, LOAD8_SPLAT_A32 },
    { LOAD8_SPLAT_A64_S, LOAD8_SPLAT_A64 },
    { LOAD8_S_I32_A32_S, LOAD8_S_I32_A32 },
    { LOAD8_S_I32_A64_S, LOAD8_S_I32_A64 },
    { LOAD8_S_I64_A32_S, LOAD8_S_I64_A32 },
    { LOAD8_S_I64_A64_S, LOAD8_S_I64_A64 },
    { LOAD8_U_I32_A32_S, LOAD8_U_I32_A32 },
    { LOAD8_U_I32_A64_S, LOAD8_U_I32_A64 },
    { LOAD8_U_I64_A32_S, LOAD8_U_I64_A32 },
    { LOAD8_U_I64_A64_S, LOAD8_U_I64_A64 },
    { LOAD_EXTEND_S_I16x8_A32_S, LOAD_EXTEND_S_I16x8_A32 },
    { LOAD_EXTEND_S_I16x8_A64_S, LOAD_EXTEND_S_I16x8_A64 },
    { LOAD_EXTEND_S_I32x4_A32_S, LOAD_EXTEND_S_I32x4_A32 },
    { LOAD_EXTEND_S_I32x4_A64_S, LOAD_EXTEND_S_I32x4_A64 },
    { LOAD_EXTEND_S_I64x2_A32_S, LOAD_EXTEND_S_I64x2_A32 },
    { LOAD_EXTEND_S_I64x2_A64_S, LOAD_EXTEND_S_I64x2_A64 },
    { LOAD_EXTEND_U_I16x8_A32_S, LOAD_EXTEND_U_I16x8_A32 },
    { LOAD_EXTEND_U_I16x8_A64_S, LOAD_EXTEND_U_I16x8_A64 },
    { LOAD_EXTEND_U_I32x4_A32_S, LOAD_EXTEND_U_I32x4_A32 },
    { LOAD_EXTEND_U_I32x4_A64_S, LOAD_EXTEND_U_I32x4_A64 },
    { LOAD_EXTEND_U_I64x2_A32_S, LOAD_EXTEND_U_I64x2_A32 },
    { LOAD_EXTEND_U_I64x2_A64_S, LOAD_EXTEND_U_I64x2_A64 },
    { LOAD_F16_F32_A32_S, LOAD_F16_F32_A32 },
    { LOAD_F16_F32_A64_S, LOAD_F16_F32_A64 },
    { LOAD_F32_A32_S, LOAD_F32_A32 },
    { LOAD_F32_A64_S, LOAD_F32_A64 },
    { LOAD_F64_A32_S, LOAD_F64_A32 },
    { LOAD_F64_A64_S, LOAD_F64_A64 },
    { LOAD_I32_A32_S, LOAD_I32_A32 },
    { LOAD_I32_A64_S, LOAD_I32_A64 },
    { LOAD_I64_A32_S, LOAD_I64_A32 },
    { LOAD_I64_A64_S, LOAD_I64_A64 },
    { LOAD_LANE_16_A32_S, LOAD_LANE_16_A32 },
    { LOAD_LANE_16_A64_S, LOAD_LANE_16_A64 },
    { LOAD_LANE_32_A32_S, LOAD_LANE_32_A32 },
    { LOAD_LANE_32_A64_S, LOAD_LANE_32_A64 },
    { LOAD_LANE_64_A32_S, LOAD_LANE_64_A32 },
    { LOAD_LANE_64_A64_S, LOAD_LANE_64_A64 },
    { LOAD_LANE_8_A32_S, LOAD_LANE_8_A32 },
    { LOAD_LANE_8_A64_S, LOAD_LANE_8_A64 },
    { LOAD_V128_A32_S, LOAD_V128_A32 },
    { LOAD_V128_A64_S, LOAD_V128_A64 },
    { LOAD_ZERO_32_A32_S, LOAD_ZERO_32_A32 },
    { LOAD_ZERO_32_A64_S, LOAD_ZERO_32_A64 },
    { LOAD_ZERO_64_A32_S, LOAD_ZERO_64_A32 },
    { LOAD_ZERO_64_A64_S, LOAD_ZERO_64_A64 },
    { LOCAL_GET_EXNREF_S, LOCAL_GET_EXNREF },
    { LOCAL_GET_EXTERNREF_S, LOCAL_GET_EXTERNREF },
    { LOCAL_GET_F32_S, LOCAL_GET_F32 },
    { LOCAL_GET_F64_S, LOCAL_GET_F64 },
    { LOCAL_GET_FUNCREF_S, LOCAL_GET_FUNCREF },
    { LOCAL_GET_I32_S, LOCAL_GET_I32 },
    { LOCAL_GET_I64_S, LOCAL_GET_I64 },
    { LOCAL_GET_V128_S, LOCAL_GET_V128 },
    { LOCAL_SET_EXNREF_S, LOCAL_SET_EXNREF },
    { LOCAL_SET_EXTERNREF_S, LOCAL_SET_EXTERNREF },
    { LOCAL_SET_F32_S, LOCAL_SET_F32 },
    { LOCAL_SET_F64_S, LOCAL_SET_F64 },
    { LOCAL_SET_FUNCREF_S, LOCAL_SET_FUNCREF },
    { LOCAL_SET_I32_S, LOCAL_SET_I32 },
    { LOCAL_SET_I64_S, LOCAL_SET_I64 },
    { LOCAL_SET_V128_S, LOCAL_SET_V128 },
    { LOCAL_TEE_EXNREF_S, LOCAL_TEE_EXNREF },
    { LOCAL_TEE_EXTERNREF_S, LOCAL_TEE_EXTERNREF },
    { LOCAL_TEE_F32_S, LOCAL_TEE_F32 },
    { LOCAL_TEE_F64_S, LOCAL_TEE_F64 },
    { LOCAL_TEE_FUNCREF_S, LOCAL_TEE_FUNCREF },
    { LOCAL_TEE_I32_S, LOCAL_TEE_I32 },
    { LOCAL_TEE_I64_S, LOCAL_TEE_I64 },
    { LOCAL_TEE_V128_S, LOCAL_TEE_V128 },
    { LOOP_S, LOOP },
    { LT_F16x8_S, LT_F16x8 },
    { LT_F32_S, LT_F32 },
    { LT_F32x4_S, LT_F32x4 },
    { LT_F64_S, LT_F64 },
    { LT_F64x2_S, LT_F64x2 },
    { LT_S_I16x8_S, LT_S_I16x8 },
    { LT_S_I32_S, LT_S_I32 },
    { LT_S_I32x4_S, LT_S_I32x4 },
    { LT_S_I64_S, LT_S_I64 },
    { LT_S_I64x2_S, LT_S_I64x2 },
    { LT_S_I8x16_S, LT_S_I8x16 },
    { LT_U_I16x8_S, LT_U_I16x8 },
    { LT_U_I32_S, LT_U_I32 },
    { LT_U_I32x4_S, LT_U_I32x4 },
    { LT_U_I64_S, LT_U_I64 },
    { LT_U_I8x16_S, LT_U_I8x16 },
    { MADD_F16x8_S, MADD_F16x8 },
    { MADD_F32x4_S, MADD_F32x4 },
    { MADD_F64x2_S, MADD_F64x2 },
    { MAX_F16x8_S, MAX_F16x8 },
    { MAX_F32_S, MAX_F32 },
    { MAX_F32x4_S, MAX_F32x4 },
    { MAX_F64_S, MAX_F64 },
    { MAX_F64x2_S, MAX_F64x2 },
    { MAX_S_I16x8_S, MAX_S_I16x8 },
    { MAX_S_I32x4_S, MAX_S_I32x4 },
    { MAX_S_I8x16_S, MAX_S_I8x16 },
    { MAX_U_I16x8_S, MAX_U_I16x8 },
    { MAX_U_I32x4_S, MAX_U_I32x4 },
    { MAX_U_I8x16_S, MAX_U_I8x16 },
    { MEMCPY_A32_S, MEMCPY_A32 },
    { MEMCPY_A64_S, MEMCPY_A64 },
    { MEMORY_ATOMIC_NOTIFY_A32_S, MEMORY_ATOMIC_NOTIFY_A32 },
    { MEMORY_ATOMIC_NOTIFY_A64_S, MEMORY_ATOMIC_NOTIFY_A64 },
    { MEMORY_ATOMIC_WAIT32_A32_S, MEMORY_ATOMIC_WAIT32_A32 },
    { MEMORY_ATOMIC_WAIT32_A64_S, MEMORY_ATOMIC_WAIT32_A64 },
    { MEMORY_ATOMIC_WAIT64_A32_S, MEMORY_ATOMIC_WAIT64_A32 },
    { MEMORY_ATOMIC_WAIT64_A64_S, MEMORY_ATOMIC_WAIT64_A64 },
    { MEMORY_COPY_A32_S, MEMORY_COPY_A32 },
    { MEMORY_COPY_A64_S, MEMORY_COPY_A64 },
    { MEMORY_FILL_A32_S, MEMORY_FILL_A32 },
    { MEMORY_FILL_A64_S, MEMORY_FILL_A64 },
    { MEMORY_INIT_A32_S, MEMORY_INIT_A32 },
    { MEMORY_INIT_A64_S, MEMORY_INIT_A64 },
    { MEMSET_A32_S, MEMSET_A32 },
    { MEMSET_A64_S, MEMSET_A64 },
    { MIN_F16x8_S, MIN_F16x8 },
    { MIN_F32_S, MIN_F32 },
    { MIN_F32x4_S, MIN_F32x4 },
    { MIN_F64_S, MIN_F64 },
    { MIN_F64x2_S, MIN_F64x2 },
    { MIN_S_I16x8_S, MIN_S_I16x8 },
    { MIN_S_I32x4_S, MIN_S_I32x4 },
    { MIN_S_I8x16_S, MIN_S_I8x16 },
    { MIN_U_I16x8_S, MIN_U_I16x8 },
    { MIN_U_I32x4_S, MIN_U_I32x4 },
    { MIN_U_I8x16_S, MIN_U_I8x16 },
    { MUL_F16x8_S, MUL_F16x8 },
    { MUL_F32_S, MUL_F32 },
    { MUL_F32x4_S, MUL_F32x4 },
    { MUL_F64_S, MUL_F64 },
    { MUL_F64x2_S, MUL_F64x2 },
    { MUL_I16x8_S, MUL_I16x8 },
    { MUL_I32_S, MUL_I32 },
    { MUL_I32x4_S, MUL_I32x4 },
    { MUL_I64_S, MUL_I64 },
    { MUL_I64x2_S, MUL_I64x2 },
    { NARROW_S_I16x8_S, NARROW_S_I16x8 },
    { NARROW_S_I8x16_S, NARROW_S_I8x16 },
    { NARROW_U_I16x8_S, NARROW_U_I16x8 },
    { NARROW_U_I8x16_S, NARROW_U_I8x16 },
    { NEAREST_F16x8_S, NEAREST_F16x8 },
    { NEAREST_F32_S, NEAREST_F32 },
    { NEAREST_F32x4_S, NEAREST_F32x4 },
    { NEAREST_F64_S, NEAREST_F64 },
    { NEAREST_F64x2_S, NEAREST_F64x2 },
    { NEG_F16x8_S, NEG_F16x8 },
    { NEG_F32_S, NEG_F32 },
    { NEG_F32x4_S, NEG_F32x4 },
    { NEG_F64_S, NEG_F64 },
    { NEG_F64x2_S, NEG_F64x2 },
    { NEG_I16x8_S, NEG_I16x8 },
    { NEG_I32x4_S, NEG_I32x4 },
    { NEG_I64x2_S, NEG_I64x2 },
    { NEG_I8x16_S, NEG_I8x16 },
    { NE_F16x8_S, NE_F16x8 },
    { NE_F32_S, NE_F32 },
    { NE_F32x4_S, NE_F32x4 },
    { NE_F64_S, NE_F64 },
    { NE_F64x2_S, NE_F64x2 },
    { NE_I16x8_S, NE_I16x8 },
    { NE_I32_S, NE_I32 },
    { NE_I32x4_S, NE_I32x4 },
    { NE_I64_S, NE_I64 },
    { NE_I64x2_S, NE_I64x2 },
    { NE_I8x16_S, NE_I8x16 },
    { NMADD_F16x8_S, NMADD_F16x8 },
    { NMADD_F32x4_S, NMADD_F32x4 },
    { NMADD_F64x2_S, NMADD_F64x2 },
    { NOP_S, NOP },
    { NOT_S, NOT },
    { OR_I32_S, OR_I32 },
    { OR_I64_S, OR_I64 },
    { OR_S, OR },
    { PMAX_F16x8_S, PMAX_F16x8 },
    { PMAX_F32x4_S, PMAX_F32x4 },
    { PMAX_F64x2_S, PMAX_F64x2 },
    { PMIN_F16x8_S, PMIN_F16x8 },
    { PMIN_F32x4_S, PMIN_F32x4 },
    { PMIN_F64x2_S, PMIN_F64x2 },
    { POPCNT_I32_S, POPCNT_I32 },
    { POPCNT_I64_S, POPCNT_I64 },
    { POPCNT_I8x16_S, POPCNT_I8x16 },
    { Q15MULR_SAT_S_I16x8_S, Q15MULR_SAT_S_I16x8 },
    { REF_CAST_FUNCREF_S, REF_CAST_FUNCREF },
    { REF_FUNC_S, REF_FUNC },
    { REF_IS_NULL_EXNREF_S, REF_IS_NULL_EXNREF },
    { REF_IS_NULL_EXTERNREF_S, REF_IS_NULL_EXTERNREF },
    { REF_IS_NULL_FUNCREF_S, REF_IS_NULL_FUNCREF },
    { REF_NULL_EXNREF_S, REF_NULL_EXNREF },
    { REF_NULL_EXTERNREF_S, REF_NULL_EXTERNREF },
    { REF_NULL_FUNCREF_S, REF_NULL_FUNCREF },
    { REF_TEST_FUNCREF_S, REF_TEST_FUNCREF },
    { RELAXED_DOT_ADD_S, RELAXED_DOT_ADD },
    { RELAXED_DOT_BFLOAT_S, RELAXED_DOT_BFLOAT },
    { RELAXED_DOT_S, RELAXED_DOT },
    { RELAXED_Q15MULR_S_I16x8_S, RELAXED_Q15MULR_S_I16x8 },
    { RELAXED_SWIZZLE_S, RELAXED_SWIZZLE },
    { REM_S_I32_S, REM_S_I32 },
    { REM_S_I64_S, REM_S_I64 },
    { REM_U_I32_S, REM_U_I32 },
    { REM_U_I64_S, REM_U_I64 },
    { REPLACE_LANE_F16x8_S, REPLACE_LANE_F16x8 },
    { REPLACE_LANE_F32x4_S, REPLACE_LANE_F32x4 },
    { REPLACE_LANE_F64x2_S, REPLACE_LANE_F64x2 },
    { REPLACE_LANE_I16x8_S, REPLACE_LANE_I16x8 },
    { REPLACE_LANE_I32x4_S, REPLACE_LANE_I32x4 },
    { REPLACE_LANE_I64x2_S, REPLACE_LANE_I64x2 },
    { REPLACE_LANE_I8x16_S, REPLACE_LANE_I8x16 },
    { RETHROW_S, RETHROW },
    { RETURN_S, RETURN },
    { RET_CALL_INDIRECT_S, RET_CALL_INDIRECT },
    { RET_CALL_REF_S, RET_CALL_REF },
    { RET_CALL_S, RET_CALL },
    { ROTL_I32_S, ROTL_I32 },
    { ROTL_I64_S, ROTL_I64 },
    { ROTR_I32_S, ROTR_I32 },
    { ROTR_I64_S, ROTR_I64 },
    { SELECT_EXNREF_S, SELECT_EXNREF },
    { SELECT_EXTERNREF_S, SELECT_EXTERNREF },
    { SELECT_F32_S, SELECT_F32 },
    { SELECT_F64_S, SELECT_F64 },
    { SELECT_FUNCREF_S, SELECT_FUNCREF },
    { SELECT_I32_S, SELECT_I32 },
    { SELECT_I64_S, SELECT_I64 },
    { SELECT_T_S, SELECT_T },
    { SELECT_V128_S, SELECT_V128 },
    { SHL_I16x8_S, SHL_I16x8 },
    { SHL_I32_S, SHL_I32 },
    { SHL_I32x4_S, SHL_I32x4 },
    { SHL_I64_S, SHL_I64 },
    { SHL_I64x2_S, SHL_I64x2 },
    { SHL_I8x16_S, SHL_I8x16 },
    { SHR_S_I16x8_S, SHR_S_I16x8 },
    { SHR_S_I32_S, SHR_S_I32 },
    { SHR_S_I32x4_S, SHR_S_I32x4 },
    { SHR_S_I64_S, SHR_S_I64 },
    { SHR_S_I64x2_S, SHR_S_I64x2 },
    { SHR_S_I8x16_S, SHR_S_I8x16 },
    { SHR_U_I16x8_S, SHR_U_I16x8 },
    { SHR_U_I32_S, SHR_U_I32 },
    { SHR_U_I32x4_S, SHR_U_I32x4 },
    { SHR_U_I64_S, SHR_U_I64 },
    { SHR_U_I64x2_S, SHR_U_I64x2 },
    { SHR_U_I8x16_S, SHR_U_I8x16 },
    { SHUFFLE_S, SHUFFLE },
    { SIMD_RELAXED_FMAX_F32x4_S, SIMD_RELAXED_FMAX_F32x4 },
    { SIMD_RELAXED_FMAX_F64x2_S, SIMD_RELAXED_FMAX_F64x2 },
    { SIMD_RELAXED_FMIN_F32x4_S, SIMD_RELAXED_FMIN_F32x4 },
    { SIMD_RELAXED_FMIN_F64x2_S, SIMD_RELAXED_FMIN_F64x2 },
    { SPLAT_F16x8_S, SPLAT_F16x8 },
    { SPLAT_F32x4_S, SPLAT_F32x4 },
    { SPLAT_F64x2_S, SPLAT_F64x2 },
    { SPLAT_I16x8_S, SPLAT_I16x8 },
    { SPLAT_I32x4_S, SPLAT_I32x4 },
    { SPLAT_I64x2_S, SPLAT_I64x2 },
    { SPLAT_I8x16_S, SPLAT_I8x16 },
    { SQRT_F16x8_S, SQRT_F16x8 },
    { SQRT_F32_S, SQRT_F32 },
    { SQRT_F32x4_S, SQRT_F32x4 },
    { SQRT_F64_S, SQRT_F64 },
    { SQRT_F64x2_S, SQRT_F64x2 },
    { STORE16_I32_A32_S, STORE16_I32_A32 },
    { STORE16_I32_A64_S, STORE16_I32_A64 },
    { STORE16_I64_A32_S, STORE16_I64_A32 },
    { STORE16_I64_A64_S, STORE16_I64_A64 },
    { STORE32_I64_A32_S, STORE32_I64_A32 },
    { STORE32_I64_A64_S, STORE32_I64_A64 },
    { STORE8_I32_A32_S, STORE8_I32_A32 },
    { STORE8_I32_A64_S, STORE8_I32_A64 },
    { STORE8_I64_A32_S, STORE8_I64_A32 },
    { STORE8_I64_A64_S, STORE8_I64_A64 },
    { STORE_F16_F32_A32_S, STORE_F16_F32_A32 },
    { STORE_F16_F32_A64_S, STORE_F16_F32_A64 },
    { STORE_F32_A32_S, STORE_F32_A32 },
    { STORE_F32_A64_S, STORE_F32_A64 },
    { STORE_F64_A32_S, STORE_F64_A32 },
    { STORE_F64_A64_S, STORE_F64_A64 },
    { STORE_I32_A32_S, STORE_I32_A32 },
    { STORE_I32_A64_S, STORE_I32_A64 },
    { STORE_I64_A32_S, STORE_I64_A32 },
    { STORE_I64_A64_S, STORE_I64_A64 },
    { STORE_LANE_I16x8_A32_S, STORE_LANE_I16x8_A32 },
    { STORE_LANE_I16x8_A64_S, STORE_LANE_I16x8_A64 },
    { STORE_LANE_I32x4_A32_S, STORE_LANE_I32x4_A32 },
    { STORE_LANE_I32x4_A64_S, STORE_LANE_I32x4_A64 },
    { STORE_LANE_I64x2_A32_S, STORE_LANE_I64x2_A32 },
    { STORE_LANE_I64x2_A64_S, STORE_LANE_I64x2_A64 },
    { STORE_LANE_I8x16_A32_S, STORE_LANE_I8x16_A32 },
    { STORE_LANE_I8x16_A64_S, STORE_LANE_I8x16_A64 },
    { STORE_V128_A32_S, STORE_V128_A32 },
    { STORE_V128_A64_S, STORE_V128_A64 },
    { SUB_F16x8_S, SUB_F16x8 },
    { SUB_F32_S, SUB_F32 },
    { SUB_F32x4_S, SUB_F32x4 },
    { SUB_F64_S, SUB_F64 },
    { SUB_F64x2_S, SUB_F64x2 },
    { SUB_I16x8_S, SUB_I16x8 },
    { SUB_I32_S, SUB_I32 },
    { SUB_I32x4_S, SUB_I32x4 },
    { SUB_I64_S, SUB_I64 },
    { SUB_I64x2_S, SUB_I64x2 },
    { SUB_I8x16_S, SUB_I8x16 },
    { SUB_SAT_S_I16x8_S, SUB_SAT_S_I16x8 },
    { SUB_SAT_S_I8x16_S, SUB_SAT_S_I8x16 },
    { SUB_SAT_U_I16x8_S, SUB_SAT_U_I16x8 },
    { SUB_SAT_U_I8x16_S, SUB_SAT_U_I8x16 },
    { SWIZZLE_S, SWIZZLE },
    { TABLE_COPY_S, TABLE_COPY },
    { TABLE_FILL_EXNREF_S, TABLE_FILL_EXNREF },
    { TABLE_FILL_EXTERNREF_S, TABLE_FILL_EXTERNREF },
    { TABLE_FILL_FUNCREF_S, TABLE_FILL_FUNCREF },
    { TABLE_GET_EXNREF_S, TABLE_GET_EXNREF },
    { TABLE_GET_EXTERNREF_S, TABLE_GET_EXTERNREF },
    { TABLE_GET_FUNCREF_S, TABLE_GET_FUNCREF },
    { TABLE_GROW_EXNREF_S, TABLE_GROW_EXNREF },
    { TABLE_GROW_EXTERNREF_S, TABLE_GROW_EXTERNREF },
    { TABLE_GROW_FUNCREF_S, TABLE_GROW_FUNCREF },
    { TABLE_SET_EXNREF_S, TABLE_SET_EXNREF },
    { TABLE_SET_EXTERNREF_S, TABLE_SET_EXTERNREF },
    { TABLE_SET_FUNCREF_S, TABLE_SET_FUNCREF },
    { TABLE_SIZE_S, TABLE_SIZE },
    { TEE_EXNREF_S, TEE_EXNREF },
    { TEE_EXTERNREF_S, TEE_EXTERNREF },
    { TEE_F32_S, TEE_F32 },
    { TEE_F64_S, TEE_F64 },
    { TEE_FUNCREF_S, TEE_FUNCREF },
    { TEE_I32_S, TEE_I32 },
    { TEE_I64_S, TEE_I64 },
    { TEE_V128_S, TEE_V128 },
    { THROW_REF_S, THROW_REF },
    { THROW_S, THROW },
    { TRUNC_F16x8_S, TRUNC_F16x8 },
    { TRUNC_F32_S, TRUNC_F32 },
    { TRUNC_F32x4_S, TRUNC_F32x4 },
    { TRUNC_F64_S, TRUNC_F64 },
    { TRUNC_F64x2_S, TRUNC_F64x2 },
    { TRY_S, TRY },
    { TRY_TABLE_S, TRY_TABLE },
    { UNREACHABLE_S, UNREACHABLE },
    { XOR_I32_S, XOR_I32 },
    { XOR_I64_S, XOR_I64 },
    { XOR_S, XOR },
    { anonymous_14027MEMORY_GROW_A32_S, anonymous_14027MEMORY_GROW_A32 },
    { anonymous_14027MEMORY_SIZE_A32_S, anonymous_14027MEMORY_SIZE_A32 },
    { anonymous_14028MEMORY_GROW_A64_S, anonymous_14028MEMORY_GROW_A64 },
    { anonymous_14028MEMORY_SIZE_A64_S, anonymous_14028MEMORY_SIZE_A64 },
    { convert_low_s_F64x2_S, convert_low_s_F64x2 },
    { convert_low_u_F64x2_S, convert_low_u_F64x2 },
    { demote_zero_F16x8_S, demote_zero_F16x8 },
    { demote_zero_F32x4_S, demote_zero_F32x4 },
    { extadd_pairwise_s_I16x8_S, extadd_pairwise_s_I16x8 },
    { extadd_pairwise_s_I32x4_S, extadd_pairwise_s_I32x4 },
    { extadd_pairwise_u_I16x8_S, extadd_pairwise_u_I16x8 },
    { extadd_pairwise_u_I32x4_S, extadd_pairwise_u_I32x4 },
    { extend_high_s_I16x8_S, extend_high_s_I16x8 },
    { extend_high_s_I32x4_S, extend_high_s_I32x4 },
    { extend_high_s_I64x2_S, extend_high_s_I64x2 },
    { extend_high_u_I16x8_S, extend_high_u_I16x8 },
    { extend_high_u_I32x4_S, extend_high_u_I32x4 },
    { extend_high_u_I64x2_S, extend_high_u_I64x2 },
    { extend_low_s_I16x8_S, extend_low_s_I16x8 },
    { extend_low_s_I32x4_S, extend_low_s_I32x4 },
    { extend_low_s_I64x2_S, extend_low_s_I64x2 },
    { extend_low_u_I16x8_S, extend_low_u_I16x8 },
    { extend_low_u_I32x4_S, extend_low_u_I32x4 },
    { extend_low_u_I64x2_S, extend_low_u_I64x2 },
    { fp_to_sint_I16x8_S, fp_to_sint_I16x8 },
    { fp_to_sint_I32x4_S, fp_to_sint_I32x4 },
    { fp_to_uint_I16x8_S, fp_to_uint_I16x8 },
    { fp_to_uint_I32x4_S, fp_to_uint_I32x4 },
    { int_wasm_relaxed_trunc_signed_I32x4_S, int_wasm_relaxed_trunc_signed_I32x4 },
    { int_wasm_relaxed_trunc_signed_zero_I32x4_S, int_wasm_relaxed_trunc_signed_zero_I32x4 },
    { int_wasm_relaxed_trunc_unsigned_I32x4_S, int_wasm_relaxed_trunc_unsigned_I32x4 },
    { int_wasm_relaxed_trunc_unsigned_zero_I32x4_S, int_wasm_relaxed_trunc_unsigned_zero_I32x4 },
    { promote_low_F32x4_S, promote_low_F32x4 },
    { promote_low_F64x2_S, promote_low_F64x2 },
    { sint_to_fp_F16x8_S, sint_to_fp_F16x8 },
    { sint_to_fp_F32x4_S, sint_to_fp_F32x4 },
    { trunc_sat_zero_s_I32x4_S, trunc_sat_zero_s_I32x4 },
    { trunc_sat_zero_u_I32x4_S, trunc_sat_zero_u_I32x4 },
    { uint_to_fp_F16x8_S, uint_to_fp_F16x8 },
    { uint_to_fp_F32x4_S, uint_to_fp_F32x4 },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 823;
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

// getStackOpcode
LLVM_READONLY
int32_t getStackOpcode(uint32_t Opcode) {
  using namespace WebAssembly;
  static constexpr uint32_t Table[][2] = {
    { CALL_PARAMS, CALL_PARAMS_S },
    { CALL_RESULTS, CALL_RESULTS_S },
    { CATCHRET, CATCHRET_S },
    { CLEANUPRET, CLEANUPRET_S },
    { COMPILER_FENCE, COMPILER_FENCE_S },
    { RET_CALL_RESULTS, RET_CALL_RESULTS_S },
    { ABS_F16x8, ABS_F16x8_S },
    { ABS_F32, ABS_F32_S },
    { ABS_F32x4, ABS_F32x4_S },
    { ABS_F64, ABS_F64_S },
    { ABS_F64x2, ABS_F64x2_S },
    { ABS_I16x8, ABS_I16x8_S },
    { ABS_I32x4, ABS_I32x4_S },
    { ABS_I64x2, ABS_I64x2_S },
    { ABS_I8x16, ABS_I8x16_S },
    { ADD_F16x8, ADD_F16x8_S },
    { ADD_F32, ADD_F32_S },
    { ADD_F32x4, ADD_F32x4_S },
    { ADD_F64, ADD_F64_S },
    { ADD_F64x2, ADD_F64x2_S },
    { ADD_I16x8, ADD_I16x8_S },
    { ADD_I32, ADD_I32_S },
    { ADD_I32x4, ADD_I32x4_S },
    { ADD_I64, ADD_I64_S },
    { ADD_I64x2, ADD_I64x2_S },
    { ADD_I8x16, ADD_I8x16_S },
    { ADD_SAT_S_I16x8, ADD_SAT_S_I16x8_S },
    { ADD_SAT_S_I8x16, ADD_SAT_S_I8x16_S },
    { ADD_SAT_U_I16x8, ADD_SAT_U_I16x8_S },
    { ADD_SAT_U_I8x16, ADD_SAT_U_I8x16_S },
    { ADJCALLSTACKDOWN, ADJCALLSTACKDOWN_S },
    { ADJCALLSTACKUP, ADJCALLSTACKUP_S },
    { ALLTRUE_I16x8, ALLTRUE_I16x8_S },
    { ALLTRUE_I32x4, ALLTRUE_I32x4_S },
    { ALLTRUE_I64x2, ALLTRUE_I64x2_S },
    { ALLTRUE_I8x16, ALLTRUE_I8x16_S },
    { AND, AND_S },
    { ANDNOT, ANDNOT_S },
    { AND_I32, AND_I32_S },
    { AND_I64, AND_I64_S },
    { ANYTRUE, ANYTRUE_S },
    { ARGUMENT_exnref, ARGUMENT_exnref_S },
    { ARGUMENT_externref, ARGUMENT_externref_S },
    { ARGUMENT_f32, ARGUMENT_f32_S },
    { ARGUMENT_f64, ARGUMENT_f64_S },
    { ARGUMENT_funcref, ARGUMENT_funcref_S },
    { ARGUMENT_i32, ARGUMENT_i32_S },
    { ARGUMENT_i64, ARGUMENT_i64_S },
    { ARGUMENT_v16i8, ARGUMENT_v16i8_S },
    { ARGUMENT_v2f64, ARGUMENT_v2f64_S },
    { ARGUMENT_v2i64, ARGUMENT_v2i64_S },
    { ARGUMENT_v4f32, ARGUMENT_v4f32_S },
    { ARGUMENT_v4i32, ARGUMENT_v4i32_S },
    { ARGUMENT_v8f16, ARGUMENT_v8f16_S },
    { ARGUMENT_v8i16, ARGUMENT_v8i16_S },
    { ATOMIC_FENCE, ATOMIC_FENCE_S },
    { ATOMIC_LOAD16_U_I32_A32, ATOMIC_LOAD16_U_I32_A32_S },
    { ATOMIC_LOAD16_U_I32_A64, ATOMIC_LOAD16_U_I32_A64_S },
    { ATOMIC_LOAD16_U_I64_A32, ATOMIC_LOAD16_U_I64_A32_S },
    { ATOMIC_LOAD16_U_I64_A64, ATOMIC_LOAD16_U_I64_A64_S },
    { ATOMIC_LOAD32_U_I64_A32, ATOMIC_LOAD32_U_I64_A32_S },
    { ATOMIC_LOAD32_U_I64_A64, ATOMIC_LOAD32_U_I64_A64_S },
    { ATOMIC_LOAD8_U_I32_A32, ATOMIC_LOAD8_U_I32_A32_S },
    { ATOMIC_LOAD8_U_I32_A64, ATOMIC_LOAD8_U_I32_A64_S },
    { ATOMIC_LOAD8_U_I64_A32, ATOMIC_LOAD8_U_I64_A32_S },
    { ATOMIC_LOAD8_U_I64_A64, ATOMIC_LOAD8_U_I64_A64_S },
    { ATOMIC_LOAD_I32_A32, ATOMIC_LOAD_I32_A32_S },
    { ATOMIC_LOAD_I32_A64, ATOMIC_LOAD_I32_A64_S },
    { ATOMIC_LOAD_I64_A32, ATOMIC_LOAD_I64_A32_S },
    { ATOMIC_LOAD_I64_A64, ATOMIC_LOAD_I64_A64_S },
    { ATOMIC_RMW16_U_ADD_I32_A32, ATOMIC_RMW16_U_ADD_I32_A32_S },
    { ATOMIC_RMW16_U_ADD_I32_A64, ATOMIC_RMW16_U_ADD_I32_A64_S },
    { ATOMIC_RMW16_U_ADD_I64_A32, ATOMIC_RMW16_U_ADD_I64_A32_S },
    { ATOMIC_RMW16_U_ADD_I64_A64, ATOMIC_RMW16_U_ADD_I64_A64_S },
    { ATOMIC_RMW16_U_AND_I32_A32, ATOMIC_RMW16_U_AND_I32_A32_S },
    { ATOMIC_RMW16_U_AND_I32_A64, ATOMIC_RMW16_U_AND_I32_A64_S },
    { ATOMIC_RMW16_U_AND_I64_A32, ATOMIC_RMW16_U_AND_I64_A32_S },
    { ATOMIC_RMW16_U_AND_I64_A64, ATOMIC_RMW16_U_AND_I64_A64_S },
    { ATOMIC_RMW16_U_CMPXCHG_I32_A32, ATOMIC_RMW16_U_CMPXCHG_I32_A32_S },
    { ATOMIC_RMW16_U_CMPXCHG_I32_A64, ATOMIC_RMW16_U_CMPXCHG_I32_A64_S },
    { ATOMIC_RMW16_U_CMPXCHG_I64_A32, ATOMIC_RMW16_U_CMPXCHG_I64_A32_S },
    { ATOMIC_RMW16_U_CMPXCHG_I64_A64, ATOMIC_RMW16_U_CMPXCHG_I64_A64_S },
    { ATOMIC_RMW16_U_OR_I32_A32, ATOMIC_RMW16_U_OR_I32_A32_S },
    { ATOMIC_RMW16_U_OR_I32_A64, ATOMIC_RMW16_U_OR_I32_A64_S },
    { ATOMIC_RMW16_U_OR_I64_A32, ATOMIC_RMW16_U_OR_I64_A32_S },
    { ATOMIC_RMW16_U_OR_I64_A64, ATOMIC_RMW16_U_OR_I64_A64_S },
    { ATOMIC_RMW16_U_SUB_I32_A32, ATOMIC_RMW16_U_SUB_I32_A32_S },
    { ATOMIC_RMW16_U_SUB_I32_A64, ATOMIC_RMW16_U_SUB_I32_A64_S },
    { ATOMIC_RMW16_U_SUB_I64_A32, ATOMIC_RMW16_U_SUB_I64_A32_S },
    { ATOMIC_RMW16_U_SUB_I64_A64, ATOMIC_RMW16_U_SUB_I64_A64_S },
    { ATOMIC_RMW16_U_XCHG_I32_A32, ATOMIC_RMW16_U_XCHG_I32_A32_S },
    { ATOMIC_RMW16_U_XCHG_I32_A64, ATOMIC_RMW16_U_XCHG_I32_A64_S },
    { ATOMIC_RMW16_U_XCHG_I64_A32, ATOMIC_RMW16_U_XCHG_I64_A32_S },
    { ATOMIC_RMW16_U_XCHG_I64_A64, ATOMIC_RMW16_U_XCHG_I64_A64_S },
    { ATOMIC_RMW16_U_XOR_I32_A32, ATOMIC_RMW16_U_XOR_I32_A32_S },
    { ATOMIC_RMW16_U_XOR_I32_A64, ATOMIC_RMW16_U_XOR_I32_A64_S },
    { ATOMIC_RMW16_U_XOR_I64_A32, ATOMIC_RMW16_U_XOR_I64_A32_S },
    { ATOMIC_RMW16_U_XOR_I64_A64, ATOMIC_RMW16_U_XOR_I64_A64_S },
    { ATOMIC_RMW32_U_ADD_I64_A32, ATOMIC_RMW32_U_ADD_I64_A32_S },
    { ATOMIC_RMW32_U_ADD_I64_A64, ATOMIC_RMW32_U_ADD_I64_A64_S },
    { ATOMIC_RMW32_U_AND_I64_A32, ATOMIC_RMW32_U_AND_I64_A32_S },
    { ATOMIC_RMW32_U_AND_I64_A64, ATOMIC_RMW32_U_AND_I64_A64_S },
    { ATOMIC_RMW32_U_CMPXCHG_I64_A32, ATOMIC_RMW32_U_CMPXCHG_I64_A32_S },
    { ATOMIC_RMW32_U_CMPXCHG_I64_A64, ATOMIC_RMW32_U_CMPXCHG_I64_A64_S },
    { ATOMIC_RMW32_U_OR_I64_A32, ATOMIC_RMW32_U_OR_I64_A32_S },
    { ATOMIC_RMW32_U_OR_I64_A64, ATOMIC_RMW32_U_OR_I64_A64_S },
    { ATOMIC_RMW32_U_SUB_I64_A32, ATOMIC_RMW32_U_SUB_I64_A32_S },
    { ATOMIC_RMW32_U_SUB_I64_A64, ATOMIC_RMW32_U_SUB_I64_A64_S },
    { ATOMIC_RMW32_U_XCHG_I64_A32, ATOMIC_RMW32_U_XCHG_I64_A32_S },
    { ATOMIC_RMW32_U_XCHG_I64_A64, ATOMIC_RMW32_U_XCHG_I64_A64_S },
    { ATOMIC_RMW32_U_XOR_I64_A32, ATOMIC_RMW32_U_XOR_I64_A32_S },
    { ATOMIC_RMW32_U_XOR_I64_A64, ATOMIC_RMW32_U_XOR_I64_A64_S },
    { ATOMIC_RMW8_U_ADD_I32_A32, ATOMIC_RMW8_U_ADD_I32_A32_S },
    { ATOMIC_RMW8_U_ADD_I32_A64, ATOMIC_RMW8_U_ADD_I32_A64_S },
    { ATOMIC_RMW8_U_ADD_I64_A32, ATOMIC_RMW8_U_ADD_I64_A32_S },
    { ATOMIC_RMW8_U_ADD_I64_A64, ATOMIC_RMW8_U_ADD_I64_A64_S },
    { ATOMIC_RMW8_U_AND_I32_A32, ATOMIC_RMW8_U_AND_I32_A32_S },
    { ATOMIC_RMW8_U_AND_I32_A64, ATOMIC_RMW8_U_AND_I32_A64_S },
    { ATOMIC_RMW8_U_AND_I64_A32, ATOMIC_RMW8_U_AND_I64_A32_S },
    { ATOMIC_RMW8_U_AND_I64_A64, ATOMIC_RMW8_U_AND_I64_A64_S },
    { ATOMIC_RMW8_U_CMPXCHG_I32_A32, ATOMIC_RMW8_U_CMPXCHG_I32_A32_S },
    { ATOMIC_RMW8_U_CMPXCHG_I32_A64, ATOMIC_RMW8_U_CMPXCHG_I32_A64_S },
    { ATOMIC_RMW8_U_CMPXCHG_I64_A32, ATOMIC_RMW8_U_CMPXCHG_I64_A32_S },
    { ATOMIC_RMW8_U_CMPXCHG_I64_A64, ATOMIC_RMW8_U_CMPXCHG_I64_A64_S },
    { ATOMIC_RMW8_U_OR_I32_A32, ATOMIC_RMW8_U_OR_I32_A32_S },
    { ATOMIC_RMW8_U_OR_I32_A64, ATOMIC_RMW8_U_OR_I32_A64_S },
    { ATOMIC_RMW8_U_OR_I64_A32, ATOMIC_RMW8_U_OR_I64_A32_S },
    { ATOMIC_RMW8_U_OR_I64_A64, ATOMIC_RMW8_U_OR_I64_A64_S },
    { ATOMIC_RMW8_U_SUB_I32_A32, ATOMIC_RMW8_U_SUB_I32_A32_S },
    { ATOMIC_RMW8_U_SUB_I32_A64, ATOMIC_RMW8_U_SUB_I32_A64_S },
    { ATOMIC_RMW8_U_SUB_I64_A32, ATOMIC_RMW8_U_SUB_I64_A32_S },
    { ATOMIC_RMW8_U_SUB_I64_A64, ATOMIC_RMW8_U_SUB_I64_A64_S },
    { ATOMIC_RMW8_U_XCHG_I32_A32, ATOMIC_RMW8_U_XCHG_I32_A32_S },
    { ATOMIC_RMW8_U_XCHG_I32_A64, ATOMIC_RMW8_U_XCHG_I32_A64_S },
    { ATOMIC_RMW8_U_XCHG_I64_A32, ATOMIC_RMW8_U_XCHG_I64_A32_S },
    { ATOMIC_RMW8_U_XCHG_I64_A64, ATOMIC_RMW8_U_XCHG_I64_A64_S },
    { ATOMIC_RMW8_U_XOR_I32_A32, ATOMIC_RMW8_U_XOR_I32_A32_S },
    { ATOMIC_RMW8_U_XOR_I32_A64, ATOMIC_RMW8_U_XOR_I32_A64_S },
    { ATOMIC_RMW8_U_XOR_I64_A32, ATOMIC_RMW8_U_XOR_I64_A32_S },
    { ATOMIC_RMW8_U_XOR_I64_A64, ATOMIC_RMW8_U_XOR_I64_A64_S },
    { ATOMIC_RMW_ADD_I32_A32, ATOMIC_RMW_ADD_I32_A32_S },
    { ATOMIC_RMW_ADD_I32_A64, ATOMIC_RMW_ADD_I32_A64_S },
    { ATOMIC_RMW_ADD_I64_A32, ATOMIC_RMW_ADD_I64_A32_S },
    { ATOMIC_RMW_ADD_I64_A64, ATOMIC_RMW_ADD_I64_A64_S },
    { ATOMIC_RMW_AND_I32_A32, ATOMIC_RMW_AND_I32_A32_S },
    { ATOMIC_RMW_AND_I32_A64, ATOMIC_RMW_AND_I32_A64_S },
    { ATOMIC_RMW_AND_I64_A32, ATOMIC_RMW_AND_I64_A32_S },
    { ATOMIC_RMW_AND_I64_A64, ATOMIC_RMW_AND_I64_A64_S },
    { ATOMIC_RMW_CMPXCHG_I32_A32, ATOMIC_RMW_CMPXCHG_I32_A32_S },
    { ATOMIC_RMW_CMPXCHG_I32_A64, ATOMIC_RMW_CMPXCHG_I32_A64_S },
    { ATOMIC_RMW_CMPXCHG_I64_A32, ATOMIC_RMW_CMPXCHG_I64_A32_S },
    { ATOMIC_RMW_CMPXCHG_I64_A64, ATOMIC_RMW_CMPXCHG_I64_A64_S },
    { ATOMIC_RMW_OR_I32_A32, ATOMIC_RMW_OR_I32_A32_S },
    { ATOMIC_RMW_OR_I32_A64, ATOMIC_RMW_OR_I32_A64_S },
    { ATOMIC_RMW_OR_I64_A32, ATOMIC_RMW_OR_I64_A32_S },
    { ATOMIC_RMW_OR_I64_A64, ATOMIC_RMW_OR_I64_A64_S },
    { ATOMIC_RMW_SUB_I32_A32, ATOMIC_RMW_SUB_I32_A32_S },
    { ATOMIC_RMW_SUB_I32_A64, ATOMIC_RMW_SUB_I32_A64_S },
    { ATOMIC_RMW_SUB_I64_A32, ATOMIC_RMW_SUB_I64_A32_S },
    { ATOMIC_RMW_SUB_I64_A64, ATOMIC_RMW_SUB_I64_A64_S },
    { ATOMIC_RMW_XCHG_I32_A32, ATOMIC_RMW_XCHG_I32_A32_S },
    { ATOMIC_RMW_XCHG_I32_A64, ATOMIC_RMW_XCHG_I32_A64_S },
    { ATOMIC_RMW_XCHG_I64_A32, ATOMIC_RMW_XCHG_I64_A32_S },
    { ATOMIC_RMW_XCHG_I64_A64, ATOMIC_RMW_XCHG_I64_A64_S },
    { ATOMIC_RMW_XOR_I32_A32, ATOMIC_RMW_XOR_I32_A32_S },
    { ATOMIC_RMW_XOR_I32_A64, ATOMIC_RMW_XOR_I32_A64_S },
    { ATOMIC_RMW_XOR_I64_A32, ATOMIC_RMW_XOR_I64_A32_S },
    { ATOMIC_RMW_XOR_I64_A64, ATOMIC_RMW_XOR_I64_A64_S },
    { ATOMIC_STORE16_I32_A32, ATOMIC_STORE16_I32_A32_S },
    { ATOMIC_STORE16_I32_A64, ATOMIC_STORE16_I32_A64_S },
    { ATOMIC_STORE16_I64_A32, ATOMIC_STORE16_I64_A32_S },
    { ATOMIC_STORE16_I64_A64, ATOMIC_STORE16_I64_A64_S },
    { ATOMIC_STORE32_I64_A32, ATOMIC_STORE32_I64_A32_S },
    { ATOMIC_STORE32_I64_A64, ATOMIC_STORE32_I64_A64_S },
    { ATOMIC_STORE8_I32_A32, ATOMIC_STORE8_I32_A32_S },
    { ATOMIC_STORE8_I32_A64, ATOMIC_STORE8_I32_A64_S },
    { ATOMIC_STORE8_I64_A32, ATOMIC_STORE8_I64_A32_S },
    { ATOMIC_STORE8_I64_A64, ATOMIC_STORE8_I64_A64_S },
    { ATOMIC_STORE_I32_A32, ATOMIC_STORE_I32_A32_S },
    { ATOMIC_STORE_I32_A64, ATOMIC_STORE_I32_A64_S },
    { ATOMIC_STORE_I64_A32, ATOMIC_STORE_I64_A32_S },
    { ATOMIC_STORE_I64_A64, ATOMIC_STORE_I64_A64_S },
    { AVGR_U_I16x8, AVGR_U_I16x8_S },
    { AVGR_U_I8x16, AVGR_U_I8x16_S },
    { BITMASK_I16x8, BITMASK_I16x8_S },
    { BITMASK_I32x4, BITMASK_I32x4_S },
    { BITMASK_I64x2, BITMASK_I64x2_S },
    { BITMASK_I8x16, BITMASK_I8x16_S },
    { BITSELECT, BITSELECT_S },
    { BLOCK, BLOCK_S },
    { BR, BR_S },
    { BR_IF, BR_IF_S },
    { BR_TABLE_I32, BR_TABLE_I32_S },
    { BR_TABLE_I64, BR_TABLE_I64_S },
    { BR_UNLESS, BR_UNLESS_S },
    { CALL, CALL_S },
    { CALL_INDIRECT, CALL_INDIRECT_S },
    { CALL_REF, CALL_REF_S },
    { CATCH, CATCH_S },
    { CATCH_ALL, CATCH_ALL_S },
    { CATCH_ALL_LEGACY, CATCH_ALL_LEGACY_S },
    { CATCH_ALL_REF, CATCH_ALL_REF_S },
    { CATCH_LEGACY, CATCH_LEGACY_S },
    { CATCH_REF, CATCH_REF_S },
    { CEIL_F16x8, CEIL_F16x8_S },
    { CEIL_F32, CEIL_F32_S },
    { CEIL_F32x4, CEIL_F32x4_S },
    { CEIL_F64, CEIL_F64_S },
    { CEIL_F64x2, CEIL_F64x2_S },
    { CLZ_I32, CLZ_I32_S },
    { CLZ_I64, CLZ_I64_S },
    { CONST_F32, CONST_F32_S },
    { CONST_F64, CONST_F64_S },
    { CONST_I32, CONST_I32_S },
    { CONST_I64, CONST_I64_S },
    { CONST_V128_F32x4, CONST_V128_F32x4_S },
    { CONST_V128_F64x2, CONST_V128_F64x2_S },
    { CONST_V128_I16x8, CONST_V128_I16x8_S },
    { CONST_V128_I32x4, CONST_V128_I32x4_S },
    { CONST_V128_I64x2, CONST_V128_I64x2_S },
    { CONST_V128_I8x16, CONST_V128_I8x16_S },
    { COPYSIGN_F32, COPYSIGN_F32_S },
    { COPYSIGN_F64, COPYSIGN_F64_S },
    { COPY_EXNREF, COPY_EXNREF_S },
    { COPY_EXTERNREF, COPY_EXTERNREF_S },
    { COPY_F32, COPY_F32_S },
    { COPY_F64, COPY_F64_S },
    { COPY_FUNCREF, COPY_FUNCREF_S },
    { COPY_I32, COPY_I32_S },
    { COPY_I64, COPY_I64_S },
    { COPY_V128, COPY_V128_S },
    { CTZ_I32, CTZ_I32_S },
    { CTZ_I64, CTZ_I64_S },
    { DATA_DROP, DATA_DROP_S },
    { DEBUG_UNREACHABLE, DEBUG_UNREACHABLE_S },
    { DELEGATE, DELEGATE_S },
    { DIV_F16x8, DIV_F16x8_S },
    { DIV_F32, DIV_F32_S },
    { DIV_F32x4, DIV_F32x4_S },
    { DIV_F64, DIV_F64_S },
    { DIV_F64x2, DIV_F64x2_S },
    { DIV_S_I32, DIV_S_I32_S },
    { DIV_S_I64, DIV_S_I64_S },
    { DIV_U_I32, DIV_U_I32_S },
    { DIV_U_I64, DIV_U_I64_S },
    { DOT, DOT_S },
    { DROP_EXNREF, DROP_EXNREF_S },
    { DROP_EXTERNREF, DROP_EXTERNREF_S },
    { DROP_F32, DROP_F32_S },
    { DROP_F64, DROP_F64_S },
    { DROP_FUNCREF, DROP_FUNCREF_S },
    { DROP_I32, DROP_I32_S },
    { DROP_I64, DROP_I64_S },
    { DROP_V128, DROP_V128_S },
    { ELSE, ELSE_S },
    { END, END_S },
    { END_BLOCK, END_BLOCK_S },
    { END_FUNCTION, END_FUNCTION_S },
    { END_IF, END_IF_S },
    { END_LOOP, END_LOOP_S },
    { END_TRY, END_TRY_S },
    { END_TRY_TABLE, END_TRY_TABLE_S },
    { EQZ_I32, EQZ_I32_S },
    { EQZ_I64, EQZ_I64_S },
    { EQ_F16x8, EQ_F16x8_S },
    { EQ_F32, EQ_F32_S },
    { EQ_F32x4, EQ_F32x4_S },
    { EQ_F64, EQ_F64_S },
    { EQ_F64x2, EQ_F64x2_S },
    { EQ_I16x8, EQ_I16x8_S },
    { EQ_I32, EQ_I32_S },
    { EQ_I32x4, EQ_I32x4_S },
    { EQ_I64, EQ_I64_S },
    { EQ_I64x2, EQ_I64x2_S },
    { EQ_I8x16, EQ_I8x16_S },
    { EXTMUL_HIGH_S_I16x8, EXTMUL_HIGH_S_I16x8_S },
    { EXTMUL_HIGH_S_I32x4, EXTMUL_HIGH_S_I32x4_S },
    { EXTMUL_HIGH_S_I64x2, EXTMUL_HIGH_S_I64x2_S },
    { EXTMUL_HIGH_U_I16x8, EXTMUL_HIGH_U_I16x8_S },
    { EXTMUL_HIGH_U_I32x4, EXTMUL_HIGH_U_I32x4_S },
    { EXTMUL_HIGH_U_I64x2, EXTMUL_HIGH_U_I64x2_S },
    { EXTMUL_LOW_S_I16x8, EXTMUL_LOW_S_I16x8_S },
    { EXTMUL_LOW_S_I32x4, EXTMUL_LOW_S_I32x4_S },
    { EXTMUL_LOW_S_I64x2, EXTMUL_LOW_S_I64x2_S },
    { EXTMUL_LOW_U_I16x8, EXTMUL_LOW_U_I16x8_S },
    { EXTMUL_LOW_U_I32x4, EXTMUL_LOW_U_I32x4_S },
    { EXTMUL_LOW_U_I64x2, EXTMUL_LOW_U_I64x2_S },
    { EXTRACT_LANE_F16x8, EXTRACT_LANE_F16x8_S },
    { EXTRACT_LANE_F32x4, EXTRACT_LANE_F32x4_S },
    { EXTRACT_LANE_F64x2, EXTRACT_LANE_F64x2_S },
    { EXTRACT_LANE_I16x8_s, EXTRACT_LANE_I16x8_s_S },
    { EXTRACT_LANE_I16x8_u, EXTRACT_LANE_I16x8_u_S },
    { EXTRACT_LANE_I32x4, EXTRACT_LANE_I32x4_S },
    { EXTRACT_LANE_I64x2, EXTRACT_LANE_I64x2_S },
    { EXTRACT_LANE_I8x16_s, EXTRACT_LANE_I8x16_s_S },
    { EXTRACT_LANE_I8x16_u, EXTRACT_LANE_I8x16_u_S },
    { F32_CONVERT_S_I32, F32_CONVERT_S_I32_S },
    { F32_CONVERT_S_I64, F32_CONVERT_S_I64_S },
    { F32_CONVERT_U_I32, F32_CONVERT_U_I32_S },
    { F32_CONVERT_U_I64, F32_CONVERT_U_I64_S },
    { F32_DEMOTE_F64, F32_DEMOTE_F64_S },
    { F32_REINTERPRET_I32, F32_REINTERPRET_I32_S },
    { F64_CONVERT_S_I32, F64_CONVERT_S_I32_S },
    { F64_CONVERT_S_I64, F64_CONVERT_S_I64_S },
    { F64_CONVERT_U_I32, F64_CONVERT_U_I32_S },
    { F64_CONVERT_U_I64, F64_CONVERT_U_I64_S },
    { F64_PROMOTE_F32, F64_PROMOTE_F32_S },
    { F64_REINTERPRET_I64, F64_REINTERPRET_I64_S },
    { FALLTHROUGH_RETURN, FALLTHROUGH_RETURN_S },
    { FLOOR_F16x8, FLOOR_F16x8_S },
    { FLOOR_F32, FLOOR_F32_S },
    { FLOOR_F32x4, FLOOR_F32x4_S },
    { FLOOR_F64, FLOOR_F64_S },
    { FLOOR_F64x2, FLOOR_F64x2_S },
    { FP_TO_SINT_I32_F32, FP_TO_SINT_I32_F32_S },
    { FP_TO_SINT_I32_F64, FP_TO_SINT_I32_F64_S },
    { FP_TO_SINT_I64_F32, FP_TO_SINT_I64_F32_S },
    { FP_TO_SINT_I64_F64, FP_TO_SINT_I64_F64_S },
    { FP_TO_UINT_I32_F32, FP_TO_UINT_I32_F32_S },
    { FP_TO_UINT_I32_F64, FP_TO_UINT_I32_F64_S },
    { FP_TO_UINT_I64_F32, FP_TO_UINT_I64_F32_S },
    { FP_TO_UINT_I64_F64, FP_TO_UINT_I64_F64_S },
    { GE_F16x8, GE_F16x8_S },
    { GE_F32, GE_F32_S },
    { GE_F32x4, GE_F32x4_S },
    { GE_F64, GE_F64_S },
    { GE_F64x2, GE_F64x2_S },
    { GE_S_I16x8, GE_S_I16x8_S },
    { GE_S_I32, GE_S_I32_S },
    { GE_S_I32x4, GE_S_I32x4_S },
    { GE_S_I64, GE_S_I64_S },
    { GE_S_I64x2, GE_S_I64x2_S },
    { GE_S_I8x16, GE_S_I8x16_S },
    { GE_U_I16x8, GE_U_I16x8_S },
    { GE_U_I32, GE_U_I32_S },
    { GE_U_I32x4, GE_U_I32x4_S },
    { GE_U_I64, GE_U_I64_S },
    { GE_U_I8x16, GE_U_I8x16_S },
    { GLOBAL_GET_EXNREF, GLOBAL_GET_EXNREF_S },
    { GLOBAL_GET_EXTERNREF, GLOBAL_GET_EXTERNREF_S },
    { GLOBAL_GET_F32, GLOBAL_GET_F32_S },
    { GLOBAL_GET_F64, GLOBAL_GET_F64_S },
    { GLOBAL_GET_FUNCREF, GLOBAL_GET_FUNCREF_S },
    { GLOBAL_GET_I32, GLOBAL_GET_I32_S },
    { GLOBAL_GET_I64, GLOBAL_GET_I64_S },
    { GLOBAL_GET_V128, GLOBAL_GET_V128_S },
    { GLOBAL_SET_EXNREF, GLOBAL_SET_EXNREF_S },
    { GLOBAL_SET_EXTERNREF, GLOBAL_SET_EXTERNREF_S },
    { GLOBAL_SET_F32, GLOBAL_SET_F32_S },
    { GLOBAL_SET_F64, GLOBAL_SET_F64_S },
    { GLOBAL_SET_FUNCREF, GLOBAL_SET_FUNCREF_S },
    { GLOBAL_SET_I32, GLOBAL_SET_I32_S },
    { GLOBAL_SET_I64, GLOBAL_SET_I64_S },
    { GLOBAL_SET_V128, GLOBAL_SET_V128_S },
    { GT_F16x8, GT_F16x8_S },
    { GT_F32, GT_F32_S },
    { GT_F32x4, GT_F32x4_S },
    { GT_F64, GT_F64_S },
    { GT_F64x2, GT_F64x2_S },
    { GT_S_I16x8, GT_S_I16x8_S },
    { GT_S_I32, GT_S_I32_S },
    { GT_S_I32x4, GT_S_I32x4_S },
    { GT_S_I64, GT_S_I64_S },
    { GT_S_I64x2, GT_S_I64x2_S },
    { GT_S_I8x16, GT_S_I8x16_S },
    { GT_U_I16x8, GT_U_I16x8_S },
    { GT_U_I32, GT_U_I32_S },
    { GT_U_I32x4, GT_U_I32x4_S },
    { GT_U_I64, GT_U_I64_S },
    { GT_U_I8x16, GT_U_I8x16_S },
    { I32_EXTEND16_S_I32, I32_EXTEND16_S_I32_S },
    { I32_EXTEND8_S_I32, I32_EXTEND8_S_I32_S },
    { I32_REINTERPRET_F32, I32_REINTERPRET_F32_S },
    { I32_TRUNC_S_F32, I32_TRUNC_S_F32_S },
    { I32_TRUNC_S_F64, I32_TRUNC_S_F64_S },
    { I32_TRUNC_S_SAT_F32, I32_TRUNC_S_SAT_F32_S },
    { I32_TRUNC_S_SAT_F64, I32_TRUNC_S_SAT_F64_S },
    { I32_TRUNC_U_F32, I32_TRUNC_U_F32_S },
    { I32_TRUNC_U_F64, I32_TRUNC_U_F64_S },
    { I32_TRUNC_U_SAT_F32, I32_TRUNC_U_SAT_F32_S },
    { I32_TRUNC_U_SAT_F64, I32_TRUNC_U_SAT_F64_S },
    { I32_WRAP_I64, I32_WRAP_I64_S },
    { I64_ADD128, I64_ADD128_S },
    { I64_EXTEND16_S_I64, I64_EXTEND16_S_I64_S },
    { I64_EXTEND32_S_I64, I64_EXTEND32_S_I64_S },
    { I64_EXTEND8_S_I64, I64_EXTEND8_S_I64_S },
    { I64_EXTEND_S_I32, I64_EXTEND_S_I32_S },
    { I64_EXTEND_U_I32, I64_EXTEND_U_I32_S },
    { I64_MUL_WIDE_S, I64_MUL_WIDE_S_S },
    { I64_MUL_WIDE_U, I64_MUL_WIDE_U_S },
    { I64_REINTERPRET_F64, I64_REINTERPRET_F64_S },
    { I64_SUB128, I64_SUB128_S },
    { I64_TRUNC_S_F32, I64_TRUNC_S_F32_S },
    { I64_TRUNC_S_F64, I64_TRUNC_S_F64_S },
    { I64_TRUNC_S_SAT_F32, I64_TRUNC_S_SAT_F32_S },
    { I64_TRUNC_S_SAT_F64, I64_TRUNC_S_SAT_F64_S },
    { I64_TRUNC_U_F32, I64_TRUNC_U_F32_S },
    { I64_TRUNC_U_F64, I64_TRUNC_U_F64_S },
    { I64_TRUNC_U_SAT_F32, I64_TRUNC_U_SAT_F32_S },
    { I64_TRUNC_U_SAT_F64, I64_TRUNC_U_SAT_F64_S },
    { IF, IF_S },
    { LANESELECT_I16x8, LANESELECT_I16x8_S },
    { LANESELECT_I32x4, LANESELECT_I32x4_S },
    { LANESELECT_I64x2, LANESELECT_I64x2_S },
    { LANESELECT_I8x16, LANESELECT_I8x16_S },
    { LE_F16x8, LE_F16x8_S },
    { LE_F32, LE_F32_S },
    { LE_F32x4, LE_F32x4_S },
    { LE_F64, LE_F64_S },
    { LE_F64x2, LE_F64x2_S },
    { LE_S_I16x8, LE_S_I16x8_S },
    { LE_S_I32, LE_S_I32_S },
    { LE_S_I32x4, LE_S_I32x4_S },
    { LE_S_I64, LE_S_I64_S },
    { LE_S_I64x2, LE_S_I64x2_S },
    { LE_S_I8x16, LE_S_I8x16_S },
    { LE_U_I16x8, LE_U_I16x8_S },
    { LE_U_I32, LE_U_I32_S },
    { LE_U_I32x4, LE_U_I32x4_S },
    { LE_U_I64, LE_U_I64_S },
    { LE_U_I8x16, LE_U_I8x16_S },
    { LOAD16_SPLAT_A32, LOAD16_SPLAT_A32_S },
    { LOAD16_SPLAT_A64, LOAD16_SPLAT_A64_S },
    { LOAD16_S_I32_A32, LOAD16_S_I32_A32_S },
    { LOAD16_S_I32_A64, LOAD16_S_I32_A64_S },
    { LOAD16_S_I64_A32, LOAD16_S_I64_A32_S },
    { LOAD16_S_I64_A64, LOAD16_S_I64_A64_S },
    { LOAD16_U_I32_A32, LOAD16_U_I32_A32_S },
    { LOAD16_U_I32_A64, LOAD16_U_I32_A64_S },
    { LOAD16_U_I64_A32, LOAD16_U_I64_A32_S },
    { LOAD16_U_I64_A64, LOAD16_U_I64_A64_S },
    { LOAD32_SPLAT_A32, LOAD32_SPLAT_A32_S },
    { LOAD32_SPLAT_A64, LOAD32_SPLAT_A64_S },
    { LOAD32_S_I64_A32, LOAD32_S_I64_A32_S },
    { LOAD32_S_I64_A64, LOAD32_S_I64_A64_S },
    { LOAD32_U_I64_A32, LOAD32_U_I64_A32_S },
    { LOAD32_U_I64_A64, LOAD32_U_I64_A64_S },
    { LOAD64_SPLAT_A32, LOAD64_SPLAT_A32_S },
    { LOAD64_SPLAT_A64, LOAD64_SPLAT_A64_S },
    { LOAD8_SPLAT_A32, LOAD8_SPLAT_A32_S },
    { LOAD8_SPLAT_A64, LOAD8_SPLAT_A64_S },
    { LOAD8_S_I32_A32, LOAD8_S_I32_A32_S },
    { LOAD8_S_I32_A64, LOAD8_S_I32_A64_S },
    { LOAD8_S_I64_A32, LOAD8_S_I64_A32_S },
    { LOAD8_S_I64_A64, LOAD8_S_I64_A64_S },
    { LOAD8_U_I32_A32, LOAD8_U_I32_A32_S },
    { LOAD8_U_I32_A64, LOAD8_U_I32_A64_S },
    { LOAD8_U_I64_A32, LOAD8_U_I64_A32_S },
    { LOAD8_U_I64_A64, LOAD8_U_I64_A64_S },
    { LOAD_EXTEND_S_I16x8_A32, LOAD_EXTEND_S_I16x8_A32_S },
    { LOAD_EXTEND_S_I16x8_A64, LOAD_EXTEND_S_I16x8_A64_S },
    { LOAD_EXTEND_S_I32x4_A32, LOAD_EXTEND_S_I32x4_A32_S },
    { LOAD_EXTEND_S_I32x4_A64, LOAD_EXTEND_S_I32x4_A64_S },
    { LOAD_EXTEND_S_I64x2_A32, LOAD_EXTEND_S_I64x2_A32_S },
    { LOAD_EXTEND_S_I64x2_A64, LOAD_EXTEND_S_I64x2_A64_S },
    { LOAD_EXTEND_U_I16x8_A32, LOAD_EXTEND_U_I16x8_A32_S },
    { LOAD_EXTEND_U_I16x8_A64, LOAD_EXTEND_U_I16x8_A64_S },
    { LOAD_EXTEND_U_I32x4_A32, LOAD_EXTEND_U_I32x4_A32_S },
    { LOAD_EXTEND_U_I32x4_A64, LOAD_EXTEND_U_I32x4_A64_S },
    { LOAD_EXTEND_U_I64x2_A32, LOAD_EXTEND_U_I64x2_A32_S },
    { LOAD_EXTEND_U_I64x2_A64, LOAD_EXTEND_U_I64x2_A64_S },
    { LOAD_F16_F32_A32, LOAD_F16_F32_A32_S },
    { LOAD_F16_F32_A64, LOAD_F16_F32_A64_S },
    { LOAD_F32_A32, LOAD_F32_A32_S },
    { LOAD_F32_A64, LOAD_F32_A64_S },
    { LOAD_F64_A32, LOAD_F64_A32_S },
    { LOAD_F64_A64, LOAD_F64_A64_S },
    { LOAD_I32_A32, LOAD_I32_A32_S },
    { LOAD_I32_A64, LOAD_I32_A64_S },
    { LOAD_I64_A32, LOAD_I64_A32_S },
    { LOAD_I64_A64, LOAD_I64_A64_S },
    { LOAD_LANE_16_A32, LOAD_LANE_16_A32_S },
    { LOAD_LANE_16_A64, LOAD_LANE_16_A64_S },
    { LOAD_LANE_32_A32, LOAD_LANE_32_A32_S },
    { LOAD_LANE_32_A64, LOAD_LANE_32_A64_S },
    { LOAD_LANE_64_A32, LOAD_LANE_64_A32_S },
    { LOAD_LANE_64_A64, LOAD_LANE_64_A64_S },
    { LOAD_LANE_8_A32, LOAD_LANE_8_A32_S },
    { LOAD_LANE_8_A64, LOAD_LANE_8_A64_S },
    { LOAD_V128_A32, LOAD_V128_A32_S },
    { LOAD_V128_A64, LOAD_V128_A64_S },
    { LOAD_ZERO_32_A32, LOAD_ZERO_32_A32_S },
    { LOAD_ZERO_32_A64, LOAD_ZERO_32_A64_S },
    { LOAD_ZERO_64_A32, LOAD_ZERO_64_A32_S },
    { LOAD_ZERO_64_A64, LOAD_ZERO_64_A64_S },
    { LOCAL_GET_EXNREF, LOCAL_GET_EXNREF_S },
    { LOCAL_GET_EXTERNREF, LOCAL_GET_EXTERNREF_S },
    { LOCAL_GET_F32, LOCAL_GET_F32_S },
    { LOCAL_GET_F64, LOCAL_GET_F64_S },
    { LOCAL_GET_FUNCREF, LOCAL_GET_FUNCREF_S },
    { LOCAL_GET_I32, LOCAL_GET_I32_S },
    { LOCAL_GET_I64, LOCAL_GET_I64_S },
    { LOCAL_GET_V128, LOCAL_GET_V128_S },
    { LOCAL_SET_EXNREF, LOCAL_SET_EXNREF_S },
    { LOCAL_SET_EXTERNREF, LOCAL_SET_EXTERNREF_S },
    { LOCAL_SET_F32, LOCAL_SET_F32_S },
    { LOCAL_SET_F64, LOCAL_SET_F64_S },
    { LOCAL_SET_FUNCREF, LOCAL_SET_FUNCREF_S },
    { LOCAL_SET_I32, LOCAL_SET_I32_S },
    { LOCAL_SET_I64, LOCAL_SET_I64_S },
    { LOCAL_SET_V128, LOCAL_SET_V128_S },
    { LOCAL_TEE_EXNREF, LOCAL_TEE_EXNREF_S },
    { LOCAL_TEE_EXTERNREF, LOCAL_TEE_EXTERNREF_S },
    { LOCAL_TEE_F32, LOCAL_TEE_F32_S },
    { LOCAL_TEE_F64, LOCAL_TEE_F64_S },
    { LOCAL_TEE_FUNCREF, LOCAL_TEE_FUNCREF_S },
    { LOCAL_TEE_I32, LOCAL_TEE_I32_S },
    { LOCAL_TEE_I64, LOCAL_TEE_I64_S },
    { LOCAL_TEE_V128, LOCAL_TEE_V128_S },
    { LOOP, LOOP_S },
    { LT_F16x8, LT_F16x8_S },
    { LT_F32, LT_F32_S },
    { LT_F32x4, LT_F32x4_S },
    { LT_F64, LT_F64_S },
    { LT_F64x2, LT_F64x2_S },
    { LT_S_I16x8, LT_S_I16x8_S },
    { LT_S_I32, LT_S_I32_S },
    { LT_S_I32x4, LT_S_I32x4_S },
    { LT_S_I64, LT_S_I64_S },
    { LT_S_I64x2, LT_S_I64x2_S },
    { LT_S_I8x16, LT_S_I8x16_S },
    { LT_U_I16x8, LT_U_I16x8_S },
    { LT_U_I32, LT_U_I32_S },
    { LT_U_I32x4, LT_U_I32x4_S },
    { LT_U_I64, LT_U_I64_S },
    { LT_U_I8x16, LT_U_I8x16_S },
    { MADD_F16x8, MADD_F16x8_S },
    { MADD_F32x4, MADD_F32x4_S },
    { MADD_F64x2, MADD_F64x2_S },
    { MAX_F16x8, MAX_F16x8_S },
    { MAX_F32, MAX_F32_S },
    { MAX_F32x4, MAX_F32x4_S },
    { MAX_F64, MAX_F64_S },
    { MAX_F64x2, MAX_F64x2_S },
    { MAX_S_I16x8, MAX_S_I16x8_S },
    { MAX_S_I32x4, MAX_S_I32x4_S },
    { MAX_S_I8x16, MAX_S_I8x16_S },
    { MAX_U_I16x8, MAX_U_I16x8_S },
    { MAX_U_I32x4, MAX_U_I32x4_S },
    { MAX_U_I8x16, MAX_U_I8x16_S },
    { MEMCPY_A32, MEMCPY_A32_S },
    { MEMCPY_A64, MEMCPY_A64_S },
    { MEMORY_ATOMIC_NOTIFY_A32, MEMORY_ATOMIC_NOTIFY_A32_S },
    { MEMORY_ATOMIC_NOTIFY_A64, MEMORY_ATOMIC_NOTIFY_A64_S },
    { MEMORY_ATOMIC_WAIT32_A32, MEMORY_ATOMIC_WAIT32_A32_S },
    { MEMORY_ATOMIC_WAIT32_A64, MEMORY_ATOMIC_WAIT32_A64_S },
    { MEMORY_ATOMIC_WAIT64_A32, MEMORY_ATOMIC_WAIT64_A32_S },
    { MEMORY_ATOMIC_WAIT64_A64, MEMORY_ATOMIC_WAIT64_A64_S },
    { MEMORY_COPY_A32, MEMORY_COPY_A32_S },
    { MEMORY_COPY_A64, MEMORY_COPY_A64_S },
    { MEMORY_FILL_A32, MEMORY_FILL_A32_S },
    { MEMORY_FILL_A64, MEMORY_FILL_A64_S },
    { MEMORY_INIT_A32, MEMORY_INIT_A32_S },
    { MEMORY_INIT_A64, MEMORY_INIT_A64_S },
    { MEMSET_A32, MEMSET_A32_S },
    { MEMSET_A64, MEMSET_A64_S },
    { MIN_F16x8, MIN_F16x8_S },
    { MIN_F32, MIN_F32_S },
    { MIN_F32x4, MIN_F32x4_S },
    { MIN_F64, MIN_F64_S },
    { MIN_F64x2, MIN_F64x2_S },
    { MIN_S_I16x8, MIN_S_I16x8_S },
    { MIN_S_I32x4, MIN_S_I32x4_S },
    { MIN_S_I8x16, MIN_S_I8x16_S },
    { MIN_U_I16x8, MIN_U_I16x8_S },
    { MIN_U_I32x4, MIN_U_I32x4_S },
    { MIN_U_I8x16, MIN_U_I8x16_S },
    { MUL_F16x8, MUL_F16x8_S },
    { MUL_F32, MUL_F32_S },
    { MUL_F32x4, MUL_F32x4_S },
    { MUL_F64, MUL_F64_S },
    { MUL_F64x2, MUL_F64x2_S },
    { MUL_I16x8, MUL_I16x8_S },
    { MUL_I32, MUL_I32_S },
    { MUL_I32x4, MUL_I32x4_S },
    { MUL_I64, MUL_I64_S },
    { MUL_I64x2, MUL_I64x2_S },
    { NARROW_S_I16x8, NARROW_S_I16x8_S },
    { NARROW_S_I8x16, NARROW_S_I8x16_S },
    { NARROW_U_I16x8, NARROW_U_I16x8_S },
    { NARROW_U_I8x16, NARROW_U_I8x16_S },
    { NEAREST_F16x8, NEAREST_F16x8_S },
    { NEAREST_F32, NEAREST_F32_S },
    { NEAREST_F32x4, NEAREST_F32x4_S },
    { NEAREST_F64, NEAREST_F64_S },
    { NEAREST_F64x2, NEAREST_F64x2_S },
    { NEG_F16x8, NEG_F16x8_S },
    { NEG_F32, NEG_F32_S },
    { NEG_F32x4, NEG_F32x4_S },
    { NEG_F64, NEG_F64_S },
    { NEG_F64x2, NEG_F64x2_S },
    { NEG_I16x8, NEG_I16x8_S },
    { NEG_I32x4, NEG_I32x4_S },
    { NEG_I64x2, NEG_I64x2_S },
    { NEG_I8x16, NEG_I8x16_S },
    { NE_F16x8, NE_F16x8_S },
    { NE_F32, NE_F32_S },
    { NE_F32x4, NE_F32x4_S },
    { NE_F64, NE_F64_S },
    { NE_F64x2, NE_F64x2_S },
    { NE_I16x8, NE_I16x8_S },
    { NE_I32, NE_I32_S },
    { NE_I32x4, NE_I32x4_S },
    { NE_I64, NE_I64_S },
    { NE_I64x2, NE_I64x2_S },
    { NE_I8x16, NE_I8x16_S },
    { NMADD_F16x8, NMADD_F16x8_S },
    { NMADD_F32x4, NMADD_F32x4_S },
    { NMADD_F64x2, NMADD_F64x2_S },
    { NOP, NOP_S },
    { NOT, NOT_S },
    { OR, OR_S },
    { OR_I32, OR_I32_S },
    { OR_I64, OR_I64_S },
    { PMAX_F16x8, PMAX_F16x8_S },
    { PMAX_F32x4, PMAX_F32x4_S },
    { PMAX_F64x2, PMAX_F64x2_S },
    { PMIN_F16x8, PMIN_F16x8_S },
    { PMIN_F32x4, PMIN_F32x4_S },
    { PMIN_F64x2, PMIN_F64x2_S },
    { POPCNT_I32, POPCNT_I32_S },
    { POPCNT_I64, POPCNT_I64_S },
    { POPCNT_I8x16, POPCNT_I8x16_S },
    { Q15MULR_SAT_S_I16x8, Q15MULR_SAT_S_I16x8_S },
    { REF_CAST_FUNCREF, REF_CAST_FUNCREF_S },
    { REF_FUNC, REF_FUNC_S },
    { REF_IS_NULL_EXNREF, REF_IS_NULL_EXNREF_S },
    { REF_IS_NULL_EXTERNREF, REF_IS_NULL_EXTERNREF_S },
    { REF_IS_NULL_FUNCREF, REF_IS_NULL_FUNCREF_S },
    { REF_NULL_EXNREF, REF_NULL_EXNREF_S },
    { REF_NULL_EXTERNREF, REF_NULL_EXTERNREF_S },
    { REF_NULL_FUNCREF, REF_NULL_FUNCREF_S },
    { REF_TEST_FUNCREF, REF_TEST_FUNCREF_S },
    { RELAXED_DOT, RELAXED_DOT_S },
    { RELAXED_DOT_ADD, RELAXED_DOT_ADD_S },
    { RELAXED_DOT_BFLOAT, RELAXED_DOT_BFLOAT_S },
    { RELAXED_Q15MULR_S_I16x8, RELAXED_Q15MULR_S_I16x8_S },
    { RELAXED_SWIZZLE, RELAXED_SWIZZLE_S },
    { REM_S_I32, REM_S_I32_S },
    { REM_S_I64, REM_S_I64_S },
    { REM_U_I32, REM_U_I32_S },
    { REM_U_I64, REM_U_I64_S },
    { REPLACE_LANE_F16x8, REPLACE_LANE_F16x8_S },
    { REPLACE_LANE_F32x4, REPLACE_LANE_F32x4_S },
    { REPLACE_LANE_F64x2, REPLACE_LANE_F64x2_S },
    { REPLACE_LANE_I16x8, REPLACE_LANE_I16x8_S },
    { REPLACE_LANE_I32x4, REPLACE_LANE_I32x4_S },
    { REPLACE_LANE_I64x2, REPLACE_LANE_I64x2_S },
    { REPLACE_LANE_I8x16, REPLACE_LANE_I8x16_S },
    { RETHROW, RETHROW_S },
    { RETURN, RETURN_S },
    { RET_CALL, RET_CALL_S },
    { RET_CALL_INDIRECT, RET_CALL_INDIRECT_S },
    { RET_CALL_REF, RET_CALL_REF_S },
    { ROTL_I32, ROTL_I32_S },
    { ROTL_I64, ROTL_I64_S },
    { ROTR_I32, ROTR_I32_S },
    { ROTR_I64, ROTR_I64_S },
    { SELECT_EXNREF, SELECT_EXNREF_S },
    { SELECT_EXTERNREF, SELECT_EXTERNREF_S },
    { SELECT_F32, SELECT_F32_S },
    { SELECT_F64, SELECT_F64_S },
    { SELECT_FUNCREF, SELECT_FUNCREF_S },
    { SELECT_I32, SELECT_I32_S },
    { SELECT_I64, SELECT_I64_S },
    { SELECT_T, SELECT_T_S },
    { SELECT_V128, SELECT_V128_S },
    { SHL_I16x8, SHL_I16x8_S },
    { SHL_I32, SHL_I32_S },
    { SHL_I32x4, SHL_I32x4_S },
    { SHL_I64, SHL_I64_S },
    { SHL_I64x2, SHL_I64x2_S },
    { SHL_I8x16, SHL_I8x16_S },
    { SHR_S_I16x8, SHR_S_I16x8_S },
    { SHR_S_I32, SHR_S_I32_S },
    { SHR_S_I32x4, SHR_S_I32x4_S },
    { SHR_S_I64, SHR_S_I64_S },
    { SHR_S_I64x2, SHR_S_I64x2_S },
    { SHR_S_I8x16, SHR_S_I8x16_S },
    { SHR_U_I16x8, SHR_U_I16x8_S },
    { SHR_U_I32, SHR_U_I32_S },
    { SHR_U_I32x4, SHR_U_I32x4_S },
    { SHR_U_I64, SHR_U_I64_S },
    { SHR_U_I64x2, SHR_U_I64x2_S },
    { SHR_U_I8x16, SHR_U_I8x16_S },
    { SHUFFLE, SHUFFLE_S },
    { SIMD_RELAXED_FMAX_F32x4, SIMD_RELAXED_FMAX_F32x4_S },
    { SIMD_RELAXED_FMAX_F64x2, SIMD_RELAXED_FMAX_F64x2_S },
    { SIMD_RELAXED_FMIN_F32x4, SIMD_RELAXED_FMIN_F32x4_S },
    { SIMD_RELAXED_FMIN_F64x2, SIMD_RELAXED_FMIN_F64x2_S },
    { SPLAT_F16x8, SPLAT_F16x8_S },
    { SPLAT_F32x4, SPLAT_F32x4_S },
    { SPLAT_F64x2, SPLAT_F64x2_S },
    { SPLAT_I16x8, SPLAT_I16x8_S },
    { SPLAT_I32x4, SPLAT_I32x4_S },
    { SPLAT_I64x2, SPLAT_I64x2_S },
    { SPLAT_I8x16, SPLAT_I8x16_S },
    { SQRT_F16x8, SQRT_F16x8_S },
    { SQRT_F32, SQRT_F32_S },
    { SQRT_F32x4, SQRT_F32x4_S },
    { SQRT_F64, SQRT_F64_S },
    { SQRT_F64x2, SQRT_F64x2_S },
    { STORE16_I32_A32, STORE16_I32_A32_S },
    { STORE16_I32_A64, STORE16_I32_A64_S },
    { STORE16_I64_A32, STORE16_I64_A32_S },
    { STORE16_I64_A64, STORE16_I64_A64_S },
    { STORE32_I64_A32, STORE32_I64_A32_S },
    { STORE32_I64_A64, STORE32_I64_A64_S },
    { STORE8_I32_A32, STORE8_I32_A32_S },
    { STORE8_I32_A64, STORE8_I32_A64_S },
    { STORE8_I64_A32, STORE8_I64_A32_S },
    { STORE8_I64_A64, STORE8_I64_A64_S },
    { STORE_F16_F32_A32, STORE_F16_F32_A32_S },
    { STORE_F16_F32_A64, STORE_F16_F32_A64_S },
    { STORE_F32_A32, STORE_F32_A32_S },
    { STORE_F32_A64, STORE_F32_A64_S },
    { STORE_F64_A32, STORE_F64_A32_S },
    { STORE_F64_A64, STORE_F64_A64_S },
    { STORE_I32_A32, STORE_I32_A32_S },
    { STORE_I32_A64, STORE_I32_A64_S },
    { STORE_I64_A32, STORE_I64_A32_S },
    { STORE_I64_A64, STORE_I64_A64_S },
    { STORE_LANE_I16x8_A32, STORE_LANE_I16x8_A32_S },
    { STORE_LANE_I16x8_A64, STORE_LANE_I16x8_A64_S },
    { STORE_LANE_I32x4_A32, STORE_LANE_I32x4_A32_S },
    { STORE_LANE_I32x4_A64, STORE_LANE_I32x4_A64_S },
    { STORE_LANE_I64x2_A32, STORE_LANE_I64x2_A32_S },
    { STORE_LANE_I64x2_A64, STORE_LANE_I64x2_A64_S },
    { STORE_LANE_I8x16_A32, STORE_LANE_I8x16_A32_S },
    { STORE_LANE_I8x16_A64, STORE_LANE_I8x16_A64_S },
    { STORE_V128_A32, STORE_V128_A32_S },
    { STORE_V128_A64, STORE_V128_A64_S },
    { SUB_F16x8, SUB_F16x8_S },
    { SUB_F32, SUB_F32_S },
    { SUB_F32x4, SUB_F32x4_S },
    { SUB_F64, SUB_F64_S },
    { SUB_F64x2, SUB_F64x2_S },
    { SUB_I16x8, SUB_I16x8_S },
    { SUB_I32, SUB_I32_S },
    { SUB_I32x4, SUB_I32x4_S },
    { SUB_I64, SUB_I64_S },
    { SUB_I64x2, SUB_I64x2_S },
    { SUB_I8x16, SUB_I8x16_S },
    { SUB_SAT_S_I16x8, SUB_SAT_S_I16x8_S },
    { SUB_SAT_S_I8x16, SUB_SAT_S_I8x16_S },
    { SUB_SAT_U_I16x8, SUB_SAT_U_I16x8_S },
    { SUB_SAT_U_I8x16, SUB_SAT_U_I8x16_S },
    { SWIZZLE, SWIZZLE_S },
    { TABLE_COPY, TABLE_COPY_S },
    { TABLE_FILL_EXNREF, TABLE_FILL_EXNREF_S },
    { TABLE_FILL_EXTERNREF, TABLE_FILL_EXTERNREF_S },
    { TABLE_FILL_FUNCREF, TABLE_FILL_FUNCREF_S },
    { TABLE_GET_EXNREF, TABLE_GET_EXNREF_S },
    { TABLE_GET_EXTERNREF, TABLE_GET_EXTERNREF_S },
    { TABLE_GET_FUNCREF, TABLE_GET_FUNCREF_S },
    { TABLE_GROW_EXNREF, TABLE_GROW_EXNREF_S },
    { TABLE_GROW_EXTERNREF, TABLE_GROW_EXTERNREF_S },
    { TABLE_GROW_FUNCREF, TABLE_GROW_FUNCREF_S },
    { TABLE_SET_EXNREF, TABLE_SET_EXNREF_S },
    { TABLE_SET_EXTERNREF, TABLE_SET_EXTERNREF_S },
    { TABLE_SET_FUNCREF, TABLE_SET_FUNCREF_S },
    { TABLE_SIZE, TABLE_SIZE_S },
    { TEE_EXNREF, TEE_EXNREF_S },
    { TEE_EXTERNREF, TEE_EXTERNREF_S },
    { TEE_F32, TEE_F32_S },
    { TEE_F64, TEE_F64_S },
    { TEE_FUNCREF, TEE_FUNCREF_S },
    { TEE_I32, TEE_I32_S },
    { TEE_I64, TEE_I64_S },
    { TEE_V128, TEE_V128_S },
    { THROW, THROW_S },
    { THROW_REF, THROW_REF_S },
    { TRUNC_F16x8, TRUNC_F16x8_S },
    { TRUNC_F32, TRUNC_F32_S },
    { TRUNC_F32x4, TRUNC_F32x4_S },
    { TRUNC_F64, TRUNC_F64_S },
    { TRUNC_F64x2, TRUNC_F64x2_S },
    { TRY, TRY_S },
    { TRY_TABLE, TRY_TABLE_S },
    { UNREACHABLE, UNREACHABLE_S },
    { XOR, XOR_S },
    { XOR_I32, XOR_I32_S },
    { XOR_I64, XOR_I64_S },
    { anonymous_14027MEMORY_GROW_A32, anonymous_14027MEMORY_GROW_A32_S },
    { anonymous_14027MEMORY_SIZE_A32, anonymous_14027MEMORY_SIZE_A32_S },
    { anonymous_14028MEMORY_GROW_A64, anonymous_14028MEMORY_GROW_A64_S },
    { anonymous_14028MEMORY_SIZE_A64, anonymous_14028MEMORY_SIZE_A64_S },
    { convert_low_s_F64x2, convert_low_s_F64x2_S },
    { convert_low_u_F64x2, convert_low_u_F64x2_S },
    { demote_zero_F16x8, demote_zero_F16x8_S },
    { demote_zero_F32x4, demote_zero_F32x4_S },
    { extadd_pairwise_s_I16x8, extadd_pairwise_s_I16x8_S },
    { extadd_pairwise_s_I32x4, extadd_pairwise_s_I32x4_S },
    { extadd_pairwise_u_I16x8, extadd_pairwise_u_I16x8_S },
    { extadd_pairwise_u_I32x4, extadd_pairwise_u_I32x4_S },
    { extend_high_s_I16x8, extend_high_s_I16x8_S },
    { extend_high_s_I32x4, extend_high_s_I32x4_S },
    { extend_high_s_I64x2, extend_high_s_I64x2_S },
    { extend_high_u_I16x8, extend_high_u_I16x8_S },
    { extend_high_u_I32x4, extend_high_u_I32x4_S },
    { extend_high_u_I64x2, extend_high_u_I64x2_S },
    { extend_low_s_I16x8, extend_low_s_I16x8_S },
    { extend_low_s_I32x4, extend_low_s_I32x4_S },
    { extend_low_s_I64x2, extend_low_s_I64x2_S },
    { extend_low_u_I16x8, extend_low_u_I16x8_S },
    { extend_low_u_I32x4, extend_low_u_I32x4_S },
    { extend_low_u_I64x2, extend_low_u_I64x2_S },
    { fp_to_sint_I16x8, fp_to_sint_I16x8_S },
    { fp_to_sint_I32x4, fp_to_sint_I32x4_S },
    { fp_to_uint_I16x8, fp_to_uint_I16x8_S },
    { fp_to_uint_I32x4, fp_to_uint_I32x4_S },
    { int_wasm_relaxed_trunc_signed_I32x4, int_wasm_relaxed_trunc_signed_I32x4_S },
    { int_wasm_relaxed_trunc_signed_zero_I32x4, int_wasm_relaxed_trunc_signed_zero_I32x4_S },
    { int_wasm_relaxed_trunc_unsigned_I32x4, int_wasm_relaxed_trunc_unsigned_I32x4_S },
    { int_wasm_relaxed_trunc_unsigned_zero_I32x4, int_wasm_relaxed_trunc_unsigned_zero_I32x4_S },
    { promote_low_F32x4, promote_low_F32x4_S },
    { promote_low_F64x2, promote_low_F64x2_S },
    { sint_to_fp_F16x8, sint_to_fp_F16x8_S },
    { sint_to_fp_F32x4, sint_to_fp_F32x4_S },
    { trunc_sat_zero_s_I32x4, trunc_sat_zero_s_I32x4_S },
    { trunc_sat_zero_u_I32x4, trunc_sat_zero_u_I32x4_S },
    { uint_to_fp_F16x8, uint_to_fp_F16x8_S },
    { uint_to_fp_F32x4, uint_to_fp_F32x4_S },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 823;
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

// getWasm64Opcode
LLVM_READONLY
int32_t getWasm64Opcode(uint32_t Opcode) {
  using namespace WebAssembly;
  static constexpr uint32_t Table[][2] = {
    { ATOMIC_LOAD16_U_I32_A32, ATOMIC_LOAD16_U_I32_A64 },
    { ATOMIC_LOAD16_U_I32_A32_S, ATOMIC_LOAD16_U_I32_A64_S },
    { ATOMIC_LOAD16_U_I64_A32, ATOMIC_LOAD16_U_I64_A64 },
    { ATOMIC_LOAD16_U_I64_A32_S, ATOMIC_LOAD16_U_I64_A64_S },
    { ATOMIC_LOAD32_U_I64_A32, ATOMIC_LOAD32_U_I64_A64 },
    { ATOMIC_LOAD32_U_I64_A32_S, ATOMIC_LOAD32_U_I64_A64_S },
    { ATOMIC_LOAD8_U_I32_A32, ATOMIC_LOAD8_U_I32_A64 },
    { ATOMIC_LOAD8_U_I32_A32_S, ATOMIC_LOAD8_U_I32_A64_S },
    { ATOMIC_LOAD8_U_I64_A32, ATOMIC_LOAD8_U_I64_A64 },
    { ATOMIC_LOAD8_U_I64_A32_S, ATOMIC_LOAD8_U_I64_A64_S },
    { ATOMIC_LOAD_I32_A32, ATOMIC_LOAD_I32_A64 },
    { ATOMIC_LOAD_I32_A32_S, ATOMIC_LOAD_I32_A64_S },
    { ATOMIC_LOAD_I64_A32, ATOMIC_LOAD_I64_A64 },
    { ATOMIC_LOAD_I64_A32_S, ATOMIC_LOAD_I64_A64_S },
    { ATOMIC_RMW16_U_ADD_I32_A32, ATOMIC_RMW16_U_ADD_I32_A64 },
    { ATOMIC_RMW16_U_ADD_I32_A32_S, ATOMIC_RMW16_U_ADD_I32_A64_S },
    { ATOMIC_RMW16_U_ADD_I64_A32, ATOMIC_RMW16_U_ADD_I64_A64 },
    { ATOMIC_RMW16_U_ADD_I64_A32_S, ATOMIC_RMW16_U_ADD_I64_A64_S },
    { ATOMIC_RMW16_U_AND_I32_A32, ATOMIC_RMW16_U_AND_I32_A64 },
    { ATOMIC_RMW16_U_AND_I32_A32_S, ATOMIC_RMW16_U_AND_I32_A64_S },
    { ATOMIC_RMW16_U_AND_I64_A32, ATOMIC_RMW16_U_AND_I64_A64 },
    { ATOMIC_RMW16_U_AND_I64_A32_S, ATOMIC_RMW16_U_AND_I64_A64_S },
    { ATOMIC_RMW16_U_CMPXCHG_I32_A32, ATOMIC_RMW16_U_CMPXCHG_I32_A64 },
    { ATOMIC_RMW16_U_CMPXCHG_I32_A32_S, ATOMIC_RMW16_U_CMPXCHG_I32_A64_S },
    { ATOMIC_RMW16_U_CMPXCHG_I64_A32, ATOMIC_RMW16_U_CMPXCHG_I64_A64 },
    { ATOMIC_RMW16_U_CMPXCHG_I64_A32_S, ATOMIC_RMW16_U_CMPXCHG_I64_A64_S },
    { ATOMIC_RMW16_U_OR_I32_A32, ATOMIC_RMW16_U_OR_I32_A64 },
    { ATOMIC_RMW16_U_OR_I32_A32_S, ATOMIC_RMW16_U_OR_I32_A64_S },
    { ATOMIC_RMW16_U_OR_I64_A32, ATOMIC_RMW16_U_OR_I64_A64 },
    { ATOMIC_RMW16_U_OR_I64_A32_S, ATOMIC_RMW16_U_OR_I64_A64_S },
    { ATOMIC_RMW16_U_SUB_I32_A32, ATOMIC_RMW16_U_SUB_I32_A64 },
    { ATOMIC_RMW16_U_SUB_I32_A32_S, ATOMIC_RMW16_U_SUB_I32_A64_S },
    { ATOMIC_RMW16_U_SUB_I64_A32, ATOMIC_RMW16_U_SUB_I64_A64 },
    { ATOMIC_RMW16_U_SUB_I64_A32_S, ATOMIC_RMW16_U_SUB_I64_A64_S },
    { ATOMIC_RMW16_U_XCHG_I32_A32, ATOMIC_RMW16_U_XCHG_I32_A64 },
    { ATOMIC_RMW16_U_XCHG_I32_A32_S, ATOMIC_RMW16_U_XCHG_I32_A64_S },
    { ATOMIC_RMW16_U_XCHG_I64_A32, ATOMIC_RMW16_U_XCHG_I64_A64 },
    { ATOMIC_RMW16_U_XCHG_I64_A32_S, ATOMIC_RMW16_U_XCHG_I64_A64_S },
    { ATOMIC_RMW16_U_XOR_I32_A32, ATOMIC_RMW16_U_XOR_I32_A64 },
    { ATOMIC_RMW16_U_XOR_I32_A32_S, ATOMIC_RMW16_U_XOR_I32_A64_S },
    { ATOMIC_RMW16_U_XOR_I64_A32, ATOMIC_RMW16_U_XOR_I64_A64 },
    { ATOMIC_RMW16_U_XOR_I64_A32_S, ATOMIC_RMW16_U_XOR_I64_A64_S },
    { ATOMIC_RMW32_U_ADD_I64_A32, ATOMIC_RMW32_U_ADD_I64_A64 },
    { ATOMIC_RMW32_U_ADD_I64_A32_S, ATOMIC_RMW32_U_ADD_I64_A64_S },
    { ATOMIC_RMW32_U_AND_I64_A32, ATOMIC_RMW32_U_AND_I64_A64 },
    { ATOMIC_RMW32_U_AND_I64_A32_S, ATOMIC_RMW32_U_AND_I64_A64_S },
    { ATOMIC_RMW32_U_CMPXCHG_I64_A32, ATOMIC_RMW32_U_CMPXCHG_I64_A64 },
    { ATOMIC_RMW32_U_CMPXCHG_I64_A32_S, ATOMIC_RMW32_U_CMPXCHG_I64_A64_S },
    { ATOMIC_RMW32_U_OR_I64_A32, ATOMIC_RMW32_U_OR_I64_A64 },
    { ATOMIC_RMW32_U_OR_I64_A32_S, ATOMIC_RMW32_U_OR_I64_A64_S },
    { ATOMIC_RMW32_U_SUB_I64_A32, ATOMIC_RMW32_U_SUB_I64_A64 },
    { ATOMIC_RMW32_U_SUB_I64_A32_S, ATOMIC_RMW32_U_SUB_I64_A64_S },
    { ATOMIC_RMW32_U_XCHG_I64_A32, ATOMIC_RMW32_U_XCHG_I64_A64 },
    { ATOMIC_RMW32_U_XCHG_I64_A32_S, ATOMIC_RMW32_U_XCHG_I64_A64_S },
    { ATOMIC_RMW32_U_XOR_I64_A32, ATOMIC_RMW32_U_XOR_I64_A64 },
    { ATOMIC_RMW32_U_XOR_I64_A32_S, ATOMIC_RMW32_U_XOR_I64_A64_S },
    { ATOMIC_RMW8_U_ADD_I32_A32, ATOMIC_RMW8_U_ADD_I32_A64 },
    { ATOMIC_RMW8_U_ADD_I32_A32_S, ATOMIC_RMW8_U_ADD_I32_A64_S },
    { ATOMIC_RMW8_U_ADD_I64_A32, ATOMIC_RMW8_U_ADD_I64_A64 },
    { ATOMIC_RMW8_U_ADD_I64_A32_S, ATOMIC_RMW8_U_ADD_I64_A64_S },
    { ATOMIC_RMW8_U_AND_I32_A32, ATOMIC_RMW8_U_AND_I32_A64 },
    { ATOMIC_RMW8_U_AND_I32_A32_S, ATOMIC_RMW8_U_AND_I32_A64_S },
    { ATOMIC_RMW8_U_AND_I64_A32, ATOMIC_RMW8_U_AND_I64_A64 },
    { ATOMIC_RMW8_U_AND_I64_A32_S, ATOMIC_RMW8_U_AND_I64_A64_S },
    { ATOMIC_RMW8_U_CMPXCHG_I32_A32, ATOMIC_RMW8_U_CMPXCHG_I32_A64 },
    { ATOMIC_RMW8_U_CMPXCHG_I32_A32_S, ATOMIC_RMW8_U_CMPXCHG_I32_A64_S },
    { ATOMIC_RMW8_U_CMPXCHG_I64_A32, ATOMIC_RMW8_U_CMPXCHG_I64_A64 },
    { ATOMIC_RMW8_U_CMPXCHG_I64_A32_S, ATOMIC_RMW8_U_CMPXCHG_I64_A64_S },
    { ATOMIC_RMW8_U_OR_I32_A32, ATOMIC_RMW8_U_OR_I32_A64 },
    { ATOMIC_RMW8_U_OR_I32_A32_S, ATOMIC_RMW8_U_OR_I32_A64_S },
    { ATOMIC_RMW8_U_OR_I64_A32, ATOMIC_RMW8_U_OR_I64_A64 },
    { ATOMIC_RMW8_U_OR_I64_A32_S, ATOMIC_RMW8_U_OR_I64_A64_S },
    { ATOMIC_RMW8_U_SUB_I32_A32, ATOMIC_RMW8_U_SUB_I32_A64 },
    { ATOMIC_RMW8_U_SUB_I32_A32_S, ATOMIC_RMW8_U_SUB_I32_A64_S },
    { ATOMIC_RMW8_U_SUB_I64_A32, ATOMIC_RMW8_U_SUB_I64_A64 },
    { ATOMIC_RMW8_U_SUB_I64_A32_S, ATOMIC_RMW8_U_SUB_I64_A64_S },
    { ATOMIC_RMW8_U_XCHG_I32_A32, ATOMIC_RMW8_U_XCHG_I32_A64 },
    { ATOMIC_RMW8_U_XCHG_I32_A32_S, ATOMIC_RMW8_U_XCHG_I32_A64_S },
    { ATOMIC_RMW8_U_XCHG_I64_A32, ATOMIC_RMW8_U_XCHG_I64_A64 },
    { ATOMIC_RMW8_U_XCHG_I64_A32_S, ATOMIC_RMW8_U_XCHG_I64_A64_S },
    { ATOMIC_RMW8_U_XOR_I32_A32, ATOMIC_RMW8_U_XOR_I32_A64 },
    { ATOMIC_RMW8_U_XOR_I32_A32_S, ATOMIC_RMW8_U_XOR_I32_A64_S },
    { ATOMIC_RMW8_U_XOR_I64_A32, ATOMIC_RMW8_U_XOR_I64_A64 },
    { ATOMIC_RMW8_U_XOR_I64_A32_S, ATOMIC_RMW8_U_XOR_I64_A64_S },
    { ATOMIC_RMW_ADD_I32_A32, ATOMIC_RMW_ADD_I32_A64 },
    { ATOMIC_RMW_ADD_I32_A32_S, ATOMIC_RMW_ADD_I32_A64_S },
    { ATOMIC_RMW_ADD_I64_A32, ATOMIC_RMW_ADD_I64_A64 },
    { ATOMIC_RMW_ADD_I64_A32_S, ATOMIC_RMW_ADD_I64_A64_S },
    { ATOMIC_RMW_AND_I32_A32, ATOMIC_RMW_AND_I32_A64 },
    { ATOMIC_RMW_AND_I32_A32_S, ATOMIC_RMW_AND_I32_A64_S },
    { ATOMIC_RMW_AND_I64_A32, ATOMIC_RMW_AND_I64_A64 },
    { ATOMIC_RMW_AND_I64_A32_S, ATOMIC_RMW_AND_I64_A64_S },
    { ATOMIC_RMW_CMPXCHG_I32_A32, ATOMIC_RMW_CMPXCHG_I32_A64 },
    { ATOMIC_RMW_CMPXCHG_I32_A32_S, ATOMIC_RMW_CMPXCHG_I32_A64_S },
    { ATOMIC_RMW_CMPXCHG_I64_A32, ATOMIC_RMW_CMPXCHG_I64_A64 },
    { ATOMIC_RMW_CMPXCHG_I64_A32_S, ATOMIC_RMW_CMPXCHG_I64_A64_S },
    { ATOMIC_RMW_OR_I32_A32, ATOMIC_RMW_OR_I32_A64 },
    { ATOMIC_RMW_OR_I32_A32_S, ATOMIC_RMW_OR_I32_A64_S },
    { ATOMIC_RMW_OR_I64_A32, ATOMIC_RMW_OR_I64_A64 },
    { ATOMIC_RMW_OR_I64_A32_S, ATOMIC_RMW_OR_I64_A64_S },
    { ATOMIC_RMW_SUB_I32_A32, ATOMIC_RMW_SUB_I32_A64 },
    { ATOMIC_RMW_SUB_I32_A32_S, ATOMIC_RMW_SUB_I32_A64_S },
    { ATOMIC_RMW_SUB_I64_A32, ATOMIC_RMW_SUB_I64_A64 },
    { ATOMIC_RMW_SUB_I64_A32_S, ATOMIC_RMW_SUB_I64_A64_S },
    { ATOMIC_RMW_XCHG_I32_A32, ATOMIC_RMW_XCHG_I32_A64 },
    { ATOMIC_RMW_XCHG_I32_A32_S, ATOMIC_RMW_XCHG_I32_A64_S },
    { ATOMIC_RMW_XCHG_I64_A32, ATOMIC_RMW_XCHG_I64_A64 },
    { ATOMIC_RMW_XCHG_I64_A32_S, ATOMIC_RMW_XCHG_I64_A64_S },
    { ATOMIC_RMW_XOR_I32_A32, ATOMIC_RMW_XOR_I32_A64 },
    { ATOMIC_RMW_XOR_I32_A32_S, ATOMIC_RMW_XOR_I32_A64_S },
    { ATOMIC_RMW_XOR_I64_A32, ATOMIC_RMW_XOR_I64_A64 },
    { ATOMIC_RMW_XOR_I64_A32_S, ATOMIC_RMW_XOR_I64_A64_S },
    { ATOMIC_STORE16_I32_A32, ATOMIC_STORE16_I32_A64 },
    { ATOMIC_STORE16_I32_A32_S, ATOMIC_STORE16_I32_A64_S },
    { ATOMIC_STORE16_I64_A32, ATOMIC_STORE16_I64_A64 },
    { ATOMIC_STORE16_I64_A32_S, ATOMIC_STORE16_I64_A64_S },
    { ATOMIC_STORE32_I64_A32, ATOMIC_STORE32_I64_A64 },
    { ATOMIC_STORE32_I64_A32_S, ATOMIC_STORE32_I64_A64_S },
    { ATOMIC_STORE8_I32_A32, ATOMIC_STORE8_I32_A64 },
    { ATOMIC_STORE8_I32_A32_S, ATOMIC_STORE8_I32_A64_S },
    { ATOMIC_STORE8_I64_A32, ATOMIC_STORE8_I64_A64 },
    { ATOMIC_STORE8_I64_A32_S, ATOMIC_STORE8_I64_A64_S },
    { ATOMIC_STORE_I32_A32, ATOMIC_STORE_I32_A64 },
    { ATOMIC_STORE_I32_A32_S, ATOMIC_STORE_I32_A64_S },
    { ATOMIC_STORE_I64_A32, ATOMIC_STORE_I64_A64 },
    { ATOMIC_STORE_I64_A32_S, ATOMIC_STORE_I64_A64_S },
    { LOAD16_S_I32_A32, LOAD16_S_I32_A64 },
    { LOAD16_S_I32_A32_S, LOAD16_S_I32_A64_S },
    { LOAD16_S_I64_A32, LOAD16_S_I64_A64 },
    { LOAD16_S_I64_A32_S, LOAD16_S_I64_A64_S },
    { LOAD16_U_I32_A32, LOAD16_U_I32_A64 },
    { LOAD16_U_I32_A32_S, LOAD16_U_I32_A64_S },
    { LOAD16_U_I64_A32, LOAD16_U_I64_A64 },
    { LOAD16_U_I64_A32_S, LOAD16_U_I64_A64_S },
    { LOAD32_S_I64_A32, LOAD32_S_I64_A64 },
    { LOAD32_S_I64_A32_S, LOAD32_S_I64_A64_S },
    { LOAD32_U_I64_A32, LOAD32_U_I64_A64 },
    { LOAD32_U_I64_A32_S, LOAD32_U_I64_A64_S },
    { LOAD8_S_I32_A32, LOAD8_S_I32_A64 },
    { LOAD8_S_I32_A32_S, LOAD8_S_I32_A64_S },
    { LOAD8_S_I64_A32, LOAD8_S_I64_A64 },
    { LOAD8_S_I64_A32_S, LOAD8_S_I64_A64_S },
    { LOAD8_U_I32_A32, LOAD8_U_I32_A64 },
    { LOAD8_U_I32_A32_S, LOAD8_U_I32_A64_S },
    { LOAD8_U_I64_A32, LOAD8_U_I64_A64 },
    { LOAD8_U_I64_A32_S, LOAD8_U_I64_A64_S },
    { LOAD_F16_F32_A32, LOAD_F16_F32_A64 },
    { LOAD_F16_F32_A32_S, LOAD_F16_F32_A64_S },
    { LOAD_F32_A32, LOAD_F32_A64 },
    { LOAD_F32_A32_S, LOAD_F32_A64_S },
    { LOAD_F64_A32, LOAD_F64_A64 },
    { LOAD_F64_A32_S, LOAD_F64_A64_S },
    { LOAD_I32_A32, LOAD_I32_A64 },
    { LOAD_I32_A32_S, LOAD_I32_A64_S },
    { LOAD_I64_A32, LOAD_I64_A64 },
    { LOAD_I64_A32_S, LOAD_I64_A64_S },
    { MEMORY_ATOMIC_NOTIFY_A32, MEMORY_ATOMIC_NOTIFY_A64 },
    { MEMORY_ATOMIC_NOTIFY_A32_S, MEMORY_ATOMIC_NOTIFY_A64_S },
    { MEMORY_ATOMIC_WAIT32_A32, MEMORY_ATOMIC_WAIT32_A64 },
    { MEMORY_ATOMIC_WAIT32_A32_S, MEMORY_ATOMIC_WAIT32_A64_S },
    { MEMORY_ATOMIC_WAIT64_A32, MEMORY_ATOMIC_WAIT64_A64 },
    { MEMORY_ATOMIC_WAIT64_A32_S, MEMORY_ATOMIC_WAIT64_A64_S },
    { STORE16_I32_A32, STORE16_I32_A64 },
    { STORE16_I32_A32_S, STORE16_I32_A64_S },
    { STORE16_I64_A32, STORE16_I64_A64 },
    { STORE16_I64_A32_S, STORE16_I64_A64_S },
    { STORE32_I64_A32, STORE32_I64_A64 },
    { STORE32_I64_A32_S, STORE32_I64_A64_S },
    { STORE8_I32_A32, STORE8_I32_A64 },
    { STORE8_I32_A32_S, STORE8_I32_A64_S },
    { STORE8_I64_A32, STORE8_I64_A64 },
    { STORE8_I64_A32_S, STORE8_I64_A64_S },
    { STORE_F16_F32_A32, STORE_F16_F32_A64 },
    { STORE_F16_F32_A32_S, STORE_F16_F32_A64_S },
    { STORE_F32_A32, STORE_F32_A64 },
    { STORE_F32_A32_S, STORE_F32_A64_S },
    { STORE_F64_A32, STORE_F64_A64 },
    { STORE_F64_A32_S, STORE_F64_A64_S },
    { STORE_I32_A32, STORE_I32_A64 },
    { STORE_I32_A32_S, STORE_I32_A64_S },
    { STORE_I64_A32, STORE_I64_A64 },
    { STORE_I64_A32_S, STORE_I64_A64_S },
  }; // End of Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 182;
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


} // namespace llvm_ks::WebAssembly

#endif // GET_INSTRMAP_INFO

