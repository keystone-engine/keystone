/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Subtarget Enumeration Source Fragment                                      *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_SUBTARGETINFO_ENUM
#undef GET_SUBTARGETINFO_ENUM

namespace llvm_ks {

namespace RISCV {

enum {
  Experimental = 0,
  Feature32Bit = 1,
  Feature64Bit = 2,
  FeatureExactAssembly = 3,
  FeatureForcedAtomics = 4,
  FeatureNoTrailingSeqCstFence = 5,
  FeaturePermissiveZalrsc = 6,
  FeatureRelax = 7,
  FeatureReserveX1 = 8,
  FeatureReserveX2 = 9,
  FeatureReserveX3 = 10,
  FeatureReserveX4 = 11,
  FeatureReserveX5 = 12,
  FeatureReserveX6 = 13,
  FeatureReserveX7 = 14,
  FeatureReserveX8 = 15,
  FeatureReserveX9 = 16,
  FeatureReserveX10 = 17,
  FeatureReserveX11 = 18,
  FeatureReserveX12 = 19,
  FeatureReserveX13 = 20,
  FeatureReserveX14 = 21,
  FeatureReserveX15 = 22,
  FeatureReserveX16 = 23,
  FeatureReserveX17 = 24,
  FeatureReserveX18 = 25,
  FeatureReserveX19 = 26,
  FeatureReserveX20 = 27,
  FeatureReserveX21 = 28,
  FeatureReserveX22 = 29,
  FeatureReserveX23 = 30,
  FeatureReserveX24 = 31,
  FeatureReserveX25 = 32,
  FeatureReserveX26 = 33,
  FeatureReserveX27 = 34,
  FeatureReserveX28 = 35,
  FeatureReserveX29 = 36,
  FeatureReserveX30 = 37,
  FeatureReserveX31 = 38,
  FeatureSaveRestore = 39,
  FeatureStdExtA = 40,
  FeatureStdExtB = 41,
  FeatureStdExtC = 42,
  FeatureStdExtD = 43,
  FeatureStdExtE = 44,
  FeatureStdExtF = 45,
  FeatureStdExtH = 46,
  FeatureStdExtI = 47,
  FeatureStdExtM = 48,
  FeatureStdExtP = 49,
  FeatureStdExtQ = 50,
  FeatureStdExtSdext = 51,
  FeatureStdExtSdtrig = 52,
  FeatureStdExtSha = 53,
  FeatureStdExtShcounterenw = 54,
  FeatureStdExtShgatpa = 55,
  FeatureStdExtShlcofideleg = 56,
  FeatureStdExtShtvala = 57,
  FeatureStdExtShvsatpa = 58,
  FeatureStdExtShvstvala = 59,
  FeatureStdExtShvstvecd = 60,
  FeatureStdExtSmaia = 61,
  FeatureStdExtSmcdeleg = 62,
  FeatureStdExtSmcntrpmf = 63,
  FeatureStdExtSmcsrind = 64,
  FeatureStdExtSmctr = 65,
  FeatureStdExtSmdbltrp = 66,
  FeatureStdExtSmepmp = 67,
  FeatureStdExtSmmpm = 68,
  FeatureStdExtSmnpm = 69,
  FeatureStdExtSmpmpmt = 70,
  FeatureStdExtSmrnmi = 71,
  FeatureStdExtSmstateen = 72,
  FeatureStdExtSsaia = 73,
  FeatureStdExtSsccfg = 74,
  FeatureStdExtSsccptr = 75,
  FeatureStdExtSscofpmf = 76,
  FeatureStdExtSscounterenw = 77,
  FeatureStdExtSscsrind = 78,
  FeatureStdExtSsctr = 79,
  FeatureStdExtSsdbltrp = 80,
  FeatureStdExtSsnpm = 81,
  FeatureStdExtSspm = 82,
  FeatureStdExtSsqosid = 83,
  FeatureStdExtSsstateen = 84,
  FeatureStdExtSsstrict = 85,
  FeatureStdExtSstc = 86,
  FeatureStdExtSstvala = 87,
  FeatureStdExtSstvecd = 88,
  FeatureStdExtSsu64xl = 89,
  FeatureStdExtSupm = 90,
  FeatureStdExtSvade = 91,
  FeatureStdExtSvadu = 92,
  FeatureStdExtSvbare = 93,
  FeatureStdExtSvinval = 94,
  FeatureStdExtSvnapot = 95,
  FeatureStdExtSvpbmt = 96,
  FeatureStdExtSvrsw60t59b = 97,
  FeatureStdExtSvukte = 98,
  FeatureStdExtSvvptc = 99,
  FeatureStdExtV = 100,
  FeatureStdExtY = 101,
  FeatureStdExtZa64rs = 102,
  FeatureStdExtZa128rs = 103,
  FeatureStdExtZaamo = 104,
  FeatureStdExtZabha = 105,
  FeatureStdExtZacas = 106,
  FeatureStdExtZalasr = 107,
  FeatureStdExtZalrsc = 108,
  FeatureStdExtZama16b = 109,
  FeatureStdExtZawrs = 110,
  FeatureStdExtZba = 111,
  FeatureStdExtZbb = 112,
  FeatureStdExtZbc = 113,
  FeatureStdExtZbkb = 114,
  FeatureStdExtZbkc = 115,
  FeatureStdExtZbkx = 116,
  FeatureStdExtZbs = 117,
  FeatureStdExtZca = 118,
  FeatureStdExtZcb = 119,
  FeatureStdExtZcd = 120,
  FeatureStdExtZce = 121,
  FeatureStdExtZcf = 122,
  FeatureStdExtZclsd = 123,
  FeatureStdExtZcmop = 124,
  FeatureStdExtZcmp = 125,
  FeatureStdExtZcmt = 126,
  FeatureStdExtZdinx = 127,
  FeatureStdExtZfa = 128,
  FeatureStdExtZfbfmin = 129,
  FeatureStdExtZfh = 130,
  FeatureStdExtZfhmin = 131,
  FeatureStdExtZfinx = 132,
  FeatureStdExtZhinx = 133,
  FeatureStdExtZhinxmin = 134,
  FeatureStdExtZibi = 135,
  FeatureStdExtZic64b = 136,
  FeatureStdExtZicbom = 137,
  FeatureStdExtZicbop = 138,
  FeatureStdExtZicboz = 139,
  FeatureStdExtZiccamoa = 140,
  FeatureStdExtZiccamoc = 141,
  FeatureStdExtZiccid = 142,
  FeatureStdExtZiccif = 143,
  FeatureStdExtZicclsm = 144,
  FeatureStdExtZiccrse = 145,
  FeatureStdExtZicfilp = 146,
  FeatureStdExtZicfiss = 147,
  FeatureStdExtZicntr = 148,
  FeatureStdExtZicond = 149,
  FeatureStdExtZicsr = 150,
  FeatureStdExtZifencei = 151,
  FeatureStdExtZihintntl = 152,
  FeatureStdExtZihintpause = 153,
  FeatureStdExtZihpm = 154,
  FeatureStdExtZilsd = 155,
  FeatureStdExtZimop = 156,
  FeatureStdExtZk = 157,
  FeatureStdExtZkn = 158,
  FeatureStdExtZknd = 159,
  FeatureStdExtZkne = 160,
  FeatureStdExtZknh = 161,
  FeatureStdExtZkr = 162,
  FeatureStdExtZks = 163,
  FeatureStdExtZksed = 164,
  FeatureStdExtZksh = 165,
  FeatureStdExtZkt = 166,
  FeatureStdExtZmmul = 167,
  FeatureStdExtZtso = 168,
  FeatureStdExtZvabd = 169,
  FeatureStdExtZvbb = 170,
  FeatureStdExtZvbc = 171,
  FeatureStdExtZvbc32e = 172,
  FeatureStdExtZvdot4a8i = 173,
  FeatureStdExtZve32f = 174,
  FeatureStdExtZve32x = 175,
  FeatureStdExtZve64d = 176,
  FeatureStdExtZve64f = 177,
  FeatureStdExtZve64x = 178,
  FeatureStdExtZvfbdota32f = 179,
  FeatureStdExtZvfbfa = 180,
  FeatureStdExtZvfbfmin = 181,
  FeatureStdExtZvfbfwma = 182,
  FeatureStdExtZvfh = 183,
  FeatureStdExtZvfhmin = 184,
  FeatureStdExtZvfofp8min = 185,
  FeatureStdExtZvfqwbdota8f = 186,
  FeatureStdExtZvfqwdota8f = 187,
  FeatureStdExtZvfwbdota16bf = 188,
  FeatureStdExtZvfwdota16bf = 189,
  FeatureStdExtZvkb = 190,
  FeatureStdExtZvkg = 191,
  FeatureStdExtZvkgs = 192,
  FeatureStdExtZvkn = 193,
  FeatureStdExtZvknc = 194,
  FeatureStdExtZvkned = 195,
  FeatureStdExtZvkng = 196,
  FeatureStdExtZvknha = 197,
  FeatureStdExtZvknhb = 198,
  FeatureStdExtZvks = 199,
  FeatureStdExtZvksc = 200,
  FeatureStdExtZvksed = 201,
  FeatureStdExtZvksg = 202,
  FeatureStdExtZvksh = 203,
  FeatureStdExtZvkt = 204,
  FeatureStdExtZvl32b = 205,
  FeatureStdExtZvl64b = 206,
  FeatureStdExtZvl128b = 207,
  FeatureStdExtZvl256b = 208,
  FeatureStdExtZvl512b = 209,
  FeatureStdExtZvl1024b = 210,
  FeatureStdExtZvl2048b = 211,
  FeatureStdExtZvl4096b = 212,
  FeatureStdExtZvl8192b = 213,
  FeatureStdExtZvl16384b = 214,
  FeatureStdExtZvl32768b = 215,
  FeatureStdExtZvl65536b = 216,
  FeatureStdExtZvqwbdota8i = 217,
  FeatureStdExtZvqwbdota16i = 218,
  FeatureStdExtZvqwdota8i = 219,
  FeatureStdExtZvqwdota16i = 220,
  FeatureStdExtZvvfmm = 221,
  FeatureStdExtZvvmm = 222,
  FeatureStdExtZvvmtls = 223,
  FeatureStdExtZvvmttls = 224,
  FeatureStdExtZvzip = 225,
  FeatureTaggedGlobals = 226,
  FeatureUnalignedScalarMem = 227,
  FeatureUnalignedVectorMem = 228,
  FeatureVendorXAIFET = 229,
  FeatureVendorXAndesBFHCvt = 230,
  FeatureVendorXAndesPerf = 231,
  FeatureVendorXAndesVBFHCvt = 232,
  FeatureVendorXAndesVDot = 233,
  FeatureVendorXAndesVPackFPH = 234,
  FeatureVendorXAndesVSIntH = 235,
  FeatureVendorXAndesVSIntLoad = 236,
  FeatureVendorXCValu = 237,
  FeatureVendorXCVbi = 238,
  FeatureVendorXCVbitmanip = 239,
  FeatureVendorXCVelw = 240,
  FeatureVendorXCVmac = 241,
  FeatureVendorXCVmem = 242,
  FeatureVendorXCVsimd = 243,
  FeatureVendorXCheriot = 244,
  FeatureVendorXMIPSCBOP = 245,
  FeatureVendorXMIPSCMov = 246,
  FeatureVendorXMIPSEXECTL = 247,
  FeatureVendorXMIPSLSP = 248,
  FeatureVendorXSMTVDot = 249,
  FeatureVendorXSMTVDotII = 250,
  FeatureVendorXSfcease = 251,
  FeatureVendorXSfmclic = 252,
  FeatureVendorXSfmm16t = 253,
  FeatureVendorXSfmm32a = 254,
  FeatureVendorXSfmm32a8f = 255,
  FeatureVendorXSfmm32a8i = 256,
  FeatureVendorXSfmm32a16f = 257,
  FeatureVendorXSfmm32a32f = 258,
  FeatureVendorXSfmm32t = 259,
  FeatureVendorXSfmm64a64f = 260,
  FeatureVendorXSfmm64t = 261,
  FeatureVendorXSfmm128t = 262,
  FeatureVendorXSfmmbase = 263,
  FeatureVendorXSfsclic = 264,
  FeatureVendorXSfvcp = 265,
  FeatureVendorXSfvfbfexp16e = 266,
  FeatureVendorXSfvfexp16e = 267,
  FeatureVendorXSfvfexp32e = 268,
  FeatureVendorXSfvfexpa = 269,
  FeatureVendorXSfvfexpa64e = 270,
  FeatureVendorXSfvfnrclipxfqf = 271,
  FeatureVendorXSfvfwmaccqqq = 272,
  FeatureVendorXSfvqmaccdod = 273,
  FeatureVendorXSfvqmaccqoq = 274,
  FeatureVendorXSiFivecdiscarddlone = 275,
  FeatureVendorXSiFivecflushdlone = 276,
  FeatureVendorXTHeadBa = 277,
  FeatureVendorXTHeadBb = 278,
  FeatureVendorXTHeadBs = 279,
  FeatureVendorXTHeadCmo = 280,
  FeatureVendorXTHeadCondMov = 281,
  FeatureVendorXTHeadFMemIdx = 282,
  FeatureVendorXTHeadMac = 283,
  FeatureVendorXTHeadMemIdx = 284,
  FeatureVendorXTHeadMemPair = 285,
  FeatureVendorXTHeadSync = 286,
  FeatureVendorXTHeadVdot = 287,
  FeatureVendorXVentanaCondOps = 288,
  FeatureVendorXqccmp = 289,
  FeatureVendorXqccmt = 290,
  FeatureVendorXqci = 291,
  FeatureVendorXqcia = 292,
  FeatureVendorXqciac = 293,
  FeatureVendorXqcibi = 294,
  FeatureVendorXqcibm = 295,
  FeatureVendorXqcicli = 296,
  FeatureVendorXqcicm = 297,
  FeatureVendorXqcics = 298,
  FeatureVendorXqcicsr = 299,
  FeatureVendorXqciint = 300,
  FeatureVendorXqciio = 301,
  FeatureVendorXqcilb = 302,
  FeatureVendorXqcili = 303,
  FeatureVendorXqcilia = 304,
  FeatureVendorXqcilo = 305,
  FeatureVendorXqcilsm = 306,
  FeatureVendorXqcisim = 307,
  FeatureVendorXqcisls = 308,
  FeatureVendorXqcisync = 309,
  FeatureVendorXwchc = 310,
  FeatureZilsdWordAlign = 311,
  RVA20S64 = 312,
  RVA20U64 = 313,
  RVA22S64 = 314,
  RVA22U64 = 315,
  RVA23S64 = 316,
  RVA23U64 = 317,
  RVB23S64 = 318,
  RVB23U64 = 319,
  RVI20U32 = 320,
  RVI20U64 = 321,
  RVM23U32 = 322,
  TuneADDILoadFusion = 323,
  TuneADDLoadFusion = 324,
  TuneAUIPCADDIFusion = 325,
  TuneAUIPCLoadFusion = 326,
  TuneAndes45 = 327,
  TuneBFExtFusion = 328,
  TuneConditionalCompressedMoveFusion = 329,
  TuneDLenFactor2 = 330,
  TuneDisableLatencySchedHeuristic = 331,
  TuneDisableMISchedLoadClustering = 332,
  TuneDisableMISchedStoreClustering = 333,
  TuneDisablePostMISchedLoadClustering = 334,
  TuneDisablePostMISchedStoreClustering = 335,
  TuneEnableSelectOptimize = 336,
  TuneEnableVsetvliSchedHeuristic = 337,
  TuneFusionAddMem = 338,
  TuneFusionLogicImmReg = 339,
  TuneFusionLogicRegImm = 340,
  TuneFusionLogicRegReg = 341,
  TuneFusionMulAdd = 342,
  TuneFusionShiftBitExtract = 343,
  TuneHasSingleElementVecFP64 = 344,
  TuneLDADDFusion = 345,
  TuneLUIADDIFusion = 346,
  TuneLUILoadFusion = 347,
  TuneMIPSP8700 = 348,
  TuneNLogNVRGather = 349,
  TuneNoDefaultUnroll = 350,
  TuneNoSinkSplatOperands = 351,
  TuneOptimizedNF2SegmentLoadStore = 352,
  TuneOptimizedNF3SegmentLoadStore = 353,
  TuneOptimizedNF4SegmentLoadStore = 354,
  TuneOptimizedNF5SegmentLoadStore = 355,
  TuneOptimizedNF6SegmentLoadStore = 356,
  TuneOptimizedNF7SegmentLoadStore = 357,
  TuneOptimizedNF8SegmentLoadStore = 358,
  TuneOptimizedZeroStrideLoad = 359,
  TunePostRAScheduler = 360,
  TunePredictableSelectIsExpensive = 361,
  TunePreferAscendingLoadStore = 362,
  TunePreferVsetvliOverReadVLENB = 363,
  TunePreferWInst = 364,
  TuneQCELILoadStoreFusion = 365,
  TuneSHXADDLoadFusion = 366,
  TuneShiftedZExtWFusion = 367,
  TuneShortForwardBranchIALU = 368,
  TuneShortForwardBranchILoad = 369,
  TuneShortForwardBranchIMinMax = 370,
  TuneShortForwardBranchIMul = 371,
  TuneShortForwardBranchImm = 372,
  TuneSiFive7 = 373,
  TuneVLDependentLatency = 374,
  TuneVXRMPipelineFlush = 375,
  TuneVentanaVeyron = 376,
  TuneZExtHFusion = 377,
  TuneZExtWFusion = 378,
  NumSubtargetFeatures = 379
};

} // namespace RISCV

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MACRO

GET_SUBTARGETINFO_MACRO(AllowTaggedGlobals, false, allowTaggedGlobals)
GET_SUBTARGETINFO_MACRO(AllowZilsdWordAlign, false, allowZilsdWordAlign)
GET_SUBTARGETINFO_MACRO(DLenFactor2, false, dLenFactor2)
GET_SUBTARGETINFO_MACRO(DisableLatencySchedHeuristic, false, disableLatencySchedHeuristic)
GET_SUBTARGETINFO_MACRO(EnableDefaultUnroll, true, enableDefaultUnroll)
GET_SUBTARGETINFO_MACRO(EnableExactAssembly, false, enableExactAssembly)
GET_SUBTARGETINFO_MACRO(EnableLinkerRelax, false, enableLinkerRelax)
GET_SUBTARGETINFO_MACRO(EnableMISchedLoadClustering, true, enableMISchedLoadClustering)
GET_SUBTARGETINFO_MACRO(EnableMISchedStoreClustering, true, enableMISchedStoreClustering)
GET_SUBTARGETINFO_MACRO(EnablePostMISchedLoadClustering, true, enablePostMISchedLoadClustering)
GET_SUBTARGETINFO_MACRO(EnablePostMISchedStoreClustering, true, enablePostMISchedStoreClustering)
GET_SUBTARGETINFO_MACRO(EnableSaveRestore, false, enableSaveRestore)
GET_SUBTARGETINFO_MACRO(EnableSelectOptimize, false, enableSelectOptimize)
GET_SUBTARGETINFO_MACRO(EnableTrailingSeqCstFence, true, enableTrailingSeqCstFence)
GET_SUBTARGETINFO_MACRO(EnableUnalignedScalarMem, false, enableUnalignedScalarMem)
GET_SUBTARGETINFO_MACRO(EnableUnalignedVectorMem, false, enableUnalignedVectorMem)
GET_SUBTARGETINFO_MACRO(EnableVsetvliSchedHeuristic, false, enableVsetvliSchedHeuristic)
GET_SUBTARGETINFO_MACRO(HasADDILoadFusion, false, hasADDILoadFusion)
GET_SUBTARGETINFO_MACRO(HasADDLoadFusion, false, hasADDLoadFusion)
GET_SUBTARGETINFO_MACRO(HasAUIPCADDIFusion, false, hasAUIPCADDIFusion)
GET_SUBTARGETINFO_MACRO(HasAUIPCLoadFusion, false, hasAUIPCLoadFusion)
GET_SUBTARGETINFO_MACRO(HasBFExtFusion, false, hasBFExtFusion)
GET_SUBTARGETINFO_MACRO(HasConditionalCompressedMoveFusion, false, hasConditionalCompressedMoveFusion)
GET_SUBTARGETINFO_MACRO(HasExperimental, false, hasExperimental)
GET_SUBTARGETINFO_MACRO(HasForcedAtomics, false, hasForcedAtomics)
GET_SUBTARGETINFO_MACRO(HasFusionAddMem, false, hasFusionAddMem)
GET_SUBTARGETINFO_MACRO(HasFusionLogicImmReg, false, hasFusionLogicImmReg)
GET_SUBTARGETINFO_MACRO(HasFusionLogicRegImm, false, hasFusionLogicRegImm)
GET_SUBTARGETINFO_MACRO(HasFusionLogicRegReg, false, hasFusionLogicRegReg)
GET_SUBTARGETINFO_MACRO(HasFusionMulAdd, false, hasFusionMulAdd)
GET_SUBTARGETINFO_MACRO(HasFusionShiftBitExtract, false, hasFusionShiftBitExtract)
GET_SUBTARGETINFO_MACRO(HasLDADDFusion, false, hasLDADDFusion)
GET_SUBTARGETINFO_MACRO(HasLUIADDIFusion, false, hasLUIADDIFusion)
GET_SUBTARGETINFO_MACRO(HasLUILoadFusion, false, hasLUILoadFusion)
GET_SUBTARGETINFO_MACRO(HasOptimizedNF2SegmentLoadStore, false, hasOptimizedNF2SegmentLoadStore)
GET_SUBTARGETINFO_MACRO(HasOptimizedNF3SegmentLoadStore, false, hasOptimizedNF3SegmentLoadStore)
GET_SUBTARGETINFO_MACRO(HasOptimizedNF4SegmentLoadStore, false, hasOptimizedNF4SegmentLoadStore)
GET_SUBTARGETINFO_MACRO(HasOptimizedNF5SegmentLoadStore, false, hasOptimizedNF5SegmentLoadStore)
GET_SUBTARGETINFO_MACRO(HasOptimizedNF6SegmentLoadStore, false, hasOptimizedNF6SegmentLoadStore)
GET_SUBTARGETINFO_MACRO(HasOptimizedNF7SegmentLoadStore, false, hasOptimizedNF7SegmentLoadStore)
GET_SUBTARGETINFO_MACRO(HasOptimizedNF8SegmentLoadStore, false, hasOptimizedNF8SegmentLoadStore)
GET_SUBTARGETINFO_MACRO(HasOptimizedZeroStrideLoad, false, hasOptimizedZeroStrideLoad)
GET_SUBTARGETINFO_MACRO(HasPermissiveZalrsc, false, hasPermissiveZalrsc)
GET_SUBTARGETINFO_MACRO(HasQCELILoadStoreFusion, false, hasQCELILoadStoreFusion)
GET_SUBTARGETINFO_MACRO(HasSHXADDLoadFusion, false, hasSHXADDLoadFusion)
GET_SUBTARGETINFO_MACRO(HasShiftedZExtWFusion, false, hasShiftedZExtWFusion)
GET_SUBTARGETINFO_MACRO(HasShortForwardBranchIALU, false, hasShortForwardBranchIALU)
GET_SUBTARGETINFO_MACRO(HasShortForwardBranchILoad, false, hasShortForwardBranchILoad)
GET_SUBTARGETINFO_MACRO(HasShortForwardBranchIMinMax, false, hasShortForwardBranchIMinMax)
GET_SUBTARGETINFO_MACRO(HasShortForwardBranchIMul, false, hasShortForwardBranchIMul)
GET_SUBTARGETINFO_MACRO(HasShortForwardBranchImm, false, hasShortForwardBranchImm)
GET_SUBTARGETINFO_MACRO(HasSingleElementVectorFP64, false, hasSingleElementVectorFP64)
GET_SUBTARGETINFO_MACRO(HasStdExtA, false, hasStdExtA)
GET_SUBTARGETINFO_MACRO(HasStdExtB, false, hasStdExtB)
GET_SUBTARGETINFO_MACRO(HasStdExtC, false, hasStdExtC)
GET_SUBTARGETINFO_MACRO(HasStdExtD, false, hasStdExtD)
GET_SUBTARGETINFO_MACRO(HasStdExtE, false, hasStdExtE)
GET_SUBTARGETINFO_MACRO(HasStdExtF, false, hasStdExtF)
GET_SUBTARGETINFO_MACRO(HasStdExtH, false, hasStdExtH)
GET_SUBTARGETINFO_MACRO(HasStdExtI, false, hasStdExtI)
GET_SUBTARGETINFO_MACRO(HasStdExtM, false, hasStdExtM)
GET_SUBTARGETINFO_MACRO(HasStdExtP, false, hasStdExtP)
GET_SUBTARGETINFO_MACRO(HasStdExtQ, false, hasStdExtQ)
GET_SUBTARGETINFO_MACRO(HasStdExtSdext, false, hasStdExtSdext)
GET_SUBTARGETINFO_MACRO(HasStdExtSdtrig, false, hasStdExtSdtrig)
GET_SUBTARGETINFO_MACRO(HasStdExtSha, false, hasStdExtSha)
GET_SUBTARGETINFO_MACRO(HasStdExtShcounterenw, false, hasStdExtShcounterenw)
GET_SUBTARGETINFO_MACRO(HasStdExtShgatpa, false, hasStdExtShgatpa)
GET_SUBTARGETINFO_MACRO(HasStdExtShlcofideleg, false, hasStdExtShlcofideleg)
GET_SUBTARGETINFO_MACRO(HasStdExtShtvala, false, hasStdExtShtvala)
GET_SUBTARGETINFO_MACRO(HasStdExtShvsatpa, false, hasStdExtShvsatpa)
GET_SUBTARGETINFO_MACRO(HasStdExtShvstvala, false, hasStdExtShvstvala)
GET_SUBTARGETINFO_MACRO(HasStdExtShvstvecd, false, hasStdExtShvstvecd)
GET_SUBTARGETINFO_MACRO(HasStdExtSmaia, false, hasStdExtSmaia)
GET_SUBTARGETINFO_MACRO(HasStdExtSmcdeleg, false, hasStdExtSmcdeleg)
GET_SUBTARGETINFO_MACRO(HasStdExtSmcntrpmf, false, hasStdExtSmcntrpmf)
GET_SUBTARGETINFO_MACRO(HasStdExtSmcsrind, false, hasStdExtSmcsrind)
GET_SUBTARGETINFO_MACRO(HasStdExtSmctr, false, hasStdExtSmctr)
GET_SUBTARGETINFO_MACRO(HasStdExtSmdbltrp, false, hasStdExtSmdbltrp)
GET_SUBTARGETINFO_MACRO(HasStdExtSmepmp, false, hasStdExtSmepmp)
GET_SUBTARGETINFO_MACRO(HasStdExtSmmpm, false, hasStdExtSmmpm)
GET_SUBTARGETINFO_MACRO(HasStdExtSmnpm, false, hasStdExtSmnpm)
GET_SUBTARGETINFO_MACRO(HasStdExtSmpmpmt, false, hasStdExtSmpmpmt)
GET_SUBTARGETINFO_MACRO(HasStdExtSmrnmi, false, hasStdExtSmrnmi)
GET_SUBTARGETINFO_MACRO(HasStdExtSmstateen, false, hasStdExtSmstateen)
GET_SUBTARGETINFO_MACRO(HasStdExtSsaia, false, hasStdExtSsaia)
GET_SUBTARGETINFO_MACRO(HasStdExtSsccfg, false, hasStdExtSsccfg)
GET_SUBTARGETINFO_MACRO(HasStdExtSsccptr, false, hasStdExtSsccptr)
GET_SUBTARGETINFO_MACRO(HasStdExtSscofpmf, false, hasStdExtSscofpmf)
GET_SUBTARGETINFO_MACRO(HasStdExtSscounterenw, false, hasStdExtSscounterenw)
GET_SUBTARGETINFO_MACRO(HasStdExtSscsrind, false, hasStdExtSscsrind)
GET_SUBTARGETINFO_MACRO(HasStdExtSsctr, false, hasStdExtSsctr)
GET_SUBTARGETINFO_MACRO(HasStdExtSsdbltrp, false, hasStdExtSsdbltrp)
GET_SUBTARGETINFO_MACRO(HasStdExtSsnpm, false, hasStdExtSsnpm)
GET_SUBTARGETINFO_MACRO(HasStdExtSspm, false, hasStdExtSspm)
GET_SUBTARGETINFO_MACRO(HasStdExtSsqosid, false, hasStdExtSsqosid)
GET_SUBTARGETINFO_MACRO(HasStdExtSsstateen, false, hasStdExtSsstateen)
GET_SUBTARGETINFO_MACRO(HasStdExtSsstrict, false, hasStdExtSsstrict)
GET_SUBTARGETINFO_MACRO(HasStdExtSstc, false, hasStdExtSstc)
GET_SUBTARGETINFO_MACRO(HasStdExtSstvala, false, hasStdExtSstvala)
GET_SUBTARGETINFO_MACRO(HasStdExtSstvecd, false, hasStdExtSstvecd)
GET_SUBTARGETINFO_MACRO(HasStdExtSsu64xl, false, hasStdExtSsu64xl)
GET_SUBTARGETINFO_MACRO(HasStdExtSupm, false, hasStdExtSupm)
GET_SUBTARGETINFO_MACRO(HasStdExtSvade, false, hasStdExtSvade)
GET_SUBTARGETINFO_MACRO(HasStdExtSvadu, false, hasStdExtSvadu)
GET_SUBTARGETINFO_MACRO(HasStdExtSvbare, false, hasStdExtSvbare)
GET_SUBTARGETINFO_MACRO(HasStdExtSvinval, false, hasStdExtSvinval)
GET_SUBTARGETINFO_MACRO(HasStdExtSvnapot, false, hasStdExtSvnapot)
GET_SUBTARGETINFO_MACRO(HasStdExtSvpbmt, false, hasStdExtSvpbmt)
GET_SUBTARGETINFO_MACRO(HasStdExtSvrsw60t59b, false, hasStdExtSvrsw60t59b)
GET_SUBTARGETINFO_MACRO(HasStdExtSvukte, false, hasStdExtSvukte)
GET_SUBTARGETINFO_MACRO(HasStdExtSvvptc, false, hasStdExtSvvptc)
GET_SUBTARGETINFO_MACRO(HasStdExtV, false, hasStdExtV)
GET_SUBTARGETINFO_MACRO(HasStdExtY, false, hasStdExtY)
GET_SUBTARGETINFO_MACRO(HasStdExtZa128rs, false, hasStdExtZa128rs)
GET_SUBTARGETINFO_MACRO(HasStdExtZa64rs, false, hasStdExtZa64rs)
GET_SUBTARGETINFO_MACRO(HasStdExtZaamo, false, hasStdExtZaamo)
GET_SUBTARGETINFO_MACRO(HasStdExtZabha, false, hasStdExtZabha)
GET_SUBTARGETINFO_MACRO(HasStdExtZacas, false, hasStdExtZacas)
GET_SUBTARGETINFO_MACRO(HasStdExtZalasr, false, hasStdExtZalasr)
GET_SUBTARGETINFO_MACRO(HasStdExtZalrsc, false, hasStdExtZalrsc)
GET_SUBTARGETINFO_MACRO(HasStdExtZama16b, false, hasStdExtZama16b)
GET_SUBTARGETINFO_MACRO(HasStdExtZawrs, false, hasStdExtZawrs)
GET_SUBTARGETINFO_MACRO(HasStdExtZba, false, hasStdExtZba)
GET_SUBTARGETINFO_MACRO(HasStdExtZbb, false, hasStdExtZbb)
GET_SUBTARGETINFO_MACRO(HasStdExtZbc, false, hasStdExtZbc)
GET_SUBTARGETINFO_MACRO(HasStdExtZbkb, false, hasStdExtZbkb)
GET_SUBTARGETINFO_MACRO(HasStdExtZbkc, false, hasStdExtZbkc)
GET_SUBTARGETINFO_MACRO(HasStdExtZbkx, false, hasStdExtZbkx)
GET_SUBTARGETINFO_MACRO(HasStdExtZbs, false, hasStdExtZbs)
GET_SUBTARGETINFO_MACRO(HasStdExtZca, false, hasStdExtZca)
GET_SUBTARGETINFO_MACRO(HasStdExtZcb, false, hasStdExtZcb)
GET_SUBTARGETINFO_MACRO(HasStdExtZcd, false, hasStdExtZcd)
GET_SUBTARGETINFO_MACRO(HasStdExtZce, false, hasStdExtZce)
GET_SUBTARGETINFO_MACRO(HasStdExtZcf, false, hasStdExtZcf)
GET_SUBTARGETINFO_MACRO(HasStdExtZclsd, false, hasStdExtZclsd)
GET_SUBTARGETINFO_MACRO(HasStdExtZcmop, false, hasStdExtZcmop)
GET_SUBTARGETINFO_MACRO(HasStdExtZcmp, false, hasStdExtZcmp)
GET_SUBTARGETINFO_MACRO(HasStdExtZcmt, false, hasStdExtZcmt)
GET_SUBTARGETINFO_MACRO(HasStdExtZdinx, false, hasStdExtZdinx)
GET_SUBTARGETINFO_MACRO(HasStdExtZfa, false, hasStdExtZfa)
GET_SUBTARGETINFO_MACRO(HasStdExtZfbfmin, false, hasStdExtZfbfmin)
GET_SUBTARGETINFO_MACRO(HasStdExtZfh, false, hasStdExtZfh)
GET_SUBTARGETINFO_MACRO(HasStdExtZfhmin, false, hasStdExtZfhmin)
GET_SUBTARGETINFO_MACRO(HasStdExtZfinx, false, hasStdExtZfinx)
GET_SUBTARGETINFO_MACRO(HasStdExtZhinx, false, hasStdExtZhinx)
GET_SUBTARGETINFO_MACRO(HasStdExtZhinxmin, false, hasStdExtZhinxmin)
GET_SUBTARGETINFO_MACRO(HasStdExtZibi, false, hasStdExtZibi)
GET_SUBTARGETINFO_MACRO(HasStdExtZic64b, false, hasStdExtZic64b)
GET_SUBTARGETINFO_MACRO(HasStdExtZicbom, false, hasStdExtZicbom)
GET_SUBTARGETINFO_MACRO(HasStdExtZicbop, false, hasStdExtZicbop)
GET_SUBTARGETINFO_MACRO(HasStdExtZicboz, false, hasStdExtZicboz)
GET_SUBTARGETINFO_MACRO(HasStdExtZiccamoa, false, hasStdExtZiccamoa)
GET_SUBTARGETINFO_MACRO(HasStdExtZiccamoc, false, hasStdExtZiccamoc)
GET_SUBTARGETINFO_MACRO(HasStdExtZiccid, false, hasStdExtZiccid)
GET_SUBTARGETINFO_MACRO(HasStdExtZiccif, false, hasStdExtZiccif)
GET_SUBTARGETINFO_MACRO(HasStdExtZicclsm, false, hasStdExtZicclsm)
GET_SUBTARGETINFO_MACRO(HasStdExtZiccrse, false, hasStdExtZiccrse)
GET_SUBTARGETINFO_MACRO(HasStdExtZicfilp, false, hasStdExtZicfilp)
GET_SUBTARGETINFO_MACRO(HasStdExtZicfiss, false, hasStdExtZicfiss)
GET_SUBTARGETINFO_MACRO(HasStdExtZicntr, false, hasStdExtZicntr)
GET_SUBTARGETINFO_MACRO(HasStdExtZicond, false, hasStdExtZicond)
GET_SUBTARGETINFO_MACRO(HasStdExtZicsr, false, hasStdExtZicsr)
GET_SUBTARGETINFO_MACRO(HasStdExtZifencei, false, hasStdExtZifencei)
GET_SUBTARGETINFO_MACRO(HasStdExtZihintntl, false, hasStdExtZihintntl)
GET_SUBTARGETINFO_MACRO(HasStdExtZihintpause, false, hasStdExtZihintpause)
GET_SUBTARGETINFO_MACRO(HasStdExtZihpm, false, hasStdExtZihpm)
GET_SUBTARGETINFO_MACRO(HasStdExtZilsd, false, hasStdExtZilsd)
GET_SUBTARGETINFO_MACRO(HasStdExtZimop, false, hasStdExtZimop)
GET_SUBTARGETINFO_MACRO(HasStdExtZk, false, hasStdExtZk)
GET_SUBTARGETINFO_MACRO(HasStdExtZkn, false, hasStdExtZkn)
GET_SUBTARGETINFO_MACRO(HasStdExtZknd, false, hasStdExtZknd)
GET_SUBTARGETINFO_MACRO(HasStdExtZkne, false, hasStdExtZkne)
GET_SUBTARGETINFO_MACRO(HasStdExtZknh, false, hasStdExtZknh)
GET_SUBTARGETINFO_MACRO(HasStdExtZkr, false, hasStdExtZkr)
GET_SUBTARGETINFO_MACRO(HasStdExtZks, false, hasStdExtZks)
GET_SUBTARGETINFO_MACRO(HasStdExtZksed, false, hasStdExtZksed)
GET_SUBTARGETINFO_MACRO(HasStdExtZksh, false, hasStdExtZksh)
GET_SUBTARGETINFO_MACRO(HasStdExtZkt, false, hasStdExtZkt)
GET_SUBTARGETINFO_MACRO(HasStdExtZmmul, false, hasStdExtZmmul)
GET_SUBTARGETINFO_MACRO(HasStdExtZtso, false, hasStdExtZtso)
GET_SUBTARGETINFO_MACRO(HasStdExtZvabd, false, hasStdExtZvabd)
GET_SUBTARGETINFO_MACRO(HasStdExtZvbb, false, hasStdExtZvbb)
GET_SUBTARGETINFO_MACRO(HasStdExtZvbc, false, hasStdExtZvbc)
GET_SUBTARGETINFO_MACRO(HasStdExtZvbc32e, false, hasStdExtZvbc32e)
GET_SUBTARGETINFO_MACRO(HasStdExtZvdot4a8i, false, hasStdExtZvdot4a8i)
GET_SUBTARGETINFO_MACRO(HasStdExtZve32f, false, hasStdExtZve32f)
GET_SUBTARGETINFO_MACRO(HasStdExtZve32x, false, hasStdExtZve32x)
GET_SUBTARGETINFO_MACRO(HasStdExtZve64d, false, hasStdExtZve64d)
GET_SUBTARGETINFO_MACRO(HasStdExtZve64f, false, hasStdExtZve64f)
GET_SUBTARGETINFO_MACRO(HasStdExtZve64x, false, hasStdExtZve64x)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfbdota32f, false, hasStdExtZvfbdota32f)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfbfa, false, hasStdExtZvfbfa)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfbfmin, false, hasStdExtZvfbfmin)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfbfwma, false, hasStdExtZvfbfwma)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfh, false, hasStdExtZvfh)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfhmin, false, hasStdExtZvfhmin)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfofp8min, false, hasStdExtZvfofp8min)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfqwbdota8f, false, hasStdExtZvfqwbdota8f)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfqwdota8f, false, hasStdExtZvfqwdota8f)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfwbdota16bf, false, hasStdExtZvfwbdota16bf)
GET_SUBTARGETINFO_MACRO(HasStdExtZvfwdota16bf, false, hasStdExtZvfwdota16bf)
GET_SUBTARGETINFO_MACRO(HasStdExtZvkb, false, hasStdExtZvkb)
GET_SUBTARGETINFO_MACRO(HasStdExtZvkg, false, hasStdExtZvkg)
GET_SUBTARGETINFO_MACRO(HasStdExtZvkgs, false, hasStdExtZvkgs)
GET_SUBTARGETINFO_MACRO(HasStdExtZvkn, false, hasStdExtZvkn)
GET_SUBTARGETINFO_MACRO(HasStdExtZvknc, false, hasStdExtZvknc)
GET_SUBTARGETINFO_MACRO(HasStdExtZvkned, false, hasStdExtZvkned)
GET_SUBTARGETINFO_MACRO(HasStdExtZvkng, false, hasStdExtZvkng)
GET_SUBTARGETINFO_MACRO(HasStdExtZvknha, false, hasStdExtZvknha)
GET_SUBTARGETINFO_MACRO(HasStdExtZvknhb, false, hasStdExtZvknhb)
GET_SUBTARGETINFO_MACRO(HasStdExtZvks, false, hasStdExtZvks)
GET_SUBTARGETINFO_MACRO(HasStdExtZvksc, false, hasStdExtZvksc)
GET_SUBTARGETINFO_MACRO(HasStdExtZvksed, false, hasStdExtZvksed)
GET_SUBTARGETINFO_MACRO(HasStdExtZvksg, false, hasStdExtZvksg)
GET_SUBTARGETINFO_MACRO(HasStdExtZvksh, false, hasStdExtZvksh)
GET_SUBTARGETINFO_MACRO(HasStdExtZvkt, false, hasStdExtZvkt)
GET_SUBTARGETINFO_MACRO(HasStdExtZvqwbdota16i, false, hasStdExtZvqwbdota16i)
GET_SUBTARGETINFO_MACRO(HasStdExtZvqwbdota8i, false, hasStdExtZvqwbdota8i)
GET_SUBTARGETINFO_MACRO(HasStdExtZvqwdota16i, false, hasStdExtZvqwdota16i)
GET_SUBTARGETINFO_MACRO(HasStdExtZvqwdota8i, false, hasStdExtZvqwdota8i)
GET_SUBTARGETINFO_MACRO(HasStdExtZvvfmm, false, hasStdExtZvvfmm)
GET_SUBTARGETINFO_MACRO(HasStdExtZvvmm, false, hasStdExtZvvmm)
GET_SUBTARGETINFO_MACRO(HasStdExtZvvmtls, false, hasStdExtZvvmtls)
GET_SUBTARGETINFO_MACRO(HasStdExtZvvmttls, false, hasStdExtZvvmttls)
GET_SUBTARGETINFO_MACRO(HasStdExtZvzip, false, hasStdExtZvzip)
GET_SUBTARGETINFO_MACRO(HasVLDependentLatency, false, hasVLDependentLatency)
GET_SUBTARGETINFO_MACRO(HasVXRMPipelineFlush, false, hasVXRMPipelineFlush)
GET_SUBTARGETINFO_MACRO(HasVendorXAIFET, false, hasVendorXAIFET)
GET_SUBTARGETINFO_MACRO(HasVendorXAndesBFHCvt, false, hasVendorXAndesBFHCvt)
GET_SUBTARGETINFO_MACRO(HasVendorXAndesPerf, false, hasVendorXAndesPerf)
GET_SUBTARGETINFO_MACRO(HasVendorXAndesVBFHCvt, false, hasVendorXAndesVBFHCvt)
GET_SUBTARGETINFO_MACRO(HasVendorXAndesVDot, false, hasVendorXAndesVDot)
GET_SUBTARGETINFO_MACRO(HasVendorXAndesVPackFPH, false, hasVendorXAndesVPackFPH)
GET_SUBTARGETINFO_MACRO(HasVendorXAndesVSIntH, false, hasVendorXAndesVSIntH)
GET_SUBTARGETINFO_MACRO(HasVendorXAndesVSIntLoad, false, hasVendorXAndesVSIntLoad)
GET_SUBTARGETINFO_MACRO(HasVendorXCValu, false, hasVendorXCValu)
GET_SUBTARGETINFO_MACRO(HasVendorXCVbi, false, hasVendorXCVbi)
GET_SUBTARGETINFO_MACRO(HasVendorXCVbitmanip, false, hasVendorXCVbitmanip)
GET_SUBTARGETINFO_MACRO(HasVendorXCVelw, false, hasVendorXCVelw)
GET_SUBTARGETINFO_MACRO(HasVendorXCVmac, false, hasVendorXCVmac)
GET_SUBTARGETINFO_MACRO(HasVendorXCVmem, false, hasVendorXCVmem)
GET_SUBTARGETINFO_MACRO(HasVendorXCVsimd, false, hasVendorXCVsimd)
GET_SUBTARGETINFO_MACRO(HasVendorXCheriot, false, hasVendorXCheriot)
GET_SUBTARGETINFO_MACRO(HasVendorXMIPSCBOP, false, hasVendorXMIPSCBOP)
GET_SUBTARGETINFO_MACRO(HasVendorXMIPSCMov, false, hasVendorXMIPSCMov)
GET_SUBTARGETINFO_MACRO(HasVendorXMIPSEXECTL, false, hasVendorXMIPSEXECTL)
GET_SUBTARGETINFO_MACRO(HasVendorXMIPSLSP, false, hasVendorXMIPSLSP)
GET_SUBTARGETINFO_MACRO(HasVendorXSMTVDot, false, hasVendorXSMTVDot)
GET_SUBTARGETINFO_MACRO(HasVendorXSMTVDotII, false, hasVendorXSMTVDotII)
GET_SUBTARGETINFO_MACRO(HasVendorXSfcease, false, hasVendorXSfcease)
GET_SUBTARGETINFO_MACRO(HasVendorXSfmclic, false, hasVendorXSfmclic)
GET_SUBTARGETINFO_MACRO(HasVendorXSfmm32a, false, hasVendorXSfmm32a)
GET_SUBTARGETINFO_MACRO(HasVendorXSfmm32a16f, false, hasVendorXSfmm32a16f)
GET_SUBTARGETINFO_MACRO(HasVendorXSfmm32a32f, false, hasVendorXSfmm32a32f)
GET_SUBTARGETINFO_MACRO(HasVendorXSfmm32a8f, false, hasVendorXSfmm32a8f)
GET_SUBTARGETINFO_MACRO(HasVendorXSfmm32a8i, false, hasVendorXSfmm32a8i)
GET_SUBTARGETINFO_MACRO(HasVendorXSfmm64a64f, false, hasVendorXSfmm64a64f)
GET_SUBTARGETINFO_MACRO(HasVendorXSfmmbase, false, hasVendorXSfmmbase)
GET_SUBTARGETINFO_MACRO(HasVendorXSfsclic, false, hasVendorXSfsclic)
GET_SUBTARGETINFO_MACRO(HasVendorXSfvcp, false, hasVendorXSfvcp)
GET_SUBTARGETINFO_MACRO(HasVendorXSfvfbfexp16e, false, hasVendorXSfvfbfexp16e)
GET_SUBTARGETINFO_MACRO(HasVendorXSfvfexp16e, false, hasVendorXSfvfexp16e)
GET_SUBTARGETINFO_MACRO(HasVendorXSfvfexp32e, false, hasVendorXSfvfexp32e)
GET_SUBTARGETINFO_MACRO(HasVendorXSfvfexpa, false, hasVendorXSfvfexpa)
GET_SUBTARGETINFO_MACRO(HasVendorXSfvfexpa64e, false, hasVendorXSfvfexpa64e)
GET_SUBTARGETINFO_MACRO(HasVendorXSfvfnrclipxfqf, false, hasVendorXSfvfnrclipxfqf)
GET_SUBTARGETINFO_MACRO(HasVendorXSfvfwmaccqqq, false, hasVendorXSfvfwmaccqqq)
GET_SUBTARGETINFO_MACRO(HasVendorXSfvqmaccdod, false, hasVendorXSfvqmaccdod)
GET_SUBTARGETINFO_MACRO(HasVendorXSfvqmaccqoq, false, hasVendorXSfvqmaccqoq)
GET_SUBTARGETINFO_MACRO(HasVendorXSiFivecdiscarddlone, false, hasVendorXSiFivecdiscarddlone)
GET_SUBTARGETINFO_MACRO(HasVendorXSiFivecflushdlone, false, hasVendorXSiFivecflushdlone)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadBa, false, hasVendorXTHeadBa)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadBb, false, hasVendorXTHeadBb)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadBs, false, hasVendorXTHeadBs)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadCmo, false, hasVendorXTHeadCmo)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadCondMov, false, hasVendorXTHeadCondMov)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadFMemIdx, false, hasVendorXTHeadFMemIdx)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadMac, false, hasVendorXTHeadMac)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadMemIdx, false, hasVendorXTHeadMemIdx)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadMemPair, false, hasVendorXTHeadMemPair)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadSync, false, hasVendorXTHeadSync)
GET_SUBTARGETINFO_MACRO(HasVendorXTHeadVdot, false, hasVendorXTHeadVdot)
GET_SUBTARGETINFO_MACRO(HasVendorXVentanaCondOps, false, hasVendorXVentanaCondOps)
GET_SUBTARGETINFO_MACRO(HasVendorXqccmp, false, hasVendorXqccmp)
GET_SUBTARGETINFO_MACRO(HasVendorXqccmt, false, hasVendorXqccmt)
GET_SUBTARGETINFO_MACRO(HasVendorXqci, false, hasVendorXqci)
GET_SUBTARGETINFO_MACRO(HasVendorXqcia, false, hasVendorXqcia)
GET_SUBTARGETINFO_MACRO(HasVendorXqciac, false, hasVendorXqciac)
GET_SUBTARGETINFO_MACRO(HasVendorXqcibi, false, hasVendorXqcibi)
GET_SUBTARGETINFO_MACRO(HasVendorXqcibm, false, hasVendorXqcibm)
GET_SUBTARGETINFO_MACRO(HasVendorXqcicli, false, hasVendorXqcicli)
GET_SUBTARGETINFO_MACRO(HasVendorXqcicm, false, hasVendorXqcicm)
GET_SUBTARGETINFO_MACRO(HasVendorXqcics, false, hasVendorXqcics)
GET_SUBTARGETINFO_MACRO(HasVendorXqcicsr, false, hasVendorXqcicsr)
GET_SUBTARGETINFO_MACRO(HasVendorXqciint, false, hasVendorXqciint)
GET_SUBTARGETINFO_MACRO(HasVendorXqciio, false, hasVendorXqciio)
GET_SUBTARGETINFO_MACRO(HasVendorXqcilb, false, hasVendorXqcilb)
GET_SUBTARGETINFO_MACRO(HasVendorXqcili, false, hasVendorXqcili)
GET_SUBTARGETINFO_MACRO(HasVendorXqcilia, false, hasVendorXqcilia)
GET_SUBTARGETINFO_MACRO(HasVendorXqcilo, false, hasVendorXqcilo)
GET_SUBTARGETINFO_MACRO(HasVendorXqcilsm, false, hasVendorXqcilsm)
GET_SUBTARGETINFO_MACRO(HasVendorXqcisim, false, hasVendorXqcisim)
GET_SUBTARGETINFO_MACRO(HasVendorXqcisls, false, hasVendorXqcisls)
GET_SUBTARGETINFO_MACRO(HasVendorXqcisync, false, hasVendorXqcisync)
GET_SUBTARGETINFO_MACRO(HasVendorXwchc, false, hasVendorXwchc)
GET_SUBTARGETINFO_MACRO(HasZExtHFusion, false, hasZExtHFusion)
GET_SUBTARGETINFO_MACRO(HasZExtWFusion, false, hasZExtWFusion)
GET_SUBTARGETINFO_MACRO(IsRV32, false, isRV32)
GET_SUBTARGETINFO_MACRO(IsRV64, false, isRV64)
GET_SUBTARGETINFO_MACRO(IsRVA20S64, false, isRVA20S64)
GET_SUBTARGETINFO_MACRO(IsRVA20U64, false, isRVA20U64)
GET_SUBTARGETINFO_MACRO(IsRVA22S64, false, isRVA22S64)
GET_SUBTARGETINFO_MACRO(IsRVA22U64, false, isRVA22U64)
GET_SUBTARGETINFO_MACRO(IsRVA23S64, false, isRVA23S64)
GET_SUBTARGETINFO_MACRO(IsRVA23U64, false, isRVA23U64)
GET_SUBTARGETINFO_MACRO(IsRVB23S64, false, isRVB23S64)
GET_SUBTARGETINFO_MACRO(IsRVB23U64, false, isRVB23U64)
GET_SUBTARGETINFO_MACRO(IsRVI20U32, false, isRVI20U32)
GET_SUBTARGETINFO_MACRO(IsRVI20U64, false, isRVI20U64)
GET_SUBTARGETINFO_MACRO(IsRVM23U32, false, isRVM23U32)
GET_SUBTARGETINFO_MACRO(PredictableSelectIsExpensive, false, predictableSelectIsExpensive)
GET_SUBTARGETINFO_MACRO(PreferAscendingLoadStore, false, preferAscendingLoadStore)
GET_SUBTARGETINFO_MACRO(PreferVsetvliOverReadVLENB, false, preferVsetvliOverReadVLENB)
GET_SUBTARGETINFO_MACRO(PreferWInst, false, preferWInst)
GET_SUBTARGETINFO_MACRO(SinkSplatOperands, true, sinkSplatOperands)
GET_SUBTARGETINFO_MACRO(UsePostRAScheduler, false, usePostRAScheduler)

#undef GET_SUBTARGETINFO_MACRO
#endif // GET_SUBTARGETINFO_MACRO

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm_ks {

// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKVStorage< 379, 21644> RISCVFeatureKVStorage = {
  {
    { sizeof(SubtargetFeatureKV) * 379 + 1, sizeof(SubtargetFeatureKV) * 379 + 7, RISCV::Feature32Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 378 + 23, sizeof(SubtargetFeatureKV) * 378 + 29, RISCV::Feature64Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 377 + 45, sizeof(SubtargetFeatureKV) * 377 + 47, RISCV::FeatureStdExtA, { { { 0x0ULL, 0x110000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 376 + 73, sizeof(SubtargetFeatureKV) * 376 + 81, RISCV::TuneAndes45, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 375 + 108, sizeof(SubtargetFeatureKV) * 375 + 110, RISCV::FeatureStdExtB, { { { 0x0ULL, 0x21800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 374 + 163, sizeof(SubtargetFeatureKV) * 374 + 165, RISCV::FeatureStdExtC, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 373 + 195, sizeof(SubtargetFeatureKV) * 373 + 218, RISCV::TuneConditionalCompressedMoveFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 372 + 244, sizeof(SubtargetFeatureKV) * 372 + 246, RISCV::FeatureStdExtD, { { { 0x200000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 371 + 284, sizeof(SubtargetFeatureKV) * 371 + 316, RISCV::TuneDisableLatencySchedHeuristic, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 370 + 353, sizeof(SubtargetFeatureKV) * 370 + 385, RISCV::TuneDisableMISchedLoadClustering, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 369 + 434, sizeof(SubtargetFeatureKV) * 369 + 467, RISCV::TuneDisableMISchedStoreClustering, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 368 + 517, sizeof(SubtargetFeatureKV) * 368 + 553, RISCV::TuneDisablePostMISchedLoadClustering, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 367 + 609, sizeof(SubtargetFeatureKV) * 367 + 646, RISCV::TuneDisablePostMISchedStoreClustering, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 366 + 703, sizeof(SubtargetFeatureKV) * 366 + 717, RISCV::TuneDLenFactor2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 365 + 767, sizeof(SubtargetFeatureKV) * 365 + 769, RISCV::FeatureStdExtE, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 364 + 813, sizeof(SubtargetFeatureKV) * 364 + 831, RISCV::TuneEnableSelectOptimize, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 363 + 890, sizeof(SubtargetFeatureKV) * 363 + 921, RISCV::TuneEnableVsetvliSchedHeuristic, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 362 + 963, sizeof(SubtargetFeatureKV) * 362 + 973, RISCV::FeatureExactAssembly, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 361 + 1033, sizeof(SubtargetFeatureKV) * 361 + 1046, RISCV::Experimental, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 360 + 1070, sizeof(SubtargetFeatureKV) * 360 + 1085, RISCV::FeatureStdExtP, { { { 0x0ULL, 0x1800000000000ULL, 0x8000400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 359 + 1114, sizeof(SubtargetFeatureKV) * 359 + 1136, RISCV::RVM23U32, { { { 0x1820000000002ULL, 0x1200000000000000ULL, 0x13200400ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 358 + 1173, sizeof(SubtargetFeatureKV) * 358 + 1194, RISCV::FeatureStdExtSmpmpmt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 357 + 1239, sizeof(SubtargetFeatureKV) * 357 + 1259, RISCV::FeatureStdExtSvukte, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 356 + 1342, sizeof(SubtargetFeatureKV) * 356 + 1362, RISCV::FeatureVendorXqccmt, { { { 0x0ULL, 0x40000000000000ULL, 0x400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 355 + 1400, sizeof(SubtargetFeatureKV) * 355 + 1422, RISCV::FeatureVendorXSfmclic, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 354 + 1465, sizeof(SubtargetFeatureKV) * 354 + 1487, RISCV::FeatureVendorXSfsclic, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 353 + 1533, sizeof(SubtargetFeatureKV) * 353 + 1548, RISCV::FeatureStdExtY, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 352 + 1571, sizeof(SubtargetFeatureKV) * 352 + 1589, RISCV::FeatureStdExtZibi, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 351 + 1620, sizeof(SubtargetFeatureKV) * 351 + 1641, RISCV::FeatureStdExtZicfilp, { { { 0x0ULL, 0x0ULL, 0x400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 350 + 1665, sizeof(SubtargetFeatureKV) * 350 + 1686, RISCV::FeatureStdExtZicfiss, { { { 0x0ULL, 0x0ULL, 0x10400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 349 + 1711, sizeof(SubtargetFeatureKV) * 349 + 1730, RISCV::FeatureStdExtZvabd, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 348 + 1767, sizeof(SubtargetFeatureKV) * 348 + 1788, RISCV::FeatureStdExtZvbc32e, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 347 + 1854, sizeof(SubtargetFeatureKV) * 347 + 1877, RISCV::FeatureStdExtZvdot4a8i, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 346 + 1945, sizeof(SubtargetFeatureKV) * 346 + 1970, RISCV::FeatureStdExtZvfbdota32f, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 345 + 2021, sizeof(SubtargetFeatureKV) * 345 + 2041, RISCV::FeatureStdExtZvfbfa, { { { 0x0ULL, 0x0ULL, 0x400000000002ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 344 + 2091, sizeof(SubtargetFeatureKV) * 344 + 2115, RISCV::FeatureStdExtZvfofp8min, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 343 + 2151, sizeof(SubtargetFeatureKV) * 343 + 2177, RISCV::FeatureStdExtZvfqwbdota8f, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 342 + 2232, sizeof(SubtargetFeatureKV) * 342 + 2257, RISCV::FeatureStdExtZvfqwdota8f, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 341 + 2293, sizeof(SubtargetFeatureKV) * 341 + 2320, RISCV::FeatureStdExtZvfwbdota16bf, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 340 + 2373, sizeof(SubtargetFeatureKV) * 340 + 2399, RISCV::FeatureStdExtZvfwdota16bf, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 339 + 2433, sizeof(SubtargetFeatureKV) * 339 + 2452, RISCV::FeatureStdExtZvkgs, { { { 0x0ULL, 0x0ULL, 0x8000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 338 + 2510, sizeof(SubtargetFeatureKV) * 338 + 2536, RISCV::FeatureStdExtZvqwbdota16i, { { { 0x0ULL, 0x0ULL, 0x4000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 337 + 2598, sizeof(SubtargetFeatureKV) * 337 + 2623, RISCV::FeatureStdExtZvqwbdota8i, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 336 + 2683, sizeof(SubtargetFeatureKV) * 336 + 2708, RISCV::FeatureStdExtZvqwdota16i, { { { 0x0ULL, 0x0ULL, 0x4000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 335 + 2751, sizeof(SubtargetFeatureKV) * 335 + 2775, RISCV::FeatureStdExtZvqwdota8i, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 334 + 2816, sizeof(SubtargetFeatureKV) * 334 + 2836, RISCV::FeatureStdExtZvvfmm, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 333 + 2889, sizeof(SubtargetFeatureKV) * 333 + 2908, RISCV::FeatureStdExtZvvmm, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 332 + 2953, sizeof(SubtargetFeatureKV) * 332 + 2974, RISCV::FeatureStdExtZvvmtls, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 331 + 3009, sizeof(SubtargetFeatureKV) * 331 + 3031, RISCV::FeatureStdExtZvvmttls, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 330 + 3079, sizeof(SubtargetFeatureKV) * 330 + 3098, RISCV::FeatureStdExtZvzip, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 329 + 3142, sizeof(SubtargetFeatureKV) * 329 + 3144, RISCV::FeatureStdExtF, { { { 0x0ULL, 0x0ULL, 0x400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 328 + 3182, sizeof(SubtargetFeatureKV) * 328 + 3197, RISCV::FeatureForcedAtomics, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 327 + 3254, sizeof(SubtargetFeatureKV) * 327 + 3270, RISCV::TuneADDLoadFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 326 + 3305, sizeof(SubtargetFeatureKV) * 326 + 3320, RISCV::TuneFusionAddMem, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 325 + 3354, sizeof(SubtargetFeatureKV) * 325 + 3371, RISCV::TuneADDILoadFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 324 + 3402, sizeof(SubtargetFeatureKV) * 324 + 3420, RISCV::TuneAUIPCADDIFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 323 + 3450, sizeof(SubtargetFeatureKV) * 323 + 3468, RISCV::TuneAUIPCLoadFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 322 + 3500, sizeof(SubtargetFeatureKV) * 322 + 3513, RISCV::TuneBFExtFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 321 + 3561, sizeof(SubtargetFeatureKV) * 321 + 3575, RISCV::TuneLDADDFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 320 + 3601, sizeof(SubtargetFeatureKV) * 320 + 3622, RISCV::TuneFusionLogicImmReg, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 319 + 3666, sizeof(SubtargetFeatureKV) * 319 + 3687, RISCV::TuneFusionLogicRegImm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 318 + 3731, sizeof(SubtargetFeatureKV) * 318 + 3752, RISCV::TuneFusionLogicRegReg, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 317 + 3793, sizeof(SubtargetFeatureKV) * 317 + 3809, RISCV::TuneLUIADDIFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 316 + 3838, sizeof(SubtargetFeatureKV) * 316 + 3854, RISCV::TuneLUILoadFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 315 + 3884, sizeof(SubtargetFeatureKV) * 315 + 3899, RISCV::TuneFusionMulAdd, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 314 + 3926, sizeof(SubtargetFeatureKV) * 314 + 3952, RISCV::TuneQCELILoadStoreFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 313 + 3992, sizeof(SubtargetFeatureKV) * 313 + 4017, RISCV::TuneFusionShiftBitExtract, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 312 + 4051, sizeof(SubtargetFeatureKV) * 312 + 4072, RISCV::TuneShiftedZExtWFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 311 + 4146, sizeof(SubtargetFeatureKV) * 311 + 4165, RISCV::TuneSHXADDLoadFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 310 + 4209, sizeof(SubtargetFeatureKV) * 310 + 4222, RISCV::TuneZExtHFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 309 + 4281, sizeof(SubtargetFeatureKV) * 309 + 4294, RISCV::TuneZExtWFusion, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 308 + 4349, sizeof(SubtargetFeatureKV) * 308 + 4351, RISCV::FeatureStdExtH, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 307 + 4368, sizeof(SubtargetFeatureKV) * 307 + 4370, RISCV::FeatureStdExtI, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 306 + 4405, sizeof(SubtargetFeatureKV) * 306 + 4418, RISCV::TuneNLogNVRGather, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 305 + 4463, sizeof(SubtargetFeatureKV) * 305 + 4465, RISCV::FeatureStdExtM, { { { 0x0ULL, 0x0ULL, 0x8000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 304 + 4507, sizeof(SubtargetFeatureKV) * 304 + 4518, RISCV::TuneMIPSP8700, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 303 + 4539, sizeof(SubtargetFeatureKV) * 303 + 4557, RISCV::TuneNoDefaultUnroll, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 302 + 4591, sizeof(SubtargetFeatureKV) * 302 + 4614, RISCV::TuneNoSinkSplatOperands, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 301 + 4687, sizeof(SubtargetFeatureKV) * 301 + 4713, RISCV::FeatureNoTrailingSeqCstFence, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 300 + 4754, sizeof(SubtargetFeatureKV) * 300 + 4787, RISCV::TuneOptimizedNF2SegmentLoadStore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 299 + 4861, sizeof(SubtargetFeatureKV) * 299 + 4894, RISCV::TuneOptimizedNF3SegmentLoadStore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 298 + 4968, sizeof(SubtargetFeatureKV) * 298 + 5001, RISCV::TuneOptimizedNF4SegmentLoadStore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 297 + 5075, sizeof(SubtargetFeatureKV) * 297 + 5108, RISCV::TuneOptimizedNF5SegmentLoadStore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 296 + 5182, sizeof(SubtargetFeatureKV) * 296 + 5215, RISCV::TuneOptimizedNF6SegmentLoadStore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 295 + 5289, sizeof(SubtargetFeatureKV) * 295 + 5322, RISCV::TuneOptimizedNF7SegmentLoadStore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 294 + 5396, sizeof(SubtargetFeatureKV) * 294 + 5429, RISCV::TuneOptimizedNF8SegmentLoadStore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 293 + 5503, sizeof(SubtargetFeatureKV) * 293 + 5530, RISCV::TuneOptimizedZeroStrideLoad, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 292 + 5597, sizeof(SubtargetFeatureKV) * 292 + 5615, RISCV::FeaturePermissiveZalrsc, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 291 + 5680, sizeof(SubtargetFeatureKV) * 291 + 5709, RISCV::TunePredictableSelectIsExpensive, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 290 + 5755, sizeof(SubtargetFeatureKV) * 290 + 5783, RISCV::TunePreferAscendingLoadStore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 289 + 5855, sizeof(SubtargetFeatureKV) * 289 + 5886, RISCV::TunePreferVsetvliOverReadVLENB, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 288 + 5939, sizeof(SubtargetFeatureKV) * 288 + 5953, RISCV::TunePreferWInst, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 287 + 5987, sizeof(SubtargetFeatureKV) * 287 + 5989, RISCV::FeatureStdExtQ, { { { 0x80000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 286 + 6025, sizeof(SubtargetFeatureKV) * 286 + 6031, RISCV::FeatureRelax, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 285 + 6056, sizeof(SubtargetFeatureKV) * 285 + 6067, RISCV::FeatureReserveX1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 284 + 6078, sizeof(SubtargetFeatureKV) * 284 + 6090, RISCV::FeatureReserveX10, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 283 + 6102, sizeof(SubtargetFeatureKV) * 283 + 6114, RISCV::FeatureReserveX11, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 282 + 6126, sizeof(SubtargetFeatureKV) * 282 + 6138, RISCV::FeatureReserveX12, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 281 + 6150, sizeof(SubtargetFeatureKV) * 281 + 6162, RISCV::FeatureReserveX13, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 280 + 6174, sizeof(SubtargetFeatureKV) * 280 + 6186, RISCV::FeatureReserveX14, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 279 + 6198, sizeof(SubtargetFeatureKV) * 279 + 6210, RISCV::FeatureReserveX15, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 278 + 6222, sizeof(SubtargetFeatureKV) * 278 + 6234, RISCV::FeatureReserveX16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 277 + 6246, sizeof(SubtargetFeatureKV) * 277 + 6258, RISCV::FeatureReserveX17, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 276 + 6270, sizeof(SubtargetFeatureKV) * 276 + 6282, RISCV::FeatureReserveX18, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 275 + 6294, sizeof(SubtargetFeatureKV) * 275 + 6306, RISCV::FeatureReserveX19, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 274 + 6318, sizeof(SubtargetFeatureKV) * 274 + 6329, RISCV::FeatureReserveX2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 273 + 6340, sizeof(SubtargetFeatureKV) * 273 + 6352, RISCV::FeatureReserveX20, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 272 + 6364, sizeof(SubtargetFeatureKV) * 272 + 6376, RISCV::FeatureReserveX21, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 271 + 6388, sizeof(SubtargetFeatureKV) * 271 + 6400, RISCV::FeatureReserveX22, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 270 + 6412, sizeof(SubtargetFeatureKV) * 270 + 6424, RISCV::FeatureReserveX23, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 269 + 6436, sizeof(SubtargetFeatureKV) * 269 + 6448, RISCV::FeatureReserveX24, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 268 + 6460, sizeof(SubtargetFeatureKV) * 268 + 6472, RISCV::FeatureReserveX25, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 267 + 6484, sizeof(SubtargetFeatureKV) * 267 + 6496, RISCV::FeatureReserveX26, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 266 + 6508, sizeof(SubtargetFeatureKV) * 266 + 6520, RISCV::FeatureReserveX27, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 265 + 6532, sizeof(SubtargetFeatureKV) * 265 + 6544, RISCV::FeatureReserveX28, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 264 + 6556, sizeof(SubtargetFeatureKV) * 264 + 6568, RISCV::FeatureReserveX29, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 263 + 6580, sizeof(SubtargetFeatureKV) * 263 + 6591, RISCV::FeatureReserveX3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 262 + 6602, sizeof(SubtargetFeatureKV) * 262 + 6614, RISCV::FeatureReserveX30, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 261 + 6626, sizeof(SubtargetFeatureKV) * 261 + 6638, RISCV::FeatureReserveX31, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 260 + 6650, sizeof(SubtargetFeatureKV) * 260 + 6661, RISCV::FeatureReserveX4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 259 + 6672, sizeof(SubtargetFeatureKV) * 259 + 6683, RISCV::FeatureReserveX5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 258 + 6694, sizeof(SubtargetFeatureKV) * 258 + 6705, RISCV::FeatureReserveX6, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 257 + 6716, sizeof(SubtargetFeatureKV) * 257 + 6727, RISCV::FeatureReserveX7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 256 + 6738, sizeof(SubtargetFeatureKV) * 256 + 6749, RISCV::FeatureReserveX8, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 255 + 6760, sizeof(SubtargetFeatureKV) * 255 + 6771, RISCV::FeatureReserveX9, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 254 + 6782, sizeof(SubtargetFeatureKV) * 254 + 6791, RISCV::RVA20S64, { { { 0x1ad0000000004ULL, 0x8029800800ULL, 0xd39000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 253 + 6815, sizeof(SubtargetFeatureKV) * 253 + 6824, RISCV::RVA20U64, { { { 0x1ad0000000004ULL, 0x8000000000ULL, 0x539000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 252 + 6848, sizeof(SubtargetFeatureKV) * 252 + 6857, RISCV::RVA22S64, { { { 0x1af0000000004ULL, 0x4169802800ULL, 0x4006d39f08ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 251 + 6881, sizeof(SubtargetFeatureKV) * 251 + 6890, RISCV::RVA22U64, { { { 0x1af0000000004ULL, 0x4000000000ULL, 0x4006539f08ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 250 + 6914, sizeof(SubtargetFeatureKV) * 250 + 6923, RISCV::RVA23S64, { { { 0x21af0000000004ULL, 0x10804051efc23800ULL, 0x100044017f39f09ULL, 0x1000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 249 + 6947, sizeof(SubtargetFeatureKV) * 249 + 6956, RISCV::RVA23U64, { { { 0x1af0000000004ULL, 0x1080405004000000ULL, 0x100044017739f09ULL, 0x1000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 248 + 6980, sizeof(SubtargetFeatureKV) * 248 + 6989, RISCV::RVB23S64, { { { 0x1af0000000004ULL, 0x10804041ebc03800ULL, 0x4017f39f01ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 247 + 7013, sizeof(SubtargetFeatureKV) * 247 + 7022, RISCV::RVB23U64, { { { 0x1af0000000004ULL, 0x1080404000000000ULL, 0x4017739f01ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 246 + 7046, sizeof(SubtargetFeatureKV) * 246 + 7055, RISCV::RVI20U32, { { { 0x800000000002ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 245 + 7079, sizeof(SubtargetFeatureKV) * 245 + 7088, RISCV::RVI20U64, { { { 0x800000000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 244 + 7112, sizeof(SubtargetFeatureKV) * 244 + 7125, RISCV::FeatureSaveRestore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 243 + 7145, sizeof(SubtargetFeatureKV) * 243 + 7151, RISCV::FeatureStdExtSdext, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 242 + 7179, sizeof(SubtargetFeatureKV) * 242 + 7186, RISCV::FeatureStdExtSdtrig, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 241 + 7215, sizeof(SubtargetFeatureKV) * 241 + 7219, RISCV::FeatureStdExtSha, { { { 0x1ec0400000000000ULL, 0x100000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 240 + 7248, sizeof(SubtargetFeatureKV) * 240 + 7261, RISCV::FeatureStdExtShcounterenw, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 239 + 7364, sizeof(SubtargetFeatureKV) * 239 + 7372, RISCV::FeatureStdExtShgatpa, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 238 + 7455, sizeof(SubtargetFeatureKV) * 238 + 7468, RISCV::FeatureStdExtShlcofideleg, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 237 + 7524, sizeof(SubtargetFeatureKV) * 237 + 7550, RISCV::TuneShortForwardBranchIALU, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 236 + 7617, sizeof(SubtargetFeatureKV) * 236 + 7644, RISCV::TuneShortForwardBranchILoad, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1000000000000ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 235 + 7707, sizeof(SubtargetFeatureKV) * 235 + 7736, RISCV::TuneShortForwardBranchIMinMax, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1000000000000ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 234 + 7809, sizeof(SubtargetFeatureKV) * 234 + 7834, RISCV::TuneShortForwardBranchImm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1000000000000ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 233 + 7904, sizeof(SubtargetFeatureKV) * 233 + 7930, RISCV::TuneShortForwardBranchIMul, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1000000000000ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 232 + 7991, sizeof(SubtargetFeatureKV) * 232 + 7999, RISCV::FeatureStdExtShtvala, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 231 + 8044, sizeof(SubtargetFeatureKV) * 231 + 8053, RISCV::FeatureStdExtShvsatpa, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 230 + 8109, sizeof(SubtargetFeatureKV) * 230 + 8119, RISCV::FeatureStdExtShvstvala, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 229 + 8167, sizeof(SubtargetFeatureKV) * 229 + 8177, RISCV::FeatureStdExtShvstvecd, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 228 + 8219, sizeof(SubtargetFeatureKV) * 228 + 8227, RISCV::TuneSiFive7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 227 + 8254, sizeof(SubtargetFeatureKV) * 227 + 8278, RISCV::TuneHasSingleElementVecFP64, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 226 + 8351, sizeof(SubtargetFeatureKV) * 226 + 8357, RISCV::FeatureStdExtSmaia, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 225 + 8413, sizeof(SubtargetFeatureKV) * 225 + 8422, RISCV::FeatureStdExtSmcdeleg, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 224 + 8468, sizeof(SubtargetFeatureKV) * 224 + 8478, RISCV::FeatureStdExtSmcntrpmf, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 223 + 8535, sizeof(SubtargetFeatureKV) * 223 + 8544, RISCV::FeatureStdExtSmcsrind, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 222 + 8591, sizeof(SubtargetFeatureKV) * 222 + 8597, RISCV::FeatureStdExtSmctr, { { { 0x0ULL, 0x4000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 221 + 8646, sizeof(SubtargetFeatureKV) * 221 + 8655, RISCV::FeatureStdExtSmdbltrp, { { { 0x0ULL, 0x0ULL, 0x400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 220 + 8694, sizeof(SubtargetFeatureKV) * 220 + 8701, RISCV::FeatureStdExtSmepmp, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 219 + 8748, sizeof(SubtargetFeatureKV) * 219 + 8754, RISCV::FeatureStdExtSmmpm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 218 + 8805, sizeof(SubtargetFeatureKV) * 218 + 8811, RISCV::FeatureStdExtSmnpm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 217 + 8881, sizeof(SubtargetFeatureKV) * 217 + 8888, RISCV::FeatureStdExtSmrnmi, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 216 + 8933, sizeof(SubtargetFeatureKV) * 216 + 8943, RISCV::FeatureStdExtSmstateen, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 215 + 9005, sizeof(SubtargetFeatureKV) * 215 + 9011, RISCV::FeatureStdExtSsaia, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 214 + 9070, sizeof(SubtargetFeatureKV) * 214 + 9077, RISCV::FeatureStdExtSsccfg, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 213 + 9127, sizeof(SubtargetFeatureKV) * 213 + 9135, RISCV::FeatureStdExtSsccptr, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 212 + 9185, sizeof(SubtargetFeatureKV) * 212 + 9194, RISCV::FeatureStdExtSscofpmf, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 211 + 9247, sizeof(SubtargetFeatureKV) * 211 + 9260, RISCV::FeatureStdExtSscounterenw, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 210 + 9363, sizeof(SubtargetFeatureKV) * 210 + 9372, RISCV::FeatureStdExtSscsrind, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 209 + 9422, sizeof(SubtargetFeatureKV) * 209 + 9428, RISCV::FeatureStdExtSsctr, { { { 0x0ULL, 0x4000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 208 + 9480, sizeof(SubtargetFeatureKV) * 208 + 9489, RISCV::FeatureStdExtSsdbltrp, { { { 0x0ULL, 0x0ULL, 0x400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 207 + 9531, sizeof(SubtargetFeatureKV) * 207 + 9537, RISCV::FeatureStdExtSsnpm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 206 + 9610, sizeof(SubtargetFeatureKV) * 206 + 9615, RISCV::FeatureStdExtSspm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 205 + 9666, sizeof(SubtargetFeatureKV) * 205 + 9674, RISCV::FeatureStdExtSsqosid, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 204 + 9723, sizeof(SubtargetFeatureKV) * 204 + 9733, RISCV::FeatureStdExtSsstateen, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 203 + 9798, sizeof(SubtargetFeatureKV) * 203 + 9807, RISCV::FeatureStdExtSsstrict, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 202 + 9861, sizeof(SubtargetFeatureKV) * 202 + 9866, RISCV::FeatureStdExtSstc, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 201 + 9908, sizeof(SubtargetFeatureKV) * 201 + 9916, RISCV::FeatureStdExtSstvala, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 200 + 9961, sizeof(SubtargetFeatureKV) * 200 + 9969, RISCV::FeatureStdExtSstvecd, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 199 + 10008, sizeof(SubtargetFeatureKV) * 199 + 10016, RISCV::FeatureStdExtSsu64xl, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 198 + 10047, sizeof(SubtargetFeatureKV) * 198 + 10052, RISCV::FeatureStdExtSupm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 197 + 10097, sizeof(SubtargetFeatureKV) * 197 + 10103, RISCV::FeatureStdExtSvade, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 196 + 10151, sizeof(SubtargetFeatureKV) * 196 + 10157, RISCV::FeatureStdExtSvadu, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 195 + 10188, sizeof(SubtargetFeatureKV) * 195 + 10195, RISCV::FeatureStdExtSvbare, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 194 + 10231, sizeof(SubtargetFeatureKV) * 194 + 10239, RISCV::FeatureStdExtSvinval, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 193 + 10303, sizeof(SubtargetFeatureKV) * 193 + 10311, RISCV::FeatureStdExtSvnapot, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 192 + 10352, sizeof(SubtargetFeatureKV) * 192 + 10359, RISCV::FeatureStdExtSvpbmt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 191 + 10394, sizeof(SubtargetFeatureKV) * 191 + 10406, RISCV::FeatureStdExtSvrsw60t59b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 190 + 10459, sizeof(SubtargetFeatureKV) * 190 + 10466, RISCV::FeatureStdExtSvvptc, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 189 + 10543, sizeof(SubtargetFeatureKV) * 189 + 10558, RISCV::FeatureTaggedGlobals, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 188 + 10672, sizeof(SubtargetFeatureKV) * 188 + 10693, RISCV::FeatureUnalignedScalarMem, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 187 + 10753, sizeof(SubtargetFeatureKV) * 187 + 10774, RISCV::FeatureUnalignedVectorMem, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 186 + 10834, sizeof(SubtargetFeatureKV) * 186 + 10855, RISCV::TunePostRAScheduler, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 185 + 10896, sizeof(SubtargetFeatureKV) * 185 + 10898, RISCV::FeatureStdExtV, { { { 0x0ULL, 0x0ULL, 0x1000000000000ULL, 0x8000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 184 + 10948, sizeof(SubtargetFeatureKV) * 184 + 10963, RISCV::TuneVentanaVeyron, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 183 + 10996, sizeof(SubtargetFeatureKV) * 183 + 11017, RISCV::TuneVLDependentLatency, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 182 + 11088, sizeof(SubtargetFeatureKV) * 182 + 11108, RISCV::TuneVXRMPipelineFlush, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 181 + 11142, sizeof(SubtargetFeatureKV) * 181 + 11149, RISCV::FeatureVendorXAIFET, { { { 0x200000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 180 + 11184, sizeof(SubtargetFeatureKV) * 180 + 11197, RISCV::FeatureVendorXAndesBFHCvt, { { { 0x200000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 179 + 11257, sizeof(SubtargetFeatureKV) * 179 + 11268, RISCV::FeatureVendorXAndesPerf, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 178 + 11311, sizeof(SubtargetFeatureKV) * 178 + 11325, RISCV::FeatureVendorXAndesVBFHCvt, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 177 + 11386, sizeof(SubtargetFeatureKV) * 177 + 11397, RISCV::FeatureVendorXAndesVDot, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 176 + 11447, sizeof(SubtargetFeatureKV) * 176 + 11462, RISCV::FeatureVendorXAndesVPackFPH, { { { 0x200000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 175 + 11516, sizeof(SubtargetFeatureKV) * 175 + 11529, RISCV::FeatureVendorXAndesVSIntH, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 174 + 11588, sizeof(SubtargetFeatureKV) * 174 + 11604, RISCV::FeatureVendorXAndesVSIntLoad, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 173 + 11657, sizeof(SubtargetFeatureKV) * 173 + 11666, RISCV::FeatureVendorXCheriot, { { { 0x1100000000000ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 172 + 11697, sizeof(SubtargetFeatureKV) * 172 + 11704, RISCV::FeatureVendorXCValu, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 171 + 11737, sizeof(SubtargetFeatureKV) * 171 + 11743, RISCV::FeatureVendorXCVbi, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 170 + 11780, sizeof(SubtargetFeatureKV) * 170 + 11792, RISCV::FeatureVendorXCVbitmanip, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 169 + 11832, sizeof(SubtargetFeatureKV) * 169 + 11839, RISCV::FeatureVendorXCVelw, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 168 + 11873, sizeof(SubtargetFeatureKV) * 168 + 11880, RISCV::FeatureVendorXCVmac, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 167 + 11918, sizeof(SubtargetFeatureKV) * 167 + 11925, RISCV::FeatureVendorXCVmem, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 166 + 11974, sizeof(SubtargetFeatureKV) * 166 + 11982, RISCV::FeatureVendorXCVsimd, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 165 + 12010, sizeof(SubtargetFeatureKV) * 165 + 12020, RISCV::FeatureVendorXMIPSCBOP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 164 + 12057, sizeof(SubtargetFeatureKV) * 164 + 12067, RISCV::FeatureVendorXMIPSCMov, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 163 + 12128, sizeof(SubtargetFeatureKV) * 163 + 12140, RISCV::FeatureVendorXMIPSEXECTL, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 162 + 12179, sizeof(SubtargetFeatureKV) * 162 + 12188, RISCV::FeatureVendorXMIPSLSP, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 161 + 12251, sizeof(SubtargetFeatureKV) * 161 + 12258, RISCV::FeatureVendorXqccmp, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 160 + 12311, sizeof(SubtargetFeatureKV) * 160 + 12316, RISCV::FeatureVendorXqci, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x3ffff000000000ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 159 + 12347, sizeof(SubtargetFeatureKV) * 159 + 12353, RISCV::FeatureVendorXqcia, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 158 + 12396, sizeof(SubtargetFeatureKV) * 158 + 12403, RISCV::FeatureVendorXqciac, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 157 + 12467, sizeof(SubtargetFeatureKV) * 157 + 12474, RISCV::FeatureVendorXqcibi, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 156 + 12524, sizeof(SubtargetFeatureKV) * 156 + 12531, RISCV::FeatureVendorXqcibm, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 155 + 12581, sizeof(SubtargetFeatureKV) * 155 + 12589, RISCV::FeatureVendorXqcicli, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 154 + 12650, sizeof(SubtargetFeatureKV) * 154 + 12657, RISCV::FeatureVendorXqcicm, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 153 + 12707, sizeof(SubtargetFeatureKV) * 153 + 12714, RISCV::FeatureVendorXqcics, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 152 + 12766, sizeof(SubtargetFeatureKV) * 152 + 12774, RISCV::FeatureVendorXqcicsr, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 151 + 12812, sizeof(SubtargetFeatureKV) * 151 + 12820, RISCV::FeatureVendorXqciint, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 150 + 12865, sizeof(SubtargetFeatureKV) * 150 + 12872, RISCV::FeatureVendorXqciio, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 149 + 12927, sizeof(SubtargetFeatureKV) * 149 + 12934, RISCV::FeatureVendorXqcilb, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 148 + 12979, sizeof(SubtargetFeatureKV) * 148 + 12986, RISCV::FeatureVendorXqcili, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 147 + 13040, sizeof(SubtargetFeatureKV) * 147 + 13048, RISCV::FeatureVendorXqcilia, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 146 + 13109, sizeof(SubtargetFeatureKV) * 146 + 13116, RISCV::FeatureVendorXqcilo, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 145 + 13173, sizeof(SubtargetFeatureKV) * 145 + 13181, RISCV::FeatureVendorXqcilsm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 144 + 13235, sizeof(SubtargetFeatureKV) * 144 + 13243, RISCV::FeatureVendorXqcisim, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 143 + 13293, sizeof(SubtargetFeatureKV) * 143 + 13301, RISCV::FeatureVendorXqcisls, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 142 + 13353, sizeof(SubtargetFeatureKV) * 142 + 13362, RISCV::FeatureVendorXqcisync, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 141 + 13408, sizeof(SubtargetFeatureKV) * 141 + 13417, RISCV::FeatureVendorXSfcease, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 140 + 13458, sizeof(SubtargetFeatureKV) * 140 + 13468, RISCV::FeatureVendorXSfmm128t, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x20000ULL, 0x80ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 139 + 13503, sizeof(SubtargetFeatureKV) * 139 + 13512, RISCV::FeatureVendorXSfmm16t, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x4000ULL, 0x80ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 138 + 13545, sizeof(SubtargetFeatureKV) * 138 + 13554, RISCV::FeatureVendorXSfmm32a, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x7ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 137 + 13635, sizeof(SubtargetFeatureKV) * 137 + 13647, RISCV::FeatureVendorXSfmm32a16f, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x80ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 136 + 13730, sizeof(SubtargetFeatureKV) * 136 + 13742, RISCV::FeatureVendorXSfmm32a32f, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x80ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 135 + 13805, sizeof(SubtargetFeatureKV) * 135 + 13816, RISCV::FeatureVendorXSfmm32a8f, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x80ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 134 + 13878, sizeof(SubtargetFeatureKV) * 134 + 13889, RISCV::FeatureVendorXSfmm32a8i, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x80ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 133 + 13948, sizeof(SubtargetFeatureKV) * 133 + 13957, RISCV::FeatureVendorXSfmm32t, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x8000ULL, 0x80ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 132 + 13990, sizeof(SubtargetFeatureKV) * 132 + 14002, RISCV::FeatureVendorXSfmm64a64f, { { { 0x0ULL, 0x0ULL, 0x1000000000000ULL, 0x0ULL, 0x80ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 131 + 14066, sizeof(SubtargetFeatureKV) * 131 + 14075, RISCV::FeatureVendorXSfmm64t, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x10000ULL, 0x80ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 130 + 14108, sizeof(SubtargetFeatureKV) * 130 + 14118, RISCV::FeatureVendorXSfmmbase, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 129 + 14191, sizeof(SubtargetFeatureKV) * 129 + 14198, RISCV::FeatureVendorXSfvcp, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 128 + 14265, sizeof(SubtargetFeatureKV) * 128 + 14279, RISCV::FeatureVendorXSfvfbfexp16e, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 127 + 14369, sizeof(SubtargetFeatureKV) * 127 + 14381, RISCV::FeatureVendorXSfvfexp16e, { { { 0x0ULL, 0x0ULL, 0x80000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 126 + 14475, sizeof(SubtargetFeatureKV) * 126 + 14487, RISCV::FeatureVendorXSfvfexp32e, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 125 + 14583, sizeof(SubtargetFeatureKV) * 125 + 14593, RISCV::FeatureVendorXSfvfexpa, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 124 + 14674, sizeof(SubtargetFeatureKV) * 124 + 14687, RISCV::FeatureVendorXSfvfexpa64e, { { { 0x0ULL, 0x0ULL, 0x1000000000000ULL, 0x0ULL, 0x2000ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 123 + 14793, sizeof(SubtargetFeatureKV) * 123 + 14809, RISCV::FeatureVendorXSfvfnrclipxfqf, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 122 + 14874, sizeof(SubtargetFeatureKV) * 122 + 14888, RISCV::FeatureVendorXSfvfwmaccqqq, { { { 0x0ULL, 0x0ULL, 0x20000000000000ULL, 0x8000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 121 + 14961, sizeof(SubtargetFeatureKV) * 121 + 14974, RISCV::FeatureVendorXSfvqmaccdod, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x8000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 120 + 15058, sizeof(SubtargetFeatureKV) * 120 + 15071, RISCV::FeatureVendorXSfvqmaccqoq, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x10000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 119 + 15155, sizeof(SubtargetFeatureKV) * 119 + 15176, RISCV::FeatureVendorXSiFivecdiscarddlone, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 118 + 15237, sizeof(SubtargetFeatureKV) * 118 + 15256, RISCV::FeatureVendorXSiFivecflushdlone, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 117 + 15313, sizeof(SubtargetFeatureKV) * 117 + 15322, RISCV::FeatureVendorXSMTVDot, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 116 + 15373, sizeof(SubtargetFeatureKV) * 116 + 15384, RISCV::FeatureVendorXSMTVDotII, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 115 + 15440, sizeof(SubtargetFeatureKV) * 115 + 15449, RISCV::FeatureVendorXTHeadBa, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 114 + 15502, sizeof(SubtargetFeatureKV) * 114 + 15511, RISCV::FeatureVendorXTHeadBb, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 113 + 15567, sizeof(SubtargetFeatureKV) * 113 + 15576, RISCV::FeatureVendorXTHeadBs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 112 + 15620, sizeof(SubtargetFeatureKV) * 112 + 15630, RISCV::FeatureVendorXTHeadCmo, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 111 + 15681, sizeof(SubtargetFeatureKV) * 111 + 15695, RISCV::FeatureVendorXTHeadCondMov, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 110 + 15750, sizeof(SubtargetFeatureKV) * 110 + 15764, RISCV::FeatureVendorXTHeadFMemIdx, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 109 + 15818, sizeof(SubtargetFeatureKV) * 109 + 15828, RISCV::FeatureVendorXTHeadMac, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 108 + 15882, sizeof(SubtargetFeatureKV) * 108 + 15895, RISCV::FeatureVendorXTHeadMemIdx, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 107 + 15945, sizeof(SubtargetFeatureKV) * 107 + 15959, RISCV::FeatureVendorXTHeadMemPair, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 106 + 16010, sizeof(SubtargetFeatureKV) * 106 + 16021, RISCV::FeatureVendorXTHeadSync, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 105 + 16082, sizeof(SubtargetFeatureKV) * 105 + 16093, RISCV::FeatureVendorXTHeadVdot, { { { 0x0ULL, 0x1000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 104 + 16141, sizeof(SubtargetFeatureKV) * 104 + 16157, RISCV::FeatureVendorXVentanaCondOps, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 103 + 16201, sizeof(SubtargetFeatureKV) * 103 + 16207, RISCV::FeatureVendorXwchc, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 102 + 16258, sizeof(SubtargetFeatureKV) * 102 + 16266, RISCV::FeatureStdExtZa128rs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 101 + 16320, sizeof(SubtargetFeatureKV) * 101 + 16327, RISCV::FeatureStdExtZa64rs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 100 + 16379, sizeof(SubtargetFeatureKV) * 100 + 16385, RISCV::FeatureStdExtZaamo, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 99 + 16420, sizeof(SubtargetFeatureKV) * 99 + 16426, RISCV::FeatureStdExtZabha, { { { 0x0ULL, 0x10000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 98 + 16479, sizeof(SubtargetFeatureKV) * 98 + 16485, RISCV::FeatureStdExtZacas, { { { 0x0ULL, 0x10000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 97 + 16532, sizeof(SubtargetFeatureKV) * 97 + 16539, RISCV::FeatureStdExtZalasr, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 96 + 16594, sizeof(SubtargetFeatureKV) * 96 + 16601, RISCV::FeatureStdExtZalrsc, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 95 + 16644, sizeof(SubtargetFeatureKV) * 95 + 16652, RISCV::FeatureStdExtZama16b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 94 + 16713, sizeof(SubtargetFeatureKV) * 94 + 16719, RISCV::FeatureStdExtZawrs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 93 + 16753, sizeof(SubtargetFeatureKV) * 93 + 16757, RISCV::FeatureStdExtZba, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 92 + 16797, sizeof(SubtargetFeatureKV) * 92 + 16801, RISCV::FeatureStdExtZbb, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 91 + 16832, sizeof(SubtargetFeatureKV) * 91 + 16836, RISCV::FeatureStdExtZbc, { { { 0x0ULL, 0x8000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 90 + 16870, sizeof(SubtargetFeatureKV) * 90 + 16875, RISCV::FeatureStdExtZbkb, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 89 + 16923, sizeof(SubtargetFeatureKV) * 89 + 16928, RISCV::FeatureStdExtZbkc, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 88 + 16987, sizeof(SubtargetFeatureKV) * 88 + 16992, RISCV::FeatureStdExtZbkx, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 87 + 17035, sizeof(SubtargetFeatureKV) * 87 + 17039, RISCV::FeatureStdExtZbs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 86 + 17071, sizeof(SubtargetFeatureKV) * 86 + 17075, RISCV::FeatureStdExtZca, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 85 + 17157, sizeof(SubtargetFeatureKV) * 85 + 17161, RISCV::FeatureStdExtZcb, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 84 + 17216, sizeof(SubtargetFeatureKV) * 84 + 17220, RISCV::FeatureStdExtZcd, { { { 0x80000000000ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 83 + 17284, sizeof(SubtargetFeatureKV) * 83 + 17288, RISCV::FeatureStdExtZce, { { { 0x0ULL, 0x60c0000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 82 + 17339, sizeof(SubtargetFeatureKV) * 82 + 17343, RISCV::FeatureStdExtZcf, { { { 0x200000000000ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 81 + 17407, sizeof(SubtargetFeatureKV) * 81 + 17413, RISCV::FeatureStdExtZclsd, { { { 0x0ULL, 0x40000000000000ULL, 0x8000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 80 + 17463, sizeof(SubtargetFeatureKV) * 80 + 17469, RISCV::FeatureStdExtZcmop, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 79 + 17508, sizeof(SubtargetFeatureKV) * 79 + 17513, RISCV::FeatureStdExtZcmp, { { { 0x0ULL, 0x40000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 78 + 17569, sizeof(SubtargetFeatureKV) * 78 + 17574, RISCV::FeatureStdExtZcmt, { { { 0x0ULL, 0x40000000000000ULL, 0x400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 77 + 17631, sizeof(SubtargetFeatureKV) * 77 + 17637, RISCV::FeatureStdExtZdinx, { { { 0x0ULL, 0x0ULL, 0x10ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 76 + 17665, sizeof(SubtargetFeatureKV) * 76 + 17669, RISCV::FeatureStdExtZfa, { { { 0x200000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 75 + 17703, sizeof(SubtargetFeatureKV) * 75 + 17711, RISCV::FeatureStdExtZfbfmin, { { { 0x200000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 74 + 17744, sizeof(SubtargetFeatureKV) * 74 + 17748, RISCV::FeatureStdExtZfh, { { { 0x0ULL, 0x0ULL, 0x8ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 73 + 17786, sizeof(SubtargetFeatureKV) * 73 + 17793, RISCV::FeatureStdExtZfhmin, { { { 0x200000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 72 + 17842, sizeof(SubtargetFeatureKV) * 72 + 17848, RISCV::FeatureStdExtZfinx, { { { 0x0ULL, 0x0ULL, 0x400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 71 + 17875, sizeof(SubtargetFeatureKV) * 71 + 17881, RISCV::FeatureStdExtZhinx, { { { 0x0ULL, 0x0ULL, 0x40ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 70 + 17913, sizeof(SubtargetFeatureKV) * 70 + 17922, RISCV::FeatureStdExtZhinxmin, { { { 0x0ULL, 0x0ULL, 0x10ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 69 + 17965, sizeof(SubtargetFeatureKV) * 69 + 17972, RISCV::FeatureStdExtZic64b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 68 + 18012, sizeof(SubtargetFeatureKV) * 68 + 18019, RISCV::FeatureStdExtZicbom, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 67 + 18066, sizeof(SubtargetFeatureKV) * 67 + 18073, RISCV::FeatureStdExtZicbop, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 66 + 18118, sizeof(SubtargetFeatureKV) * 66 + 18125, RISCV::FeatureStdExtZicboz, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 65 + 18166, sizeof(SubtargetFeatureKV) * 65 + 18175, RISCV::FeatureStdExtZiccamoa, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 64 + 18226, sizeof(SubtargetFeatureKV) * 64 + 18235, RISCV::FeatureStdExtZiccamoc, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 63 + 18286, sizeof(SubtargetFeatureKV) * 63 + 18293, RISCV::FeatureStdExtZiccid, { { { 0x0ULL, 0x0ULL, 0x8000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 62 + 18347, sizeof(SubtargetFeatureKV) * 62 + 18354, RISCV::FeatureStdExtZiccif, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 61 + 18431, sizeof(SubtargetFeatureKV) * 61 + 18439, RISCV::FeatureStdExtZicclsm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 60 + 18496, sizeof(SubtargetFeatureKV) * 60 + 18504, RISCV::FeatureStdExtZiccrse, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 59 + 18573, sizeof(SubtargetFeatureKV) * 59 + 18580, RISCV::FeatureStdExtZicntr, { { { 0x0ULL, 0x0ULL, 0x400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 58 + 18616, sizeof(SubtargetFeatureKV) * 58 + 18623, RISCV::FeatureStdExtZicond, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 57 + 18665, sizeof(SubtargetFeatureKV) * 57 + 18671, RISCV::FeatureStdExtZicsr, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 56 + 18686, sizeof(SubtargetFeatureKV) * 56 + 18695, RISCV::FeatureStdExtZifencei, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 55 + 18716, sizeof(SubtargetFeatureKV) * 55 + 18726, RISCV::FeatureStdExtZihintntl, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 54 + 18768, sizeof(SubtargetFeatureKV) * 54 + 18780, RISCV::FeatureStdExtZihintpause, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 53 + 18807, sizeof(SubtargetFeatureKV) * 53 + 18813, RISCV::FeatureStdExtZihpm, { { { 0x0ULL, 0x0ULL, 0x400000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 52 + 18853, sizeof(SubtargetFeatureKV) * 52 + 18859, RISCV::FeatureStdExtZilsd, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 51 + 18898, sizeof(SubtargetFeatureKV) * 51 + 18915, RISCV::FeatureZilsdWordAlign, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 50 + 18967, sizeof(SubtargetFeatureKV) * 50 + 18973, RISCV::FeatureStdExtZimop, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 49 + 19001, sizeof(SubtargetFeatureKV) * 49 + 19004, RISCV::FeatureStdExtZk, { { { 0x0ULL, 0x0ULL, 0x4440000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 48 + 19050, sizeof(SubtargetFeatureKV) * 48 + 19054, RISCV::FeatureStdExtZkn, { { { 0x0ULL, 0x1c000000000000ULL, 0x380000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 47 + 19083, sizeof(SubtargetFeatureKV) * 47 + 19088, RISCV::FeatureStdExtZknd, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 46 + 19124, sizeof(SubtargetFeatureKV) * 46 + 19129, RISCV::FeatureStdExtZkne, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 45 + 19165, sizeof(SubtargetFeatureKV) * 45 + 19170, RISCV::FeatureStdExtZknh, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 44 + 19218, sizeof(SubtargetFeatureKV) * 44 + 19222, RISCV::FeatureStdExtZkr, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 43 + 19255, sizeof(SubtargetFeatureKV) * 43 + 19259, RISCV::FeatureStdExtZks, { { { 0x0ULL, 0x1c000000000000ULL, 0x3000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 42 + 19291, sizeof(SubtargetFeatureKV) * 42 + 19297, RISCV::FeatureStdExtZksed, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 41 + 19352, sizeof(SubtargetFeatureKV) * 41 + 19357, RISCV::FeatureStdExtZksh, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 40 + 19412, sizeof(SubtargetFeatureKV) * 40 + 19416, RISCV::FeatureStdExtZkt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 39 + 19459, sizeof(SubtargetFeatureKV) * 39 + 19465, RISCV::FeatureStdExtZmmul, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 38 + 19498, sizeof(SubtargetFeatureKV) * 38 + 19503, RISCV::FeatureStdExtZtso, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 37 + 19545, sizeof(SubtargetFeatureKV) * 37 + 19550, RISCV::FeatureStdExtZvbb, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 36 + 19602, sizeof(SubtargetFeatureKV) * 36 + 19607, RISCV::FeatureStdExtZvbc, { { { 0x0ULL, 0x0ULL, 0x4000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 35 + 19648, sizeof(SubtargetFeatureKV) * 35 + 19655, RISCV::FeatureStdExtZve32f, { { { 0x200000000000ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 34 + 19744, sizeof(SubtargetFeatureKV) * 34 + 19751, RISCV::FeatureStdExtZve32x, { { { 0x0ULL, 0x0ULL, 0x400000ULL, 0x2000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 33 + 19824, sizeof(SubtargetFeatureKV) * 33 + 19831, RISCV::FeatureStdExtZve64d, { { { 0x80000000000ULL, 0x0ULL, 0x2000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 32 + 19923, sizeof(SubtargetFeatureKV) * 32 + 19930, RISCV::FeatureStdExtZve64f, { { { 0x0ULL, 0x0ULL, 0x4400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 31 + 20019, sizeof(SubtargetFeatureKV) * 31 + 20026, RISCV::FeatureStdExtZve64x, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x4000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 30 + 20099, sizeof(SubtargetFeatureKV) * 30 + 20108, RISCV::FeatureStdExtZvfbfmin, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 29 + 20142, sizeof(SubtargetFeatureKV) * 29 + 20151, RISCV::FeatureStdExtZvfbfwma, { { { 0x0ULL, 0x0ULL, 0x20000000000002ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 28 + 20193, sizeof(SubtargetFeatureKV) * 28 + 20198, RISCV::FeatureStdExtZvfh, { { { 0x0ULL, 0x0ULL, 0x100000000000008ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 27 + 20244, sizeof(SubtargetFeatureKV) * 27 + 20252, RISCV::FeatureStdExtZvfhmin, { { { 0x0ULL, 0x0ULL, 0x400000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 26 + 20309, sizeof(SubtargetFeatureKV) * 26 + 20314, RISCV::FeatureStdExtZvkb, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 25 + 20368, sizeof(SubtargetFeatureKV) * 25 + 20373, RISCV::FeatureStdExtZvkg, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 24 + 20423, sizeof(SubtargetFeatureKV) * 24 + 20428, RISCV::FeatureStdExtZvkn, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x1048ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 23 + 20490, sizeof(SubtargetFeatureKV) * 23 + 20496, RISCV::FeatureStdExtZvknc, { { { 0x0ULL, 0x0ULL, 0x80000000000ULL, 0x2ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 22 + 20539, sizeof(SubtargetFeatureKV) * 22 + 20546, RISCV::FeatureStdExtZvkned, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 21 + 20607, sizeof(SubtargetFeatureKV) * 21 + 20613, RISCV::FeatureStdExtZvkng, { { { 0x0ULL, 0x0ULL, 0x8000000000000000ULL, 0x2ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 20 + 20655, sizeof(SubtargetFeatureKV) * 20 + 20662, RISCV::FeatureStdExtZvknha, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 19 + 20701, sizeof(SubtargetFeatureKV) * 19 + 20708, RISCV::FeatureStdExtZvknhb, { { { 0x0ULL, 0x0ULL, 0x4000000000000ULL, 0x20ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 18 + 20754, sizeof(SubtargetFeatureKV) * 18 + 20759, RISCV::FeatureStdExtZvks, { { { 0x0ULL, 0x0ULL, 0x4000000000000000ULL, 0x1a00ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 17 + 20820, sizeof(SubtargetFeatureKV) * 17 + 20826, RISCV::FeatureStdExtZvksc, { { { 0x0ULL, 0x0ULL, 0x80000000000ULL, 0x80ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 16 + 20868, sizeof(SubtargetFeatureKV) * 16 + 20875, RISCV::FeatureStdExtZvksed, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 15 + 20916, sizeof(SubtargetFeatureKV) * 15 + 20922, RISCV::FeatureStdExtZvksg, { { { 0x0ULL, 0x0ULL, 0x8000000000000000ULL, 0x80ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 14 + 20964, sizeof(SubtargetFeatureKV) * 14 + 20970, RISCV::FeatureStdExtZvksh, { { { 0x0ULL, 0x0ULL, 0x800000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 13 + 21011, sizeof(SubtargetFeatureKV) * 13 + 21016, RISCV::FeatureStdExtZvkt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 12 + 21067, sizeof(SubtargetFeatureKV) * 12 + 21076, RISCV::FeatureStdExtZvl1024b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x20000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 11 + 21116, sizeof(SubtargetFeatureKV) * 11 + 21124, RISCV::FeatureStdExtZvl128b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x4000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 10 + 21162, sizeof(SubtargetFeatureKV) * 10 + 21172, RISCV::FeatureStdExtZvl16384b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x200000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 9 + 21214, sizeof(SubtargetFeatureKV) * 9 + 21223, RISCV::FeatureStdExtZvl2048b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x40000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 8 + 21263, sizeof(SubtargetFeatureKV) * 8 + 21271, RISCV::FeatureStdExtZvl256b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x8000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 7 + 21309, sizeof(SubtargetFeatureKV) * 7 + 21319, RISCV::FeatureStdExtZvl32768b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x400000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 6 + 21361, sizeof(SubtargetFeatureKV) * 6 + 21368, RISCV::FeatureStdExtZvl32b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 5 + 21404, sizeof(SubtargetFeatureKV) * 5 + 21413, RISCV::FeatureStdExtZvl4096b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x80000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 4 + 21453, sizeof(SubtargetFeatureKV) * 4 + 21461, RISCV::FeatureStdExtZvl512b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x10000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 3 + 21499, sizeof(SubtargetFeatureKV) * 3 + 21506, RISCV::FeatureStdExtZvl64b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x2000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 2 + 21542, sizeof(SubtargetFeatureKV) * 2 + 21552, RISCV::FeatureStdExtZvl65536b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, } } }   },
    { sizeof(SubtargetFeatureKV) * 1 + 21594, sizeof(SubtargetFeatureKV) * 1 + 21603, RISCV::FeatureStdExtZvl8192b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x100000ULL, 0x0ULL, 0x0ULL, } } }   },
  },
    "\000" "32bit\000Implements RV32\000" "64bit\000Implements RV64\000a\000"
    "'A' (Atomic Instructions)\000andes45\000Andes 45-Series processors\000b"
    "\000'B' (the collection of the Zba, Zbb, Zbs extensions)\000c\000'C' (C"
    "ompressed Instructions)\000conditional-cmv-fusion\000Enable branch+c.mv"
    " fusion\000d\000'D' (Double-Precision Floating-Point)\000disable-latenc"
    "y-sched-heuristic\000Disable latency scheduling heuristic\000disable-mi"
    "sched-load-clustering\000Disable load clustering in the machine schedul"
    "er\000disable-misched-store-clustering\000Disable store clustering in t"
    "he machine scheduler\000disable-postmisched-load-clustering\000Disable "
    "PostRA load clustering in the machine scheduler\000disable-postmisched-"
    "store-clustering\000Disable PostRA store clustering in the machine sche"
    "duler\000dlen-factor-2\000Vector unit DLEN(data path width) is half of "
    "VLEN\000e\000'E' (Embedded Instruction Set with 16 GPRs)\000enable-sele"
    "ct-opt\000Enable the select optimize pass for select loop heuristics\000"
    "enable-vsetvli-sched-heuristic\000Enable vsetvli-based scheduling heuri"
    "stic\000exact-asm\000Enable Exact Assembly (Disables Compression and Re"
    "laxation)\000experimental\000Experimental intrinsics\000experimental-p\000"
    "'P' ('Base P' (Packed SIMD))\000experimental-rvm23u32\000RISC-V experim"
    "ental-rvm23u32 profile\000experimental-smpmpmt\000'Smpmpmt' (PMP-based "
    "Memory Types Extension)\000experimental-svukte\000'Svukte' (Address-Ind"
    "ependent Latency of User-Mode Faults to Supervisor Addresses)\000experi"
    "mental-xqccmt\000'Xqccmt' (Qualcomm 16-bit Table Jump)\000experimental-"
    "xsfmclic\000'XSfmclic' (SiFive CLIC Machine-mode CSRs)\000experimental-"
    "xsfsclic\000'XSfsclic' (SiFive CLIC Supervisor-mode CSRs)\000experiment"
    "al-y\000'Y' ('Base Y' (CHERI))\000experimental-zibi\000'Zibi' (Branch w"
    "ith Immediate)\000experimental-zicfilp\000'Zicfilp' (Landing pad)\000ex"
    "perimental-zicfiss\000'Zicfiss' (Shadow stack)\000experimental-zvabd\000"
    "'Zvabd' (Vector Absolute Difference)\000experimental-zvbc32e\000'Zvbc32"
    "e' (Vector Carryless Multiplication with 32-bits elements)\000experimen"
    "tal-zvdot4a8i\000'Zvdot4a8i' (Vector 4-element Dot Product of packed 8-"
    "bit Integers)\000experimental-zvfbdota32f\000'Zvfbdota32f' (FP32 batche"
    "d dot-product extension)\000experimental-zvfbfa\000'Zvfbfa' (Additional"
    " BF16 vector compute support)\000experimental-zvfofp8min\000'Zvfofp8min"
    "' (Vector OFP8 Converts)\000experimental-zvfqwbdota8f\000'Zvfqwbdota8f'"
    " (OCP FP8 batched dot-product extension)\000experimental-zvfqwdota8f\000"
    "'Zvfqwdota8f' (OCP FP8 Dot-Product)\000experimental-zvfwbdota16bf\000'Z"
    "vfwbdota16bf' (BF16 batched dot-product extension)\000experimental-zvfw"
    "dota16bf\000'Zvfwdota16bf' (BF16 Dot-Product)\000experimental-zvkgs\000"
    "'Zvkgs' (Vector-Scalar GCM instructions for Cryptography)\000experiment"
    "al-zvqwbdota16i\000'Zvqwbdota16i' (16-bit integer batched dot-product e"
    "xtension)\000experimental-zvqwbdota8i\000'Zvqwbdota8i' (8-bit integer b"
    "atched dot-product extension)\000experimental-zvqwdota16i\000'Zvqwdota1"
    "6i' (16-bit Integer Dot-Product)\000experimental-zvqwdota8i\000'Zvqwdot"
    "a8i' (8-bit Integer Dot-Product)\000experimental-zvvfmm\000'Zvvfmm' (Fl"
    "oating-Point Matrix Multiply-Accumulate)\000experimental-zvvmm\000'Zvvm"
    "m' (Integer Matrix Multiply-Accumulate)\000experimental-zvvmtls\000'Zvv"
    "mtls' (Matrix Tile Load/Store)\000experimental-zvvmttls\000'Zvvmttls' ("
    "Transposing Matrix Tile Load/Store)\000experimental-zvzip\000'Zvzip' (V"
    "ector Reordering Structured Data)\000f\000'F' (Single-Precision Floatin"
    "g-Point)\000forced-atomics\000Assume that lock-free native-width atomic"
    "s are available\000fusion-add-load\000Enable ADD(.UW) + load macrofusio"
    "n\000fusion-add-mem\000Enable ADD+LOAD/STORE macrofusion\000fusion-addi"
    "-load\000Enable ADDI + load macrofusion\000fusion-auipc-addi\000Enable "
    "AUIPC+ADDI macrofusion\000fusion-auipc-load\000Enable AUIPC + load macr"
    "ofusion\000fusion-bfext\000Enable SLLI+SRLI (bitfield extract) macrofus"
    "ion\000fusion-ld-add\000Enable LD+ADD macrofusion\000fusion-logic-imm-r"
    "eg\000Enable ANDI/ORI/XORI+AND/OR/XOR macrofusion\000fusion-logic-reg-i"
    "mm\000Enable AND/OR/XOR+ANDI/ORI/XORI macrofusion\000fusion-logic-reg-r"
    "eg\000Enable AND/OR/XOR+AND/OR/XOR macrofusion\000fusion-lui-addi\000En"
    "able LUI+ADDI macro fusion\000fusion-lui-load\000Enable LUI + load macr"
    "ofusion\000fusion-mul-add\000Enable MUL+ADD macrofusion\000fusion-qc-e-"
    "li-load-store\000Enable QC.E.LI + Load/Store macrofusion\000fusion-shif"
    "t-bit-extract\000Enable SLLI+SRLI/SRAI macrofusion\000fusion-shifted-ze"
    "xtw\000Enable SLLI+SRLI to be fused when computing (shifted) word zero "
    "extension\000fusion-shxadd-load\000Enable SH(1|2|3)ADD(.UW) + load macr"
    "ofusion\000fusion-zexth\000Enable SLLI+SRLI to be fused to zero extensi"
    "on of halfword\000fusion-zextw\000Enable SLLI+SRLI to be fused to zero "
    "extension of word\000h\000'H' (Hypervisor)\000i\000'I' (Base Integer In"
    "struction Set)\000log-vrgather\000Has vrgather.vv with LMUL*log2(LMUL) "
    "latency\000m\000'M' (Integer Multiplication and Division)\000mips-p8700"
    "\000MIPS p8700 processor\000no-default-unroll\000Disable default unroll"
    " preference\000no-sink-splat-operands\000Disable sink splat operands to"
    " enable .vx, .vf,.wx, and .wf instructions\000no-trailing-seq-cst-fence"
    "\000Disable trailing fence for seq-cst store\000optimized-nf2-segment-l"
    "oad-store\000vlseg2eN.v and vsseg2eN.v are implemented as a wide memory"
    " op and shuffle\000optimized-nf3-segment-load-store\000vlseg3eN.v and v"
    "sseg3eN.v are implemented as a wide memory op and shuffle\000optimized-"
    "nf4-segment-load-store\000vlseg4eN.v and vsseg4eN.v are implemented as "
    "a wide memory op and shuffle\000optimized-nf5-segment-load-store\000vls"
    "eg5eN.v and vsseg5eN.v are implemented as a wide memory op and shuffle\000"
    "optimized-nf6-segment-load-store\000vlseg6eN.v and vsseg6eN.v are imple"
    "mented as a wide memory op and shuffle\000optimized-nf7-segment-load-st"
    "ore\000vlseg7eN.v and vsseg7eN.v are implemented as a wide memory op an"
    "d shuffle\000optimized-nf8-segment-load-store\000vlseg8eN.v and vsseg8e"
    "N.v are implemented as a wide memory op and shuffle\000optimized-zero-s"
    "tride-load\000Optimized (perform fewer memory operations)zero-stride ve"
    "ctor load\000permissive-zalrsc\000Implementation permits non-base instr"
    "uctions between LR/SC pairs\000predictable-select-expensive\000Prefer l"
    "ikely predicted branches over selects\000prefer-ascending-load-store\000"
    "Prefer ascending load/store order for better clustering and performance"
    "\000prefer-vsetvli-over-read-vlenb\000Prefer vsetvli over read vlenb CS"
    "R to calculate VLEN\000prefer-w-inst\000Prefer instructions with W suff"
    "ix\000q\000'Q' (Quad-Precision Floating-Point)\000relax\000Enable Linke"
    "r relaxation\000reserve-x1\000Reserve X1\000reserve-x10\000Reserve X10\000"
    "reserve-x11\000Reserve X11\000reserve-x12\000Reserve X12\000reserve-x13"
    "\000Reserve X13\000reserve-x14\000Reserve X14\000reserve-x15\000Reserve"
    " X15\000reserve-x16\000Reserve X16\000reserve-x17\000Reserve X17\000res"
    "erve-x18\000Reserve X18\000reserve-x19\000Reserve X19\000reserve-x2\000"
    "Reserve X2\000reserve-x20\000Reserve X20\000reserve-x21\000Reserve X21\000"
    "reserve-x22\000Reserve X22\000reserve-x23\000Reserve X23\000reserve-x24"
    "\000Reserve X24\000reserve-x25\000Reserve X25\000reserve-x26\000Reserve"
    " X26\000reserve-x27\000Reserve X27\000reserve-x28\000Reserve X28\000res"
    "erve-x29\000Reserve X29\000reserve-x3\000Reserve X3\000reserve-x30\000R"
    "eserve X30\000reserve-x31\000Reserve X31\000reserve-x4\000Reserve X4\000"
    "reserve-x5\000Reserve X5\000reserve-x6\000Reserve X6\000reserve-x7\000R"
    "eserve X7\000reserve-x8\000Reserve X8\000reserve-x9\000Reserve X9\000rv"
    "a20s64\000RISC-V rva20s64 profile\000rva20u64\000RISC-V rva20u64 profil"
    "e\000rva22s64\000RISC-V rva22s64 profile\000rva22u64\000RISC-V rva22u64"
    " profile\000rva23s64\000RISC-V rva23s64 profile\000rva23u64\000RISC-V r"
    "va23u64 profile\000rvb23s64\000RISC-V rvb23s64 profile\000rvb23u64\000R"
    "ISC-V rvb23u64 profile\000rvi20u32\000RISC-V rvi20u32 profile\000rvi20u"
    "64\000RISC-V rvi20u64 profile\000save-restore\000Enable save/restore\000"
    "sdext\000'Sdext' (External debugger)\000sdtrig\000'Sdtrig' (Debugger tr"
    "iggers)\000sha\000'Sha' (Augmented Hypervisor)\000shcounterenw\000'Shco"
    "unterenw' (Support writeable hcounteren enable bit for any hpmcounter t"
    "hat is not read-only zero)\000shgatpa\000'Shgatpa' (SvNNx4 mode support"
    "ed for all modes supported by satp, as well as Bare)\000shlcofideleg\000"
    "'Shlcofideleg' (Delegating LCOFI Interrupts to VS-mode)\000short-forwar"
    "d-branch-ialu\000Enable short forward branch optimization for RVI base "
    "instructions\000short-forward-branch-iload\000Enable short forward bran"
    "ch optimization for load instructions\000short-forward-branch-iminmax\000"
    "Enable short forward branch optimization for MIN,MAX instructions in Zb"
    "b\000short-forward-branch-imm\000Enable short forward branch optimizati"
    "on for branches with immediates\000short-forward-branch-imul\000Enable "
    "short forward branch optimization for MUL instruction\000shtvala\000'Sh"
    "tvala' (htval provides all needed values)\000shvsatpa\000'Shvsatpa' (vs"
    "atp supports all modes supported by satp)\000shvstvala\000'Shvstvala' ("
    "vstval provides all needed values)\000shvstvecd\000'Shvstvecd' (vstvec "
    "supports Direct mode)\000sifive7\000SiFive 7-Series processors\000singl"
    "e-element-vec-fp64\000Certain vector FP64 operations produce a single r"
    "esult element per cycle\000smaia\000'Smaia' (Advanced Interrupt Archite"
    "cture Machine Level)\000smcdeleg\000'Smcdeleg' (Counter Delegation Mach"
    "ine Level)\000smcntrpmf\000'Smcntrpmf' (Cycle and Instret Privilege Mod"
    "e Filtering)\000smcsrind\000'Smcsrind' (Indirect CSR Access Machine Lev"
    "el)\000smctr\000'Smctr' (Control Transfer Records Machine Level)\000smd"
    "bltrp\000'Smdbltrp' (Double Trap Machine Level)\000smepmp\000'Smepmp' ("
    "Enhanced Physical Memory Protection)\000smmpm\000'Smmpm' (Machine-level"
    " Pointer Masking for M-mode)\000smnpm\000'Smnpm' (Machine-level Pointer"
    " Masking for next lower privilege mode)\000smrnmi\000'Smrnmi' (Resumabl"
    "e Non-Maskable Interrupts)\000smstateen\000'Smstateen' (Machine-mode vi"
    "ew of the state-enable extension)\000ssaia\000'Ssaia' (Advanced Interru"
    "pt Architecture Supervisor Level)\000ssccfg\000'Ssccfg' (Counter Config"
    "uration Supervisor Level)\000ssccptr\000'Ssccptr' (Main memory supports"
    " page table reads)\000sscofpmf\000'Sscofpmf' (Count Overflow and Mode-B"
    "ased Filtering)\000sscounterenw\000'Sscounterenw' (Support writeable sc"
    "ounteren enable bit for any hpmcounter that is not read-only zero)\000s"
    "scsrind\000'Sscsrind' (Indirect CSR Access Supervisor Level)\000ssctr\000"
    "'Ssctr' (Control Transfer Records Supervisor Level)\000ssdbltrp\000'Ssd"
    "bltrp' (Double Trap Supervisor Level)\000ssnpm\000'Ssnpm' (Supervisor-l"
    "evel Pointer Masking for next lower privilege mode)\000sspm\000'Sspm' ("
    "Indicates Supervisor-mode Pointer Masking)\000ssqosid\000'Ssqosid' (Qua"
    "lity-of-Service (QoS) Identifiers)\000ssstateen\000'Ssstateen' (Supervi"
    "sor-mode view of the state-enable extension)\000ssstrict\000'Ssstrict' "
    "(No non-conforming extensions are present)\000sstc\000'Sstc' (Superviso"
    "r-mode timer interrupts)\000sstvala\000'Sstvala' (stval provides all ne"
    "eded values)\000sstvecd\000'Sstvecd' (stvec supports Direct mode)\000ss"
    "u64xl\000'Ssu64xl' (UXLEN=64 supported)\000supm\000'Supm' (Indicates Us"
    "er-mode Pointer Masking)\000svade\000'Svade' (Raise exceptions on impro"
    "per A/D bits)\000svadu\000'Svadu' (Hardware A/D updates)\000svbare\000'"
    "Svbare' (satp mode Bare supported)\000svinval\000'Svinval' (Fine-Graine"
    "d Address-Translation Cache Invalidation)\000svnapot\000'Svnapot' (NAPO"
    "T Translation Contiguity)\000svpbmt\000'Svpbmt' (Page-Based Memory Type"
    "s)\000svrsw60t59b\000'Svrsw60t59b' (PTE Reserved-for-Software Bits 60-5"
    "9)\000svvptc\000'Svvptc' (Obviating Memory-Management Instructions afte"
    "r Marking PTEs Valid)\000tagged-globals\000Use an instruction sequence "
    "for taking the address of a global that allows a memory tag in the uppe"
    "r address bits\000unaligned-scalar-mem\000Has reasonably performant una"
    "ligned scalar loads and stores\000unaligned-vector-mem\000Has reasonabl"
    "y performant unaligned vector loads and stores\000use-postra-scheduler\000"
    "Schedule again after register allocation\000v\000'V' (Vector Extension "
    "for Application Processors)\000ventana-veyron\000Ventana Veyron-Series "
    "processors\000vl-dependent-latency\000Latency of vector instructions is"
    " dependent on the dynamic value of vl\000vxrm-pipeline-flush\000VXRM wr"
    "ites causes pipeline flush\000xaifet\000'XAIFET' (AI Foundry ET Extensi"
    "on)\000xandesbfhcvt\000'XAndesBFHCvt' (Andes Scalar BFLOAT16 Conversion"
    " Extension)\000xandesperf\000'XAndesPerf' (Andes Performance Extension)"
    "\000xandesvbfhcvt\000'XAndesVBFHCvt' (Andes Vector BFLOAT16 Conversion "
    "Extension)\000xandesvdot\000'XAndesVDot' (Andes Vector Dot Product Exte"
    "nsion)\000xandesvpackfph\000'XAndesVPackFPH' (Andes Vector Packed FP16 "
    "Extension)\000xandesvsinth\000'XAndesVSIntH' (Andes Vector Small INT Ha"
    "ndling Extension)\000xandesvsintload\000'XAndesVSIntLoad' (Andes Vector"
    " INT4 Load Extension)\000xcheriot\000'XCheriot' (CHERIoT extension)\000"
    "xcvalu\000'XCValu' (CORE-V ALU Operations)\000xcvbi\000'XCVbi' (CORE-V "
    "Immediate Branching)\000xcvbitmanip\000'XCVbitmanip' (CORE-V Bit Manipu"
    "lation)\000xcvelw\000'XCVelw' (CORE-V Event Load Word)\000xcvmac\000'XC"
    "Vmac' (CORE-V Multiply-Accumulate)\000xcvmem\000'XCVmem' (CORE-V Post-i"
    "ncrementing Load & Store)\000xcvsimd\000'XCVsimd' (CORE-V SIMD ALU)\000"
    "xmipscbop\000'XMIPSCBOP' (MIPS Software Prefetch)\000xmipscmov\000'XMIP"
    "SCMov' (MIPS conditional move instruction (mips.ccmov))\000xmipsexectl\000"
    "'XMIPSEXECTL' (MIPS execution control)\000xmipslsp\000'XMIPSLSP' (MIPS "
    "optimization for hardware load-store bonding)\000xqccmp\000'Xqccmp' (Qu"
    "alcomm 16-bit Push/Pop and Double Moves)\000xqci\000'Xqci' (Qualcomm uC"
    " Extension)\000xqcia\000'Xqcia' (Qualcomm uC Arithmetic Extension)\000x"
    "qciac\000'Xqciac' (Qualcomm uC Load-Store Address Calculation Extension"
    ")\000xqcibi\000'Xqcibi' (Qualcomm uC Branch Immediate Extension)\000xqc"
    "ibm\000'Xqcibm' (Qualcomm uC Bit Manipulation Extension)\000xqcicli\000"
    "'Xqcicli' (Qualcomm uC Conditional Load Immediate Extension)\000xqcicm\000"
    "'Xqcicm' (Qualcomm uC Conditional Move Extension)\000xqcics\000'Xqcics'"
    " (Qualcomm uC Conditional Select Extension)\000xqcicsr\000'Xqcicsr' (Qu"
    "alcomm uC CSR Extension)\000xqciint\000'Xqciint' (Qualcomm uC Interrupt"
    "s Extension)\000xqciio\000'Xqciio' (Qualcomm uC External Input Output E"
    "xtension)\000xqcilb\000'Xqcilb' (Qualcomm uC Long Branch Extension)\000"
    "xqcili\000'Xqcili' (Qualcomm uC Load Large Immediate Extension)\000xqci"
    "lia\000'Xqcilia' (Qualcomm uC Large Immediate Arithmetic Extension)\000"
    "xqcilo\000'Xqcilo' (Qualcomm uC Large Offset Load Store Extension)\000x"
    "qcilsm\000'Xqcilsm' (Qualcomm uC Load Store Multiple Extension)\000xqci"
    "sim\000'Xqcisim' (Qualcomm uC Simulation Hint Extension)\000xqcisls\000"
    "'Xqcisls' (Qualcomm uC Scaled Load Store Extension)\000xqcisync\000'Xqc"
    "isync' (Qualcomm uC Sync Delay Extension)\000xsfcease\000'XSfcease' (Si"
    "Five sf.cease Instruction)\000xsfmm128t\000'XSfmm128t' (TE=128 configur"
    "ation)\000xsfmm16t\000'XSfmm16t' (TE=16 configuration)\000xsfmm32a\000'"
    "XSfmm32a' (TEW=32-bit accumulation operands - int: 8b; float: fp16, bf1"
    "6, fp32)\000xsfmm32a16f\000'XSfmm32a16f' (TEW=32-bit accumulation, oper"
    "ands - float: 16b, widen=2 (IEEE, BF))\000xsfmm32a32f\000'XSfmm32a32f' "
    "(TEW=32-bit accumulation, operands - float: 32b)\000xsfmm32a8f\000'XSfm"
    "m32a8f' (TEW=32-bit accumulation, operands - float: fp8)\000xsfmm32a8i\000"
    "'XSfmm32a8i' (TEW=32-bit accumulation, operands - int: 8b)\000xsfmm32t\000"
    "'XSfmm32t' (TE=32 configuration)\000xsfmm64a64f\000'XSfmm64a64f' (TEW=6"
    "4-bit accumulation, operands - float: fp64)\000xsfmm64t\000'XSfmm64t' ("
    "TE=64 configuration)\000xsfmmbase\000'XSfmmbase' (All non arithmetic in"
    "structions for all TEWs and sf.vtzero)\000xsfvcp\000'XSfvcp' (SiFive Cu"
    "stom Vector Coprocessor Interface Instructions)\000xsfvfbfexp16e\000'XS"
    "fvfbfexp16e' (SiFive Vector Floating-Point Exponential Function Instruc"
    "tion, BFloat16)\000xsfvfexp16e\000'XSfvfexp16e' (SiFive Vector Floating"
    "-Point Exponential Function Instruction, Half Precision)\000xsfvfexp32e"
    "\000'XSfvfexp32e' (SiFive Vector Floating-Point Exponential Function In"
    "struction, Single Precision)\000xsfvfexpa\000'XSfvfexpa' (SiFive Vector"
    " Floating-Point Exponential Approximation Instruction)\000xsfvfexpa64e\000"
    "'XSfvfexpa64e' (SiFive Vector Floating-Point Exponential Approximation "
    "Instruction with Double-Precision)\000xsfvfnrclipxfqf\000'XSfvfnrclipxf"
    "qf' (SiFive FP32-to-int8 Ranged Clip Instructions)\000xsfvfwmaccqqq\000"
    "'XSfvfwmaccqqq' (SiFive Matrix Multiply Accumulate Instruction (4-by-4)"
    ")\000xsfvqmaccdod\000'XSfvqmaccdod' (SiFive Int8 Matrix Multiplication "
    "Instructions (2-by-8 and 8-by-2))\000xsfvqmaccqoq\000'XSfvqmaccqoq' (Si"
    "Five Int8 Matrix Multiplication Instructions (4-by-8 and 8-by-4))\000xs"
    "ifivecdiscarddlone\000'XSiFivecdiscarddlone' (SiFive sf.cdiscard.d.l1 I"
    "nstruction)\000xsifivecflushdlone\000'XSiFivecflushdlone' (SiFive sf.cf"
    "lush.d.l1 Instruction)\000xsmtvdot\000'XSMTVDot' (SpacemiT Vector Dot P"
    "roduct Extension)\000xsmtvdotii\000'XSMTVDotII' (SpacemiT Vector Extens"
    "ion for Matrix 2.0)\000xtheadba\000'XTHeadBa' (T-Head address calculati"
    "on instructions)\000xtheadbb\000'XTHeadBb' (T-Head basic bit-manipulati"
    "on instructions)\000xtheadbs\000'XTHeadBs' (T-Head single-bit instructi"
    "ons)\000xtheadcmo\000'XTHeadCmo' (T-Head cache management instructions)"
    "\000xtheadcondmov\000'XTHeadCondMov' (T-Head conditional move instructi"
    "ons)\000xtheadfmemidx\000'XTHeadFMemIdx' (T-Head FP Indexed Memory Oper"
    "ations)\000xtheadmac\000'XTHeadMac' (T-Head Multiply-Accumulate Instruc"
    "tions)\000xtheadmemidx\000'XTHeadMemIdx' (T-Head Indexed Memory Operati"
    "ons)\000xtheadmempair\000'XTHeadMemPair' (T-Head two-GPR Memory Operati"
    "ons)\000xtheadsync\000'XTHeadSync' (T-Head multicore synchronization in"
    "structions)\000xtheadvdot\000'XTHeadVdot' (T-Head Vector Extensions for"
    " Dot)\000xventanacondops\000'XVentanaCondOps' (Ventana Conditional Ops)"
    "\000xwchc\000'Xwchc' (WCH/QingKe additional compressed opcodes)\000za12"
    "8rs\000'Za128rs' (Reservation Set Size of at Most 128 Bytes)\000za64rs\000"
    "'Za64rs' (Reservation Set Size of at Most 64 Bytes)\000zaamo\000'Zaamo'"
    " (Atomic Memory Operations)\000zabha\000'Zabha' (Byte and Halfword Atom"
    "ic Memory Operations)\000zacas\000'Zacas' (Atomic Compare-And-Swap Inst"
    "ructions)\000zalasr\000'Zalasr' (Load-Acquire and Store-Release Instruc"
    "tions)\000zalrsc\000'Zalrsc' (Load-Reserved/Store-Conditional)\000zama1"
    "6b\000'Zama16b' (Atomic 16-byte misaligned loads, stores and AMOs)\000z"
    "awrs\000'Zawrs' (Wait on Reservation Set)\000zba\000'Zba' (Address Gene"
    "ration Instructions)\000zbb\000'Zbb' (Basic Bit-Manipulation)\000zbc\000"
    "'Zbc' (Carry-Less Multiplication)\000zbkb\000'Zbkb' (Bitmanip instructi"
    "ons for Cryptography)\000zbkc\000'Zbkc' (Carry-less multiply instructio"
    "ns for Cryptography)\000zbkx\000'Zbkx' (Crossbar permutation instructio"
    "ns)\000zbs\000'Zbs' (Single-Bit Instructions)\000zca\000'Zca' (part of "
    "the C extension, excluding compressed floating point loads/stores)\000z"
    "cb\000'Zcb' (Compressed basic bit manipulation instructions)\000zcd\000"
    "'Zcd' (Compressed Double-Precision Floating-Point Instructions)\000zce\000"
    "'Zce' (Compressed extensions for microcontrollers)\000zcf\000'Zcf' (Com"
    "pressed Single-Precision Floating-Point Instructions)\000zclsd\000'Zcls"
    "d' (Compressed Load/Store Pair Instructions)\000zcmop\000'Zcmop' (Compr"
    "essed May-Be-Operations)\000zcmp\000'Zcmp' (sequenced instructions for "
    "code-size reduction)\000zcmt\000'Zcmt' (table jump instructions for cod"
    "e-size reduction)\000zdinx\000'Zdinx' (Double in Integer)\000zfa\000'Zf"
    "a' (Additional Floating-Point)\000zfbfmin\000'Zfbfmin' (Scalar BF16 Con"
    "verts)\000zfh\000'Zfh' (Half-Precision Floating-Point)\000zfhmin\000'Zf"
    "hmin' (Half-Precision Floating-Point Minimal)\000zfinx\000'Zfinx' (Floa"
    "t in Integer)\000zhinx\000'Zhinx' (Half Float in Integer)\000zhinxmin\000"
    "'Zhinxmin' (Half Float in Integer Minimal)\000zic64b\000'Zic64b' (Cache"
    " Block Size Is 64 Bytes)\000zicbom\000'Zicbom' (Cache-Block Management "
    "Instructions)\000zicbop\000'Zicbop' (Cache-Block Prefetch Instructions)"
    "\000zicboz\000'Zicboz' (Cache-Block Zero Instructions)\000ziccamoa\000'"
    "Ziccamoa' (Main Memory Supports All Atomics in A)\000ziccamoc\000'Zicca"
    "moc' (Main Memory Supports Atomics in Zacas)\000ziccid\000'Ziccid' (Ins"
    "truction/Data Coherence and Consistency)\000ziccif\000'Ziccif' (Main Me"
    "mory Supports Instruction Fetch with Atomicity Requirement)\000zicclsm\000"
    "'Zicclsm' (Main Memory Supports Misaligned Loads/Stores)\000ziccrse\000"
    "'Ziccrse' (Main Memory Supports Forward Progress on LR/SC Sequences)\000"
    "zicntr\000'Zicntr' (Base Counters and Timers)\000zicond\000'Zicond' (In"
    "teger Conditional Operations)\000zicsr\000'Zicsr' (CSRs)\000zifencei\000"
    "'Zifencei' (fence.i)\000zihintntl\000'Zihintntl' (Non-Temporal Locality"
    " Hints)\000zihintpause\000'Zihintpause' (Pause Hint)\000zihpm\000'Zihpm"
    "' (Hardware Performance Counters)\000zilsd\000'Zilsd' (Load/Store Pair "
    "Instructions)\000zilsd-word-align\000Allow 4-byte alignment for Zilsd L"
    "D/SD instructions\000zimop\000'Zimop' (May-Be-Operations)\000zk\000'Zk'"
    " (Standard scalar cryptography extension)\000zkn\000'Zkn' (NIST Algorit"
    "hm Suite)\000zknd\000'Zknd' (NIST Suite: AES Decryption)\000zkne\000'Zk"
    "ne' (NIST Suite: AES Encryption)\000zknh\000'Zknh' (NIST Suite: Hash Fu"
    "nction Instructions)\000zkr\000'Zkr' (Entropy Source Extension)\000zks\000"
    "'Zks' (ShangMi Algorithm Suite)\000zksed\000'Zksed' (ShangMi Suite: SM4"
    " Block Cipher Instructions)\000zksh\000'Zksh' (ShangMi Suite: SM3 Hash "
    "Function Instructions)\000zkt\000'Zkt' (Data Independent Execution Late"
    "ncy)\000zmmul\000'Zmmul' (Integer Multiplication)\000ztso\000'Ztso' (Me"
    "mory Model - Total Store Order)\000zvbb\000'Zvbb' (Vector basic bit-man"
    "ipulation instructions)\000zvbc\000'Zvbc' (Vector Carryless Multiplicat"
    "ion)\000zve32f\000'Zve32f' (Vector Extensions for Embedded Processors w"
    "ith maximal 32 EEW and F extension)\000zve32x\000'Zve32x' (Vector Exten"
    "sions for Embedded Processors with maximal 32 EEW)\000zve64d\000'Zve64d"
    "' (Vector Extensions for Embedded Processors with maximal 64 EEW, F and"
    " D extension)\000zve64f\000'Zve64f' (Vector Extensions for Embedded Pro"
    "cessors with maximal 64 EEW and F extension)\000zve64x\000'Zve64x' (Vec"
    "tor Extensions for Embedded Processors with maximal 64 EEW)\000zvfbfmin"
    "\000'Zvfbfmin' (Vector BF16 Converts)\000zvfbfwma\000'Zvfbfwma' (Vector"
    " BF16 widening mul-add)\000zvfh\000'Zvfh' (Vector Half-Precision Floati"
    "ng-Point)\000zvfhmin\000'Zvfhmin' (Vector Half-Precision Floating-Point"
    " Minimal)\000zvkb\000'Zvkb' (Vector Bit-manipulation used in Cryptograp"
    "hy)\000zvkg\000'Zvkg' (Vector GCM instructions for Cryptography)\000zvk"
    "n\000'Zvkn' (shorthand for 'Zvkned', 'Zvknhb', 'Zvkb', and 'Zvkt')\000z"
    "vknc\000'Zvknc' (shorthand for 'Zvknc' and 'Zvbc')\000zvkned\000'Zvkned"
    "' (Vector AES Encryption & Decryption (Single Round))\000zvkng\000'Zvkn"
    "g' (shorthand for 'Zvkn' and 'Zvkg')\000zvknha\000'Zvknha' (Vector SHA-"
    "2 (SHA-256 only))\000zvknhb\000'Zvknhb' (Vector SHA-2 (SHA-256 and SHA-"
    "512))\000zvks\000'Zvks' (shorthand for 'Zvksed', 'Zvksh', 'Zvkb', and '"
    "Zvkt')\000zvksc\000'Zvksc' (shorthand for 'Zvks' and 'Zvbc')\000zvksed\000"
    "'Zvksed' (SM4 Block Cipher Instructions)\000zvksg\000'Zvksg' (shorthand"
    " for 'Zvks' and 'Zvkg')\000zvksh\000'Zvksh' (SM3 Hash Function Instruct"
    "ions)\000zvkt\000'Zvkt' (Vector Data-Independent Execution Latency)\000"
    "zvl1024b\000'Zvl1024b' (Minimum Vector Length 1024)\000zvl128b\000'Zvl1"
    "28b' (Minimum Vector Length 128)\000zvl16384b\000'Zvl16384b' (Minimum V"
    "ector Length 16384)\000zvl2048b\000'Zvl2048b' (Minimum Vector Length 20"
    "48)\000zvl256b\000'Zvl256b' (Minimum Vector Length 256)\000zvl32768b\000"
    "'Zvl32768b' (Minimum Vector Length 32768)\000zvl32b\000'Zvl32b' (Minimu"
    "m Vector Length 32)\000zvl4096b\000'Zvl4096b' (Minimum Vector Length 40"
    "96)\000zvl512b\000'Zvl512b' (Minimum Vector Length 512)\000zvl64b\000'Z"
    "vl64b' (Minimum Vector Length 64)\000zvl65536b\000'Zvl65536b' (Minimum "
    "Vector Length 65536)\000zvl8192b\000'Zvl8192b' (Minimum Vector Length 8"
    "192)\000"};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetSubTypeKVStorage< 59, 768> RISCVSubTypeKVStorage = {
  {
   { sizeof(SubtargetSubTypeKV) * 59 + 1, { { { 0x1240000000004ULL, 0x0ULL, 0x0ULL, 0x2000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 58 + 11, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1010040000080ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 57 + 27, { { { 0x1ad0000000002ULL, 0x0ULL, 0xc00000ULL, 0x8000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 56 + 37, { { { 0x1ad0000000002ULL, 0x0ULL, 0xc00000ULL, 0x8000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1010040000080ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 55 + 47, { { { 0x1ad0000000004ULL, 0x0ULL, 0xc00000ULL, 0x8000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 54 + 58, { { { 0x1ad0000000004ULL, 0x0ULL, 0xc00000ULL, 0x8000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1010040000080ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 53 + 69, { { { 0x1ad0000000004ULL, 0x1000000000ULL, 0xc00000ULL, 0x8000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1010040000080ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 52 + 83, { { { 0x1ad0000000002ULL, 0x0ULL, 0xc00000ULL, 0x8000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1010040000080ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 51 + 93, { { { 0x1ad0000000004ULL, 0x0ULL, 0xc00000ULL, 0x8000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1010040000080ULL, } } }, 1 },
   { sizeof(SubtargetSubTypeKV) * 50 + 104, { { { 0x1240000000004ULL, 0x0ULL, 0x0ULL, 0x2000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 49 + 112, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 48 + 120, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 47 + 132, { { { 0x800000000002ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x100010000ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 46 + 145, { { { 0x800000000004ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x100010000ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 45 + 158, { { { 0x1ad0000000004ULL, 0x1800000000000ULL, 0xc00000ULL, 0x1e0000000000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x10000000ULL, } } }, 4 },
   { sizeof(SubtargetSubTypeKV) * 44 + 169, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 43 + 176, { { { 0x800000000002ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 42 + 188, { { { 0x800000000004ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 41 + 200, { { { 0x1850000000002ULL, 0x20a5800000000000ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 40 + 215, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x21010040000000ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 39 + 231, { { { 0x1840000000002ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 38 + 242, { { { 0x1850000000002ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 37 + 253, { { { 0x1a50000000002ULL, 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 36 + 264, { { { 0x1850000000002ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 35 + 275, { { { 0x1a50000000002ULL, 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 34 + 286, { { { 0x1a50000000002ULL, 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x21010040000000ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 33 + 297, { { { 0x1af0000000004ULL, 0x4000000000ULL, 0x4007c39f08ULL, 0x1800000000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x10044000220ULL, } } }, 7 },
   { sizeof(SubtargetSubTypeKV) * 32 + 309, { { { 0x1af0000000004ULL, 0x5000000000ULL, 0x44007c39f08ULL, 0x1800008514ULL, 0x180000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x800100c4000220ULL, } } }, 7 },
   { sizeof(SubtargetSubTypeKV) * 31 + 321, { { { 0x1ad0000000004ULL, 0x1800000000000ULL, 0x800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x10044010220ULL, } } }, 8 },
   { sizeof(SubtargetSubTypeKV) * 30 + 333, { { { 0x1af0000000004ULL, 0x5000000000ULL, 0x44007c39f08ULL, 0x1800008514ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x800100c4000220ULL, } } }, 9 },
   { sizeof(SubtargetSubTypeKV) * 29 + 345, { { { 0x1af0000000004ULL, 0x1080605004000000ULL, 0x1e0044417f39f0dULL, 0x1800009514ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x800100c4000220ULL, } } }, 10 },
   { sizeof(SubtargetSubTypeKV) * 28 + 359, { { { 0x1850000000004ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 27 + 370, { { { 0x1850000000004ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 26 + 381, { { { 0x1ad0000000004ULL, 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 25 + 392, { { { 0x1ad0000000004ULL, 0x0ULL, 0x2800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x21010040000000ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 24 + 403, { { { 0x1ad0000000004ULL, 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, 5 },
   { sizeof(SubtargetSubTypeKV) * 23 + 414, { { { 0x1ad0000000004ULL, 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x21010040000000ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 22 + 425, { { { 0x1a70000000002ULL, 0x7680400000000000ULL, 0xf0e44017a40e07ULL, 0x800000000009000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x61018140000400ULL, } } }, 11 },
   { sizeof(SubtargetSubTypeKV) * 21 + 437, { { { 0x1af0000000004ULL, 0x1180405000000000ULL, 0x40f0244017a69f07ULL, 0x800000000009000ULL, 0x103c00ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x61018140000400ULL, } } }, 11 },
   { sizeof(SubtargetSubTypeKV) * 20 + 449, { { { 0x1ad0000000004ULL, 0x1801000000000ULL, 0x80000000800004ULL, 0x20000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x61018140000400ULL, } } }, 6 },
   { sizeof(SubtargetSubTypeKV) * 19 + 461, { { { 0x1af0000000004ULL, 0x1080405000000000ULL, 0xe0044417be9f05ULL, 0x41000ULL, 0x180000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x61018141000400ULL, } } }, 12 },
   { sizeof(SubtargetSubTypeKV) * 18 + 473, { { { 0x1af0000000004ULL, 0x108a4051efc63928ULL, 0x1c00c4017f39f0fULL, 0x400000800041530ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x80000700000400ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 17 + 487, { { { 0x21af0000000004ULL, 0x108a4051efc63928ULL, 0x1c00c4017f39f0fULL, 0x200000800011530ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x80000740fc0400ULL, } } }, 13 },
   { sizeof(SubtargetSubTypeKV) * 16 + 501, { { { 0x1af0000000004ULL, 0xa0051e9c03800ULL, 0x80004006f39f0cULL, 0x200000800011000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x80040700010400ULL, } } }, 3 },
   { sizeof(SubtargetSubTypeKV) * 15 + 514, { { { 0x840000000002ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x40000000ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 14 + 534, { { { 0x1840000000002ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x40000000ULL, } } }, 14 },
   { sizeof(SubtargetSubTypeKV) * 13 + 553, { { { 0x1840000000002ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x10040000000ULL, } } }, 15 },
   { sizeof(SubtargetSubTypeKV) * 12 + 573, { { { 0x1850000000004ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x10040000000ULL, } } }, 16 },
   { sizeof(SubtargetSubTypeKV) * 11 + 593, { { { 0x1ac0000000002ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x10040000000ULL, } } }, 17 },
   { sizeof(SubtargetSubTypeKV) * 10 + 613, { { { 0x1ad0000000004ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x10040000000ULL, } } }, 18 },
   { sizeof(SubtargetSubTypeKV) * 9 + 633, { { { 0x1ad0000000002ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x10040000000ULL, } } }, 19 },
   { sizeof(SubtargetSubTypeKV) * 8 + 653, { { { 0x1ad0000000004ULL, 0x0ULL, 0xc00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x10040000000ULL, } } }, 20 },
   { sizeof(SubtargetSubTypeKV) * 7 + 673, { { { 0x1ad0000000004ULL, 0x23801000000000ULL, 0x40c00000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x10040000000ULL, } } }, 21 },
   { sizeof(SubtargetSubTypeKV) * 6 + 688, { { { 0x2021af0000000004ULL, 0x10804051efe23bb0ULL, 0x1e00c4417f39f0fULL, 0x1800011010ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x1ff60000000ULL, } } }, 22 },
   { sizeof(SubtargetSubTypeKV) * 5 + 701, { { { 0x1ad0000000004ULL, 0x23800000000000ULL, 0x6d00e00ULL, 0x0ULL, 0x100000000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x70080000c00d070ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 4 + 711, { { { 0x2021af0000000004ULL, 0x10824451efe77bb5ULL, 0x180044857f39f0dULL, 0x9000ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x600800040000000ULL, } } }, 0 },
   { sizeof(SubtargetSubTypeKV) * 3 + 731, { { { 0x1ad0000000004ULL, 0x23800040000000ULL, 0x3040c00a00ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x600800040000000ULL, } } }, 23 },
   { sizeof(SubtargetSubTypeKV) * 2 + 747, { { { 0x1af0000000004ULL, 0x11c24041ebc03800ULL, 0x4017f39f07ULL, 0x800000000ULL, 0x7fe00000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x80010000000000ULL, } } }, 2 },
   { sizeof(SubtargetSubTypeKV) * 1 + 757, { { { 0x1af0000000004ULL, 0x11c24051ebc03800ULL, 0xe0004017f29f07ULL, 0x800000000ULL, 0xffe00000ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x80010000000000ULL, } } }, 2 },
  },
    "\000an-erbium\000andes-45-series\000andes-a25\000andes-a45\000andes-ax2"
    "5\000andes-ax45\000andes-ax45mpv\000andes-n45\000andes-nx45\000et-soc1\000"
    "generic\000generic-ooo\000generic-rv32\000generic-rv64\000mips-p8700\000"
    "rocket\000rocket-rv32\000rocket-rv64\000rp2350-hazard3\000sifive-7-seri"
    "es\000sifive-e20\000sifive-e21\000sifive-e24\000sifive-e31\000sifive-e3"
    "4\000sifive-e76\000sifive-p450\000sifive-p470\000sifive-p550\000sifive-"
    "p670\000sifive-p870-d\000sifive-s21\000sifive-s51\000sifive-s54\000sifi"
    "ve-s76\000sifive-u54\000sifive-u74\000sifive-x160\000sifive-x180\000sif"
    "ive-x280\000sifive-x390\000spacemit-a100\000spacemit-x100\000spacemit-x"
    "60\000syntacore-scr1-base\000syntacore-scr1-max\000syntacore-scr3-rv32\000"
    "syntacore-scr3-rv64\000syntacore-scr4-rv32\000syntacore-scr4-rv64\000sy"
    "ntacore-scr5-rv32\000syntacore-scr5-rv64\000syntacore-scr7\000tt-ascalo"
    "n-x\000veyron-v1\000xiangshan-kunminghu\000xiangshan-nanhu\000xt-c910v2"
    "\000xt-c920v2\000"};

namespace RISCV_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID) {
  switch (SchedClass) {
  case 751: // WriteVFALUF_M1_E64_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5825; // VLEN512SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
      return 5826; // VLEN512SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5827; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
      return 5828; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5829; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
      return 5830; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
    }
    break;
  case 752: // WriteVFALUF_M1_E64_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5831; // VLEN512SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
      return 5832; // VLEN512SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5833; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
      return 5834; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5835; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
      return 5836; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
    }
    break;
  case 753: // WriteVFALUF_M2_E64_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5837; // VLEN512SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
      return 5838; // VLEN512SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5839; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
      return 5840; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5841; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
      return 5842; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
    }
    break;
  case 754: // WriteVFALUF_M2_E64_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5843; // VLEN512SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
      return 5844; // VLEN512SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5845; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
      return 5846; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5847; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
      return 5848; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
    }
    break;
  case 755: // WriteVFALUF_M4_E64_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5849; // VLEN512SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
      return 5850; // VLEN512SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5851; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
      return 5852; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5853; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
      return 5854; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
    }
    break;
  case 756: // WriteVFALUF_M4_E64_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5855; // VLEN512SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
      return 5856; // VLEN512SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5857; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
      return 5858; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5859; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
      return 5860; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
    }
    break;
  case 757: // WriteVFALUF_M8_E64_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5861; // VLEN512SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
      return 5862; // VLEN512SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5863; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
      return 5864; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5865; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
      return 5866; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
    }
    break;
  case 758: // WriteVFALUF_M8_E64_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5867; // VLEN512SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
      return 5868; // VLEN512SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5869; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
      return 5870; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5871; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
      return 5872; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
    }
    break;
  case 761: // WriteVFALUV_M1_E64_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5873; // VLEN512SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
      return 5874; // VLEN512SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5875; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
      return 5876; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5877; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
      return 5878; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
    }
    break;
  case 762: // WriteVFALUV_M1_E64_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5879; // VLEN512SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
      return 5880; // VLEN512SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5881; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
      return 5882; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5883; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
      return 5884; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
    }
    break;
  case 765: // WriteVFALUV_M2_E64_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5885; // VLEN512SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
      return 5886; // VLEN512SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5887; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
      return 5888; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5889; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
      return 5890; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
    }
    break;
  case 766: // WriteVFALUV_M2_E64_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5891; // VLEN512SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
      return 5892; // VLEN512SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5893; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
      return 5894; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5895; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
      return 5896; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
    }
    break;
  case 769: // WriteVFALUV_M4_E64_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5897; // VLEN512SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
      return 5898; // VLEN512SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5899; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
      return 5900; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5901; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
      return 5902; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
    }
    break;
  case 770: // WriteVFALUV_M4_E64_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5903; // VLEN512SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
      return 5904; // VLEN512SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5905; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
      return 5906; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5907; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
      return 5908; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
    }
    break;
  case 773: // WriteVFALUV_M8_E64_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5909; // VLEN512SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
      return 5910; // VLEN512SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5911; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
      return 5912; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5913; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
      return 5914; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
    }
    break;
  case 774: // WriteVFALUV_M8_E64_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5915; // VLEN512SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
      return 5916; // VLEN512SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5917; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
      return 5918; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5919; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
      return 5920; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
    }
    break;
  case 793: // WriteVFCvtIToFV_M1_E64_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5921; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
      return 5922; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5923; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
      return 5924; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5925; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
      return 5926; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
    }
    break;
  case 794: // WriteVFCvtIToFV_M1_E64_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5927; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
      return 5928; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5929; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
      return 5930; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5931; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
      return 5932; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
    }
    break;
  case 799: // WriteVFCvtIToFV_M2_E64_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5933; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
      return 5934; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5935; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
      return 5936; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5937; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
      return 5938; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
    }
    break;
  case 800: // WriteVFCvtIToFV_M2_E64_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5939; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
      return 5940; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5941; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
      return 5942; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5943; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
      return 5944; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
    }
    break;
  case 805: // WriteVFCvtIToFV_M4_E64_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5945; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
      return 5946; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5947; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
      return 5948; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5949; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
      return 5950; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
    }
    break;
  case 806: // WriteVFCvtIToFV_M4_E64_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5951; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
      return 5952; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5953; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
      return 5954; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5955; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
      return 5956; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
    }
    break;
  case 811: // WriteVFCvtIToFV_M8_E64_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5957; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
      return 5958; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5959; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
      return 5960; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5961; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
      return 5962; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
    }
    break;
  case 812: // WriteVFCvtIToFV_M8_E64_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5963; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
      return 5964; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5965; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
      return 5966; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5967; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
      return 5968; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
    }
    break;
  case 939: // WriteVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5969; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
      return 5970; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5971; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
      return 5972; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5973; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
      return 5974; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
    }
    break;
  case 940: // WriteVFMulAddF_M1_E64_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5975; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 5976; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5977; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 5978; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5979; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 5980; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    break;
  case 941: // WriteVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5981; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
      return 5982; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5983; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
      return 5984; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5985; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
      return 5986; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
    }
    break;
  case 942: // WriteVFMulAddF_M2_E64_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5987; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 5988; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5989; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 5990; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5991; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 5992; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    break;
  case 943: // WriteVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5993; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
      return 5994; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5995; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
      return 5996; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5997; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
      return 5998; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
    }
    break;
  case 944: // WriteVFMulAddF_M4_E64_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5999; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6000; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6001; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6002; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6003; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6004; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    break;
  case 945: // WriteVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6005; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
      return 6006; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6007; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
      return 6008; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6009; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
      return 6010; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
    }
    break;
  case 946: // WriteVFMulAddF_M8_E64_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6011; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6012; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6013; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6014; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6015; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6016; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    break;
  case 949: // WriteVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6017; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
      return 6018; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6019; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
      return 6020; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6021; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
      return 6022; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
    }
    break;
  case 950: // WriteVFMulAddV_M1_E64_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6023; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 6024; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6025; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 6026; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6027; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 6028; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    break;
  case 953: // WriteVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6029; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
      return 6030; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6031; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
      return 6032; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6033; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
      return 6034; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
    }
    break;
  case 954: // WriteVFMulAddV_M2_E64_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6035; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 6036; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6037; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 6038; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6039; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 6040; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    break;
  case 957: // WriteVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6041; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
      return 6042; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6043; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
      return 6044; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6045; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
      return 6046; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
    }
    break;
  case 958: // WriteVFMulAddV_M4_E64_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6047; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6048; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6049; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6050; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6051; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6052; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    break;
  case 961: // WriteVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6053; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
      return 6054; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6055; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
      return 6056; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6057; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
      return 6058; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
    }
    break;
  case 962: // WriteVFMulAddV_M8_E64_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6059; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6060; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6061; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6062; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6063; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6064; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    break;
  case 999: // WriteVFMinMaxF_M1_E64_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6065; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
      return 6066; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6067; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
      return 6068; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6069; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
      return 6070; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
    }
    break;
  case 1000: // WriteVFMinMaxF_M1_E64_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6071; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
      return 6072; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6073; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
      return 6074; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6075; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
      return 6076; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
    }
    break;
  case 1001: // WriteVFMinMaxF_M2_E64_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6077; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
      return 6078; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6079; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
      return 6080; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6081; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
      return 6082; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
    }
    break;
  case 1002: // WriteVFMinMaxF_M2_E64_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6083; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
      return 6084; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6085; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
      return 6086; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6087; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
      return 6088; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
    }
    break;
  case 1003: // WriteVFMinMaxF_M4_E64_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6089; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
      return 6090; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6091; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
      return 6092; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6093; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
      return 6094; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
    }
    break;
  case 1004: // WriteVFMinMaxF_M4_E64_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6095; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
      return 6096; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6097; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
      return 6098; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6099; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
      return 6100; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
    }
    break;
  case 1005: // WriteVFMinMaxF_M8_E64_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6101; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
      return 6102; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6103; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
      return 6104; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6105; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
      return 6106; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
    }
    break;
  case 1006: // WriteVFMinMaxF_M8_E64_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6107; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
      return 6108; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6109; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
      return 6110; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6111; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
      return 6112; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
    }
    break;
  case 1009: // WriteVFMinMaxV_M1_E64_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6113; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
      return 6114; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6115; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
      return 6116; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6117; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
      return 6118; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
    }
    break;
  case 1010: // WriteVFMinMaxV_M1_E64_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6119; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
      return 6120; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6121; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
      return 6122; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6123; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
      return 6124; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
    }
    break;
  case 1013: // WriteVFMinMaxV_M2_E64_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6125; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
      return 6126; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6127; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
      return 6128; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6129; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
      return 6130; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
    }
    break;
  case 1014: // WriteVFMinMaxV_M2_E64_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6131; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
      return 6132; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6133; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
      return 6134; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6135; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
      return 6136; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
    }
    break;
  case 1017: // WriteVFMinMaxV_M4_E64_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6137; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
      return 6138; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6139; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
      return 6140; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6141; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
      return 6142; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
    }
    break;
  case 1018: // WriteVFMinMaxV_M4_E64_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6143; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
      return 6144; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6145; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
      return 6146; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6147; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
      return 6148; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
    }
    break;
  case 1021: // WriteVFMinMaxV_M8_E64_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6149; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
      return 6150; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6151; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
      return 6152; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6153; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
      return 6154; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
    }
    break;
  case 1022: // WriteVFMinMaxV_M8_E64_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6155; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
      return 6156; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6157; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
      return 6158; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6159; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
      return 6160; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
    }
    break;
  case 1065: // WriteVFMulF_M1_E64_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6161; // VLEN512SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
      return 6162; // VLEN512SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6163; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
      return 6164; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6165; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
      return 6166; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
    }
    break;
  case 1066: // WriteVFMulF_M1_E64_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6167; // VLEN512SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
      return 6168; // VLEN512SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6169; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
      return 6170; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6171; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
      return 6172; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
    }
    break;
  case 1067: // WriteVFMulF_M2_E64_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6173; // VLEN512SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
      return 6174; // VLEN512SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6175; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
      return 6176; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6177; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
      return 6178; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
    }
    break;
  case 1068: // WriteVFMulF_M2_E64_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6179; // VLEN512SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
      return 6180; // VLEN512SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6181; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
      return 6182; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6183; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
      return 6184; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
    }
    break;
  case 1069: // WriteVFMulF_M4_E64_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6185; // VLEN512SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
      return 6186; // VLEN512SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6187; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
      return 6188; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6189; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
      return 6190; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
    }
    break;
  case 1070: // WriteVFMulF_M4_E64_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6191; // VLEN512SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
      return 6192; // VLEN512SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6193; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
      return 6194; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6195; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
      return 6196; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
    }
    break;
  case 1071: // WriteVFMulF_M8_E64_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6197; // VLEN512SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
      return 6198; // VLEN512SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6199; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
      return 6200; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6201; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
      return 6202; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
    }
    break;
  case 1072: // WriteVFMulF_M8_E64_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6203; // VLEN512SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
      return 6204; // VLEN512SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6205; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
      return 6206; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6207; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
      return 6208; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
    }
    break;
  case 1075: // WriteVFMulV_M1_E64_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6209; // VLEN512SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
      return 6210; // VLEN512SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6211; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
      return 6212; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6213; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
      return 6214; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
    }
    break;
  case 1076: // WriteVFMulV_M1_E64_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6215; // VLEN512SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
      return 6216; // VLEN512SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6217; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
      return 6218; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6219; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
      return 6220; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
    }
    break;
  case 1079: // WriteVFMulV_M2_E64_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6221; // VLEN512SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
      return 6222; // VLEN512SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6223; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
      return 6224; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6225; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
      return 6226; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
    }
    break;
  case 1080: // WriteVFMulV_M2_E64_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6227; // VLEN512SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
      return 6228; // VLEN512SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6229; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
      return 6230; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6231; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
      return 6232; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
    }
    break;
  case 1083: // WriteVFMulV_M4_E64_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6233; // VLEN512SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
      return 6234; // VLEN512SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6235; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
      return 6236; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6237; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
      return 6238; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
    }
    break;
  case 1084: // WriteVFMulV_M4_E64_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6239; // VLEN512SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
      return 6240; // VLEN512SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6241; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
      return 6242; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6243; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
      return 6244; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
    }
    break;
  case 1087: // WriteVFMulV_M8_E64_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6245; // VLEN512SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
      return 6246; // VLEN512SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6247; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
      return 6248; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6249; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
      return 6250; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
    }
    break;
  case 1088: // WriteVFMulV_M8_E64_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6251; // VLEN512SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
      return 6252; // VLEN512SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6253; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
      return 6254; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6255; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
      return 6256; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
    }
    break;
  case 1100: // WriteVFNCvtFToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6257; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
      return 6258; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6259; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
      return 6260; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6261; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
      return 6262; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
    }
    break;
  case 1101: // WriteVFNCvtFToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6263; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
      return 6264; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6265; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
      return 6266; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6267; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
      return 6268; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
    }
    break;
  case 1103: // WriteVFNCvtFToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6269; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
      return 6270; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6271; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
      return 6272; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6273; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
      return 6274; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
    }
    break;
  case 1104: // WriteVFNCvtFToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6275; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
      return 6276; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6277; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
      return 6278; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6279; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
      return 6280; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
    }
    break;
  case 1106: // WriteVFNCvtFToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6281; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
      return 6282; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6283; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
      return 6284; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6285; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
      return 6286; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
    }
    break;
  case 1107: // WriteVFNCvtFToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6287; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
      return 6288; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6289; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
      return 6290; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6291; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
      return 6292; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
    }
    break;
  case 1109: // WriteVFNCvtFToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6293; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
      return 6294; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6295; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
      return 6296; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6297; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
      return 6298; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
    }
    break;
  case 1110: // WriteVFNCvtFToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6299; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
      return 6300; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6301; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
      return 6302; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6303; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
      return 6304; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
    }
    break;
  case 1114: // WriteVFNCvtIToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6305; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
      return 6306; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6307; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
      return 6308; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6309; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
      return 6310; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
    }
    break;
  case 1115: // WriteVFNCvtIToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6311; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
      return 6312; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6313; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
      return 6314; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6315; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
      return 6316; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
    }
    break;
  case 1118: // WriteVFNCvtIToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6317; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
      return 6318; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6319; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
      return 6320; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6321; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
      return 6322; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
    }
    break;
  case 1119: // WriteVFNCvtIToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6323; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
      return 6324; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6325; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
      return 6326; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6327; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
      return 6328; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
    }
    break;
  case 1122: // WriteVFNCvtIToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6329; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
      return 6330; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6331; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
      return 6332; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6333; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
      return 6334; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
    }
    break;
  case 1123: // WriteVFNCvtIToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6335; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
      return 6336; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6337; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
      return 6338; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6339; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
      return 6340; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
    }
    break;
  case 1126: // WriteVFNCvtIToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6341; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
      return 6342; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6343; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
      return 6344; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6345; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
      return 6346; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
    }
    break;
  case 1127: // WriteVFNCvtIToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6347; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
      return 6348; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6349; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
      return 6350; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6351; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
      return 6352; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
    }
    break;
  case 1156: // WriteVFRecpV_M1_E64_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6353; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
      return 6354; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6355; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
      return 6356; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6357; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
      return 6358; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
    }
    break;
  case 1157: // WriteVFRecpV_M1_E64_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6359; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
      return 6360; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6361; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
      return 6362; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6363; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
      return 6364; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
    }
    break;
  case 1160: // WriteVFRecpV_M2_E64_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6365; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
      return 6366; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6367; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
      return 6368; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6369; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
      return 6370; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
    }
    break;
  case 1161: // WriteVFRecpV_M2_E64_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6371; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
      return 6372; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6373; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
      return 6374; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6375; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
      return 6376; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
    }
    break;
  case 1164: // WriteVFRecpV_M4_E64_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6377; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
      return 6378; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6379; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
      return 6380; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6381; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
      return 6382; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
    }
    break;
  case 1165: // WriteVFRecpV_M4_E64_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6383; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
      return 6384; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6385; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
      return 6386; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6387; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
      return 6388; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
    }
    break;
  case 1168: // WriteVFRecpV_M8_E64_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6389; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
      return 6390; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6391; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
      return 6392; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6393; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
      return 6394; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
    }
    break;
  case 1169: // WriteVFRecpV_M8_E64_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6395; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
      return 6396; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6397; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
      return 6398; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6399; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
      return 6400; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
    }
    break;
  case 1296: // WriteVFSgnjF_M1_E64_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6401; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
      return 6402; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6403; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
      return 6404; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6405; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
      return 6406; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
    }
    break;
  case 1297: // WriteVFSgnjF_M1_E64_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6407; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
      return 6408; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6409; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
      return 6410; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6411; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
      return 6412; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
    }
    break;
  case 1298: // WriteVFSgnjF_M2_E64_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6413; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
      return 6414; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6415; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
      return 6416; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6417; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
      return 6418; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
    }
    break;
  case 1299: // WriteVFSgnjF_M2_E64_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6419; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
      return 6420; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6421; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
      return 6422; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6423; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
      return 6424; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
    }
    break;
  case 1300: // WriteVFSgnjF_M4_E64_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6425; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
      return 6426; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6427; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
      return 6428; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6429; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
      return 6430; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
    }
    break;
  case 1301: // WriteVFSgnjF_M4_E64_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6431; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
      return 6432; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6433; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
      return 6434; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6435; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
      return 6436; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
    }
    break;
  case 1302: // WriteVFSgnjF_M8_E64_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6437; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
      return 6438; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6439; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
      return 6440; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6441; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
      return 6442; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
    }
    break;
  case 1303: // WriteVFSgnjF_M8_E64_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6443; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
      return 6444; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6445; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
      return 6446; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6447; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
      return 6448; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
    }
    break;
  case 1306: // WriteVFSgnjV_M1_E64_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6449; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
      return 6450; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6451; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
      return 6452; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6453; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
      return 6454; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
    }
    break;
  case 1307: // WriteVFSgnjV_M1_E64_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6455; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
      return 6456; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6457; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
      return 6458; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6459; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
      return 6460; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
    }
    break;
  case 1310: // WriteVFSgnjV_M2_E64_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6461; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
      return 6462; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6463; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
      return 6464; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6465; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
      return 6466; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
    }
    break;
  case 1311: // WriteVFSgnjV_M2_E64_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6467; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
      return 6468; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6469; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
      return 6470; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6471; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
      return 6472; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
    }
    break;
  case 1314: // WriteVFSgnjV_M4_E64_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6473; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
      return 6474; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6475; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
      return 6476; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6477; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
      return 6478; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
    }
    break;
  case 1315: // WriteVFSgnjV_M4_E64_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6479; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
      return 6480; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6481; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
      return 6482; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6483; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
      return 6484; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
    }
    break;
  case 1318: // WriteVFSgnjV_M8_E64_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6485; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
      return 6486; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6487; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
      return 6488; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6489; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
      return 6490; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
    }
    break;
  case 1319: // WriteVFSgnjV_M8_E64_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6491; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
      return 6492; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6493; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
      return 6494; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6495; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
      return 6496; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
    }
    break;
  case 1420: // WriteVFWCvtFToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6497; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
      return 6498; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6499; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
      return 6500; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6501; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
      return 6502; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
    }
    break;
  case 1421: // WriteVFWCvtFToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6503; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
      return 6504; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6505; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
      return 6506; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6507; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
      return 6508; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
    }
    break;
  case 1424: // WriteVFWCvtFToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6509; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
      return 6510; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6511; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
      return 6512; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6513; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
      return 6514; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
    }
    break;
  case 1425: // WriteVFWCvtFToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6515; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
      return 6516; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6517; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
      return 6518; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6519; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
      return 6520; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
    }
    break;
  case 1428: // WriteVFWCvtFToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6521; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
      return 6522; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6523; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
      return 6524; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6525; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
      return 6526; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
    }
    break;
  case 1429: // WriteVFWCvtFToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6527; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
      return 6528; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6529; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
      return 6530; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6531; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
      return 6532; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
    }
    break;
  case 1432: // WriteVFWCvtFToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6533; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
      return 6534; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6535; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
      return 6536; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6537; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
      return 6538; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
    }
    break;
  case 1433: // WriteVFWCvtFToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6539; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
      return 6540; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6541; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
      return 6542; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6543; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
      return 6544; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
    }
    break;
  case 1449: // WriteVFWCvtIToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6545; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
      return 6546; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6547; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
      return 6548; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6549; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
      return 6550; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
    }
    break;
  case 1450: // WriteVFWCvtIToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6551; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
      return 6552; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6553; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
      return 6554; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6555; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
      return 6556; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
    }
    break;
  case 1452: // WriteVFWCvtIToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6557; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
      return 6558; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6559; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
      return 6560; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6561; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
      return 6562; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
    }
    break;
  case 1453: // WriteVFWCvtIToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6563; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
      return 6564; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6565; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
      return 6566; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6567; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
      return 6568; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
    }
    break;
  case 1455: // WriteVFWCvtIToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6569; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
      return 6570; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6571; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
      return 6572; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6573; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
      return 6574; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
    }
    break;
  case 1456: // WriteVFWCvtIToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6575; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
      return 6576; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6577; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
      return 6578; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6579; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
      return 6580; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
    }
    break;
  case 1458: // WriteVFWCvtIToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6581; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
      return 6582; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6583; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
      return 6584; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6585; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
      return 6586; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
    }
    break;
  case 1459: // WriteVFWCvtIToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6587; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
      return 6588; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6589; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
      return 6590; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6591; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
      return 6592; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
    }
    break;
  case 1974: // WriteVLDS16_M1_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6593; // VLEN512SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVLDX_ReadVLDSX
      return 6594; // VLEN512SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6595; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVLDX_ReadVLDSX
      return 6596; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6597; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVLDX_ReadVLDSX
      return 6598; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1975: // WriteVLDS16_M1_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6599; // VLEN512SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6600; // VLEN512SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6601; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6602; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6603; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6604; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1976: // WriteVLDS16_M2_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6605; // VLEN512SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVLDX_ReadVLDSX
      return 6606; // VLEN512SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6607; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVLDX_ReadVLDSX
      return 6608; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6609; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVLDX_ReadVLDSX
      return 6610; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1977: // WriteVLDS16_M2_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6611; // VLEN512SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6612; // VLEN512SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6613; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6614; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6615; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6616; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1978: // WriteVLDS16_M4_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6617; // VLEN512SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVLDX_ReadVLDSX
      return 6618; // VLEN512SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6619; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVLDX_ReadVLDSX
      return 6620; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6621; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVLDX_ReadVLDSX
      return 6622; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1979: // WriteVLDS16_M4_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6623; // VLEN512SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6624; // VLEN512SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6625; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6626; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6627; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6628; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1980: // WriteVLDS16_M8_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6629; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVLDX_ReadVLDSX
      return 6630; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6631; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVLDX_ReadVLDSX
      return 6632; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6633; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVLDX_ReadVLDSX
      return 6634; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1981: // WriteVLDS16_M8_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6635; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6636; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6637; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6638; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6639; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6640; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1982: // WriteVLDS16_MF2_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6641; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6642; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6643; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6644; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6645; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6646; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1983: // WriteVLDS16_MF2_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6647; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6648; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6649; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6650; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6651; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6652; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1984: // WriteVLDS16_MF4_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6653; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6654; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6655; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6656; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6657; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6658; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1985: // WriteVLDS16_MF4_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6659; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6660; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6661; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6662; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6663; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6664; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1986: // WriteVLDS32_M1_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6665; // VLEN512SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVLDX_ReadVLDSX
      return 6666; // VLEN512SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6667; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVLDX_ReadVLDSX
      return 6668; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6669; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVLDX_ReadVLDSX
      return 6670; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1987: // WriteVLDS32_M1_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6671; // VLEN512SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6672; // VLEN512SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6673; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6674; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6675; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6676; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1988: // WriteVLDS32_M2_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6677; // VLEN512SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVLDX_ReadVLDSX
      return 6678; // VLEN512SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6679; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVLDX_ReadVLDSX
      return 6680; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6681; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVLDX_ReadVLDSX
      return 6682; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1989: // WriteVLDS32_M2_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6683; // VLEN512SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6684; // VLEN512SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6685; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6686; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6687; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6688; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1990: // WriteVLDS32_M4_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6689; // VLEN512SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVLDX_ReadVLDSX
      return 6690; // VLEN512SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6691; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVLDX_ReadVLDSX
      return 6692; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6693; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVLDX_ReadVLDSX
      return 6694; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1991: // WriteVLDS32_M4_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6695; // VLEN512SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6696; // VLEN512SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6697; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6698; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6699; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6700; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1992: // WriteVLDS32_M8_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6701; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVLDX_ReadVLDSX
      return 6702; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6703; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVLDX_ReadVLDSX
      return 6704; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6705; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVLDX_ReadVLDSX
      return 6706; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1993: // WriteVLDS32_M8_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6707; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6708; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6709; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6710; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6711; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6712; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1994: // WriteVLDS32_MF2_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6713; // VLEN512SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6714; // VLEN512SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6715; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6716; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6717; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6718; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1995: // WriteVLDS32_MF2_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6719; // VLEN512SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6720; // VLEN512SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6721; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6722; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6723; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6724; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1996: // WriteVLDS64_M1_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6725; // VLEN512SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVLDX_ReadVLDSX
      return 6726; // VLEN512SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6727; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVLDX_ReadVLDSX
      return 6728; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6729; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVLDX_ReadVLDSX
      return 6730; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1997: // WriteVLDS64_M1_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6731; // VLEN512SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6732; // VLEN512SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6733; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6734; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6735; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6736; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1998: // WriteVLDS64_M2_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6737; // VLEN512SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVLDX_ReadVLDSX
      return 6738; // VLEN512SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6739; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVLDX_ReadVLDSX
      return 6740; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6741; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVLDX_ReadVLDSX
      return 6742; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1999: // WriteVLDS64_M2_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6743; // VLEN512SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6744; // VLEN512SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6745; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6746; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6747; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6748; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2000: // WriteVLDS64_M4_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6749; // VLEN512SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVLDX_ReadVLDSX
      return 6750; // VLEN512SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6751; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVLDX_ReadVLDSX
      return 6752; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6753; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVLDX_ReadVLDSX
      return 6754; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2001: // WriteVLDS64_M4_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6755; // VLEN512SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6756; // VLEN512SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6757; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6758; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6759; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6760; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2002: // WriteVLDS64_M8_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6761; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVLDX_ReadVLDSX
      return 6762; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6763; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVLDX_ReadVLDSX
      return 6764; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6765; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVLDX_ReadVLDSX
      return 6766; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2003: // WriteVLDS64_M8_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6767; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6768; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6769; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6770; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6771; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6772; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2004: // WriteVLDS8_M1_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6773; // VLEN512SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVLDX_ReadVLDSX
      return 6774; // VLEN512SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6775; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVLDX_ReadVLDSX
      return 6776; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6777; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVLDX_ReadVLDSX
      return 6778; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2005: // WriteVLDS8_M1_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6779; // VLEN512SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6780; // VLEN512SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6781; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6782; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6783; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6784; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2006: // WriteVLDS8_M2_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6785; // VLEN512SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVLDX_ReadVLDSX
      return 6786; // VLEN512SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6787; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVLDX_ReadVLDSX
      return 6788; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6789; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVLDX_ReadVLDSX
      return 6790; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2007: // WriteVLDS8_M2_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6791; // VLEN512SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6792; // VLEN512SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6793; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6794; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6795; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6796; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2008: // WriteVLDS8_M4_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6797; // VLEN512SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVLDX_ReadVLDSX
      return 6798; // VLEN512SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6799; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVLDX_ReadVLDSX
      return 6800; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6801; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVLDX_ReadVLDSX
      return 6802; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2009: // WriteVLDS8_M4_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6803; // VLEN512SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6804; // VLEN512SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6805; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6806; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6807; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6808; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2010: // WriteVLDS8_M8_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6809; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVLDX_ReadVLDSX
      return 6810; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6811; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVLDX_ReadVLDSX
      return 6812; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6813; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVLDX_ReadVLDSX
      return 6814; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2011: // WriteVLDS8_M8_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6815; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6816; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6817; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6818; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6819; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6820; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2012: // WriteVLDS8_MF2_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6821; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6822; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6823; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6824; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6825; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6826; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2013: // WriteVLDS8_MF2_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6827; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6828; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6829; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6830; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6831; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6832; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2014: // WriteVLDS8_MF4_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6833; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6834; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6835; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6836; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6837; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6838; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2015: // WriteVLDS8_MF4_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6839; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6840; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6841; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6842; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6843; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6844; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2016: // WriteVLDS8_MF8_ReadVLDX_ReadVLDSX
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6845; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVLDX_ReadVLDSX
      return 6846; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6847; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVLDX_ReadVLDSX
      return 6848; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6849; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVLDX_ReadVLDSX
      return 6850; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2017: // WriteVLDS8_MF8_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6851; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6852; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6853; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6854; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6855; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6856; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 5160: // WriteIDiv_ReadIDiv_ReadIDiv
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (!STI.hasFeature(RISCV::Feature64Bit))
        return 6857; // VLEN512SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
      return 6858; // VLEN512SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (!STI.hasFeature(RISCV::Feature64Bit))
        return 6859; // VLEN128X100SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
      return 6860; // VLEN128X100SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (!STI.hasFeature(RISCV::Feature64Bit))
        return 6861; // VLEN1024X300SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
      return 6862; // VLEN1024X300SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
    }
    break;
  case 5261: // WriteIRem_ReadIRem_ReadIRem
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (!STI.hasFeature(RISCV::Feature64Bit))
        return 6863; // VLEN512SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIRem_ReadIRem
      return 6864; // VLEN512SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIRem_ReadIRem
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (!STI.hasFeature(RISCV::Feature64Bit))
        return 6865; // VLEN128X100SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIRem_ReadIRem
      return 6866; // VLEN128X100SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIRem_ReadIRem
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (!STI.hasFeature(RISCV::Feature64Bit))
        return 6867; // VLEN1024X300SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIRem_ReadIRem
      return 6868; // VLEN1024X300SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIRem_ReadIRem
    }
    break;
  case 5382: // WriteVLDS16_WorstCase_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6869; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6870; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6871; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6872; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6873; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6874; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 5383: // WriteVLDS32_WorstCase_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6875; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6876; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6877; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6878; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6879; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6880; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 5384: // WriteVLDS64_WorstCase_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6881; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6882; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6883; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6884; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6885; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6886; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 5385: // WriteVLDS8_WorstCase_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    if (CPUID == 6) { // SiFive7VLEN512Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6887; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6888; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 11) { // SiFive7VLEN128X100Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6889; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6890; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (CPUID == 12) { // SiFive7VLEN1024X300Model
      if (STI.hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6891; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6892; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 5705: // COPY
    if (CPUID == 3) { // SpacemitX60Model
  return 6897; // WriteIALU
    }
    break;
  };
  // Don't know how to resolve this scheduling class.
  return 0;
}

} // namespace RISCV_MC
struct RISCVGenMCSubtargetInfo : public MCSubtargetInfo {
  RISCVGenMCSubtargetInfo(const Triple &TT,
    StringRef CPU, StringRef TuneCPU, StringRef FS,
    StringTable PN,
    ArrayRef<SubtargetFeatureKV> PF,
    ArrayRef<SubtargetSubTypeKV> PD,
    const MCSchedModel *PSM,
    const MCWriteProcResEntry *WPR,
    const MCWriteLatencyEntry *WL,
    const MCReadAdvanceEntry *RA, const InstrStage *IS,
    const unsigned *OC, const unsigned *FP) :
      MCSubtargetInfo(TT, CPU, TuneCPU, FS, PN, PF, PD, PSM,
                      WPR, WL, RA, IS, OC, FP) { }

  unsigned resolveVariantSchedClass(unsigned SchedClass,
      const MCInst *MI, const MCInstrInfo *MCII,
      unsigned CPUID) const final {
    return RISCV_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
  }
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
};
unsigned RISCVGenMCSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const FeatureBitset &FB = getFeatureBits();
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if (FB[RISCV::Feature64Bit]) Modes |= (1 << 0);
  return Modes;
}
unsigned RISCVGenMCSubtargetInfo::getHwMode(enum HwModeType type) const {
  unsigned Modes = getHwModeSet();

  if (!Modes)
    return Modes;

  switch (type) {
  case HwMode_Default:
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_ValueType:
    Modes &= 1;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for ValueType were found!");
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_RegInfo:
    Modes &= 1;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for RegInfo were found!");
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_EncodingInfo:
    // No HwMode for EncodingInfo.
    return 0;
  }
  llvm_unreachable("unexpected HwModeType");
  return 0; // should not get here
}

static inline MCSubtargetInfo *createRISCVMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new RISCVGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(RISCVSubTypeKVStorage.Strings), RISCVFeatureKVStorage.Features, RISCVSubTypeKVStorage.SubTypes, nullptr, 
                      nullptr, nullptr, nullptr, 
                      nullptr, nullptr, nullptr);
}


} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_MC_DESC

#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC

#include "llvm/ADT/BitmaskEnum.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::RISCVSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[RISCV::Experimental]) HasExperimental = true;
  if (Bits[RISCV::Feature32Bit]) IsRV32 = true;
  if (Bits[RISCV::Feature64Bit]) IsRV64 = true;
  if (Bits[RISCV::FeatureExactAssembly]) EnableExactAssembly = true;
  if (Bits[RISCV::FeatureForcedAtomics]) HasForcedAtomics = true;
  if (Bits[RISCV::FeatureNoTrailingSeqCstFence]) EnableTrailingSeqCstFence = false;
  if (Bits[RISCV::FeaturePermissiveZalrsc]) HasPermissiveZalrsc = true;
  if (Bits[RISCV::FeatureRelax]) EnableLinkerRelax = true;
  if (Bits[RISCV::FeatureReserveX1]) UserReservedRegister[RISCV::X1] = true;
  if (Bits[RISCV::FeatureReserveX2]) UserReservedRegister[RISCV::X2] = true;
  if (Bits[RISCV::FeatureReserveX3]) UserReservedRegister[RISCV::X3] = true;
  if (Bits[RISCV::FeatureReserveX4]) UserReservedRegister[RISCV::X4] = true;
  if (Bits[RISCV::FeatureReserveX5]) UserReservedRegister[RISCV::X5] = true;
  if (Bits[RISCV::FeatureReserveX6]) UserReservedRegister[RISCV::X6] = true;
  if (Bits[RISCV::FeatureReserveX7]) UserReservedRegister[RISCV::X7] = true;
  if (Bits[RISCV::FeatureReserveX8]) UserReservedRegister[RISCV::X8] = true;
  if (Bits[RISCV::FeatureReserveX9]) UserReservedRegister[RISCV::X9] = true;
  if (Bits[RISCV::FeatureReserveX10]) UserReservedRegister[RISCV::X10] = true;
  if (Bits[RISCV::FeatureReserveX11]) UserReservedRegister[RISCV::X11] = true;
  if (Bits[RISCV::FeatureReserveX12]) UserReservedRegister[RISCV::X12] = true;
  if (Bits[RISCV::FeatureReserveX13]) UserReservedRegister[RISCV::X13] = true;
  if (Bits[RISCV::FeatureReserveX14]) UserReservedRegister[RISCV::X14] = true;
  if (Bits[RISCV::FeatureReserveX15]) UserReservedRegister[RISCV::X15] = true;
  if (Bits[RISCV::FeatureReserveX16]) UserReservedRegister[RISCV::X16] = true;
  if (Bits[RISCV::FeatureReserveX17]) UserReservedRegister[RISCV::X17] = true;
  if (Bits[RISCV::FeatureReserveX18]) UserReservedRegister[RISCV::X18] = true;
  if (Bits[RISCV::FeatureReserveX19]) UserReservedRegister[RISCV::X19] = true;
  if (Bits[RISCV::FeatureReserveX20]) UserReservedRegister[RISCV::X20] = true;
  if (Bits[RISCV::FeatureReserveX21]) UserReservedRegister[RISCV::X21] = true;
  if (Bits[RISCV::FeatureReserveX22]) UserReservedRegister[RISCV::X22] = true;
  if (Bits[RISCV::FeatureReserveX23]) UserReservedRegister[RISCV::X23] = true;
  if (Bits[RISCV::FeatureReserveX24]) UserReservedRegister[RISCV::X24] = true;
  if (Bits[RISCV::FeatureReserveX25]) UserReservedRegister[RISCV::X25] = true;
  if (Bits[RISCV::FeatureReserveX26]) UserReservedRegister[RISCV::X26] = true;
  if (Bits[RISCV::FeatureReserveX27]) UserReservedRegister[RISCV::X27] = true;
  if (Bits[RISCV::FeatureReserveX28]) UserReservedRegister[RISCV::X28] = true;
  if (Bits[RISCV::FeatureReserveX29]) UserReservedRegister[RISCV::X29] = true;
  if (Bits[RISCV::FeatureReserveX30]) UserReservedRegister[RISCV::X30] = true;
  if (Bits[RISCV::FeatureReserveX31]) UserReservedRegister[RISCV::X31] = true;
  if (Bits[RISCV::FeatureSaveRestore]) EnableSaveRestore = true;
  if (Bits[RISCV::FeatureStdExtA]) HasStdExtA = true;
  if (Bits[RISCV::FeatureStdExtB]) HasStdExtB = true;
  if (Bits[RISCV::FeatureStdExtC]) HasStdExtC = true;
  if (Bits[RISCV::FeatureStdExtD]) HasStdExtD = true;
  if (Bits[RISCV::FeatureStdExtE]) HasStdExtE = true;
  if (Bits[RISCV::FeatureStdExtF]) HasStdExtF = true;
  if (Bits[RISCV::FeatureStdExtH]) HasStdExtH = true;
  if (Bits[RISCV::FeatureStdExtI]) HasStdExtI = true;
  if (Bits[RISCV::FeatureStdExtM]) HasStdExtM = true;
  if (Bits[RISCV::FeatureStdExtP]) HasStdExtP = true;
  if (Bits[RISCV::FeatureStdExtQ]) HasStdExtQ = true;
  if (Bits[RISCV::FeatureStdExtSdext]) HasStdExtSdext = true;
  if (Bits[RISCV::FeatureStdExtSdtrig]) HasStdExtSdtrig = true;
  if (Bits[RISCV::FeatureStdExtSha]) HasStdExtSha = true;
  if (Bits[RISCV::FeatureStdExtShcounterenw]) HasStdExtShcounterenw = true;
  if (Bits[RISCV::FeatureStdExtShgatpa]) HasStdExtShgatpa = true;
  if (Bits[RISCV::FeatureStdExtShlcofideleg]) HasStdExtShlcofideleg = true;
  if (Bits[RISCV::FeatureStdExtShtvala]) HasStdExtShtvala = true;
  if (Bits[RISCV::FeatureStdExtShvsatpa]) HasStdExtShvsatpa = true;
  if (Bits[RISCV::FeatureStdExtShvstvala]) HasStdExtShvstvala = true;
  if (Bits[RISCV::FeatureStdExtShvstvecd]) HasStdExtShvstvecd = true;
  if (Bits[RISCV::FeatureStdExtSmaia]) HasStdExtSmaia = true;
  if (Bits[RISCV::FeatureStdExtSmcdeleg]) HasStdExtSmcdeleg = true;
  if (Bits[RISCV::FeatureStdExtSmcntrpmf]) HasStdExtSmcntrpmf = true;
  if (Bits[RISCV::FeatureStdExtSmcsrind]) HasStdExtSmcsrind = true;
  if (Bits[RISCV::FeatureStdExtSmctr]) HasStdExtSmctr = true;
  if (Bits[RISCV::FeatureStdExtSmdbltrp]) HasStdExtSmdbltrp = true;
  if (Bits[RISCV::FeatureStdExtSmepmp]) HasStdExtSmepmp = true;
  if (Bits[RISCV::FeatureStdExtSmmpm]) HasStdExtSmmpm = true;
  if (Bits[RISCV::FeatureStdExtSmnpm]) HasStdExtSmnpm = true;
  if (Bits[RISCV::FeatureStdExtSmpmpmt]) HasStdExtSmpmpmt = true;
  if (Bits[RISCV::FeatureStdExtSmrnmi]) HasStdExtSmrnmi = true;
  if (Bits[RISCV::FeatureStdExtSmstateen]) HasStdExtSmstateen = true;
  if (Bits[RISCV::FeatureStdExtSsaia]) HasStdExtSsaia = true;
  if (Bits[RISCV::FeatureStdExtSsccfg]) HasStdExtSsccfg = true;
  if (Bits[RISCV::FeatureStdExtSsccptr]) HasStdExtSsccptr = true;
  if (Bits[RISCV::FeatureStdExtSscofpmf]) HasStdExtSscofpmf = true;
  if (Bits[RISCV::FeatureStdExtSscounterenw]) HasStdExtSscounterenw = true;
  if (Bits[RISCV::FeatureStdExtSscsrind]) HasStdExtSscsrind = true;
  if (Bits[RISCV::FeatureStdExtSsctr]) HasStdExtSsctr = true;
  if (Bits[RISCV::FeatureStdExtSsdbltrp]) HasStdExtSsdbltrp = true;
  if (Bits[RISCV::FeatureStdExtSsnpm]) HasStdExtSsnpm = true;
  if (Bits[RISCV::FeatureStdExtSspm]) HasStdExtSspm = true;
  if (Bits[RISCV::FeatureStdExtSsqosid]) HasStdExtSsqosid = true;
  if (Bits[RISCV::FeatureStdExtSsstateen]) HasStdExtSsstateen = true;
  if (Bits[RISCV::FeatureStdExtSsstrict]) HasStdExtSsstrict = true;
  if (Bits[RISCV::FeatureStdExtSstc]) HasStdExtSstc = true;
  if (Bits[RISCV::FeatureStdExtSstvala]) HasStdExtSstvala = true;
  if (Bits[RISCV::FeatureStdExtSstvecd]) HasStdExtSstvecd = true;
  if (Bits[RISCV::FeatureStdExtSsu64xl]) HasStdExtSsu64xl = true;
  if (Bits[RISCV::FeatureStdExtSupm]) HasStdExtSupm = true;
  if (Bits[RISCV::FeatureStdExtSvade]) HasStdExtSvade = true;
  if (Bits[RISCV::FeatureStdExtSvadu]) HasStdExtSvadu = true;
  if (Bits[RISCV::FeatureStdExtSvbare]) HasStdExtSvbare = true;
  if (Bits[RISCV::FeatureStdExtSvinval]) HasStdExtSvinval = true;
  if (Bits[RISCV::FeatureStdExtSvnapot]) HasStdExtSvnapot = true;
  if (Bits[RISCV::FeatureStdExtSvpbmt]) HasStdExtSvpbmt = true;
  if (Bits[RISCV::FeatureStdExtSvrsw60t59b]) HasStdExtSvrsw60t59b = true;
  if (Bits[RISCV::FeatureStdExtSvukte]) HasStdExtSvukte = true;
  if (Bits[RISCV::FeatureStdExtSvvptc]) HasStdExtSvvptc = true;
  if (Bits[RISCV::FeatureStdExtV]) HasStdExtV = true;
  if (Bits[RISCV::FeatureStdExtY]) HasStdExtY = true;
  if (Bits[RISCV::FeatureStdExtZa64rs]) HasStdExtZa64rs = true;
  if (Bits[RISCV::FeatureStdExtZa128rs]) HasStdExtZa128rs = true;
  if (Bits[RISCV::FeatureStdExtZaamo]) HasStdExtZaamo = true;
  if (Bits[RISCV::FeatureStdExtZabha]) HasStdExtZabha = true;
  if (Bits[RISCV::FeatureStdExtZacas]) HasStdExtZacas = true;
  if (Bits[RISCV::FeatureStdExtZalasr]) HasStdExtZalasr = true;
  if (Bits[RISCV::FeatureStdExtZalrsc]) HasStdExtZalrsc = true;
  if (Bits[RISCV::FeatureStdExtZama16b]) HasStdExtZama16b = true;
  if (Bits[RISCV::FeatureStdExtZawrs]) HasStdExtZawrs = true;
  if (Bits[RISCV::FeatureStdExtZba]) HasStdExtZba = true;
  if (Bits[RISCV::FeatureStdExtZbb]) HasStdExtZbb = true;
  if (Bits[RISCV::FeatureStdExtZbc]) HasStdExtZbc = true;
  if (Bits[RISCV::FeatureStdExtZbkb]) HasStdExtZbkb = true;
  if (Bits[RISCV::FeatureStdExtZbkc]) HasStdExtZbkc = true;
  if (Bits[RISCV::FeatureStdExtZbkx]) HasStdExtZbkx = true;
  if (Bits[RISCV::FeatureStdExtZbs]) HasStdExtZbs = true;
  if (Bits[RISCV::FeatureStdExtZca]) HasStdExtZca = true;
  if (Bits[RISCV::FeatureStdExtZcb]) HasStdExtZcb = true;
  if (Bits[RISCV::FeatureStdExtZcd]) HasStdExtZcd = true;
  if (Bits[RISCV::FeatureStdExtZce]) HasStdExtZce = true;
  if (Bits[RISCV::FeatureStdExtZcf]) HasStdExtZcf = true;
  if (Bits[RISCV::FeatureStdExtZclsd]) HasStdExtZclsd = true;
  if (Bits[RISCV::FeatureStdExtZcmop]) HasStdExtZcmop = true;
  if (Bits[RISCV::FeatureStdExtZcmp]) HasStdExtZcmp = true;
  if (Bits[RISCV::FeatureStdExtZcmt]) HasStdExtZcmt = true;
  if (Bits[RISCV::FeatureStdExtZdinx]) HasStdExtZdinx = true;
  if (Bits[RISCV::FeatureStdExtZfa]) HasStdExtZfa = true;
  if (Bits[RISCV::FeatureStdExtZfbfmin]) HasStdExtZfbfmin = true;
  if (Bits[RISCV::FeatureStdExtZfh]) HasStdExtZfh = true;
  if (Bits[RISCV::FeatureStdExtZfhmin]) HasStdExtZfhmin = true;
  if (Bits[RISCV::FeatureStdExtZfinx]) HasStdExtZfinx = true;
  if (Bits[RISCV::FeatureStdExtZhinx]) HasStdExtZhinx = true;
  if (Bits[RISCV::FeatureStdExtZhinxmin]) HasStdExtZhinxmin = true;
  if (Bits[RISCV::FeatureStdExtZibi]) HasStdExtZibi = true;
  if (Bits[RISCV::FeatureStdExtZic64b]) HasStdExtZic64b = true;
  if (Bits[RISCV::FeatureStdExtZicbom]) HasStdExtZicbom = true;
  if (Bits[RISCV::FeatureStdExtZicbop]) HasStdExtZicbop = true;
  if (Bits[RISCV::FeatureStdExtZicboz]) HasStdExtZicboz = true;
  if (Bits[RISCV::FeatureStdExtZiccamoa]) HasStdExtZiccamoa = true;
  if (Bits[RISCV::FeatureStdExtZiccamoc]) HasStdExtZiccamoc = true;
  if (Bits[RISCV::FeatureStdExtZiccid]) HasStdExtZiccid = true;
  if (Bits[RISCV::FeatureStdExtZiccif]) HasStdExtZiccif = true;
  if (Bits[RISCV::FeatureStdExtZicclsm]) HasStdExtZicclsm = true;
  if (Bits[RISCV::FeatureStdExtZiccrse]) HasStdExtZiccrse = true;
  if (Bits[RISCV::FeatureStdExtZicfilp]) HasStdExtZicfilp = true;
  if (Bits[RISCV::FeatureStdExtZicfiss]) HasStdExtZicfiss = true;
  if (Bits[RISCV::FeatureStdExtZicntr]) HasStdExtZicntr = true;
  if (Bits[RISCV::FeatureStdExtZicond]) HasStdExtZicond = true;
  if (Bits[RISCV::FeatureStdExtZicsr]) HasStdExtZicsr = true;
  if (Bits[RISCV::FeatureStdExtZifencei]) HasStdExtZifencei = true;
  if (Bits[RISCV::FeatureStdExtZihintntl]) HasStdExtZihintntl = true;
  if (Bits[RISCV::FeatureStdExtZihintpause]) HasStdExtZihintpause = true;
  if (Bits[RISCV::FeatureStdExtZihpm]) HasStdExtZihpm = true;
  if (Bits[RISCV::FeatureStdExtZilsd]) HasStdExtZilsd = true;
  if (Bits[RISCV::FeatureStdExtZimop]) HasStdExtZimop = true;
  if (Bits[RISCV::FeatureStdExtZk]) HasStdExtZk = true;
  if (Bits[RISCV::FeatureStdExtZkn]) HasStdExtZkn = true;
  if (Bits[RISCV::FeatureStdExtZknd]) HasStdExtZknd = true;
  if (Bits[RISCV::FeatureStdExtZkne]) HasStdExtZkne = true;
  if (Bits[RISCV::FeatureStdExtZknh]) HasStdExtZknh = true;
  if (Bits[RISCV::FeatureStdExtZkr]) HasStdExtZkr = true;
  if (Bits[RISCV::FeatureStdExtZks]) HasStdExtZks = true;
  if (Bits[RISCV::FeatureStdExtZksed]) HasStdExtZksed = true;
  if (Bits[RISCV::FeatureStdExtZksh]) HasStdExtZksh = true;
  if (Bits[RISCV::FeatureStdExtZkt]) HasStdExtZkt = true;
  if (Bits[RISCV::FeatureStdExtZmmul]) HasStdExtZmmul = true;
  if (Bits[RISCV::FeatureStdExtZtso]) HasStdExtZtso = true;
  if (Bits[RISCV::FeatureStdExtZvabd]) HasStdExtZvabd = true;
  if (Bits[RISCV::FeatureStdExtZvbb]) HasStdExtZvbb = true;
  if (Bits[RISCV::FeatureStdExtZvbc]) HasStdExtZvbc = true;
  if (Bits[RISCV::FeatureStdExtZvbc32e]) HasStdExtZvbc32e = true;
  if (Bits[RISCV::FeatureStdExtZvdot4a8i]) HasStdExtZvdot4a8i = true;
  if (Bits[RISCV::FeatureStdExtZve32f]) HasStdExtZve32f = true;
  if (Bits[RISCV::FeatureStdExtZve32x]) HasStdExtZve32x = true;
  if (Bits[RISCV::FeatureStdExtZve64d]) HasStdExtZve64d = true;
  if (Bits[RISCV::FeatureStdExtZve64f]) HasStdExtZve64f = true;
  if (Bits[RISCV::FeatureStdExtZve64x]) HasStdExtZve64x = true;
  if (Bits[RISCV::FeatureStdExtZvfbdota32f]) HasStdExtZvfbdota32f = true;
  if (Bits[RISCV::FeatureStdExtZvfbfa]) HasStdExtZvfbfa = true;
  if (Bits[RISCV::FeatureStdExtZvfbfmin]) HasStdExtZvfbfmin = true;
  if (Bits[RISCV::FeatureStdExtZvfbfwma]) HasStdExtZvfbfwma = true;
  if (Bits[RISCV::FeatureStdExtZvfh]) HasStdExtZvfh = true;
  if (Bits[RISCV::FeatureStdExtZvfhmin]) HasStdExtZvfhmin = true;
  if (Bits[RISCV::FeatureStdExtZvfofp8min]) HasStdExtZvfofp8min = true;
  if (Bits[RISCV::FeatureStdExtZvfqwbdota8f]) HasStdExtZvfqwbdota8f = true;
  if (Bits[RISCV::FeatureStdExtZvfqwdota8f]) HasStdExtZvfqwdota8f = true;
  if (Bits[RISCV::FeatureStdExtZvfwbdota16bf]) HasStdExtZvfwbdota16bf = true;
  if (Bits[RISCV::FeatureStdExtZvfwdota16bf]) HasStdExtZvfwdota16bf = true;
  if (Bits[RISCV::FeatureStdExtZvkb]) HasStdExtZvkb = true;
  if (Bits[RISCV::FeatureStdExtZvkg]) HasStdExtZvkg = true;
  if (Bits[RISCV::FeatureStdExtZvkgs]) HasStdExtZvkgs = true;
  if (Bits[RISCV::FeatureStdExtZvkn]) HasStdExtZvkn = true;
  if (Bits[RISCV::FeatureStdExtZvknc]) HasStdExtZvknc = true;
  if (Bits[RISCV::FeatureStdExtZvkned]) HasStdExtZvkned = true;
  if (Bits[RISCV::FeatureStdExtZvkng]) HasStdExtZvkng = true;
  if (Bits[RISCV::FeatureStdExtZvknha]) HasStdExtZvknha = true;
  if (Bits[RISCV::FeatureStdExtZvknhb]) HasStdExtZvknhb = true;
  if (Bits[RISCV::FeatureStdExtZvks]) HasStdExtZvks = true;
  if (Bits[RISCV::FeatureStdExtZvksc]) HasStdExtZvksc = true;
  if (Bits[RISCV::FeatureStdExtZvksed]) HasStdExtZvksed = true;
  if (Bits[RISCV::FeatureStdExtZvksg]) HasStdExtZvksg = true;
  if (Bits[RISCV::FeatureStdExtZvksh]) HasStdExtZvksh = true;
  if (Bits[RISCV::FeatureStdExtZvkt]) HasStdExtZvkt = true;
  if (Bits[RISCV::FeatureStdExtZvl32b] && ZvlLen < 32) ZvlLen = 32;
  if (Bits[RISCV::FeatureStdExtZvl64b] && ZvlLen < 64) ZvlLen = 64;
  if (Bits[RISCV::FeatureStdExtZvl128b] && ZvlLen < 128) ZvlLen = 128;
  if (Bits[RISCV::FeatureStdExtZvl256b] && ZvlLen < 256) ZvlLen = 256;
  if (Bits[RISCV::FeatureStdExtZvl512b] && ZvlLen < 512) ZvlLen = 512;
  if (Bits[RISCV::FeatureStdExtZvl1024b] && ZvlLen < 1024) ZvlLen = 1024;
  if (Bits[RISCV::FeatureStdExtZvl2048b] && ZvlLen < 2048) ZvlLen = 2048;
  if (Bits[RISCV::FeatureStdExtZvl4096b] && ZvlLen < 4096) ZvlLen = 4096;
  if (Bits[RISCV::FeatureStdExtZvl8192b] && ZvlLen < 8192) ZvlLen = 8192;
  if (Bits[RISCV::FeatureStdExtZvl16384b] && ZvlLen < 16384) ZvlLen = 16384;
  if (Bits[RISCV::FeatureStdExtZvl32768b] && ZvlLen < 32768) ZvlLen = 32768;
  if (Bits[RISCV::FeatureStdExtZvl65536b] && ZvlLen < 65536) ZvlLen = 65536;
  if (Bits[RISCV::FeatureStdExtZvqwbdota8i]) HasStdExtZvqwbdota8i = true;
  if (Bits[RISCV::FeatureStdExtZvqwbdota16i]) HasStdExtZvqwbdota16i = true;
  if (Bits[RISCV::FeatureStdExtZvqwdota8i]) HasStdExtZvqwdota8i = true;
  if (Bits[RISCV::FeatureStdExtZvqwdota16i]) HasStdExtZvqwdota16i = true;
  if (Bits[RISCV::FeatureStdExtZvvfmm]) HasStdExtZvvfmm = true;
  if (Bits[RISCV::FeatureStdExtZvvmm]) HasStdExtZvvmm = true;
  if (Bits[RISCV::FeatureStdExtZvvmtls]) HasStdExtZvvmtls = true;
  if (Bits[RISCV::FeatureStdExtZvvmttls]) HasStdExtZvvmttls = true;
  if (Bits[RISCV::FeatureStdExtZvzip]) HasStdExtZvzip = true;
  if (Bits[RISCV::FeatureTaggedGlobals]) AllowTaggedGlobals = true;
  if (Bits[RISCV::FeatureUnalignedScalarMem]) EnableUnalignedScalarMem = true;
  if (Bits[RISCV::FeatureUnalignedVectorMem]) EnableUnalignedVectorMem = true;
  if (Bits[RISCV::FeatureVendorXAIFET]) HasVendorXAIFET = true;
  if (Bits[RISCV::FeatureVendorXAndesBFHCvt]) HasVendorXAndesBFHCvt = true;
  if (Bits[RISCV::FeatureVendorXAndesPerf]) HasVendorXAndesPerf = true;
  if (Bits[RISCV::FeatureVendorXAndesVBFHCvt]) HasVendorXAndesVBFHCvt = true;
  if (Bits[RISCV::FeatureVendorXAndesVDot]) HasVendorXAndesVDot = true;
  if (Bits[RISCV::FeatureVendorXAndesVPackFPH]) HasVendorXAndesVPackFPH = true;
  if (Bits[RISCV::FeatureVendorXAndesVSIntH]) HasVendorXAndesVSIntH = true;
  if (Bits[RISCV::FeatureVendorXAndesVSIntLoad]) HasVendorXAndesVSIntLoad = true;
  if (Bits[RISCV::FeatureVendorXCValu]) HasVendorXCValu = true;
  if (Bits[RISCV::FeatureVendorXCVbi]) HasVendorXCVbi = true;
  if (Bits[RISCV::FeatureVendorXCVbitmanip]) HasVendorXCVbitmanip = true;
  if (Bits[RISCV::FeatureVendorXCVelw]) HasVendorXCVelw = true;
  if (Bits[RISCV::FeatureVendorXCVmac]) HasVendorXCVmac = true;
  if (Bits[RISCV::FeatureVendorXCVmem]) HasVendorXCVmem = true;
  if (Bits[RISCV::FeatureVendorXCVsimd]) HasVendorXCVsimd = true;
  if (Bits[RISCV::FeatureVendorXCheriot]) HasVendorXCheriot = true;
  if (Bits[RISCV::FeatureVendorXMIPSCBOP]) HasVendorXMIPSCBOP = true;
  if (Bits[RISCV::FeatureVendorXMIPSCMov]) HasVendorXMIPSCMov = true;
  if (Bits[RISCV::FeatureVendorXMIPSEXECTL]) HasVendorXMIPSEXECTL = true;
  if (Bits[RISCV::FeatureVendorXMIPSLSP]) HasVendorXMIPSLSP = true;
  if (Bits[RISCV::FeatureVendorXSMTVDot]) HasVendorXSMTVDot = true;
  if (Bits[RISCV::FeatureVendorXSMTVDotII]) HasVendorXSMTVDotII = true;
  if (Bits[RISCV::FeatureVendorXSfcease]) HasVendorXSfcease = true;
  if (Bits[RISCV::FeatureVendorXSfmclic]) HasVendorXSfmclic = true;
  if (Bits[RISCV::FeatureVendorXSfmm16t] && XSfmmTE < 16) XSfmmTE = 16;
  if (Bits[RISCV::FeatureVendorXSfmm32a]) HasVendorXSfmm32a = true;
  if (Bits[RISCV::FeatureVendorXSfmm32a8f]) HasVendorXSfmm32a8f = true;
  if (Bits[RISCV::FeatureVendorXSfmm32a8i]) HasVendorXSfmm32a8i = true;
  if (Bits[RISCV::FeatureVendorXSfmm32a16f]) HasVendorXSfmm32a16f = true;
  if (Bits[RISCV::FeatureVendorXSfmm32a32f]) HasVendorXSfmm32a32f = true;
  if (Bits[RISCV::FeatureVendorXSfmm32t] && XSfmmTE < 32) XSfmmTE = 32;
  if (Bits[RISCV::FeatureVendorXSfmm64a64f]) HasVendorXSfmm64a64f = true;
  if (Bits[RISCV::FeatureVendorXSfmm64t] && XSfmmTE < 64) XSfmmTE = 64;
  if (Bits[RISCV::FeatureVendorXSfmm128t] && XSfmmTE < 128) XSfmmTE = 128;
  if (Bits[RISCV::FeatureVendorXSfmmbase]) HasVendorXSfmmbase = true;
  if (Bits[RISCV::FeatureVendorXSfsclic]) HasVendorXSfsclic = true;
  if (Bits[RISCV::FeatureVendorXSfvcp]) HasVendorXSfvcp = true;
  if (Bits[RISCV::FeatureVendorXSfvfbfexp16e]) HasVendorXSfvfbfexp16e = true;
  if (Bits[RISCV::FeatureVendorXSfvfexp16e]) HasVendorXSfvfexp16e = true;
  if (Bits[RISCV::FeatureVendorXSfvfexp32e]) HasVendorXSfvfexp32e = true;
  if (Bits[RISCV::FeatureVendorXSfvfexpa]) HasVendorXSfvfexpa = true;
  if (Bits[RISCV::FeatureVendorXSfvfexpa64e]) HasVendorXSfvfexpa64e = true;
  if (Bits[RISCV::FeatureVendorXSfvfnrclipxfqf]) HasVendorXSfvfnrclipxfqf = true;
  if (Bits[RISCV::FeatureVendorXSfvfwmaccqqq]) HasVendorXSfvfwmaccqqq = true;
  if (Bits[RISCV::FeatureVendorXSfvqmaccdod]) HasVendorXSfvqmaccdod = true;
  if (Bits[RISCV::FeatureVendorXSfvqmaccqoq]) HasVendorXSfvqmaccqoq = true;
  if (Bits[RISCV::FeatureVendorXSiFivecdiscarddlone]) HasVendorXSiFivecdiscarddlone = true;
  if (Bits[RISCV::FeatureVendorXSiFivecflushdlone]) HasVendorXSiFivecflushdlone = true;
  if (Bits[RISCV::FeatureVendorXTHeadBa]) HasVendorXTHeadBa = true;
  if (Bits[RISCV::FeatureVendorXTHeadBb]) HasVendorXTHeadBb = true;
  if (Bits[RISCV::FeatureVendorXTHeadBs]) HasVendorXTHeadBs = true;
  if (Bits[RISCV::FeatureVendorXTHeadCmo]) HasVendorXTHeadCmo = true;
  if (Bits[RISCV::FeatureVendorXTHeadCondMov]) HasVendorXTHeadCondMov = true;
  if (Bits[RISCV::FeatureVendorXTHeadFMemIdx]) HasVendorXTHeadFMemIdx = true;
  if (Bits[RISCV::FeatureVendorXTHeadMac]) HasVendorXTHeadMac = true;
  if (Bits[RISCV::FeatureVendorXTHeadMemIdx]) HasVendorXTHeadMemIdx = true;
  if (Bits[RISCV::FeatureVendorXTHeadMemPair]) HasVendorXTHeadMemPair = true;
  if (Bits[RISCV::FeatureVendorXTHeadSync]) HasVendorXTHeadSync = true;
  if (Bits[RISCV::FeatureVendorXTHeadVdot]) HasVendorXTHeadVdot = true;
  if (Bits[RISCV::FeatureVendorXVentanaCondOps]) HasVendorXVentanaCondOps = true;
  if (Bits[RISCV::FeatureVendorXqccmp]) HasVendorXqccmp = true;
  if (Bits[RISCV::FeatureVendorXqccmt]) HasVendorXqccmt = true;
  if (Bits[RISCV::FeatureVendorXqci]) HasVendorXqci = true;
  if (Bits[RISCV::FeatureVendorXqcia]) HasVendorXqcia = true;
  if (Bits[RISCV::FeatureVendorXqciac]) HasVendorXqciac = true;
  if (Bits[RISCV::FeatureVendorXqcibi]) HasVendorXqcibi = true;
  if (Bits[RISCV::FeatureVendorXqcibm]) HasVendorXqcibm = true;
  if (Bits[RISCV::FeatureVendorXqcicli]) HasVendorXqcicli = true;
  if (Bits[RISCV::FeatureVendorXqcicm]) HasVendorXqcicm = true;
  if (Bits[RISCV::FeatureVendorXqcics]) HasVendorXqcics = true;
  if (Bits[RISCV::FeatureVendorXqcicsr]) HasVendorXqcicsr = true;
  if (Bits[RISCV::FeatureVendorXqciint]) HasVendorXqciint = true;
  if (Bits[RISCV::FeatureVendorXqciio]) HasVendorXqciio = true;
  if (Bits[RISCV::FeatureVendorXqcilb]) HasVendorXqcilb = true;
  if (Bits[RISCV::FeatureVendorXqcili]) HasVendorXqcili = true;
  if (Bits[RISCV::FeatureVendorXqcilia]) HasVendorXqcilia = true;
  if (Bits[RISCV::FeatureVendorXqcilo]) HasVendorXqcilo = true;
  if (Bits[RISCV::FeatureVendorXqcilsm]) HasVendorXqcilsm = true;
  if (Bits[RISCV::FeatureVendorXqcisim]) HasVendorXqcisim = true;
  if (Bits[RISCV::FeatureVendorXqcisls]) HasVendorXqcisls = true;
  if (Bits[RISCV::FeatureVendorXqcisync]) HasVendorXqcisync = true;
  if (Bits[RISCV::FeatureVendorXwchc]) HasVendorXwchc = true;
  if (Bits[RISCV::FeatureZilsdWordAlign]) AllowZilsdWordAlign = true;
  if (Bits[RISCV::RVA20S64]) IsRVA20S64 = true;
  if (Bits[RISCV::RVA20U64]) IsRVA20U64 = true;
  if (Bits[RISCV::RVA22S64]) IsRVA22S64 = true;
  if (Bits[RISCV::RVA22U64]) IsRVA22U64 = true;
  if (Bits[RISCV::RVA23S64]) IsRVA23S64 = true;
  if (Bits[RISCV::RVA23U64]) IsRVA23U64 = true;
  if (Bits[RISCV::RVB23S64]) IsRVB23S64 = true;
  if (Bits[RISCV::RVB23U64]) IsRVB23U64 = true;
  if (Bits[RISCV::RVI20U32]) IsRVI20U32 = true;
  if (Bits[RISCV::RVI20U64]) IsRVI20U64 = true;
  if (Bits[RISCV::RVM23U32]) IsRVM23U32 = true;
  if (Bits[RISCV::TuneADDILoadFusion]) HasADDILoadFusion = true;
  if (Bits[RISCV::TuneADDLoadFusion]) HasADDLoadFusion = true;
  if (Bits[RISCV::TuneAUIPCADDIFusion]) HasAUIPCADDIFusion = true;
  if (Bits[RISCV::TuneAUIPCLoadFusion]) HasAUIPCLoadFusion = true;
  if (Bits[RISCV::TuneAndes45] && RISCVProcFamily < Andes45) RISCVProcFamily = Andes45;
  if (Bits[RISCV::TuneBFExtFusion]) HasBFExtFusion = true;
  if (Bits[RISCV::TuneConditionalCompressedMoveFusion]) HasConditionalCompressedMoveFusion = true;
  if (Bits[RISCV::TuneDLenFactor2]) DLenFactor2 = true;
  if (Bits[RISCV::TuneDisableLatencySchedHeuristic]) DisableLatencySchedHeuristic = true;
  if (Bits[RISCV::TuneDisableMISchedLoadClustering]) EnableMISchedLoadClustering = false;
  if (Bits[RISCV::TuneDisableMISchedStoreClustering]) EnableMISchedStoreClustering = false;
  if (Bits[RISCV::TuneDisablePostMISchedLoadClustering]) EnablePostMISchedLoadClustering = false;
  if (Bits[RISCV::TuneDisablePostMISchedStoreClustering]) EnablePostMISchedStoreClustering = false;
  if (Bits[RISCV::TuneEnableSelectOptimize]) EnableSelectOptimize = true;
  if (Bits[RISCV::TuneEnableVsetvliSchedHeuristic]) EnableVsetvliSchedHeuristic = true;
  if (Bits[RISCV::TuneFusionAddMem]) HasFusionAddMem = true;
  if (Bits[RISCV::TuneFusionLogicImmReg]) HasFusionLogicImmReg = true;
  if (Bits[RISCV::TuneFusionLogicRegImm]) HasFusionLogicRegImm = true;
  if (Bits[RISCV::TuneFusionLogicRegReg]) HasFusionLogicRegReg = true;
  if (Bits[RISCV::TuneFusionMulAdd]) HasFusionMulAdd = true;
  if (Bits[RISCV::TuneFusionShiftBitExtract]) HasFusionShiftBitExtract = true;
  if (Bits[RISCV::TuneHasSingleElementVecFP64]) HasSingleElementVectorFP64 = true;
  if (Bits[RISCV::TuneLDADDFusion]) HasLDADDFusion = true;
  if (Bits[RISCV::TuneLUIADDIFusion]) HasLUIADDIFusion = true;
  if (Bits[RISCV::TuneLUILoadFusion]) HasLUILoadFusion = true;
  if (Bits[RISCV::TuneMIPSP8700] && RISCVProcFamily < MIPSP8700) RISCVProcFamily = MIPSP8700;
  if (Bits[RISCV::TuneNLogNVRGather] && RISCVVRGatherCostModel < NLog2N) RISCVVRGatherCostModel = NLog2N;
  if (Bits[RISCV::TuneNoDefaultUnroll]) EnableDefaultUnroll = false;
  if (Bits[RISCV::TuneNoSinkSplatOperands]) SinkSplatOperands = false;
  if (Bits[RISCV::TuneOptimizedNF2SegmentLoadStore]) HasOptimizedNF2SegmentLoadStore = true;
  if (Bits[RISCV::TuneOptimizedNF3SegmentLoadStore]) HasOptimizedNF3SegmentLoadStore = true;
  if (Bits[RISCV::TuneOptimizedNF4SegmentLoadStore]) HasOptimizedNF4SegmentLoadStore = true;
  if (Bits[RISCV::TuneOptimizedNF5SegmentLoadStore]) HasOptimizedNF5SegmentLoadStore = true;
  if (Bits[RISCV::TuneOptimizedNF6SegmentLoadStore]) HasOptimizedNF6SegmentLoadStore = true;
  if (Bits[RISCV::TuneOptimizedNF7SegmentLoadStore]) HasOptimizedNF7SegmentLoadStore = true;
  if (Bits[RISCV::TuneOptimizedNF8SegmentLoadStore]) HasOptimizedNF8SegmentLoadStore = true;
  if (Bits[RISCV::TuneOptimizedZeroStrideLoad]) HasOptimizedZeroStrideLoad = true;
  if (Bits[RISCV::TunePostRAScheduler]) UsePostRAScheduler = true;
  if (Bits[RISCV::TunePredictableSelectIsExpensive]) PredictableSelectIsExpensive = true;
  if (Bits[RISCV::TunePreferAscendingLoadStore]) PreferAscendingLoadStore = true;
  if (Bits[RISCV::TunePreferVsetvliOverReadVLENB]) PreferVsetvliOverReadVLENB = true;
  if (Bits[RISCV::TunePreferWInst]) PreferWInst = true;
  if (Bits[RISCV::TuneQCELILoadStoreFusion]) HasQCELILoadStoreFusion = true;
  if (Bits[RISCV::TuneSHXADDLoadFusion]) HasSHXADDLoadFusion = true;
  if (Bits[RISCV::TuneShiftedZExtWFusion]) HasShiftedZExtWFusion = true;
  if (Bits[RISCV::TuneShortForwardBranchIALU]) HasShortForwardBranchIALU = true;
  if (Bits[RISCV::TuneShortForwardBranchILoad]) HasShortForwardBranchILoad = true;
  if (Bits[RISCV::TuneShortForwardBranchIMinMax]) HasShortForwardBranchIMinMax = true;
  if (Bits[RISCV::TuneShortForwardBranchIMul]) HasShortForwardBranchIMul = true;
  if (Bits[RISCV::TuneShortForwardBranchImm]) HasShortForwardBranchImm = true;
  if (Bits[RISCV::TuneSiFive7] && RISCVProcFamily < SiFive7) RISCVProcFamily = SiFive7;
  if (Bits[RISCV::TuneVLDependentLatency]) HasVLDependentLatency = true;
  if (Bits[RISCV::TuneVXRMPipelineFlush]) HasVXRMPipelineFlush = true;
  if (Bits[RISCV::TuneVentanaVeyron] && RISCVProcFamily < VentanaVeyron) RISCVProcFamily = VentanaVeyron;
  if (Bits[RISCV::TuneZExtHFusion]) HasZExtHFusion = true;
  if (Bits[RISCV::TuneZExtWFusion]) HasZExtWFusion = true;
}

#endif // GET_SUBTARGETINFO_TARGET_DESC

#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm_ks {

class DFAPacketizer;
namespace RISCV_MC {

unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, const MCSubtargetInfo &STI, unsigned CPUID);

} // namespace RISCV_MC
struct RISCVGenSubtargetInfo : public TargetSubtargetInfo {
  explicit RISCVGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const final;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const final;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  enum class RISCVHwModeBits : unsigned {
    DefaultMode = 0,
    RV64 = (1 << 0),

    LLVM_MARK_AS_BITMASK_ENUM(/*LargestValue=*/RV64),
  };
  unsigned getHwModeSet() const final;
  unsigned getHwMode(enum HwModeType type = HwMode_Default) const final;
  std::vector<MacroFusionPredTy> getMacroFusions() const final;
  const FeatureBitset &getInlineIgnoreFeatures() const override;
  const FeatureBitset &getInlineInverseFeatures() const override;
  const FeatureBitset &getInlineMustMatchFeatures() const override;
};

} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_HEADER

#ifdef GET_SUBTARGETINFO_CTOR
#undef GET_SUBTARGETINFO_CTOR

#include "llvm/CodeGen/TargetSchedule.h"

namespace llvm_ks {

extern const llvm_ks::StringRef RISCVNames[];
extern const llvm_ks::SubtargetFeatureKVStorage<379, 21644> RISCVFeatureKVStorage;
extern const llvm_ks::SubtargetSubTypeKVStorage<59, 768> RISCVSubTypeKVStorage;
extern const llvm_ks::MCSchedModel RISCVSchedModels[];
extern const llvm_ks::MCWriteProcResEntry RISCVWriteProcResTable[];
extern const llvm_ks::MCWriteLatencyEntry RISCVWriteLatencyTable[];
extern const llvm_ks::MCReadAdvanceEntry RISCVReadAdvanceTable[];
RISCVGenSubtargetInfo::RISCVGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, StringTable(RISCVSubTypeKVStorage.Strings), ArrayRef(RISCVFeatureKVStorage.Features), ArrayRef(RISCVSubTypeKVStorage.SubTypes), RISCVSchedModels, 
                        RISCVWriteProcResTable, RISCVWriteLatencyTable, RISCVReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned RISCVGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {

  [[maybe_unused]] const RISCVInstrInfo *TII =
    static_cast<const RISCVInstrInfo*>(SchedModel->getInstrInfo());

  switch (SchedClass) {
  case 751: // WriteVFALUF_M1_E64_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5825; // VLEN512SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
      return 5826; // VLEN512SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5827; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
      return 5828; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5829; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
      return 5830; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64
    }
    break;
  case 752: // WriteVFALUF_M1_E64_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5831; // VLEN512SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
      return 5832; // VLEN512SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5833; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
      return 5834; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5835; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
      return 5836; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUF_M1_E64_ReadVMask
    }
    break;
  case 753: // WriteVFALUF_M2_E64_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5837; // VLEN512SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
      return 5838; // VLEN512SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5839; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
      return 5840; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5841; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
      return 5842; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64
    }
    break;
  case 754: // WriteVFALUF_M2_E64_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5843; // VLEN512SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
      return 5844; // VLEN512SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5845; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
      return 5846; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5847; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
      return 5848; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUF_M2_E64_ReadVMask
    }
    break;
  case 755: // WriteVFALUF_M4_E64_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5849; // VLEN512SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
      return 5850; // VLEN512SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5851; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
      return 5852; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5853; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
      return 5854; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64
    }
    break;
  case 756: // WriteVFALUF_M4_E64_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5855; // VLEN512SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
      return 5856; // VLEN512SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5857; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
      return 5858; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5859; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
      return 5860; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUF_M4_E64_ReadVMask
    }
    break;
  case 757: // WriteVFALUF_M8_E64_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5861; // VLEN512SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
      return 5862; // VLEN512SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5863; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
      return 5864; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5865; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
      return 5866; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64
    }
    break;
  case 758: // WriteVFALUF_M8_E64_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5867; // VLEN512SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
      return 5868; // VLEN512SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5869; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
      return 5870; // VLEN128X100SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5871; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
      return 5872; // VLEN1024X300SiFive7anonymous_88219WriteVFALUF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUF_M8_E64_ReadVMask
    }
    break;
  case 761: // WriteVFALUV_M1_E64_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5873; // VLEN512SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
      return 5874; // VLEN512SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5875; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
      return 5876; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5877; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
      return 5878; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64
    }
    break;
  case 762: // WriteVFALUV_M1_E64_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5879; // VLEN512SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
      return 5880; // VLEN512SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5881; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
      return 5882; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5883; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
      return 5884; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFALUV_M1_E64_ReadVFALUV_M1_E64_ReadVMask
    }
    break;
  case 765: // WriteVFALUV_M2_E64_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5885; // VLEN512SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
      return 5886; // VLEN512SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5887; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
      return 5888; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5889; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
      return 5890; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64
    }
    break;
  case 766: // WriteVFALUV_M2_E64_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5891; // VLEN512SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
      return 5892; // VLEN512SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5893; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
      return 5894; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5895; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
      return 5896; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFALUV_M2_E64_ReadVFALUV_M2_E64_ReadVMask
    }
    break;
  case 769: // WriteVFALUV_M4_E64_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5897; // VLEN512SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
      return 5898; // VLEN512SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5899; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
      return 5900; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5901; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
      return 5902; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64
    }
    break;
  case 770: // WriteVFALUV_M4_E64_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5903; // VLEN512SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
      return 5904; // VLEN512SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5905; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
      return 5906; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5907; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
      return 5908; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFALUV_M4_E64_ReadVFALUV_M4_E64_ReadVMask
    }
    break;
  case 773: // WriteVFALUV_M8_E64_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5909; // VLEN512SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
      return 5910; // VLEN512SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5911; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
      return 5912; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5913; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
      return 5914; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64
    }
    break;
  case 774: // WriteVFALUV_M8_E64_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5915; // VLEN512SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
      return 5916; // VLEN512SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5917; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
      return 5918; // VLEN128X100SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5919; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
      return 5920; // VLEN1024X300SiFive7anonymous_88219WriteVFALUV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFALUV_M8_E64_ReadVFALUV_M8_E64_ReadVMask
    }
    break;
  case 793: // WriteVFCvtIToFV_M1_E64_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5921; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
      return 5922; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5923; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
      return 5924; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5925; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
      return 5926; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64
    }
    break;
  case 794: // WriteVFCvtIToFV_M1_E64_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5927; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
      return 5928; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5929; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
      return 5930; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5931; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
      return 5932; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFCvtIToFV_M1_E64_ReadVMask
    }
    break;
  case 799: // WriteVFCvtIToFV_M2_E64_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5933; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
      return 5934; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5935; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
      return 5936; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5937; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
      return 5938; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64
    }
    break;
  case 800: // WriteVFCvtIToFV_M2_E64_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5939; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
      return 5940; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5941; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
      return 5942; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5943; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
      return 5944; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFCvtIToFV_M2_E64_ReadVMask
    }
    break;
  case 805: // WriteVFCvtIToFV_M4_E64_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5945; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
      return 5946; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5947; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
      return 5948; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5949; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
      return 5950; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64
    }
    break;
  case 806: // WriteVFCvtIToFV_M4_E64_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5951; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
      return 5952; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5953; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
      return 5954; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5955; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
      return 5956; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFCvtIToFV_M4_E64_ReadVMask
    }
    break;
  case 811: // WriteVFCvtIToFV_M8_E64_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5957; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
      return 5958; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5959; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
      return 5960; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5961; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
      return 5962; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64
    }
    break;
  case 812: // WriteVFCvtIToFV_M8_E64_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5963; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
      return 5964; // VLEN512SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5965; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
      return 5966; // VLEN128X100SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5967; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
      return 5968; // VLEN1024X300SiFive7anonymous_88220WriteVFCvtIToFV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFCvtIToFV_M8_E64_ReadVMask
    }
    break;
  case 939: // WriteVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5969; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
      return 5970; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5971; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
      return 5972; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5973; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
      return 5974; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64
    }
    break;
  case 940: // WriteVFMulAddF_M1_E64_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5975; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 5976; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5977; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 5978; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5979; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 5980; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddF_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    break;
  case 941: // WriteVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5981; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
      return 5982; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5983; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
      return 5984; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5985; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
      return 5986; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64
    }
    break;
  case 942: // WriteVFMulAddF_M2_E64_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5987; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 5988; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5989; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 5990; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5991; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 5992; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddF_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    break;
  case 943: // WriteVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5993; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
      return 5994; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5995; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
      return 5996; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5997; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
      return 5998; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64
    }
    break;
  case 944: // WriteVFMulAddF_M4_E64_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 5999; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6000; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6001; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6002; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6003; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6004; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddF_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    break;
  case 945: // WriteVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6005; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
      return 6006; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6007; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
      return 6008; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6009; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
      return 6010; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64
    }
    break;
  case 946: // WriteVFMulAddF_M8_E64_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6011; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6012; // VLEN512SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6013; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6014; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6015; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6016; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddF_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    break;
  case 949: // WriteVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6017; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
      return 6018; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6019; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
      return 6020; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6021; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
      return 6022; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64
    }
    break;
  case 950: // WriteVFMulAddV_M1_E64_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6023; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 6024; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6025; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 6026; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6027; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
      return 6028; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVFMulAddV_M1_E64_ReadVMask
    }
    break;
  case 953: // WriteVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6029; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
      return 6030; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6031; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
      return 6032; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6033; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
      return 6034; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64
    }
    break;
  case 954: // WriteVFMulAddV_M2_E64_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6035; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 6036; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6037; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 6038; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6039; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
      return 6040; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVFMulAddV_M2_E64_ReadVMask
    }
    break;
  case 957: // WriteVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6041; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
      return 6042; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6043; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
      return 6044; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6045; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
      return 6046; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64
    }
    break;
  case 958: // WriteVFMulAddV_M4_E64_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6047; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6048; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6049; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6050; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6051; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
      return 6052; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVFMulAddV_M4_E64_ReadVMask
    }
    break;
  case 961: // WriteVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6053; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
      return 6054; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6055; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
      return 6056; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6057; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
      return 6058; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64
    }
    break;
  case 962: // WriteVFMulAddV_M8_E64_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6059; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6060; // VLEN512SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6061; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6062; // VLEN128X100SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6063; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
      return 6064; // VLEN1024X300SiFive7anonymous_88219WriteVFMulAddV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVFMulAddV_M8_E64_ReadVMask
    }
    break;
  case 999: // WriteVFMinMaxF_M1_E64_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6065; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
      return 6066; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6067; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
      return 6068; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6069; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
      return 6070; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64
    }
    break;
  case 1000: // WriteVFMinMaxF_M1_E64_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6071; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
      return 6072; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6073; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
      return 6074; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6075; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
      return 6076; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxF_M1_E64_ReadVMask
    }
    break;
  case 1001: // WriteVFMinMaxF_M2_E64_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6077; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
      return 6078; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6079; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
      return 6080; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6081; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
      return 6082; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64
    }
    break;
  case 1002: // WriteVFMinMaxF_M2_E64_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6083; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
      return 6084; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6085; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
      return 6086; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6087; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
      return 6088; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxF_M2_E64_ReadVMask
    }
    break;
  case 1003: // WriteVFMinMaxF_M4_E64_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6089; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
      return 6090; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6091; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
      return 6092; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6093; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
      return 6094; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64
    }
    break;
  case 1004: // WriteVFMinMaxF_M4_E64_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6095; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
      return 6096; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6097; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
      return 6098; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6099; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
      return 6100; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxF_M4_E64_ReadVMask
    }
    break;
  case 1005: // WriteVFMinMaxF_M8_E64_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6101; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
      return 6102; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6103; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
      return 6104; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6105; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
      return 6106; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64
    }
    break;
  case 1006: // WriteVFMinMaxF_M8_E64_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6107; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
      return 6108; // VLEN512SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6109; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
      return 6110; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6111; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
      return 6112; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxF_M8_E64_ReadVMask
    }
    break;
  case 1009: // WriteVFMinMaxV_M1_E64_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6113; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
      return 6114; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6115; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
      return 6116; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6117; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
      return 6118; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64
    }
    break;
  case 1010: // WriteVFMinMaxV_M1_E64_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6119; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
      return 6120; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6121; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
      return 6122; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6123; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
      return 6124; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMinMaxV_M1_E64_ReadVFMinMaxV_M1_E64_ReadVMask
    }
    break;
  case 1013: // WriteVFMinMaxV_M2_E64_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6125; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
      return 6126; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6127; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
      return 6128; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6129; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
      return 6130; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64
    }
    break;
  case 1014: // WriteVFMinMaxV_M2_E64_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6131; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
      return 6132; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6133; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
      return 6134; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6135; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
      return 6136; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMinMaxV_M2_E64_ReadVFMinMaxV_M2_E64_ReadVMask
    }
    break;
  case 1017: // WriteVFMinMaxV_M4_E64_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6137; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
      return 6138; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6139; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
      return 6140; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6141; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
      return 6142; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64
    }
    break;
  case 1018: // WriteVFMinMaxV_M4_E64_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6143; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
      return 6144; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6145; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
      return 6146; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6147; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
      return 6148; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMinMaxV_M4_E64_ReadVFMinMaxV_M4_E64_ReadVMask
    }
    break;
  case 1021: // WriteVFMinMaxV_M8_E64_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6149; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
      return 6150; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6151; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
      return 6152; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6153; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
      return 6154; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64
    }
    break;
  case 1022: // WriteVFMinMaxV_M8_E64_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6155; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
      return 6156; // VLEN512SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6157; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
      return 6158; // VLEN128X100SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6159; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
      return 6160; // VLEN1024X300SiFive7anonymous_88222WriteVFMinMaxV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMinMaxV_M8_E64_ReadVFMinMaxV_M8_E64_ReadVMask
    }
    break;
  case 1065: // WriteVFMulF_M1_E64_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6161; // VLEN512SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
      return 6162; // VLEN512SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6163; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
      return 6164; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6165; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
      return 6166; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64
    }
    break;
  case 1066: // WriteVFMulF_M1_E64_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6167; // VLEN512SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
      return 6168; // VLEN512SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6169; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
      return 6170; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6171; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
      return 6172; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulF_M1_E64_ReadVMask
    }
    break;
  case 1067: // WriteVFMulF_M2_E64_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6173; // VLEN512SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
      return 6174; // VLEN512SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6175; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
      return 6176; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6177; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
      return 6178; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64
    }
    break;
  case 1068: // WriteVFMulF_M2_E64_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6179; // VLEN512SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
      return 6180; // VLEN512SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6181; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
      return 6182; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6183; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
      return 6184; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulF_M2_E64_ReadVMask
    }
    break;
  case 1069: // WriteVFMulF_M4_E64_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6185; // VLEN512SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
      return 6186; // VLEN512SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6187; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
      return 6188; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6189; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
      return 6190; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64
    }
    break;
  case 1070: // WriteVFMulF_M4_E64_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6191; // VLEN512SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
      return 6192; // VLEN512SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6193; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
      return 6194; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6195; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
      return 6196; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulF_M4_E64_ReadVMask
    }
    break;
  case 1071: // WriteVFMulF_M8_E64_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6197; // VLEN512SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
      return 6198; // VLEN512SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6199; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
      return 6200; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6201; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
      return 6202; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64
    }
    break;
  case 1072: // WriteVFMulF_M8_E64_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6203; // VLEN512SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
      return 6204; // VLEN512SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6205; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
      return 6206; // VLEN128X100SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6207; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
      return 6208; // VLEN1024X300SiFive7anonymous_88219WriteVFMulF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulF_M8_E64_ReadVMask
    }
    break;
  case 1075: // WriteVFMulV_M1_E64_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6209; // VLEN512SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
      return 6210; // VLEN512SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6211; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
      return 6212; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6213; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
      return 6214; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64
    }
    break;
  case 1076: // WriteVFMulV_M1_E64_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6215; // VLEN512SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
      return 6216; // VLEN512SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6217; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
      return 6218; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6219; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
      return 6220; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFMulV_M1_E64_ReadVFMulV_M1_E64_ReadVMask
    }
    break;
  case 1079: // WriteVFMulV_M2_E64_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6221; // VLEN512SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
      return 6222; // VLEN512SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6223; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
      return 6224; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6225; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
      return 6226; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64
    }
    break;
  case 1080: // WriteVFMulV_M2_E64_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6227; // VLEN512SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
      return 6228; // VLEN512SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6229; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
      return 6230; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6231; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
      return 6232; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFMulV_M2_E64_ReadVFMulV_M2_E64_ReadVMask
    }
    break;
  case 1083: // WriteVFMulV_M4_E64_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6233; // VLEN512SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
      return 6234; // VLEN512SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6235; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
      return 6236; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6237; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
      return 6238; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64
    }
    break;
  case 1084: // WriteVFMulV_M4_E64_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6239; // VLEN512SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
      return 6240; // VLEN512SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6241; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
      return 6242; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6243; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
      return 6244; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFMulV_M4_E64_ReadVFMulV_M4_E64_ReadVMask
    }
    break;
  case 1087: // WriteVFMulV_M8_E64_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6245; // VLEN512SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
      return 6246; // VLEN512SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6247; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
      return 6248; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6249; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
      return 6250; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64
    }
    break;
  case 1088: // WriteVFMulV_M8_E64_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6251; // VLEN512SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
      return 6252; // VLEN512SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6253; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
      return 6254; // VLEN128X100SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6255; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
      return 6256; // VLEN1024X300SiFive7anonymous_88219WriteVFMulV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFMulV_M8_E64_ReadVFMulV_M8_E64_ReadVMask
    }
    break;
  case 1100: // WriteVFNCvtFToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6257; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
      return 6258; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6259; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
      return 6260; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6261; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
      return 6262; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32
    }
    break;
  case 1101: // WriteVFNCvtFToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6263; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
      return 6264; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6265; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
      return 6266; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6267; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
      return 6268; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtFToFV_M1_E32_ReadVMask
    }
    break;
  case 1103: // WriteVFNCvtFToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6269; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
      return 6270; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6271; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
      return 6272; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6273; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
      return 6274; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32
    }
    break;
  case 1104: // WriteVFNCvtFToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6275; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
      return 6276; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6277; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
      return 6278; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6279; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
      return 6280; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtFToFV_M2_E32_ReadVMask
    }
    break;
  case 1106: // WriteVFNCvtFToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6281; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
      return 6282; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6283; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
      return 6284; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6285; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
      return 6286; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32
    }
    break;
  case 1107: // WriteVFNCvtFToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6287; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
      return 6288; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6289; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
      return 6290; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6291; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
      return 6292; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtFToFV_M4_E32_ReadVMask
    }
    break;
  case 1109: // WriteVFNCvtFToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6293; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
      return 6294; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6295; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
      return 6296; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6297; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
      return 6298; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32
    }
    break;
  case 1110: // WriteVFNCvtFToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6299; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
      return 6300; // VLEN512SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6301; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
      return 6302; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6303; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
      return 6304; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtFToFV_MF2_E32_ReadVMask
    }
    break;
  case 1114: // WriteVFNCvtIToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6305; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
      return 6306; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6307; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
      return 6308; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6309; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
      return 6310; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32
    }
    break;
  case 1115: // WriteVFNCvtIToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6311; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
      return 6312; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6313; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
      return 6314; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6315; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
      return 6316; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFNCvtIToFV_M1_E32_ReadVMask
    }
    break;
  case 1118: // WriteVFNCvtIToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6317; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
      return 6318; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6319; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
      return 6320; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6321; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
      return 6322; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32
    }
    break;
  case 1119: // WriteVFNCvtIToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6323; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
      return 6324; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6325; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
      return 6326; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6327; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
      return 6328; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFNCvtIToFV_M2_E32_ReadVMask
    }
    break;
  case 1122: // WriteVFNCvtIToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6329; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
      return 6330; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6331; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
      return 6332; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6333; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
      return 6334; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32
    }
    break;
  case 1123: // WriteVFNCvtIToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6335; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
      return 6336; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6337; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
      return 6338; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6339; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
      return 6340; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFNCvtIToFV_M4_E32_ReadVMask
    }
    break;
  case 1126: // WriteVFNCvtIToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6341; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
      return 6342; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6343; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
      return 6344; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6345; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
      return 6346; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32
    }
    break;
  case 1127: // WriteVFNCvtIToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6347; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
      return 6348; // VLEN512SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6349; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
      return 6350; // VLEN128X100SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6351; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
      return 6352; // VLEN1024X300SiFive7anonymous_88318WriteVFNCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFNCvtIToFV_MF2_E32_ReadVMask
    }
    break;
  case 1156: // WriteVFRecpV_M1_E64_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6353; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
      return 6354; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6355; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
      return 6356; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6357; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
      return 6358; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64
    }
    break;
  case 1157: // WriteVFRecpV_M1_E64_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6359; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
      return 6360; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6361; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
      return 6362; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6363; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
      return 6364; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFRecpV_M1_E64_ReadVMask
    }
    break;
  case 1160: // WriteVFRecpV_M2_E64_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6365; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
      return 6366; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6367; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
      return 6368; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6369; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
      return 6370; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64
    }
    break;
  case 1161: // WriteVFRecpV_M2_E64_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6371; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
      return 6372; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6373; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
      return 6374; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6375; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
      return 6376; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFRecpV_M2_E64_ReadVMask
    }
    break;
  case 1164: // WriteVFRecpV_M4_E64_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6377; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
      return 6378; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6379; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
      return 6380; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6381; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
      return 6382; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64
    }
    break;
  case 1165: // WriteVFRecpV_M4_E64_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6383; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
      return 6384; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6385; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
      return 6386; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6387; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
      return 6388; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFRecpV_M4_E64_ReadVMask
    }
    break;
  case 1168: // WriteVFRecpV_M8_E64_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6389; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
      return 6390; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6391; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
      return 6392; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6393; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
      return 6394; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64
    }
    break;
  case 1169: // WriteVFRecpV_M8_E64_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6395; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
      return 6396; // VLEN512SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6397; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
      return 6398; // VLEN128X100SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6399; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
      return 6400; // VLEN1024X300SiFive7anonymous_88220WriteVFRecpV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFRecpV_M8_E64_ReadVMask
    }
    break;
  case 1296: // WriteVFSgnjF_M1_E64_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6401; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
      return 6402; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6403; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
      return 6404; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6405; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
      return 6406; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64
    }
    break;
  case 1297: // WriteVFSgnjF_M1_E64_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6407; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
      return 6408; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6409; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
      return 6410; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6411; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
      return 6412; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjF_M1_E64_ReadVMask
    }
    break;
  case 1298: // WriteVFSgnjF_M2_E64_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6413; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
      return 6414; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6415; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
      return 6416; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6417; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
      return 6418; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64
    }
    break;
  case 1299: // WriteVFSgnjF_M2_E64_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6419; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
      return 6420; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6421; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
      return 6422; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6423; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
      return 6424; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjF_M2_E64_ReadVMask
    }
    break;
  case 1300: // WriteVFSgnjF_M4_E64_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6425; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
      return 6426; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6427; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
      return 6428; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6429; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
      return 6430; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64
    }
    break;
  case 1301: // WriteVFSgnjF_M4_E64_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6431; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
      return 6432; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6433; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
      return 6434; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6435; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
      return 6436; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjF_M4_E64_ReadVMask
    }
    break;
  case 1302: // WriteVFSgnjF_M8_E64_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6437; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
      return 6438; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6439; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
      return 6440; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6441; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
      return 6442; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64
    }
    break;
  case 1303: // WriteVFSgnjF_M8_E64_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6443; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
      return 6444; // VLEN512SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6445; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
      return 6446; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6447; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
      return 6448; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjF_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjF_M8_E64_ReadVMask
    }
    break;
  case 1306: // WriteVFSgnjV_M1_E64_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6449; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
      return 6450; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6451; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
      return 6452; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6453; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
      return 6454; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64
    }
    break;
  case 1307: // WriteVFSgnjV_M1_E64_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6455; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
      return 6456; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6457; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
      return 6458; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6459; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M1_E64_Pred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
      return 6460; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M1_E64_NoPred_ReadVPassthru_M1_E64_ReadVFSgnjV_M1_E64_ReadVFSgnjV_M1_E64_ReadVMask
    }
    break;
  case 1310: // WriteVFSgnjV_M2_E64_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6461; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
      return 6462; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6463; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
      return 6464; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6465; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
      return 6466; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64
    }
    break;
  case 1311: // WriteVFSgnjV_M2_E64_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6467; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
      return 6468; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6469; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
      return 6470; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6471; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M2_E64_Pred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
      return 6472; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M2_E64_NoPred_ReadVPassthru_M2_E64_ReadVFSgnjV_M2_E64_ReadVFSgnjV_M2_E64_ReadVMask
    }
    break;
  case 1314: // WriteVFSgnjV_M4_E64_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6473; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
      return 6474; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6475; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
      return 6476; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6477; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
      return 6478; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64
    }
    break;
  case 1315: // WriteVFSgnjV_M4_E64_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6479; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
      return 6480; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6481; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
      return 6482; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6483; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M4_E64_Pred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
      return 6484; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M4_E64_NoPred_ReadVPassthru_M4_E64_ReadVFSgnjV_M4_E64_ReadVFSgnjV_M4_E64_ReadVMask
    }
    break;
  case 1318: // WriteVFSgnjV_M8_E64_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6485; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
      return 6486; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6487; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
      return 6488; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6489; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
      return 6490; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64
    }
    break;
  case 1319: // WriteVFSgnjV_M8_E64_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6491; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
      return 6492; // VLEN512SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6493; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
      return 6494; // VLEN128X100SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6495; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M8_E64_Pred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
      return 6496; // VLEN1024X300SiFive7anonymous_88221WriteVFSgnjV_M8_E64_NoPred_ReadVPassthru_M8_E64_ReadVFSgnjV_M8_E64_ReadVFSgnjV_M8_E64_ReadVMask
    }
    break;
  case 1420: // WriteVFWCvtFToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6497; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
      return 6498; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6499; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
      return 6500; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6501; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
      return 6502; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32
    }
    break;
  case 1421: // WriteVFWCvtFToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6503; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
      return 6504; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6505; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
      return 6506; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6507; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
      return 6508; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtFToFV_M1_E32_ReadVMask
    }
    break;
  case 1424: // WriteVFWCvtFToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6509; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
      return 6510; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6511; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
      return 6512; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6513; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
      return 6514; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32
    }
    break;
  case 1425: // WriteVFWCvtFToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6515; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
      return 6516; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6517; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
      return 6518; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6519; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
      return 6520; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtFToFV_M2_E32_ReadVMask
    }
    break;
  case 1428: // WriteVFWCvtFToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6521; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
      return 6522; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6523; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
      return 6524; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6525; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
      return 6526; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32
    }
    break;
  case 1429: // WriteVFWCvtFToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6527; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
      return 6528; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6529; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
      return 6530; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6531; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
      return 6532; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtFToFV_M4_E32_ReadVMask
    }
    break;
  case 1432: // WriteVFWCvtFToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6533; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
      return 6534; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6535; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
      return 6536; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6537; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
      return 6538; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32
    }
    break;
  case 1433: // WriteVFWCvtFToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6539; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
      return 6540; // VLEN512SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6541; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
      return 6542; // VLEN128X100SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6543; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
      return 6544; // VLEN1024X300SiFive7anonymous_88300WriteVFWCvtFToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtFToFV_MF2_E32_ReadVMask
    }
    break;
  case 1449: // WriteVFWCvtIToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6545; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
      return 6546; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6547; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
      return 6548; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6549; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
      return 6550; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32
    }
    break;
  case 1450: // WriteVFWCvtIToFV_M1_E32_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6551; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
      return 6552; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6553; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
      return 6554; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6555; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_Pred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
      return 6556; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M1_E32_NoPred_ReadVPassthru_M1_E32_ReadVFWCvtIToFV_M1_E32_ReadVMask
    }
    break;
  case 1452: // WriteVFWCvtIToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6557; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
      return 6558; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6559; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
      return 6560; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6561; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
      return 6562; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32
    }
    break;
  case 1453: // WriteVFWCvtIToFV_M2_E32_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6563; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
      return 6564; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6565; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
      return 6566; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6567; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_Pred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
      return 6568; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M2_E32_NoPred_ReadVPassthru_M2_E32_ReadVFWCvtIToFV_M2_E32_ReadVMask
    }
    break;
  case 1455: // WriteVFWCvtIToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6569; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
      return 6570; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6571; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
      return 6572; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6573; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
      return 6574; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32
    }
    break;
  case 1456: // WriteVFWCvtIToFV_M4_E32_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6575; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
      return 6576; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6577; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
      return 6578; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6579; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_Pred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
      return 6580; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_M4_E32_NoPred_ReadVPassthru_M4_E32_ReadVFWCvtIToFV_M4_E32_ReadVMask
    }
    break;
  case 1458: // WriteVFWCvtIToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6581; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
      return 6582; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6583; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
      return 6584; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6585; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
      return 6586; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32
    }
    break;
  case 1459: // WriteVFWCvtIToFV_MF2_E32_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6587; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
      return 6588; // VLEN512SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6589; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
      return 6590; // VLEN128X100SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneHasSingleElementVecFP64))
        return 6591; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_Pred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
      return 6592; // VLEN1024X300SiFive7anonymous_88277WriteVFWCvtIToFV_MF2_E32_NoPred_ReadVPassthru_MF2_E32_ReadVFWCvtIToFV_MF2_E32_ReadVMask
    }
    break;
  case 1974: // WriteVLDS16_M1_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6593; // VLEN512SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVLDX_ReadVLDSX
      return 6594; // VLEN512SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6595; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVLDX_ReadVLDSX
      return 6596; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6597; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVLDX_ReadVLDSX
      return 6598; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1975: // WriteVLDS16_M1_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6599; // VLEN512SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6600; // VLEN512SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6601; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6602; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6603; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M1_Pred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6604; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M1_NoPred_ReadVPassthru_M1_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1976: // WriteVLDS16_M2_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6605; // VLEN512SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVLDX_ReadVLDSX
      return 6606; // VLEN512SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6607; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVLDX_ReadVLDSX
      return 6608; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6609; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVLDX_ReadVLDSX
      return 6610; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1977: // WriteVLDS16_M2_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6611; // VLEN512SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6612; // VLEN512SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6613; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6614; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6615; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M2_Pred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6616; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M2_NoPred_ReadVPassthru_M2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1978: // WriteVLDS16_M4_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6617; // VLEN512SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVLDX_ReadVLDSX
      return 6618; // VLEN512SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6619; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVLDX_ReadVLDSX
      return 6620; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6621; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVLDX_ReadVLDSX
      return 6622; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1979: // WriteVLDS16_M4_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6623; // VLEN512SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6624; // VLEN512SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6625; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6626; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6627; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M4_Pred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6628; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M4_NoPred_ReadVPassthru_M4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1980: // WriteVLDS16_M8_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6629; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVLDX_ReadVLDSX
      return 6630; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6631; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVLDX_ReadVLDSX
      return 6632; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6633; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVLDX_ReadVLDSX
      return 6634; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1981: // WriteVLDS16_M8_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6635; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6636; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6637; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6638; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6639; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6640; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_M8_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1982: // WriteVLDS16_MF2_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6641; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6642; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6643; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6644; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6645; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6646; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1983: // WriteVLDS16_MF2_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6647; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6648; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6649; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6650; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6651; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF2_Pred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6652; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF2_NoPred_ReadVPassthru_MF2_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1984: // WriteVLDS16_MF4_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6653; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6654; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6655; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6656; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6657; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6658; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1985: // WriteVLDS16_MF4_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6659; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6660; // VLEN512SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6661; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6662; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6663; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF4_Pred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
      return 6664; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_MF4_NoPred_ReadVPassthru_MF4_E16_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1986: // WriteVLDS32_M1_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6665; // VLEN512SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVLDX_ReadVLDSX
      return 6666; // VLEN512SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6667; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVLDX_ReadVLDSX
      return 6668; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6669; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVLDX_ReadVLDSX
      return 6670; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1987: // WriteVLDS32_M1_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6671; // VLEN512SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6672; // VLEN512SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6673; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6674; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6675; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M1_Pred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6676; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M1_NoPred_ReadVPassthru_M1_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1988: // WriteVLDS32_M2_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6677; // VLEN512SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVLDX_ReadVLDSX
      return 6678; // VLEN512SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6679; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVLDX_ReadVLDSX
      return 6680; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6681; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVLDX_ReadVLDSX
      return 6682; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1989: // WriteVLDS32_M2_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6683; // VLEN512SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6684; // VLEN512SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6685; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6686; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6687; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M2_Pred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6688; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M2_NoPred_ReadVPassthru_M2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1990: // WriteVLDS32_M4_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6689; // VLEN512SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVLDX_ReadVLDSX
      return 6690; // VLEN512SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6691; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVLDX_ReadVLDSX
      return 6692; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6693; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVLDX_ReadVLDSX
      return 6694; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1991: // WriteVLDS32_M4_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6695; // VLEN512SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6696; // VLEN512SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6697; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6698; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6699; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M4_Pred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6700; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M4_NoPred_ReadVPassthru_M4_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1992: // WriteVLDS32_M8_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6701; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVLDX_ReadVLDSX
      return 6702; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6703; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVLDX_ReadVLDSX
      return 6704; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6705; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVLDX_ReadVLDSX
      return 6706; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1993: // WriteVLDS32_M8_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6707; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6708; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6709; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6710; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6711; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6712; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_M8_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1994: // WriteVLDS32_MF2_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6713; // VLEN512SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6714; // VLEN512SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6715; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6716; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6717; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6718; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1995: // WriteVLDS32_MF2_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6719; // VLEN512SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6720; // VLEN512SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6721; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6722; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6723; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_MF2_Pred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
      return 6724; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_MF2_NoPred_ReadVPassthru_MF2_E32_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1996: // WriteVLDS64_M1_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6725; // VLEN512SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVLDX_ReadVLDSX
      return 6726; // VLEN512SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6727; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVLDX_ReadVLDSX
      return 6728; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6729; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVLDX_ReadVLDSX
      return 6730; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1997: // WriteVLDS64_M1_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6731; // VLEN512SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6732; // VLEN512SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6733; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6734; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6735; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M1_Pred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6736; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M1_NoPred_ReadVPassthru_M1_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 1998: // WriteVLDS64_M2_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6737; // VLEN512SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVLDX_ReadVLDSX
      return 6738; // VLEN512SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6739; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVLDX_ReadVLDSX
      return 6740; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6741; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVLDX_ReadVLDSX
      return 6742; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 1999: // WriteVLDS64_M2_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6743; // VLEN512SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6744; // VLEN512SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6745; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6746; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6747; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M2_Pred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6748; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M2_NoPred_ReadVPassthru_M2_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2000: // WriteVLDS64_M4_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6749; // VLEN512SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVLDX_ReadVLDSX
      return 6750; // VLEN512SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6751; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVLDX_ReadVLDSX
      return 6752; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6753; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVLDX_ReadVLDSX
      return 6754; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2001: // WriteVLDS64_M4_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6755; // VLEN512SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6756; // VLEN512SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6757; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6758; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6759; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M4_Pred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6760; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M4_NoPred_ReadVPassthru_M4_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2002: // WriteVLDS64_M8_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6761; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVLDX_ReadVLDSX
      return 6762; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6763; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVLDX_ReadVLDSX
      return 6764; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6765; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVLDX_ReadVLDSX
      return 6766; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2003: // WriteVLDS64_M8_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6767; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6768; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6769; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6770; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6771; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
      return 6772; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_M8_E64_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2004: // WriteVLDS8_M1_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6773; // VLEN512SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVLDX_ReadVLDSX
      return 6774; // VLEN512SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6775; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVLDX_ReadVLDSX
      return 6776; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6777; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVLDX_ReadVLDSX
      return 6778; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2005: // WriteVLDS8_M1_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6779; // VLEN512SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6780; // VLEN512SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6781; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6782; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6783; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M1_Pred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6784; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M1_NoPred_ReadVPassthru_M1_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2006: // WriteVLDS8_M2_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6785; // VLEN512SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVLDX_ReadVLDSX
      return 6786; // VLEN512SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6787; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVLDX_ReadVLDSX
      return 6788; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6789; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVLDX_ReadVLDSX
      return 6790; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2007: // WriteVLDS8_M2_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6791; // VLEN512SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6792; // VLEN512SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6793; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6794; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6795; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M2_Pred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6796; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M2_NoPred_ReadVPassthru_M2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2008: // WriteVLDS8_M4_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6797; // VLEN512SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVLDX_ReadVLDSX
      return 6798; // VLEN512SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6799; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVLDX_ReadVLDSX
      return 6800; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6801; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVLDX_ReadVLDSX
      return 6802; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2009: // WriteVLDS8_M4_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6803; // VLEN512SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6804; // VLEN512SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6805; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6806; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6807; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M4_Pred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6808; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M4_NoPred_ReadVPassthru_M4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2010: // WriteVLDS8_M8_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6809; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVLDX_ReadVLDSX
      return 6810; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6811; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVLDX_ReadVLDSX
      return 6812; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6813; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVLDX_ReadVLDSX
      return 6814; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2011: // WriteVLDS8_M8_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6815; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6816; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6817; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6818; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6819; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6820; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_M8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2012: // WriteVLDS8_MF2_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6821; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6822; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6823; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6824; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6825; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVLDX_ReadVLDSX
      return 6826; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2013: // WriteVLDS8_MF2_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6827; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6828; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6829; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6830; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6831; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF2_Pred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6832; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF2_NoPred_ReadVPassthru_MF2_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2014: // WriteVLDS8_MF4_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6833; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6834; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6835; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6836; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6837; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVLDX_ReadVLDSX
      return 6838; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2015: // WriteVLDS8_MF4_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6839; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6840; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6841; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6842; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6843; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF4_Pred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6844; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF4_NoPred_ReadVPassthru_MF4_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 2016: // WriteVLDS8_MF8_ReadVLDX_ReadVLDSX
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6845; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVLDX_ReadVLDSX
      return 6846; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6847; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVLDX_ReadVLDSX
      return 6848; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVLDX_ReadVLDSX
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6849; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVLDX_ReadVLDSX
      return 6850; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVLDX_ReadVLDSX
    }
    break;
  case 2017: // WriteVLDS8_MF8_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6851; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6852; // VLEN512SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6853; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6854; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6855; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF8_Pred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
      return 6856; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_MF8_NoPred_ReadVPassthru_MF8_E8_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 5160: // WriteIDiv_ReadIDiv_ReadIDiv
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (!this->hasFeature(RISCV::Feature64Bit))
        return 6857; // VLEN512SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
      return 6858; // VLEN512SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (!this->hasFeature(RISCV::Feature64Bit))
        return 6859; // VLEN128X100SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
      return 6860; // VLEN128X100SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (!this->hasFeature(RISCV::Feature64Bit))
        return 6861; // VLEN1024X300SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
      return 6862; // VLEN1024X300SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIDiv_ReadIDiv
    }
    break;
  case 5261: // WriteIRem_ReadIRem_ReadIRem
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (!this->hasFeature(RISCV::Feature64Bit))
        return 6863; // VLEN512SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIRem_ReadIRem
      return 6864; // VLEN512SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIRem_ReadIRem
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (!this->hasFeature(RISCV::Feature64Bit))
        return 6865; // VLEN128X100SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIRem_ReadIRem
      return 6866; // VLEN128X100SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIRem_ReadIRem
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (!this->hasFeature(RISCV::Feature64Bit))
        return 6867; // VLEN1024X300SiFive7SiFive7RV32IDivRemSchedWriteRes_ReadIRem_ReadIRem
      return 6868; // VLEN1024X300SiFive7SiFive7RV64IDivRemSchedWriteRes_ReadIRem_ReadIRem
    }
    break;
  case 5382: // WriteVLDS16_WorstCase_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6869; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6870; // VLEN512SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6871; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6872; // VLEN128X100SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6873; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6874; // VLEN1024X300SiFive7anonymous_88087WriteVLDS16_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 5383: // WriteVLDS32_WorstCase_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6875; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6876; // VLEN512SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6877; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6878; // VLEN128X100SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6879; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6880; // VLEN1024X300SiFive7anonymous_88093WriteVLDS32_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 5384: // WriteVLDS64_WorstCase_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6881; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6882; // VLEN512SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6883; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6884; // VLEN128X100SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6885; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6886; // VLEN1024X300SiFive7anonymous_88099WriteVLDS64_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 5385: // WriteVLDS8_WorstCase_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    if (SchedModel->getProcessorID() == 6) { // SiFive7VLEN512Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6887; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6888; // VLEN512SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 11) { // SiFive7VLEN128X100Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6889; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6890; // VLEN128X100SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    if (SchedModel->getProcessorID() == 12) { // SiFive7VLEN1024X300Model
      if (this->hasFeature(RISCV::TuneOptimizedZeroStrideLoad) && MI->getOperand(3).getReg() == RISCV::X0)
        return 6891; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_Pred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
      return 6892; // VLEN1024X300SiFive7anonymous_88081WriteVLDS8_M8_NoPred_ReadVPassthru_WorstCase_ReadVLDX_ReadVLDSX_ReadVMask
    }
    break;
  case 5705: // COPY
    if (SchedModel->getProcessorID() == 3) { // SpacemitX60Model
      if ( TII->isVRegCopy(MI, /*LMUL=*/1) )
        return 6893; // SMX60WriteVCOPY_M1
      if ( TII->isVRegCopy(MI, /*LMUL=*/2) )
        return 6894; // SMX60WriteVCOPY_M2
      if ( TII->isVRegCopy(MI, /*LMUL=*/4) )
        return 6895; // SMX60WriteVCOPY_M4
      if ( TII->isVRegCopy(MI, /*LMUL=*/8) )
        return 6896; // SMX60WriteVCOPY_M8
      return 6897; // WriteIALU
    }
    break;
  };
  report_fatal_error("Expected a variant SchedClass");
} // RISCVGenSubtargetInfo::resolveSchedClass

unsigned RISCVGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return RISCV_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, *this, CPUID);
} // RISCVGenSubtargetInfo::resolveVariantSchedClass

unsigned RISCVGenSubtargetInfo::getHwModeSet() const {
  [[maybe_unused]] const auto *Subtarget =
      static_cast<const RISCVSubtarget *>(this);
  // Collect HwModes and store them as a bit set.
  unsigned Modes = 0;
  if ((Subtarget->is64Bit())) Modes |= (1 << 0);
  return Modes;
}
unsigned RISCVGenSubtargetInfo::getHwMode(enum HwModeType type) const {
  unsigned Modes = getHwModeSet();

  if (!Modes)
    return Modes;

  switch (type) {
  case HwMode_Default:
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_ValueType:
    Modes &= 1;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for ValueType were found!");
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_RegInfo:
    Modes &= 1;
    if (!Modes)
      return Modes;
    if (!llvm_ks::has_single_bit<unsigned>(Modes))
      llvm_unreachable("Two or more HwModes for RegInfo were found!");
    return llvm_ks::countr_zero(Modes) + 1;
  case HwMode_EncodingInfo:
    // No HwMode for EncodingInfo.
    return 0;
  }
  llvm_unreachable("unexpected HwModeType");
  return 0; // should not get here
}
std::vector<MacroFusionPredTy> RISCVGenSubtargetInfo::getMacroFusions() const {
  std::vector<MacroFusionPredTy> Fusions;
  if (hasFeature(RISCV::TuneADDILoadFusion)) Fusions.push_back(llvm_ks::isTuneADDILoadFusion);
  if (hasFeature(RISCV::TuneADDLoadFusion)) Fusions.push_back(llvm_ks::isTuneADDLoadFusion);
  if (hasFeature(RISCV::TuneAUIPCADDIFusion)) Fusions.push_back(llvm_ks::isTuneAUIPCADDIFusion);
  if (hasFeature(RISCV::TuneAUIPCLoadFusion)) Fusions.push_back(llvm_ks::isTuneAUIPCLoadFusion);
  if (hasFeature(RISCV::TuneBFExtFusion)) Fusions.push_back(llvm_ks::isTuneBFExtFusion);
  if (hasFeature(RISCV::TuneFusionAddMem)) Fusions.push_back(llvm_ks::isTuneFusionAddMem);
  if (hasFeature(RISCV::TuneFusionLogicImmReg)) Fusions.push_back(llvm_ks::isTuneFusionLogicImmReg);
  if (hasFeature(RISCV::TuneFusionLogicRegImm)) Fusions.push_back(llvm_ks::isTuneFusionLogicRegImm);
  if (hasFeature(RISCV::TuneFusionLogicRegReg)) Fusions.push_back(llvm_ks::isTuneFusionLogicRegReg);
  if (hasFeature(RISCV::TuneFusionMulAdd)) Fusions.push_back(llvm_ks::isTuneFusionMulAdd);
  if (hasFeature(RISCV::TuneFusionShiftBitExtract)) Fusions.push_back(llvm_ks::isTuneFusionShiftBitExtract);
  if (hasFeature(RISCV::TuneLDADDFusion)) Fusions.push_back(llvm_ks::isTuneLDADDFusion);
  if (hasFeature(RISCV::TuneLUIADDIFusion)) Fusions.push_back(llvm_ks::isTuneLUIADDIFusion);
  if (hasFeature(RISCV::TuneLUILoadFusion)) Fusions.push_back(llvm_ks::isTuneLUILoadFusion);
  if (hasFeature(RISCV::TuneQCELILoadStoreFusion)) Fusions.push_back(llvm_ks::isTuneQCELILoadStoreFusion);
  if (hasFeature(RISCV::TuneSHXADDLoadFusion)) Fusions.push_back(llvm_ks::isTuneSHXADDLoadFusion);
  if (hasFeature(RISCV::TuneShiftedZExtWFusion)) Fusions.push_back(llvm_ks::isTuneShiftedZExtWFusion);
  if (hasFeature(RISCV::TuneZExtHFusion)) Fusions.push_back(llvm_ks::isTuneZExtHFusion);
  if (hasFeature(RISCV::TuneZExtWFusion)) Fusions.push_back(llvm_ks::isTuneZExtWFusion);
  return Fusions;
}
const FeatureBitset &RISCVGenSubtargetInfo::getInlineIgnoreFeatures() const {
  static constexpr FeatureBitset Features = {
RISCV::TuneDLenFactor2,
RISCV::TuneDisableLatencySchedHeuristic,
RISCV::TuneNoDefaultUnroll,
RISCV::TuneDisableMISchedLoadClustering,
RISCV::TuneDisableMISchedStoreClustering,
RISCV::TuneDisablePostMISchedLoadClustering,
RISCV::TuneDisablePostMISchedStoreClustering,
RISCV::TuneEnableSelectOptimize,
RISCV::TuneEnableVsetvliSchedHeuristic,
RISCV::TuneConditionalCompressedMoveFusion,
RISCV::TuneOptimizedNF2SegmentLoadStore,
RISCV::TuneOptimizedNF3SegmentLoadStore,
RISCV::TuneOptimizedNF4SegmentLoadStore,
RISCV::TuneOptimizedNF5SegmentLoadStore,
RISCV::TuneOptimizedNF6SegmentLoadStore,
RISCV::TuneOptimizedNF7SegmentLoadStore,
RISCV::TuneOptimizedNF8SegmentLoadStore,
RISCV::TuneOptimizedZeroStrideLoad,
RISCV::TuneShortForwardBranchIALU,
RISCV::TuneShortForwardBranchILoad,
RISCV::TuneShortForwardBranchIMinMax,
RISCV::TuneShortForwardBranchIMul,
RISCV::TuneShortForwardBranchImm,
RISCV::TuneHasSingleElementVecFP64,
RISCV::TuneVLDependentLatency,
RISCV::TuneVXRMPipelineFlush,
RISCV::TunePredictableSelectIsExpensive,
RISCV::TunePreferAscendingLoadStore,
RISCV::TunePreferVsetvliOverReadVLENB,
RISCV::TunePreferWInst,
RISCV::TuneAndes45,
RISCV::TuneMIPSP8700,
RISCV::TuneVentanaVeyron,
RISCV::TuneSiFive7,
RISCV::TuneNLogNVRGather,
RISCV::TuneNoSinkSplatOperands,
RISCV::TunePostRAScheduler,
  };
  return Features;
}

const FeatureBitset &RISCVGenSubtargetInfo::getInlineInverseFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}

const FeatureBitset &RISCVGenSubtargetInfo::getInlineMustMatchFeatures() const {
  static constexpr FeatureBitset Features = {
  };
  return Features;
}


} // namespace llvm_ks

#endif // GET_SUBTARGETINFO_CTOR

#ifdef GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS
#undef GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS


#endif // GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS

#ifdef GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS
#undef GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS


#endif // GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS

