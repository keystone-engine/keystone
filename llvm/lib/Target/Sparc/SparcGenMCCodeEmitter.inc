/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Machine Code Emitter                                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

uint64_t SparcMCCodeEmitter::getBinaryCodeForInstr(const MCInst &MI,
    SmallVectorImpl<MCFixup> &Fixups,
    const MCSubtargetInfo &STI) const {
  static const uint64_t InstBits[] = {
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(2155880448),	// ADDCCri
    UINT64_C(2155872256),	// ADDCCrr
    UINT64_C(2151686144),	// ADDCri
    UINT64_C(2151677952),	// ADDCrr
    UINT64_C(2160074752),	// ADDEri
    UINT64_C(2160066560),	// ADDErr
    UINT64_C(2175795744),	// ADDXC
    UINT64_C(2175795808),	// ADDXCCC
    UINT64_C(2147491840),	// ADDXri
    UINT64_C(2147483648),	// ADDXrr
    UINT64_C(2147491840),	// ADDri
    UINT64_C(2147483648),	// ADDrr
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(2175795968),	// ALIGNADDR
    UINT64_C(2175796032),	// ALIGNADDRL
    UINT64_C(2156404736),	// ANDCCri
    UINT64_C(2156396544),	// ANDCCrr
    UINT64_C(2158501888),	// ANDNCCri
    UINT64_C(2158493696),	// ANDNCCrr
    UINT64_C(2150113280),	// ANDNri
    UINT64_C(2150105088),	// ANDNrr
    UINT64_C(2150105088),	// ANDXNrr
    UINT64_C(2148016128),	// ANDXri
    UINT64_C(2148007936),	// ANDXrr
    UINT64_C(2148016128),	// ANDri
    UINT64_C(2148007936),	// ANDrr
    UINT64_C(2175795776),	// ARRAY16
    UINT64_C(2175795840),	// ARRAY32
    UINT64_C(2175795712),	// ARRAY8
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(276824064),	// BA
    UINT64_C(8388608),	// BCOND
    UINT64_C(545259520),	// BCONDA
    UINT64_C(2176851968),	// BINDri
    UINT64_C(2176843776),	// BINDrr
    UINT64_C(2175796000),	// BMASK
    UINT64_C(21495808),	// BPFCC
    UINT64_C(558366720),	// BPFCCA
    UINT64_C(557842432),	// BPFCCANT
    UINT64_C(20971520),	// BPFCCNT
    UINT64_C(784334848),	// BPGEZapn
    UINT64_C(784859136),	// BPGEZapt
    UINT64_C(247463936),	// BPGEZnapn
    UINT64_C(247988224),	// BPGEZnapt
    UINT64_C(750780416),	// BPGZapn
    UINT64_C(751304704),	// BPGZapt
    UINT64_C(213909504),	// BPGZnapn
    UINT64_C(214433792),	// BPGZnapt
    UINT64_C(4718592),	// BPICC
    UINT64_C(541589504),	// BPICCA
    UINT64_C(541065216),	// BPICCANT
    UINT64_C(4194304),	// BPICCNT
    UINT64_C(616562688),	// BPLEZapn
    UINT64_C(617086976),	// BPLEZapt
    UINT64_C(79691776),	// BPLEZnapn
    UINT64_C(80216064),	// BPLEZnapt
    UINT64_C(650117120),	// BPLZapn
    UINT64_C(650641408),	// BPLZapt
    UINT64_C(113246208),	// BPLZnapn
    UINT64_C(113770496),	// BPLZnapt
    UINT64_C(717225984),	// BPNZapn
    UINT64_C(717750272),	// BPNZapt
    UINT64_C(180355072),	// BPNZnapn
    UINT64_C(180879360),	// BPNZnapt
    UINT64_C(6815744),	// BPXCC
    UINT64_C(543686656),	// BPXCCA
    UINT64_C(543162368),	// BPXCCANT
    UINT64_C(6291456),	// BPXCCNT
    UINT64_C(583008256),	// BPZapn
    UINT64_C(583532544),	// BPZapt
    UINT64_C(46137344),	// BPZnapn
    UINT64_C(46661632),	// BPZnapt
    UINT64_C(2175796096),	// BSHUFFLE
    UINT64_C(1073741824),	// CALL
    UINT64_C(2680168448),	// CALLri
    UINT64_C(2680160256),	// CALLrr
    UINT64_C(3253735424),	// CASXrr
    UINT64_C(3252686848),	// CASrr
    UINT64_C(2175796128),	// CMASK16
    UINT64_C(2175796192),	// CMASK32
    UINT64_C(2175796064),	// CMASK8
    UINT64_C(2157977600),	// CMPri
    UINT64_C(2157969408),	// CMPrr
    UINT64_C(2175795328),	// EDGE16
    UINT64_C(2175795392),	// EDGE16L
    UINT64_C(2175795424),	// EDGE16LN
    UINT64_C(2175795360),	// EDGE16N
    UINT64_C(2175795456),	// EDGE32
    UINT64_C(2175795520),	// EDGE32L
    UINT64_C(2175795552),	// EDGE32LN
    UINT64_C(2175795488),	// EDGE32N
    UINT64_C(2175795200),	// EDGE8
    UINT64_C(2175795264),	// EDGE8L
    UINT64_C(2175795296),	// EDGE8LN
    UINT64_C(2175795232),	// EDGE8N
    UINT64_C(2174746944),	// FABSD
    UINT64_C(2174746976),	// FABSQ
    UINT64_C(2174746912),	// FABSS
    UINT64_C(2174748736),	// FADDD
    UINT64_C(2174748768),	// FADDQ
    UINT64_C(2174748704),	// FADDS
    UINT64_C(2175797504),	// FALIGNADATA
    UINT64_C(2175798784),	// FAND
    UINT64_C(2175798528),	// FANDNOT1
    UINT64_C(2175798560),	// FANDNOT1S
    UINT64_C(2175798400),	// FANDNOT2
    UINT64_C(2175798432),	// FANDNOT2S
    UINT64_C(2175798816),	// FANDS
    UINT64_C(25165824),	// FBCOND
    UINT64_C(562036736),	// FBCONDA
    UINT64_C(2175797376),	// FCHKSM16
    UINT64_C(2175273536),	// FCMPD
    UINT64_C(2175796544),	// FCMPEQ16
    UINT64_C(2175796672),	// FCMPEQ32
    UINT64_C(2175796480),	// FCMPGT16
    UINT64_C(2175796608),	// FCMPGT32
    UINT64_C(2175796224),	// FCMPLE16
    UINT64_C(2175796352),	// FCMPLE32
    UINT64_C(2175796288),	// FCMPNE16
    UINT64_C(2175796416),	// FCMPNE32
    UINT64_C(2175273568),	// FCMPQ
    UINT64_C(2175273504),	// FCMPS
    UINT64_C(2174749120),	// FDIVD
    UINT64_C(2174749152),	// FDIVQ
    UINT64_C(2174749088),	// FDIVS
    UINT64_C(2174750144),	// FDMULQ
    UINT64_C(2174753344),	// FDTOI
    UINT64_C(2174753216),	// FDTOQ
    UINT64_C(2174752960),	// FDTOS
    UINT64_C(2174750784),	// FDTOX
    UINT64_C(2175797664),	// FEXPAND
    UINT64_C(2174749760),	// FHADDD
    UINT64_C(2174749728),	// FHADDS
    UINT64_C(2174749888),	// FHSUBD
    UINT64_C(2174749856),	// FHSUBS
    UINT64_C(2174753024),	// FITOD
    UINT64_C(2174753152),	// FITOQ
    UINT64_C(2174752896),	// FITOS
    UINT64_C(2175806016),	// FLCMPD
    UINT64_C(2175805984),	// FLCMPS
    UINT64_C(2178416640),	// FLUSH
    UINT64_C(2170028032),	// FLUSHW
    UINT64_C(2178424832),	// FLUSHri
    UINT64_C(2178416640),	// FLUSHrr
    UINT64_C(2175797248),	// FMEAN16
    UINT64_C(2174746688),	// FMOVD
    UINT64_C(2175270976),	// FMOVD_FCC
    UINT64_C(2175279168),	// FMOVD_ICC
    UINT64_C(2175283264),	// FMOVD_XCC
    UINT64_C(2174746720),	// FMOVQ
    UINT64_C(2175271008),	// FMOVQ_FCC
    UINT64_C(2175279200),	// FMOVQ_ICC
    UINT64_C(2175283296),	// FMOVQ_XCC
    UINT64_C(2175278272),	// FMOVRGEZD
    UINT64_C(2175278304),	// FMOVRGEZQ
    UINT64_C(2175278240),	// FMOVRGEZS
    UINT64_C(2175277248),	// FMOVRGZD
    UINT64_C(2175277280),	// FMOVRGZQ
    UINT64_C(2175277216),	// FMOVRGZS
    UINT64_C(2175273152),	// FMOVRLEZD
    UINT64_C(2175273184),	// FMOVRLEZQ
    UINT64_C(2175273120),	// FMOVRLEZS
    UINT64_C(2175274176),	// FMOVRLZD
    UINT64_C(2175274208),	// FMOVRLZQ
    UINT64_C(2175274144),	// FMOVRLZS
    UINT64_C(2175276224),	// FMOVRNZD
    UINT64_C(2175276256),	// FMOVRNZQ
    UINT64_C(2175276192),	// FMOVRNZS
    UINT64_C(2175272128),	// FMOVRZD
    UINT64_C(2175272160),	// FMOVRZQ
    UINT64_C(2175272096),	// FMOVRZS
    UINT64_C(2174746656),	// FMOVS
    UINT64_C(2175270944),	// FMOVS_FCC
    UINT64_C(2175279136),	// FMOVS_ICC
    UINT64_C(2175283232),	// FMOVS_XCC
    UINT64_C(2175796928),	// FMUL8SUX16
    UINT64_C(2175796960),	// FMUL8ULX16
    UINT64_C(2175796768),	// FMUL8X16
    UINT64_C(2175796896),	// FMUL8X16AL
    UINT64_C(2175796832),	// FMUL8X16AU
    UINT64_C(2174748992),	// FMULD
    UINT64_C(2175796992),	// FMULD8SUX16
    UINT64_C(2175797024),	// FMULD8ULX16
    UINT64_C(2174749024),	// FMULQ
    UINT64_C(2174748960),	// FMULS
    UINT64_C(2174749248),	// FNADDD
    UINT64_C(2174749216),	// FNADDS
    UINT64_C(2175798720),	// FNAND
    UINT64_C(2175798752),	// FNANDS
    UINT64_C(2174746816),	// FNEGD
    UINT64_C(2174746848),	// FNEGQ
    UINT64_C(2174746784),	// FNEGS
    UINT64_C(2174750272),	// FNHADDD
    UINT64_C(2174750240),	// FNHADDS
    UINT64_C(2174749504),	// FNMULD
    UINT64_C(2174749472),	// FNMULS
    UINT64_C(2175798336),	// FNOR
    UINT64_C(2175798368),	// FNORS
    UINT64_C(2175798592),	// FNOT1
    UINT64_C(2175798624),	// FNOT1S
    UINT64_C(2175798464),	// FNOT2
    UINT64_C(2175798496),	// FNOT2S
    UINT64_C(2174750496),	// FNSMULD
    UINT64_C(2175799232),	// FONE
    UINT64_C(2175799264),	// FONES
    UINT64_C(2175799168),	// FOR
    UINT64_C(2175799104),	// FORNOT1
    UINT64_C(2175799136),	// FORNOT1S
    UINT64_C(2175798976),	// FORNOT2
    UINT64_C(2175799008),	// FORNOT2S
    UINT64_C(2175799200),	// FORS
    UINT64_C(2175797088),	// FPACK16
    UINT64_C(2175797056),	// FPACK32
    UINT64_C(2175797152),	// FPACKFIX
    UINT64_C(2175797760),	// FPADD16
    UINT64_C(2175797792),	// FPADD16S
    UINT64_C(2175797824),	// FPADD32
    UINT64_C(2175797856),	// FPADD32S
    UINT64_C(2175797312),	// FPADD64
    UINT64_C(2175797600),	// FPMERGE
    UINT64_C(2175797888),	// FPSUB16
    UINT64_C(2175797920),	// FPSUB16S
    UINT64_C(2175797952),	// FPSUB32
    UINT64_C(2175797984),	// FPSUB32S
    UINT64_C(2174753120),	// FQTOD
    UINT64_C(2174753376),	// FQTOI
    UINT64_C(2174752992),	// FQTOS
    UINT64_C(2174750816),	// FQTOX
    UINT64_C(2175796512),	// FSLAS16
    UINT64_C(2175796640),	// FSLAS32
    UINT64_C(2175796256),	// FSLL16
    UINT64_C(2175796384),	// FSLL32
    UINT64_C(2174749984),	// FSMULD
    UINT64_C(2174747968),	// FSQRTD
    UINT64_C(2174748000),	// FSQRTQ
    UINT64_C(2174747936),	// FSQRTS
    UINT64_C(2175796576),	// FSRA16
    UINT64_C(2175796704),	// FSRA32
    UINT64_C(2175798912),	// FSRC1
    UINT64_C(2175798944),	// FSRC1S
    UINT64_C(2175799040),	// FSRC2
    UINT64_C(2175799072),	// FSRC2S
    UINT64_C(2175796320),	// FSRL16
    UINT64_C(2175796448),	// FSRL32
    UINT64_C(2174753056),	// FSTOD
    UINT64_C(2174753312),	// FSTOI
    UINT64_C(2174753184),	// FSTOQ
    UINT64_C(2174750752),	// FSTOX
    UINT64_C(2174748864),	// FSUBD
    UINT64_C(2174748896),	// FSUBQ
    UINT64_C(2174748832),	// FSUBS
    UINT64_C(2175798848),	// FXNOR
    UINT64_C(2175798880),	// FXNORS
    UINT64_C(2175798656),	// FXOR
    UINT64_C(2175798688),	// FXORS
    UINT64_C(2174750976),	// FXTOD
    UINT64_C(2174751104),	// FXTOQ
    UINT64_C(2174750848),	// FXTOS
    UINT64_C(2175798272),	// FZERO
    UINT64_C(2175798304),	// FZEROS
    UINT64_C(0),
    UINT64_C(2176851968),	// JMPLri
    UINT64_C(2176843776),	// JMPLrr
    UINT64_C(3229614080),	// LDArr
    UINT64_C(3231186944),	// LDDArr
    UINT64_C(3247964160),	// LDDFArr
    UINT64_C(3239583744),	// LDDFri
    UINT64_C(3239575552),	// LDDFrr
    UINT64_C(3222806528),	// LDDri
    UINT64_C(3222798336),	// LDDrr
    UINT64_C(3246391296),	// LDFArr
    UINT64_C(3238535168),	// LDFSRri
    UINT64_C(3238526976),	// LDFSRrr
    UINT64_C(3238010880),	// LDFri
    UINT64_C(3238002688),	// LDFrr
    UINT64_C(3247439872),	// LDQFArr
    UINT64_C(3239059456),	// LDQFri
    UINT64_C(3239051264),	// LDQFrr
    UINT64_C(3234332672),	// LDSBArr
    UINT64_C(3225952256),	// LDSBri
    UINT64_C(3225944064),	// LDSBrr
    UINT64_C(3234856960),	// LDSHArr
    UINT64_C(3226476544),	// LDSHri
    UINT64_C(3226468352),	// LDSHrr
    UINT64_C(3236429824),	// LDSTUBArr
    UINT64_C(3228049408),	// LDSTUBri
    UINT64_C(3228041216),	// LDSTUBrr
    UINT64_C(3225427968),	// LDSWri
    UINT64_C(3225419776),	// LDSWrr
    UINT64_C(3230138368),	// LDUBArr
    UINT64_C(3221757952),	// LDUBri
    UINT64_C(3221749760),	// LDUBrr
    UINT64_C(3230662656),	// LDUHArr
    UINT64_C(3222282240),	// LDUHri
    UINT64_C(3222274048),	// LDUHrr
    UINT64_C(3272089600),	// LDXFSRri
    UINT64_C(3272081408),	// LDXFSRrr
    UINT64_C(3227000832),	// LDXri
    UINT64_C(3226992640),	// LDXrr
    UINT64_C(3221233664),	// LDri
    UINT64_C(3221225472),	// LDrr
    UINT64_C(2147491840),	// LEAX_ADDri
    UINT64_C(2147491840),	// LEA_ADDri
    UINT64_C(2175795936),	// LZCNT
    UINT64_C(2168709120),	// MEMBARi
    UINT64_C(2175803904),	// MOVDTOX
    UINT64_C(2170560512),	// MOVFCCri
    UINT64_C(2170552320),	// MOVFCCrr
    UINT64_C(2170822656),	// MOVICCri
    UINT64_C(2170814464),	// MOVICCrr
    UINT64_C(2172140544),	// MOVRGEZri
    UINT64_C(2172132352),	// MOVRGEZrr
    UINT64_C(2172139520),	// MOVRGZri
    UINT64_C(2172131328),	// MOVRGZrr
    UINT64_C(2172135424),	// MOVRLEZri
    UINT64_C(2172127232),	// MOVRLEZrr
    UINT64_C(2172136448),	// MOVRLZri
    UINT64_C(2172128256),	// MOVRLZrr
    UINT64_C(2172138496),	// MOVRNZri
    UINT64_C(2172130304),	// MOVRNZrr
    UINT64_C(2172134400),	// MOVRRZri
    UINT64_C(2172126208),	// MOVRRZrr
    UINT64_C(2175804000),	// MOVSTOSW
    UINT64_C(2175803936),	// MOVSTOUW
    UINT64_C(2175804192),	// MOVWTOS
    UINT64_C(2170826752),	// MOVXCCri
    UINT64_C(2170818560),	// MOVXCCrr
    UINT64_C(2175804160),	// MOVXTOD
    UINT64_C(2166366208),	// MULSCCri
    UINT64_C(2166358016),	// MULSCCrr
    UINT64_C(2152210432),	// MULXri
    UINT64_C(2152202240),	// MULXrr
    UINT64_C(16777216),	// NOP
    UINT64_C(2156929024),	// ORCCri
    UINT64_C(2156920832),	// ORCCrr
    UINT64_C(2159026176),	// ORNCCri
    UINT64_C(2159017984),	// ORNCCrr
    UINT64_C(2150637568),	// ORNri
    UINT64_C(2150629376),	// ORNrr
    UINT64_C(2150629376),	// ORXNrr
    UINT64_C(2148540416),	// ORXri
    UINT64_C(2148532224),	// ORXrr
    UINT64_C(2148540416),	// ORri
    UINT64_C(2148532224),	// ORrr
    UINT64_C(2175797184),	// PDIST
    UINT64_C(2175797216),	// PDISTN
    UINT64_C(2171600896),	// POPCrr
    UINT64_C(2168455168),	// RDASR
    UINT64_C(2169503744),	// RDPR
    UINT64_C(2168979456),	// RDPSR
    UINT64_C(2170028032),	// RDTBR
    UINT64_C(2169503744),	// RDWIM
    UINT64_C(2179473408),	// RESTOREri
    UINT64_C(2179465216),	// RESTORErr
    UINT64_C(2177359872),	// RET
    UINT64_C(2177097728),	// RETL
    UINT64_C(2177376256),	// RETTri
    UINT64_C(2177368064),	// RETTrr
    UINT64_C(2178949120),	// SAVEri
    UINT64_C(2178940928),	// SAVErr
    UINT64_C(2163744768),	// SDIVCCri
    UINT64_C(2163736576),	// SDIVCCrr
    UINT64_C(2171084800),	// SDIVXri
    UINT64_C(2171076608),	// SDIVXrr
    UINT64_C(2155356160),	// SDIVri
    UINT64_C(2155347968),	// SDIVrr
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(16777216),	// SETHIXi
    UINT64_C(16777216),	// SETHIi
    UINT64_C(2175799296),	// SHUTDOWN
    UINT64_C(2175799328),	// SIAM
    UINT64_C(2166894592),	// SLLXri
    UINT64_C(2166886400),	// SLLXrr
    UINT64_C(2166890496),	// SLLri
    UINT64_C(2166882304),	// SLLrr
    UINT64_C(2161647616),	// SMULCCri
    UINT64_C(2161639424),	// SMULCCrr
    UINT64_C(2153259008),	// SMULri
    UINT64_C(2153250816),	// SMULrr
    UINT64_C(2167943168),	// SRAXri
    UINT64_C(2167934976),	// SRAXrr
    UINT64_C(2167939072),	// SRAri
    UINT64_C(2167930880),	// SRArr
    UINT64_C(2167418880),	// SRLXri
    UINT64_C(2167410688),	// SRLXrr
    UINT64_C(2167414784),	// SRLri
    UINT64_C(2167406592),	// SRLrr
    UINT64_C(3231711232),	// STArr
    UINT64_C(2168700928),	// STBAR
    UINT64_C(3232235520),	// STBArr
    UINT64_C(3223855104),	// STBri
    UINT64_C(3223846912),	// STBrr
    UINT64_C(3233284096),	// STDArr
    UINT64_C(3250061312),	// STDFArr
    UINT64_C(3241680896),	// STDFri
    UINT64_C(3241672704),	// STDFrr
    UINT64_C(3224903680),	// STDri
    UINT64_C(3224895488),	// STDrr
    UINT64_C(3248488448),	// STFArr
    UINT64_C(3240632320),	// STFSRri
    UINT64_C(3240624128),	// STFSRrr
    UINT64_C(3240108032),	// STFri
    UINT64_C(3240099840),	// STFrr
    UINT64_C(3232759808),	// STHArr
    UINT64_C(3224379392),	// STHri
    UINT64_C(3224371200),	// STHrr
    UINT64_C(3249537024),	// STQFArr
    UINT64_C(3241156608),	// STQFri
    UINT64_C(3241148416),	// STQFrr
    UINT64_C(3274186752),	// STXFSRri
    UINT64_C(3274178560),	// STXFSRrr
    UINT64_C(3228573696),	// STXri
    UINT64_C(3228565504),	// STXrr
    UINT64_C(3223330816),	// STri
    UINT64_C(3223322624),	// STrr
    UINT64_C(2157977600),	// SUBCCri
    UINT64_C(2157969408),	// SUBCCrr
    UINT64_C(2153783296),	// SUBCri
    UINT64_C(2153775104),	// SUBCrr
    UINT64_C(2162171904),	// SUBEri
    UINT64_C(2162163712),	// SUBErr
    UINT64_C(2149588992),	// SUBXri
    UINT64_C(2149580800),	// SUBXrr
    UINT64_C(2149588992),	// SUBri
    UINT64_C(2149580800),	// SUBrr
    UINT64_C(3237478400),	// SWAPArr
    UINT64_C(3229097984),	// SWAPri
    UINT64_C(3229089792),	// SWAPrr
    UINT64_C(2177916931),	// TA3
    UINT64_C(2446336005),	// TA5
    UINT64_C(2165317632),	// TADDCCTVri
    UINT64_C(2165309440),	// TADDCCTVrr
    UINT64_C(2164269056),	// TADDCCri
    UINT64_C(2164260864),	// TADDCCrr
    UINT64_C(2177900544),	// TICCri
    UINT64_C(2177892352),	// TICCrr
    UINT64_C(2147483648),	// TLS_ADDXrr
    UINT64_C(2147483648),	// TLS_ADDrr
    UINT64_C(1073741824),	// TLS_CALL
    UINT64_C(3226992640),	// TLS_LDXrr
    UINT64_C(3221225472),	// TLS_LDrr
    UINT64_C(2165841920),	// TSUBCCTVri
    UINT64_C(2165833728),	// TSUBCCTVrr
    UINT64_C(2164793344),	// TSUBCCri
    UINT64_C(2164785152),	// TSUBCCrr
    UINT64_C(2177904640),	// TXCCri
    UINT64_C(2177896448),	// TXCCrr
    UINT64_C(2163220480),	// UDIVCCri
    UINT64_C(2163212288),	// UDIVCCrr
    UINT64_C(2154307584),	// UDIVXri
    UINT64_C(2154299392),	// UDIVXrr
    UINT64_C(2154831872),	// UDIVri
    UINT64_C(2154823680),	// UDIVrr
    UINT64_C(2161123328),	// UMULCCri
    UINT64_C(2161115136),	// UMULCCrr
    UINT64_C(2175795904),	// UMULXHI
    UINT64_C(2152734720),	// UMULri
    UINT64_C(2152726528),	// UMULrr
    UINT64_C(0),	// UNIMP
    UINT64_C(2175273536),	// V9FCMPD
    UINT64_C(2175273664),	// V9FCMPED
    UINT64_C(2175273696),	// V9FCMPEQ
    UINT64_C(2175273632),	// V9FCMPES
    UINT64_C(2175273568),	// V9FCMPQ
    UINT64_C(2175273504),	// V9FCMPS
    UINT64_C(2175270976),	// V9FMOVD_FCC
    UINT64_C(2175271008),	// V9FMOVQ_FCC
    UINT64_C(2175270944),	// V9FMOVS_FCC
    UINT64_C(2170560512),	// V9MOVFCCri
    UINT64_C(2170552320),	// V9MOVFCCrr
    UINT64_C(2172657664),	// WRASRri
    UINT64_C(2172649472),	// WRASRrr
    UINT64_C(2173706240),	// WRPRri
    UINT64_C(2173698048),	// WRPRrr
    UINT64_C(2173181952),	// WRPSRri
    UINT64_C(2173173760),	// WRPSRrr
    UINT64_C(2174230528),	// WRTBRri
    UINT64_C(2174222336),	// WRTBRrr
    UINT64_C(2173706240),	// WRWIMri
    UINT64_C(2173698048),	// WRWIMrr
    UINT64_C(2175804064),	// XMULX
    UINT64_C(2175804128),	// XMULXHI
    UINT64_C(2159550464),	// XNORCCri
    UINT64_C(2159542272),	// XNORCCrr
    UINT64_C(2151153664),	// XNORXrr
    UINT64_C(2151161856),	// XNORri
    UINT64_C(2151153664),	// XNORrr
    UINT64_C(2157453312),	// XORCCri
    UINT64_C(2157445120),	// XORCCrr
    UINT64_C(2149064704),	// XORXri
    UINT64_C(2149056512),	// XORXrr
    UINT64_C(2149064704),	// XORri
    UINT64_C(2149056512),	// XORrr
    UINT64_C(0)
  };
  const unsigned opcode = MI.getOpcode();
  uint64_t Value = InstBits[opcode];
  uint64_t op = 0;
  (void)op;  // suppress warning
  switch (opcode) {
    case SP::FLUSH:
    case SP::FLUSHW:
    case SP::NOP:
    case SP::SHUTDOWN:
    case SP::SIAM:
    case SP::STBAR:
    case SP::TA3:
    case SP::TA5: {
      break;
    }
    case SP::BPFCC:
    case SP::BPFCCA:
    case SP::BPFCCANT:
    case SP::BPFCCNT: {
      // op: cc
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 20;
      // op: cond
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 25;
      // op: imm19
      op = getBranchPredTargetOpValue(MI, 0, Fixups, STI);
      Value |= op & UINT64_C(524287);
      break;
    }
    case SP::BPICC:
    case SP::BPICCA:
    case SP::BPICCANT:
    case SP::BPICCNT:
    case SP::BPXCC:
    case SP::BPXCCA:
    case SP::BPXCCANT:
    case SP::BPXCCNT: {
      // op: cond
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 25;
      // op: imm19
      op = getBranchPredTargetOpValue(MI, 0, Fixups, STI);
      Value |= op & UINT64_C(524287);
      break;
    }
    case SP::CALL:
    case SP::TLS_CALL: {
      // op: disp
      op = getCallTargetOpValue(MI, 0, Fixups, STI);
      Value |= op & UINT64_C(1073741823);
      break;
    }
    case SP::BPGEZapn:
    case SP::BPGEZapt:
    case SP::BPGEZnapn:
    case SP::BPGEZnapt:
    case SP::BPGZapn:
    case SP::BPGZapt:
    case SP::BPGZnapn:
    case SP::BPGZnapt:
    case SP::BPLEZapn:
    case SP::BPLEZapt:
    case SP::BPLEZnapn:
    case SP::BPLEZnapt:
    case SP::BPLZapn:
    case SP::BPLZapt:
    case SP::BPLZnapn:
    case SP::BPLZnapt:
    case SP::BPNZapn:
    case SP::BPNZapt:
    case SP::BPNZnapn:
    case SP::BPNZnapt:
    case SP::BPZapn:
    case SP::BPZapt:
    case SP::BPZnapn:
    case SP::BPZnapt: {
      // op: imm16
      op = getBranchOnRegTargetOpValue(MI, 1, Fixups, STI);
      Value |= (op & UINT64_C(49152)) << 6;
      Value |= op & UINT64_C(16383);
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      break;
    }
    case SP::BA: {
      // op: imm22
      op = getBranchTargetOpValue(MI, 0, Fixups, STI);
      Value |= op & UINT64_C(4194303);
      break;
    }
    case SP::BCOND:
    case SP::BCONDA:
    case SP::FBCOND:
    case SP::FBCONDA: {
      // op: imm22
      op = getBranchTargetOpValue(MI, 0, Fixups, STI);
      Value |= op & UINT64_C(4194303);
      // op: cond
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 25;
      break;
    }
    case SP::UNIMP: {
      // op: imm22
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(4194303);
      break;
    }
    case SP::SETHIXi:
    case SP::SETHIi: {
      // op: imm22
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(4194303);
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      break;
    }
    case SP::FONE:
    case SP::FONES:
    case SP::FZERO:
    case SP::FZEROS:
    case SP::RDPSR:
    case SP::RDTBR:
    case SP::RDWIM: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      break;
    }
    case SP::V9MOVFCCrr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: cc
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: cond
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 14;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::V9MOVFCCri: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: cc
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: cond
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 14;
      // op: simm11
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(2047);
      break;
    }
    case SP::FMOVD_FCC:
    case SP::FMOVD_ICC:
    case SP::FMOVD_XCC:
    case SP::FMOVQ_FCC:
    case SP::FMOVQ_ICC:
    case SP::FMOVQ_XCC:
    case SP::FMOVS_FCC:
    case SP::FMOVS_ICC:
    case SP::FMOVS_XCC:
    case SP::MOVFCCrr:
    case SP::MOVICCrr:
    case SP::MOVXCCrr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: cond
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 14;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::MOVFCCri:
    case SP::MOVICCri:
    case SP::MOVXCCri: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: cond
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 14;
      // op: simm11
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(2047);
      break;
    }
    case SP::V9FMOVD_FCC:
    case SP::V9FMOVQ_FCC:
    case SP::V9FMOVS_FCC: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: cond
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 14;
      // op: opf_cc
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::FNOT1:
    case SP::FNOT1S:
    case SP::FSRC1:
    case SP::FSRC1S:
    case SP::RDASR:
    case SP::RDPR: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      break;
    }
    case SP::LDArr:
    case SP::LDDArr:
    case SP::LDDFArr:
    case SP::LDFArr:
    case SP::LDQFArr:
    case SP::LDSBArr:
    case SP::LDSHArr:
    case SP::LDSTUBArr:
    case SP::LDUBArr:
    case SP::LDUHArr:
    case SP::SWAPArr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: asi
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::ADDCCrr:
    case SP::ADDCrr:
    case SP::ADDErr:
    case SP::ADDXC:
    case SP::ADDXCCC:
    case SP::ADDXrr:
    case SP::ADDrr:
    case SP::ALIGNADDR:
    case SP::ALIGNADDRL:
    case SP::ANDCCrr:
    case SP::ANDNCCrr:
    case SP::ANDNrr:
    case SP::ANDXNrr:
    case SP::ANDXrr:
    case SP::ANDrr:
    case SP::ARRAY16:
    case SP::ARRAY32:
    case SP::ARRAY8:
    case SP::BMASK:
    case SP::BSHUFFLE:
    case SP::CASXrr:
    case SP::CASrr:
    case SP::EDGE16:
    case SP::EDGE16L:
    case SP::EDGE16LN:
    case SP::EDGE16N:
    case SP::EDGE32:
    case SP::EDGE32L:
    case SP::EDGE32LN:
    case SP::EDGE32N:
    case SP::EDGE8:
    case SP::EDGE8L:
    case SP::EDGE8LN:
    case SP::EDGE8N:
    case SP::FADDD:
    case SP::FADDQ:
    case SP::FADDS:
    case SP::FALIGNADATA:
    case SP::FAND:
    case SP::FANDNOT1:
    case SP::FANDNOT1S:
    case SP::FANDNOT2:
    case SP::FANDNOT2S:
    case SP::FANDS:
    case SP::FCHKSM16:
    case SP::FCMPEQ16:
    case SP::FCMPEQ32:
    case SP::FCMPGT16:
    case SP::FCMPGT32:
    case SP::FCMPLE16:
    case SP::FCMPLE32:
    case SP::FCMPNE16:
    case SP::FCMPNE32:
    case SP::FDIVD:
    case SP::FDIVQ:
    case SP::FDIVS:
    case SP::FDMULQ:
    case SP::FHADDD:
    case SP::FHADDS:
    case SP::FHSUBD:
    case SP::FHSUBS:
    case SP::FLCMPD:
    case SP::FLCMPS:
    case SP::FMEAN16:
    case SP::FMOVRGEZD:
    case SP::FMOVRGEZQ:
    case SP::FMOVRGEZS:
    case SP::FMOVRGZD:
    case SP::FMOVRGZQ:
    case SP::FMOVRGZS:
    case SP::FMOVRLEZD:
    case SP::FMOVRLEZQ:
    case SP::FMOVRLEZS:
    case SP::FMOVRLZD:
    case SP::FMOVRLZQ:
    case SP::FMOVRLZS:
    case SP::FMOVRNZD:
    case SP::FMOVRNZQ:
    case SP::FMOVRNZS:
    case SP::FMOVRZD:
    case SP::FMOVRZQ:
    case SP::FMOVRZS:
    case SP::FMUL8SUX16:
    case SP::FMUL8ULX16:
    case SP::FMUL8X16:
    case SP::FMUL8X16AL:
    case SP::FMUL8X16AU:
    case SP::FMULD:
    case SP::FMULD8SUX16:
    case SP::FMULD8ULX16:
    case SP::FMULQ:
    case SP::FMULS:
    case SP::FNADDD:
    case SP::FNADDS:
    case SP::FNAND:
    case SP::FNANDS:
    case SP::FNHADDD:
    case SP::FNHADDS:
    case SP::FNMULD:
    case SP::FNMULS:
    case SP::FNOR:
    case SP::FNORS:
    case SP::FNSMULD:
    case SP::FOR:
    case SP::FORNOT1:
    case SP::FORNOT1S:
    case SP::FORNOT2:
    case SP::FORNOT2S:
    case SP::FORS:
    case SP::FPACK32:
    case SP::FPADD16:
    case SP::FPADD16S:
    case SP::FPADD32:
    case SP::FPADD32S:
    case SP::FPADD64:
    case SP::FPMERGE:
    case SP::FPSUB16:
    case SP::FPSUB16S:
    case SP::FPSUB32:
    case SP::FPSUB32S:
    case SP::FSLAS16:
    case SP::FSLAS32:
    case SP::FSLL16:
    case SP::FSLL32:
    case SP::FSMULD:
    case SP::FSRA16:
    case SP::FSRA32:
    case SP::FSRL16:
    case SP::FSRL32:
    case SP::FSUBD:
    case SP::FSUBQ:
    case SP::FSUBS:
    case SP::FXNOR:
    case SP::FXNORS:
    case SP::FXOR:
    case SP::FXORS:
    case SP::JMPLrr:
    case SP::LDDFrr:
    case SP::LDDrr:
    case SP::LDFrr:
    case SP::LDQFrr:
    case SP::LDSBrr:
    case SP::LDSHrr:
    case SP::LDSTUBrr:
    case SP::LDSWrr:
    case SP::LDUBrr:
    case SP::LDUHrr:
    case SP::LDXrr:
    case SP::LDrr:
    case SP::MOVRGEZrr:
    case SP::MOVRGZrr:
    case SP::MOVRLEZrr:
    case SP::MOVRLZrr:
    case SP::MOVRNZrr:
    case SP::MOVRRZrr:
    case SP::MULSCCrr:
    case SP::MULXrr:
    case SP::ORCCrr:
    case SP::ORNCCrr:
    case SP::ORNrr:
    case SP::ORXNrr:
    case SP::ORXrr:
    case SP::ORrr:
    case SP::PDIST:
    case SP::PDISTN:
    case SP::RESTORErr:
    case SP::SAVErr:
    case SP::SDIVCCrr:
    case SP::SDIVXrr:
    case SP::SDIVrr:
    case SP::SLLXrr:
    case SP::SLLrr:
    case SP::SMULCCrr:
    case SP::SMULrr:
    case SP::SRAXrr:
    case SP::SRArr:
    case SP::SRLXrr:
    case SP::SRLrr:
    case SP::SUBCCrr:
    case SP::SUBCrr:
    case SP::SUBErr:
    case SP::SUBXrr:
    case SP::SUBrr:
    case SP::SWAPrr:
    case SP::TADDCCTVrr:
    case SP::TADDCCrr:
    case SP::TLS_ADDXrr:
    case SP::TLS_ADDrr:
    case SP::TLS_LDXrr:
    case SP::TLS_LDrr:
    case SP::TSUBCCTVrr:
    case SP::TSUBCCrr:
    case SP::UDIVCCrr:
    case SP::UDIVXrr:
    case SP::UDIVrr:
    case SP::UMULCCrr:
    case SP::UMULXHI:
    case SP::UMULrr:
    case SP::V9FCMPD:
    case SP::V9FCMPED:
    case SP::V9FCMPEQ:
    case SP::V9FCMPES:
    case SP::V9FCMPQ:
    case SP::V9FCMPS:
    case SP::WRASRrr:
    case SP::WRPRrr:
    case SP::XMULX:
    case SP::XMULXHI:
    case SP::XNORCCrr:
    case SP::XNORXrr:
    case SP::XNORrr:
    case SP::XORCCrr:
    case SP::XORXrr:
    case SP::XORrr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::SLLXri:
    case SP::SRAXri:
    case SP::SRLXri: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: shcnt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(63);
      break;
    }
    case SP::MOVRGEZri:
    case SP::MOVRGZri:
    case SP::MOVRLEZri:
    case SP::MOVRLZri:
    case SP::MOVRNZri:
    case SP::MOVRRZri: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: simm10
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(1023);
      break;
    }
    case SP::ADDCCri:
    case SP::ADDCri:
    case SP::ADDEri:
    case SP::ADDXri:
    case SP::ADDri:
    case SP::ANDCCri:
    case SP::ANDNCCri:
    case SP::ANDNri:
    case SP::ANDXri:
    case SP::ANDri:
    case SP::JMPLri:
    case SP::LDDFri:
    case SP::LDDri:
    case SP::LDFri:
    case SP::LDQFri:
    case SP::LDSBri:
    case SP::LDSHri:
    case SP::LDSTUBri:
    case SP::LDSWri:
    case SP::LDUBri:
    case SP::LDUHri:
    case SP::LDXri:
    case SP::LDri:
    case SP::LEAX_ADDri:
    case SP::LEA_ADDri:
    case SP::MULSCCri:
    case SP::MULXri:
    case SP::ORCCri:
    case SP::ORNCCri:
    case SP::ORNri:
    case SP::ORXri:
    case SP::ORri:
    case SP::RESTOREri:
    case SP::SAVEri:
    case SP::SDIVCCri:
    case SP::SDIVXri:
    case SP::SDIVri:
    case SP::SLLri:
    case SP::SMULCCri:
    case SP::SMULri:
    case SP::SRAri:
    case SP::SRLri:
    case SP::SUBCCri:
    case SP::SUBCri:
    case SP::SUBEri:
    case SP::SUBXri:
    case SP::SUBri:
    case SP::SWAPri:
    case SP::TADDCCTVri:
    case SP::TADDCCri:
    case SP::TSUBCCTVri:
    case SP::TSUBCCri:
    case SP::UDIVCCri:
    case SP::UDIVXri:
    case SP::UDIVri:
    case SP::UMULCCri:
    case SP::UMULri:
    case SP::WRASRri:
    case SP::WRPRri:
    case SP::XNORCCri:
    case SP::XNORri:
    case SP::XORCCri:
    case SP::XORXri:
    case SP::XORri: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: simm13
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(8191);
      break;
    }
    case SP::FABSD:
    case SP::FABSQ:
    case SP::FABSS:
    case SP::FDTOI:
    case SP::FDTOQ:
    case SP::FDTOS:
    case SP::FDTOX:
    case SP::FEXPAND:
    case SP::FITOD:
    case SP::FITOQ:
    case SP::FITOS:
    case SP::FMOVD:
    case SP::FMOVQ:
    case SP::FMOVS:
    case SP::FNEGD:
    case SP::FNEGQ:
    case SP::FNEGS:
    case SP::FNOT2:
    case SP::FNOT2S:
    case SP::FPACK16:
    case SP::FPACKFIX:
    case SP::FQTOD:
    case SP::FQTOI:
    case SP::FQTOS:
    case SP::FQTOX:
    case SP::FSQRTD:
    case SP::FSQRTQ:
    case SP::FSQRTS:
    case SP::FSRC2:
    case SP::FSRC2S:
    case SP::FSTOD:
    case SP::FSTOI:
    case SP::FSTOQ:
    case SP::FSTOX:
    case SP::FXTOD:
    case SP::FXTOQ:
    case SP::FXTOS:
    case SP::LZCNT:
    case SP::MOVDTOX:
    case SP::MOVSTOSW:
    case SP::MOVSTOUW:
    case SP::MOVWTOS:
    case SP::MOVXTOD:
    case SP::POPCrr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::STArr:
    case SP::STBArr:
    case SP::STDArr:
    case SP::STDFArr:
    case SP::STFArr:
    case SP::STHArr:
    case SP::STQFArr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: asi
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::STBrr:
    case SP::STDFrr:
    case SP::STDrr:
    case SP::STFrr:
    case SP::STHrr:
    case SP::STQFrr:
    case SP::STXrr:
    case SP::STrr: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::STBri:
    case SP::STDFri:
    case SP::STDri:
    case SP::STFri:
    case SP::STHri:
    case SP::STQFri:
    case SP::STXri:
    case SP::STri: {
      // op: rd
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 25;
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: simm13
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(8191);
      break;
    }
    case SP::TICCri:
    case SP::TXCCri: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: cond
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 25;
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(255);
      break;
    }
    case SP::TICCrr:
    case SP::TXCCrr: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: cond
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 25;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::BINDrr:
    case SP::CALLrr:
    case SP::CMPrr:
    case SP::FCMPD:
    case SP::FCMPQ:
    case SP::FCMPS:
    case SP::FLUSHrr:
    case SP::LDFSRrr:
    case SP::LDXFSRrr:
    case SP::RETTrr:
    case SP::STFSRrr:
    case SP::STXFSRrr:
    case SP::WRPSRrr:
    case SP::WRTBRrr:
    case SP::WRWIMrr: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::BINDri:
    case SP::CALLri:
    case SP::CMPri:
    case SP::FLUSHri:
    case SP::LDFSRri:
    case SP::LDXFSRri:
    case SP::RETTri:
    case SP::STFSRri:
    case SP::STXFSRri:
    case SP::WRPSRri:
    case SP::WRTBRri:
    case SP::WRWIMri: {
      // op: rs1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 14;
      // op: simm13
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(8191);
      break;
    }
    case SP::CMASK16:
    case SP::CMASK32:
    case SP::CMASK8: {
      // op: rs2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case SP::MEMBARi:
    case SP::RET:
    case SP::RETL: {
      // op: simm13
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(8191);
      break;
    }
  default:
    std::string msg;
    raw_string_ostream Msg(msg);
    Msg << "Not supported instr: " << MI;
    report_fatal_error(Msg.str());
  }
  return Value;
}

