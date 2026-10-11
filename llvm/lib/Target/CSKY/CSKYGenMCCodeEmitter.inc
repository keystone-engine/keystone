/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Machine Code Emitter                                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

uint64_t CSKYMCCodeEmitter::getBinaryCodeForInstr(const MCInst &MI,
    SmallVectorImpl<MCFixup> &Fixups,
    const MCSubtargetInfo &STI) const {
  static const uint64_t InstBits[] = {
    UINT64_C(3288334848),	// ABS32
    UINT64_C(24577),	// ADDC16
    UINT64_C(3288334400),	// ADDC32
    UINT64_C(8192),	// ADDI16
    UINT64_C(5120),	// ADDI16SPSP
    UINT64_C(22530),	// ADDI16XZ
    UINT64_C(6144),	// ADDI16ZSP
    UINT64_C(3825205248),	// ADDI32
    UINT64_C(22528),	// ADDU16
    UINT64_C(24576),	// ADDU16XZ
    UINT64_C(3288334368),	// ADDU32
    UINT64_C(26624),	// AND16
    UINT64_C(3288342560),	// AND32
    UINT64_C(3825213440),	// ANDI32
    UINT64_C(26625),	// ANDN16
    UINT64_C(3288342592),	// ANDN32
    UINT64_C(3825217536),	// ANDNI32
    UINT64_C(28674),	// ASR16
    UINT64_C(3288350848),	// ASR32
    UINT64_C(3288353920),	// ASRC32
    UINT64_C(20480),	// ASRI16
    UINT64_C(3288352896),	// ASRI32
    UINT64_C(14464),	// BCLRI16
    UINT64_C(3288344608),	// BCLRI32
    UINT64_C(3909091328),	// BEZ32
    UINT64_C(3072),	// BF16
    UINT64_C(3896508416),	// BF32
    UINT64_C(3288354880),	// BGENR32
    UINT64_C(3919577088),	// BHSZ32
    UINT64_C(3913285632),	// BHZ32
    UINT64_C(0),	// BKPT
    UINT64_C(3915382784),	// BLSZ32
    UINT64_C(3917479936),	// BLZ32
    UINT64_C(3288354848),	// BMASKI32
    UINT64_C(3911188480),	// BNEZ32
    UINT64_C(3894411264),	// BNEZAD32
    UINT64_C(5280),	// BPOPH
    UINT64_C(5282),	// BPOPW
    UINT64_C(5344),	// BPUSHH
    UINT64_C(5346),	// BPUSHW
    UINT64_C(1024),	// BR16
    UINT64_C(3892314112),	// BR32
    UINT64_C(3221259301),	// BRAR
    UINT64_C(3254813733),	// BRARS
    UINT64_C(3221259303),	// BRARW
    UINT64_C(3254813735),	// BRARWS
    UINT64_C(3288359424),	// BREV32
    UINT64_C(3221259311),	// BRWARW
    UINT64_C(3254813743),	// BRWARWS
    UINT64_C(3221259310),	// BRWAW
    UINT64_C(3254813742),	// BRWAWS
    UINT64_C(14496),	// BSETI16
    UINT64_C(3288344640),	// BSETI32
    UINT64_C(3758096384),	// BSR32
    UINT64_C(3758096384),	// BSR32_BR
    UINT64_C(2048),	// BT16
    UINT64_C(3898605568),	// BT32
    UINT64_C(14528),	// BTSTI16
    UINT64_C(3288344704),	// BTSTI32
    UINT64_C(3221259306),	// BWAW
    UINT64_C(3254813738),	// BWAWS
    UINT64_C(25602),	// CLRC16
    UINT64_C(3288335488),	// CLRC32
    UINT64_C(3288345632),	// CLRF32
    UINT64_C(3288345664),	// CLRT32
    UINT64_C(25600),	// CMPHS16
    UINT64_C(3288335392),	// CMPHS32
    UINT64_C(14336),	// CMPHSI16
    UINT64_C(3942645760),	// CMPHSI32
    UINT64_C(25601),	// CMPLT16
    UINT64_C(3288335424),	// CMPLT32
    UINT64_C(14368),	// CMPLTI16
    UINT64_C(3944742912),	// CMPLTI32
    UINT64_C(25602),	// CMPNE16
    UINT64_C(3288335488),	// CMPNE32
    UINT64_C(14400),	// CMPNEI16
    UINT64_C(3946840064),	// CMPNEI32
    UINT64_C(4227891200),	// CPOP32
    UINT64_C(4227874816),	// CPRC32
    UINT64_C(4227866624),	// CPRCR32
    UINT64_C(4227858432),	// CPRGR32
    UINT64_C(4227870720),	// CPWCR32
    UINT64_C(4227862528),	// CPWGR32
    UINT64_C(3229652000),	// DCACHE_CALL32
    UINT64_C(3246429216),	// DCACHE_CIALL32
    UINT64_C(3250623520),	// DCACHE_CISW32
    UINT64_C(3252720672),	// DCACHE_CIVA32
    UINT64_C(3233846304),	// DCACHE_CSW32
    UINT64_C(3235943456),	// DCACHE_CVA32
    UINT64_C(3269497888),	// DCACHE_CVAL32
    UINT64_C(3238040608),	// DCACHE_IALL32
    UINT64_C(3242234912),	// DCACHE_ISW32
    UINT64_C(3244332064),	// DCACHE_IVA32
    UINT64_C(3288337536),	// DECF32
    UINT64_C(3288338464),	// DECGT32
    UINT64_C(3288338496),	// DECLT32
    UINT64_C(3288338560),	// DECNE32
    UINT64_C(3288337664),	// DECT32
    UINT64_C(3288367168),	// DIVS32
    UINT64_C(3288367136),	// DIVU32
    UINT64_C(3221245984),	// DOZE32
    UINT64_C(4093644992),	// FABSM
    UINT64_C(4093642944),	// FABS_D
    UINT64_C(4093640896),	// FABS_S
    UINT64_C(4093644800),	// FADDM
    UINT64_C(4093642752),	// FADD_D
    UINT64_C(4093640704),	// FADD_S
    UINT64_C(4093643136),	// FCMPHS_D
    UINT64_C(4093641088),	// FCMPHS_S
    UINT64_C(4093643168),	// FCMPLT_D
    UINT64_C(4093641120),	// FCMPLT_S
    UINT64_C(4093643200),	// FCMPNE_D
    UINT64_C(4093641152),	// FCMPNE_S
    UINT64_C(4093643232),	// FCMPUO_D
    UINT64_C(4093641184),	// FCMPUO_S
    UINT64_C(4093643008),	// FCMPZHS_D
    UINT64_C(4093640960),	// FCMPZHS_S
    UINT64_C(4093643040),	// FCMPZLS_D
    UINT64_C(4093640992),	// FCMPZLS_S
    UINT64_C(4093643072),	// FCMPZNE_D
    UINT64_C(4093641024),	// FCMPZNE_S
    UINT64_C(4093643104),	// FCMPZUO_D
    UINT64_C(4093641056),	// FCMPZUO_S
    UINT64_C(4093643520),	// FDIV_D
    UINT64_C(4093641472),	// FDIV_S
    UINT64_C(4093647552),	// FDTOS
    UINT64_C(3288366112),	// FF0
    UINT64_C(3288366144),	// FF1
    UINT64_C(4093649408),	// FLDM
    UINT64_C(4093653504),	// FLDMM
    UINT64_C(4093653248),	// FLDM_D
    UINT64_C(4093652992),	// FLDM_S
    UINT64_C(4093651456),	// FLDRM
    UINT64_C(4093651200),	// FLDR_D
    UINT64_C(4093650944),	// FLDR_S
    UINT64_C(4093649152),	// FLD_D
    UINT64_C(4093648896),	// FLD_S
    UINT64_C(4093645440),	// FMACM
    UINT64_C(4093643392),	// FMAC_D
    UINT64_C(4093641344),	// FMAC_S
    UINT64_C(4093647616),	// FMFVRH_D
    UINT64_C(4093647648),	// FMFVRL
    UINT64_C(4093647648),	// FMFVRL_D
    UINT64_C(4093644928),	// FMOVM
    UINT64_C(4093642880),	// FMOV_D
    UINT64_C(4093640832),	// FMOV_S
    UINT64_C(4093645472),	// FMSCM
    UINT64_C(4093643424),	// FMSC_D
    UINT64_C(4093641376),	// FMSC_S
    UINT64_C(4093647680),	// FMTVRH_D
    UINT64_C(4093647712),	// FMTVRL
    UINT64_C(4093647712),	// FMTVRL_D
    UINT64_C(4093645312),	// FMULM
    UINT64_C(4093643264),	// FMUL_D
    UINT64_C(4093641216),	// FMUL_S
    UINT64_C(4093645024),	// FNEGM
    UINT64_C(4093642976),	// FNEG_D
    UINT64_C(4093640928),	// FNEG_S
    UINT64_C(4093645504),	// FNMACM
    UINT64_C(4093643456),	// FNMAC_D
    UINT64_C(4093641408),	// FNMAC_S
    UINT64_C(4093645536),	// FNMSCM
    UINT64_C(4093643488),	// FNMSC_D
    UINT64_C(4093641440),	// FNMSC_S
    UINT64_C(4093645344),	// FNMULM
    UINT64_C(4093643296),	// FNMUL_D
    UINT64_C(4093641248),	// FNMUL_S
    UINT64_C(4093643552),	// FRECIP_D
    UINT64_C(4093641504),	// FRECIP_S
    UINT64_C(4093647488),	// FSITOD
    UINT64_C(4093647360),	// FSITOS
    UINT64_C(4093643584),	// FSQRT_D
    UINT64_C(4093641536),	// FSQRT_S
    UINT64_C(4093650432),	// FSTM
    UINT64_C(4093654528),	// FSTMM
    UINT64_C(4093654272),	// FSTM_D
    UINT64_C(4093654016),	// FSTM_S
    UINT64_C(4093647584),	// FSTOD
    UINT64_C(4093652480),	// FSTRM
    UINT64_C(4093652224),	// FSTR_D
    UINT64_C(4093651968),	// FSTR_S
    UINT64_C(4093650176),	// FST_D
    UINT64_C(4093649920),	// FST_S
    UINT64_C(4093644832),	// FSUBM
    UINT64_C(4093642784),	// FSUB_D
    UINT64_C(4093640736),	// FSUB_S
    UINT64_C(4093647520),	// FUITOD
    UINT64_C(4093647392),	// FUITOS
    UINT64_C(3423338496),	// GRS32
    UINT64_C(3238039584),	// ICACHE_IALL32
    UINT64_C(3271594016),	// ICACHE_IALLS32
    UINT64_C(3244331040),	// ICACHE_IVA32
    UINT64_C(3221232672),	// IDLY32
    UINT64_C(3288337440),	// INCF32
    UINT64_C(3288337472),	// INCT32
    UINT64_C(3288357888),	// INS32
    UINT64_C(5219),	// IPOP16
    UINT64_C(5218),	// IPUSH16
    UINT64_C(3288336512),	// IXD32
    UINT64_C(3288336416),	// IXH32
    UINT64_C(3288336448),	// IXW32
    UINT64_C(30720),	// JMP16
    UINT64_C(3904897024),	// JMP32
    UINT64_C(3938451456),	// JMPI32
    UINT64_C(14560),	// JMPIX16
    UINT64_C(31681),	// JSR16
    UINT64_C(3906994176),	// JSR32
    UINT64_C(3940548608),	// JSRI32
    UINT64_C(3229653024),	// L2CACHE_CALL
    UINT64_C(3246430240),	// L2CACHE_CIALL
    UINT64_C(3238041632),	// L2CACHE_IALL
    UINT64_C(32768),	// LD16B
    UINT64_C(34816),	// LD16H
    UINT64_C(36864),	// LD16W
    UINT64_C(38912),	// LD16WSP
    UINT64_C(3623878656),	// LD32B
    UINT64_C(3623895040),	// LD32BS
    UINT64_C(3623890944),	// LD32D
    UINT64_C(3623882752),	// LD32H
    UINT64_C(3623899136),	// LD32HS
    UINT64_C(3623886848),	// LD32W
    UINT64_C(3623907328),	// LDEX32W
    UINT64_C(3489668128),	// LDM32
    UINT64_C(3489660928),	// LDR32B
    UINT64_C(3489665024),	// LDR32BS
    UINT64_C(3489661952),	// LDR32H
    UINT64_C(3489666048),	// LDR32HS
    UINT64_C(3489662976),	// LDR32W
    UINT64_C(3422552064),	// LRS32B
    UINT64_C(3422814208),	// LRS32H
    UINT64_C(3423076352),	// LRS32W
    UINT64_C(0),	// LRW16
    UINT64_C(0),	// LRW16_Gen
    UINT64_C(3934257152),	// LRW32
    UINT64_C(3934257152),	// LRW32_Gen
    UINT64_C(28672),	// LSL16
    UINT64_C(3288350752),	// LSL32
    UINT64_C(3288353824),	// LSLC32
    UINT64_C(16384),	// LSLI16
    UINT64_C(3288352800),	// LSLI32
    UINT64_C(28673),	// LSR16
    UINT64_C(3288350784),	// LSR32
    UINT64_C(3288353856),	// LSRC32
    UINT64_C(18432),	// LSRI16
    UINT64_C(3288352832),	// LSRI32
    UINT64_C(3225509920),	// MFFCR
    UINT64_C(27651),	// MOV16
    UINT64_C(3288352800),	// MOV32
    UINT64_C(3288337440),	// MOVF32
    UINT64_C(12288),	// MOVI16
    UINT64_C(3925868544),	// MOVI32
    UINT64_C(3927965696),	// MOVIH32
    UINT64_C(3288337472),	// MOVT32
    UINT64_C(3225445409),	// MTFCR
    UINT64_C(4160782976),	// MULATS32
    UINT64_C(4160782464),	// MULATU32
    UINT64_C(31745),	// MULSH16
    UINT64_C(3288371232),	// MULSH32
    UINT64_C(31744),	// MULT16
    UINT64_C(3288368160),	// MULT32
    UINT64_C(4160782848),	// MULTS32
    UINT64_C(4160782336),	// MULTU32
    UINT64_C(3288335616),	// MVC32
    UINT64_C(25603),	// MVCV16
    UINT64_C(3288335872),	// MVCV32
    UINT64_C(5216),	// NIE
    UINT64_C(5217),	// NIR
    UINT64_C(27650),	// NOR16
    UINT64_C(3288343680),	// NOR32
    UINT64_C(27650),	// NOT16
    UINT64_C(3288343680),	// NOT32
    UINT64_C(27648),	// OR16
    UINT64_C(3288343584),	// OR32
    UINT64_C(3959422976),	// ORI32
    UINT64_C(3623903232),	// PLDR32
    UINT64_C(3691012096),	// PLDW32
    UINT64_C(5248),	// POP16
    UINT64_C(3955228672),	// POP32
    UINT64_C(5312),	// PUSH16
    UINT64_C(3957325824),	// PUSH32
    UINT64_C(30722),	// REVB16
    UINT64_C(3288359040),	// REVB32
    UINT64_C(30723),	// REVH16
    UINT64_C(3288359168),	// REVH32
    UINT64_C(3221242912),	// RFI32
    UINT64_C(28675),	// ROTL16
    UINT64_C(3288350976),	// ROTL32
    UINT64_C(3288353024),	// ROTLI32
    UINT64_C(30780),	// RTS16
    UINT64_C(3221231648),	// SCE32
    UINT64_C(3221248032),	// SE32
    UINT64_C(25600),	// SETC16
    UINT64_C(3288335392),	// SETC32
    UINT64_C(3288356864),	// SEXT32
    UINT64_C(29698),	// SEXTB16
    UINT64_C(3288357088),	// SEXTB32
    UINT64_C(29699),	// SEXTH16
    UINT64_C(3288357344),	// SEXTH32
    UINT64_C(3423600640),	// SRS32B
    UINT64_C(3423862784),	// SRS32H
    UINT64_C(3424124928),	// SRS32W
    UINT64_C(40960),	// ST16B
    UINT64_C(43008),	// ST16H
    UINT64_C(45056),	// ST16W
    UINT64_C(47104),	// ST16WSP
    UINT64_C(3690987520),	// ST32B
    UINT64_C(3690999808),	// ST32D
    UINT64_C(3690991616),	// ST32H
    UINT64_C(3690995712),	// ST32W
    UINT64_C(3691016192),	// STEX32W
    UINT64_C(3556776992),	// STM32
    UINT64_C(3221243936),	// STOP32
    UINT64_C(3556769792),	// STR32B
    UINT64_C(3556770816),	// STR32H
    UINT64_C(3556771840),	// STR32W
    UINT64_C(24579),	// SUBC16
    UINT64_C(3288334592),	// SUBC32
    UINT64_C(10240),	// SUBI16
    UINT64_C(5152),	// SUBI16SPSP
    UINT64_C(22531),	// SUBI16XZ
    UINT64_C(3825209344),	// SUBI32
    UINT64_C(22529),	// SUBU16
    UINT64_C(24578),	// SUBU16XZ
    UINT64_C(3288334464),	// SUBU32
    UINT64_C(3221226528),	// SYNC0_32
    UINT64_C(3221226528),	// SYNC32
    UINT64_C(3223323680),	// SYNC_32_I
    UINT64_C(3256878112),	// SYNC_32_IS
    UINT64_C(3254780960),	// SYNC_32_S
    UINT64_C(3221260320),	// TLBI_ALL32
    UINT64_C(3254814752),	// TLBI_ALLS32
    UINT64_C(3223357472),	// TLBI_ASID32
    UINT64_C(3256911904),	// TLBI_ASIDS32
    UINT64_C(3227551776),	// TLBI_VA32
    UINT64_C(3225454624),	// TLBI_VAA32
    UINT64_C(3259009056),	// TLBI_VAAS32
    UINT64_C(3261106208),	// TLBI_VAS32
    UINT64_C(3221233696),	// TRAP32
    UINT64_C(26626),	// TST16
    UINT64_C(3288342656),	// TST32
    UINT64_C(26627),	// TSTNBZ16
    UINT64_C(3288342784),	// TSTNBZ32
    UINT64_C(3221244960),	// WAIT32
    UINT64_C(3221247008),	// WE32
    UINT64_C(3221240864),	// WSC32
    UINT64_C(27649),	// XOR16
    UINT64_C(3288343616),	// XOR32
    UINT64_C(3825221632),	// XORI32
    UINT64_C(3288354048),	// XSR32
    UINT64_C(3288363040),	// XTRB0
    UINT64_C(3288363072),	// XTRB1
    UINT64_C(3288363136),	// XTRB2
    UINT64_C(3288363264),	// XTRB3
    UINT64_C(3288355840),	// ZEXT32
    UINT64_C(29696),	// ZEXTB16
    UINT64_C(3288356064),	// ZEXTB32
    UINT64_C(29697),	// ZEXTH16
    UINT64_C(3288356320),	// ZEXTH32
    UINT64_C(4093642944),	// f2FABS_D
    UINT64_C(4093640896),	// f2FABS_S
    UINT64_C(4093642752),	// f2FADD_D
    UINT64_C(4093640704),	// f2FADD_S
    UINT64_C(4093643008),	// f2FCMPHSZ_D
    UINT64_C(4093640960),	// f2FCMPHSZ_S
    UINT64_C(4093643136),	// f2FCMPHS_D
    UINT64_C(4093641088),	// f2FCMPHS_S
    UINT64_C(4093644096),	// f2FCMPHZ_D
    UINT64_C(4093642048),	// f2FCMPHZ_S
    UINT64_C(4093644128),	// f2FCMPLSZ_D
    UINT64_C(4093642080),	// f2FCMPLSZ_S
    UINT64_C(4093643040),	// f2FCMPLTZ_D
    UINT64_C(4093640992),	// f2FCMPLTZ_S
    UINT64_C(4093643168),	// f2FCMPLT_D
    UINT64_C(4093641120),	// f2FCMPLT_S
    UINT64_C(4093643072),	// f2FCMPNEZ_D
    UINT64_C(4093641024),	// f2FCMPNEZ_S
    UINT64_C(4093643200),	// f2FCMPNE_D
    UINT64_C(4093641152),	// f2FCMPNE_S
    UINT64_C(4093643104),	// f2FCMPUOZ_D
    UINT64_C(4093641056),	// f2FCMPUOZ_S
    UINT64_C(4093643232),	// f2FCMPUO_D
    UINT64_C(4093641184),	// f2FCMPUO_S
    UINT64_C(4093643520),	// f2FDIV_D
    UINT64_C(4093641472),	// f2FDIV_S
    UINT64_C(4093647552),	// f2FDTOS
    UINT64_C(4093658240),	// f2FF32TOFI32_RN
    UINT64_C(4093658336),	// f2FF32TOFI32_RNI
    UINT64_C(4093658304),	// f2FF32TOFI32_RPI
    UINT64_C(4093658272),	// f2FF32TOFI32_RZ
    UINT64_C(4093646848),	// f2FF32TOSI32_RN
    UINT64_C(4093646944),	// f2FF32TOSI32_RNI
    UINT64_C(4093646912),	// f2FF32TOSI32_RPI
    UINT64_C(4093646880),	// f2FF32TOSI32_RZ
    UINT64_C(4093646976),	// f2FF32TOUI32_RN
    UINT64_C(4093647072),	// f2FF32TOUI32_RNI
    UINT64_C(4093647040),	// f2FF32TOUI32_RPI
    UINT64_C(4093647008),	// f2FF32TOUI32_RZ
    UINT64_C(4093658368),	// f2FF64TOFI32_RN
    UINT64_C(4093658464),	// f2FF64TOFI32_RNI
    UINT64_C(4093658432),	// f2FF64TOFI32_RPI
    UINT64_C(4093658400),	// f2FF64TOFI32_RZ
    UINT64_C(4093647104),	// f2FF64TOSI32_RN
    UINT64_C(4093647200),	// f2FF64TOSI32_RNI
    UINT64_C(4093647168),	// f2FF64TOSI32_RPI
    UINT64_C(4093647136),	// f2FF64TOSI32_RZ
    UINT64_C(4093647232),	// f2FF64TOUI32_RN
    UINT64_C(4093647328),	// f2FF64TOUI32_RNI
    UINT64_C(4093647296),	// f2FF64TOUI32_RPI
    UINT64_C(4093647264),	// f2FF64TOUI32_RZ
    UINT64_C(4093644288),	// f2FFMULA_D
    UINT64_C(4093642240),	// f2FFMULA_S
    UINT64_C(4093644320),	// f2FFMULS_D
    UINT64_C(4093642272),	// f2FFMULS_S
    UINT64_C(4093644352),	// f2FFNMULA_D
    UINT64_C(4093642304),	// f2FFNMULA_S
    UINT64_C(4093644384),	// f2FFNMULS_D
    UINT64_C(4093642336),	// f2FFNMULS_S
    UINT64_C(4093658016),	// f2FFTOS32_D
    UINT64_C(4093657952),	// f2FFTOS32_S
    UINT64_C(4093657984),	// f2FFTOU32_D
    UINT64_C(4093657920),	// f2FFTOU32_S
    UINT64_C(4093657504),	// f2FFTOXS32_D
    UINT64_C(4093657440),	// f2FFTOXS32_S
    UINT64_C(4093657472),	// f2FFTOXU32_D
    UINT64_C(4093657408),	// f2FFTOXU32_S
    UINT64_C(4093641568),	// f2FINS
    UINT64_C(4093653376),	// f2FLDMU_D
    UINT64_C(4093653120),	// f2FLDMU_S
    UINT64_C(4093653248),	// f2FLDM_D
    UINT64_C(4093652992),	// f2FLDM_S
    UINT64_C(4093651200),	// f2FLDR_D
    UINT64_C(4093650944),	// f2FLDR_S
    UINT64_C(4093649152),	// f2FLD_D
    UINT64_C(4093648896),	// f2FLD_S
    UINT64_C(4093655296),	// f2FLRW_D
    UINT64_C(4093655040),	// f2FLRW_S
    UINT64_C(4093644032),	// f2FMAXNM_D
    UINT64_C(4093641984),	// f2FMAXNM_S
    UINT64_C(4093647616),	// f2FMFVRH_D
    UINT64_C(4093647648),	// f2FMFVRL
    UINT64_C(4093648704),	// f2FMFVRL_2
    UINT64_C(4093647648),	// f2FMFVRL_D
    UINT64_C(4093648640),	// f2FMFVR_D
    UINT64_C(4093644064),	// f2FMINNM_D
    UINT64_C(4093642016),	// f2FMINNM_S
    UINT64_C(4093642912),	// f2FMOVX
    UINT64_C(4093642880),	// f2FMOV_D
    UINT64_C(4093640832),	// f2FMOV_S
    UINT64_C(4093647680),	// f2FMTVRH_D
    UINT64_C(4093647712),	// f2FMTVRL
    UINT64_C(4093648832),	// f2FMTVRL_2
    UINT64_C(4093647712),	// f2FMTVRL_D
    UINT64_C(4093648768),	// f2FMTVR_D
    UINT64_C(4093643392),	// f2FMULA_D
    UINT64_C(4093641344),	// f2FMULA_S
    UINT64_C(4093643456),	// f2FMULS_D
    UINT64_C(4093641408),	// f2FMULS_S
    UINT64_C(4093643264),	// f2FMUL_D
    UINT64_C(4093641216),	// f2FMUL_S
    UINT64_C(4093642976),	// f2FNEG_D
    UINT64_C(4093640928),	// f2FNEG_S
    UINT64_C(4093643488),	// f2FNMULA_D
    UINT64_C(4093641440),	// f2FNMULA_S
    UINT64_C(4093643424),	// f2FNMULS_D
    UINT64_C(4093641376),	// f2FNMULS_S
    UINT64_C(4093643296),	// f2FNMUL_D
    UINT64_C(4093641248),	// f2FNMUL_S
    UINT64_C(4093660064),	// f2FS32TOF_D
    UINT64_C(4093660000),	// f2FS32TOF_S
    UINT64_C(4093644576),	// f2FSEL_D
    UINT64_C(4093642528),	// f2FSEL_S
    UINT64_C(4093643584),	// f2FSQRT_D
    UINT64_C(4093641536),	// f2FSQRT_S
    UINT64_C(4093654400),	// f2FSTMU_D
    UINT64_C(4093654144),	// f2FSTMU_S
    UINT64_C(4093654272),	// f2FSTM_D
    UINT64_C(4093654016),	// f2FSTM_S
    UINT64_C(4093647584),	// f2FSTOD
    UINT64_C(4093652224),	// f2FSTR_D
    UINT64_C(4093651968),	// f2FSTR_S
    UINT64_C(4093650176),	// f2FST_D
    UINT64_C(4093649920),	// f2FST_S
    UINT64_C(4093642784),	// f2FSUB_D
    UINT64_C(4093640736),	// f2FSUB_S
    UINT64_C(4093660032),	// f2FU32TOF_D
    UINT64_C(4093659968),	// f2FU32TOF_S
    UINT64_C(4093659552),	// f2FXTOFS32_D
    UINT64_C(4093659488),	// f2FXTOFS32_S
    UINT64_C(4093659520),	// f2FXTOFU32_D
    UINT64_C(4093659456),	// f2FXTOFU32_S
    UINT64_C(4093643552),	// f2RECIP_D
    UINT64_C(4093641504),	// f2RECIP_S
    UINT64_C(4093647104),	// rnFDTOSI
    UINT64_C(4093647232),	// rnFDTOUI
    UINT64_C(4093646848),	// rnFSTOSI
    UINT64_C(4093646976),	// rnFSTOUI
    UINT64_C(4093647200),	// rniFDTOSI
    UINT64_C(4093647328),	// rniFDTOUI
    UINT64_C(4093646944),	// rniFSTOSI
    UINT64_C(4093647072),	// rniFSTOUI
    UINT64_C(4093647168),	// rpiFDTOSI
    UINT64_C(4093647296),	// rpiFDTOUI
    UINT64_C(4093646912),	// rpiFSTOSI
    UINT64_C(4093647040),	// rpiFSTOUI
    UINT64_C(4093647136),	// rzFDTOSI
    UINT64_C(4093647264),	// rzFDTOUI
    UINT64_C(4093646880),	// rzFSTOSI
    UINT64_C(4093647008),	// rzFSTOUI
  };
  constexpr unsigned FirstSupportedOpcode = 366;

  const unsigned opcode = MI.getOpcode();
  if (opcode < FirstSupportedOpcode)
    reportUnsupportedInst(MI);
  unsigned TableIndex = opcode - FirstSupportedOpcode;
  uint64_t Value = InstBits[TableIndex];
  uint64_t op = 0;
  (void)op;  // suppress warning
  switch (opcode) {
    case CSKY::BKPT:
    case CSKY::BRAR:
    case CSKY::BRARS:
    case CSKY::BRARW:
    case CSKY::BRARWS:
    case CSKY::BRWARW:
    case CSKY::BRWARWS:
    case CSKY::BRWAW:
    case CSKY::BRWAWS:
    case CSKY::BWAW:
    case CSKY::BWAWS:
    case CSKY::CLRC16:
    case CSKY::CLRC32:
    case CSKY::DCACHE_CALL32:
    case CSKY::DCACHE_CIALL32:
    case CSKY::DCACHE_IALL32:
    case CSKY::DOZE32:
    case CSKY::ICACHE_IALL32:
    case CSKY::ICACHE_IALLS32:
    case CSKY::IPOP16:
    case CSKY::IPUSH16:
    case CSKY::L2CACHE_CALL:
    case CSKY::L2CACHE_CIALL:
    case CSKY::L2CACHE_IALL:
    case CSKY::NIE:
    case CSKY::NIR:
    case CSKY::RFI32:
    case CSKY::RTS16:
    case CSKY::SE32:
    case CSKY::SETC16:
    case CSKY::SETC32:
    case CSKY::STOP32:
    case CSKY::SYNC0_32:
    case CSKY::SYNC_32_I:
    case CSKY::SYNC_32_IS:
    case CSKY::SYNC_32_S:
    case CSKY::TLBI_ALL32:
    case CSKY::TLBI_ALLS32:
    case CSKY::WAIT32:
    case CSKY::WE32:
    case CSKY::WSC32: {
      break;
    }
    case CSKY::CPOP32: {
      // op: cpid
      op = getImmOpValue<0>(MI, 0, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: usdef
      op = getImmOpValue<0>(MI, 1, Fixups, STI);
      Value |= (op & 0xf8000) << 1;
      Value |= (op & 0x7fff);
      break;
    }
    case CSKY::CPRC32: {
      // op: cpid
      op = getImmOpValue<0>(MI, 1, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: usdef
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case CSKY::CPRCR32:
    case CSKY::CPRGR32:
    case CSKY::CPWCR32:
    case CSKY::CPWGR32: {
      // op: cpid
      op = getImmOpValue<0>(MI, 1, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: usdef
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0xfff);
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::BR32: {
      // op: imm16
      op = getBranchSymbolOpValue<CSKY::fixup_csky_pcrel_imm16_scale2>(MI, 0, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case CSKY::BF32:
    case CSKY::BT32: {
      // op: imm16
      op = getBranchSymbolOpValue<CSKY::fixup_csky_pcrel_imm16_scale2>(MI, 1, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case CSKY::JMPI32:
    case CSKY::JSRI32: {
      // op: imm16
      op = getConstpoolSymbolOpValue<CSKY::fixup_csky_pcrel_uimm16_scale4>(MI, 0, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case CSKY::CMPNEI32: {
      // op: imm16
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0xffff);
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::CMPHSI32:
    case CSKY::CMPLTI32: {
      // op: imm16
      op = getOImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & 0xffff);
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::TRAP32: {
      // op: imm2
      op = getImmOpValue<0>(MI, 0, Fixups, STI);
      Value |= (op & 0x3) << 10;
      break;
    }
    case CSKY::SCE32:
    case CSKY::SYNC32: {
      // op: imm5
      op = getImmOpValue<0>(MI, 0, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      break;
    }
    case CSKY::BTSTI32: {
      // op: imm5
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::ASRI32:
    case CSKY::BCLRI32:
    case CSKY::BSETI32:
    case CSKY::LSLI32:
    case CSKY::LSRI32:
    case CSKY::ROTLI32: {
      // op: imm5
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::DECGT32:
    case CSKY::DECLT32:
    case CSKY::DECNE32: {
      // op: imm5
      op = getImmOpValue<0>(MI, 3, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::IDLY32: {
      // op: imm5
      op = getImmOpValueIDLY(MI, 0, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      break;
    }
    case CSKY::BMASKI32: {
      // op: imm5
      op = getOImmOpValue(MI, 1, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::ASRC32:
    case CSKY::LSLC32:
    case CSKY::LSRC32:
    case CSKY::XSR32: {
      // op: imm5
      op = getOImmOpValue(MI, 3, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::ADDI16SPSP:
    case CSKY::SUBI16SPSP: {
      // op: imm7
      op = getImmOpValue<2>(MI, 2, Fixups, STI);
      Value |= (op & 0x60) << 3;
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::f2FLRW_D:
    case CSKY::f2FLRW_S: {
      // op: imm8
      op = getConstpoolSymbolOpValue<CSKY::fixup_csky_pcrel_uimm8_scale4>(MI, 1, Fixups, STI);
      Value |= (op & 0xf0) << 17;
      Value |= (op & 0xf) << 4;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x10) << 21;
      Value |= (op & 0xf);
      break;
    }
    case CSKY::f2FLD_D:
    case CSKY::f2FLD_S:
    case CSKY::f2FST_D:
    case CSKY::f2FST_S: {
      // op: imm8
      op = getImmOpValue<2>(MI, 2, Fixups, STI);
      Value |= (op & 0xf0) << 17;
      Value |= (op & 0xf) << 4;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x10) << 21;
      Value |= (op & 0xf);
      break;
    }
    case CSKY::BR16: {
      // op: offset
      op = getBranchSymbolOpValue<CSKY::fixup_csky_pcrel_imm10_scale2>(MI, 0, Fixups, STI);
      Value |= (op & 0x3ff);
      break;
    }
    case CSKY::BF16:
    case CSKY::BT16: {
      // op: offset
      op = getBranchSymbolOpValue<CSKY::fixup_csky_pcrel_imm10_scale2>(MI, 1, Fixups, STI);
      Value |= (op & 0x3ff);
      break;
    }
    case CSKY::BSR32:
    case CSKY::BSR32_BR: {
      // op: offset
      op = getCallSymbolOpValue(MI, 0, Fixups, STI);
      Value |= (op & 0x3ffffff);
      break;
    }
    case CSKY::POP16:
    case CSKY::PUSH16: {
      // op: regs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::POP32:
    case CSKY::PUSH32: {
      // op: regs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case CSKY::f2FLDMU_D:
    case CSKY::f2FLDMU_S:
    case CSKY::f2FLDM_D:
    case CSKY::f2FLDM_S:
    case CSKY::f2FSTMU_D:
    case CSKY::f2FSTMU_S:
    case CSKY::f2FSTM_D:
    case CSKY::f2FSTM_S: {
      // op: regs
      op = getRegisterSeqOpValue(MI, 1, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      Value |= (op & 0x3e0) >> 5;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::LDM32:
    case CSKY::STM32: {
      // op: regs
      op = getRegisterSeqOpValue(MI, 1, Fixups, STI);
      Value |= (op & 0x3e0) << 16;
      Value |= (op & 0x1f);
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::FLDMM:
    case CSKY::FLDM_D:
    case CSKY::FLDM_S:
    case CSKY::FSTMM:
    case CSKY::FSTM_D:
    case CSKY::FSTM_S: {
      // op: regs
      op = getRegisterSeqOpValue(MI, 1, Fixups, STI);
      Value |= (op & 0xf) << 21;
      Value |= (op & 0x1e0) >> 5;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::DCACHE_CISW32:
    case CSKY::DCACHE_CIVA32:
    case CSKY::DCACHE_CSW32:
    case CSKY::DCACHE_CVA32:
    case CSKY::DCACHE_CVAL32:
    case CSKY::DCACHE_ISW32:
    case CSKY::DCACHE_IVA32:
    case CSKY::ICACHE_IVA32:
    case CSKY::JMP32:
    case CSKY::JSR32:
    case CSKY::MTFCR:
    case CSKY::TLBI_ASID32:
    case CSKY::TLBI_ASIDS32:
    case CSKY::TLBI_VA32:
    case CSKY::TLBI_VAA32:
    case CSKY::TLBI_VAAS32:
    case CSKY::TLBI_VAS32: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::PLDR32:
    case CSKY::PLDW32: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm12
      op = getImmOpValue<2>(MI, 1, Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case CSKY::BEZ32:
    case CSKY::BHSZ32:
    case CSKY::BHZ32:
    case CSKY::BLSZ32:
    case CSKY::BLZ32:
    case CSKY::BNEZ32: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm16
      op = getBranchSymbolOpValue<CSKY::fixup_csky_pcrel_imm16_scale2>(MI, 1, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case CSKY::MFFCR: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::JMPIX16: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: indeximm2
      op = getImmJMPIX(MI, 1, Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case CSKY::JMP16:
    case CSKY::JSR16: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 2;
      break;
    }
    case CSKY::TSTNBZ32: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::BNEZAD32: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm16
      op = getBranchSymbolOpValue<CSKY::fixup_csky_pcrel_imm16_scale2>(MI, 2, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case CSKY::f2FLDR_D:
    case CSKY::f2FLDR_S:
    case CSKY::f2FSTR_D:
    case CSKY::f2FSTR_S: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: ry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: imm
      op = getImmOpValue<0>(MI, 3, Fixups, STI);
      Value |= (op & 0x3) << 5;
      break;
    }
    case CSKY::LDR32B:
    case CSKY::LDR32BS:
    case CSKY::LDR32H:
    case CSKY::LDR32HS:
    case CSKY::LDR32W:
    case CSKY::STR32B:
    case CSKY::STR32H:
    case CSKY::STR32W: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: ry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: imm
      op = getImmShiftOpValue(MI, 3, Fixups, STI);
      Value |= (op & 0x1f) << 5;
      break;
    }
    case CSKY::FLDRM:
    case CSKY::FLDR_D:
    case CSKY::FLDR_S:
    case CSKY::FSTRM:
    case CSKY::FSTR_D:
    case CSKY::FSTR_S: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: ry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      // op: imm
      op = getImmOpValue<0>(MI, 3, Fixups, STI);
      Value |= (op & 0x3) << 5;
      break;
    }
    case CSKY::LD32B:
    case CSKY::LD32BS:
    case CSKY::ST32B: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: imm12
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case CSKY::LD32H:
    case CSKY::LD32HS:
    case CSKY::ST32H: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: imm12
      op = getImmOpValue<1>(MI, 2, Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case CSKY::LD32D:
    case CSKY::LD32W:
    case CSKY::LDEX32W:
    case CSKY::ST32D:
    case CSKY::ST32W: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: imm12
      op = getImmOpValue<2>(MI, 2, Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case CSKY::ABS32:
    case CSKY::BGENR32:
    case CSKY::BREV32:
    case CSKY::FF0:
    case CSKY::FF1:
    case CSKY::MOV32:
    case CSKY::REVB32:
    case CSKY::REVH32:
    case CSKY::SEXTB32:
    case CSKY::SEXTH32:
    case CSKY::XTRB0:
    case CSKY::XTRB1:
    case CSKY::XTRB2:
    case CSKY::XTRB3:
    case CSKY::ZEXTB32:
    case CSKY::ZEXTH32: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::SEXT32:
    case CSKY::ZEXT32: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: msb
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0x1f) << 5;
      // op: lsb
      op = getImmOpValue<0>(MI, 3, Fixups, STI);
      Value |= (op & 0x1f) << 21;
      break;
    }
    case CSKY::FMTVRL:
    case CSKY::FMTVRL_D: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case CSKY::FLD_D:
    case CSKY::FLD_S:
    case CSKY::FST_D:
    case CSKY::FST_S: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      // op: imm8
      op = getImmOpValue<2>(MI, 2, Fixups, STI);
      Value |= (op & 0xf0) << 17;
      Value |= (op & 0xf) << 4;
      break;
    }
    case CSKY::FLDM:
    case CSKY::FSTM: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      // op: imm8
      op = getImmOpValue<3>(MI, 2, Fixups, STI);
      Value |= (op & 0xf0) << 17;
      Value |= (op & 0xf) << 4;
      break;
    }
    case CSKY::NOT32: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::CMPNEI16: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: imm5
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::CMPHSI16:
    case CSKY::CMPLTI16: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: imm5
      op = getOImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::LD16B:
    case CSKY::ST16B: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: imm
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::LD16H:
    case CSKY::ST16H: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: imm
      op = getImmOpValue<1>(MI, 2, Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::LD16W:
    case CSKY::ST16W: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: imm
      op = getImmOpValue<2>(MI, 2, Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::ASRI16:
    case CSKY::LSLI16:
    case CSKY::LSRI16: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: imm5
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::ADDI16XZ:
    case CSKY::SUBI16XZ: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: oimm3
      op = getOImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & 0x7) << 2;
      break;
    }
    case CSKY::TSTNBZ16: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 2;
      break;
    }
    case CSKY::INS32: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: msb
      op = getImmOpValueMSBSize(MI, 3, Fixups, STI);
      Value |= (op & 0x1f) << 5;
      // op: lsb
      op = getImmOpValue<0>(MI, 4, Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::STEX32W: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: imm12
      op = getImmOpValue<2>(MI, 3, Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case CSKY::FMTVRH_D: {
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case CSKY::CMPHS32:
    case CSKY::CMPLT32:
    case CSKY::CMPNE32:
    case CSKY::TST32: {
      // op: ry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::ADDU32:
    case CSKY::AND32:
    case CSKY::ANDN32:
    case CSKY::ASR32:
    case CSKY::DIVS32:
    case CSKY::DIVU32:
    case CSKY::IXD32:
    case CSKY::IXH32:
    case CSKY::IXW32:
    case CSKY::LSL32:
    case CSKY::LSR32:
    case CSKY::MULSH32:
    case CSKY::MULT32:
    case CSKY::MULTS32:
    case CSKY::MULTU32:
    case CSKY::NOR32:
    case CSKY::OR32:
    case CSKY::ROTL32:
    case CSKY::SUBU32:
    case CSKY::XOR32: {
      // op: ry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::CMPHS16:
    case CSKY::CMPLT16:
    case CSKY::CMPNE16:
    case CSKY::TST16: {
      // op: ry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 6;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 2;
      break;
    }
    case CSKY::ADDC32:
    case CSKY::SUBC32: {
      // op: ry
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::MULATS32:
    case CSKY::MULATU32: {
      // op: ry
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::LRW32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm16
      op = getConstpoolSymbolOpValue<CSKY::fixup_csky_pcrel_uimm16_scale4>(MI, 1, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case CSKY::LRW32_Gen: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm16
      op = getConstpoolSymbolOpValue<CSKY::fixup_csky_pcrel_uimm16_scale4>(MI, 2, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case CSKY::MOVIH32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm16
      op = getImmOpValue(MI, 1, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case CSKY::MOVI32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm16
      op = getImmOpValue<0>(MI, 1, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case CSKY::CLRF32:
    case CSKY::CLRT32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      break;
    }
    case CSKY::GRS32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: offset
      op = getBareSymbolOpValue(MI, 1, Fixups, STI);
      Value |= (op & 0x3ffff);
      break;
    }
    case CSKY::LRS32B:
    case CSKY::SRS32B: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: offset
      op = getDataSymbolOpValue<CSKY::fixup_csky_doffset_imm18>(MI, 1, Fixups, STI);
      Value |= (op & 0x3ffff);
      break;
    }
    case CSKY::LRS32H:
    case CSKY::SRS32H: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: offset
      op = getDataSymbolOpValue<CSKY::fixup_csky_doffset_imm18_scale2>(MI, 1, Fixups, STI);
      Value |= (op & 0x3ffff);
      break;
    }
    case CSKY::LRS32W:
    case CSKY::SRS32W: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: offset
      op = getDataSymbolOpValue<CSKY::fixup_csky_doffset_imm18_scale4>(MI, 1, Fixups, STI);
      Value |= (op & 0x3ffff);
      break;
    }
    case CSKY::ANDI32:
    case CSKY::XORI32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm12
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case CSKY::ANDNI32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm12
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case CSKY::ADDI32:
    case CSKY::SUBI32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm12
      op = getOImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & 0xfff);
      break;
    }
    case CSKY::ORI32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm16
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0xffff);
      break;
    }
    case CSKY::MOVF32:
    case CSKY::MOVT32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::DECF32:
    case CSKY::DECT32:
    case CSKY::INCF32:
    case CSKY::INCT32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm5
      op = getImmOpValue<0>(MI, 4, Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::MVC32:
    case CSKY::MVCV32: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::BPOPH:
    case CSKY::BPOPW:
    case CSKY::BPUSHH:
    case CSKY::BPUSHW: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 2;
      break;
    }
    case CSKY::LD16WSP:
    case CSKY::ST16WSP: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: addr
      op = getImmOpValue<2>(MI, 2, Fixups, STI);
      Value |= (op & 0xe0) << 3;
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::LRW16: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: label
      op = getConstpoolSymbolOpValue<CSKY::fixup_csky_pcrel_uimm7_scale4>(MI, 1, Fixups, STI);
      Value |= (op & 0x80) << 5;
      Value |= (op & 0x60) << 3;
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::LRW16_Gen: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: label
      op = getConstpoolSymbolOpValue<CSKY::fixup_csky_pcrel_uimm7_scale4>(MI, 2, Fixups, STI);
      Value |= (op & 0x80) << 5;
      Value |= (op & 0x60) << 3;
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::ADDU16:
    case CSKY::SUBU16: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: ry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 2;
      break;
    }
    case CSKY::BCLRI16:
    case CSKY::BSETI16: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: imm5
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::MOVI16: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: imm8
      op = getImmOpValue<0>(MI, 1, Fixups, STI);
      Value |= (op & 0xff);
      break;
    }
    case CSKY::ADDI16ZSP: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: imm8
      op = getImmOpValue<2>(MI, 2, Fixups, STI);
      Value |= (op & 0xff);
      break;
    }
    case CSKY::ADDI16:
    case CSKY::SUBI16: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: imm8
      op = getOImmOpValue(MI, 2, Fixups, STI);
      Value |= (op & 0xff);
      break;
    }
    case CSKY::MVCV16: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 6;
      break;
    }
    case CSKY::MOV16:
    case CSKY::NOT16:
    case CSKY::REVB16:
    case CSKY::REVH16:
    case CSKY::SEXTB16:
    case CSKY::SEXTH16:
    case CSKY::ZEXTB16:
    case CSKY::ZEXTH16: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 6;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 2;
      break;
    }
    case CSKY::ADDU16XZ:
    case CSKY::AND16:
    case CSKY::ANDN16:
    case CSKY::ASR16:
    case CSKY::LSL16:
    case CSKY::LSR16:
    case CSKY::MULSH16:
    case CSKY::MULT16:
    case CSKY::NOR16:
    case CSKY::OR16:
    case CSKY::ROTL16:
    case CSKY::SUBU16XZ:
    case CSKY::XOR16: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 6;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 2;
      break;
    }
    case CSKY::ADDC16:
    case CSKY::SUBC16: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 6;
      // op: rx
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xf) << 2;
      break;
    }
    case CSKY::BTSTI16: {
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: imm5
      op = getImmOpValue<0>(MI, 2, Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::f2FCMPHSZ_D:
    case CSKY::f2FCMPHSZ_S:
    case CSKY::f2FCMPHZ_D:
    case CSKY::f2FCMPHZ_S:
    case CSKY::f2FCMPLSZ_D:
    case CSKY::f2FCMPLSZ_S:
    case CSKY::f2FCMPLTZ_D:
    case CSKY::f2FCMPLTZ_S:
    case CSKY::f2FCMPNEZ_D:
    case CSKY::f2FCMPNEZ_S:
    case CSKY::f2FCMPUOZ_D:
    case CSKY::f2FCMPUOZ_S: {
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::f2FABS_D:
    case CSKY::f2FABS_S:
    case CSKY::f2FDTOS:
    case CSKY::f2FF32TOFI32_RN:
    case CSKY::f2FF32TOFI32_RNI:
    case CSKY::f2FF32TOFI32_RPI:
    case CSKY::f2FF32TOFI32_RZ:
    case CSKY::f2FF32TOSI32_RN:
    case CSKY::f2FF32TOSI32_RNI:
    case CSKY::f2FF32TOSI32_RPI:
    case CSKY::f2FF32TOSI32_RZ:
    case CSKY::f2FF32TOUI32_RN:
    case CSKY::f2FF32TOUI32_RNI:
    case CSKY::f2FF32TOUI32_RPI:
    case CSKY::f2FF32TOUI32_RZ:
    case CSKY::f2FF64TOFI32_RN:
    case CSKY::f2FF64TOFI32_RNI:
    case CSKY::f2FF64TOFI32_RPI:
    case CSKY::f2FF64TOFI32_RZ:
    case CSKY::f2FF64TOSI32_RN:
    case CSKY::f2FF64TOSI32_RNI:
    case CSKY::f2FF64TOSI32_RPI:
    case CSKY::f2FF64TOSI32_RZ:
    case CSKY::f2FF64TOUI32_RN:
    case CSKY::f2FF64TOUI32_RNI:
    case CSKY::f2FF64TOUI32_RPI:
    case CSKY::f2FF64TOUI32_RZ:
    case CSKY::f2FFTOS32_D:
    case CSKY::f2FFTOS32_S:
    case CSKY::f2FFTOU32_D:
    case CSKY::f2FFTOU32_S:
    case CSKY::f2FFTOXS32_D:
    case CSKY::f2FFTOXS32_S:
    case CSKY::f2FFTOXU32_D:
    case CSKY::f2FFTOXU32_S:
    case CSKY::f2FINS:
    case CSKY::f2FMFVRH_D:
    case CSKY::f2FMFVRL:
    case CSKY::f2FMFVRL_D:
    case CSKY::f2FMOVX:
    case CSKY::f2FMOV_D:
    case CSKY::f2FMOV_S:
    case CSKY::f2FMTVRL:
    case CSKY::f2FMTVRL_D:
    case CSKY::f2FNEG_D:
    case CSKY::f2FNEG_S:
    case CSKY::f2FS32TOF_D:
    case CSKY::f2FS32TOF_S:
    case CSKY::f2FSQRT_D:
    case CSKY::f2FSQRT_S:
    case CSKY::f2FSTOD:
    case CSKY::f2FU32TOF_D:
    case CSKY::f2FU32TOF_S:
    case CSKY::f2FXTOFS32_D:
    case CSKY::f2FXTOFS32_S:
    case CSKY::f2FXTOFU32_D:
    case CSKY::f2FXTOFU32_S:
    case CSKY::f2RECIP_D:
    case CSKY::f2RECIP_S: {
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::FCMPZHS_D:
    case CSKY::FCMPZHS_S:
    case CSKY::FCMPZLS_D:
    case CSKY::FCMPZLS_S:
    case CSKY::FCMPZNE_D:
    case CSKY::FCMPZNE_S:
    case CSKY::FCMPZUO_D:
    case CSKY::FCMPZUO_S: {
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 16;
      break;
    }
    case CSKY::FMFVRH_D:
    case CSKY::FMFVRL:
    case CSKY::FMFVRL_D: {
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 16;
      // op: rz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::FCMPHS_D:
    case CSKY::FCMPHS_S:
    case CSKY::FCMPLT_D:
    case CSKY::FCMPLT_S:
    case CSKY::FCMPNE_D:
    case CSKY::FCMPNE_S:
    case CSKY::FCMPUO_D:
    case CSKY::FCMPUO_S: {
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 16;
      // op: vry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 21;
      break;
    }
    case CSKY::FADDM:
    case CSKY::FADD_D:
    case CSKY::FADD_S:
    case CSKY::FDIV_D:
    case CSKY::FDIV_S:
    case CSKY::FMULM:
    case CSKY::FMUL_D:
    case CSKY::FMUL_S:
    case CSKY::FNMULM:
    case CSKY::FNMUL_D:
    case CSKY::FNMUL_S:
    case CSKY::FSUBM:
    case CSKY::FSUB_D:
    case CSKY::FSUB_S: {
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 16;
      // op: vry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 21;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case CSKY::FABSM:
    case CSKY::FABS_D:
    case CSKY::FABS_S:
    case CSKY::FDTOS:
    case CSKY::FMOVM:
    case CSKY::FMOV_D:
    case CSKY::FMOV_S:
    case CSKY::FNEGM:
    case CSKY::FNEG_D:
    case CSKY::FNEG_S:
    case CSKY::FRECIP_D:
    case CSKY::FRECIP_S:
    case CSKY::FSITOD:
    case CSKY::FSITOS:
    case CSKY::FSQRT_D:
    case CSKY::FSQRT_S:
    case CSKY::FSTOD:
    case CSKY::FUITOD:
    case CSKY::FUITOS:
    case CSKY::rnFDTOSI:
    case CSKY::rnFDTOUI:
    case CSKY::rnFSTOSI:
    case CSKY::rnFSTOUI:
    case CSKY::rniFDTOSI:
    case CSKY::rniFDTOUI:
    case CSKY::rniFSTOSI:
    case CSKY::rniFSTOUI:
    case CSKY::rpiFDTOSI:
    case CSKY::rpiFDTOUI:
    case CSKY::rpiFSTOSI:
    case CSKY::rpiFSTOUI:
    case CSKY::rzFDTOSI:
    case CSKY::rzFDTOUI:
    case CSKY::rzFSTOSI:
    case CSKY::rzFSTOUI: {
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case CSKY::f2FMTVRH_D: {
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::FMACM:
    case CSKY::FMAC_D:
    case CSKY::FMAC_S:
    case CSKY::FMSCM:
    case CSKY::FMSC_D:
    case CSKY::FMSC_S:
    case CSKY::FNMACM:
    case CSKY::FNMAC_D:
    case CSKY::FNMAC_S:
    case CSKY::FNMSCM:
    case CSKY::FNMSC_D:
    case CSKY::FNMSC_S: {
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 16;
      // op: vry
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xf) << 21;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case CSKY::f2FMFVRL_2:
    case CSKY::f2FMFVR_D: {
      // op: vry
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::f2FCMPHS_D:
    case CSKY::f2FCMPHS_S:
    case CSKY::f2FCMPLT_D:
    case CSKY::f2FCMPLT_S:
    case CSKY::f2FCMPNE_D:
    case CSKY::f2FCMPNE_S:
    case CSKY::f2FCMPUO_D:
    case CSKY::f2FCMPUO_S: {
      // op: vry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case CSKY::f2FADD_D:
    case CSKY::f2FADD_S:
    case CSKY::f2FDIV_D:
    case CSKY::f2FDIV_S:
    case CSKY::f2FMAXNM_D:
    case CSKY::f2FMAXNM_S:
    case CSKY::f2FMINNM_D:
    case CSKY::f2FMINNM_S:
    case CSKY::f2FMTVRL_2:
    case CSKY::f2FMTVR_D:
    case CSKY::f2FMUL_D:
    case CSKY::f2FMUL_S:
    case CSKY::f2FNMUL_D:
    case CSKY::f2FNMUL_S:
    case CSKY::f2FSUB_D:
    case CSKY::f2FSUB_S: {
      // op: vry
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case CSKY::f2FFMULA_D:
    case CSKY::f2FFMULA_S:
    case CSKY::f2FFMULS_D:
    case CSKY::f2FFMULS_S:
    case CSKY::f2FFNMULA_D:
    case CSKY::f2FFNMULA_S:
    case CSKY::f2FFNMULS_D:
    case CSKY::f2FFNMULS_S:
    case CSKY::f2FMULA_D:
    case CSKY::f2FMULA_S:
    case CSKY::f2FMULS_D:
    case CSKY::f2FMULS_S:
    case CSKY::f2FNMULA_D:
    case CSKY::f2FNMULA_S:
    case CSKY::f2FNMULS_D:
    case CSKY::f2FNMULS_S:
    case CSKY::f2FSEL_D:
    case CSKY::f2FSEL_S: {
      // op: vry
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 21;
      // op: vrx
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: vrz
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
  default:
    reportUnsupportedInst(MI);
  }
  return Value;
}

#ifdef GET_OPERAND_BIT_OFFSET
#undef GET_OPERAND_BIT_OFFSET

uint32_t CSKYMCCodeEmitter::getOperandBitOffset(const MCInst &MI,
    unsigned OpNum,
    const MCSubtargetInfo &STI) const {
  switch (MI.getOpcode()) {
    case CSKY::BKPT:
    case CSKY::BRAR:
    case CSKY::BRARS:
    case CSKY::BRARW:
    case CSKY::BRARWS:
    case CSKY::BRWARW:
    case CSKY::BRWARWS:
    case CSKY::BRWAW:
    case CSKY::BRWAWS:
    case CSKY::BWAW:
    case CSKY::BWAWS:
    case CSKY::CLRC16:
    case CSKY::CLRC32:
    case CSKY::DCACHE_CALL32:
    case CSKY::DCACHE_CIALL32:
    case CSKY::DCACHE_IALL32:
    case CSKY::DOZE32:
    case CSKY::ICACHE_IALL32:
    case CSKY::ICACHE_IALLS32:
    case CSKY::IPOP16:
    case CSKY::IPUSH16:
    case CSKY::L2CACHE_CALL:
    case CSKY::L2CACHE_CIALL:
    case CSKY::L2CACHE_IALL:
    case CSKY::NIE:
    case CSKY::NIR:
    case CSKY::RFI32:
    case CSKY::RTS16:
    case CSKY::SE32:
    case CSKY::SETC16:
    case CSKY::SETC32:
    case CSKY::STOP32:
    case CSKY::SYNC0_32:
    case CSKY::SYNC_32_I:
    case CSKY::SYNC_32_IS:
    case CSKY::SYNC_32_S:
    case CSKY::TLBI_ALL32:
    case CSKY::TLBI_ALLS32:
    case CSKY::WAIT32:
    case CSKY::WE32:
    case CSKY::WSC32: {
      break;
    }
    case CSKY::CPOP32: {
      switch (OpNum) {
      case 0:
        // op: cpid
        return 21;
      case 1:
        // op: usdef
        return 0;
      }
      break;
    }
    case CSKY::BR32:
    case CSKY::JMPI32:
    case CSKY::JSRI32: {
      switch (OpNum) {
      case 0:
        // op: imm16
        return 0;
      }
      break;
    }
    case CSKY::TRAP32: {
      switch (OpNum) {
      case 0:
        // op: imm2
        return 10;
      }
      break;
    }
    case CSKY::IDLY32:
    case CSKY::SCE32:
    case CSKY::SYNC32: {
      switch (OpNum) {
      case 0:
        // op: imm5
        return 21;
      }
      break;
    }
    case CSKY::BR16:
    case CSKY::BSR32:
    case CSKY::BSR32_BR: {
      switch (OpNum) {
      case 0:
        // op: offset
        return 0;
      }
      break;
    }
    case CSKY::POP16:
    case CSKY::POP32:
    case CSKY::PUSH16:
    case CSKY::PUSH32: {
      switch (OpNum) {
      case 0:
        // op: regs
        return 0;
      }
      break;
    }
    case CSKY::MFFCR: {
      switch (OpNum) {
      case 0:
        // op: rx
        return 0;
      }
      break;
    }
    case CSKY::PLDR32:
    case CSKY::PLDW32: {
      switch (OpNum) {
      case 0:
        // op: rx
        return 16;
      case 1:
        // op: imm12
        return 0;
      }
      break;
    }
    case CSKY::BEZ32:
    case CSKY::BHSZ32:
    case CSKY::BHZ32:
    case CSKY::BLSZ32:
    case CSKY::BLZ32:
    case CSKY::BNEZ32: {
      switch (OpNum) {
      case 0:
        // op: rx
        return 16;
      case 1:
        // op: imm16
        return 0;
      }
      break;
    }
    case CSKY::DCACHE_CISW32:
    case CSKY::DCACHE_CIVA32:
    case CSKY::DCACHE_CSW32:
    case CSKY::DCACHE_CVA32:
    case CSKY::DCACHE_CVAL32:
    case CSKY::DCACHE_ISW32:
    case CSKY::DCACHE_IVA32:
    case CSKY::ICACHE_IVA32:
    case CSKY::JMP32:
    case CSKY::JSR32:
    case CSKY::MTFCR:
    case CSKY::TLBI_ASID32:
    case CSKY::TLBI_ASIDS32:
    case CSKY::TLBI_VA32:
    case CSKY::TLBI_VAA32:
    case CSKY::TLBI_VAAS32:
    case CSKY::TLBI_VAS32: {
      switch (OpNum) {
      case 0:
        // op: rx
        return 16;
      }
      break;
    }
    case CSKY::JMP16:
    case CSKY::JSR16: {
      switch (OpNum) {
      case 0:
        // op: rx
        return 2;
      }
      break;
    }
    case CSKY::JMPIX16: {
      switch (OpNum) {
      case 0:
        // op: rx
        return 8;
      case 1:
        // op: indeximm2
        return 0;
      }
      break;
    }
    case CSKY::MVC32:
    case CSKY::MVCV32: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 0;
      }
      break;
    }
    case CSKY::LRW32:
    case CSKY::MOVI32:
    case CSKY::MOVIH32: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 16;
      case 1:
        // op: imm16
        return 0;
      }
      break;
    }
    case CSKY::LRW32_Gen: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 16;
      case 2:
        // op: imm16
        return 0;
      }
      break;
    }
    case CSKY::GRS32:
    case CSKY::LRS32B:
    case CSKY::LRS32H:
    case CSKY::LRS32W:
    case CSKY::SRS32B:
    case CSKY::SRS32H:
    case CSKY::SRS32W: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 21;
      case 1:
        // op: offset
        return 0;
      }
      break;
    }
    case CSKY::ADDI32:
    case CSKY::ANDI32:
    case CSKY::ANDNI32:
    case CSKY::SUBI32:
    case CSKY::XORI32: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 21;
      case 1:
        // op: rx
        return 16;
      case 2:
        // op: imm12
        return 0;
      }
      break;
    }
    case CSKY::ORI32: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 21;
      case 1:
        // op: rx
        return 16;
      case 2:
        // op: imm16
        return 0;
      }
      break;
    }
    case CSKY::MOVF32:
    case CSKY::MOVT32: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 21;
      case 2:
        // op: rx
        return 16;
      }
      break;
    }
    case CSKY::DECF32:
    case CSKY::DECT32:
    case CSKY::INCF32:
    case CSKY::INCT32: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 21;
      case 3:
        // op: rx
        return 16;
      case 4:
        // op: imm5
        return 0;
      }
      break;
    }
    case CSKY::CLRF32:
    case CSKY::CLRT32: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 21;
      }
      break;
    }
    case CSKY::BPOPH:
    case CSKY::BPOPW:
    case CSKY::BPUSHH:
    case CSKY::BPUSHW: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 2;
      }
      break;
    }
    case CSKY::LRW16: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 5;
      case 1:
        // op: label
        return 0;
      }
      break;
    }
    case CSKY::ADDU16:
    case CSKY::SUBU16: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 5;
      case 1:
        // op: rx
        return 8;
      case 2:
        // op: ry
        return 2;
      }
      break;
    }
    case CSKY::LD16WSP:
    case CSKY::ST16WSP: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 5;
      case 2:
        // op: addr
        return 0;
      }
      break;
    }
    case CSKY::LRW16_Gen: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 5;
      case 2:
        // op: label
        return 0;
      }
      break;
    }
    case CSKY::MOV16:
    case CSKY::NOT16:
    case CSKY::REVB16:
    case CSKY::REVH16:
    case CSKY::SEXTB16:
    case CSKY::SEXTH16:
    case CSKY::ZEXTB16:
    case CSKY::ZEXTH16: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 6;
      case 1:
        // op: rx
        return 2;
      }
      break;
    }
    case CSKY::ADDU16XZ:
    case CSKY::AND16:
    case CSKY::ANDN16:
    case CSKY::ASR16:
    case CSKY::LSL16:
    case CSKY::LSR16:
    case CSKY::MULSH16:
    case CSKY::MULT16:
    case CSKY::NOR16:
    case CSKY::OR16:
    case CSKY::ROTL16:
    case CSKY::SUBU16XZ:
    case CSKY::XOR16: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 6;
      case 2:
        // op: rx
        return 2;
      }
      break;
    }
    case CSKY::ADDC16:
    case CSKY::SUBC16: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 6;
      case 3:
        // op: rx
        return 2;
      }
      break;
    }
    case CSKY::MVCV16: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 6;
      }
      break;
    }
    case CSKY::MOVI16: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 8;
      case 1:
        // op: imm8
        return 0;
      }
      break;
    }
    case CSKY::BCLRI16:
    case CSKY::BSETI16: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 8;
      case 2:
        // op: imm5
        return 0;
      }
      break;
    }
    case CSKY::ADDI16:
    case CSKY::ADDI16ZSP:
    case CSKY::SUBI16: {
      switch (OpNum) {
      case 0:
        // op: rz
        return 8;
      case 2:
        // op: imm8
        return 0;
      }
      break;
    }
    case CSKY::CPRCR32:
    case CSKY::CPRGR32:
    case CSKY::CPWCR32:
    case CSKY::CPWGR32: {
      switch (OpNum) {
      case 1:
        // op: cpid
        return 21;
      case 2:
        // op: usdef
        return 0;
      case 0:
        // op: rz
        return 16;
      }
      break;
    }
    case CSKY::CPRC32: {
      switch (OpNum) {
      case 1:
        // op: cpid
        return 21;
      case 2:
        // op: usdef
        return 0;
      }
      break;
    }
    case CSKY::BF32:
    case CSKY::BT32: {
      switch (OpNum) {
      case 1:
        // op: imm16
        return 0;
      }
      break;
    }
    case CSKY::BMASKI32: {
      switch (OpNum) {
      case 1:
        // op: imm5
        return 21;
      case 0:
        // op: rz
        return 0;
      }
      break;
    }
    case CSKY::f2FLRW_D:
    case CSKY::f2FLRW_S: {
      switch (OpNum) {
      case 1:
        // op: imm8
        return 4;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
    case CSKY::BF16:
    case CSKY::BT16: {
      switch (OpNum) {
      case 1:
        // op: offset
        return 0;
      }
      break;
    }
    case CSKY::FLDMM:
    case CSKY::FLDM_D:
    case CSKY::FLDM_S:
    case CSKY::FSTMM:
    case CSKY::FSTM_D:
    case CSKY::FSTM_S:
    case CSKY::LDM32:
    case CSKY::STM32:
    case CSKY::f2FLDMU_D:
    case CSKY::f2FLDMU_S:
    case CSKY::f2FLDM_D:
    case CSKY::f2FLDM_S:
    case CSKY::f2FSTMU_D:
    case CSKY::f2FSTMU_S:
    case CSKY::f2FSTM_D:
    case CSKY::f2FSTM_S: {
      switch (OpNum) {
      case 1:
        // op: regs
        return 0;
      case 0:
        // op: rx
        return 16;
      }
      break;
    }
    case CSKY::SEXT32:
    case CSKY::ZEXT32: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 16;
      case 0:
        // op: rz
        return 0;
      case 2:
        // op: msb
        return 5;
      case 3:
        // op: lsb
        return 21;
      }
      break;
    }
    case CSKY::ABS32:
    case CSKY::BGENR32:
    case CSKY::BREV32:
    case CSKY::FF0:
    case CSKY::FF1:
    case CSKY::MOV32:
    case CSKY::NOT32:
    case CSKY::REVB32:
    case CSKY::REVH32:
    case CSKY::SEXTB32:
    case CSKY::SEXTH32:
    case CSKY::XTRB0:
    case CSKY::XTRB1:
    case CSKY::XTRB2:
    case CSKY::XTRB3:
    case CSKY::ZEXTB32:
    case CSKY::ZEXTH32: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 16;
      case 0:
        // op: rz
        return 0;
      }
      break;
    }
    case CSKY::LD32B:
    case CSKY::LD32BS:
    case CSKY::LD32D:
    case CSKY::LD32H:
    case CSKY::LD32HS:
    case CSKY::LD32W:
    case CSKY::LDEX32W:
    case CSKY::ST32B:
    case CSKY::ST32D:
    case CSKY::ST32H:
    case CSKY::ST32W: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 16;
      case 0:
        // op: rz
        return 21;
      case 2:
        // op: imm12
        return 0;
      }
      break;
    }
    case CSKY::FLDM:
    case CSKY::FLD_D:
    case CSKY::FLD_S:
    case CSKY::FSTM:
    case CSKY::FST_D:
    case CSKY::FST_S: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 16;
      case 0:
        // op: vrz
        return 0;
      case 2:
        // op: imm8
        return 4;
      }
      break;
    }
    case CSKY::FMTVRL:
    case CSKY::FMTVRL_D: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 16;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
    case CSKY::BNEZAD32: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 16;
      case 2:
        // op: imm16
        return 0;
      }
      break;
    }
    case CSKY::LDR32B:
    case CSKY::LDR32BS:
    case CSKY::LDR32H:
    case CSKY::LDR32HS:
    case CSKY::LDR32W:
    case CSKY::STR32B:
    case CSKY::STR32H:
    case CSKY::STR32W:
    case CSKY::f2FLDR_D:
    case CSKY::f2FLDR_S:
    case CSKY::f2FSTR_D:
    case CSKY::f2FSTR_S: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 16;
      case 2:
        // op: ry
        return 21;
      case 0:
        // op: rz
        return 0;
      case 3:
        // op: imm
        return 5;
      }
      break;
    }
    case CSKY::FLDRM:
    case CSKY::FLDR_D:
    case CSKY::FLDR_S:
    case CSKY::FSTRM:
    case CSKY::FSTR_D:
    case CSKY::FSTR_S: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 16;
      case 2:
        // op: ry
        return 21;
      case 0:
        // op: vrz
        return 0;
      case 3:
        // op: imm
        return 5;
      }
      break;
    }
    case CSKY::TSTNBZ32: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 16;
      }
      break;
    }
    case CSKY::TSTNBZ16: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 2;
      }
      break;
    }
    case CSKY::LD16B:
    case CSKY::LD16H:
    case CSKY::LD16W:
    case CSKY::ST16B:
    case CSKY::ST16H:
    case CSKY::ST16W: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 8;
      case 0:
        // op: rz
        return 5;
      case 2:
        // op: imm
        return 0;
      }
      break;
    }
    case CSKY::ASRI16:
    case CSKY::LSLI16:
    case CSKY::LSRI16: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 8;
      case 0:
        // op: rz
        return 5;
      case 2:
        // op: imm5
        return 0;
      }
      break;
    }
    case CSKY::ADDI16XZ:
    case CSKY::SUBI16XZ: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 8;
      case 0:
        // op: rz
        return 5;
      case 2:
        // op: oimm3
        return 2;
      }
      break;
    }
    case CSKY::CMPHSI16:
    case CSKY::CMPLTI16:
    case CSKY::CMPNEI16: {
      switch (OpNum) {
      case 1:
        // op: rx
        return 8;
      case 2:
        // op: imm5
        return 0;
      }
      break;
    }
    case CSKY::BTSTI16: {
      switch (OpNum) {
      case 1:
        // op: rz
        return 8;
      case 2:
        // op: imm5
        return 0;
      }
      break;
    }
    case CSKY::FMFVRH_D:
    case CSKY::FMFVRL:
    case CSKY::FMFVRL_D: {
      switch (OpNum) {
      case 1:
        // op: vrx
        return 16;
      case 0:
        // op: rz
        return 0;
      }
      break;
    }
    case CSKY::FABSM:
    case CSKY::FABS_D:
    case CSKY::FABS_S:
    case CSKY::FDTOS:
    case CSKY::FMOVM:
    case CSKY::FMOV_D:
    case CSKY::FMOV_S:
    case CSKY::FNEGM:
    case CSKY::FNEG_D:
    case CSKY::FNEG_S:
    case CSKY::FRECIP_D:
    case CSKY::FRECIP_S:
    case CSKY::FSITOD:
    case CSKY::FSITOS:
    case CSKY::FSQRT_D:
    case CSKY::FSQRT_S:
    case CSKY::FSTOD:
    case CSKY::FUITOD:
    case CSKY::FUITOS:
    case CSKY::f2FABS_D:
    case CSKY::f2FABS_S:
    case CSKY::f2FDTOS:
    case CSKY::f2FF32TOFI32_RN:
    case CSKY::f2FF32TOFI32_RNI:
    case CSKY::f2FF32TOFI32_RPI:
    case CSKY::f2FF32TOFI32_RZ:
    case CSKY::f2FF32TOSI32_RN:
    case CSKY::f2FF32TOSI32_RNI:
    case CSKY::f2FF32TOSI32_RPI:
    case CSKY::f2FF32TOSI32_RZ:
    case CSKY::f2FF32TOUI32_RN:
    case CSKY::f2FF32TOUI32_RNI:
    case CSKY::f2FF32TOUI32_RPI:
    case CSKY::f2FF32TOUI32_RZ:
    case CSKY::f2FF64TOFI32_RN:
    case CSKY::f2FF64TOFI32_RNI:
    case CSKY::f2FF64TOFI32_RPI:
    case CSKY::f2FF64TOFI32_RZ:
    case CSKY::f2FF64TOSI32_RN:
    case CSKY::f2FF64TOSI32_RNI:
    case CSKY::f2FF64TOSI32_RPI:
    case CSKY::f2FF64TOSI32_RZ:
    case CSKY::f2FF64TOUI32_RN:
    case CSKY::f2FF64TOUI32_RNI:
    case CSKY::f2FF64TOUI32_RPI:
    case CSKY::f2FF64TOUI32_RZ:
    case CSKY::f2FFTOS32_D:
    case CSKY::f2FFTOS32_S:
    case CSKY::f2FFTOU32_D:
    case CSKY::f2FFTOU32_S:
    case CSKY::f2FFTOXS32_D:
    case CSKY::f2FFTOXS32_S:
    case CSKY::f2FFTOXU32_D:
    case CSKY::f2FFTOXU32_S:
    case CSKY::f2FINS:
    case CSKY::f2FMFVRH_D:
    case CSKY::f2FMFVRL:
    case CSKY::f2FMFVRL_D:
    case CSKY::f2FMOVX:
    case CSKY::f2FMOV_D:
    case CSKY::f2FMOV_S:
    case CSKY::f2FMTVRL:
    case CSKY::f2FMTVRL_D:
    case CSKY::f2FNEG_D:
    case CSKY::f2FNEG_S:
    case CSKY::f2FS32TOF_D:
    case CSKY::f2FS32TOF_S:
    case CSKY::f2FSQRT_D:
    case CSKY::f2FSQRT_S:
    case CSKY::f2FSTOD:
    case CSKY::f2FU32TOF_D:
    case CSKY::f2FU32TOF_S:
    case CSKY::f2FXTOFS32_D:
    case CSKY::f2FXTOFS32_S:
    case CSKY::f2FXTOFU32_D:
    case CSKY::f2FXTOFU32_S:
    case CSKY::f2RECIP_D:
    case CSKY::f2RECIP_S:
    case CSKY::rnFDTOSI:
    case CSKY::rnFDTOUI:
    case CSKY::rnFSTOSI:
    case CSKY::rnFSTOUI:
    case CSKY::rniFDTOSI:
    case CSKY::rniFDTOUI:
    case CSKY::rniFSTOSI:
    case CSKY::rniFSTOUI:
    case CSKY::rpiFDTOSI:
    case CSKY::rpiFDTOUI:
    case CSKY::rpiFSTOSI:
    case CSKY::rpiFSTOUI:
    case CSKY::rzFDTOSI:
    case CSKY::rzFDTOUI:
    case CSKY::rzFSTOSI:
    case CSKY::rzFSTOUI: {
      switch (OpNum) {
      case 1:
        // op: vrx
        return 16;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
    case CSKY::FADDM:
    case CSKY::FADD_D:
    case CSKY::FADD_S:
    case CSKY::FDIV_D:
    case CSKY::FDIV_S:
    case CSKY::FMULM:
    case CSKY::FMUL_D:
    case CSKY::FMUL_S:
    case CSKY::FNMULM:
    case CSKY::FNMUL_D:
    case CSKY::FNMUL_S:
    case CSKY::FSUBM:
    case CSKY::FSUB_D:
    case CSKY::FSUB_S: {
      switch (OpNum) {
      case 1:
        // op: vrx
        return 16;
      case 2:
        // op: vry
        return 21;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
    case CSKY::FCMPHS_D:
    case CSKY::FCMPHS_S:
    case CSKY::FCMPLT_D:
    case CSKY::FCMPLT_S:
    case CSKY::FCMPNE_D:
    case CSKY::FCMPNE_S:
    case CSKY::FCMPUO_D:
    case CSKY::FCMPUO_S: {
      switch (OpNum) {
      case 1:
        // op: vrx
        return 16;
      case 2:
        // op: vry
        return 21;
      }
      break;
    }
    case CSKY::FCMPZHS_D:
    case CSKY::FCMPZHS_S:
    case CSKY::FCMPZLS_D:
    case CSKY::FCMPZLS_S:
    case CSKY::FCMPZNE_D:
    case CSKY::FCMPZNE_S:
    case CSKY::FCMPZUO_D:
    case CSKY::FCMPZUO_S:
    case CSKY::f2FCMPHSZ_D:
    case CSKY::f2FCMPHSZ_S:
    case CSKY::f2FCMPHZ_D:
    case CSKY::f2FCMPHZ_S:
    case CSKY::f2FCMPLSZ_D:
    case CSKY::f2FCMPLSZ_S:
    case CSKY::f2FCMPLTZ_D:
    case CSKY::f2FCMPLTZ_S:
    case CSKY::f2FCMPNEZ_D:
    case CSKY::f2FCMPNEZ_S:
    case CSKY::f2FCMPUOZ_D:
    case CSKY::f2FCMPUOZ_S: {
      switch (OpNum) {
      case 1:
        // op: vrx
        return 16;
      }
      break;
    }
    case CSKY::f2FMFVRL_2:
    case CSKY::f2FMFVR_D: {
      switch (OpNum) {
      case 1:
        // op: vry
        return 21;
      case 2:
        // op: vrx
        return 16;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
    case CSKY::CMPHSI32:
    case CSKY::CMPLTI32:
    case CSKY::CMPNEI32: {
      switch (OpNum) {
      case 2:
        // op: imm16
        return 0;
      case 1:
        // op: rx
        return 16;
      }
      break;
    }
    case CSKY::ASRI32:
    case CSKY::BCLRI32:
    case CSKY::BSETI32:
    case CSKY::LSLI32:
    case CSKY::LSRI32:
    case CSKY::ROTLI32: {
      switch (OpNum) {
      case 2:
        // op: imm5
        return 21;
      case 1:
        // op: rx
        return 16;
      case 0:
        // op: rz
        return 0;
      }
      break;
    }
    case CSKY::BTSTI32: {
      switch (OpNum) {
      case 2:
        // op: imm5
        return 21;
      case 1:
        // op: rx
        return 16;
      }
      break;
    }
    case CSKY::ADDI16SPSP:
    case CSKY::SUBI16SPSP: {
      switch (OpNum) {
      case 2:
        // op: imm7
        return 0;
      }
      break;
    }
    case CSKY::f2FLD_D:
    case CSKY::f2FLD_S:
    case CSKY::f2FST_D:
    case CSKY::f2FST_S: {
      switch (OpNum) {
      case 2:
        // op: imm8
        return 4;
      case 1:
        // op: rx
        return 16;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
    case CSKY::INS32: {
      switch (OpNum) {
      case 2:
        // op: rx
        return 16;
      case 0:
        // op: rz
        return 21;
      case 3:
        // op: msb
        return 5;
      case 4:
        // op: lsb
        return 0;
      }
      break;
    }
    case CSKY::FMTVRH_D: {
      switch (OpNum) {
      case 2:
        // op: rx
        return 16;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
    case CSKY::STEX32W: {
      switch (OpNum) {
      case 2:
        // op: rx
        return 16;
      case 1:
        // op: rz
        return 21;
      case 3:
        // op: imm12
        return 0;
      }
      break;
    }
    case CSKY::ADDU32:
    case CSKY::AND32:
    case CSKY::ANDN32:
    case CSKY::ASR32:
    case CSKY::DIVS32:
    case CSKY::DIVU32:
    case CSKY::IXD32:
    case CSKY::IXH32:
    case CSKY::IXW32:
    case CSKY::LSL32:
    case CSKY::LSR32:
    case CSKY::MULSH32:
    case CSKY::MULT32:
    case CSKY::MULTS32:
    case CSKY::MULTU32:
    case CSKY::NOR32:
    case CSKY::OR32:
    case CSKY::ROTL32:
    case CSKY::SUBU32:
    case CSKY::XOR32: {
      switch (OpNum) {
      case 2:
        // op: ry
        return 21;
      case 1:
        // op: rx
        return 16;
      case 0:
        // op: rz
        return 0;
      }
      break;
    }
    case CSKY::CMPHS32:
    case CSKY::CMPLT32:
    case CSKY::CMPNE32:
    case CSKY::TST32: {
      switch (OpNum) {
      case 2:
        // op: ry
        return 21;
      case 1:
        // op: rx
        return 16;
      }
      break;
    }
    case CSKY::CMPHS16:
    case CSKY::CMPLT16:
    case CSKY::CMPNE16:
    case CSKY::TST16: {
      switch (OpNum) {
      case 2:
        // op: ry
        return 6;
      case 1:
        // op: rx
        return 2;
      }
      break;
    }
    case CSKY::f2FMTVRH_D: {
      switch (OpNum) {
      case 2:
        // op: vrx
        return 16;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
    case CSKY::FMACM:
    case CSKY::FMAC_D:
    case CSKY::FMAC_S:
    case CSKY::FMSCM:
    case CSKY::FMSC_D:
    case CSKY::FMSC_S:
    case CSKY::FNMACM:
    case CSKY::FNMAC_D:
    case CSKY::FNMAC_S:
    case CSKY::FNMSCM:
    case CSKY::FNMSC_D:
    case CSKY::FNMSC_S: {
      switch (OpNum) {
      case 2:
        // op: vrx
        return 16;
      case 3:
        // op: vry
        return 21;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
    case CSKY::f2FADD_D:
    case CSKY::f2FADD_S:
    case CSKY::f2FDIV_D:
    case CSKY::f2FDIV_S:
    case CSKY::f2FMAXNM_D:
    case CSKY::f2FMAXNM_S:
    case CSKY::f2FMINNM_D:
    case CSKY::f2FMINNM_S:
    case CSKY::f2FMTVRL_2:
    case CSKY::f2FMTVR_D:
    case CSKY::f2FMUL_D:
    case CSKY::f2FMUL_S:
    case CSKY::f2FNMUL_D:
    case CSKY::f2FNMUL_S:
    case CSKY::f2FSUB_D:
    case CSKY::f2FSUB_S: {
      switch (OpNum) {
      case 2:
        // op: vry
        return 21;
      case 1:
        // op: vrx
        return 16;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
    case CSKY::f2FCMPHS_D:
    case CSKY::f2FCMPHS_S:
    case CSKY::f2FCMPLT_D:
    case CSKY::f2FCMPLT_S:
    case CSKY::f2FCMPNE_D:
    case CSKY::f2FCMPNE_S:
    case CSKY::f2FCMPUO_D:
    case CSKY::f2FCMPUO_S: {
      switch (OpNum) {
      case 2:
        // op: vry
        return 21;
      case 1:
        // op: vrx
        return 16;
      }
      break;
    }
    case CSKY::ASRC32:
    case CSKY::DECGT32:
    case CSKY::DECLT32:
    case CSKY::DECNE32:
    case CSKY::LSLC32:
    case CSKY::LSRC32:
    case CSKY::XSR32: {
      switch (OpNum) {
      case 3:
        // op: imm5
        return 21;
      case 2:
        // op: rx
        return 16;
      case 0:
        // op: rz
        return 0;
      }
      break;
    }
    case CSKY::ADDC32:
    case CSKY::SUBC32: {
      switch (OpNum) {
      case 3:
        // op: ry
        return 21;
      case 2:
        // op: rx
        return 16;
      case 0:
        // op: rz
        return 0;
      }
      break;
    }
    case CSKY::MULATS32:
    case CSKY::MULATU32: {
      switch (OpNum) {
      case 3:
        // op: ry
        return 21;
      case 2:
        // op: rx
        return 16;
      case 1:
        // op: rz
        return 0;
      }
      break;
    }
    case CSKY::f2FFMULA_D:
    case CSKY::f2FFMULA_S:
    case CSKY::f2FFMULS_D:
    case CSKY::f2FFMULS_S:
    case CSKY::f2FFNMULA_D:
    case CSKY::f2FFNMULA_S:
    case CSKY::f2FFNMULS_D:
    case CSKY::f2FFNMULS_S:
    case CSKY::f2FMULA_D:
    case CSKY::f2FMULA_S:
    case CSKY::f2FMULS_D:
    case CSKY::f2FMULS_S:
    case CSKY::f2FNMULA_D:
    case CSKY::f2FNMULA_S:
    case CSKY::f2FNMULS_D:
    case CSKY::f2FNMULS_S:
    case CSKY::f2FSEL_D:
    case CSKY::f2FSEL_S: {
      switch (OpNum) {
      case 3:
        // op: vry
        return 21;
      case 2:
        // op: vrx
        return 16;
      case 0:
        // op: vrz
        return 0;
      }
      break;
    }
  default:
    reportUnsupportedInst(MI);
  }
  reportUnsupportedOperand(MI, OpNum);
}

#endif // GET_OPERAND_BIT_OFFSET

